import sys
import os
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, conf
from datetime import datetime, timedelta
import json
import threading
import argparse
import socket

# Silence Scapy warnings for MAC address
conf.verb = 0

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# ... (imports)

class TrafficMonitor:
    def __init__(self, interface=None):
        self.interface = interface
        self.local_ip = get_local_ip()
        self.workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.state = MirageState(self.workspace_root)
        self.db = MirageDB(self.workspace_root)
        self.baseline = self._load_baseline()
        self.ids = IDS_Engine(self.state)
        self.dns_guard = DNS_Guard()
        self.escalation = EscalationManager(self.state)
        self.counter = CounterAttack()
        self.proc_monitor = ProcessMonitor(self.db)
        self.running = False
        self.alert_cooldown = {} # {ip: last_alert_time}

    def packet_callback(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # --- FILTRE D'AUTO-IMMUNITÉ ---
            # Si le paquet vient de ma machine, je ne l'analyse pas comme une attaque
            if src_ip == self.local_ip:
                return

            pkt_size = len(pkt)
            now = datetime.now()
            
            # --- ZEEK LAYER ---
            meta = self.zeek.extract_metadata(pkt)
            self.zeek.log_metadata(src_ip, dst_ip, meta)
            self._update_stats(src_ip, pkt)
            
            # --- MÉCANISME DE COOLDOWN ---
            # Si on a déjà alerté sur cette IP il y a moins de 30 secondes, on reste calme
            if src_ip in self.alert_cooldown:
                if now < self.alert_cooldown[src_ip] + timedelta(seconds=30):
                    return

            # --- SURICATA & IDS LAYERS ---
            triggered = False

            if pkt.haslayer(Raw):
                match = self.suricata.inspect_payload(pkt[Raw].load)
                if match:
                    msg = f"ALERTE SIGNATURE : {match['name']} détecté !"
                    self.db.log_event("sentinelle_suricata", "attack_signature", "critical", src_ip, msg)
                    self.escalation.handle_threat(src_ip, "critical")
                    triggered = True

            if TCP in pkt and not triggered:
                if self.ids.check_port_scan(src_ip, pkt[TCP].dport):
                    self.db.log_event("sentinelle", "port_scan", "high", src_ip, "Tentative de scan de ports détectée.")
                    self.escalation.handle_threat(src_ip, "high")
                    self.counter.flood_fake_responses(src_ip)
                    self.counter.corrupt_scan_data(src_ip)
                    triggered = True

            if triggered:
                self.alert_cooldown[src_ip] = now

            # 2. DNS Guard & Counter-DNS
            if DNS in pkt and pkt[DNS].qr == 0:
                try:
                    domain = pkt[DNSQR].qname.decode()
                    is_mal, msg = self.dns_guard.check_query(domain)
                    if is_mal:
                        self.db.log_event("sentinelle", "dns_threat", "medium", src_ip, msg)
                        self.ids._trigger_alert(src_ip, "dns_threat", msg)
                        self.escalation.handle_threat(src_ip, "medium")
                        self.counter.send_fake_dns_reply(src_ip, domain)
                except:
                    pass

            # 3. Lateral Movement Detection
            if self.ids.check_lateral_movement(src_ip, dst_ip):
                self.db.log_event("sentinelle", "lateral_movement", "critical", src_ip, f"Mouvement latéral vers {dst_ip}")
                self.escalation.handle_threat(src_ip, "critical")
                self.counter.fake_network_topology(src_ip)

            # 4. Data Exfiltration Detection
            if self.ids.check_exfiltration(src_ip, pkt_size):
                self.db.log_event("sentinelle", "data_exfiltration", "critical", src_ip, "Exfiltration de données détectée")
                self.escalation.handle_threat(src_ip, "critical")

    def _update_stats(self, ip, pkt):
        if ip not in self.baseline:
            self.baseline[ip] = {
                "first_seen": str(datetime.now()),
                "packet_count": 0,
                "common_dst_ports": {},
                "dns_queries": []
            }
        self.baseline[ip]["packet_count"] += 1
        if TCP in pkt:
            port = pkt[TCP].dport
            self.baseline[ip]["common_dst_ports"][str(port)] = self.baseline[ip]["common_dst_ports"].get(str(port), 0) + 1
        elif UDP in pkt:
            port = pkt[UDP].dport
            self.baseline[ip]["common_dst_ports"][str(port)] = self.baseline[ip]["common_dst_ports"].get(str(port), 0) + 1

    def start(self):
        print(f"[*] 🛡️ MIRAGE SENTINELLE (Engine: Dual Suricata/Zeek) : Surveillance lancée sur {self.interface if self.interface else 'toutes les interfaces'}")
        proc_thread = threading.Thread(target=self.proc_monitor.run_daemon, args=(30,), daemon=True)
        proc_thread.start()
        self.running = True
        sniff(iface=self.interface, prn=self.packet_callback, store=0)

    def stop(self):
        self.running = False
        self._save_baseline()
        print("\n[*] Sentinelle : Capture arrêtée.")

def main():
    parser = argparse.ArgumentParser(description="Mirage Sentinelle - Real-time Network Guardian")
    parser.add_argument("--interface", help="Network interface to monitor")
    parser.add_argument("--threshold", type=int, default=20, help="Port scan sensitivity threshold")
    args = parser.parse_args()
    monitor = TrafficMonitor(interface=args.interface)
    monitor.ids.port_scan_threshold = args.threshold
    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.stop()

if __name__ == "__main__":
    main()
