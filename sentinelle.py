import sys
import os
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, conf
from datetime import datetime, timedelta
import json
import threading
import argparse
import socket
import time

# Add parent directory for state_manager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from state_manager import MirageState
from ids_engine import IDS_Engine
from dns_guard import DNS_Guard
from escalation import EscalationManager
from counter_attack import CounterAttack
from database import MirageDB
from process_monitor import ProcessMonitor
from signature_engine import SignatureEngine
from metadata_engine import MetadataEngine
from communicator import MirageCommunicator

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

class TrafficMonitor:
    def __init__(self, interface=None):
        self.interface = interface
        self.local_ip = get_local_ip()
        self.workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.state = MirageState(self.workspace_root)
        self.db = MirageDB(self.workspace_root)
        self.comm = MirageCommunicator(self.workspace_root)
        self.baseline = self._load_baseline()
        
        # Dual Engine Setup
        self.suricata = SignatureEngine()
        self.zeek = MetadataEngine(self.db)
        
        self.ids = IDS_Engine(self.state)
        self.dns_guard = DNS_Guard()
        self.escalation = EscalationManager(self.state)
        self.counter = CounterAttack()
        self.proc_monitor = ProcessMonitor(self.db)
        self.running = False
        self.alert_cooldown = {}

    def _load_baseline(self):
        path = os.path.join(self.workspace_root, "sentinelle_baseline.json")
        if os.path.exists(path):
            try:
                with open(path, 'r') as f: return json.load(f)
            except: return {}
        return {}

    def _save_baseline(self):
        path = os.path.join(self.workspace_root, "sentinelle_baseline.json")
        with open(path, 'w') as f:
            json.dump(self.baseline, f, indent=4)

    def _auto_save_loop(self):
        """Sauvegarde périodique toutes les 5 minutes"""
        while self.running:
            time.sleep(300)
            self._save_baseline()
            print("[*] Baseline sauvegardée automatiquement.")

    def packet_callback(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if src_ip == self.local_ip: return

            pkt_size = len(pkt)
            now = datetime.now()
            
            # --- ZEEK LAYER ---
            meta = self.zeek.extract_metadata(pkt)
            self.zeek.log_metadata(src_ip, dst_ip, meta)
            self._update_stats(src_ip, pkt)
            
            # Cooldown check
            if src_ip in self.alert_cooldown:
                if now < self.alert_cooldown[src_ip] + timedelta(seconds=30): return

            # --- SURICATA LAYER ---
            triggered = False
            if pkt.haslayer(Raw):
                match = self.suricata.inspect_payload(pkt[Raw].load)
                if match:
                    msg = f"ALERTE SIGNATURE : {match['name']}"
                    self.db.log_event("sentinelle_suricata", "attack_signature", "critical", src_ip, msg)
                    self.escalation.handle_threat(src_ip, "critical")
                    self.comm.notify_oracle({"type": "signature_match", "ip": src_ip, "msg": msg})
                    self.comm.activate_ghost(src_ip, dst_ip)
                    triggered = True

            # --- IDS LAYER ---
            if TCP in pkt and not triggered:
                if self.ids.check_port_scan(src_ip, pkt[TCP].dport):
                    self.db.log_event("sentinelle", "port_scan", "high", src_ip, "Scan détecté.")
                    self.escalation.handle_threat(src_ip, "high")
                    self.counter.flood_fake_responses(src_ip)
                    self.comm.notify_oracle({"type": "port_scan", "ip": src_ip})
                    triggered = True

            if DNS in pkt and pkt[DNS].qr == 0 and not triggered:
                try:
                    domain = pkt[DNSQR].qname.decode()
                    is_mal, msg = self.dns_guard.check_query(domain)
                    if is_mal:
                        self.db.log_event("sentinelle", "dns_threat", "medium", src_ip, msg)
                        self.comm.notify_oracle({"type": "dns_threat", "ip": src_ip, "domain": domain})
                        self.escalation.handle_threat(src_ip, "medium")
                        self.counter.send_fake_dns_reply(src_ip, domain)
                        triggered = True
                except: pass

            if triggered: self.alert_cooldown[src_ip] = now

    def _update_stats(self, ip, pkt):
        if ip not in self.baseline:
            self.baseline[ip] = {"first_seen": str(datetime.now()), "packet_count": 0, "common_dst_ports": {}, "dns_queries": []}
        self.baseline[ip]["packet_count"] += 1

    def start(self):
        print(f"[*] 🛡️ MIRAGE SENTINELLE : Surveillance lancée sur {self.interface if self.interface else 'toutes les interfaces'}")
        self.running = True
        threading.Thread(target=self.proc_monitor.run_daemon, args=(30,), daemon=True).start()
        threading.Thread(target=self._auto_save_loop, daemon=True).start()
        sniff(iface=self.interface, prn=self.packet_callback, store=0)

def main():
    parser = argparse.ArgumentParser(description="Mirage Sentinelle - Real-time Network Guardian")
    parser.add_argument("--interface", help="Network interface to monitor")
    parser.add_argument("--threshold", type=int, default=20, help="Port scan sensitivity threshold")
    args = parser.parse_args()
    monitor = TrafficMonitor(interface=args.interface)
    try: monitor.start()
    except KeyboardInterrupt: print("\nArrêt..."); monitor.running = False

if __name__ == "__main__":
    main()
