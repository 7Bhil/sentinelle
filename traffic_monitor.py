import sys
import os
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from datetime import datetime
import json
import threading
import argparse

# Add parent directory for state_manager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from state_manager import MirageState
from ids_engine import IDS_Engine
from dns_guard import DNS_Guard
from escalation import EscalationManager
from counter_attack import CounterAttack

class TrafficMonitor:
    def __init__(self, interface=None):
        self.interface = interface
        self.workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.state = MirageState(self.workspace_root)
        self.baseline = self._load_baseline()
        self.ids = IDS_Engine(self.state)
        self.dns_guard = DNS_Guard()
        self.escalation = EscalationManager(self.state)
        self.counter = CounterAttack()
        self.running = False

    def _load_baseline(self):
        path = os.path.join(self.workspace_root, "sentinelle_baseline.json")
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_baseline(self):
        path = os.path.join(self.workspace_root, "sentinelle_baseline.json")
        with open(path, 'w') as f:
            json.dump(self.baseline, f, indent=4)

    def packet_callback(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            pkt_size = len(pkt)
            
            # 1. Update baseline stats
            self._update_stats(src_ip, pkt)
            
            # 2. Port Scan Detection
            if TCP in pkt:
                if self.ids.check_port_scan(src_ip, pkt[TCP].dport):
                    self.escalation.handle_threat(src_ip, "high")
                    self.counter.flood_fake_responses(src_ip)
                    self.counter.corrupt_scan_data(src_ip)

            # 3. DNS Guard & Counter-DNS
            if DNS in pkt and pkt[DNS].qr == 0:
                try:
                    domain = pkt[DNSQR].qname.decode()
                    is_mal, msg = self.dns_guard.check_query(domain)
                    if is_mal:
                        self.ids._trigger_alert(src_ip, "dns_threat", msg)
                        self.escalation.handle_threat(src_ip, "medium")
                        self.counter.send_fake_dns_reply(src_ip, domain)
                except:
                    pass

            # 4. Lateral Movement Detection
            if self.ids.check_lateral_movement(src_ip, dst_ip):
                self.escalation.handle_threat(src_ip, "critical")
                self.counter.fake_network_topology(src_ip)

            # 5. Data Exfiltration Detection
            if self.ids.check_exfiltration(src_ip, pkt_size):
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
        print(f"[*] 🛡️ MIRAGE SENTINELLE : Surveillance lancée sur {self.interface if self.interface else 'toutes les interfaces'}")
        self.running = True
        sniff(iface=self.interface, prn=self.packet_callback, store=0)

    def stop(self):
        self.running = False
        self._save_baseline()
        print("\n[*] Sentinelle : Capture arrêtée et baseline sauvegardée.")

def main():
    parser = argparse.ArgumentParser(description="Mirage Sentinelle - Real-time Network Guardian")
    parser.add_argument("--interface", help="Network interface to monitor (e.g. eth0, wlan0)")
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
