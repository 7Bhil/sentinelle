import json
from datetime import datetime

class IDS_Engine:
    def __init__(self, state_manager):
        self.state = state_manager
        self.port_scan_threshold = 20 # ports in 10 seconds
        self.ip_history = {} # {ip: [timestamps]}

    def check_port_scan(self, src_ip, dst_port):
        now = datetime.now()
        if src_ip not in self.ip_history:
            self.ip_history[src_ip] = []
        
        self.ip_history[src_ip].append(now)
        
        # Cleanup old history (> 10s)
        self.ip_history[src_ip] = [t for t in self.ip_history[src_ip] if (now - t).total_seconds() < 10]
        
        if len(self.ip_history[src_ip]) > self.port_scan_threshold:
            self._trigger_alert(src_ip, "port_scan", "Tentative de scan de ports détectée.")
            return True
        return False

    def check_bruteforce(self, pkt):
        # Simple detection of many small packets to port 22 or 3389
        if pkt.haslayer('TCP') and (pkt['TCP'].dport == 22 or pkt['TCP'].dport == 3389):
            # Logique simplifiée pour la démo
            pass

    def _trigger_alert(self, ip, type, message):
        alert = {
            "version": "1.0",
            "component": "sentinelle",
            "timestamp": datetime.now().isoformat(),
            "type": "threat",
            "severity": "high",
            "target": {"ip": ip},
            "data": {
                "type": type,
                "description": message
            }
        }
        self.state.add_event(alert)
        print(f"[⚠️ ALERT] {ip} : {message}")
