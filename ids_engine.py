import json
from datetime import datetime

class IDS_Engine:
    def __init__(self, state_manager):
        self.state = state_manager
        self.port_scan_threshold = 20
        self.ip_history = {}
        self.internal_traffic = {} # {src_ip: {dst_ip: count}}
        self.data_outbound = {} # {src_ip: total_bytes}
        self.exfiltration_threshold = 1024 * 1024 * 50 # 50MB for demo

    def check_port_scan(self, src_ip, dst_port):
        now = datetime.now()
        if src_ip not in self.ip_history: self.ip_history[src_ip] = []
        self.ip_history[src_ip].append(now)
        self.ip_history[src_ip] = [t for t in self.ip_history[src_ip] if (now - t).total_seconds() < 10]
        if len(self.ip_history[src_ip]) > self.port_scan_threshold:
            self._trigger_alert(src_ip, "port_scan", "Tentative de scan de ports détectée.")
            return True
        return False

    def check_lateral_movement(self, src_ip, dst_ip):
        # Only check internal to internal (RFC 1918)
        if src_ip.startswith("10.") and dst_ip.startswith("10."):
            if src_ip not in self.internal_traffic: self.internal_traffic[src_ip] = {}
            self.internal_traffic[src_ip][dst_ip] = self.internal_traffic[src_ip].get(dst_ip, 0) + 1
            
            # If a machine connects to too many unique internal IPs
            if len(self.internal_traffic[src_ip]) > 10:
                self._trigger_alert(src_ip, "lateral_movement", f"Mouvement latéral suspect : Connexions vers {len(self.internal_traffic[src_ip])} machines internes.")
                return True
        return False

    def check_exfiltration(self, src_ip, pkt_size):
        self.data_outbound[src_ip] = self.data_outbound.get(src_ip, 0) + pkt_size
        if self.data_outbound[src_ip] > self.exfiltration_threshold:
            self._trigger_alert(src_ip, "data_exfiltration", f"Exfiltration suspecte : {self.data_outbound[src_ip] / (1024*1024):.2f} MB envoyés.")
            return True
        return False

    def _trigger_alert(self, ip, type, message):
        alert = {
            "version": "1.0",
            "component": "sentinelle",
            "timestamp": datetime.now().isoformat(),
            "type": "threat",
            "severity": "high" if "scan" in type else "critical",
            "target": {"ip": ip},
            "data": {
                "type": type,
                "description": message
            }
        }
        self.state.add_event(alert)
        print(f"[⚠️ ALERT] {ip} : {message}")
