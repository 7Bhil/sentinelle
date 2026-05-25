import re
import yaml
import os

class SignatureEngine:
    def __init__(self):
        self.rules = self._load_rules()

    def _load_rules(self):
        # Exemple de règles simplifiées (format type Snort/Suricata)
        return [
            {"id": 1001, "name": "SQL Injection attempt", "pattern": r"UNION\s+SELECT|OR\s+1=1", "proto": "TCP"},
            {"id": 1002, "name": "Cross-Site Scripting (XSS)", "pattern": r"<script>|alert\(", "proto": "TCP"},
            {"id": 1003, "name": "Path Traversal", "pattern": r"\.\./\.\./", "proto": "TCP"},
            {"id": 1004, "name": "Log4Shell Attempt", "pattern": r"\$\{jndi:ldap", "proto": "TCP"}
        ]

    def inspect_payload(self, pkt_payload):
        if not pkt_payload: return None
        
        payload_str = str(pkt_payload)
        for rule in self.rules:
            if re.search(rule["pattern"], payload_str, re.IGNORECASE):
                return rule
        return None
