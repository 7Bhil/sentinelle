import re
import yaml
import os

class SignatureEngine:
    def __init__(self):
        self.rules_path = os.path.join(os.path.dirname(__file__), "rules.yaml")
        self.rules = self._load_rules()

    def _load_rules(self):
        if os.path.exists(self.rules_path):
            with open(self.rules_path, 'r') as f:
                data = yaml.safe_load(f)
                return data.get("rules", [])
        return []

    def inspect_payload(self, pkt_payload):
        if not pkt_payload: return None
        
        try:
            # Decode payload, ignore errors for binary data
            payload_str = pkt_payload.decode(errors='ignore')
            for rule in self.rules:
                if re.search(rule["pattern"], payload_str, re.IGNORECASE):
                    return rule
        except:
            pass
        return None
