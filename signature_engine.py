import re
import yaml
import os

class SignatureEngine:
    def __init__(self):
        self.rules_path = os.path.join(os.path.dirname(__file__), "rules.yaml")
        self.et_rules_path = os.path.join(os.path.dirname(__file__), "emerging_threats.rules")
        self.rules = self._load_rules()
        self.et_patterns = self._load_et_rules()

    def _load_et_rules(self):
        """Charge un sous-ensemble des règles ET pour la performance"""
        patterns = []
        if os.path.exists(self.et_rules_path):
            with open(self.et_rules_path, 'r') as f:
                # On prend les 500 premières règles pour garder Mirage rapide
                for i, line in enumerate(f):
                    if line.startswith("alert tcp") and 'content:"' in line:
                        # Extraction simplifiée du pattern et du message
                        try:
                            content = line.split('content:"')[1].split('"')[0]
                            msg = line.split('msg:"')[1].split('"')[0]
                            patterns.append({"name": msg, "pattern": content})
                        except: pass
                    if i > 2000: break # Limite pour le MVP
        return patterns

    def inspect_payload(self, pkt_payload):
        if not pkt_payload: return None
        payload_str = pkt_payload.decode(errors='ignore')
        
        # 1. Vérifier nos règles custom YAML (prioritaires)
        for rule in self.rules:
            if re.search(rule["pattern"], payload_str, re.IGNORECASE):
                return rule

        # 2. Vérifier les règles Emerging Threats
        for rule in self.et_patterns:
            if rule["pattern"] in payload_str:
                return rule
        return None
