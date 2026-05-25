import requests

class DNS_Guard:
    def __init__(self):
        # Placeholder malicious domains for demo
        self.blacklist = [
            "malware.com",
            "phishing-site.net",
            "c2-server.org",
            "evil-tracker.io"
        ]
        # Possibility to load from external lists (e.g. abuse.ch)
        # self.load_external_blacklists()

    def is_malicious(self, domain):
        # Remove trailing dot if present
        domain = domain.rstrip('.')
        for b in self.blacklist:
            if b in domain:
                return True
        return False

    def check_query(self, domain):
        if self.is_malicious(domain):
            return True, f"Connexion suspecte vers un domaine sur liste noire : {domain}"
        return False, ""
