import dns.resolver
import dns.reversename

class DNS_Guard:
    def __init__(self):
        self.blacklist = ["malware.com", "phishing-site.net", "c2-server.org", "evil-tracker.io"]
        self.resolver = dns.resolver.Resolver()

    def deep_inspect(self, domain):
        try:
            # Vérifier si le domaine a des enregistrements TXT bizarres (souvent utilisé par C2)
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                if len(str(rdata)) > 100: # Payload suspect dans un DNS TXT
                    return True, f"Payload suspect détecté dans l'enregistrement TXT de {domain}"
        except:
            pass
        return False, ""

    def check_query(self, domain):
        domain = domain.rstrip('.')
        if any(b in domain for b in self.blacklist):
            return True, f"Connexion suspecte vers un domaine sur liste noire : {domain}"
        
        # Inspection approfondie avec dnspython
        is_sus, msg = self.deep_inspect(domain)
        if is_sus: return True, msg
            
        return False, ""
