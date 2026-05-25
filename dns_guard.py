import dns.resolver
import dns.reversename
import requests
import threading
import time

class DNS_Guard:
    def __init__(self):
        self.blacklist = set(["malware.com", "phishing-site.net", "c2-server.org", "evil-tracker.io"])
        self.resolver = dns.resolver.Resolver()
        # Lancer la mise à jour de la blacklist en arrière-plan
        threading.Thread(target=self._update_blacklist_loop, daemon=True).start()

    def _update_blacklist_loop(self):
        while True:
            self.load_real_blacklist()
            time.sleep(86400) # Mise à jour une fois par jour

    def load_real_blacklist(self):
        print("[*] DNS Guard : Mise à jour de la blacklist via URLHaus...")
        try:
            # URLHaus feed (plain text domains)
            url = "https://urlhaus.abuse.ch/downloads/hostfile/"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) > 1:
                            self.blacklist.add(parts[1])
                print(f"[+] DNS Guard : {len(self.blacklist)} domaines chargés.")
        except Exception as e:
            print(f"[!] Erreur mise à jour blacklist : {e}")

    def deep_inspect(self, domain):
...

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
