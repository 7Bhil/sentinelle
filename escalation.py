import time
import subprocess
import threading

class EscalationManager:
    def __init__(self, state_manager):
        self.state = state_manager
        self.active_timers = {} # {ip: timer_thread}

    def handle_threat(self, ip, severity):
        if severity == "low":
            self.level_1(ip)
        elif severity == "medium":
            self.level_2(ip)
        elif severity == "high" or severity == "critical":
            self.level_3(ip)

    def level_1(self, ip):
        print(f"[ LEVEL 1] Alerte Admin envoyée pour {ip}. En attente de 30s...")
        if ip not in self.active_timers:
            # Démarrer un timer : si pas d'action après 30s, passer au Niveau 2
            t = threading.Timer(30.0, self.level_2, args=[ip])
            t.start()
            self.active_timers[ip] = t

    def level_2(self, ip):
        # Annuler le timer si on passe au niveau 2 manuellement ou par escalade
        if ip in self.active_timers:
            self.active_timers[ip].cancel()
            del self.active_timers[ip]
            
        print(f"[ LEVEL 2] Escalade : Mesures défensives automatiques (Throttling) pour {ip}.")
        subprocess.run(f"sudo iptables -A INPUT -s {ip} -m limit --limit 1/s -j ACCEPT", shell=True)
        subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True)

    def level_3(self, ip):
        if ip in self.active_timers:
            self.active_timers[ip].cancel()
            del self.active_timers[ip]
            
        print(f"[ LEVEL 3] Décision immédiate : Blocage total de {ip}.")
        subprocess.run(f"sudo iptables -I INPUT -s {ip} -j DROP", shell=True)
        subprocess.run(f"sudo iptables -I OUTPUT -d {ip} -j DROP", shell=True)
