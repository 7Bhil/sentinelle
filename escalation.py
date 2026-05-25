import time
import subprocess

class EscalationManager:
    def __init__(self, state_manager):
        self.state = state_manager

    def handle_threat(self, ip, severity):
        if severity == "low":
            self.level_1(ip)
        elif severity == "medium":
            self.level_2(ip)
        elif severity == "high" or severity == "critical":
            self.level_3(ip)

    def level_1(self, ip):
        print(f"[🛡️ LEVEL 1] Alerte Admin envoyée pour {ip}. En attente...")
        # Simuler une attente ou un log spécial

    def level_2(self, ip):
        print(f"[🛡️ LEVEL 2] Pas de réponse Admin. Activation du throttling pour {ip}.")
        # Commande système pour ralentir (ex: tc pour Linux)
        subprocess.run(f"sudo iptables -A INPUT -s {ip} -m limit --limit 1/s -j ACCEPT", shell=True)
        subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True)

    def level_3(self, ip):
        print(f"[🛡️ LEVEL 3] Menace Critique ! Isolation immédiate de {ip}.")
        # Blocage total
        subprocess.run(f"sudo iptables -I INPUT -s {ip} -j DROP", shell=True)
        subprocess.run(f"sudo iptables -I OUTPUT -d {ip} -j DROP", shell=True)
