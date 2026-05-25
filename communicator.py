import json
import os
from datetime import datetime

class MirageCommunicator:
    def __init__(self, workspace_root):
        self.workspace_root = workspace_root
        self.oracle_queue = os.path.join(workspace_root, "oracle_queue.json")
        self.ghost_trigger = os.path.join(workspace_root, "ghost_trigger.json")

    def notify_oracle(self, event):
        """Envoyer une alerte critique au cerveau Oracle"""
        print(f"[*] Notification Oracle : {event['type']} détecté.")
        # Simuler un bus de message par fichier pour le MVP
        try:
            queue = []
            if os.path.exists(self.oracle_queue):
                with open(self.oracle_queue, 'r') as f:
                    queue = json.load(f)
            queue.append(event)
            with open(self.oracle_queue, 'w') as f:
                json.dump(queue, f, indent=4)
        except Exception as e:
            print(f"[!] Erreur de communication Oracle : {e}")

    def activate_ghost(self, attacker_ip, target_ip):
        """Déclencher la création d'un clone Ghost pour piéger l'attaquant"""
        print(f"[👻 GHOST] Signal envoyé pour piéger {attacker_ip}...")
        trigger_data = {
            "timestamp": datetime.now().isoformat(),
            "attacker_ip": attacker_ip,
            "target_ip": target_ip,
            "action": "clone_and_redirect"
        }
        with open(self.ghost_trigger, 'w') as f:
            json.dump(trigger_data, f, indent=4)
