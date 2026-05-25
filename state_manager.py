import json
import os
from datetime import datetime

class MirageState:
    def __init__(self, workspace_root):
        self.state_file = os.path.join(workspace_root, "mirage_global_state.json")
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except:
                return {"machines": {}, "last_update": None, "events": []}
        return {"machines": {}, "last_update": str(datetime.now()), "events": []}

    def update_machine(self, ip, key, value):
        if ip not in self.data["machines"]:
            self.data["machines"][ip] = {
                "ip": ip,
                "hostname": "Unknown",
                "last_seen": str(datetime.now()),
                "ports": [],
                "vulns": [],
                "score": 100,
                "status": "Healthy"
            }
        self.data["machines"][ip][key] = value
        self.data["last_update"] = str(datetime.now())
        self._save()

    def add_event(self, event):
        self.data["events"].append(event)
        if len(self.data["events"]) > 100: # Keep last 100 events
            self.data["events"].pop(0)
        self._save()

    def _save(self):
        with open(self.state_file, 'w') as f:
            json.dump(self.data, f, indent=4)

    def get_all(self):
        return self.data
