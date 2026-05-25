import sqlite3
import os
from datetime import datetime

class MirageDB:
    def __init__(self, workspace_root):
        self.db_path = os.path.join(workspace_root, "mirage_events.db")
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Table pour les événements de sécurité (Timeline)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                component TEXT,
                type TEXT,
                severity TEXT,
                ip TEXT,
                description TEXT,
                data TEXT
            )
        ''')
        # Table pour le monitoring des processus suspects
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                pid INTEGER,
                name TEXT,
                status TEXT,
                connections TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def log_event(self, component, event_type, severity, ip, description, data=""):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO events (timestamp, component, type, severity, ip, description, data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), component, event_type, severity, ip, description, str(data)))
        conn.commit()
        conn.close()

    def log_process(self, pid, name, status, connections):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO process_logs (timestamp, pid, name, status, connections)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), pid, name, status, str(connections)))
        conn.commit()
        conn.close()
