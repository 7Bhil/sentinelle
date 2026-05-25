import psutil
import time

class ProcessMonitor:
    def __init__(self, db_manager, cloud_db=None):
        self.db = db_manager
        self.cloud_db = cloud_db

    def scan_suspicious_processes(self):
        # ...
                    if conn_list:
                        # Log to SQLite
                        self.db.log_process(proc.info['pid'], proc.info['name'], proc.info['status'], conn_list)
                        
                        # Detection simple : trop de connexions établies pour un seul process
                        if len(conn_list) > 50:
                            msg = f"Processus {proc.info['name']} (PID {proc.info['pid']}) a trop de connexions actives."
                            self.db.log_event("sentinelle", "suspicious_process", "high", "127.0.0.1", msg)
                            
                            if self.cloud_db and self.cloud_db.db is not None:
                                self.cloud_db.insert_event({
                                    "component": "sentinelle",
                                    "type": "suspicious_process",
                                    "severity": "high",
                                    "target": {"ip": "127.0.0.1"},
                                    "message": msg,
                                    "data": {"pid": proc.info['pid'], "name": proc.info['name'], "connections": conn_list}
                                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
# ...

    def run_daemon(self, interval=60):
        while True:
            self.scan_suspicious_processes()
            time.sleep(interval)
