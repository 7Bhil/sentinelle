import psutil
import time

class ProcessMonitor:
    def __init__(self, db_manager):
        self.db = db_manager

    def scan_suspicious_processes(self):
        print("[*] Scan des processus et connexions locales...")
        for proc in psutil.process_iter(['pid', 'name', 'status']):
            try:
                # Check for suspicious network connections
                connections = proc.connections(kind='inet')
                if connections:
                    conn_list = []
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            conn_list.append(f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
                    
                    if conn_list:
                        # Log to SQLite
                        self.db.log_process(proc.info['pid'], proc.info['name'], proc.info['status'], conn_list)
                        
                        # Detection simple : trop de connexions établies pour un seul process
                        if len(conn_list) > 50:
                            self.db.log_event("sentinelle", "suspicious_process", "high", "127.0.0.1", 
                                              f"Processus {proc.info['name']} (PID {proc.info['pid']}) a trop de connexions actives.")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def run_daemon(self, interval=60):
        while True:
            self.scan_suspicious_processes()
            time.sleep(interval)
