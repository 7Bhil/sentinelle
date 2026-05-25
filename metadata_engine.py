from scapy.all import TCP, UDP, DNS, Raw
import json

class MetadataEngine:
    def __init__(self, db_manager):
        self.db = db_manager

    def extract_metadata(self, pkt):
        metadata = {}
        
        # Zeek-style protocol logging
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors='ignore')
            
            # Simple HTTP detection
            if "HTTP" in payload:
                metadata['protocol'] = 'HTTP'
                lines = payload.split('\r\n')
                if lines:
                    metadata['request'] = lines[0]
                    for line in lines:
                        if "User-Agent:" in line:
                            metadata['user_agent'] = line.split(':', 1)[1].strip()
                        if "Host:" in line:
                            metadata['host'] = line.split(':', 1)[1].strip()

        if pkt.haslayer(DNS):
            metadata['protocol'] = 'DNS'
            # (DNS details already handled by DNSGuard, but we could log more here)

        return metadata

    def log_metadata(self, src_ip, dst_ip, metadata):
        if metadata:
            description = f"Flux {metadata.get('protocol', 'Inconnu')} détecté"
            self.db.log_event("sentinelle_metadata", "flow_log", "info", src_ip, description, metadata)
