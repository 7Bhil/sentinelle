from scapy.all import IP, TCP, send, DNS, DNSRR, UDP, ARP, Ether
import random

class CounterAttack:
    def __init__(self):
        pass

    def flood_fake_responses(self, target_ip):
        print(f"[⚔️ COUNTER] Inondation de fausses réponses TCP pour {target_ip}...")
        for _ in range(10):
            fake_port = random.randint(1024, 65535)
            pkt = IP(dst=target_ip)/TCP(sport=fake_port, dport=random.randint(1, 1000), flags="SA")
            send(pkt, verbose=False)

    def send_fake_dns_reply(self, target_ip, query_domain):
        print(f"[⚔️ COUNTER] Envoi d'une fausse réponse DNS à {target_ip} pour {query_domain}")
        fake_ip = "10.0.0.66" 
        dns_ans = IP(dst=target_ip)/UDP(dport=53)/DNS(id=random.randint(1, 65535), qr=1, aa=1, qd=query_domain, an=DNSRR(rrname=query_domain, rdata=fake_ip))
        send(dns_ans, verbose=False)

    def fake_network_topology(self, target_ip):
        print(f"[⚔️ COUNTER] Génération d'une fausse topologie réseau pour {target_ip}")
        # Répondre à des ARP requests pour des IPs qui n'existent pas
        for i in range(200, 210):
            fake_ip = f"10.58.76.{i}"
            fake_mac = "00:de:ad:be:ef:01"
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=fake_ip, hwsrc=fake_mac, pdst=target_ip)
            send(pkt, verbose=False)

    def corrupt_scan_data(self, target_ip):
        print(f"[⚔️ COUNTER] Corruption des outils de scan de {target_ip}")
        # Envoyer des paquets avec des TTL bizarres ou des flags TCP invalides
        for _ in range(5):
            pkt = IP(dst=target_ip, ttl=random.randint(1, 5))/TCP(flags="FPU") # Christmas Tree Packet
            send(pkt, verbose=False)
