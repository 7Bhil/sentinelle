import requests
import os

def download_emerging_threats():
    """Télécharge les règles Emerging Threats Open (Format Snort/Suricata)"""
    print("[*] Téléchargement des règles Emerging Threats Open...")
    url = "https://rules.emergingthreats.net/open/suricata/emerging-all.rules"
    
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            with open("emerging_threats.rules", "w") as f:
                f.write(response.text)
            
            # Compter les règles pour l'effet "Wow"
            count = len([l for l in response.text.splitlines() if l.startswith("alert")])
            print(f"[✅] {count} règles professionnelles chargées avec succès.")
            return True
    except Exception as e:
        print(f"[!] Erreur téléchargement règles : {e}")
    return False

if __name__ == "__main__":
    download_emerging_threats()
