#!/bin/bash
# --- MIRAGE SENTINELLE INSTALLER ---

# Vérification ROOT
if [ "$EUID" -ne 0 ]; then
  echo " Erreur : Veuillez lancer l'installation avec sudo."
  exit 1
fi

echo "Installation de Mirage Sentinelle..."

# Dépendances système
apt-get update && apt-get install -y iptables libpcap-dev python3-dev

# Environnement virtuel
python3 -m venv venv
...

source venv/bin/activate
pip install --upgrade pip
pip install scapy requests psutil dnspython PyYAML

# Sentinelle nécessite souvent les outils iptables
sudo apt-get update && sudo apt-get install -y iptables

echo "Installation terminée."
