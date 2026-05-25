#!/bin/bash

# --- MIRAGE SENTINELLE INSTALLER ---

echo "Installation de Mirage Sentinelle..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install scapy requests psutil dnspython PyYAML

# Sentinelle nécessite souvent les outils iptables
sudo apt-get update && sudo apt-get install -y iptables

echo "Installation terminée."
