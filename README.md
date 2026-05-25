# 🛡️ Mirage Sentinelle Engine

> **Le Gardien du Réseau.**  
> Deuxième pilier de l'écosystème **MIRAGE**, ce module est un IDS/IPS actif capable de surveiller, détecter et contre-attaquer en temps réel.

## ✨ Fonctionnalités clés

- **Monitoring Temps Réel** : Analyse de flux réseau via Scapy.
- **Détection d'Anomalies** : Identifie les scans de ports et les comportements suspects.
- **DNS Guard** : Bloque les requêtes vers des domaines malveillants (Blacklist).
- **Escalade Progressive** : Réponse automatique graduée (Alerte -> Throttling -> Isolation).
- **Contre-Attaque Défensive** : Inonde l'attaquant de fausses réponses pour le ralentir.

## 🚀 Installation Rapide

```bash
git clone https://github.com/7Bhil/sentinelle.git
cd sentinelle
chmod +x install.sh
./install.sh
```

## 🛠️ Utilisation

```bash
# Lancer la surveillance globale
sudo venv/bin/python3 traffic_monitor.py
```

---
© 2026 Mirage Security - "Le réseau a désormais un gardien."
