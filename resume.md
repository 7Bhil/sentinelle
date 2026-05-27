#  Résumé technique : Module SENTINELLE

**Rôle** : Le Gardien (IDS/IPS Actif & Analyse comportementale)
**État** : 100% Terminée (Jour 7-11 + Optimisations Pro)

##  Fonctionnalités implémentées
- **Architecture Dual-Engine** (`sentinelle.py`) :
    - **Couche Suricata** (`signature_engine.py`) : Détection par signatures (SQLi, XSS, Log4Shell). Support des règles professionnelles **Emerging Threats**.
    - **Couche Zeek** (`metadata_engine.py`) : Extraction de métadonnées HTTP/DNS/SSH et logging protocolaire.
- **Moteur IDS Avancé** (`ids_engine.py`) : Détection de scans de ports, mouvements latéraux et exfiltration de données.
- **DNS Guard** (`dns_guard.py`) : Filtrage en temps réel via la blacklist mondiale **Abuse.ch (URLHaus)**.
- **Escalade Active** (`escalation.py`) : Système à 3 niveaux (Alerte -> Throttling -> Isolation via Iptables) avec timers asynchrones.
- **Contre-Attaque** (`counter_attack.py`) : Flood TCP, redirection DNS et génération de fausse topologie réseau (ARP).
- **Monitoring Système** (`process_monitor.py`) : Surveillance des processus locaux et connexions via `psutil`.
- **Persistance** (`database.py`) : Stockage de tous les événements dans une base **SQLite** (`mirage_events.db`).

##  Stack Technique
- **Scapy** (Capture & Injection)
- **dnspython** (Analyse DNS profonde)
- **psutil** (Monitoring local)
- **SQLite3** (Timeline des événements)
- **Requests** (Mise à jour des feeds de menaces)

##  Fichiers clés
- `rule_updater.py` : Télécharge 30k+ règles de détection pro.
- `rules.yaml` : Règles de signatures personnalisables.
- `sentinelle_baseline.json` : Profil comportemental du réseau.
