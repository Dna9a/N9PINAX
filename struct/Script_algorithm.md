```markdown
projet/
├── scanner/          # Dna9a (Python/Scapy)
├── server/           # Dbvonie (Flask)
├── frontend/         # Dbvonie (HTML/CSS/JS)
├── database/         # Partagé
├── Makefile
└── README.md

scanner/
├── main.py              # Point d'entrée — lance le scan complet
├── arp_scan.py          # Étape 1.1 — découverte des hôtes
├── oui_lookup.py        # Étape 1.2 — MAC → Fabricant
├── port_scan.py         # Étape 1.3 — scan des ports
├── firewall_detect.py   # Étape 1.4 — détection pare-feu
├── storage.py           # Étape 1.5 — sauvegarde JSON/SQLite
├── models.py            # Structure des données (dataclasses)
└── data/
    └── oui.txt          # Base IEEE téléchargée une fois

## Algo de chaque fichier

### models.py — Commence par ici
```text
C'est la structure de données que tout le projet va partager. Définit ce qu'est un "Device" :
Device:
  - ip          (str)
  - mac         (str)
  - vendor      (str)        ← depuis OUI lookup
  - hostname    (str)        ← optionnel, reverse DNS
  - ports       (list)       ← liste de ports ouverts
  - is_online   (bool)
  - first_seen  (datetime)
  - last_seen   (datetime)

Port:
  - number      (int)
  - state       (str)        ← "open" / "filtered" / "closed"
  - service     (str)        ← "HTTP" / "SSH" / "unknown"
```

### arp_scan.py — Le cœur du scanner
```text
Comment fonctionne ARP :
Toi (192.168.1.x)  →  broadcast "Qui a l'IP 192.168.1.1 ?"
Routeur            →  "C'est moi, mon MAC est AA:BB:CC:DD:EE:FF"
Algo :
ENTRÉE : réseau cible (ex: "192.168.1.0/24")

1. Crée un paquet ARP "who-has" pour toutes les IPs du réseau
2. Enveloppe dans un paquet Ethernet broadcast (FF:FF:FF:FF:FF:FF)
3. Envoie le paquet et attend les réponses (timeout: 2s)
4. Pour chaque réponse reçue :
     → extraire IP source
     → extraire MAC source
     → créer un objet Device
5. Retourner la liste de Device

SORTIE : liste de Device { ip, mac }
Ce que tu vas utiliser dans Scapy :
pythonEther(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")
srp(paquet, timeout=2, verbose=False)
```

### oui_lookup.py — MAC → Fabricant
```text
Comment fonctionne OUI :
MAC address : A4:C3:F0:12:34:56
                ↑↑↑↑↑↑
             OUI (3 premiers octets) → identifie le fabricant
             A4:C3:F0 = Apple Inc.
Algo :
SETUP (une seule fois au démarrage) :
1. Télécharge le fichier IEEE depuis :
   https://standards-oui.ieee.org/oui/oui.txt
2. Parse le fichier ligne par ligne
3. Construit un dictionnaire :
   { "A4C3F0": "Apple Inc.", "3C5AB4": "Google LLC", ... }
4. Sauvegarde en cache local (data/oui.txt)

LOOKUP (à chaque appel) :
ENTRÉE : adresse MAC (ex: "A4:C3:F0:12:34:56")

1. Nettoie le MAC → retire ":" → majuscules → "A4C3F012 3456"
2. Prend les 6 premiers caractères → "A4C3F0"
3. Cherche dans le dictionnaire
4. Si trouvé → retourne le nom du fabricant
5. Sinon → retourne "Unknown"

SORTIE : string (nom du fabricant)
```

### port_scan.py — Détection des services
```text
Algo :
ENTRÉE : ip (str), liste de ports à scanner

PORTS COMMUNS À SCANNER :
  21   → FTP
  22   → SSH
  23   → Telnet (dangereux si ouvert)
  25   → SMTP
  53   → DNS
  80   → HTTP
  110  → POP3
  443  → HTTPS
  445  → SMB (Windows)
  3306 → MySQL
  3389 → RDP (Windows Remote Desktop)
  8080 → HTTP alternatif
  8443 → HTTPS alternatif

POUR CHAQUE PORT :
1. Crée une socket TCP
2. Fixe un timeout court (0.5s)
3. Tente connect(ip, port)
4. Si connexion réussie  → port OUVERT → ajouter au Device
5. Si timeout           → port FILTRÉ (pare-feu probable)
6. Si refus (ECONNREFUSED) → port FERMÉ
7. Ferme la socket

OPTIMISATION : utilise threading pour scanner plusieurs ports
               en parallèle (sinon trop lent)

SORTIE : liste de Port { number, state, service }
```

### firewall_detect.py — Détection de filtrage
```text
Algo :
ENTRÉE : ip (str)

MÉTHODE 1 — TTL analysis :
1. Envoie un paquet ICMP (ping)
2. Regarde le TTL de la réponse
   TTL ≈ 64  → Linux/Mac
   TTL ≈ 128 → Windows
   TTL ≈ 255 → Routeur/Switch
   Pas de réponse → possible filtrage ICMP

MÉTHODE 2 — Port behavior :
1. Si port répond "filtered" sur beaucoup de ports
   → probablement derrière un firewall

SORTIE : dict {
  "icmp_blocked": bool,
  "ttl": int,
  "os_guess": str,       ← "Linux", "Windows", "Network device"
  "firewall_suspected": bool
}
```

### storage.py — Sauvegarde des résultats
```text
Algo :
STRUCTURE SQLite (simple, pas besoin de serveur) :

Table "scans" :
  id          INTEGER PRIMARY KEY
  timestamp   DATETIME
  network     TEXT          ← "192.168.1.0/24"
  total_hosts INTEGER

Table "devices" :
  id          INTEGER PRIMARY KEY
  scan_id     INTEGER       ← lié à "scans"
  ip          TEXT
  mac         TEXT
  vendor      TEXT
  hostname    TEXT
  is_online   BOOLEAN
  first_seen  DATETIME
  last_seen   DATETIME

Table "ports" :
  id          INTEGER PRIMARY KEY
  device_id   INTEGER       ← lié à "devices"
  number      INTEGER
  state       TEXT
  service     TEXT

FONCTIONS À ÉCRIRE :
  save_scan(devices)     → insère un nouveau scan
  get_last_scan()        → retourne le dernier scan
  get_diff(scan1, scan2) → retourne les nouveaux/disparus devices
  export_json(scan_id)   → exporte en JSON
  export_csv(scan_id)    → exporte en CSV
```

### main.py — Le chef d'orchestre
```text
Algo :
1. Parse les arguments CLI :
     --network  "192.168.1.0/24"   (défaut: auto-détecte)
     --ports    "22,80,443"        (défaut: liste commune)
     --output   "json" | "sqlite"

2. Vérifie les permissions (Scapy a besoin de raw sockets)
   → si pas root : affiche erreur claire et quitte

3. Lance arp_scan()
   → affiche progression

4. Pour chaque device trouvé :
     → lance oui_lookup()
     → lance port_scan()     (en threads)
     → lance firewall_detect()

5. Sauvegarde via storage.save_scan()

6. Compare avec le scan précédent
   → affiche les nouveaux devices
   → affiche les devices disparus

7. Affiche le résumé final
```

## ⚡ Ordre de développement recommandé

```text
Jour 1 → models.py + arp_scan.py
          → teste : python main.py --network 192.168.1.0/24
          → tu dois voir la liste des IPs/MACs de ton réseau WSL

Jour 2 → oui_lookup.py
          → télécharge oui.txt, parse, teste sur quelques MACs

Jour 3 → port_scan.py
          → teste sur une seule IP d'abord, puis threading

Jour 4 → firewall_detect.py + storage.py
          → sauvegarde un scan, relis-le

Jour 5 → main.py qui relie tout
          → premier scan complet fonctionnel ✅
```

## ⚠️ Note importante WSL

```text
Scapy a besoin de raw sockets — dans WSL tu devras lancer avec :
bashsudo python main.py
Et installer la dépendance réseau :
bashsudo apt install python3-scapy
# ou
pip install scapy
```