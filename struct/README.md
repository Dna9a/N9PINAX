projet/
├── scanner/          # Dna9a (Python/Scapy)
├── server/           # Dbvonie (Flask)
├── frontend/         # Dbvonie (HTML/CSS/JS)
├── database/         # Partagé
├── Makefile
└── README.md


## Phase 1 — Le Scanner (Dna9a commence ici)
```
C'est le cœur du projet. L'ordre logique :
```
### Étape 1.1 — ARP Scan (découverte des hôtes)
```
Envoie un paquet ARP broadcast → qui répond = actif
Résultat : liste de { IP, MAC }
```
### Étape 1.2 — Lookup OUI (MAC → Fabricant)
```
Télécharge la base IEEE (fichier .txt gratuit)
Lis les 3 premiers octets du MAC → cherche le fabricant
Ex: A4:C3:F0 → Apple Inc.
```
### Étape 1.3 — Port Scan
```
Pour chaque IP trouvée → tente connexion TCP sur ports communs
[22, 80, 443, 21, 23, 3306, 8080...]
Résultat : { port: 80, état: ouvert, service: HTTP }
```
### Étape 1.4 — Détection de pare-feu
```
Si le port répond ICMP "port unreachable" → filtré
Si timeout → possiblement filtré par firewall
```
### Étape 1.5 — Sauvegarde JSON/SQLite
```
Chaque scan → sauvegardé avec timestamp
Comparaison avec scan précédent → détection de changements
```

## Phase 2 — Le Serveur Flask (Dbvonie commence ici)

### Étape 2.1 — API REST de base
```
GET  /api/scan/start    → lance le scanner
GET  /api/scan/results  → retourne les résultats JSON
GET  /api/history       → historique des scans
```

### Étape 2.2 — Authentification
```
POST /auth/login   → vérifie mdp avec bcrypt → crée session
POST /auth/logout  → détruit la session
```

### Étape 2.3 — Sécurisation (cybersécurité ici)
```
- Input validation sur tous les paramètres reçus
- Rate limiting : max 10 req/min par IP
- CSRF token sur les formulaires
- Sessions avec expiration automatique
```

### Étape 2.4 — WebSocket (temps réel)
```
Flask-SocketIO → pousse les résultats live au dashboard
Pas besoin de polling toutes les X secondes
```

## Phase 3 — Le Frontend (Dbvonie)

Dans cet ordre :
```
Page login (simple, sécurisée)
Dashboard principal (tableau des devices)
Graphiques live (Chart.js ou ApexCharts)
Système de notifications (badge / toast quand nouveau device)
Export CSV/JSON
```

## Phase 4 — Intégration
```
C'est là que scanner + serveur + frontend se parlent :
Scanner Python → écrit en base → Flask lit la base
Flask → pousse via WebSocket → Frontend reçoit et affiche
```

## Phase 5 — Sécurité & Tests
```
Tester les injections sur l'interface web
Tester le rate limiting (script qui spam les requêtes)
Vérifier que le scanner tourne sans droits root inutiles
Documenter tout dans le README
```

**⚡ Par où commencer concrètement ?**

- **Dna9a** — commence par l'ARP scan (environ 50 lignes avec Scapy)
    - teste-le et vérifie qu'il fonctionne sur ton réseau

- **Dbvonie** — commence par l'authentification Flask avec bcrypt
    - créer une route protégée et une page HTML de login basique

Une fois que les deux parties fonctionnent séparément, connectez-les :
- le scanner écrit les résultats en base
- le serveur Flask lit la base et expose l'API / WebSocket