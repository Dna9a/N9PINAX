Sommaire
Introduction générale ................................................... 1

Chapitre I — Contexte et problématique
    1.1   Présentation du projet .............................................. 3
    1.2   Problématique de sécurité des réseaux locaux ................... 4
    1.3   Objectifs du PFE ........................................................ 5
    1.4   Périmètre et limites du projet ......................................... 6

Chapitre II — État de l'art et revue de littérature
    2.1   La reconnaissance réseau et ses enjeux de sécurité .............. 8
    2.2   Outils existants : Nmap, Angry IP Scanner, Netdiscover ........ 9
    2.3   Positionnement de notre solution ...................................... 11

Chapitre III — Conception de l'architecture sécurisée
    3.1   Architecture générale du système ..................................... 13
    3.2   Modélisation des menaces (Threat Modeling) ........................ 14
    3.3   Choix technologiques justifiés par la sécurité ...................... 16
        3.3.1   Python / Scapy pour la couche réseau .......................... 16
        3.3.2   Flask avec sécurisation applicative .............................. 17

Chapitre IV — Implémentation du scanner réseau
    4.1   Découverte d'hôtes par ARP (couche 2) .............................. 19
    4.2   Scan de ports et identification des services ......................... 20
    4.3   Identification des constructeurs via lookup OUI/MAC ............. 21
    4.4   Gestion des privilèges système et isolation de l'exécution ....... 22

Chapitre V — Sécurisation de la plateforme web
    5.1   Authentification et gestion des sessions ............................. 24
        5.1.1   Hachage des mots de passe avec bcrypt ......................... 24
        5.1.2   OAuth GitHub comme alternative sécurisée ..................... 25
    5.2   Validation et assainissement des entrées .............................. 26
    5.3   Limitation du débit (Rate Limiting) ..................................... 27
    5.4   Protection des données de scan stockées .............................. 28
    5.5   Communication sécurisée (HTTPS / TLS) .............................. 29

Chapitre VI — Interface et visualisation des résultats
    6.1   Tableau de bord et présentation des données ....................... 31
    6.2   Historique des scans et suivi des changements ...................... 32
    6.3   Export des résultats (CSV / JSON) ...................................... 33

Chapitre VII — Tests et évaluation de la sécurité
    7.1   Tests fonctionnels du scanner .......................................... 35
    7.2   Tests de pénétration de l'interface web ............................... 36
    7.3   Analyse des vulnérabilités résiduelles ................................. 37

Conclusion et perspectives ................................................ 39
Bibliographie / Webographie .............................................. 41
Annexes ...................................................................... 43