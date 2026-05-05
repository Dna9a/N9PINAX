# scanner/core/port_scan.py
# Scan des ports TCP et détection des services
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import Device, Port, PortState, PortProtocol

# ─────────────────────────────────────────────
# Ports et services connus
# ─────────────────────────────────────────────

# Port → nom du service
# Inclut : FTP, SSH, SMTP/DNS, HTTP(S), NetBIOS/SMB, RDP, bases de données,
# services cloud, brokers de message, conteneurs, VoIP, etc.
COMMON_PORTS: dict[int, str] = {
    # ── Services fondamentaux ────────────────────────
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    # ── Web et proxy ──────────────────────────────────
    80: "HTTP",
    443: "HTTPS",
    3128: "Squid Proxy",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    # ── Mail ──────────────────────────────────────────
    110: "POP3",
    143: "IMAP",
    993: "IMAPS",
    995: "POP3S",
    # ── Windows / SMB / RDP ───────────────────────────
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    # ── Bases de données ──────────────────────────────
    1433: "SQL Server",
    3306: "MySQL",
    5432: "PostgreSQL",
    5984: "CouchDB",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",
    # ── Cache & messaging ─────────────────────────────
    5672: "RabbitMQ",
    6379: "Redis",
    6380: "Redis-alt",
    11211: "Memcached",
    # ── Conteneurs & orchestration ────────────────────
    2375: "Docker",
    2376: "Docker-TLS",
    # ── Kubernetes & infrastructure ───────────────────
    6443: "Kubernetes",
    10250: "Kubelet",
    # ── Elasticearch & monitoring ─────────────────────
    9200: "Elasticsearch",
    9300: "Elasticsearch-node",
    8086: "InfluxDB",
    8089: "Splunk",
    9042: "Cassandra",
    # ── VNC & remote access ──────────────────────────
    5900: "VNC",
    5901: "VNC-alt",
    # ── PPTP & VPN ───────────────────────────────────
    1723: "PPTP",
    500: "IKE",
    # ── Développement & frameworks ───────────────────
    3000: "Node.js",
    5000: "Flask",
    8000: "Dev-server",
    8161: "ActiveMQ",
    # ── Services additionnels ─────────────────────────
    161: "SNMP",
    162: "SNMP-trap",
    389: "LDAP",
    636: "LDAPS",
    1099: "JBoss",
}

# Ports sur lesquels on tente de lire une bannière
BANNER_PORTS: set[int] = {21, 22, 25, 80, 110, 143, 443, 8080, 8443}


# ─────────────────────────────────────────────
# Scan d'un seul port
# ─────────────────────────────────────────────


def _scan_port(ip: str, port: int, timeout: float) -> Port:
    """
    Tente une connexion TCP sur (ip, port).

    Retourne un Port avec :
      - state  OPEN     si connexion réussie
      - state  FILTERED si timeout (pare-feu probable)
      - state  CLOSED   si refus explicite (ECONNREFUSED)
    """
    service = COMMON_PORTS.get(port, "unknown")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((ip, port))

        if result == 0:
            # Port ouvert — tentative de lecture bannière
            banner = _grab_banner(sock, port)

            return Port(
                number=port,
                state=PortState.OPEN,
                protocol=PortProtocol.TCP,
                service=service,
                banner=banner,
                os_hint=_fingerprint_from_banner(banner, service) if banner else None,
            )
        else:
            # Refus explicite = port fermé
            return Port(
                number=port,
                state=PortState.CLOSED,
                protocol=PortProtocol.TCP,
                service=service,
            )

    except socket.timeout:
        # Pas de réponse = filtré (pare-feu probable)
        return Port(
            number=port,
            state=PortState.FILTERED,
            protocol=PortProtocol.TCP,
            service=service,
        )

    except OSError:
        # Autre erreur réseau = on considère filtré
        return Port(
            number=port,
            state=PortState.FILTERED,
            protocol=PortProtocol.TCP,
            service=service,
        )

    finally:
        sock.close()


# ─────────────────────────────────────────────
# Service fingerprinting from banners
# ─────────────────────────────────────────────


def _fingerprint_from_banner(banner: str, service: str) -> str | None:
    """
    Extrait des indices de fingerprinting (OS, version) à partir d'une bannière.

    Exemples:
      - "Apache/2.4.41 (Ubuntu)" → "Ubuntu 20.04 likely"
      - "OpenSSH_7.4" → "CentOS/RHEL 7 likely"
      - "Microsoft-IIS/10.0" → "Windows Server 2016+"

    Args:
        banner: Contenu de la bannière brute.
        service: Nom du service (ex: "HTTP", "SSH").

    Returns:
        Hint de fingerprinting ou None.
    """
    if not banner:
        return None

    # ── SSH fingerprinting ────────────────────────────────────────────────
    if "OpenSSH" in banner:
        if "7.4" in banner:
            return "CentOS/RHEL 7 likely"
        elif "7.6" in banner or "7.9" in banner:
            return "CentOS 7 / RHEL 7 likely"
        elif "8.0" in banner or "8.1" in banner or "8.2" in banner:
            return "CentOS 8 / RHEL 8 / Ubuntu 20.04 likely"
        elif "8.3" in banner or "8.4" in banner:
            return "Ubuntu 20.04 / Debian 11 likely"

    # ── HTTP fingerprinting ───────────────────────────────────────────────
    if "Apache" in banner:
        if "2.4.41" in banner:
            return "Ubuntu 20.04 likely"
        elif "2.4.37" in banner:
            return "CentOS 8 / RHEL 8 likely"
        elif "2.2.15" in banner:
            return "CentOS 6 / RHEL 6 (EOL!)"

    if "IIS/10.0" in banner:
        return "Windows Server 2016 / Windows 10"
    elif "IIS/8.5" in banner:
        return "Windows Server 2012 R2 / Windows 8.1"

    if "nginx" in banner:
        if "1.14" in banner:
            return "Ubuntu 18.04 / Debian 10 likely"
        elif "1.18" in banner:
            return "Ubuntu 20.04 / Debian 11 likely"

    # ── Database fingerprinting ──────────────────────────────────────────
    if service == "MySQL" and "5.7" in banner:
        return "MySQL 5.7 (EOL)"
    elif service == "MySQL" and "8.0" in banner:
        return "MySQL 8.0+ (current)"

    if service == "PostgreSQL" and "9.6" in banner:
        return "PostgreSQL 9.6 (EOL)"

    return None


# ─────────────────────────────────────────────
# Banner grabbing
# ─────────────────────────────────────────────


def _grab_banner(
    sock: socket.socket, port: int, max_bytes: int = 256, banner_timeout: float = 0.2
) -> str | None:
    """
    Tente de lire une bannière sur un socket déjà connecté.

    Seulement sur les ports connus pour envoyer une bannière.
    Retourne None si rien reçu ou port non concerné.

    Args:
        sock:            Socket déjà connecté.
        port:            Numéro du port.
        max_bytes:       Nombre maximum d'octets à lire.
        banner_timeout:  Timeout court pour éviter les ralentissements (défaut 200ms).
    """
    if port not in BANNER_PORTS:
        return None

    # Sauvegarde le timeout original avant d'essayer
    original_timeout = sock.gettimeout()
    try:
        # Réduit temporairement le timeout pour la bannière
        sock.settimeout(banner_timeout)

        # HTTP nécessite une requête pour répondre
        # Pour les ports HTTPS, on effectue un wrapping TLS sur le socket connecté
        conn = sock
        if port in (443, 8443):
            return None  # Bannière TLS difficile à exploiter sans handshake complet

        if port in (80, 8080):
            try:
                sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            except Exception:
                pass

        banner = conn.recv(max_bytes).decode("utf-8", errors="replace").strip()
        # Garde seulement la première ligne (évite les bannières géantes)
        first_line = banner.splitlines()[0] if banner else None
        return first_line[:512] if first_line else None

    except socket.timeout:
        # Timeout bannière, pas grave — le port est quand même ouvert
        return None
    except Exception:
        return None
    finally:
        # Restaure le timeout original
        try:
            if original_timeout is not None:
                sock.settimeout(original_timeout)
        except Exception:
            pass


# ─────────────────────────────────────────────
# Scan d'un Device
# ─────────────────────────────────────────────


def scan_ports(
    device: Device,
    ports: list[int] | None = None,
    timeout: float = 0.5,
    max_workers: int = 50,
    only_open: bool = True,
) -> Device:
    """
    Scanne les ports d'un Device et l'enrichit avec les résultats.

    Args:
        device:      Device à scanner (modifié en place).
        ports:       Liste de ports à tester. Défaut : COMMON_PORTS.
        timeout:     Timeout par port en secondes.
        max_workers: Nombre de threads parallèles.
        only_open:   Si True, n'ajoute que les ports OPEN au Device.
                     Si False, ajoute aussi FILTERED et CLOSED.

    Returns:
        Le même Device enrichi avec ses ports.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    print(f"  [*] Scan ports sur {device.ip} ({len(ports)} ports) ...")

    scanned: list[Port] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(_scan_port, device.ip, p, timeout): p for p in ports
        }
        for future in as_completed(future_to_port):
            try:
                port_result = future.result()
                scanned.append(port_result)
            except Exception as e:
                p = future_to_port[future]
                print(f"  [!] Erreur sur port {p} : {e}")

    # Filtre selon only_open et trie par numéro
    if only_open:
        scanned = [p for p in scanned if p.state == PortState.OPEN]

    scanned.sort(key=lambda p: p.number)

    # Enrichit le Device via add_or_update_port
    for port in scanned:
        device.add_or_update_port(port)

    open_count = device.open_ports_count
    if open_count:
        print(
            f"  [+] {device.ip} — {open_count} port(s) ouvert(s) : "
            f"{[p.number for p in device.get_open_ports()]}"
        )
    else:
        print(f"  [-] {device.ip} — aucun port ouvert détecté")

    return device


# ─────────────────────────────────────────────
# Scan de plusieurs Devices
# ─────────────────────────────────────────────


def scan_all_ports(
    devices: list[Device],
    ports: list[int] | None = None,
    timeout: float = 0.5,
    max_workers: int = 50,
    only_open: bool = True,
) -> list[Device]:
    """
    Lance scan_ports() sur une liste de Device.

    Chaque Device est scanné séquentiellement
    mais ses ports sont scannés en parallèle en interne.

    Args:
        devices:     Liste de Device à enrichir.
        ports:       Ports à tester (défaut : COMMON_PORTS).
        timeout:     Timeout par port.
        max_workers: Threads par Device.
        only_open:   Ne garder que les ports ouverts.

    Returns:
        La même liste de Device enrichie.
    """
    print(f"\n[*] Scan des ports sur {len(devices)} hôte(s) ...\n")

    for device in devices:
        scan_ports(
            device=device,
            ports=ports,
            timeout=timeout,
            max_workers=max_workers,
            only_open=only_open,
        )

    total_open = sum(d.open_ports_count for d in devices)
    print(f"\n[*] Scan terminé — {total_open} port(s) ouvert(s) au total")
    return devices
