# scanner/core/arp_scan.py
# Découverte des hôtes actifs via ARP (couche 2)
# Nécessite : sudo / CAP_NET_RAW
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import os
import re
import socket
import subprocess

from scapy.all import ARP, Ether, srp

from ..models import Device


def _has_raw_socket_access() -> bool:
    """Return True if this process can use raw sockets.

    Root (UID 0) always qualifies. Non-root processes qualify when they hold
    CAP_NET_RAW in their effective capability set — which Docker grants via
    ``cap_add: NET_RAW`` even when the container runs as a non-root user.
    Falls back to False if the capability bitmask cannot be read (non-Linux).
    """
    if os.geteuid() == 0:
        return True
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split(":", 1)[1].strip(), 16)
                    return bool(cap_eff & (1 << 13))  # CAP_NET_RAW = bit 13
    except OSError:
        pass
    return False

# ─────────────────────────────────────────────
# Network detection
# ─────────────────────────────────────────────

# IP prefixes that are never real LAN routes.
# Covers the full 172.16-31.x.x range Docker allocates for bridge networks.
_EXCLUDED_PREFIXES = (
    "169.254.",       # link-local (APIPA)
    "127.",           # loopback
    "::1",            # IPv6 loopback
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)

# Interface name prefixes that belong to Docker / virtual networking.
# Routes via these interfaces are never the real LAN even when their IP
# falls outside the excluded prefix list above.
_EXCLUDED_IFACES = ("docker", "br-", "veth", "virbr", "vmnet", "vboxnet")


def get_local_network() -> str:
    """
    Détecte le réseau LAN actif via `ip route show`.

    Filtre les routes Docker, link-local et loopback — par préfixe IP
    ET par nom d'interface virtuelle.
    Retourne ex: "192.168.1.0/24"

    Raises:
        RuntimeError: si aucun réseau LAN valide n'est détecté.
    """
    try:
        result = subprocess.run(
            ["ip", "route", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        raise RuntimeError("Commande `ip` introuvable. Êtes-vous sur Linux ?")
    except subprocess.TimeoutExpired:
        raise RuntimeError("`ip route show` a expiré.")

    if result.returncode != 0:
        raise RuntimeError(f"`ip route show` a échoué : {result.stderr.strip()}")

    candidates = []

    for line in result.stdout.splitlines():
        # Look for lines with a CIDR, e.g. "192.168.1.0/24 dev wlan0 ..."
        match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not match:
            continue

        cidr = match.group(1)

        # Skip non-LAN IP ranges
        if any(cidr.startswith(prefix) for prefix in _EXCLUDED_PREFIXES):
            continue

        # Skip virtual/Docker interfaces regardless of their IP range
        if any(f"dev {iface}" in line for iface in _EXCLUDED_IFACES):
            continue

        # Prefer routes that have a local src IP (active/connected routes)
        priority = 0 if "src" in line else 1
        candidates.append((priority, cidr))

    if not candidates:
        # Fallback: Detect IP by attempting to connect to a public IP (doesn't send data)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Assume /24 for the local LAN if route parsing fails
            return f"{local_ip.rsplit('.', 1)[0]}.0/24"
        except Exception:
            raise RuntimeError(
                "Aucun réseau LAN détecté automatiquement par `ip route` ou fallback.\n"
                "Passez le réseau manuellement : arp_scan('192.168.x.x/24')"
            )

    # Retourne le meilleur candidat (priorité la plus basse = meilleur)
    candidates.sort(key=lambda x: x[0])
    return candidates[0][1]


# ─────────────────────────────────────────────
# ARP Scan
# ─────────────────────────────────────────────


def arp_scan(
    network: str | None = None,
    timeout: int = 2,
    resolve_hostnames: bool = False,
) -> list[Device]:
    """
    Scanne le réseau local via ARP et retourne les hôtes actifs.

    Args:
        network:           Plage CIDR à scanner (ex: '192.168.1.0/24').
                           Si None, détecté automatiquement.
        timeout:           Secondes d'attente pour les réponses ARP.
        resolve_hostnames: Si True, résout les hostnames en parallèle.
                           Désactivé par défaut (ralentit le scan).

    Returns:
        Liste de Device { ip, mac, hostname } prêts à être enrichis.

    Raises:
        PermissionError: si Scapy n'a pas les droits raw socket.
        RuntimeError:    si la détection réseau échoue.
    """
    if not _has_raw_socket_access():
        raise PermissionError(
            "Scan ARP requires root privileges (sudo) or CAP_NET_RAW capability."
        )

    if network is None:
        network = get_local_network()

    print(f"[*] Scan ARP sur {network} ...")

    # ── Construction du paquet ────────────────────────────────
    ethernet = Ether(dst="ff:ff:ff:ff:ff:ff")  # broadcast Ethernet
    arp = ARP(pdst=network)  # "qui a ces IPs ?"
    paquet = ethernet / arp

    # ── Envoi et réception ────────────────────────────────────
    try:
        reponses, _ = srp(paquet, timeout=timeout, verbose=0)
    except PermissionError:
        raise PermissionError(
            "Scapy nécessite les droits raw socket.\n"
            "Lancez avec sudo ou ajoutez CAP_NET_RAW au container."
        )
    except Exception as e:
        raise RuntimeError(f"Erreur Scapy lors du scan ARP : {e}")

    # ── Extraction des résultats ──────────────────────────────
    devices: list[Device] = []
    ips_found: list[str] = []

    for _, recu in reponses:
        ip = recu[ARP].psrc  # IP source de la réponse
        mac = recu[Ether].src  # MAC source de la réponse

        try:
            device = Device(ip=ip, mac=mac)
            devices.append(device)
            ips_found.append(ip)
        except Exception as e:
            # Si Pydantic rejette l'IP ou le MAC, on log et on continue
            print(f"  [!] Device ignoré ({ip} / {mac}) : {e}")
            continue

    # ── Résolution DNS optionnelle ────────────────────────────
    if resolve_hostnames and devices:
        # Use the bounded-timeout, persistent-cache module instead of the old
        # bare socket.gethostbyaddr calls that could block indefinitely.
        from ..fingerprint.hostname import enrich_devices as _enrich_hostnames

        _enrich_hostnames(devices)

    # ── Affichage ─────────────────────────────────────────────
    for d in devices:
        print(f"  [+] {d.ip:16} | {d.mac} | {d.hostname}")

    print(f"[*] {len(devices)} hôte(s) découvert(s) sur {network}")
    return devices
