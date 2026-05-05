# scanner/core/arp_scan.py
# Découverte des hôtes actifs via ARP (couche 2)
# Nécessite : sudo / CAP_NET_RAW
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import socket
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

from scapy.all import Ether, ARP, srp

from ..models import Device

# ─────────────────────────────────────────────
# Network detection
# ─────────────────────────────────────────────

# Routes à ignorer — pas le vrai LAN
_EXCLUDED_PREFIXES = (
    "169.254.",  # link-local
    "172.17.",  # Docker bridge par défaut
    "172.18.",
    "172.19.",
    "127.",  # loopback
    "::1",  # IPv6 loopback
)


def get_local_network() -> str:
    """
    Détecte le réseau LAN actif via `ip route show`.

    Filtre les routes Docker, link-local et loopback.
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
        # On cherche les lignes avec un CIDR ex: "192.168.1.0/24 dev eth0 ..."
        match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not match:
            continue

        cidr = match.group(1)

        # Filtre les routes non-LAN
        if any(cidr.startswith(prefix) for prefix in _EXCLUDED_PREFIXES):
            continue

        # Préfère les routes avec "src" (route active avec IP locale)
        priority = 0 if "src" in line else 1
        candidates.append((priority, cidr))

    if not candidates:
        raise RuntimeError(
            "Aucun réseau LAN détecté automatiquement. "
            "Passez le réseau manuellement : arp_scan('192.168.x.x/24')"
        )

    # Retourne le meilleur candidat (priorité la plus basse = meilleur)
    candidates.sort(key=lambda x: x[0])
    return candidates[0][1]


# ─────────────────────────────────────────────
# Hostname resolution (optionnel, threadé)
# ─────────────────────────────────────────────


@lru_cache(maxsize=512)
def _resolve_hostname(ip: str) -> str:
    """
    Résout un hostname via reverse DNS avec cache LRU.

    Cache jusqu'à 512 résolutions pour éviter les doublons.
    Retourne 'unknown' si échec.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "unknown"


def _resolve_hostnames_parallel(
    ips: list[str], max_workers: int = 20
) -> dict[str, str]:
    """
    Résout plusieurs hostnames en parallèle via ThreadPoolExecutor.

    Retourne un dict { ip: hostname }.
    """
    results: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(_resolve_hostname, ip): ip for ip in ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            results[ip] = future.result()

    return results


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
    if resolve_hostnames and ips_found:
        print(f"[*] Résolution DNS pour {len(ips_found)} hôte(s) ...")
        hostname_map = _resolve_hostnames_parallel(ips_found)
        for device in devices:
            device.hostname = hostname_map.get(device.ip, "unknown")

    # ── Affichage ─────────────────────────────────────────────
    for d in devices:
        print(f"  [+] {d.ip:16} | {d.mac} | {d.hostname}")

    print(f"[*] {len(devices)} hôte(s) découvert(s) sur {network}")
    return devices
