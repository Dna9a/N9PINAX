# scanner/fingerprint/dhcp_fingerprint.py
# Identification du type d'appareil via DHCP fingerprinting
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import json
import threading
from pathlib import Path

from scapy.all import IP, UDP, BOOTP, DHCP, sniff, conf

from ..models import Device, FingerprintResult, OSFamily, DeviceType

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

conf.verb = 0

_DHCP_FILE = Path(__file__).parent.parent / "data" / "dhcp_fingerprints.json"
_SNIFF_TIMEOUT = 30  # secondes d'écoute passive


# ─────────────────────────────────────────────
# Base de fingerprints DHCP embarquée
# ─────────────────────────────────────────────
# Format option order : liste des numéros d'options DHCP
# Source : fingerbank.org

_BUILTIN_FINGERPRINTS: list[dict] = [
    {
        "label": "iOS / macOS",
        "options": [1, 121, 3, 6, 15, 119, 252, 95, 44, 46],
        "os_family": "iOS",
        "device_type": "Smartphone",
        "confidence": 0.85,
    },
    {
        "label": "macOS (desktop)",
        "options": [1, 121, 3, 6, 15, 119, 252, 95, 44, 46, 47],
        "os_family": "macOS",
        "device_type": "Laptop",
        "confidence": 0.82,
    },
    {
        "label": "Android",
        "options": [1, 33, 3, 6, 15, 28, 51, 58, 59],
        "os_family": "Android",
        "device_type": "Smartphone",
        "confidence": 0.80,
    },
    {
        "label": "Windows 10 / 11",
        "options": [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
        "os_family": "Windows",
        "device_type": "Desktop",
        "confidence": 0.85,
    },
    {
        "label": "Windows 7",
        "options": [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 249, 252],
        "os_family": "Windows",
        "device_type": "Desktop",
        "confidence": 0.78,
    },
    {
        "label": "Linux (systemd-networkd)",
        "options": [1, 3, 6, 12, 15, 17, 18, 28, 41, 42, 119],
        "os_family": "Linux",
        "device_type": "Server",
        "confidence": 0.75,
    },
    {
        "label": "Linux (dhclient)",
        "options": [1, 28, 2, 3, 15, 6, 12],
        "os_family": "Linux",
        "device_type": "Server",
        "confidence": 0.72,
    },
    {
        "label": "Raspberry Pi (Raspbian)",
        "options": [1, 28, 2, 3, 15, 6, 119, 12],
        "os_family": "Linux",
        "device_type": "IoT Device",
        "confidence": 0.70,
    },
    {
        "label": "Router / Network Device",
        "options": [1, 3, 6],
        "os_family": "Network Device",
        "device_type": "Router",
        "confidence": 0.65,
    },
]


# ─────────────────────────────────────────────
# Chargement
# ─────────────────────────────────────────────


def _load_fingerprints() -> list[dict]:
    """Charge les fingerprints depuis JSON ou utilise les builtin."""
    if _DHCP_FILE.exists():
        try:
            with open(_DHCP_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return _BUILTIN_FINGERPRINTS


# ─────────────────────────────────────────────
# Parsing DHCP
# ─────────────────────────────────────────────


def _extract_dhcp_options(pkt) -> list[int] | None:
    """
    Extrait l'ordre des options DHCP d'un paquet DHCP Discover/Request.

    L'option 55 (Parameter Request List) contient exactement
    la liste des options demandées dans l'ordre — c'est le fingerprint.

    Returns:
        Liste d'entiers (option numbers) ou None si non trouvé.
    """
    if not pkt.haslayer(DHCP):
        return None

    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "param_req_list":
            return list(opt[1])

    return None


def _extract_client_mac(pkt) -> str | None:
    """Extrait l'adresse MAC du client DHCP depuis le champ chaddr."""
    if not pkt.haslayer(BOOTP):
        return None
    try:
        mac_bytes = pkt[BOOTP].chaddr[:6]
        return ":".join(f"{b:02X}" for b in mac_bytes)
    except Exception:
        return None


# ─────────────────────────────────────────────
# Matching
# ─────────────────────────────────────────────


def _match_options(
    observed: list[int], fingerprints: list[dict]
) -> FingerprintResult | None:
    """
    Compare les options DHCP observées avec la base de fingerprints.

    Utilise la similarité de Jaccard pondérée par l'ordre.

    Returns:
        Meilleur FingerprintResult ou None.
    """
    if not observed:
        return None

    best_score = 0.0
    best_fp = None

    observed_set = set(observed)

    for fp in fingerprints:
        expected = fp["options"]
        expected_set = set(expected)

        # Similarité Jaccard : intersection / union
        intersection = len(observed_set & expected_set)
        union = len(observed_set | expected_set)
        jaccard = intersection / union if union else 0.0

        # Bonus si les premières options concordent (ordre)
        order_bonus = 0.0
        for i, opt in enumerate(expected[:5]):
            if i < len(observed) and observed[i] == opt:
                order_bonus += 0.02

        score = fp["confidence"] * jaccard + order_bonus
        score = min(score, 1.0)

        if score > best_score:
            best_score = score
            best_fp = fp

    if best_fp is None or best_score < 0.3:
        return None

    return FingerprintResult(
        os_family=OSFamily(best_fp["os_family"]),
        device_type=DeviceType(best_fp["device_type"]),
        confidence=round(best_score, 2),
        sources={"dhcp": best_fp["label"]},
    )


# ─────────────────────────────────────────────
# Écoute passive
# ─────────────────────────────────────────────

# Stockage des résultats capturés : { mac: FingerprintResult }
_captured: dict[str, FingerprintResult] = {}
_capture_lock = threading.Lock()


def _process_dhcp_packet(pkt) -> None:
    """Callback appelé par Scapy pour chaque paquet DHCP capturé."""
    fingerprints = _load_fingerprints()

    options = _extract_dhcp_options(pkt)
    mac = _extract_client_mac(pkt)

    if not options or not mac:
        return

    result = _match_options(options, fingerprints)
    if result:
        with _capture_lock:
            _captured[mac] = result
        print(f"  [DHCP] {mac} → {result.summary()} ({result.confidence:.0%})")


def start_passive_capture(
    timeout: int = _SNIFF_TIMEOUT, iface: str | None = None
) -> dict[str, FingerprintResult]:
    """
    Écoute passivement le trafic DHCP sur le réseau.

    Capture les DHCP Discover/Request et fingerprinte les appareils
    sans leur envoyer aucun paquet — totalement passif.

    Args:
        timeout: Durée d'écoute en secondes.
        iface:   Interface réseau (None = auto).

    Returns:
        Dict { mac: FingerprintResult } des appareils identifiés.
    """
    global _captured
    _captured = {}

    print(f"[*] Écoute DHCP passive pendant {timeout}s ...")

    sniff(
        filter="udp and (port 67 or port 68)",
        prn=_process_dhcp_packet,
        timeout=timeout,
        iface=iface,
        store=False,
    )

    print(f"[+] {len(_captured)} appareil(s) identifié(s) via DHCP")
    return dict(_captured)


# ─────────────────────────────────────────────
# Enrichissement Device
# ─────────────────────────────────────────────


def enrich_devices(
    devices: list[Device],
    captured: dict[str, FingerprintResult] | None = None,
) -> list[Device]:
    """
    Enrichit les Device avec les fingerprints DHCP capturés.

    Args:
        devices:  Liste de Device à enrichir.
        captured: Résultats de start_passive_capture().
                  Si None, tente une capture de 30s.

    Returns:
        La même liste enrichie.
    """
    if captured is None:
        captured = start_passive_capture()

    for device in devices:
        result = captured.get(device.mac)
        if result is None:
            continue

        if device.fingerprint is None:
            device.fingerprint = result
        else:
            device.fingerprint = device.fingerprint.merge(result)

        print(f"  [+] {device.ip} — DHCP: {result.summary()}")

    return devices
