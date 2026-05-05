# scanner/fingerprint/tcp_fingerprint.py
# Fingerprinting OS via analyse de la stack TCP/IP
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import json
from pathlib import Path

from scapy.all import IP, TCP, ICMP, sr1, conf

from ..models import Device, FingerprintResult, OSFamily, DeviceType

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

conf.verb = 0  # Silence Scapy

_SIGNATURES_FILE = Path(__file__).parent.parent / "data" / "tcp_signatures.json"

_PROBE_TIMEOUT = 2  # secondes


# ─────────────────────────────────────────────
# Signatures TCP embarquées
# ─────────────────────────────────────────────
# Utilisées si tcp_signatures.json absent
# Format : { ttl_range, window, options_pattern, os_family, os_version, device_type, confidence }

_BUILTIN_SIGNATURES: list[dict] = [
    # ── Windows ──────────────────────────────────────────────
    {
        "ttl_min": 120,
        "ttl_max": 128,
        "window": 65535,
        "options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp"],
        "os_family": "Windows",
        "os_version": "Windows 10 / 11",
        "device_type": "Desktop",
        "confidence": 0.80,
    },
    {
        "ttl_min": 120,
        "ttl_max": 128,
        "window": 8192,
        "options": ["MSS", "NOP", "WScale"],
        "os_family": "Windows",
        "os_version": "Windows 7 / Server 2008",
        "device_type": "Desktop",
        "confidence": 0.75,
    },
    {
        "ttl_min": 120,
        "ttl_max": 128,
        "window": 65535,
        "options": [],
        "os_family": "Windows",
        "os_version": "Windows XP / 2003",
        "device_type": "Desktop",
        "confidence": 0.70,
    },
    # ── Linux ─────────────────────────────────────────────────
    {
        "ttl_min": 56,
        "ttl_max": 64,
        "window": 29200,
        "options": ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"],
        "os_family": "Linux",
        "os_version": "Linux 4.x / 5.x",
        "device_type": "Server",
        "confidence": 0.82,
    },
    {
        "ttl_min": 56,
        "ttl_max": 64,
        "window": 65535,
        "options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp"],
        "os_family": "Linux",
        "os_version": "Linux 3.x",
        "device_type": "Server",
        "confidence": 0.72,
    },
    # ── macOS ─────────────────────────────────────────────────
    {
        "ttl_min": 56,
        "ttl_max": 64,
        "window": 65535,
        "options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SAckOK", "EOL"],
        "os_family": "macOS",
        "os_version": "macOS 10.x+",
        "device_type": "Laptop",
        "confidence": 0.78,
    },
    # ── iOS ───────────────────────────────────────────────────
    {
        "ttl_min": 56,
        "ttl_max": 64,
        "window": 65535,
        "options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp"],
        "os_family": "iOS",
        "os_version": "iOS 14+",
        "device_type": "Smartphone",
        "confidence": 0.70,
    },
    # ── Android ───────────────────────────────────────────────
    {
        "ttl_min": 56,
        "ttl_max": 64,
        "window": 29200,
        "options": ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"],
        "os_family": "Android",
        "os_version": "Android 8+",
        "device_type": "Smartphone",
        "confidence": 0.68,
    },
    # ── Network devices (routeurs, switches) ──────────────────
    {
        "ttl_min": 250,
        "ttl_max": 255,
        "window": 4096,
        "options": [],
        "os_family": "Network Device",
        "os_version": "Cisco IOS / RouterOS",
        "device_type": "Router",
        "confidence": 0.85,
    },
    {
        "ttl_min": 250,
        "ttl_max": 255,
        "window": 65535,
        "options": ["MSS"],
        "os_family": "Network Device",
        "os_version": "Embedded Linux (OpenWRT)",
        "device_type": "Router",
        "confidence": 0.80,
    },
]


# ─────────────────────────────────────────────
# Chargement signatures
# ─────────────────────────────────────────────


def _load_signatures() -> list[dict]:
    """Charge les signatures depuis fichier JSON ou utilise les builtin."""
    if _SIGNATURES_FILE.exists():
        try:
            with open(_SIGNATURES_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return _BUILTIN_SIGNATURES


# ─────────────────────────────────────────────
# Probes réseau
# ─────────────────────────────────────────────


def _probe_tcp_syn(ip: str, port: int = 80) -> dict | None:
    """
    Envoie un paquet TCP SYN et analyse la réponse SYN-ACK.

    Extrait : TTL, window size, options TCP.

    Returns:
        dict { ttl, window, options } ou None si pas de réponse.
    """
    pkt = IP(dst=ip) / TCP(
        dport=port,
        flags="S",
        options=[
            ("MSS", 1460),
            ("NOP", None),
            ("WScale", 6),
            ("NOP", None),
            ("NOP", None),
            ("Timestamp", (0, 0)),
        ],
    )

    resp = sr1(pkt, timeout=_PROBE_TIMEOUT, verbose=0)

    if resp is None:
        return None

    if not resp.haslayer(TCP):
        return None

    tcp_layer = resp[TCP]

    # Extrait les noms des options TCP
    options = []
    for opt in tcp_layer.options:
        name = opt[0] if isinstance(opt[0], str) else str(opt[0])
        options.append(name)

    return {
        "ttl": resp[IP].ttl,
        "window": tcp_layer.window,
        "options": options,
    }


def _probe_icmp(ip: str) -> dict | None:
    """
    Envoie un ping ICMP et mesure le TTL de la réponse.

    Returns:
        dict { ttl, icmp_response } ou None si pas de réponse.
    """
    pkt = IP(dst=ip) / ICMP()
    resp = sr1(pkt, timeout=_PROBE_TIMEOUT, verbose=0)

    if resp is None:
        return {"ttl": None, "icmp_response": False}

    return {
        "ttl": resp[IP].ttl,
        "icmp_response": True,
    }


# ─────────────────────────────────────────────
# Matching signatures
# ─────────────────────────────────────────────


def _options_similarity(observed: list[str], expected: list[str]) -> float:
    """
    Calcule un score de similarité entre les options TCP observées
    et celles d'une signature.

    Score entre 0.0 et 1.0 :
      1.0 = correspondance exacte
      0.0 = aucune correspondance
    """
    if not expected:
        # Signature sans options → match si l'observé est vide aussi
        return 1.0 if not observed else 0.5

    if not observed:
        return 0.0

    matches = sum(1 for opt in expected if opt in observed)
    return matches / len(expected)


def _match_signatures(probe: dict, signatures: list[dict]) -> FingerprintResult | None:
    """
    Compare les données TCP observées avec la base de signatures.

    Retourne le meilleur match ou None.
    """
    ttl = probe.get("ttl", 0) or 0
    window = probe.get("window", 0) or 0
    options = probe.get("options", [])

    best_score = 0.0
    best_sig = None

    for sig in signatures:
        # TTL dans la plage ?
        if not (sig["ttl_min"] <= ttl <= sig["ttl_max"]):
            continue

        score = sig["confidence"]

        # Window size
        if window == sig["window"]:
            score += 0.10
        elif abs(window - sig["window"]) < 4096:
            score += 0.05

        # Options TCP
        opt_score = _options_similarity(options, sig["options"])
        score += opt_score * 0.15

        # Clamp
        score = min(score, 1.0)

        if score > best_score:
            best_score = score
            best_sig = sig

    if best_sig is None:
        return None

    return FingerprintResult(
        os_family=OSFamily(best_sig["os_family"]),
        os_version=best_sig["os_version"],
        device_type=DeviceType(best_sig["device_type"]),
        confidence=round(best_score, 2),
        tcp_ttl=ttl,
        tcp_window=window,
        tcp_options=options,
        sources={"tcp": f"TTL={ttl}, Win={window}"},
    )


# ─────────────────────────────────────────────
# Fonction principale
# ─────────────────────────────────────────────


def tcp_fingerprint(
    device: Device, ports: list[int] | None = None
) -> FingerprintResult:
    """
    Fingerprinte l'OS d'un Device via TCP SYN + ICMP.

    Essaie plusieurs ports si le premier ne répond pas.

    Args:
        device: Device à analyser.
        ports:  Ports à tester pour le SYN probe (défaut: 80, 443, 22).

    Returns:
        FingerprintResult avec os_family, os_version, confidence.
    """
    if ports is None:
        ports = [80, 443, 22, 8080]

    signatures = _load_signatures()

    print(f"  [*] TCP fingerprint sur {device.ip} ...")

    # ── Probe TCP SYN ─────────────────────────────────────────
    tcp_data = None
    for port in ports:
        tcp_data = _probe_tcp_syn(device.ip, port)
        if tcp_data:
            break

    # ── Probe ICMP ────────────────────────────────────────────
    icmp_data = _probe_icmp(device.ip)

    # ── Fusion TTL ────────────────────────────────────────────
    # Si TCP SYN n'a pas répondu, utilise le TTL ICMP
    if tcp_data is None and icmp_data and icmp_data.get("ttl"):
        tcp_data = {
            "ttl": icmp_data["ttl"],
            "window": 0,
            "options": [],
        }

    # ── Résultat si aucune réponse ────────────────────────────
    if tcp_data is None:
        print(f"  [-] {device.ip} — aucune réponse TCP/ICMP")
        return FingerprintResult(
            os_family=OSFamily.UNKNOWN,
            icmp_response=False,
            sources={"tcp": "no response"},
        )

    # ── Matching ──────────────────────────────────────────────
    result = _match_signatures(tcp_data, signatures)

    if result is None:
        # TTL connu mais aucun match précis
        ttl = tcp_data["ttl"]
        result = FingerprintResult(
            os_family=_ttl_to_os_family(ttl),
            confidence=0.40,
            tcp_ttl=ttl,
            tcp_window=tcp_data.get("window"),
            tcp_options=tcp_data.get("options"),
            icmp_response=icmp_data.get("icmp_response") if icmp_data else None,
            sources={"tcp": f"TTL={ttl} (match approximatif)"},
        )
    else:
        result.icmp_response = icmp_data.get("icmp_response") if icmp_data else None

    print(f"  [+] {device.ip} — {result}")
    return result


def _ttl_to_os_family(ttl: int) -> OSFamily:
    """Déduit l'OS family depuis le TTL seul (fallback)."""
    if ttl >= 250:
        return OSFamily.NETWORK_DEVICE
    elif ttl >= 120:
        return OSFamily.WINDOWS
    elif ttl >= 56:
        return OSFamily.LINUX
    return OSFamily.UNKNOWN


# ─────────────────────────────────────────────
# Enrichissement Device
# ─────────────────────────────────────────────


def enrich_devices(
    devices: list[Device], ports: list[int] | None = None
) -> list[Device]:
    """
    Lance tcp_fingerprint() sur une liste de Device.

    Si un Device a déjà un fingerprint (depuis mac_lookup),
    fusionne les résultats via FingerprintResult.merge().

    Args:
        devices: Liste de Device à enrichir.
        ports:   Ports à sonder.

    Returns:
        La même liste enrichie.
    """
    print(f"\n[*] TCP fingerprinting sur {len(devices)} hôte(s) ...\n")

    for device in devices:
        tcp_result = tcp_fingerprint(device, ports)

        if device.fingerprint is None:
            device.fingerprint = tcp_result
        else:
            device.fingerprint = device.fingerprint.merge(tcp_result)

    return devices
