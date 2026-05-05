# scanner/fingerprint/mac_lookup.py
# Lookup MAC OUI → Vendor mapping
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from ..models import Device, FingerprintResult, OSFamily, DeviceType

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

_OUI_FILE = Path(__file__).parent.parent / "data" / "oui.json"
_OUI_URL = (
    "https://standards-oui.ieee.org/oui/oui.json"  # Fallback: simplified local DB
)


# ─────────────────────────────────────────────
# Embedded minimal OUI database
# ─────────────────────────────────────────────
# Covers major vendors for quick fingerprinting without external fetch

_BUILTIN_OUI: dict[str, str] = {
    # ── Apple ─────────────────────────────────────────────────
    "00:03:93": "Apple",
    "00:04:F2": "Apple",
    "00:05:02": "Apple",
    "00:0D:93": "Apple",
    "00:16:CB": "Apple",
    "00:1A:92": "Apple",
    "00:1E:52": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:F2": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:6C": "Apple",
    "00:25:00": "Apple",
    "00:26:15": "Apple",
    "00:3E:E1": "Apple",
    "2C:00:0D": "Apple",
    "A4:C3:F0": "Apple",
    "AC:BC:32": "Apple",
    "B8:09:8A": "Apple",
    "B8:E8:56": "Apple",
    "D4:6E:0E": "Apple",
    "E8:8D:28": "Apple",
    "F4:5C:89": "Apple",
    "F8:FF:C2": "Apple",
    # ── Samsung ───────────────────────────────────────────────
    "00:1A:8A": "Samsung",
    "00:26:37": "Samsung",
    "00:3E:2D": "Samsung",
    "1C:B7:2C": "Samsung",
    "5C:F3:70": "Samsung",
    "80:35:C1": "Samsung",
    "A0:21:95": "Samsung",
    "B0:7F:B9": "Samsung",
    "C0:84:C7": "Samsung",
    # ── Cisco ────────────────────────────────────────────────
    "00:01:42": "Cisco",
    "00:01:64": "Cisco",
    "00:01:96": "Cisco",
    "00:01:C7": "Cisco",
    "00:02:4A": "Cisco",
    "00:02:7D": "Cisco",
    "00:03:0F": "Cisco",
    "00:03:31": "Cisco",
    "00:03:6B": "Cisco",
    "00:05:5F": "Cisco",
    "00:07:EB": "Cisco",
    "00:0A:41": "Cisco",
    "00:12:43": "Cisco",
    "00:1A:70": "Cisco",
    "00:1B:54": "Cisco",
    "00:1C:0C": "Cisco",
    "00:1E:F7": "Cisco",
    "00:1F:CA": "Cisco",
    "00:21:A0": "Cisco",
    "00:22:55": "Cisco",
    "00:23:04": "Cisco",
    "00:24:97": "Cisco",
    "00:25:B3": "Cisco",
    "00:26:0B": "Cisco",
    "00:26:CA": "Cisco",
    "00:27:13": "Cisco",
    "00:28:23": "Cisco",
    "00:2A:6A": "Cisco",
    "00:2B:01": "Cisco",
    "00:2E:F7": "Cisco",
    "00:30:F2": "Cisco",
    "00:31:26": "Cisco",
    "08:00:07": "Cisco",
    "08:00:20": "Cisco",
    "08:00:21": "Cisco",
    "08:00:22": "Cisco",
    # ── Raspberry Pi ──────────────────────────────────────────
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    # ── TP-Link ───────────────────────────────────────────────
    "00:0F:E2": "TP-Link",
    "18:62:2A": "TP-Link",
    "40:16:3E": "TP-Link",
    "50:C7:BF": "TP-Link",
    "C8:5D:E2": "TP-Link",
    "EC:41:18": "TP-Link",
    # ── Netgear ───────────────────────────────────────────────
    "00:22:B0": "Netgear",
    "1C:C6:3C": "Netgear",
    "20:3D:47": "Netgear",
    "38:B1:DB": "Netgear",
    "54:A0:50": "Netgear",
    "74:6D:FC": "Netgear",
    "AC:29:B8": "Netgear",
    "B0:35:9F": "Netgear",
    "D0:37:45": "Netgear",
    # ── D-Link ────────────────────────────────────────────────
    "00:0B:78": "D-Link",
    "00:0E:FE": "D-Link",
    "00:1A:F1": "D-Link",
    "00:1C:10": "D-Link",
    "00:1D:7E": "D-Link",
    "1C:7E:E5": "D-Link",
    "5C:63:BF": "D-Link",
    "6C:41:6A": "D-Link",
    "74:DA:38": "D-Link",
    # ── Dell ──────────────────────────────────────────────────
    "00:0A:95": "Dell",
    "00:11:43": "Dell",
    "00:1E:4F": "Dell",
    "00:24:E8": "Dell",
    "00:25:B5": "Dell",
    "00:26:B9": "Dell",
    "00:27:D7": "Dell",
    "00:50:F1": "Dell",
    "08:00:69": "Dell",
    # ── HP / Hewlett-Packard ───────────────────────────────────
    "00:00:F0": "Hewlett-Packard",
    "00:01:09": "Hewlett-Packard",
    "00:01:E6": "Hewlett-Packard",
    "00:03:FF": "Hewlett-Packard",
    "00:04:38": "Hewlett-Packard",
    "00:0A:57": "Hewlett-Packard",
    "00:0E:18": "Hewlett-Packard",
    "00:10:DB": "Hewlett-Packard",
    "00:12:79": "Hewlett-Packard",
    "00:14:38": "Hewlett-Packard",
    "00:15:99": "Hewlett-Packard",
    "00:18:71": "Hewlett-Packard",
    "00:1A:4B": "Hewlett-Packard",
    "00:1C:C4": "Hewlett-Packard",
    "00:1D:09": "Hewlett-Packard",
    "00:1E:0B": "Hewlett-Packard",
    "00:21:5A": "Hewlett-Packard",
    "00:22:64": "Hewlett-Packard",
    "00:23:7D": "Hewlett-Packard",
    "00:24:BE": "Hewlett-Packard",
    "00:25:86": "Hewlett-Packard",
    "00:26:55": "Hewlett-Packard",
    "00:26:F6": "Hewlett-Packard",
    "00:1C:2E": "HP",
    "08:00:09": "HP",
    "58:40:4E": "HP",
    "60:EB:69": "HP",
    # ── Lenovo ────────────────────────────────────────────────
    "00:1A:64": "Lenovo",
    "00:21:3C": "Lenovo",
    "00:24:81": "Lenovo",
    "00:25:8C": "Lenovo",
    "08:00:27": "Lenovo",
    "28:47:DA": "Lenovo",
    "54:EE:75": "Lenovo",
    "F0:DE:F1": "Lenovo",
    # ── Google ────────────────────────────────────────────────
    "1C:11:3A": "Google",
    "30:8C:FB": "Google",
    "48:2C:A4": "Google",
    "5A:1C:D6": "Google",
    "64:BC:0C": "Google",
    "7C:7A:91": "Google",
    "E4:F4:C6": "Google",
    "F4:F5:E8": "Google",
    # ── Sony ──────────────────────────────────────────────────
    "00:0E:D8": "Sony",
    "00:1A:79": "Sony",
    "00:24:4B": "Sony",
    "00:25:DF": "Sony",
    "34:27:92": "Sony",
    "98:B6:E9": "Sony",
    # ── Epson ────────────────────────────────────────────────
    "00:05:1F": "Epson",
    "00:11:22": "Epson",
    "00:14:85": "Epson",
    "00:1A:EF": "Epson",
    "08:00:46": "Epson",
    # ── Ubiquiti ──────────────────────────────────────────────
    "00:27:0E": "Ubiquiti",
    "80:2A:A8": "Ubiquiti",
    "A0:2D:6A": "Ubiquiti",
    "B0:E1:AE": "Ubiquiti",
    # ── MikroTik ──────────────────────────────────────────────
    "00:0C:42": "MikroTik",
    "00:21:13": "MikroTik",
    "4C:5E:0C": "MikroTik",
    "6C:3B:6B": "MikroTik",
    # ── ZyXEL ────────────────────────────────────────────────
    "00:13:49": "ZyXEL",
    "00:1A:8A": "ZyXEL",
    "00:20:F6": "ZyXEL",
    "00:23:F8": "ZyXEL",
    "00:50:F2": "ZyXEL",
    # ── Arduino ───────────────────────────────────────────────
    "00:97:97": "Arduino",
    "90:A2:DA": "Arduino",
    # ── Generic fallbacks ─────────────────────────────────────
    "00:00:00": "Generic Device",
    "FF:FF:FF": "Broadcast",
}


# ─────────────────────────────────────────────
# OUI Loading and Caching
# ─────────────────────────────────────────────


def _load_oui_cache() -> dict[str, str]:
    """
    Charge le cache OUI depuis fichier JSON s'il existe.
    Sinon, retourne la base embarquée et tente une mise à jour asynchrone.

    Returns:
        dict { "AA:BB:CC": "Vendor Name" }
    """
    if _OUI_FILE.exists():
        try:
            with open(_OUI_FILE, "r", encoding="utf-8") as f:
                cache = json.load(f)
                if isinstance(cache, dict):
                    return cache
        except Exception:
            pass

    return _BUILTIN_OUI


def _download_oui_database() -> dict[str, str] | None:
    """
    Télécharge la base OUI officielle depuis IEEE (optionnel).
    Peut échouer si pas de connexion — on utilise le fallback embarqué.

    Returns:
        dict ou None si échec.
    """
    try:
        with urllib.request.urlopen(_OUI_URL, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            if isinstance(data, dict):
                # Sauvegarde le cache
                _OUI_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(_OUI_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                return data
    except Exception:
        pass

    return None


# ─────────────────────────────────────────────
# MAC Lookup
# ─────────────────────────────────────────────

_OUI_CACHE: dict[str, str] | None = None


def _get_oui_database() -> dict[str, str]:
    """Retourne la base OUI (cache en mémoire)."""
    global _OUI_CACHE
    if _OUI_CACHE is None:
        _OUI_CACHE = _load_oui_cache()
    return _OUI_CACHE


def mac_to_vendor(mac: str) -> str:
    """
    Convertit une adresse MAC en nom de vendor via OUI lookup.

    Utilise les 3 premiers octets (OUI).
    Retourne "Unknown" si pas trouvé.

    Args:
        mac: Adresse MAC normalisée (AA:BB:CC:DD:EE:FF).

    Returns:
        Nom du vendor ou "Unknown".
    """
    if not mac or len(mac) < 8:
        return "Unknown"

    oui = mac[:8].upper()  # "AA:BB:CC"
    oui_database = _get_oui_database()

    # Essaye le match exact OUI
    vendor = oui_database.get(oui)
    if vendor:
        return vendor

    # Fallback : cherche avec moins de précision (premiers 5 caractères)
    oui_prefix = oui[:5]
    for prefix, name in oui_database.items():
        if prefix.startswith(oui_prefix):
            return name

    return "Unknown"


# ─────────────────────────────────────────────
# Device enrichment
# ─────────────────────────────────────────────


def enrich_devices(devices: list[Device]) -> list[Device]:
    """
    Enrichit chaque Device avec son vendor MAC via lookup OUI.

    Cette fonction est appelée en début du pipeline (après arp_scan).

    Args:
        devices: Liste de Device avec IP et MAC mais sans vendor.

    Returns:
        La même liste enrichie avec mac_vendor.
    """
    print(f"\n[*] MAC OUI lookup sur {len(devices)} device(s) ...\n")

    for device in devices:
        vendor = mac_to_vendor(device.mac)
        device.mac_vendor = vendor
        print(f"  [+] {device.ip:16} | {device.mac} | {vendor}")

    return devices
