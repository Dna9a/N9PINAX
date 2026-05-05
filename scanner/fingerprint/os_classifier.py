# scanner/fingerprint/os_classifier.py
# Classificateur OS — combine MAC, TCP, DHCP, HTTP en verdict final
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

from ..models import Device, FingerprintResult, OSFamily, DeviceType

# ─────────────────────────────────────────────
# Règles MAC vendor → OS/Device
# ─────────────────────────────────────────────
# Format : (substring du vendor, os_family, device_type, confidence_bonus)
# Appliqué si le mac_vendor contient la substring

_MAC_RULES: list[tuple[str, str, str, float]] = [
    # ── Apple ─────────────────────────────────────────────────
    ("Apple", "macOS", "Laptop", 0.70),
    ("Apple", "iOS", "Smartphone", 0.60),  # ambigu, TCP précisera
    # ── Phones / Tablets ──────────────────────────────────────
    ("Samsung", "Android", "Smartphone", 0.75),
    ("Xiaomi", "Android", "Smartphone", 0.80),
    ("OnePlus", "Android", "Smartphone", 0.80),
    ("Huawei", "Android", "Smartphone", 0.75),
    ("LG Electronics", "Android", "Smartphone", 0.72),
    ("Motorola", "Android", "Smartphone", 0.75),
    ("Google", "Android", "Smartphone", 0.78),
    # ── PC makers ─────────────────────────────────────────────
    ("Dell", "Windows", "Laptop", 0.65),
    ("Hewlett Packard", "Windows", "Laptop", 0.65),
    ("HP", "Windows", "Laptop", 0.65),
    ("Lenovo", "Windows", "Laptop", 0.65),
    ("ASUSTeK", "Windows", "Desktop", 0.65),
    ("Gigabyte", "Windows", "Desktop", 0.65),
    ("Intel", "Windows", "Desktop", 0.55),  # carte mère Intel
    # ── Linux / SBC ───────────────────────────────────────────
    ("Raspberry Pi", "Linux", "IoT Device", 0.90),
    ("Arduino", "Linux", "IoT Device", 0.85),
    # ── Network devices ───────────────────────────────────────
    ("Cisco", "Network Device", "Router", 0.88),
    ("MikroTik", "Network Device", "Router", 0.90),
    ("Ubiquiti", "Network Device", "Access Point", 0.88),
    ("TP-LINK", "Network Device", "Router", 0.82),
    ("Netgear", "Network Device", "Router", 0.82),
    ("D-Link", "Network Device", "Router", 0.80),
    ("ASUS", "Network Device", "Router", 0.75),
    ("ZyXEL", "Network Device", "Router", 0.85),
    # ── Printers ──────────────────────────────────────────────
    ("Brother", "IoT", "Printer", 0.88),
    ("Canon", "IoT", "Printer", 0.85),
    ("Epson", "IoT", "Printer", 0.85),
    ("Hewlett-Packard", "IoT", "Printer", 0.80),  # imprimantes HP
    # ── Smart devices ─────────────────────────────────────────
    ("Amazon", "IoT", "IoT Device", 0.85),  # Echo, FireTV
    ("Google", "IoT", "IoT Device", 0.80),  # Chromecast, Nest
    ("Sonos", "IoT", "IoT Device", 0.88),
    ("Philips", "IoT", "IoT Device", 0.75),
]


# ─────────────────────────────────────────────
# Règles de raffinement Apple (iOS vs macOS)
# ─────────────────────────────────────────────


def _refine_apple(fp: FingerprintResult) -> FingerprintResult:
    """
    Distingue iOS de macOS pour les devices Apple.

    Utilise les données TCP (window size, options) pour trancher.
    """
    tcp_window = fp.tcp_window or 0
    tcp_options = fp.tcp_options or []

    has_timestamp = "Timestamp" in tcp_options
    has_wscale = "WScale" in tcp_options

    # macOS : window 65535 + timestamp + wscale + beaucoup d'options
    if tcp_window == 65535 and has_timestamp and has_wscale and len(tcp_options) >= 6:
        fp.os_family = OSFamily.MACOS
        fp.device_type = DeviceType.LAPTOP
        fp.os_version = "macOS 10.x+"
        fp.update_confidence(0.05)

    # iOS : window 65535 + timestamp mais moins d'options
    elif tcp_window == 65535 and has_timestamp:
        fp.os_family = OSFamily.IOS
        fp.device_type = DeviceType.SMARTPHONE
        fp.os_version = "iOS 14+"
        fp.update_confidence(0.03)

    return fp


# ─────────────────────────────────────────────
# Classificateur principal
# ─────────────────────────────────────────────


def classify(device: Device) -> FingerprintResult:
    """
    Produit le verdict final de fingerprinting pour un Device.

    Algorithme :
      1. Applique les règles MAC vendor → OS/device de base
      2. Fusionne avec le fingerprint existant (TCP + DHCP + HTTP)
      3. Raffine les cas ambigus (Apple iOS vs macOS)
      4. Calcule la confidence finale selon le nombre de sources

    Args:
        device: Device avec mac_vendor et fingerprint potentiellement remplis.

    Returns:
        FingerprintResult final.
    """
    # ── Étape 1 : règles MAC ──────────────────────────────────
    mac_result = _apply_mac_rules(device.mac_vendor)

    # ── Étape 2 : fusion avec fingerprint existant ────────────
    if device.fingerprint is not None:
        combined = (
            device.fingerprint.merge(mac_result) if mac_result else device.fingerprint
        )
    else:
        combined = mac_result or FingerprintResult()

    # ── Étape 3 : raffinement Apple ───────────────────────────
    if combined.os_family in (OSFamily.IOS, OSFamily.MACOS) or (
        mac_result and "Apple" in device.mac_vendor
    ):
        combined = _refine_apple(combined)

    # ── Étape 4 : bonus de confiance multi-sources ────────────
    n_sources = len(combined.sources)
    if n_sources >= 3:
        combined.update_confidence(+0.10)
    elif n_sources == 2:
        combined.update_confidence(+0.05)

    # ── Étape 5 : applique le vendor MAC dans sources ─────────
    if device.mac_vendor != "Unknown":
        combined.sources["mac"] = device.mac_vendor
        if not combined.device_vendor:
            combined.device_vendor = _short_vendor(device.mac_vendor)

    return combined


def _apply_mac_rules(vendor: str) -> FingerprintResult | None:
    """
    Cherche la première règle MAC qui correspond au vendor.

    Returns:
        FingerprintResult de base ou None si vendor inconnu.
    """
    if not vendor or vendor == "Unknown":
        return None

    vendor_upper = vendor.upper()

    for substring, os_fam, dev_type, conf in _MAC_RULES:
        if substring.upper() in vendor_upper:
            try:
                return FingerprintResult(
                    os_family=OSFamily(os_fam),
                    device_type=DeviceType(dev_type),
                    confidence=conf,
                    sources={"mac_rule": substring},
                )
            except ValueError:
                continue

    # Vendor connu mais pas dans les règles — on sait juste que c'est pas Unknown
    return FingerprintResult(
        os_family=OSFamily.UNKNOWN,
        confidence=0.20,
        sources={"mac": vendor},
    )


def _short_vendor(vendor: str) -> str:
    """
    Retourne une version courte du nom de vendor pour l'affichage.

    Ex: "Apple, Inc." → "Apple"
        "Raspberry Pi Trading Ltd" → "Raspberry Pi"
    """
    # Retire les suffixes légaux courants
    for suffix in [
        ", Inc.",
        " Inc.",
        ", Ltd",
        " Ltd",
        " Trading",
        " Technologies",
        " Co.",
    ]:
        vendor = vendor.replace(suffix, "")
    return vendor.strip()


# ─────────────────────────────────────────────
# Enrichissement Device
# ─────────────────────────────────────────────


def enrich_devices(devices: list[Device]) -> list[Device]:
    """
    Applique classify() sur tous les Device et met à jour leur fingerprint.

    C'est la dernière étape du pipeline de fingerprinting.

    Args:
        devices: Liste de Device après tous les autres modules.

    Returns:
        La même liste avec fingerprint final sur chaque Device.
    """
    print(f"\n[*] Classification OS finale sur {len(devices)} hôte(s) ...\n")

    for device in devices:
        result = classify(device)
        device.fingerprint = result

        print(
            f"  [✓] {device.display_name():<30} "
            f"| {str(result.os_family.value):<16} "
            f"| {str(result.device_type.value):<16} "
            f"| {result.confidence:.0%} "
            f"| sources: {list(result.sources.keys())}"
        )

    return devices
