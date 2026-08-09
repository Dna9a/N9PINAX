# scanner/fingerprint/os_classifier.py
# Heuristic OS classifier — combines MAC vendor, TCP/IP stack signals,
# DHCP fingerprint, HTTP banners and open-port profile into a single
# confidence-scored verdict.

from __future__ import annotations

import logging
from dataclasses import dataclass

from ..models import Device, FingerprintResult, OSFamily, DeviceType

_log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Heuristic data — kept inline so the module has no run-time dependencies.
# Each rule is a (substring, os_family, device_type, base_confidence) tuple.
# ──────────────────────────────────────────────────────────────────────────────

_MAC_RULES: list[tuple[str, str, str, float]] = [
    # ── Apple ──────────────────────────────────────────────────────
    ("Apple", "macOS", "Laptop", 0.70),
    ("Apple", "iOS", "Smartphone", 0.60),
    # ── Android phones / tablets ───────────────────────────────────
    ("Samsung", "Android", "Smartphone", 0.75),
    ("Xiaomi", "Android", "Smartphone", 0.80),
    ("OnePlus", "Android", "Smartphone", 0.80),
    ("Huawei", "Android", "Smartphone", 0.75),
    ("LG Electronics", "Android", "Smartphone", 0.72),
    ("Motorola", "Android", "Smartphone", 0.75),
    ("Google", "Android", "Smartphone", 0.55),
    ("OPPO", "Android", "Smartphone", 0.75),
    ("Vivo", "Android", "Smartphone", 0.75),
    ("Realme", "Android", "Smartphone", 0.75),
    # ── PC makers ──────────────────────────────────────────────────
    ("Dell", "Windows", "Laptop", 0.65),
    ("Hewlett Packard", "Windows", "Laptop", 0.65),
    ("HP", "Windows", "Laptop", 0.62),
    ("Lenovo", "Windows", "Laptop", 0.65),
    ("ASUSTeK", "Windows", "Desktop", 0.65),
    ("Gigabyte", "Windows", "Desktop", 0.65),
    ("MSI", "Windows", "Desktop", 0.65),
    ("Intel", "Windows", "Desktop", 0.50),
    # ── SBC / IoT Linux ────────────────────────────────────────────
    ("Raspberry Pi", "Linux", "IoT Device", 0.90),
    ("Arduino", "Linux", "IoT Device", 0.85),
    ("Espressif", "Linux", "IoT Device", 0.85),  # ESP32 / ESP8266
    # ── Network devices ────────────────────────────────────────────
    ("Cisco", "Network Device", "Router", 0.88),
    ("MikroTik", "Network Device", "Router", 0.90),
    ("Ubiquiti", "Network Device", "Access Point", 0.88),
    ("TP-LINK", "Network Device", "Router", 0.82),
    ("Netgear", "Network Device", "Router", 0.82),
    ("D-Link", "Network Device", "Router", 0.80),
    ("ASUS", "Network Device", "Router", 0.65),
    ("ZyXEL", "Network Device", "Router", 0.85),
    ("Aruba", "Network Device", "Access Point", 0.85),
    ("Juniper", "Network Device", "Router", 0.88),
    ("Fortinet", "Network Device", "Router", 0.88),
    # ── Printers ───────────────────────────────────────────────────
    ("Brother", "IoT", "Printer", 0.88),
    ("Canon", "IoT", "Printer", 0.85),
    ("Epson", "IoT", "Printer", 0.85),
    ("Hewlett-Packard", "IoT", "Printer", 0.65),
    ("Lexmark", "IoT", "Printer", 0.85),
    ("Xerox", "IoT", "Printer", 0.85),
    # ── Smart devices / IoT ────────────────────────────────────────
    ("Amazon", "IoT", "IoT Device", 0.85),
    ("Sonos", "IoT", "IoT Device", 0.88),
    ("Philips", "IoT", "IoT Device", 0.75),
    ("Nest", "IoT", "IoT Device", 0.85),
    ("Ring", "IoT", "IoT Device", 0.85),
    # ── Virtualisation / Hypervisors ───────────────────────────────
    ("VMware", "Linux", "Server", 0.65),
    ("Microsoft", "Windows", "Server", 0.50),
    ("Xen", "Linux", "Server", 0.60),
    ("Parallels", "macOS", "Laptop", 0.55),
    # ── Smart TVs ──────────────────────────────────────────────────
    ("Roku", "Linux", "Smart TV", 0.85),
    ("Sony", "Linux", "Smart TV", 0.55),
]


# Port-profile heuristics: certain open-port sets are strong indicators of an
# operating system family even when stack signals are inconclusive.
@dataclass(frozen=True)
class _PortHint:
    required: frozenset[int]
    forbidden: frozenset[int]
    os_family: OSFamily
    device_type: DeviceType
    confidence: float
    label: str


_PORT_HINTS: tuple[_PortHint, ...] = (
    # Windows: SMB/RDP/NetBIOS profile
    _PortHint(
        required=frozenset({135, 445}),
        forbidden=frozenset({22}),
        os_family=OSFamily.WINDOWS,
        device_type=DeviceType.DESKTOP,
        confidence=0.70,
        label="Windows SMB/RPC profile",
    ),
    _PortHint(
        required=frozenset({3389}),
        forbidden=frozenset(),
        os_family=OSFamily.WINDOWS,
        device_type=DeviceType.SERVER,
        confidence=0.65,
        label="RDP exposed",
    ),
    # Linux servers
    _PortHint(
        required=frozenset({22, 80}),
        forbidden=frozenset({3389, 445}),
        os_family=OSFamily.LINUX,
        device_type=DeviceType.SERVER,
        confidence=0.55,
        label="SSH+HTTP profile",
    ),
    # Printers
    _PortHint(
        required=frozenset({9100}),
        forbidden=frozenset(),
        os_family=OSFamily.IOT,
        device_type=DeviceType.PRINTER,
        confidence=0.85,
        label="JetDirect port 9100",
    ),
    _PortHint(
        required=frozenset({631}),
        forbidden=frozenset(),
        os_family=OSFamily.LINUX,
        device_type=DeviceType.PRINTER,
        confidence=0.70,
        label="IPP / CUPS port 631",
    ),
    # Routers / network management
    _PortHint(
        required=frozenset({161}),
        forbidden=frozenset({445}),
        os_family=OSFamily.NETWORK_DEVICE,
        device_type=DeviceType.ROUTER,
        confidence=0.65,
        label="SNMP without SMB → likely network device",
    ),
)


# ──────────────────────────────────────────────────────────────────────────────
# Apple iOS vs macOS disambiguation
# ──────────────────────────────────────────────────────────────────────────────


def _refine_apple(fp: FingerprintResult, device: Device) -> FingerprintResult:
    """
    Apple devices share a vendor OUI; we lean on TCP options and open ports
    to tell phones/tablets apart from Macs.
    """
    tcp_window = fp.tcp_window or 0
    tcp_options = fp.tcp_options or []

    has_timestamp = "Timestamp" in tcp_options
    has_wscale = "WScale" in tcp_options

    open_port_numbers = {p.number for p in device.get_open_ports()}
    macos_strong_ports = {22, 88, 548, 631}  # SSH, Kerberos, AFP, CUPS

    looks_like_macos = bool(open_port_numbers & macos_strong_ports) or (
        tcp_window == 65535 and has_timestamp and has_wscale and len(tcp_options) >= 6
    )

    if looks_like_macos:
        fp.os_family = OSFamily.MACOS
        fp.device_type = DeviceType.LAPTOP
        fp.os_version = "macOS 10.x+"
        fp.update_confidence(0.05)
    elif tcp_window == 65535 and has_timestamp:
        fp.os_family = OSFamily.IOS
        fp.device_type = DeviceType.SMARTPHONE
        fp.os_version = "iOS 14+"
        fp.update_confidence(0.03)

    return fp


# ──────────────────────────────────────────────────────────────────────────────
# Top-level classifier
# ──────────────────────────────────────────────────────────────────────────────


def classify(device: Device) -> FingerprintResult:
    """
    Combine every available signal into a final fingerprint.

    Algorithm:
      1. Convert MAC vendor → tentative OS/device.
      2. Merge with any signal already attached (TCP/DHCP/HTTP).
      3. Apply port-profile heuristics.
      4. Refine ambiguous Apple devices.
      5. Boost confidence proportionally to the number of independent sources.
    """
    mac_result = _apply_mac_rules(device.mac_vendor)

    if device.fingerprint is not None:
        combined = (
            device.fingerprint.merge(mac_result) if mac_result else device.fingerprint
        )
    else:
        combined = mac_result or FingerprintResult()

    # Port profile signal
    port_hint = _match_port_profile(device)
    if port_hint is not None:
        combined = combined.merge(port_hint)

    # Apple iOS/macOS disambiguation
    if combined.os_family in (OSFamily.IOS, OSFamily.MACOS) or (
        mac_result and "Apple" in (device.mac_vendor or "")
    ):
        combined = _refine_apple(combined, device)

    # Multi-source bonus
    n_sources = len(combined.sources)
    if n_sources >= 3:
        combined.update_confidence(+0.10)
    elif n_sources == 2:
        combined.update_confidence(+0.05)

    # TTL sanity fallback — corrects gross mismatches when port profile and
    # vendor disagree (e.g. printer with vendor "HP" but TTL 64 → Linux).
    combined = _ttl_sanity_check(combined)

    # Inject vendor into sources for the dashboard
    if device.mac_vendor and device.mac_vendor != "Unknown":
        combined.sources["mac"] = device.mac_vendor
        if not combined.device_vendor:
            combined.device_vendor = _short_vendor(device.mac_vendor)

    return combined


def _apply_mac_rules(vendor: str | None) -> FingerprintResult | None:
    """Return a baseline fingerprint from the MAC vendor string."""
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

    return FingerprintResult(
        os_family=OSFamily.UNKNOWN,
        confidence=0.20,
        sources={"mac": vendor},
    )


def _match_port_profile(device: Device) -> FingerprintResult | None:
    """Return a fingerprint hint inferred from the open-port profile, or None."""
    if not device.ports:
        return None

    open_set = {p.number for p in device.get_open_ports()}
    if not open_set:
        return None

    best: tuple[float, _PortHint] | None = None
    for hint in _PORT_HINTS:
        if hint.required and not hint.required.issubset(open_set):
            continue
        if hint.forbidden and (hint.forbidden & open_set):
            continue
        if best is None or hint.confidence > best[0]:
            best = (hint.confidence, hint)

    if best is None:
        return None

    _, hint = best
    return FingerprintResult(
        os_family=hint.os_family,
        device_type=hint.device_type,
        confidence=hint.confidence,
        sources={"ports": hint.label},
    )


def _ttl_sanity_check(fp: FingerprintResult) -> FingerprintResult:
    """
    Catch obvious contradictions between TTL and OS family.

    Windows hosts always reply with TTL 128 by default; Linux/macOS with 64;
    Cisco/embedded routers with 255. If we have a high-confidence TTL signal
    we shouldn't let a weak MAC rule override it.
    """
    ttl = fp.tcp_ttl
    if ttl is None or ttl <= 0:
        return fp

    # Windows initial TTL is 128, Linux/macOS 64, network gear 255. TTL only
    # decreases with hops, so widen the bands below the initial value to keep
    # correcting gross mismatches even for hosts several hops away (audit
    # F-055) instead of only directly-attached ones.
    family = fp.os_family
    if 40 <= ttl <= 64 and family in (OSFamily.WINDOWS,):
        # Strong contradiction — Linux/macOS, not Windows.
        fp.os_family = OSFamily.LINUX
        fp.sources["ttl_correction"] = f"TTL={ttl} overrides Windows guess"
        fp.update_confidence(-0.10)
    elif 100 <= ttl <= 128 and family in (OSFamily.LINUX, OSFamily.MACOS, OSFamily.IOS):
        fp.os_family = OSFamily.WINDOWS
        fp.sources["ttl_correction"] = f"TTL={ttl} overrides {family.value} guess"
        fp.update_confidence(-0.10)
    elif ttl >= 200 and family in (OSFamily.LINUX, OSFamily.WINDOWS):
        fp.os_family = OSFamily.NETWORK_DEVICE
        fp.device_type = DeviceType.ROUTER
        fp.sources["ttl_correction"] = f"TTL={ttl} suggests router"
        fp.update_confidence(-0.05)

    return fp


def _short_vendor(vendor: str) -> str:
    """Strip noisy legal suffixes from a vendor name for dashboard display."""
    for suffix in [
        ", Inc.",
        " Inc.",
        ", Ltd",
        " Ltd",
        " Trading",
        " Technologies",
        " Co.",
        " Corporation",
        " Corp.",
    ]:
        vendor = vendor.replace(suffix, "")
    return vendor.strip()


# ──────────────────────────────────────────────────────────────────────────────
# Batch enrichment
# ──────────────────────────────────────────────────────────────────────────────


def enrich_devices(devices: list[Device]) -> list[Device]:
    """Apply :func:`classify` to every device, persisting the result in place."""
    print(f"\n[*] Classification OS finale sur {len(devices)} hôte(s) ...\n")

    for device in devices:
        result = classify(device)
        device.fingerprint = result

        print(
            f"  [✓] {device.display_name():<30} "
            f"| {result.os_family.value:<16} "
            f"| {result.device_type.value:<16} "
            f"| {result.confidence:.0%} "
            f"| sources: {list(result.sources.keys())}"
        )

    return devices
