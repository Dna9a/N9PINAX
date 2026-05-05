# scanner/fingerprint/__init__.py
# Fingerprinting modules — MAC OUI, TCP, DHCP, HTTP, OS classification
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

# ─────────────────────────────────────────────
# MAC OUI Lookup (safe to import, no Scapy)
# ─────────────────────────────────────────────

from .mac_lookup import (
    mac_to_vendor,
    enrich_devices as mac_enrich,
)

# ─────────────────────────────────────────────
# Lazy imports for Scapy-dependent modules
# ─────────────────────────────────────────────

def _import_tcp():
    """Lazy import TCP fingerprinting (depends on Scapy)."""
    from .tcp_fingerprint import (
        tcp_fingerprint,
        enrich_devices as tcp_enrich,
    )
    return tcp_fingerprint, tcp_enrich

def _import_dhcp():
    """Lazy import DHCP fingerprinting (depends on Scapy)."""
    from .dhcp_fingerprint import (
        start_passive_capture,
        enrich_devices as dhcp_enrich,
    )
    return start_passive_capture, dhcp_enrich

def _import_http():
    """Lazy import HTTP banner (depends on Scapy)."""
    from .http_banner import (
        http_banner,
        enrich_devices as http_enrich,
    )
    return http_banner, http_enrich

def _import_classifier():
    """Lazy import OS classifier (safe, no Scapy)."""
    from .os_classifier import (
        classify,
        enrich_devices as classifier_enrich,
    )
    return classify, classifier_enrich

def __getattr__(name):
    """Lazy loading of Scapy-dependent modules."""
    if name == "tcp_fingerprint":
        tcp_fingerprint, _ = _import_tcp()
        return tcp_fingerprint
    elif name == "tcp_enrich":
        _, tcp_enrich = _import_tcp()
        return tcp_enrich
    elif name == "start_passive_capture":
        start_passive_capture, _ = _import_dhcp()
        return start_passive_capture
    elif name == "dhcp_enrich":
        _, dhcp_enrich = _import_dhcp()
        return dhcp_enrich
    elif name == "http_banner":
        http_banner, _ = _import_http()
        return http_banner
    elif name == "http_enrich":
        _, http_enrich = _import_http()
        return http_enrich
    elif name == "classify":
        classify, _ = _import_classifier()
        return classify
    elif name == "classifier_enrich":
        _, classifier_enrich = _import_classifier()
        return classifier_enrich
    raise AttributeError(f"module {__name__} has no attribute {name}")

# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

__all__ = [
    # MAC OUI
    "mac_to_vendor",
    "mac_enrich",
    # TCP (lazy)
    "tcp_fingerprint",
    "tcp_enrich",
    # DHCP (lazy)
    "start_passive_capture",
    "dhcp_enrich",
    # HTTP (lazy)
    "http_banner",
    "http_enrich",
    # OS Classification
    "classify",
    "classifier_enrich",
]
