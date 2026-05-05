# scanner/core/__init__.py
# Core scanning modules — ARP, Port scanning
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

# ─────────────────────────────────────────────
# Port Scanning (safe, no Scapy)
# ─────────────────────────────────────────────

from .port_scan import (
    scan_ports,
    scan_all_ports,
    COMMON_PORTS,
    BANNER_PORTS,
)

# ─────────────────────────────────────────────
# Lazy imports for Scapy-dependent modules
# ─────────────────────────────────────────────

def _import_arp():
    """Lazy import ARP scanning (depends on Scapy)."""
    from .arp_scan import (
        get_local_network,
        arp_scan,
    )
    return get_local_network, arp_scan

def __getattr__(name):
    """Lazy loading of Scapy-dependent modules."""
    if name == "get_local_network":
        get_local_network, _ = _import_arp()
        return get_local_network
    elif name == "arp_scan":
        _, arp_scan = _import_arp()
        return arp_scan
    raise AttributeError(f"module {__name__} has no attribute {name}")

# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

__all__ = [
    # ARP (lazy)
    "get_local_network",
    "arp_scan",
    # Port scan
    "scan_ports",
    "scan_all_ports",
    "COMMON_PORTS",
    "BANNER_PORTS",
]
