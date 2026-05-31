# scanner/core/__init__.py
# Core scanning modules — ARP, ICMP, SYN, UDP, TCP-connect port scan.

from __future__ import annotations

# ──────────────────────────────────────────────────────────────────────────────
# Pure-socket modules (safe to import — no Scapy required)
# ──────────────────────────────────────────────────────────────────────────────

from .port_scan import (
    scan_ports,
    scan_all_ports,
    COMMON_PORTS,
    BANNER_PORTS,
)
from .udp_scan import (
    udp_scan,
    udp_scan_into_device,
    COMMON_UDP_PORTS,
)

# ──────────────────────────────────────────────────────────────────────────────
# Lazy imports for Scapy-dependent modules
# ──────────────────────────────────────────────────────────────────────────────


def _import_arp():
    from .arp_scan import get_local_network, arp_scan

    return get_local_network, arp_scan


def _import_icmp():
    from .icmp_scan import icmp_sweep, enrich_devices as icmp_enrich

    return icmp_sweep, icmp_enrich


def _import_syn():
    from .syn_scan import syn_scan, syn_scan_into_device

    return syn_scan, syn_scan_into_device


def __getattr__(name):
    if name == "get_local_network":
        return _import_arp()[0]
    if name == "arp_scan":
        return _import_arp()[1]
    if name == "icmp_sweep":
        return _import_icmp()[0]
    if name == "icmp_enrich":
        return _import_icmp()[1]
    if name == "syn_scan":
        return _import_syn()[0]
    if name == "syn_scan_into_device":
        return _import_syn()[1]
    raise AttributeError(f"module {__name__} has no attribute {name}")


__all__ = [
    # ARP (lazy)
    "get_local_network",
    "arp_scan",
    # ICMP (lazy)
    "icmp_sweep",
    "icmp_enrich",
    # SYN (lazy)
    "syn_scan",
    "syn_scan_into_device",
    # TCP connect
    "scan_ports",
    "scan_all_ports",
    "COMMON_PORTS",
    "BANNER_PORTS",
    # UDP
    "udp_scan",
    "udp_scan_into_device",
    "COMMON_UDP_PORTS",
]
