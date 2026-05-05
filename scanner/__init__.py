# scanner/__init__.py
# Package initialization — Network Security Scanner
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "ABIED Youssef, EL-BARAZI Meriem"
__description__ = "Comprehensive Network Security Scanner with OS Fingerprinting"

# ─────────────────────────────────────────────
# Core models (safe to import)
# ─────────────────────────────────────────────

from .models import (
    Device,
    Port,
    PortState,
    PortProtocol,
    FingerprintResult,
    OSFamily,
    DeviceType,
    ScanResult,
)

# ─────────────────────────────────────────────
# Storage and persistence (safe to import)
# ─────────────────────────────────────────────

from .storage import (
    init_db,
    save_scan,
    load_scan,
    load_last_scan,
    list_scans,
    get_diff,
    export_json,
    export_csv,
)

# ─────────────────────────────────────────────
# Lazy imports for Scapy-dependent modules
# ─────────────────────────────────────────────

def _import_main():
    """Lazy import main module (depends on Scapy)."""
    from .main import run_scan, print_scan_summary, list_all_scans
    return run_scan, print_scan_summary, list_all_scans

def __getattr__(name):
    """Lazy loading of Scapy-dependent modules."""
    if name in ("run_scan", "print_scan_summary", "list_all_scans"):
        run_scan, print_scan_summary, list_all_scans = _import_main()
        globals()[name] = {
            "run_scan": run_scan,
            "print_scan_summary": print_scan_summary,
            "list_all_scans": list_all_scans,
        }.get(name)
        return globals()[name]
    raise AttributeError(f"module {__name__} has no attribute {name}")

# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

__all__ = [
    # Models
    "Device",
    "Port",
    "PortState",
    "PortProtocol",
    "FingerprintResult",
    "OSFamily",
    "DeviceType",
    "ScanResult",
    # Main scanner (lazy-loaded)
    "run_scan",
    "print_scan_summary",
    "list_all_scans",
    # Storage
    "init_db",
    "save_scan",
    "load_scan",
    "load_last_scan",
    "list_scans",
    "get_diff",
    "export_json",
    "export_csv",
]
