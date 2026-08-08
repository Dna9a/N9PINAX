# scanner/config.py
# Centralized runtime configuration for the SIEM scanner.
# Values can be overridden via environment variables for production deployments
# without touching the code (12-factor style).

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

_PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
_DATA_DIR: Final[Path] = Path(__file__).resolve().parent / "data"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class ScannerConfig:
    """Read-only configuration snapshot for the scanner runtime."""

    project_root: Path = _PROJECT_ROOT
    data_dir: Path = _DATA_DIR

    db_path: Path = field(
        default_factory=lambda: Path(
            os.environ.get("SCANNER_DB_PATH") or (_DATA_DIR / "scans.db")
        )
    )
    report_path: Path = field(
        default_factory=lambda: Path(
            os.environ.get("SCANNER_REPORT_PATH") or (_PROJECT_ROOT / "scan_report.txt")
        )
    )
    log_path: Path = field(
        default_factory=lambda: Path(
            os.environ.get("SCANNER_LOG_PATH") or (_PROJECT_ROOT / "scanner.log")
        )
    )

    # Networking ────────────────────────────────────────────────────────────
    default_network: str = os.environ.get("SCANNER_DEFAULT_NETWORK", "")
    port_timeout: float = field(
        default_factory=lambda: _env_float("SCANNER_PORT_TIMEOUT", 0.5)
    )
    arp_timeout: float = field(
        default_factory=lambda: _env_float("SCANNER_ARP_TIMEOUT", 2.0)
    )
    icmp_timeout: float = field(
        default_factory=lambda: _env_float("SCANNER_ICMP_TIMEOUT", 1.0)
    )
    syn_timeout: float = field(
        default_factory=lambda: _env_float("SCANNER_SYN_TIMEOUT", 1.5)
    )
    udp_timeout: float = field(
        default_factory=lambda: _env_float("SCANNER_UDP_TIMEOUT", 2.0)
    )
    dns_timeout: float = field(
        default_factory=lambda: _env_float("SCANNER_DNS_TIMEOUT", 1.0)
    )

    # Concurrency ───────────────────────────────────────────────────────────
    max_workers_ports: int = field(
        default_factory=lambda: _env_int("SCANNER_MAX_WORKERS_PORTS", 50)
    )
    max_workers_hosts: int = field(
        default_factory=lambda: _env_int("SCANNER_MAX_WORKERS_HOSTS", 16)
    )
    max_workers_dns: int = field(
        default_factory=lambda: _env_int("SCANNER_MAX_WORKERS_DNS", 20)
    )

    # Rate-limiting ─────────────────────────────────────────────────────────
    # Packets / probes per second per host. Prevents the scanner from being
    # mistaken for a malicious flood by IDS / firewalls.
    rate_limit_pps: int = field(
        default_factory=lambda: _env_int("SCANNER_RATE_LIMIT_PPS", 500)
    )

    # Retries ───────────────────────────────────────────────────────────────
    max_retries: int = field(default_factory=lambda: _env_int("SCANNER_MAX_RETRIES", 1))

    # API server ────────────────────────────────────────────────────────────
    # Bind to loopback by default so a local run is NOT exposed to the whole
    # LAN (the dashboard ships with default credentials). Set
    # SCANNER_API_HOST=0.0.0.0 to deliberately expose it; the Docker image does
    # exactly that, since the container is meant to serve the LAN.
    api_host: str = os.environ.get("SCANNER_API_HOST", "127.0.0.1")
    api_port: int = field(default_factory=lambda: _env_int("SCANNER_API_PORT", 8000))
    api_rate_limit_per_minute: int = field(
        default_factory=lambda: _env_int("SCANNER_API_RATE_PER_MIN", 60)
    )
    api_cors_origins: tuple[str, ...] = tuple(
        s.strip()
        for s in os.environ.get("SCANNER_API_CORS", "*").split(",")
        if s.strip()
    )

    # Behaviour toggles ─────────────────────────────────────────────────────
    enable_alerts: bool = field(
        default_factory=lambda: _env_bool("SCANNER_ALERTS", True)
    )
    enable_async_dns: bool = field(
        default_factory=lambda: _env_bool("SCANNER_ASYNC_DNS", True)
    )
    enable_dhcp: bool = field(default_factory=lambda: _env_bool("SCANNER_DHCP", False))

    # Persistence ───────────────────────────────────────────────────────────
    keep_last_n_scans: int = field(
        default_factory=lambda: _env_int("SCANNER_KEEP_LAST_N_SCANS", 200)
    )

    def ensure_dirs(self) -> None:
        """Create data dirs if they do not exist yet."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.parent.mkdir(parents=True, exist_ok=True)


# Module-level singleton — most callers should use this.
CONFIG: Final[ScannerConfig] = ScannerConfig()


def get_config() -> ScannerConfig:
    """Return the active configuration object."""
    return CONFIG
