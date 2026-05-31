# scanner/report.py
# Generates / appends the human-readable + machine-parsable scan_report.txt.
#
# The file mixes:
#   1. A pretty header that a human can read in `cat`/`less`.
#   2. A single JSON line per scan (prefixed with ``#JSON ``) so any dashboard
#      can stream-parse the file without writing a YACC-style parser.
#
# This dual format is intentional: the project mandates a single
# ``scan_report.txt`` artefact while still being trivially machine-parsable.

from __future__ import annotations

import json
import logging
import os
import stat
from datetime import timezone
from pathlib import Path

from .alerts import severity_rank
from .config import get_config
from .models import ScanResult

_log = logging.getLogger(__name__)

_HEADER_LINE = "═" * 78
_SECTION_LINE = "─" * 78
_JSON_PREFIX = "#JSON "


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────


def append_scan(scan: ScanResult, path: Path | None = None) -> Path:
    """
    Append a single scan to ``scan_report.txt``, returning the path written to.

    The function is append-only — historical reports are never overwritten.
    """
    cfg = get_config()
    target = Path(path) if path else cfg.report_path
    target.parent.mkdir(parents=True, exist_ok=True)

    pretty = _format_pretty(scan)
    machine = _JSON_PREFIX + json.dumps(_to_compact_dict(scan), ensure_ascii=False)

    payload = f"{pretty}\n{machine}\n"

    with open(target, "a", encoding="utf-8") as f:
        f.write(payload)

    # Tighten permissions on first write — reports can contain hostnames and
    # internal IPs that shouldn't be world-readable.
    try:
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    except OSError:
        pass

    return target


def parse_reports(path: Path | None = None) -> list[dict]:
    """Return the list of machine-readable JSON records stored in the report."""
    cfg = get_config()
    target = Path(path) if path else cfg.report_path
    if not target.exists():
        return []

    out: list[dict] = []
    try:
        with open(target, "r", encoding="utf-8") as f:
            for line in f:
                if not line.startswith(_JSON_PREFIX):
                    continue
                try:
                    out.append(json.loads(line[len(_JSON_PREFIX) :].strip()))
                except json.JSONDecodeError:
                    continue
    except OSError as e:
        _log.warning("Failed to read %s: %s", target, e)
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _to_compact_dict(scan: ScanResult) -> dict:
    """Compact JSON-friendly representation suitable for SSE / dashboards."""
    return {
        "scan_id": scan.scan_id,
        "timestamp": scan.timestamp.astimezone(timezone.utc).isoformat(),
        "network": scan.network,
        "total_hosts": scan.total_hosts,
        "duration_seconds": round(scan.duration_seconds, 3),
        "devices": [
            {
                "ip": d.ip,
                "mac": d.mac,
                "hostname": d.hostname,
                "vendor": d.mac_vendor,
                "os_family": (
                    d.fingerprint.os_family.value if d.fingerprint else "Unknown"
                ),
                "os_version": d.fingerprint.os_version if d.fingerprint else None,
                "device_type": (
                    d.fingerprint.device_type.value if d.fingerprint else "Unknown"
                ),
                "confidence": d.fingerprint.confidence if d.fingerprint else 0.0,
                "latency_ms": d.latency_ms,
                "open_ports": [
                    {
                        "number": p.number,
                        "protocol": p.protocol.value,
                        "service": p.service,
                        "banner": p.banner,
                    }
                    for p in d.get_open_ports()
                ],
                "is_online": d.is_online,
            }
            for d in scan.devices
        ],
        "alerts": [a.to_json() for a in scan.alerts],
    }


def _format_pretty(scan: ScanResult) -> str:
    lines: list[str] = []
    lines.append(_HEADER_LINE)
    lines.append(f"  SCAN  {scan.scan_id}")
    lines.append(f"  When  {scan.timestamp.isoformat(timespec='seconds')}")
    lines.append(f"  CIDR  {scan.network}")
    lines.append(
        f"  Stats {scan.total_hosts} hosts | "
        f"{sum(d.open_ports_count for d in scan.devices)} open ports | "
        f"{len(scan.alerts)} alerts | {scan.duration_seconds:.2f}s"
    )
    lines.append(_HEADER_LINE)

    if scan.devices:
        lines.append(
            f"  {'IP':<15} {'MAC':<18} {'Vendor':<18} {'OS':<14} {'Conf':<5} Ports"
        )
        lines.append(_SECTION_LINE)
        for d in sorted(scan.devices, key=lambda x: _sort_ip(x.ip)):
            os_name = d.fingerprint.os_family.value if d.fingerprint else "Unknown"
            conf = f"{int(d.fingerprint.confidence * 100)}%" if d.fingerprint else "0%"
            ports = ",".join(str(p.number) for p in d.get_open_ports()[:8])
            if d.open_ports_count > 8:
                ports += f",+{d.open_ports_count - 8}"
            lines.append(
                f"  {d.ip:<15} {d.mac:<18} {_truncate(d.mac_vendor, 18):<18} "
                f"{_truncate(os_name, 14):<14} {conf:<5} {ports}"
            )

    if scan.alerts:
        lines.append("")
        lines.append("  ALERTS")
        lines.append(_SECTION_LINE)
        for alert in sorted(scan.alerts, key=lambda a: -severity_rank(a.severity)):
            lines.append(
                f"  [{alert.severity.value.upper():<8}] {alert.title}"
                + (f"  ({alert.ip})" if alert.ip else "")
            )
    return "\n".join(lines)


def _sort_ip(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (0,)


def _truncate(s: str | None, n: int) -> str:
    if not s:
        return "-"
    return s if len(s) <= n else s[: n - 1] + "…"


__all__ = ["append_scan", "parse_reports"]
