# scanner/alerts.py
# Lightweight rule-based alert engine.
#
# The engine inspects a finished :class:`ScanResult` against a list of small,
# composable rules and emits :class:`Alert` objects. Rules are intentionally
# simple — no inference, no ML — so the scanner stays predictable, auditable,
# and runs in microseconds even on hundreds of hosts.

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable

from .models import (
    Alert,
    AlertSeverity,
    Device,
    ScanResult,
)

_log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Catalogue of risky ports / services
# ──────────────────────────────────────────────────────────────────────────────

# Ports/services that should rarely be exposed on a normal LAN.
# severity = level if seen open.
_RISKY_PORT_RULES: dict[int, tuple[AlertSeverity, str]] = {
    21: (AlertSeverity.MEDIUM, "FTP exposed (cleartext credentials)"),
    23: (AlertSeverity.HIGH, "Telnet exposed (cleartext, deprecated)"),
    25: (AlertSeverity.LOW, "SMTP relay exposed"),
    111: (AlertSeverity.MEDIUM, "Sun RPC portmapper exposed"),
    135: (AlertSeverity.HIGH, "Windows MSRPC exposed"),
    139: (AlertSeverity.HIGH, "NetBIOS-SSN exposed"),
    445: (AlertSeverity.HIGH, "SMB exposed — historical SMB1/EternalBlue risk"),
    1433: (AlertSeverity.HIGH, "MS-SQL Server exposed"),
    1521: (AlertSeverity.HIGH, "Oracle DB exposed"),
    2375: (AlertSeverity.CRITICAL, "Docker daemon API exposed without TLS"),
    3306: (AlertSeverity.MEDIUM, "MySQL exposed"),
    3389: (AlertSeverity.CRITICAL, "RDP exposed — top brute-force target"),
    5900: (AlertSeverity.HIGH, "VNC exposed (often passwordless)"),
    5984: (AlertSeverity.MEDIUM, "CouchDB exposed"),
    6379: (AlertSeverity.HIGH, "Redis exposed (auth often disabled)"),
    9200: (AlertSeverity.HIGH, "Elasticsearch exposed (default = no auth)"),
    11211: (AlertSeverity.MEDIUM, "Memcached exposed"),
    27017: (AlertSeverity.HIGH, "MongoDB exposed (default = no auth)"),
}


# Services for which a cleartext protocol upgrade should be flagged (banner-based).
_BANNER_RED_FLAGS: tuple[tuple[str, AlertSeverity, str], ...] = (
    ("PHP/5.", AlertSeverity.HIGH, "End-of-life PHP 5.x — multiple unpatched CVEs"),
    ("Apache/2.2", AlertSeverity.HIGH, "End-of-life Apache 2.2 series"),
    ("nginx/1.0", AlertSeverity.HIGH, "End-of-life Nginx 1.0 series"),
    ("OpenSSH_4.", AlertSeverity.HIGH, "Very old OpenSSH 4.x — multiple CVEs"),
    ("OpenSSH_5.", AlertSeverity.MEDIUM, "Old OpenSSH 5.x — review patches"),
    ("Microsoft-IIS/6", AlertSeverity.CRITICAL, "IIS 6 — unsupported, multiple CVEs"),
    ("Microsoft-IIS/7", AlertSeverity.HIGH, "IIS 7 — unsupported on most platforms"),
)


# ──────────────────────────────────────────────────────────────────────────────
# Rule helpers
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Rule:
    name: str
    check: Callable[[Device, ScanResult], Iterable[Alert]]


def _alerts_for_risky_ports(device: Device, scan: ScanResult) -> Iterable[Alert]:
    for port in device.get_open_ports():
        rule = _RISKY_PORT_RULES.get(port.number)
        if not rule:
            continue
        severity, description = rule
        yield Alert(
            scan_id=scan.scan_id,
            severity=severity,
            category="risky_port",
            title=f"{port.service or 'service'} on {port.number} exposed",
            description=f"{description}. Host: {device.ip} ({device.mac_vendor}).",
            ip=device.ip,
            mac=device.mac,
            port=port.number,
            service=port.service,
        )


def _alerts_for_banner_red_flags(device: Device, scan: ScanResult) -> Iterable[Alert]:
    for port in device.get_open_ports():
        if not port.banner:
            continue
        for needle, severity, description in _BANNER_RED_FLAGS:
            if needle in port.banner:
                yield Alert(
                    scan_id=scan.scan_id,
                    severity=severity,
                    category="service_risk",
                    title=f"End-of-life software on {device.ip}:{port.number}",
                    description=(f"{description}. Banner: {port.banner[:200]}"),
                    ip=device.ip,
                    mac=device.mac,
                    port=port.number,
                    service=port.service,
                )
                break  # one alert per port is enough


def _alerts_for_unknown_vendor(device: Device, scan: ScanResult) -> Iterable[Alert]:
    """Unknown vendor + open ports often means a rogue device on the LAN."""
    if device.mac_vendor not in ("Unknown", "Locally Administered (Randomized)"):
        return
    open_count = device.open_ports_count
    if open_count == 0:
        return
    severity = AlertSeverity.HIGH if open_count >= 3 else AlertSeverity.MEDIUM
    yield Alert(
        scan_id=scan.scan_id,
        severity=severity,
        category="unknown_host",
        title=f"Unidentified device on {device.ip} with {open_count} open port(s)",
        description=(
            f"Vendor lookup returned '{device.mac_vendor}'. "
            "Verify the device is authorised on this network."
        ),
        ip=device.ip,
        mac=device.mac,
    )


def _alerts_for_admin_telnet_combo(device: Device, scan: ScanResult) -> Iterable[Alert]:
    """Telnet + SMB or RDP on the same host is a textbook misconfiguration."""
    open_set = {p.number for p in device.get_open_ports()}
    if 23 in open_set and (445 in open_set or 3389 in open_set):
        yield Alert(
            scan_id=scan.scan_id,
            severity=AlertSeverity.CRITICAL,
            category="dangerous_combo",
            title=f"Telnet + admin protocol on {device.ip}",
            description=(
                "Telnet exposes credentials in cleartext while SMB/RDP exposes "
                "administrative interfaces. Compromise is trivial when both run "
                "on the same host."
            ),
            ip=device.ip,
            mac=device.mac,
        )


_RULES: tuple[_Rule, ...] = (
    _Rule("risky_ports", _alerts_for_risky_ports),
    _Rule("banner_red_flags", _alerts_for_banner_red_flags),
    _Rule("unknown_vendor", _alerts_for_unknown_vendor),
    _Rule("admin_telnet_combo", _alerts_for_admin_telnet_combo),
)


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────


def evaluate(scan: ScanResult) -> list[Alert]:
    """Run every rule against the scan and return the resulting alerts."""
    out: list[Alert] = []
    for device in scan.devices:
        for rule in _RULES:
            try:
                for alert in rule.check(device, scan):
                    out.append(alert)
            except Exception as e:
                _log.exception("Alert rule %s failed: %s", rule.name, e)
    return out


def evaluate_diff(
    new_scan: ScanResult,
    previous_devices_by_mac: dict[str, Device],
) -> list[Alert]:
    """
    Compare against the previous scan and emit alerts for net-new hosts or
    net-new open ports (so an analyst sees the *change*, not just the state).
    """
    out: list[Alert] = []
    for device in new_scan.devices:
        prev = previous_devices_by_mac.get(device.mac)
        if prev is None:
            out.append(
                Alert(
                    scan_id=new_scan.scan_id,
                    severity=AlertSeverity.MEDIUM,
                    category="new_host",
                    title=f"New device joined the network: {device.ip}",
                    description=(
                        f"MAC {device.mac} ({device.mac_vendor}) was not present "
                        "in the previous scan."
                    ),
                    ip=device.ip,
                    mac=device.mac,
                )
            )
            continue
        prev_open = {p.number for p in prev.get_open_ports()}
        for port in device.get_open_ports():
            if port.number not in prev_open:
                out.append(
                    Alert(
                        scan_id=new_scan.scan_id,
                        severity=AlertSeverity.LOW,
                        category="new_open_port",
                        title=(
                            f"Port {port.number}/{port.protocol.value} newly open "
                            f"on {device.ip}"
                        ),
                        description=(
                            f"Service '{port.service}' was not exposed in the "
                            "previous scan; verify this change is intentional."
                        ),
                        ip=device.ip,
                        mac=device.mac,
                        port=port.number,
                        service=port.service,
                    )
                )
    return out


def severity_rank(s: AlertSeverity) -> int:
    """Return a numeric rank for sorting alerts by severity."""
    return {
        AlertSeverity.LOW: 0,
        AlertSeverity.MEDIUM: 1,
        AlertSeverity.HIGH: 2,
        AlertSeverity.CRITICAL: 3,
    }[s]


__all__ = ["evaluate", "evaluate_diff", "severity_rank"]
