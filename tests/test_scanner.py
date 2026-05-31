# tests/test_scanner.py
# Unit tests for risk labelling (scanner.models) and the ScanRequest validator.

import pytest

from backend.schemas import ScanRequest
from scanner.models import (
    Device,
    Port,
    PortProtocol,
    PortState,
    Alert,
    AlertSeverity,
    compute_device_risk,
)


def _device(ports=()):
    return Device(
        ip="192.168.1.10",
        mac="00:11:22:33:44:55",
        ports=[
            Port(number=n, state=PortState.OPEN, protocol=PortProtocol.TCP)
            for n in ports
        ],
    )


# ── Risk label (port heuristic) ──────────────────────────────────────────────
def test_risk_port_23_high():
    assert compute_device_risk(_device([23])) == "high"


def test_risk_port_22_medium():
    assert compute_device_risk(_device([22])) == "medium"


def test_risk_no_ports_low():
    assert compute_device_risk(_device([])) == "low"


def test_risk_method_matches_function():
    d = _device([23])
    assert d.risk_label() == "high"


def test_risk_closed_port_ignored():
    d = Device(
        ip="192.168.1.11",
        mac="00:11:22:33:44:66",
        ports=[Port(number=23, state=PortState.CLOSED, protocol=PortProtocol.TCP)],
    )
    assert compute_device_risk(d) == "low"


# ── Risk label (alert-driven) ────────────────────────────────────────────────
def test_alert_overrides_port_risk():
    d = _device([22])  # port-only -> medium
    crit = Alert(severity=AlertSeverity.CRITICAL, category="x", title="t", ip="192.168.1.10")
    assert compute_device_risk(d, [crit]) == "high"


def test_unrelated_alert_ignored():
    d = _device([22])
    other = Alert(severity=AlertSeverity.CRITICAL, category="x", title="t", ip="10.0.0.9")
    assert compute_device_risk(d, [other]) == "medium"


# ── ScanRequest validator ────────────────────────────────────────────────────
def test_scanrequest_rejects_bad_cidr():
    with pytest.raises(Exception):
        ScanRequest(network="not-a-cidr")


def test_scanrequest_accepts_valid_cidr():
    assert ScanRequest(network="10.0.0.0/24").network == "10.0.0.0/24"


def test_scanrequest_accepts_none():
    assert ScanRequest(network=None).network is None


def test_scanrequest_blank_becomes_none():
    assert ScanRequest(network="   ").network is None
