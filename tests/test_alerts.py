"""Harsh unit tests for scanner.alerts engine."""

import pytest
from scanner.models import (
    Alert,
    AlertSeverity,
    Device,
    Port,
    PortState,
    ScanResult,
)
from scanner.alerts import (
    _alerts_for_risky_ports,
    _alerts_for_banner_red_flags,
)


@pytest.fixture
def base_scan():
    return ScanResult(network="192.168.1.0/24")


def test_risky_port_level_critical(base_scan):
    # RDP (3389) is critical
    dev = Device(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:01",
        ports=[Port(number=3389, state=PortState.OPEN, service="ms-wbt-server")],
    )
    alerts = list(_alerts_for_risky_ports(dev, base_scan))
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL
    assert "3389" in alerts[0].title


def test_risky_port_ignored_if_closed(base_scan):
    dev = Device(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:01",
        ports=[Port(number=3389, state=PortState.CLOSED)],
    )
    alerts = list(_alerts_for_risky_ports(dev, base_scan))
    assert len(alerts) == 0


def test_multiple_risky_ports(base_scan):
    dev = Device(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:01",
        ports=[
            Port(number=21, state=PortState.OPEN, service="ftp"),
            Port(number=23, state=PortState.OPEN, service="telnet"),
        ],
    )
    alerts = list(_alerts_for_risky_ports(dev, base_scan))
    assert len(alerts) == 2


def test_banner_red_flag_php5(base_scan):
    dev = Device(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:01",
        ports=[Port(number=80, state=PortState.OPEN, banner="PHP/5.6.40")],
    )
    alerts = list(_alerts_for_banner_red_flags(dev, base_scan))
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.HIGH
    assert "PHP 5.x" in alerts[0].description


def test_banner_no_flag_on_modern(base_scan):
    dev = Device(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:01",
        ports=[Port(number=80, state=PortState.OPEN, banner="PHP/8.2.0")],
    )
    alerts = list(_alerts_for_banner_red_flags(dev, base_scan))
    assert len(alerts) == 0


def test_banner_red_flag_iis6(base_scan):
    dev = Device(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:01",
        ports=[Port(number=80, state=PortState.OPEN, banner="Microsoft-IIS/6.0")],
    )
    alerts = list(_alerts_for_banner_red_flags(dev, base_scan))
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL


def test_alert_id_uniqueness(base_scan):
    dev = Device(
        ip="1.1.1.1",
        mac="AA:AA:AA:AA:AA:AA",
        ports=[Port(number=21, state=PortState.OPEN)],
    )
    a1 = list(_alerts_for_risky_ports(dev, base_scan))[0]
    a2 = list(_alerts_for_risky_ports(dev, base_scan))[0]
    assert a1.alert_id != a2.alert_id
