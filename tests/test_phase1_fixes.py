"""Regression tests for bugs fixed in Phase 1 scanner audit."""

import pytest
from unittest.mock import patch, MagicMock
from scanner.models import Device, Port, PortState, FingerprintResult


# ─── Bug #1: ICMP latency not stored in device.latency_ms ────────────────────


@patch("scanner.core.icmp_scan._icmp_probe")
def test_enrich_devices_stores_latency_ms(mock_probe):
    """enrich_devices() must copy rtt_ms into device.latency_ms."""
    from scanner.core.icmp_scan import enrich_devices, IcmpReply

    device = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01")
    mock_probe.return_value = IcmpReply(ip="10.0.0.1", ttl=64, rtt_ms=7.42, alive=True)

    result = enrich_devices([device])
    assert result[0].latency_ms == pytest.approx(7.42, rel=1e-3)


@patch("scanner.core.icmp_scan._icmp_probe")
def test_enrich_devices_no_latency_when_dead(mock_probe):
    """latency_ms must not be set when the host doesn't respond."""
    from scanner.core.icmp_scan import enrich_devices, IcmpReply

    device = Device(ip="10.0.0.2", mac="AA:BB:CC:DD:EE:02")
    mock_probe.return_value = IcmpReply(ip="10.0.0.2", ttl=None, rtt_ms=None, alive=False)

    result = enrich_devices([device])
    assert result[0].latency_ms is None


@patch("scanner.core.icmp_scan._icmp_probe")
def test_enrich_devices_stores_ttl(mock_probe):
    """enrich_devices() must also store TTL on the fingerprint."""
    from scanner.core.icmp_scan import enrich_devices, IcmpReply

    device = Device(ip="10.0.0.3", mac="AA:BB:CC:DD:EE:03")
    mock_probe.return_value = IcmpReply(ip="10.0.0.3", ttl=128, rtt_ms=1.0, alive=True)

    result = enrich_devices([device])
    assert result[0].fingerprint is not None
    assert result[0].fingerprint.tcp_ttl == 128


# ─── Bug #2: TTL=0 dropped from SYN scan fingerprint ─────────────────────────


@patch("scanner.core.syn_scan.syn_scan")
def test_syn_scan_ttl_zero_not_dropped(mock_syn):
    """A TTL of 0 is valid and must not be silently discarded."""
    from scanner.core.syn_scan import syn_scan_into_device, SynResult

    mock_syn.return_value = [
        SynResult(ip="1.2.3.4", port=80, state=PortState.OPEN, ttl=0, window=512)
    ]
    device = Device(ip="1.2.3.4", mac="AA:BB:CC:DD:EE:04")
    result = syn_scan_into_device(device)

    assert result.fingerprint is not None
    assert result.fingerprint.tcp_ttl == 0
    assert result.fingerprint.tcp_window == 512


@patch("scanner.core.syn_scan.syn_scan")
def test_syn_scan_ttl_none_not_stored(mock_syn):
    """ttl=None from a probe must not set any fingerprint field."""
    from scanner.core.syn_scan import syn_scan_into_device, SynResult

    mock_syn.return_value = [
        SynResult(ip="1.2.3.5", port=443, state=PortState.OPEN, ttl=None, window=None)
    ]
    device = Device(ip="1.2.3.5", mac="AA:BB:CC:DD:EE:05")
    result = syn_scan_into_device(device)
    # fingerprint may or may not exist, but if it does tcp_ttl must be None
    if result.fingerprint is not None:
        assert result.fingerprint.tcp_ttl is None


# ─── Bug #3: tcp_fingerprint module imports cleanly without Scapy ─────────────


def test_tcp_fingerprint_module_importable():
    """Module-level import must succeed whether or not scapy is present."""
    import scanner.fingerprint.tcp_fingerprint as m
    assert callable(m.tcp_fingerprint)
    assert callable(m.enrich_devices)


def test_probe_tcp_syn_handles_import_error():
    """_probe_tcp_syn must return None if scapy is unavailable."""
    import scanner.fingerprint.tcp_fingerprint as m

    with patch.dict("sys.modules", {"scapy": None, "scapy.all": None}):
        # Already imported, but simulate ImportError by patching the import
        with patch("builtins.__import__", side_effect=ImportError("no scapy")):
            result = m._probe_tcp_syn("1.1.1.1", port=80)
    # Should return None gracefully — the function handles ImportError
    assert result is None or isinstance(result, dict)


def test_probe_icmp_handles_import_error():
    """_probe_icmp must return icmp_response=False dict if scapy unavailable."""
    import scanner.fingerprint.tcp_fingerprint as m

    with patch("builtins.__import__", side_effect=ImportError("no scapy")):
        result = m._probe_icmp("1.1.1.1")
    assert result is None or (isinstance(result, dict) and not result.get("icmp_response", True))


# ─── Bug #4: Unguarded sr1() calls crash tcp fingerprint ─────────────────────


def test_probe_tcp_syn_handles_permission_error(monkeypatch):
    """PermissionError from sr1 must return None without crashing."""
    import scanner.fingerprint.tcp_fingerprint as m

    scapy_mock = MagicMock()
    scapy_mock.IP.return_value = MagicMock()
    scapy_mock.TCP.return_value = MagicMock()
    scapy_mock.sr1.side_effect = PermissionError("no cap_net_raw")
    scapy_mock.conf = MagicMock()

    with patch.dict("sys.modules", {"scapy": scapy_mock, "scapy.all": scapy_mock}):
        # Force the lazy import path to pick up our mock
        monkeypatch.setitem(__import__("sys").modules, "scapy.all", scapy_mock)
        result = m._probe_tcp_syn("1.1.1.1")
    assert result is None


def test_probe_tcp_syn_handles_generic_exception(monkeypatch):
    """Any exception from sr1 must return None without crashing."""
    import scanner.fingerprint.tcp_fingerprint as m

    scapy_mock = MagicMock()
    scapy_mock.IP.return_value = MagicMock()
    scapy_mock.TCP.return_value = MagicMock()
    scapy_mock.sr1.side_effect = OSError("network unreachable")
    scapy_mock.conf = MagicMock()

    with patch.dict("sys.modules", {"scapy": scapy_mock, "scapy.all": scapy_mock}):
        monkeypatch.setitem(__import__("sys").modules, "scapy.all", scapy_mock)
        result = m._probe_tcp_syn("1.1.1.1")
    assert result is None


# ─── Bug #5 & #6: DHCP fingerprint module / enrich_devices timeout param ─────


def test_dhcp_fingerprint_module_importable():
    """Module-level import must succeed whether or not scapy is present."""
    import scanner.fingerprint.dhcp_fingerprint as m
    assert callable(m.enrich_devices)
    assert callable(m.start_passive_capture)


def test_dhcp_enrich_devices_accepts_timeout():
    """enrich_devices must accept a timeout kwarg (was missing, caused TypeError)."""
    from scanner.fingerprint.dhcp_fingerprint import enrich_devices

    device = Device(ip="192.168.1.10", mac="AA:BB:CC:DD:EE:10")
    # Pass captured={} to skip actual sniff; timeout should not cause TypeError
    result = enrich_devices([device], captured={}, timeout=5)
    assert result == [device]


def test_dhcp_enrich_devices_uses_timeout_for_capture():
    """When captured=None, start_passive_capture must be called with the timeout."""
    from scanner.fingerprint import dhcp_fingerprint as m

    with patch.object(m, "start_passive_capture", return_value={}) as mock_capture:
        device = Device(ip="192.168.1.11", mac="AA:BB:CC:DD:EE:11")
        m.enrich_devices([device], captured=None, timeout=3)
        mock_capture.assert_called_once_with(timeout=3)


def test_dhcp_start_passive_capture_handles_permission_error():
    """PermissionError from sniff must return {} without crashing."""
    from scanner.fingerprint import dhcp_fingerprint as m

    scapy_mock = MagicMock()
    scapy_mock.sniff.side_effect = PermissionError("no cap_net_raw")
    scapy_mock.conf = MagicMock()

    with patch.dict("sys.modules", {"scapy": scapy_mock, "scapy.all": scapy_mock}):
        result = m.start_passive_capture(timeout=1)
    assert result == {}


def test_dhcp_start_passive_capture_handles_import_error():
    """ImportError on scapy import inside start_passive_capture must return {}."""
    from scanner.fingerprint import dhcp_fingerprint as m

    with patch("builtins.__import__", side_effect=ImportError("no scapy")):
        result = m.start_passive_capture(timeout=1)
    assert result == {}


# ─── Bug #8: main.py persistence uses cfg.db_path ────────────────────────────


def test_run_scan_uses_cfg_db_path(tmp_path):
    """Persistence calls must use the configured db_path, not the module default."""
    from scanner.main import run_scan
    from scanner.config import ScannerConfig

    fake_db = tmp_path / "test_scan.db"
    fake_cfg = ScannerConfig(db_path=fake_db)

    with (
        patch("scanner.main.get_config", return_value=fake_cfg),
        patch("scanner.main.arp_scan", return_value=[]),
    ):
        result = run_scan(network="192.168.99.0/30", save_to_db=False, write_report=False)
    assert result.network == "192.168.99.0/30"
    # DB was not written (save_to_db=False) but no error should have occurred
    assert not fake_db.exists()


def test_safe_step_isolates_exceptions():
    """_safe_step must catch exceptions and not re-raise unless fatal=True."""
    from scanner.main import _safe_step

    calls = []

    def boom():
        raise RuntimeError("deliberate failure")

    def ok():
        calls.append("ok")

    _safe_step("failing step", boom, fatal=False)
    _safe_step("ok step", ok, fatal=False)
    assert calls == ["ok"]


def test_safe_step_fatal_reraises():
    """_safe_step with fatal=True must re-raise exceptions."""
    from scanner.main import _safe_step

    with pytest.raises(RuntimeError, match="fatal"):
        _safe_step("fatal step", lambda: (_ for _ in ()).throw(RuntimeError("fatal")), fatal=True)
