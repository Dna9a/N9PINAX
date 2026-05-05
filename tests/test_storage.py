"""Integration tests for scanner.storage — uses a temporary SQLite file."""
import tempfile
from pathlib import Path

import pytest

from scanner.models import (
    Device,
    FingerprintResult,
    OSFamily,
    DeviceType,
    Port,
    PortState,
    ScanResult,
)
from scanner.storage import init_db, save_scan, load_scan, load_last_scan, list_scans


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "test_scans.db"
    init_db(db_path)
    return db_path


def _make_device(
    ip: str = "192.168.1.10",
    mac: str = "AA:BB:CC:DD:EE:01",
) -> Device:
    return Device(
        ip=ip,
        mac=mac,
        hostname="test-host",
        mac_vendor="TestVendor",
        fingerprint=FingerprintResult(
            os_family=OSFamily.LINUX,
            os_version="Ubuntu 22.04",
            device_type=DeviceType.SERVER,
            confidence=0.85,
            sources={"tcp": "Linux TCP stack", "http": "nginx"},
        ),
        ports=[
            Port(number=22, state=PortState.OPEN, service="SSH"),
            Port(number=80, state=PortState.OPEN, service="HTTP"),
        ],
    )


class TestSaveAndLoad:
    def test_basic_round_trip(self, tmp_db):
        scan = ScanResult(network="192.168.1.0/24", devices=[_make_device()])
        scan_id = save_scan(scan, tmp_db)
        loaded = load_scan(scan_id, tmp_db)

        assert loaded is not None
        assert loaded.network == "192.168.1.0/24"
        assert len(loaded.devices) == 1
        assert loaded.devices[0].ip == "192.168.1.10"
        assert loaded.devices[0].mac == "AA:BB:CC:DD:EE:01"

    def test_fingerprint_preserved(self, tmp_db):
        scan = ScanResult(network="192.168.1.0/24", devices=[_make_device()])
        scan_id = save_scan(scan, tmp_db)
        loaded = load_scan(scan_id, tmp_db)

        fp = loaded.devices[0].fingerprint
        assert fp is not None
        assert fp.os_family == OSFamily.LINUX
        assert fp.os_version == "Ubuntu 22.04"
        assert fp.confidence == pytest.approx(0.85)
        assert fp.sources == {"tcp": "Linux TCP stack", "http": "nginx"}

    def test_ports_preserved(self, tmp_db):
        scan = ScanResult(network="192.168.1.0/24", devices=[_make_device()])
        scan_id = save_scan(scan, tmp_db)
        loaded = load_scan(scan_id, tmp_db)

        open_ports = {p.number for p in loaded.devices[0].get_open_ports()}
        assert 22 in open_ports
        assert 80 in open_ports

    def test_load_nonexistent_returns_none(self, tmp_db):
        result = load_scan("00000000-0000-0000-0000-000000000000", tmp_db)
        assert result is None

    def test_no_fingerprint_device(self, tmp_db):
        device = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:02")
        scan = ScanResult(network="10.0.0.0/24", devices=[device])
        scan_id = save_scan(scan, tmp_db)
        loaded = load_scan(scan_id, tmp_db)

        assert loaded.devices[0].fingerprint is None


class TestListScans:
    def test_list_returns_all_scans(self, tmp_db):
        save_scan(ScanResult(network="192.168.1.0/24"), tmp_db)
        save_scan(ScanResult(network="10.0.0.0/8"), tmp_db)

        scans = list_scans(tmp_db)
        assert len(scans) == 2
        networks = {s["network"] for s in scans}
        assert "192.168.1.0/24" in networks
        assert "10.0.0.0/8" in networks

    def test_list_empty_db(self, tmp_db):
        scans = list_scans(tmp_db)
        assert scans == []


class TestLoadLastScan:
    def test_returns_most_recent(self, tmp_db):
        save_scan(ScanResult(network="192.168.1.0/24"), tmp_db)
        save_scan(ScanResult(network="10.0.0.0/8"), tmp_db)

        last = load_last_scan(tmp_db)
        assert last is not None
        assert last.network == "10.0.0.0/8"

    def test_returns_none_when_empty(self, tmp_db):
        assert load_last_scan(tmp_db) is None


class TestScanIdValidation:
    def test_export_json_rejects_invalid_id(self, tmp_db):
        from scanner.storage import export_json
        with pytest.raises(ValueError, match="scan_id invalide"):
            export_json("../../etc/shadow", db_path=tmp_db)

    def test_export_csv_rejects_invalid_id(self, tmp_db):
        from scanner.storage import export_csv
        with pytest.raises(ValueError, match="scan_id invalide"):
            export_csv("not-a-uuid", db_path=tmp_db)
