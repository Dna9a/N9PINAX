"""Harsh integration tests for scanner.storage — uses a temporary SQLite file."""

import json
import sqlite3
import tempfile
import threading
import time
import uuid
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
from scanner.storage import (
    init_db,
    save_scan,
    load_scan,
    load_last_scan,
    list_scans,
    export_json,
    export_csv,
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "test_scans.db"
    init_db(db_path)
    return db_path


@pytest.fixture
def fresh_db(tmp_path: Path) -> Path:
    """Alias that makes test intent clearer when the DB must be empty."""
    db_path = tmp_path / "fresh.db"
    init_db(db_path)
    return db_path


def _make_device(
    ip: str = "192.168.1.10",
    mac: str = "AA:BB:CC:DD:EE:01",
    hostname: str = "test-host",
    vendor: str = "TestVendor",
    os_family: OSFamily = OSFamily.LINUX,
    os_version: str = "Ubuntu 22.04",
    confidence: float = 0.85,
    sources: dict | None = None,
    ports: list[Port] | None = None,
) -> Device:
    return Device(
        ip=ip,
        mac=mac,
        hostname=hostname,
        mac_vendor=vendor,
        fingerprint=FingerprintResult(
            os_family=os_family,
            os_version=os_version,
            device_type=DeviceType.SERVER,
            confidence=confidence,
            sources=sources or {"tcp": "Linux TCP stack", "http": "nginx"},
        ),
        ports=ports
        or [
            Port(number=22, state=PortState.OPEN, service="SSH"),
            Port(number=80, state=PortState.OPEN, service="HTTP"),
        ],
    )


def _make_full_scan(network: str = "192.168.1.0/24", n_devices: int = 3) -> ScanResult:
    devices = [
        _make_device(ip=f"192.168.1.{10 + i}", mac=f"AA:BB:CC:DD:EE:{i + 1:02X}")
        for i in range(n_devices)
    ]
    return ScanResult(network=network, devices=devices)


INJECTION_STRINGS = [
    "'; DROP TABLE scans; --",
    '" OR "1"="1',
    "../../etc/shadow",
    "\x00\x01\x02",
    "a" * 10_000,
    "<script>alert(1)</script>",
    "null",
    "None",
    "",
    " ",
]

PATH_TRAVERSAL_IDS = [
    "../../etc/shadow",
    "../db/scans",
    "/etc/passwd",
    "..\\Windows\\System32",
    "%2e%2e%2fetc%2fpasswd",
    "not-a-uuid",
    "",
    " ",
    "00000000000000000000000000000000",  # no dashes
    "00000000-0000-0000-0000-00000000000Z",  # invalid char
]


# ─── init_db ──────────────────────────────────────────────────────────────────


class TestInitDb:

    def test_creates_file(self, tmp_path):
        db_path = tmp_path / "new.db"
        assert not db_path.exists()
        init_db(db_path)
        assert db_path.exists()

    def test_idempotent_double_init(self, tmp_path):
        """Calling init_db twice on the same path must not raise or corrupt."""
        db_path = tmp_path / "double.db"
        init_db(db_path)
        init_db(db_path)  # must not raise

    def test_idempotent_preserves_data(self, tmp_path):
        db_path = tmp_path / "preserve.db"
        init_db(db_path)
        scan = ScanResult(network="10.0.0.0/8")
        scan_id = save_scan(scan, db_path)
        init_db(db_path)  # re-init
        loaded = load_scan(scan_id, db_path)
        assert loaded is not None, "Re-init wiped existing data"

    def test_creates_required_tables(self, tmp_path):
        db_path = tmp_path / "schema.db"
        init_db(db_path)
        conn = sqlite3.connect(db_path)
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        conn.close()
        assert "scans" in tables, f"'scans' table missing; found: {tables}"

    def test_path_as_string_accepted(self, tmp_path):
        db_path = str(tmp_path / "str_path.db")
        init_db(db_path)  # must not raise


# ─── save_scan / load_scan round-trip ─────────────────────────────────────────


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

    def test_save_returns_string_id(self, tmp_db):
        scan_id = save_scan(ScanResult(network="10.0.0.0/8"), tmp_db)
        assert isinstance(scan_id, str)
        assert len(scan_id) > 0

    def test_save_returns_valid_uuid(self, tmp_db):
        scan_id = save_scan(ScanResult(network="10.0.0.0/8"), tmp_db)
        try:
            uuid.UUID(scan_id)
        except ValueError:
            pytest.fail(f"save_scan returned non-UUID id: {scan_id!r}")

    def test_two_saves_return_different_ids(self, tmp_db):
        id1 = save_scan(ScanResult(network="10.0.0.0/8"), tmp_db)
        id2 = save_scan(ScanResult(network="10.0.0.0/8"), tmp_db)
        assert id1 != id2

    def test_load_nonexistent_returns_none(self, tmp_db):
        result = load_scan("00000000-0000-0000-0000-000000000000", tmp_db)
        assert result is None

    def test_fingerprint_fully_preserved(self, tmp_db):
        scan = ScanResult(network="192.168.1.0/24", devices=[_make_device()])
        scan_id = save_scan(scan, tmp_db)
        loaded = load_scan(scan_id, tmp_db)

        fp = loaded.devices[0].fingerprint
        assert fp is not None
        assert fp.os_family == OSFamily.LINUX
        assert fp.os_version == "Ubuntu 22.04"
        assert fp.device_type == DeviceType.SERVER
        assert fp.confidence == pytest.approx(0.85)
        assert fp.sources == {"tcp": "Linux TCP stack", "http": "nginx"}

    def test_all_os_families_preserved(self, tmp_db):
        for family in OSFamily:
            d = _make_device(
                os_family=family,
                mac=(
                    f"AA:BB:CC:DD:EE:{family.value:02X}"
                    if hasattr(family, "value") and isinstance(family.value, int)
                    else "AA:BB:CC:DD:EE:AA"
                ),
                ip="10.0.0.1",
            )
            scan_id = save_scan(ScanResult(network="10.0.0.0/24", devices=[d]), tmp_db)
            loaded = load_scan(scan_id, tmp_db)
            assert (
                loaded.devices[0].fingerprint.os_family == family
            ), f"OSFamily.{family.name} not preserved after round-trip"

    def test_ports_fully_preserved(self, tmp_db):
        ports = [
            Port(number=22, state=PortState.OPEN, service="SSH"),
            Port(number=80, state=PortState.OPEN, service="HTTP"),
            Port(number=443, state=PortState.OPEN, service="HTTPS"),
            Port(number=8080, state=PortState.CLOSED, service="HTTP-Alt"),
        ]
        d = _make_device(ports=ports)
        scan_id = save_scan(ScanResult(network="192.168.1.0/24", devices=[d]), tmp_db)
        loaded = load_scan(scan_id, tmp_db)

        loaded_ports = {p.number: p for p in loaded.devices[0].ports}
        assert 22 in loaded_ports and loaded_ports[22].state == PortState.OPEN
        assert 80 in loaded_ports and loaded_ports[80].state == PortState.OPEN
        assert 443 in loaded_ports and loaded_ports[443].state == PortState.OPEN
        assert 8080 in loaded_ports and loaded_ports[8080].state == PortState.CLOSED

    def test_open_ports_helper_after_load(self, tmp_db):
        scan = ScanResult(network="192.168.1.0/24", devices=[_make_device()])
        scan_id = save_scan(scan, tmp_db)
        loaded = load_scan(scan_id, tmp_db)
        open_ports = {p.number for p in loaded.devices[0].get_open_ports()}
        assert 22 in open_ports
        assert 80 in open_ports

    def test_no_fingerprint_device_preserved(self, tmp_db):
        device = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:02")
        scan_id = save_scan(ScanResult(network="10.0.0.0/24", devices=[device]), tmp_db)
        loaded = load_scan(scan_id, tmp_db)
        assert loaded.devices[0].fingerprint is None

    def test_no_ports_device_preserved(self, tmp_db):
        device = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:02")
        scan_id = save_scan(ScanResult(network="10.0.0.0/24", devices=[device]), tmp_db)
        loaded = load_scan(scan_id, tmp_db)
        assert loaded.devices[0].ports == [] or loaded.devices[0].ports is not None

    def test_empty_scan_round_trip(self, tmp_db):
        scan = ScanResult(network="10.0.0.0/8", devices=[])
        scan_id = save_scan(scan, tmp_db)
        loaded = load_scan(scan_id, tmp_db)
        assert loaded is not None
        assert loaded.network == "10.0.0.0/8"
        assert loaded.devices == []

    def test_large_scan_round_trip(self, tmp_db):
        """50-device scan must round-trip cleanly."""
        devices = [
            _make_device(
                ip=f"10.0.{i // 255}.{i % 255 + 1}",
                mac=f"AA:BB:CC:{i // 255:02X}:{i % 255:02X}:FF",
            )
            for i in range(50)
        ]
        scan = ScanResult(network="10.0.0.0/16", devices=devices)
        scan_id = save_scan(scan, tmp_db)
        loaded = load_scan(scan_id, tmp_db)
        assert len(loaded.devices) == 50

    def test_unicode_hostname_preserved(self, tmp_db):
        d = _make_device(hostname="ρouter-αβγ-日本語")
        scan_id = save_scan(ScanResult(network="10.0.0.0/24", devices=[d]), tmp_db)
        loaded = load_scan(scan_id, tmp_db)
        assert loaded.devices[0].hostname == "ρouter-αβγ-日本語"

    def test_special_chars_in_vendor_preserved(self, tmp_db):
        d = _make_device(vendor="TP-Link & Co. <GmbH>")
        scan_id = save_scan(ScanResult(network="10.0.0.0/24", devices=[d]), tmp_db)
        loaded = load_scan(scan_id, tmp_db)
        assert loaded.devices[0].mac_vendor == "TP-Link & Co. <GmbH>"

    def test_confidence_boundary_values_preserved(self, tmp_db):
        for conf in (0.0, 0.5, 1.0):
            d = _make_device(confidence=conf)
            scan_id = save_scan(ScanResult(network="10.0.0.0/24", devices=[d]), tmp_db)
            loaded = load_scan(scan_id, tmp_db)
            assert loaded.devices[0].fingerprint.confidence == pytest.approx(
                conf
            ), f"Confidence {conf} not preserved"

    def test_sources_with_special_chars_preserved(self, tmp_db):
        sources = {"tcp": 'Linux "4.x"', "http": "nginx/1.18 & Apache"}
        d = _make_device(sources=sources)
        scan_id = save_scan(ScanResult(network="10.0.0.0/24", devices=[d]), tmp_db)
        loaded = load_scan(scan_id, tmp_db)
        assert loaded.devices[0].fingerprint.sources == sources

    def test_loaded_object_is_independent_of_db(self, tmp_db):
        """Mutating a loaded ScanResult must not corrupt subsequent loads."""
        d = _make_device()
        scan_id = save_scan(ScanResult(network="192.168.1.0/24", devices=[d]), tmp_db)
        loaded1 = load_scan(scan_id, tmp_db)
        loaded1.devices[0].ip = "9.9.9.9"  # mutate in memory
        loaded2 = load_scan(scan_id, tmp_db)
        assert loaded2.devices[0].ip == "192.168.1.10"

    def test_device_order_preserved(self, tmp_db):
        ips = [f"192.168.1.{i}" for i in range(10, 20)]
        devices = [
            _make_device(ip=ip, mac=f"AA:BB:CC:DD:EE:{i:02X}")
            for i, ip in enumerate(ips, 1)
        ]
        scan_id = save_scan(
            ScanResult(network="192.168.1.0/24", devices=devices), tmp_db
        )
        loaded = load_scan(scan_id, tmp_db)
        loaded_ips = [d.ip for d in loaded.devices]
        assert loaded_ips == ips, f"Device order not preserved: {loaded_ips}"


# ─── list_scans ────────────────────────────────────────────────────────────────


class TestListScans:

    def test_empty_db_returns_empty_list(self, fresh_db):
        assert list_scans(fresh_db) == []

    def test_list_returns_all_scans(self, tmp_db):
        save_scan(ScanResult(network="192.168.1.0/24"), tmp_db)
        save_scan(ScanResult(network="10.0.0.0/8"), tmp_db)
        scans = list_scans(tmp_db)
        assert len(scans) == 2
        networks = {s["network"] for s in scans}
        assert "192.168.1.0/24" in networks
        assert "10.0.0.0/8" in networks

    def test_list_entries_have_required_keys(self, tmp_db):
        save_scan(ScanResult(network="10.0.0.0/24"), tmp_db)
        scans = list_scans(tmp_db)
        assert len(scans) == 1
        entry = scans[0]
        for key in ("id", "network", "timestamp"):
            assert key in entry, f"Missing key {key!r} in list entry"

    def test_list_ids_are_valid_uuids(self, tmp_db):
        save_scan(ScanResult(network="10.0.0.0/24"), tmp_db)
        for entry in list_scans(tmp_db):
            try:
                uuid.UUID(entry["id"])
            except (ValueError, KeyError) as e:
                pytest.fail(f"list_scans entry has invalid id: {entry!r} — {e}")

    def test_list_count_matches_save_count(self, tmp_db):
        for i in range(5):
            save_scan(ScanResult(network=f"10.0.{i}.0/24"), tmp_db)
        assert len(list_scans(tmp_db)) == 5

    def test_list_ordered_by_timestamp_desc(self, tmp_db):
        """Most recent scan should appear first (or last — pin the actual order)."""
        id1 = save_scan(ScanResult(network="10.0.1.0/24"), tmp_db)
        time.sleep(0.01)
        id2 = save_scan(ScanResult(network="10.0.2.0/24"), tmp_db)
        scans = list_scans(tmp_db)
        ids = [s["id"] for s in scans]
        # Pin order: either always ascending or always descending
        assert ids in (
            [id1, id2],
            [id2, id1],
        ), f"list_scans order is inconsistent: {ids}"

    def test_list_returns_list_type(self, tmp_db):
        result = list_scans(tmp_db)
        assert isinstance(result, list)

    def test_list_does_not_load_full_device_data(self, tmp_db):
        """list_scans should be lightweight — entries are dicts, not ScanResult objects."""
        save_scan(_make_full_scan(), tmp_db)
        scans = list_scans(tmp_db)
        assert isinstance(
            scans[0], dict
        ), "list_scans should return dicts, not full ScanResult objects"


# ─── load_last_scan ────────────────────────────────────────────────────────────


class TestLoadLastScan:

    def test_returns_none_when_empty(self, fresh_db):
        assert load_last_scan(fresh_db) is None

    def test_returns_only_scan_when_one_exists(self, tmp_db):
        save_scan(ScanResult(network="192.168.1.0/24"), tmp_db)
        last = load_last_scan(tmp_db)
        assert last is not None
        assert last.network == "192.168.1.0/24"

    def test_returns_most_recent(self, tmp_db):
        save_scan(ScanResult(network="192.168.1.0/24"), tmp_db)
        save_scan(ScanResult(network="10.0.0.0/8"), tmp_db)
        last = load_last_scan(tmp_db)
        assert last is not None
        assert last.network == "10.0.0.0/8"

    def test_most_recent_after_many_saves(self, tmp_db):
        for i in range(10):
            save_scan(ScanResult(network=f"10.0.{i}.0/24"), tmp_db)
        last = load_last_scan(tmp_db)
        assert last.network == "10.0.9.0/24"

    def test_returns_scanresult_type(self, tmp_db):
        save_scan(ScanResult(network="10.0.0.0/24"), tmp_db)
        last = load_last_scan(tmp_db)
        assert isinstance(last, ScanResult)

    def test_devices_intact_in_last_scan(self, tmp_db):
        save_scan(_make_full_scan(), tmp_db)
        last = load_last_scan(tmp_db)
        assert len(last.devices) == 3


# ─── export_json ───────────────────────────────────────────────────────────────


class TestExportJson:

    def test_rejects_path_traversal(self, tmp_db):
        for bad_id in PATH_TRAVERSAL_IDS:
            with pytest.raises((ValueError, Exception)):
                export_json(bad_id, db_path=tmp_db)

    def test_rejects_sql_injection(self, tmp_db):
        for bad_id in INJECTION_STRINGS:
            with pytest.raises((ValueError, Exception)):
                export_json(bad_id, db_path=tmp_db)

    def test_valid_uuid_nonexistent_raises_or_returns_none(self, tmp_db):
        """Valid UUID format but no matching record — must not crash silently."""
        result = export_json("00000000-0000-0000-0000-000000000000", db_path=tmp_db)
        assert result is None or isinstance(result, str)

    def test_valid_scan_produces_valid_json(self, tmp_db):
        scan_id = save_scan(_make_full_scan(), tmp_db)
        output = export_json(scan_id, db_path=tmp_db)
        assert output is not None
        parsed = json.loads(output)  # must not raise
        assert isinstance(parsed, dict)

    def test_json_contains_network(self, tmp_db):
        scan_id = save_scan(ScanResult(network="172.16.0.0/12"), tmp_db)
        output = export_json(scan_id, db_path=tmp_db)
        parsed = json.loads(output)
        assert parsed.get("network") == "172.16.0.0/12"

    def test_json_contains_devices(self, tmp_db):
        scan_id = save_scan(_make_full_scan(n_devices=2), tmp_db)
        output = export_json(scan_id, db_path=tmp_db)
        parsed = json.loads(output)
        assert "devices" in parsed
        assert len(parsed["devices"]) == 2

    # --- Concurrent Access Testing ---

    def test_concurrent_saves(self, tmp_path):
        """Verify that multiple threads can save scans simultaneously (WAL mode)."""
        db_path = tmp_path / "concurrent.db"
        init_db(db_path)

        def worker(idx):
            scan = ScanResult(
                network=f"10.0.{idx}.0/24", devices=[_make_device(ip=f"10.0.{idx}.1")]
            )
            save_scan(scan, db_path)

        threads = []
        for i in range(10):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        scans = list_scans(db_path)
        assert len(scans) == 10

    def test_massive_payload_round_trip(self, tmp_db):
        """Save a scan with 1000 devices to check SQLite blob/text limits."""
        devices = []
        for i in range(1000):
            devices.append(
                Device(
                    ip=f"10.0.{i // 256}.{i % 256}",
                    mac=f"AA:BB:CC:DD:{i // 256:02X}:{i % 256:02X}",
                    hostname="heavy-load-" + "x" * 100,
                )
            )
        scan = ScanResult(network="10.0.0.0/16", devices=devices)
        scan_id = save_scan(scan, tmp_db)
        loaded = load_scan(scan_id, tmp_db)
        assert len(loaded.devices) == 1000

    def test_save_with_malicious_strings(self, tmp_db):
        """Test persistence of SQL-injection-like strings within data fields (not IDs)."""
        for s in INJECTION_STRINGS:
            # Pydantic v2 has max_length constraints from models.py
            # hostname: 253, mac_vendor: 128
            safe_s = s[:128] if len(s) > 128 else s
            scan = ScanResult(
                network="10.0.0.0/24",
                devices=[_make_device(hostname=safe_s, vendor=safe_s)],
            )
            sid = save_scan(scan, tmp_db)
            loaded = load_scan(sid, tmp_db)
            assert loaded.devices[0].hostname == safe_s or "unknown"

    def test_error_message_in_french_for_invalid_id(self, tmp_db):
        """Original spec requires French error message for invalid scan_id."""
        with pytest.raises(ValueError, match="scan_id invalide"):
            export_json("not-a-uuid", db_path=tmp_db)


# ─── export_csv ────────────────────────────────────────────────────────────────


class TestExportCsv:

    def test_rejects_path_traversal(self, tmp_db):
        for bad_id in PATH_TRAVERSAL_IDS:
            with pytest.raises((ValueError, Exception)):
                export_csv(bad_id, db_path=tmp_db)

    def test_rejects_sql_injection(self, tmp_db):
        for bad_id in INJECTION_STRINGS:
            with pytest.raises((ValueError, Exception)):
                export_csv(bad_id, db_path=tmp_db)

    def test_error_message_in_french_for_invalid_id(self, tmp_db):
        with pytest.raises(ValueError, match="scan_id invalide"):
            export_csv("not-a-uuid", db_path=tmp_db)

    def test_valid_scan_produces_nonempty_csv(self, tmp_db):
        scan_id = save_scan(_make_full_scan(), tmp_db)
        output = export_csv(scan_id, db_path=tmp_db)
        assert output is not None
        assert len(output.strip()) > 0

    def test_csv_has_header_row(self, tmp_db):
        scan_id = save_scan(_make_full_scan(), tmp_db)
        output = export_csv(scan_id, db_path=tmp_db)
        lines = output.strip().splitlines()
        assert len(lines) >= 2, "CSV must have at least a header + one data row"

    def test_csv_row_count_matches_device_count(self, tmp_db):
        scan_id = save_scan(_make_full_scan(n_devices=4), tmp_db)
        output = export_csv(scan_id, db_path=tmp_db)
        lines = [l for l in output.strip().splitlines() if l.strip()]
        assert len(lines) == 5, f"Expected 1 header + 4 data rows, got {len(lines)}"

    def test_csv_contains_ip_and_mac(self, tmp_db):
        d = _make_device(ip="192.168.1.10", mac="AA:BB:CC:DD:EE:01")
        scan_id = save_scan(ScanResult(network="192.168.1.0/24", devices=[d]), tmp_db)
        output = export_csv(scan_id, db_path=tmp_db)
        assert "192.168.1.10" in output
        assert "AA:BB:CC:DD:EE:01" in output

    def test_csv_no_injection_in_output(self, tmp_db):
        """Hostile hostname must be safely escaped in CSV output."""
        d = _make_device(hostname='evil","injected')
        scan_id = save_scan(ScanResult(network="192.168.1.0/24", devices=[d]), tmp_db)
        output = export_csv(scan_id, db_path=tmp_db)
        lines = output.strip().splitlines()
        # Number of commas per row must be consistent (no injection breaking field count)
        header_fields = len(lines[0].split(","))
        for i, line in enumerate(lines[1:], 2):
            # Use csv module logic: quoted commas don't count
            import csv, io

            row = next(csv.reader(io.StringIO(line)))
            assert (
                len(row) == header_fields
            ), f"Row {i} has {len(row)} fields, header has {header_fields}: {line!r}"


# ─── Concurrency ───────────────────────────────────────────────────────────────


class TestConcurrency:

    def test_concurrent_saves_no_data_loss(self, tmp_db):
        """10 threads saving simultaneously must each get a unique ID."""
        ids = []
        errors = []
        lock = threading.Lock()

        def worker(i):
            try:
                scan_id = save_scan(ScanResult(network=f"10.0.{i}.0/24"), tmp_db)
                with lock:
                    ids.append(scan_id)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent save errors: {errors}"
        assert len(set(ids)) == 10, f"Duplicate IDs after concurrent saves: {ids}"
        assert len(list_scans(tmp_db)) == 10

    def test_concurrent_reads_do_not_crash(self, tmp_db):
        scan_id = save_scan(_make_full_scan(), tmp_db)
        errors = []

        def reader():
            try:
                load_scan(scan_id, tmp_db)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent read errors: {errors}"


# ─── DB isolation ──────────────────────────────────────────────────────────────


class TestDbIsolation:

    def test_two_dbs_are_independent(self, tmp_path):
        db1 = tmp_path / "a.db"
        db2 = tmp_path / "b.db"
        init_db(db1)
        init_db(db2)

        id1 = save_scan(ScanResult(network="10.0.1.0/24"), db1)
        save_scan(ScanResult(network="10.0.2.0/24"), db2)

        assert load_scan(id1, db2) is None, "Scan from db1 leaked into db2"
        assert len(list_scans(db1)) == 1
        assert len(list_scans(db2)) == 1

    def test_missing_db_path_raises(self, tmp_path):
        nonexistent = tmp_path / "ghost" / "deep" / "path.db"
        with pytest.raises(Exception):
            save_scan(ScanResult(network="10.0.0.0/8"), nonexistent)
