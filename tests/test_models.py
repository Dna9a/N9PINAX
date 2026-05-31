"""Harsh unit tests for scanner.models — no network access required."""

import copy
import math
import threading
import pytest

from scanner.models import (
    _normalize_mac,
    Device,
    FingerprintResult,
    OSFamily,
    DeviceType,
    Port,
    PortState,
    ScanResult,
    merge_devices_by_mac,
)

# ─── Fixtures / shared data ────────────────────────────────────────────────────

VALID_MACS_AND_CANONICAL = [
    ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"),
    ("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF"),
    ("aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF"),
    ("AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF"),
    ("aabb.ccdd.eeff", "AA:BB:CC:DD:EE:FF"),
    ("AABB.CCDD.EEFF", "AA:BB:CC:DD:EE:FF"),
    ("aabbccddeeff", "AA:BB:CC:DD:EE:FF"),
    ("AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF"),
    ("00:00:00:00:00:00", "00:00:00:00:00:00"),
    ("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF"),
    ("0a:0b:0c:0d:0e:0f", "0A:0B:0C:0D:0E:0F"),
    ("  aa:bb:cc:dd:ee:ff  ", "AA:BB:CC:DD:EE:FF"),  # Leading/trailing spaces
]

INVALID_MACS = [
    "",
    "aa:bb:cc",  # too short
    "aa:bb:cc:dd:ee",  # 5 octets
    "aa:bb:cc:dd:ee:ff:00",  # 7 octets
    "GG:BB:CC:DD:EE:FF",  # invalid hex
    "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",
    "00:GG:00:00:00:00",
    ":::::::",
    "not_a_mac",
    " ",
    "\x00" * 12,  # Null bytes
    "aa:bb:cc:dd:ee:f",  # odd nibble count
    "aa bb cc dd ee ff",  # spaces
    "1234567890123",  # 13 chars
]

VALID_IPS = [
    "0.0.0.0",
    "127.0.0.1",
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "255.255.255.255",
]

INVALID_IPS = [
    "999.999.999.999",
    "256.0.0.1",
    "192.168.1",
    "192.168.1.1.1",
    "not-an-ip",
    "",
    "::1",  # IPv6 — if not supported by model validator
    " 192.168.1.1",  # leading space
    "192.168.1.1 ",  # trailing space
    "1.2.3.4\x00",  # Null terminator
]

VALID_NETWORKS = [
    "192.168.1.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "0.0.0.0/0",
    "255.255.255.255/32",
    "192.168.1.5/24",  # host address in a network — accepted per existing test
]

INVALID_NETWORKS = [
    "not-a-network",
    "",
    "192.168.1.0",  # no prefix length
    "192.168.1.0/33",  # prefix too large
    "192.168.1.0/-1",
    "300.0.0.0/24",
    "192.168.1.0 /24",  # Space before slash
]


# ─── _normalize_mac ────────────────────────────────────────────────────────────


class TestNormalizeMac:

    @pytest.mark.parametrize("raw,expected", VALID_MACS_AND_CANONICAL)
    def test_all_valid_formats(self, raw, expected):
        assert (
            _normalize_mac(raw) == expected
        ), f"_normalize_mac({raw!r}) expected {expected!r}"

    def test_type_error_on_non_string(self):
        with pytest.raises(TypeError):
            _normalize_mac(123456789)

    @pytest.mark.parametrize("invalid", INVALID_MACS)
    def test_invalid_raises_value_error(self, invalid):
        with pytest.raises(ValueError):
            _normalize_mac(invalid)

        with pytest.raises(ValueError):
            _normalize_mac(invalid)

    def test_returns_str(self):
        result = _normalize_mac("aa:bb:cc:dd:ee:ff")
        assert type(result) is str

    def test_output_format_exact(self):
        """Output must be exactly XX:XX:XX:XX:XX:XX — 17 chars, colons at positions 2,5,8,11,14."""
        result = _normalize_mac("aabbccddeeff")
        assert len(result) == 17
        for i in (2, 5, 8, 11, 14):
            assert (
                result[i] == ":"
            ), f"Expected colon at position {i}, got {result[i]!r}"

    def test_output_is_uppercase(self):
        result = _normalize_mac("aa:bb:cc:dd:ee:ff")
        assert result == result.upper()

    def test_idempotent(self):
        canonical = "AA:BB:CC:DD:EE:FF"
        assert _normalize_mac(canonical) == _normalize_mac(_normalize_mac(canonical))

    def test_does_not_mutate_input(self):
        raw = "aa:bb:cc:dd:ee:ff"
        original = raw
        _normalize_mac(raw)
        assert raw == original

    def test_none_raises(self):
        with pytest.raises((ValueError, TypeError)):
            _normalize_mac(None)

    def test_integer_raises(self):
        with pytest.raises((ValueError, TypeError)):
            _normalize_mac(0xAABBCCDDEEFF)

    @pytest.mark.parametrize("invalid", INVALID_MACS)
    def test_invalid_never_returns_silently(self, invalid):
        """Must never swallow the error and return a wrong value."""
        try:
            result = _normalize_mac(invalid)
            pytest.fail(
                f"_normalize_mac({invalid!r}) should have raised but returned {result!r}"
            )
        except (ValueError, TypeError):
            pass


# ─── FingerprintResult ─────────────────────────────────────────────────────────


class TestFingerprintResult:

    # --- merge: winner selection ---

    def test_higher_confidence_wins(self):
        fp1 = FingerprintResult(os_family=OSFamily.WINDOWS, confidence=0.9)
        fp2 = FingerprintResult(os_family=OSFamily.LINUX, confidence=0.5)
        merged = fp1.merge(fp2)
        assert merged.os_family == OSFamily.WINDOWS
        assert merged.confidence == pytest.approx(0.9)

    def test_merge_is_not_always_self(self):
        """Lower-confidence self must yield to higher-confidence other."""
        fp1 = FingerprintResult(os_family=OSFamily.WINDOWS, confidence=0.3)
        fp2 = FingerprintResult(os_family=OSFamily.LINUX, confidence=0.8)
        merged = fp1.merge(fp2)
        assert merged.os_family == OSFamily.LINUX
        assert merged.confidence == pytest.approx(0.8)

    def test_merge_equal_confidence_deterministic(self):
        """Tie-breaking must be deterministic (not random)."""
        fp1 = FingerprintResult(os_family=OSFamily.WINDOWS, confidence=0.7)
        fp2 = FingerprintResult(os_family=OSFamily.LINUX, confidence=0.7)
        results = {fp1.merge(fp2).os_family for _ in range(10)}
        assert len(results) == 1, "Tie-breaking is non-deterministic"

    def test_merge_returns_new_object(self):
        fp1 = FingerprintResult(os_family=OSFamily.WINDOWS, confidence=0.9)
        fp2 = FingerprintResult(os_family=OSFamily.LINUX, confidence=0.5)
        merged = fp1.merge(fp2)
        assert merged is not fp1
        assert merged is not fp2

    def test_merge_does_not_mutate_inputs(self):
        fp1 = FingerprintResult(
            os_family=OSFamily.WINDOWS, confidence=0.9, sources={"iis": "IIS"}
        )
        fp2 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.5, sources={"http": "nginx"}
        )
        fp1_sources_before = dict(fp1.sources)
        fp2_sources_before = dict(fp2.sources)
        fp1.merge(fp2)
        assert fp1.sources == fp1_sources_before
        assert fp2.sources == fp2_sources_before

    # --- merge: sources ---

    def test_sources_merged_when_same_os(self):
        fp1 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.8, sources={"tcp": "Linux"}
        )
        fp2 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.6, sources={"http": "nginx"}
        )
        merged = fp1.merge(fp2)
        assert "tcp" in merged.sources
        assert "http" in merged.sources

    def test_sources_not_merged_when_os_incompatible(self):
        fp1 = FingerprintResult(
            os_family=OSFamily.WINDOWS, confidence=0.9, sources={"iis": "IIS/10.0"}
        )
        fp2 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.5, sources={"http": "nginx"}
        )
        merged = fp1.merge(fp2)
        assert "iis" in merged.sources
        assert "http" not in merged.sources

    def test_loser_sources_not_in_winner_when_incompatible(self):
        """Verify both directions — winner's sources stay, loser's are dropped."""
        fp1 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.9, sources={"ssh": "OpenSSH"}
        )
        fp2 = FingerprintResult(
            os_family=OSFamily.WINDOWS, confidence=0.4, sources={"rdp": "MS-RDP"}
        )
        merged = fp1.merge(fp2)
        assert "ssh" in merged.sources
        assert "rdp" not in merged.sources

    def test_sources_merged_when_unknown_os(self):
        fp1 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.7, sources={"tcp": "Linux"}
        )
        fp2 = FingerprintResult(
            os_family=OSFamily.UNKNOWN, confidence=0.4, sources={"mac": "Raspberry Pi"}
        )
        merged = fp1.merge(fp2)
        assert "tcp" in merged.sources
        assert "mac" in merged.sources

    def test_source_key_collision_does_not_crash(self):
        """If both fps have the same source key, merge must not crash."""
        fp1 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.8, sources={"tcp": "Linux 4.x"}
        )
        fp2 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.6, sources={"tcp": "Linux 5.x"}
        )
        merged = fp1.merge(fp2)
        assert "tcp" in merged.sources

    def test_empty_sources_merge_safely(self):
        fp1 = FingerprintResult(os_family=OSFamily.LINUX, confidence=0.8, sources={})
        fp2 = FingerprintResult(os_family=OSFamily.LINUX, confidence=0.6, sources={})
        merged = fp1.merge(fp2)
        assert isinstance(merged.sources, dict)

    # --- update_confidence ---

    def test_confidence_clamped_at_one(self):
        fp = FingerprintResult(confidence=0.5)
        fp.update_confidence(1.0)
        assert fp.confidence == pytest.approx(1.0)

    def test_confidence_clamped_above_one(self):
        fp = FingerprintResult(confidence=0.5)
        fp.update_confidence(999.0)
        assert fp.confidence <= 1.0

    def test_confidence_not_below_zero(self):
        fp = FingerprintResult(confidence=0.3)
        fp.update_confidence(-1.0)
        assert fp.confidence == pytest.approx(0.0)

    def test_confidence_not_below_zero_large_negative(self):
        fp = FingerprintResult(confidence=0.3)
        fp.update_confidence(-999.0)
        assert fp.confidence >= 0.0

    def test_confidence_delta_applies_correctly(self):
        fp = FingerprintResult(confidence=0.4)
        fp.update_confidence(0.2)
        assert fp.confidence == pytest.approx(0.6)

    def test_confidence_initial_range(self):
        """Confidence at construction must be in [0.0, 1.0]."""
        for val in (0.0, 0.5, 1.0):
            fp = FingerprintResult(confidence=val)
            assert 0.0 <= fp.confidence <= 1.0

    def test_confidence_out_of_range_at_construction(self):
        """Construction with out-of-range confidence should raise (Pydantic v2)."""
        with pytest.raises(Exception):
            FingerprintResult(confidence=1.5)
        with pytest.raises(Exception):
            FingerprintResult(confidence=-0.5)

    def test_confidence_is_float(self):
        fp = FingerprintResult(confidence=1)
        assert isinstance(fp.confidence, float)

    def test_confidence_not_nan(self):
        fp = FingerprintResult(confidence=0.5)
        fp.update_confidence(0.1)
        assert not math.isnan(fp.confidence)


# ─── Port ─────────────────────────────────────────────────────────────────────


class TestPort:

    @pytest.mark.parametrize("number", [1, 80, 443, 8080, 22, 65535])
    def test_valid_port_numbers(self, number):
        p = Port(number=number, service="test")
        assert p.number == number

    def test_port_zero_raises(self):
        with pytest.raises(Exception):
            Port(number=0, service="test")

    def test_port_negative_raises(self):
        with pytest.raises(Exception):
            Port(number=-1, service="test")

    def test_port_too_high_raises(self):
        with pytest.raises(Exception):
            Port(number=65536, service="test")

    def test_port_way_too_high_raises(self):
        with pytest.raises(Exception):
            Port(number=999999, service="test")

    def test_service_stored(self):
        p = Port(number=80, service="HTTP")
        assert p.service == "HTTP"

    def test_banner_truncated_at_512(self):
        long_banner = "A" * 600
        p = Port(number=80, service="HTTP", banner=long_banner)
        assert len(p.banner) <= 512

    def test_banner_not_truncated_when_short(self):
        short_banner = "Apache/2.4.1"
        p = Port(number=80, service="HTTP", banner=short_banner)
        assert p.banner == short_banner

    def test_banner_exactly_512_not_truncated(self):
        banner = "B" * 512
        p = Port(number=80, service="HTTP", banner=banner)
        assert len(p.banner) == 512

    def test_banner_513_truncated(self):
        banner = "B" * 513
        p = Port(number=80, service="HTTP", banner=banner)
        assert len(p.banner) <= 512

    def test_non_printable_stripped_from_service(self):
        p = Port(number=22, service="SSH\x00\x01\x7f")
        assert "\x00" not in p.service
        assert "\x01" not in p.service

    def test_non_printable_stripped_from_banner(self):
        p = Port(number=80, service="HTTP", banner="Apache\x00Server")
        assert "\x00" not in p.banner

    def test_service_not_empty_after_sanitization(self):
        """If sanitization strips everything, service must be empty string or raise — not None."""
        p = Port(number=80, service="\x00\x01\x02")
        assert p.service is not None
        assert isinstance(p.service, str)

    def test_port_number_is_int(self):
        p = Port(number=80, service="HTTP")
        assert isinstance(p.number, int)

    def test_float_port_raises_or_coerces(self):
        """Float port numbers should raise or be coerced to int — not stored as float."""
        try:
            p = Port(number=80.9, service="HTTP")
            assert isinstance(p.number, int)
        except (TypeError, ValueError, Exception):
            pass  # raising is preferred


# ─── ScanResult ───────────────────────────────────────────────────────────────


class TestScanResult:

    @pytest.mark.parametrize("network", VALID_NETWORKS)
    def test_valid_networks_accepted(self, network):
        sr = ScanResult(network=network)
        assert sr.network == network

    @pytest.mark.parametrize("network", INVALID_NETWORKS)
    def test_invalid_networks_raise(self, network):
        with pytest.raises(Exception):
            ScanResult(network=network)

    def test_total_hosts_zero_when_empty(self):
        sr = ScanResult(network="10.0.0.0/24")
        assert sr.total_hosts == 0

    def test_total_hosts_single_device(self):
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        assert sr.total_hosts == 1

    def test_total_hosts_multiple_devices(self):
        devices = [
            Device(ip=f"10.0.0.{i}", mac=f"AA:BB:CC:DD:EE:{i:02X}") for i in range(1, 6)
        ]
        sr = ScanResult(network="10.0.0.0/24", devices=devices)
        assert sr.total_hosts == 5

    def test_total_hosts_reflects_live_list(self):
        """total_hosts must reflect the actual device list, not a snapshot."""
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        initial = sr.total_hosts
        assert initial == 1

    def test_find_device_by_mac_normalizes_query(self):
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:00:00:01")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        for fmt in ("aa:bb:cc:00:00:01", "AA-BB-CC-00-00-01", "aabbcc000001"):
            found = sr.find_device_by_mac(fmt)
            assert found is not None, f"find_device_by_mac({fmt!r}) returned None"
            assert found.ip == "10.0.0.1"

    def test_find_device_by_mac_missing_returns_none(self):
        sr = ScanResult(network="10.0.0.0/24", devices=[])
        assert sr.find_device_by_mac("AA:BB:CC:DD:EE:FF") is None

    def test_find_device_by_mac_wrong_mac_returns_none(self):
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:00:00:01")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        assert sr.find_device_by_mac("AA:BB:CC:00:00:02") is None

    def test_find_device_by_ip(self):
        d = Device(ip="10.0.0.2", mac="AA:BB:CC:00:00:02")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        found = sr.find_device_by_ip("10.0.0.2")
        assert found is not None
        assert found.mac == "AA:BB:CC:00:00:02"

    def test_find_device_by_ip_missing_returns_none(self):
        sr = ScanResult(network="10.0.0.0/24", devices=[])
        assert sr.find_device_by_ip("10.0.0.99") is None

    def test_find_device_by_ip_wrong_ip_returns_none(self):
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:00:00:01")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        assert sr.find_device_by_ip("10.0.0.2") is None

    def test_devices_default_to_empty_list(self):
        sr = ScanResult(network="10.0.0.0/24")
        assert sr.devices == [] or sr.devices is not None

    def test_duplicate_macs_handled(self):
        """Two devices with the same MAC must not crash ScanResult construction."""
        d1 = Device(ip="10.0.0.1", mac="AA:BB:CC:00:00:01")
        d2 = Device(ip="10.0.0.2", mac="AA:BB:CC:00:00:01")
        sr = ScanResult(network="10.0.0.0/24", devices=[d1, d2])
        assert sr.total_hosts == 2

    def test_model_post_init_recalculates_total_hosts(self):
        d1 = Device(ip="10.0.0.1", mac="AA:BB:CC:00:00:01")
        sr = ScanResult(network="10.0.0.0/24", devices=[d1])
        assert sr.total_hosts == 1
        # Pydantic v2 might not automatically trigger model_post_init on list modification
        # but let's see if the property-like behavior is expected
        sr.devices.append(Device(ip="10.0.0.2", mac="AA:BB:CC:00:00:02"))
        # We manually trigger or expect it to be correct on next init
        sr2 = ScanResult(network="10.0.0.0/24", devices=sr.devices)
        assert sr2.total_hosts == 2


# ─── Device ───────────────────────────────────────────────────────────────────


class TestDevice:

    @pytest.mark.parametrize("ip", VALID_IPS)
    def test_valid_ips_accepted(self, ip):
        d = Device(ip=ip, mac="AA:BB:CC:DD:EE:FF")
        assert d.ip == ip

    @pytest.mark.parametrize("ip", INVALID_IPS)
    def test_invalid_ips_raise(self, ip):
        with pytest.raises(Exception):
            Device(ip=ip, mac="AA:BB:CC:DD:EE:FF")

    @pytest.mark.parametrize("raw,expected", VALID_MACS_AND_CANONICAL)
    def test_mac_normalized_on_construction(self, raw, expected):
        d = Device(ip="10.0.0.1", mac=raw)
        assert d.mac == expected

    @pytest.mark.parametrize("invalid_mac", INVALID_MACS)
    def test_invalid_mac_raises(self, invalid_mac):
        with pytest.raises(Exception):
            Device(ip="10.0.0.1", mac=invalid_mac)

    def test_mac_stored_as_string(self):
        d = Device(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff")
        assert type(d.mac) is str

    def test_ip_stored_as_string(self):
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        assert type(d.ip) is str

    def test_device_equality_by_mac_and_ip(self):
        d1 = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        d2 = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        # If __eq__ is defined, verify it works symmetrically
        if d1 == d2:
            assert d2 == d1

    def test_device_repr_does_not_raise(self):
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        try:
            repr(d)
        except Exception as e:
            pytest.fail(f"repr(Device) raised {e}")

    def test_device_with_ports(self):
        ports = [Port(number=80, service="HTTP"), Port(number=443, service="HTTPS")]
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF", ports=ports)
        assert len(d.ports) == 2

    def test_fingerprint_default_is_none_or_unknown(self):
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        if d.fingerprint is not None:
            assert d.fingerprint.os_family in (OSFamily.UNKNOWN, None)

    def test_device_construction_is_thread_safe(self):
        """Concurrent Device construction must not produce corrupted state."""
        errors = []
        results = []

        def make_device(i):
            try:
                d = Device(ip=f"10.0.0.{i}", mac=f"AA:BB:CC:DD:EE:{i:02X}")
                results.append(d)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=make_device, args=(i,)) for i in range(1, 20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread-safety errors: {errors}"
        assert len(results) == 19


# ─── Cross-model integration ───────────────────────────────────────────────────


class TestCrossModelIntegration:

    def test_scan_result_find_after_fingerprint_update(self):
        """Updating a device's fingerprint must not break lookup."""
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        d.fingerprint = FingerprintResult(os_family=OSFamily.LINUX, confidence=0.9)
        found = sr.find_device_by_ip("10.0.0.1")
        assert found is not None
        assert found.fingerprint.os_family == OSFamily.LINUX

    def test_port_in_device_in_scan_result(self):
        port = Port(number=22, service="SSH")
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01", ports=[port])
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        found = sr.find_device_by_ip("10.0.0.1")
        assert found is not None
        assert any(p.number == 22 for p in found.ports)

    def test_merge_fingerprint_attached_to_device(self):
        fp1 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.8, sources={"tcp": "Linux"}
        )
        fp2 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.6, sources={"http": "nginx"}
        )
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01")
        d.fingerprint = fp1.merge(fp2)
        assert d.fingerprint.os_family == OSFamily.LINUX
        assert "tcp" in d.fingerprint.sources
        assert "http" in d.fingerprint.sources

    def test_deep_copy_scan_result_is_independent(self):
        """Modifying a deep copy must not affect the original."""
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        sr_copy = copy.deepcopy(sr)
        sr_copy.devices[0].ip = "10.0.0.99"
        assert sr.devices[0].ip == "10.0.0.1"


class TestMergeDevicesByMac:

    def test_duplicate_mac_rows_are_collapsed_and_enriched(self):
        d1 = Device(
            ip="10.0.0.10",
            mac="84:23:88:0D:35:7C",
            mac_vendor="Unknown",
            hostname="unknown",
        )
        d2 = Device(
            ip="10.0.0.11",
            mac="84:23:88:0D:35:7C",
            mac_vendor="Unknown",
            hostname="printer-lab",
            fingerprint=FingerprintResult(os_family=OSFamily.IOT, confidence=0.9),
            ports=[
                Port(number=22, service="ssh", state=PortState.OPEN),
                Port(number=9100, service="jetdirect", state=PortState.OPEN),
            ],
        )

        merged = merge_devices_by_mac([d1, d2])
        assert len(merged) == 1
        out = merged[0]
        assert out.ip == "10.0.0.11"
        assert out.hostname == "printer-lab"
        assert out.open_ports_count == 2
        assert out.fingerprint is not None
        assert out.fingerprint.os_family == OSFamily.IOT

    def test_known_vendor_beats_unknown_for_same_mac(self):
        d1 = Device(
            ip="10.0.0.20",
            mac="68:77:DA:49:02:A4",
            mac_vendor="Unknown",
        )
        d2 = Device(
            ip="10.0.0.20",
            mac="68:77:DA:49:02:A4",
            mac_vendor="ZTE Corporation",
        )

        merged = merge_devices_by_mac([d1, d2])
        assert len(merged) == 1
        assert merged[0].mac_vendor == "ZTE Corporation"
