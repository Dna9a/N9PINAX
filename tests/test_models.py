"""Unit tests for scanner.models — no network access required."""
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
)


class TestNormalizeMac:
    def test_colon_format(self):
        assert _normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_dash_format(self):
        assert _normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"

    def test_cisco_format(self):
        assert _normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"

    def test_raw_format(self):
        assert _normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            _normalize_mac("")

    def test_invalid_chars_raises(self):
        with pytest.raises(ValueError):
            _normalize_mac("GG:BB:CC:DD:EE:FF")

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            _normalize_mac("aa:bb:cc")


class TestFingerprintMerge:
    def test_higher_confidence_wins(self):
        fp1 = FingerprintResult(os_family=OSFamily.WINDOWS, confidence=0.9)
        fp2 = FingerprintResult(os_family=OSFamily.LINUX, confidence=0.5)
        merged = fp1.merge(fp2)
        assert merged.os_family == OSFamily.WINDOWS
        assert merged.confidence == pytest.approx(0.9)

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

    def test_sources_not_merged_when_incompatible_os(self):
        fp1 = FingerprintResult(
            os_family=OSFamily.WINDOWS, confidence=0.9, sources={"iis": "IIS/10.0"}
        )
        fp2 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.5, sources={"http": "nginx"}
        )
        merged = fp1.merge(fp2)
        assert "iis" in merged.sources
        assert "http" not in merged.sources

    def test_merge_with_unknown_os_merges_sources(self):
        fp1 = FingerprintResult(
            os_family=OSFamily.LINUX, confidence=0.7, sources={"tcp": "Linux"}
        )
        fp2 = FingerprintResult(
            os_family=OSFamily.UNKNOWN, confidence=0.4, sources={"mac": "Raspberry Pi"}
        )
        merged = fp1.merge(fp2)
        assert "tcp" in merged.sources
        assert "mac" in merged.sources

    def test_confidence_clamped(self):
        fp = FingerprintResult(confidence=0.5)
        fp.update_confidence(1.0)
        assert fp.confidence == pytest.approx(1.0)

    def test_confidence_not_below_zero(self):
        fp = FingerprintResult(confidence=0.3)
        fp.update_confidence(-1.0)
        assert fp.confidence == pytest.approx(0.0)


class TestPortValidation:
    def test_valid_port(self):
        p = Port(number=80, service="HTTP")
        assert p.number == 80
        assert p.service == "HTTP"

    def test_port_too_low(self):
        with pytest.raises(Exception):
            Port(number=0, service="test")

    def test_port_too_high(self):
        with pytest.raises(Exception):
            Port(number=65536, service="test")

    def test_banner_max_length(self):
        long_banner = "A" * 600
        p = Port(number=80, service="HTTP", banner=long_banner)
        assert len(p.banner) <= 512

    def test_non_printable_service_sanitized(self):
        p = Port(number=22, service="SSH\x00\x01")
        assert "\x00" not in p.service


class TestScanResultValidation:
    def test_valid_cidr(self):
        sr = ScanResult(network="192.168.1.0/24")
        assert sr.network == "192.168.1.0/24"

    def test_host_cidr(self):
        sr = ScanResult(network="192.168.1.5/24")
        assert sr.network == "192.168.1.5/24"

    def test_invalid_network_raises(self):
        with pytest.raises(Exception):
            ScanResult(network="not-a-network")

    def test_total_hosts_computed(self):
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        assert sr.total_hosts == 1


class TestDeviceValidation:
    def test_valid_device(self):
        d = Device(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff")
        assert d.ip == "192.168.1.1"
        assert d.mac == "AA:BB:CC:DD:EE:FF"

    def test_invalid_ip_raises(self):
        with pytest.raises(Exception):
            Device(ip="999.999.999.999", mac="AA:BB:CC:DD:EE:FF")

    def test_mac_normalized(self):
        d = Device(ip="10.0.0.1", mac="aa-bb-cc-dd-ee-ff")
        assert d.mac == "AA:BB:CC:DD:EE:FF"

    def test_find_by_mac(self):
        d = Device(ip="10.0.0.1", mac="AA:BB:CC:00:00:01")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        found = sr.find_device_by_mac("aa:bb:cc:00:00:01")
        assert found is not None
        assert found.ip == "10.0.0.1"

    def test_find_by_ip(self):
        d = Device(ip="10.0.0.2", mac="AA:BB:CC:00:00:02")
        sr = ScanResult(network="10.0.0.0/24", devices=[d])
        found = sr.find_device_by_ip("10.0.0.2")
        assert found is not None
