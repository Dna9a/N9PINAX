"""Integration/Mock tests for scanner core logic (ICMP, SYN, etc)."""

import pytest
from unittest.mock import patch, MagicMock
from scanner.core.icmp_scan import icmp_sweep, IcmpReply


def test_icmp_sweep_malformed_network():
    with pytest.raises(ValueError, match="Réseau invalide"):
        icmp_sweep("not-a-network")


@patch("scanner.core.icmp_scan._icmp_probe")
def test_icmp_sweep_success(mock_probe):
    # Mock probes for 192.168.1.0/30 (4 IPs: .0, .1, .2, .3)
    # usually network/broadcast addresses might be excluded by net.hosts()
    # Let's assume net.hosts() is used.

    mock_probe.side_effect = lambda ip, timeout: IcmpReply(
        ip=ip,
        ttl=64 if ip == "192.168.1.1" else None,
        rtt_ms=1.5 if ip == "192.168.1.1" else None,
        alive=(ip == "192.168.1.1"),
    )

    # Use a small range to avoid many mock calls
    results = icmp_sweep("192.168.1.0/30")

    # net.hosts() for 192.168.1.0/30 yields .1 and .2
    # If it yielded more, adjusted accordingly.
    alive_ips = [r.ip for r in results if r.alive]
    assert "192.168.1.1" in alive_ips
    assert "192.168.1.2" not in alive_ips


@patch("scanner.core.icmp_scan.get_config")
def test_rate_limiter_not_crashing(mock_config):
    # Simple check that the rate limiter logic runs
    # We won't test timing precisely here to avoid flaky tests,
    # but ensure it doesn't Raise.
    mock_config.return_value.rate_limit_pps = 1000
    from scanner.core.icmp_scan import _rate_limited_sleep

    _rate_limited_sleep()  # Should pass immediately
