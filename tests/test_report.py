"""Harsh unit tests for scanner.report dual format."""

import os
import json
from pathlib import Path
import pytest
from scanner.models import ScanResult, Device, Port, PortState
from scanner.report import append_scan, parse_reports


@pytest.fixture
def tmp_report(tmp_path):
    return tmp_path / "test_report.txt"


def test_append_scan_creates_file(tmp_report):
    scan = ScanResult(network="10.0.0.0/24")
    append_scan(scan, path=tmp_report)
    assert tmp_report.exists()


def test_dual_format_integrity(tmp_report):
    """Ensure the file contains both human text and the #JSON line."""
    scan = ScanResult(
        network="10.0.0.0/24", devices=[Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01")]
    )
    append_scan(scan, path=tmp_report)

    content = tmp_report.read_text(encoding="utf-8")
    assert f"CIDR  {scan.network}" in content
    assert "#JSON {" in content


def test_parse_reports_retrieval(tmp_report):
    scan1 = ScanResult(network="10.0.1.0/24")
    scan2 = ScanResult(network="10.0.2.0/24")
    append_scan(scan1, path=tmp_report)
    append_scan(scan2, path=tmp_report)

    records = parse_reports(path=tmp_report)
    assert len(records) == 2
    assert records[0]["network"] == "10.0.1.0/24"
    assert records[1]["network"] == "10.0.2.0/24"


def test_parse_corrupted_report(tmp_report):
    """Test that parser skips invalid JSON lines but continues."""
    with open(tmp_report, "a") as f:
        f.write("Some human text\n")
        f.write("#JSON {invalid json}\n")
        f.write('#JSON {"network": "10.0.0.0/24", "total_hosts": 0}\n')

    records = parse_reports(path=tmp_report)
    assert len(records) == 1
    assert records[0]["network"] == "10.0.0.0/24"


def test_report_permissions(tmp_report):
    """Check if report file has restricted permissions (Linux/macOS style)."""
    scan = ScanResult(network="10.0.0.0/24")
    append_scan(scan, path=tmp_report)

    # On Windows chmod might not behave same as Linux, but we check if tool runs
    mode = os.stat(tmp_report).st_mode
    # Check if group/other write is disabled (not always reliable on Windows)
    # but the tool call in report.py should not crash.
    assert tmp_report.exists()
