# Network Scanner — Code Audit Report

**Project:** PFE Cybersécurité — Network Security Scanner  
**Authors:** ABIED Youssef / EL-BARAZI Meriem  
**Audit date:** 2026-05-05  
**Auditor:** Claude Code (Sonnet 4.6)

---

## Table of Contents

1. [Critical Bugs (will crash at runtime)](#1-critical-bugs)
2. [Security Issues](#2-security-issues)
3. [Logic & Design Bugs](#3-logic--design-bugs)
4. [Missing Features & Hardening](#4-missing-features--hardening)
5. [Code Quality](#5-code-quality)
6. [Dependency & Environment Issues](#6-dependency--environment-issues)
7. [Remediation Priority](#7-remediation-priority)
8. [Summary Table](#8-summary-table)

---

## 1. Critical Bugs

These issues will cause the program to **crash at runtime** — they must be fixed before any testing.

---

### BUG-01 — Missing `urllib` import in `mac_lookup.py`

**File:** `scanner/fingerprint/mac_lookup.py:258`  
**Severity:** CRITICAL

The function `_download_oui_database()` calls `urllib.request.urlopen()` but `urllib` is never imported. The module only imports `json` and `pathlib.Path`. Any code path that triggers the network OUI download will raise a `NameError` at runtime.

```python
# Line 258 — urllib is used but never imported at the top of the file
with urllib.request.urlopen(_OUI_URL, timeout=5) as response:
```

**Fix:**
```python
import urllib.request
```

---

### BUG-02 — Missing `as_completed` import in `port_scan.py`

**File:** `scanner/core/port_scan.py:9` and `scanner/core/port_scan.py:324`  
**Severity:** CRITICAL

Line 9 only imports `ThreadPoolExecutor` from `concurrent.futures`, but line 324 calls `as_completed()` which is never imported. Every port scan will crash with a `NameError`.

```python
# Line 9 — incomplete import
from concurrent.futures import ThreadPoolExecutor

# Line 324 — as_completed is used but not imported
for future in as_completed(future_to_port):
```

**Fix:**
```python
from concurrent.futures import ThreadPoolExecutor, as_completed
```

---

### BUG-03 — Duplicate `import argparse` in `main.py`

**File:** `scanner/main.py:9` and `scanner/main.py:369`  
**Severity:** LOW (harmless but signals a refactor debt)

`argparse` is imported twice — once at module level (line 9) and again inside the `main()` function (line 369). Not a crash risk but adds confusion.

---

## 2. Security Issues

---

### SEC-01 — Path traversal risk in export functions

**File:** `scanner/storage.py:414`, `scanner/storage.py:442`  
**Severity:** HIGH

The export path is constructed directly from `scan_id` without validating its format:

```python
output_path = _DB_PATH.parent / f"export_{scan_id[:8]}.json"
```

If `scan_id` ever comes from an untrusted source (e.g., a future API endpoint), an attacker could craft a value like `"../../etc/cron.d/x"` to write files outside the intended directory. Even though `scan_id` currently originates from the database, the function signature accepts any string.

**Fix:** Validate `scan_id` is a valid UUID before using it:
```python
import uuid
try:
    uuid.UUID(scan_id)
except ValueError:
    raise ValueError(f"Invalid scan_id format: {scan_id}")
```

---

### SEC-02 — Sensitive scan output sent to uncontrolled stdout

**File:** `scanner/main.py`, `scanner/storage.py`  
**Severity:** MEDIUM

All scan results (IP addresses, MAC addresses, hostnames, OS fingerprints, open ports) are printed to stdout with no access control. On a shared or multi-user system, this information is visible to any user who can read the terminal output or logs. There is no persistent audit trail.

**Fix:** Replace bare `print()` calls with Python's `logging` module and write to a file with restricted permissions (mode `0600`).

---

### SEC-03 — No input validation on `--network` CIDR argument

**File:** `scanner/main.py:381-385`  
**Severity:** MEDIUM

The `--network` CLI argument accepts any string and passes it directly to `get_local_network()` and then to `arp_scan()`. An invalid or malformed CIDR could cause unpredictable behavior or expose internal errors without a clear user message.

**Fix:**
```python
import ipaddress
try:
    ipaddress.ip_network(args.network, strict=False)
except ValueError as e:
    parser.error(f"Invalid network CIDR: {e}")
```

---

### SEC-04 — No input validation on `--timeout` argument

**File:** `scanner/main.py:387-391`  
**Severity:** LOW

The timeout is accepted as a `float` with no bounds check. A negative value or an extremely large value (e.g., `--timeout 99999`) could cause the scan to hang indefinitely or behave unexpectedly.

**Fix:**
```python
if args.timeout <= 0 or args.timeout > 30:
    parser.error("Timeout must be between 0.01 and 30 seconds")
```

---

### SEC-05 — HTTP banner parsing ignores HTTP status code

**File:** `scanner/fingerprint/http_banner.py`  
**Severity:** MEDIUM

The HTTP HEAD request parses headers regardless of the HTTP status code. A `404`, `500`, or `403` response will be parsed identically to a `200 OK`. This can produce false positives in OS fingerprinting because error pages often reveal different server software than the real service.

**Fix:** Parse the status line first and skip non-2xx responses when the goal is accurate fingerprinting.

---

### SEC-06 — No rate limiting between hosts

**File:** `scanner/main.py:170-176`, `scanner/core/port_scan.py:314`  
**Severity:** MEDIUM

The port scanner uses `max_workers=50` hardcoded (line 174 of `main.py`) with no configurable delay between connection attempts. On a congested or monitored network, this generates a burst of SYN packets that can:
- Trigger IDS/IPS alerts on the target network
- Cause packet loss that produces inaccurate results
- Overload low-resource devices (printers, IoT)

**Fix:** Expose `max_workers` as a CLI argument and add an optional `--rate-limit` flag (delay in ms between batches).

---

### SEC-07 — Database file has no permission enforcement

**File:** `scanner/storage.py:35-50`  
**Severity:** MEDIUM

The SQLite database is created in `scanner/data/scans.db` with default filesystem permissions (typically `0644`), meaning any local user can read all scan history. There is no code to restrict access after creation.

**Fix:** After `sqlite3.connect()`, set permissions explicitly:
```python
import os, stat
os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
```

---

### SEC-08 — SSL/TLS errors silently swallowed in `http_banner.py`

**File:** `scanner/fingerprint/http_banner.py:46-49`  
**Severity:** LOW

TLS connection attempts wrap `ssl.SSLError` exceptions but return `None` silently. For a security scanner, certificate validation failures (expired cert, self-signed cert, CN mismatch) are meaningful information about the target host and should be recorded, not discarded.

---

## 3. Logic & Design Bugs

---

### LOGIC-01 — Timezone-naive `datetime.now()` used throughout

**File:** `scanner/models.py:308`, `312`, `353`, `389`, `420`  
**Severity:** MEDIUM

All timestamps use `datetime.now()` which produces timezone-naive datetimes. When scans are compared across machines in different timezones, or when results are exported and processed elsewhere, timestamps become ambiguous.

**Fix:** Replace all occurrences with:
```python
from datetime import datetime, timezone
datetime.now(timezone.utc)
```

---

### LOGIC-02 — Unhandled `json.JSONDecodeError` on corrupt database rows

**File:** `scanner/storage.py:215-231`  
**Severity:** MEDIUM

When loading a scan, fingerprint `sources` are parsed with `json.loads()` inside a broad `except Exception` block that sets the entire fingerprint to `None`. A single corrupt row silently drops the entire device fingerprint rather than recovering gracefully.

**Fix:** Narrow the exception to `(json.JSONDecodeError, TypeError)` and fall back only the sources field to `{}`, not the entire fingerprint object.

---

### LOGIC-03 — DHCP fingerprinting is disabled but still prints a pipeline step

**File:** `scanner/main.py:195-201`  
**Severity:** LOW

Step 6 (DHCP fingerprinting) is commented out internally but the pipeline still announces it as an active step. This is misleading in output and in code review — it suggests an incomplete feature was shipped.

```python
# DHCP fingerprinting optionnel — à décommenter si réseau bien configuré
# devices = dhcp_enrich(devices, timeout=5)
print(_warning("    ⚠ DHCP fingerprinting désactivé (optionnel)"))
```

Either remove the step from the pipeline or add a `--dhcp` CLI flag to opt in.

---

### LOGIC-04 — `FingerprintResult.merge()` can combine contradictory OS results

**File:** `scanner/models.py` — `merge()` method  
**Severity:** MEDIUM

The merge strategy is "highest confidence wins for base, then union all sources." Two fingerprinters can produce contradictory results (e.g., one says `Windows`, another says `Linux`) and the merge will silently pick one without flagging the contradiction. The resulting confidence score can mislead the OS classifier downstream.

**Fix:** Before merging, check `os_family` compatibility. If families differ, keep the higher-confidence result but do not merge sources from the incompatible result.

---

### LOGIC-05 — `Port` list has no upper bound

**File:** `scanner/models.py` — `Device.ports` field  
**Severity:** LOW

The `ports` field is an unbounded list. In theory, a malformed scan result or a corrupted database row could create a device with thousands of port entries, exhausting memory during serialization or display.

**Fix (Pydantic v2):**
```python
ports: list[Port] = Field(default_factory=list, max_length=65535)
```

---

### LOGIC-06 — Single `recv()` call in banner grabbing may truncate data

**File:** `scanner/core/port_scan.py:232-285`  
**Severity:** MEDIUM

Banner grabbing uses a single `conn.recv(max_bytes)` call. TCP does not guarantee that one `recv()` returns all available data; on a loaded network the call may return only a partial response. The current code can silently truncate HTTP headers, leading to failed pattern matches and missed fingerprint signals.

**Fix:** Loop `recv()` until the connection closes or the buffer is full, or use a sentinel check for `\r\n\r\n` (end of HTTP headers).

---

## 4. Missing Features & Hardening

---

### FEAT-01 — No test suite

**Files:** Entire project  
**Severity:** HIGH

There are no unit tests, integration tests, or fixtures. The `requirements-dev.txt` lists `pytest` and `pytest-cov` but no `tests/` directory or `test_*.py` files exist. Critical code paths (MAC normalization, OUI lookup, port scan timeout logic, DB load/save round-trip) are entirely untested.

**Recommendation:** Create `tests/` with at minimum:
- Unit tests for `_normalize_mac()`, `_resolve_hostname()`, `FingerprintResult.merge()`
- A DB round-trip test using an in-memory SQLite database
- A mock ARP scan test to verify the pipeline without network access

---

### FEAT-02 — No persistent logging

**Files:** All modules  
**Severity:** HIGH

Every output uses `print()`. There is no structured log file, no log level control, and no way to replay what happened during a scan after the terminal closes. A security tool needs an audit trail.

**Recommendation:**
```python
import logging
logging.basicConfig(
    filename="scanner.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
```

---

### FEAT-03 — No SQLite connection timeout

**File:** `scanner/storage.py:41`  
**Severity:** MEDIUM

`sqlite3.connect(db_path)` uses the default timeout of 5 seconds. If another process holds a write lock (e.g., two concurrent scans), the second will raise `OperationalError: database is locked` with no clear user message.

**Fix:**
```python
conn = sqlite3.connect(db_path, timeout=10.0)
```

---

### FEAT-04 — Hardcoded database path with no environment variable override

**File:** `scanner/storage.py:34`  
**Severity:** LOW

```python
_DB_PATH = Path(__file__).parent / "data" / "scans.db"
```

The path is fixed relative to the source tree, making it impossible to redirect the database to `/var/lib/scanner/` or a tmpfs mount without modifying code.

**Fix:**
```python
import os
_DB_PATH = Path(os.getenv("SCANNER_DB_PATH", Path(__file__).parent / "data" / "scans.db"))
```

---

### FEAT-05 — No `--diff` or `--compare` subcommand exposed via CLI

**File:** `scanner/main.py`, `scanner/storage.py`  
**Severity:** LOW

`storage.py` implements `get_diff()` but `main.py` never exposes it as a CLI option. The feature is completely inaccessible to users without reading source code.

---

### FEAT-06 — No `--export` subcommand via CLI

**File:** `scanner/main.py`, `scanner/storage.py`  
**Severity:** LOW

Same as above: `export_json()` and `export_csv()` exist in `storage.py` but are not reachable from the CLI.

---

### FEAT-07 — `max_workers` hardcoded in main pipeline

**File:** `scanner/main.py:174`  
**Severity:** MEDIUM

`max_workers=50` is hardcoded in the `run_scan()` call. This value may be too aggressive for slow networks or under-resourced machines, and too conservative for fast LAN scanning. It should be a CLI argument.

---

## 5. Code Quality

---

### QA-01 — `argparse` imported twice in `main.py`

**File:** `scanner/main.py:9`, `scanner/main.py:369`

Already listed as BUG-03. Remove the inner import inside `main()`.

---

### QA-02 — F-string with no variable in `main.py`

**File:** `scanner/main.py:158`

```python
print(_info(f"\n[*] Étape 3 : MAC OUI lookup ..."))
```

This is a plain string wrapped in an f-string for no reason. Minor, but triggers linting warnings. Replace `f"..."` with `"..."` on any line that has no `{}` interpolation.

---

### QA-03 — Broad `except Exception` used throughout the pipeline

**File:** `scanner/main.py:162`, `179`, `190`, `201`, `211`, `220`, `237`

Every pipeline step catches `Exception` and continues. While the "non-blocking" strategy is intentional, it silently swallows unexpected bugs (e.g., `AttributeError`, `TypeError`) that should surface during development. The catches should at minimum log the full traceback at DEBUG level.

---

### QA-04 — Missing type annotation on internal helpers

**File:** `scanner/fingerprint/http_banner.py:118-156`

Pattern lists (`_SERVER_PATTERNS`, `_X_POWERED_PATTERNS`) are typed as `list[tuple]` without specifying the tuple element types. Mypy cannot catch mismatches inside these structures.

---

### QA-05 — No `__all__` in package `__init__.py` files

**Files:** `scanner/__init__.py`, `scanner/core/__init__.py`, `scanner/fingerprint/__init__.py`

Without `__all__`, any wildcard import (`from scanner import *`) will expose private helpers. Define explicit public APIs.

---

### QA-06 — No version identifier

**Files:** Entire project

There is no `__version__` string, no `pyproject.toml`, and no `setup.py`. It is impossible to know which version of the tool produced a given scan, which matters for reproducibility and bug reports.

---

## 6. Dependency & Environment Issues

---

### DEP-01 — `scapy` requires root but there is no privilege check at startup

**File:** `scanner/main.py:367` — `main()`  
**Severity:** HIGH

The ARP scan (step 2) requires `CAP_NET_RAW` or root privileges. The tool only discovers this at runtime when `arp_scan()` raises `PermissionError`. There is no early check or helpful startup message.

**Fix:** Add an early privilege check in `main()`:
```python
import os
if os.geteuid() != 0:
    print(_error("This tool requires root privileges. Run with sudo."))
    sys.exit(1)
```

---

### DEP-02 — `flask` and related packages in `requirements.txt` but not used

**File:** `requirements.txt:20-25`

`flask`, `flask-login`, `flask-limiter`, `flask-socketio`, `bcrypt` are listed as production dependencies but none of the current source files import them. They bloat the install and increase the attack surface.

**Fix:** Move these to a separate `requirements-web.txt` or add a comment marking them as "future / optional."

---

### DEP-03 — No version pinning strategy

**File:** `requirements.txt`, `requirements-dev.txt`

All dependencies use `>=` lower bounds only (e.g., `scapy>=2.5.0`). This means `pip install` in a new environment may pull in a breaking future version. For a security tool, reproducible builds matter.

**Fix:** Use `pip-compile` (from `pip-tools`) to generate a fully pinned `requirements.lock` from the current working environment.

---

### DEP-04 — No `.gitignore` for sensitive generated files

**Files:** Project root  
**Severity:** MEDIUM

The SQLite database (`scanner/data/scans.db`) and JSON/CSV exports contain real network topology data. If the project is pushed to a public repository, this data would be exposed. There is no `.gitignore` entry to prevent accidental commits of these files.

**Fix:** Add to `.gitignore`:
```
scanner/data/
*.db
export_*.json
export_*.csv
scanner.log
```

---

## 7. Remediation Priority

### Immediate — fix before any testing

| ID | File | Issue |
|----|------|-------|
| BUG-01 | `scanner/fingerprint/mac_lookup.py:258` | Add `import urllib.request` |
| BUG-02 | `scanner/core/port_scan.py:9` | Add `as_completed` to import |
| DEP-01 | `scanner/main.py` | Add root/privilege check at startup |

### Before sharing or deployment

| ID | File | Issue |
|----|------|-------|
| SEC-01 | `scanner/storage.py` | Validate `scan_id` as UUID before file writes |
| SEC-03 | `scanner/main.py` | Validate `--network` CIDR input |
| SEC-07 | `scanner/storage.py` | Set DB file permissions to `0600` |
| LOGIC-01 | `scanner/models.py` | Use timezone-aware `datetime.now(timezone.utc)` |
| FEAT-01 | `tests/` | Write a basic test suite |
| FEAT-02 | All modules | Replace `print()` with `logging` |
| DEP-04 | `.gitignore` | Block accidental commit of DB/export files |

### Nice to have

| ID | File | Issue |
|----|------|-------|
| SEC-02 | `scanner/main.py` | Restrict scan output visibility |
| SEC-06 | `scanner/main.py` | Expose `max_workers` and add rate limiting |
| FEAT-05 | `scanner/main.py` | Add `--diff` CLI subcommand |
| FEAT-06 | `scanner/main.py` | Add `--export` CLI subcommand |
| FEAT-07 | `scanner/main.py` | Make `max_workers` a CLI argument |
| LOGIC-03 | `scanner/main.py` | Remove or gate DHCP step behind a flag |
| DEP-02 | `requirements.txt` | Move Flask deps to optional requirements |
| DEP-03 | `requirements.txt` | Pin dependencies with `pip-compile` |
| QA-06 | project root | Add `__version__` / `pyproject.toml` |

---

## 8. Summary Table

| ID | Severity | Category | Description |
|----|----------|----------|-------------|
| BUG-01 | **CRITICAL** | Bug | `urllib` not imported in `mac_lookup.py` → `NameError` at runtime |
| BUG-02 | **CRITICAL** | Bug | `as_completed` not imported in `port_scan.py` → `NameError` at runtime |
| BUG-03 | LOW | Code quality | `import argparse` duplicated in `main.py` |
| SEC-01 | **HIGH** | Security | Path traversal via unvalidated `scan_id` in export functions |
| SEC-02 | MEDIUM | Security | Scan results printed to uncontrolled stdout with no audit trail |
| SEC-03 | MEDIUM | Security | `--network` CIDR argument not validated before use |
| SEC-04 | LOW | Security | `--timeout` argument has no bounds check |
| SEC-05 | MEDIUM | Security | HTTP banner parsing ignores status code — false positives |
| SEC-06 | MEDIUM | Security | No rate limiting; 50 concurrent threads hardcoded |
| SEC-07 | MEDIUM | Security | SQLite DB created with world-readable permissions |
| SEC-08 | LOW | Security | TLS errors silently discarded — no record of cert failures |
| LOGIC-01 | MEDIUM | Bug | `datetime.now()` is timezone-naive throughout the codebase |
| LOGIC-02 | MEDIUM | Bug | `json.JSONDecodeError` on DB row silently drops entire fingerprint |
| LOGIC-03 | LOW | Design | DHCP step announced in pipeline but always disabled |
| LOGIC-04 | MEDIUM | Design | `FingerprintResult.merge()` can silently combine contradictory OS results |
| LOGIC-05 | LOW | Design | `Device.ports` list is unbounded |
| LOGIC-06 | MEDIUM | Bug | Single `recv()` may truncate TCP banners |
| FEAT-01 | **HIGH** | Missing feature | No test suite despite `pytest` in dev requirements |
| FEAT-02 | **HIGH** | Missing feature | No persistent logging — only stdout |
| FEAT-03 | MEDIUM | Missing feature | No SQLite connection timeout |
| FEAT-04 | LOW | Missing feature | DB path not configurable via environment variable |
| FEAT-05 | LOW | Missing feature | `get_diff()` implemented but not exposed via CLI |
| FEAT-06 | LOW | Missing feature | `export_json/csv()` implemented but not exposed via CLI |
| FEAT-07 | MEDIUM | Missing feature | `max_workers` hardcoded, cannot be tuned via CLI |
| QA-01 | LOW | Code quality | Duplicate `import argparse` |
| QA-02 | LOW | Code quality | Redundant f-strings with no interpolation |
| QA-03 | LOW | Code quality | Broad `except Exception` hides real bugs during development |
| QA-04 | LOW | Code quality | Tuple element types missing in fingerprint pattern lists |
| QA-05 | LOW | Code quality | No `__all__` in package `__init__.py` files |
| QA-06 | LOW | Code quality | No `__version__` or `pyproject.toml` |
| DEP-01 | **HIGH** | Environment | No root privilege check at startup — confusing late failure |
| DEP-02 | MEDIUM | Environment | Flask and auth deps in production `requirements.txt` but unused |
| DEP-03 | MEDIUM | Environment | No pinned lockfile — non-reproducible installs |
| DEP-04 | MEDIUM | Environment | No `.gitignore` for DB / export files containing real network data |

---

*End of audit. No source files were modified.*
