# Fixes Made — wadia

All changes implement the issues identified in `AUDIT.md`. No logic was removed or redesigned beyond what was required to fix each issue.

---

## Critical Bug Fixes

### BUG-01 — Added `import urllib.request` to `mac_lookup.py`
**File:** `scanner/fingerprint/mac_lookup.py`  
`urllib.request` was used on line 258 inside `_download_oui_database()` but was never imported. Added the missing import at the top of the file alongside the existing `json` and `pathlib` imports.

### BUG-02 — Added `as_completed` to import in `port_scan.py`
**File:** `scanner/core/port_scan.py`  
`as_completed` was called on line 324 but missing from the `concurrent.futures` import on line 9. Changed:
```python
# before
from concurrent.futures import ThreadPoolExecutor
# after
from concurrent.futures import ThreadPoolExecutor, as_completed
```

### BUG-03 — Removed duplicate `import argparse` in `main.py`
**File:** `scanner/main.py`  
`argparse` was imported at module level (line 9) and again inside `main()` (line 369). The redundant inner import was removed during the `main.py` rewrite.

---

## Security Fixes

### SEC-01 — UUID validation before export file paths
**File:** `scanner/storage.py`  
Added `_validate_scan_id()` helper that calls `uuid.UUID(scan_id)` and raises `ValueError` on failure. Called at the top of both `export_json()` and `export_csv()` before `scan_id` is embedded in any file path. Prevents path traversal via crafted `scan_id` strings.

### SEC-03 — CIDR validation on `--network` CLI argument
**File:** `scanner/main.py`  
Added `ipaddress.ip_network(args.network, strict=False)` validation after `parse_args()`. Invalid CIDR strings now exit with a clean error via `parser.error()` instead of propagating into the scan pipeline.

### SEC-04 — Bounds check on `--timeout` argument
**File:** `scanner/main.py`  
Added check: `0.01 <= args.timeout <= 30`. Values outside this range exit with `parser.error()`.

### SEC-05 — HTTP 5xx responses filtered before header parsing
**File:** `scanner/fingerprint/http_banner.py`  
Added a status-line check inside `http_banner()` before calling `_extract_headers()`. Responses starting with `5xx` are skipped — they rarely carry useful fingerprint headers and can produce false signals.

### SEC-06 — `max_workers` exposed as CLI argument with bounds check
**File:** `scanner/main.py`  
Added `--max-workers` argument (default 50, range 1–200). Previously hardcoded to 50 in the `run_scan()` call. Validated with `parser.error()` when out of range. `run_scan()` signature updated to accept `max_workers`.

### SEC-07 — Database file permissions set to 0600 after `init_db()`
**File:** `scanner/storage.py`  
Added `os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)` at the end of `init_db()`, right after the `_connect()` context closes. Added `import os, stat` to imports. Failure to chmod is silently ignored (e.g., on Windows) via `except OSError: pass`.

---

## Logic & Design Fixes

### LOGIC-01 — All datetimes are now timezone-aware (UTC)
**File:** `scanner/models.py`  
Changed `from datetime import datetime` to `from datetime import datetime, timezone`. Updated all four `default_factory=datetime.now` fields to `lambda: datetime.now(timezone.utc)`:
- `Device.first_seen`
- `Device.last_seen`
- `ScanResult.timestamp`

Updated `mark_offline()` to use `datetime.now(timezone.utc)`.

Updated the `age` property to be robust against mixed naive/aware datetimes (existing DB records store naive timestamps):
```python
now = datetime.now(timezone.utc)
fs = self.first_seen
if fs.tzinfo is None:
    fs = fs.replace(tzinfo=timezone.utc)
return (now - fs).total_seconds()
```

### LOGIC-02 — JSON parsing in `_row_to_device()` is now narrowly scoped
**File:** `scanner/storage.py`  
Previously, a `json.JSONDecodeError` on the `fp_sources` field would cause the entire broad `except Exception` to set `fp = None`, silently dropping all fingerprint data for that device. Now `fp_sources` is parsed first in a dedicated `try/except (json.JSONDecodeError, TypeError)` block that falls back to `{}`. The main `FingerprintResult` construction only catches unexpected model errors.

### LOGIC-03 — DHCP step is now properly gated behind `--dhcp` flag
**File:** `scanner/main.py`  
The DHCP step was always announced in the pipeline but always disabled internally. Replaced the permanently-disabled step with a clean `if enable_dhcp: … else: …` block. Users activate it with `--dhcp`. The `run_scan()` signature now accepts `enable_dhcp: bool = False`.

### LOGIC-04 — `FingerprintResult.merge()` no longer mixes contradictory OS sources
**File:** `scanner/models.py`  
The previous merge always combined `sources` from both results. Now, if both fingerprints have known (non-UNKNOWN) but different OS families, only the base (higher-confidence) result's sources are kept. When OS families are compatible (same family, or either is UNKNOWN), sources are merged as before.

---

## Missing Feature Implementations

### FEAT-01 — Basic test suite created
**Files:** `tests/__init__.py`, `tests/test_models.py`, `tests/test_storage.py`  
Created a `tests/` directory with two test files runnable with `pytest`:
- `test_models.py` — 20 unit tests covering MAC normalisation, `FingerprintResult.merge()`, `Port` field validation, `ScanResult` network validation, `Device` IP/MAC validation.
- `test_storage.py` — 10 integration tests covering DB round-trips, fingerprint and port preservation, `list_scans`, `load_last_scan`, and UUID validation in export functions. Uses `pytest`'s built-in `tmp_path` fixture — no manual cleanup needed.

Run with:
```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

### FEAT-02 — Persistent file logging added
**File:** `scanner/main.py`  
Added `_setup_logging()` using Python's `logging` module. Writes to `scanner.log` by default. Controlled via new `--log-file` CLI argument. Key events logged: scan start/end, each pipeline step success/failure, host counts, save/export results, and fatal errors (with `_log.exception` for full tracebacks).

### FEAT-03 — SQLite connection timeout set
**File:** `scanner/storage.py`  
Changed `sqlite3.connect(db_path)` to `sqlite3.connect(db_path, timeout=10.0)`. Prevents indefinite blocking when a concurrent process holds a write lock.

### FEAT-04 — DB path configurable via environment variable
**File:** `scanner/storage.py`  
Changed:
```python
# before
_DB_PATH = Path(__file__).parent / "data" / "scans.db"
# after
_DB_PATH = Path(
    os.environ.get("SCANNER_DB_PATH")
    or (Path(__file__).parent / "data" / "scans.db")
)
```
Set `SCANNER_DB_PATH=/var/lib/scanner/scans.db` to redirect the database without touching code.

### FEAT-05 — `--diff` subcommand added to CLI
**File:** `scanner/main.py`  
Added `--diff NEW_ID OLD_ID` argument and `run_diff()` function. Calls the existing `get_diff()` from `storage.py` and displays: new hosts, lost hosts, and ports that opened or closed between the two scans — all with colour coding.

### FEAT-06 — `--export` subcommand added to CLI
**File:** `scanner/main.py`  
Added `--export SCAN_ID` and `--format json|csv` arguments and `run_export()` function. Calls the existing `export_json()` / `export_csv()` from `storage.py`.

### FEAT-07 — `max_workers` exposed (covered by SEC-06 above)
See SEC-06.

---

## Code Quality Fixes

### QA-02 — Redundant f-strings removed
**File:** `scanner/main.py`  
Removed `f"..."` prefix from string literals that contained no `{}` interpolation (e.g., `f"\n[*] Étape 3 : MAC OUI lookup ..."`).

### QA-04 — Pattern list type hints corrected
**File:** `scanner/fingerprint/http_banner.py`  
Changed:
```python
_SERVER_PATTERNS: list[tuple] = [...]
_X_POWERED_PATTERNS: list[tuple] = [...]
```
to:
```python
_SERVER_PATTERNS: list[tuple[str, str, str, str, float]] = [...]
_X_POWERED_PATTERNS: list[tuple[str, str, str, str, float]] = [...]
```

---

## Dependency & Environment Fixes

### DEP-01 — Root privilege check at startup
**File:** `scanner/main.py`  
Added `os.geteuid() != 0` check at the very top of `main()`. If not root, prints a clear error and exits with code 1 before any argument is parsed. No more cryptic Scapy `PermissionError` after a 30-second scan.

### DEP-02 — Flask dependencies moved out of `requirements.txt`
**Files:** `requirements.txt`, `requirements-web.txt` (new)  
Removed `flask`, `flask-login`, `flask-limiter`, `flask-socketio`, `bcrypt` from `requirements.txt`. Created `requirements-web.txt` for optional web dashboard use. Prevents these packages from being installed in production scanner deployments that don't need a web UI.

### DEP-04 — `.gitignore` created
**File:** `.gitignore` (new)  
Added entries to block accidental commits of:
- `scanner/data/` — SQLite DB with real network topology
- `export_*.json` / `export_*.csv` — exported scan data
- `scanner.log` / `*.log` — log files
- `venv/` / `.venv/` — virtual environments
- Python cache (`__pycache__/`, `*.pyc`)

---

## Files Changed

| File | Change type |
|------|-------------|
| `scanner/fingerprint/mac_lookup.py` | Bug fix (missing import) |
| `scanner/core/port_scan.py` | Bug fix (missing import) |
| `scanner/models.py` | Bug fix + security + logic |
| `scanner/storage.py` | Security + logic + features |
| `scanner/fingerprint/http_banner.py` | Security + code quality |
| `scanner/main.py` | Rewrite — all remaining fixes |
| `requirements.txt` | Dependency cleanup |
| `requirements-web.txt` | New — extracted web deps |
| `.gitignore` | New |
| `tests/__init__.py` | New |
| `tests/test_models.py` | New — 20 unit tests |
| `tests/test_storage.py` | New — 10 integration tests |

---

## Recommendations

These are improvements that go beyond the audit scope but would meaningfully strengthen the project for a production or academic submission context.

### R-01 — Replace bare `print()` calls in pipeline modules with `logging`
`mac_lookup.py`, `port_scan.py`, `arp_scan.py`, and the fingerprint modules all use bare `print()`. The fix in `main.py` only logs at the orchestration level. Propagating `logging` into every sub-module would give a complete audit trail (e.g., which OUI was matched, which banner was grabbed) and allow users to control verbosity with `--verbose` / `--quiet` flags without touching source code.

### R-02 — Add `--output-json` / `--output-csv` to automatically export after a scan
Currently, export requires a second invocation with the scan ID. A `--output-json results.json` flag on the main scan command would make it far more useful in scripted/CI pipelines.

### R-03 — Pin dependencies with `pip-compile`
All packages currently use `>=` lower bounds only (e.g., `scapy>=2.5.0`). This means two `pip install -r requirements.txt` runs on different days can produce different environments. Run:
```bash
pip install pip-tools
pip-compile requirements.txt -o requirements.lock
```
And commit `requirements.lock`. Use `pip install -r requirements.lock` in CI and production.

### R-04 — Add a `--scan-id` filter to `--list` and paginate results
`list_scans()` returns all scans in reverse chronological order with no limit. On a long-running deployment, this can produce hundreds of rows. Add `--limit N` to cap the display and optionally `--network CIDR` to filter.

### R-05 — Implement scan scheduling / daemon mode
For continuous network monitoring (a natural extension of a PFE project), a `--watch INTERVAL` flag that re-runs the scan every N minutes and auto-diffs against the previous result would demonstrate real operational value. Could be implemented as a simple loop in `main.py` without any additional dependencies.

### R-06 — Move DB schema to a migration system (e.g., Alembic)
The current `executescript` in `init_db()` uses `CREATE TABLE IF NOT EXISTS`, which means schema changes (new columns, indexes) require manual `ALTER TABLE` on existing databases. A lightweight migration system (even a hand-rolled version counter in a `schema_version` table) prevents silent data loss when upgrading.

### R-07 — Add a web dashboard (Flask is already in `requirements-web.txt`)
The project already has Flask listed. A minimal single-page dashboard showing the last scan result, a timeline of `total_hosts` over time, and a diff view would make this immediately useful and visually impressive for a PFE presentation. The `export_json()` output can serve as the data source.

### R-08 — Containerise with Docker
A `Dockerfile` and `docker-compose.yml` would let reviewers and professors run the tool without installing Scapy and its system dependencies manually. Key consideration: the container needs `NET_RAW` capability (`--cap-add=NET_RAW`) for ARP scanning, which is a good teaching point about Linux capabilities.
