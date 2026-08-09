# scanner/storage.py
# Persistance des résultats de scan — SQLite + export CSV/JSON
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import csv
import json
import logging
import os
import sqlite3
import stat
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import get_config
from .models import (
    Alert,
    AlertSeverity,
    Device,
    FingerprintResult,
    OSFamily,
    DeviceType,
    Port,
    PortState,
    PortProtocol,
    ScanResult,
)

_log = logging.getLogger(__name__)


def _csv_safe(value) -> str:
    """Neutralise CSV/spreadsheet formula injection.

    A cell whose text begins with ``=``, ``+``, ``-``, ``@`` (or a leading tab/
    CR) is executed as a formula by Excel/LibreOffice when an analyst opens the
    exported report. Several CSV columns carry attacker-influenceable text —
    hostnames (spoofable via reverse-DNS/PTR) and OS versions derived from
    service banners — so we prefix a single quote to force text interpretation
    (audit F-024). Returns "" for None.
    """
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

_DB_PATH = Path(
    os.environ.get("SCANNER_DB_PATH") or (Path(__file__).parent / "data" / "scans.db")
)

# Default admin account seeded on first run when the users table is empty.
# Hash below is bcrypt of "1234" (work factor 12) — same credentials the
# backend documents. Stored as a constant so storage.py needs no bcrypt import.
_DEFAULT_ADMIN_ID = "00000000-0000-0000-0000-000000000001"
_DEFAULT_ADMIN_EMAIL = "na9a"
_DEFAULT_ADMIN_HASH = "$2b$12$oSAcGwLfr1cH1124ks8lC.mBVKq6lOHAoeWlG5xUmu4NVKVUpkiky"


def _now_iso() -> str:
    """UTC timestamp in ISO-8601 — used for created_at / updated_at columns."""
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────


def _validate_scan_id(scan_id: str) -> None:
    """Ensure scan_id is a valid UUID to prevent path traversal in export paths."""
    try:
        val = uuid.UUID(scan_id)
        if str(val) != scan_id:
            raise ValueError
    except (ValueError, AttributeError, TypeError):
        raise ValueError(f"scan_id invalide (doit être un UUID) : '{scan_id}'")


def _prune_old_scans(conn: sqlite3.Connection, keep_n: int) -> None:
    """
    Delete scans beyond the newest ``keep_n``.

    Devices / ports / alerts cascade away via ON DELETE CASCADE; notes linked
    to a pruned scan keep their content (scan_id is set NULL by the FK rule).
    A non-positive ``keep_n`` disables pruning entirely.
    """
    if keep_n <= 0:
        return
    conn.execute(
        """
        DELETE FROM scans WHERE scan_id NOT IN (
            SELECT scan_id FROM scans ORDER BY timestamp DESC LIMIT ?
        )
        """,
        (keep_n,),
    )


def _ensure_column(
    conn: sqlite3.Connection, table: str, column: str, decl: str
) -> None:
    """Add a column to an existing table only if it isn't there already."""
    info = conn.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {row[1] for row in info}
    if column not in existing:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        except sqlite3.OperationalError:
            # Table doesn't exist yet — CREATE TABLE will set it up.
            pass


# ─────────────────────────────────────────────
# Connexion
# ─────────────────────────────────────────────


@contextmanager
def _connect(db_path: str | Path = _DB_PATH):
    """Context manager — ouvre et ferme la connexion SQLite proprement."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row  # accès par nom de colonne
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")  # meilleure concurrence
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Initialisation du schéma
# ─────────────────────────────────────────────


def init_db(db_path: str | Path = _DB_PATH) -> None:
    """
    Crée les tables si elles n'existent pas.
    Appelé une fois au démarrage.
    """
    path = Path(db_path)
    with _connect(path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT    NOT NULL UNIQUE,
                network         TEXT    NOT NULL,
                timestamp       TEXT    NOT NULL,
                total_hosts     INTEGER NOT NULL DEFAULT 0,
                duration_seconds REAL   NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id    TEXT    NOT NULL UNIQUE,
                scan_id     TEXT    REFERENCES scans(scan_id) ON DELETE CASCADE,
                timestamp   TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                category    TEXT    NOT NULL,
                title       TEXT    NOT NULL,
                description TEXT    NOT NULL DEFAULT '',
                ip          TEXT,
                mac         TEXT,
                port        INTEGER,
                service     TEXT,
                resolved    INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_scan_id   ON alerts(scan_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved);

            CREATE TABLE IF NOT EXISTS devices (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id      TEXT    NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                ip           TEXT    NOT NULL,
                mac          TEXT    NOT NULL,
                hostname     TEXT    NOT NULL DEFAULT 'unknown',
                mac_vendor   TEXT    NOT NULL DEFAULT 'Unknown',
                is_online    INTEGER NOT NULL DEFAULT 1,
                first_seen   TEXT    NOT NULL,
                last_seen    TEXT    NOT NULL,
                -- Fingerprint (dénormalisé pour simplicité)
                os_family    TEXT,
                os_version   TEXT,
                device_type  TEXT,
                device_vendor TEXT,
                confidence   REAL,
                fp_sources   TEXT,   -- JSON string
                tcp_ttl      INTEGER,
                tcp_window   INTEGER
            );

            CREATE TABLE IF NOT EXISTS ports (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                number     INTEGER NOT NULL,
                state      TEXT    NOT NULL,
                protocol   TEXT    NOT NULL DEFAULT 'tcp',
                service    TEXT    NOT NULL DEFAULT 'unknown',
                banner     TEXT,
                os_hint    TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id);
            CREATE INDEX IF NOT EXISTS idx_devices_mac     ON devices(mac);
            CREATE INDEX IF NOT EXISTS idx_ports_device_id ON ports(device_id);

            CREATE TABLE IF NOT EXISTS users (
                user_id       TEXT PRIMARY KEY,
                email         TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'analyst',
                created_at    TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

            CREATE TABLE IF NOT EXISTS notes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                note_id     TEXT    NOT NULL UNIQUE,
                title       TEXT    NOT NULL DEFAULT 'Untitled',
                content     TEXT    NOT NULL DEFAULT '',
                author      TEXT    NOT NULL DEFAULT 'admin',
                scan_id     TEXT    REFERENCES scans(scan_id) ON DELETE SET NULL,
                device_ip   TEXT,
                tags        TEXT,
                created_at  TEXT    NOT NULL,
                updated_at  TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_notes_scan_id   ON notes(scan_id);
            CREATE INDEX IF NOT EXISTS idx_notes_author    ON notes(author);
            CREATE INDEX IF NOT EXISTS idx_notes_created   ON notes(created_at);
        """)

        # ── Migrations (safe ALTERs for older databases) ─────────────────
        _ensure_column(conn, "scans", "duration_seconds", "REAL NOT NULL DEFAULT 0")
        _ensure_column(conn, "devices", "latency_ms", "REAL")

        # ── Seed the default admin account on first run ──────────────────
        try:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if user_count == 0:
                conn.execute(
                    """
                    INSERT INTO users
                        (user_id, email, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        _DEFAULT_ADMIN_ID,
                        _DEFAULT_ADMIN_EMAIL,
                        _DEFAULT_ADMIN_HASH,
                        "admin",
                        _now_iso(),
                    ),
                )
        except sqlite3.OperationalError:
            pass

    # Restrict DB file access to owner only (mode 0600)
    try:
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    print(f"[+] Base de données initialisée : {db_path}")


# ─────────────────────────────────────────────
# Sauvegarde
# ─────────────────────────────────────────────


def save_scan(
    scan: ScanResult,
    db_path: str | Path = _DB_PATH,
    keep_last_n: int | None = None,
) -> str:
    """
    Sauvegarde un ScanResult complet en base.

    Args:
        scan:        ScanResult à persister.
        db_path:     Chemin de la base SQLite.
        keep_last_n: Retain only the newest N scans (older ones are pruned).
                     Defaults to the configured ``keep_last_n_scans``.

    Returns:
        scan_id du scan sauvegardé.
    """
    path = Path(db_path)
    if keep_last_n is None:
        keep_last_n = get_config().keep_last_n_scans
    with _connect(path) as conn:

        # ── Table scans ───────────────────────────────────────
        conn.execute(
            """
            INSERT OR REPLACE INTO scans
                (scan_id, network, timestamp, total_hosts, duration_seconds)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                scan.scan_id,
                scan.network,
                scan.timestamp.isoformat(),
                scan.total_hosts,
                float(getattr(scan, "duration_seconds", 0.0) or 0.0),
            ),
        )

        for device in scan.devices:

            fp = device.fingerprint

            # ── Table devices ─────────────────────────────────
            cursor = conn.execute(
                """
                INSERT INTO devices (
                    scan_id, ip, mac, hostname, mac_vendor,
                    is_online, first_seen, last_seen,
                    os_family, os_version, device_type, device_vendor,
                    confidence, fp_sources, tcp_ttl, tcp_window, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    scan.scan_id,
                    device.ip,
                    device.mac,
                    device.hostname,
                    device.mac_vendor,
                    int(device.is_online),
                    device.first_seen.isoformat(),
                    device.last_seen.isoformat(),
                    fp.os_family.value if fp else None,
                    fp.os_version if fp else None,
                    fp.device_type.value if fp else None,
                    fp.device_vendor if fp else None,
                    fp.confidence if fp else None,
                    json.dumps(fp.sources) if fp else None,
                    fp.tcp_ttl if fp else None,
                    fp.tcp_window if fp else None,
                    device.latency_ms,
                ),
            )

            device_id = cursor.lastrowid

            # ── Table ports ───────────────────────────────────
            for port in device.ports:
                conn.execute(
                    """
                    INSERT INTO ports (device_id, number, state, protocol, service, banner, os_hint)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        device_id,
                        port.number,
                        port.state.value,
                        port.protocol.value,
                        port.service,
                        port.banner,
                        port.os_hint,
                    ),
                )

        # ── Table alerts ──────────────────────────────────────
        for alert in getattr(scan, "alerts", []) or []:
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO alerts
                        (alert_id, scan_id, timestamp, severity, category,
                         title, description, ip, mac, port, service, resolved)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.alert_id,
                        scan.scan_id,
                        alert.timestamp.isoformat(),
                        alert.severity.value,
                        alert.category,
                        alert.title,
                        alert.description,
                        alert.ip,
                        alert.mac,
                        alert.port,
                        alert.service,
                        int(alert.resolved),
                    ),
                )
            except sqlite3.Error:
                # Best-effort — never let alert persistence break a scan save.
                continue

        # ── Retention: prune scans beyond the newest keep_last_n ──────
        try:
            _prune_old_scans(conn, keep_last_n)
        except sqlite3.Error as e:
            _log.warning("Scan retention pruning failed: %s", e)

    print(f"[+] Scan sauvegardé : {scan.scan_id} ({scan.total_hosts} hôte(s))")
    return scan.scan_id


# ─────────────────────────────────────────────
# Lecture
# ─────────────────────────────────────────────


def _row_to_device(row: sqlite3.Row, ports: list[sqlite3.Row]) -> Device:
    """Reconstruit un Device depuis les lignes SQLite."""

    # Parse fp_sources separately to handle corruption without dropping the whole fingerprint
    fp_sources: dict = {}
    if row["fp_sources"]:
        try:
            parsed = json.loads(row["fp_sources"])
            if isinstance(parsed, dict):
                fp_sources = parsed
        except (json.JSONDecodeError, TypeError):
            pass  # Corrupt sources field — fall back to empty dict

    # Fingerprint
    fp = None
    if row["os_family"]:
        try:
            fp = FingerprintResult(
                os_family=OSFamily(row["os_family"]),
                os_version=row["os_version"],
                device_type=(
                    DeviceType(row["device_type"])
                    if row["device_type"]
                    else DeviceType.UNKNOWN
                ),
                device_vendor=row["device_vendor"],
                confidence=row["confidence"] or 0.0,
                sources=fp_sources,
                tcp_ttl=row["tcp_ttl"],
                tcp_window=row["tcp_window"],
            )
        except Exception:
            fp = None

    # Ports
    port_list = []
    for p in ports:
        try:
            port_list.append(
                Port(
                    number=p["number"],
                    state=PortState(p["state"]),
                    protocol=PortProtocol(p["protocol"]),
                    service=p["service"],
                    banner=p["banner"],
                    os_hint=p["os_hint"],
                )
            )
        except Exception as e:
            _log.debug("Dropping malformed port row for %s: %s", row["ip"], e)
            continue

    latency_ms: float | None = None
    try:
        latency_ms = row["latency_ms"]
    except (IndexError, KeyError):
        pass

    return Device(
        ip=row["ip"],
        mac=row["mac"],
        hostname=row["hostname"],
        mac_vendor=row["mac_vendor"],
        is_online=bool(row["is_online"]),
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
        fingerprint=fp,
        ports=port_list,
        latency_ms=latency_ms,
    )


def load_scan(scan_id: str, db_path: str | Path = _DB_PATH) -> ScanResult | None:
    """
    Charge un ScanResult depuis la base par son scan_id.

    Returns:
        ScanResult ou None si non trouvé.
    """
    path = Path(db_path)
    with _connect(path) as conn:
        scan_row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()

        if scan_row is None:
            return None

        device_rows = conn.execute(
            "SELECT * FROM devices WHERE scan_id = ?", (scan_id,)
        ).fetchall()

        devices = []
        for d_row in device_rows:
            port_rows = conn.execute(
                "SELECT * FROM ports WHERE device_id = ?", (d_row["id"],)
            ).fetchall()
            devices.append(_row_to_device(d_row, port_rows))

    # Load duration + alerts (best-effort — older DBs may not have them)
    duration_seconds = 0.0
    try:
        duration_seconds = float(scan_row["duration_seconds"] or 0.0)
    except (IndexError, KeyError, TypeError):
        pass

    alerts: list[Alert] = []
    try:
        with _connect(path) as conn:
            alert_rows = conn.execute(
                "SELECT * FROM alerts WHERE scan_id = ? ORDER BY timestamp", (scan_id,)
            ).fetchall()
        for a_row in alert_rows:
            try:
                alerts.append(
                    Alert(
                        alert_id=a_row["alert_id"],
                        scan_id=a_row["scan_id"],
                        timestamp=datetime.fromisoformat(a_row["timestamp"]),
                        severity=AlertSeverity(a_row["severity"]),
                        category=a_row["category"],
                        title=a_row["title"],
                        description=a_row["description"] or "",
                        ip=a_row["ip"],
                        mac=a_row["mac"],
                        port=a_row["port"],
                        service=a_row["service"],
                        resolved=bool(a_row["resolved"]),
                    )
                )
            except Exception:
                continue
    except sqlite3.OperationalError:
        # Alerts table may not exist in very old DBs.
        pass

    return ScanResult(
        scan_id=scan_row["scan_id"],
        network=scan_row["network"],
        timestamp=datetime.fromisoformat(scan_row["timestamp"]),
        devices=devices,
        duration_seconds=duration_seconds,
        alerts=alerts,
    )


def load_last_scan(db_path: Path = _DB_PATH) -> ScanResult | None:
    """
    Charge le scan le plus récent.

    Returns:
        ScanResult ou None si aucun scan en base.
    """
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT scan_id FROM scans ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()

    if row is None:
        return None

    return load_scan(row["scan_id"], db_path)


def list_alerts(
    db_path: str | Path = _DB_PATH,
    limit: int = 100,
    severity: str | None = None,
    only_unresolved: bool = False,
) -> list[dict]:
    """List recent alerts ordered by timestamp DESC for the SSE / dashboard layer."""
    path = Path(db_path)
    sql = "SELECT * FROM alerts"
    clauses: list[str] = []
    params: list = []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if only_unresolved:
        clauses.append("resolved = 0")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(int(limit))

    with _connect(path) as conn:
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            return []

    return [dict(r) for r in rows]


def mark_alert_resolved(alert_id: str, db_path: str | Path = _DB_PATH) -> bool:
    """Flag a single alert as resolved. Returns True if a row was updated."""
    path = Path(db_path)
    with _connect(path) as conn:
        try:
            cur = conn.execute(
                "UPDATE alerts SET resolved = 1 WHERE alert_id = ?", (alert_id,)
            )
        except sqlite3.OperationalError:
            return False
    return cur.rowcount > 0


def list_scans(db_path: str | Path = _DB_PATH) -> list[dict]:
    """
    Retourne la liste de tous les scans (métadonnées uniquement).

    Returns:
        Liste de dicts { id (alias), scan_id, network, timestamp, total_hosts }.
    """
    path = Path(db_path)
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT scan_id, network, timestamp, total_hosts, duration_seconds "
            "FROM scans ORDER BY timestamp DESC"
        ).fetchall()

    results = []
    for r in rows:
        d = dict(r)
        d["id"] = d["scan_id"]  # Le test attend 'id'
        results.append(d)
    return results


# ─────────────────────────────────────────────
# Users (persisted in SQLite — survive restarts)
# ─────────────────────────────────────────────


def _row_to_user(row: sqlite3.Row) -> dict:
    return {
        "user_id": row["user_id"],
        "email": row["email"],
        "password_hash": row["password_hash"],
        "role": row["role"],
        "created_at": row["created_at"],
    }


def create_user(
    user_id: str,
    email: str,
    password_hash: str,
    role: str = "analyst",
    db_path: str | Path = _DB_PATH,
) -> dict:
    """Insert a new user. Raises sqlite3.IntegrityError if the email exists."""
    with _connect(Path(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO users (user_id, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, email, password_hash, role, _now_iso()),
        )
    return {"user_id": user_id, "email": email, "role": role}


def get_user_by_email(email: str, db_path: str | Path = _DB_PATH) -> dict | None:
    """Return the full user record (including password_hash) or None."""
    with _connect(Path(db_path)) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
    return _row_to_user(row) if row else None


def get_user_by_id(user_id: str, db_path: str | Path = _DB_PATH) -> dict | None:
    """Return the full user record by user_id or None."""
    with _connect(Path(db_path)) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
    return _row_to_user(row) if row else None


def list_users(db_path: str | Path = _DB_PATH) -> list[dict]:
    """Return all users (without password hashes) ordered by creation time."""
    with _connect(Path(db_path)) as conn:
        rows = conn.execute(
            "SELECT user_id, email, role, created_at FROM users ORDER BY created_at"
        ).fetchall()
    return [
        {
            "user_id": r["user_id"],
            "email": r["email"],
            "role": r["role"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def delete_user(user_id: str, db_path: str | Path = _DB_PATH) -> bool:
    """Delete a user by user_id. Returns True if a row was removed."""
    with _connect(Path(db_path)) as conn:
        cur = conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    return cur.rowcount > 0


# ─────────────────────────────────────────────
# Notes (freeform operator annotations)
# ─────────────────────────────────────────────


def _row_to_note(row: sqlite3.Row) -> dict:
    tags: list[str] = []
    if row["tags"]:
        try:
            parsed = json.loads(row["tags"])
            if isinstance(parsed, list):
                tags = [str(t) for t in parsed]
        except (json.JSONDecodeError, TypeError):
            pass
    return {
        "note_id": row["note_id"],
        "title": row["title"],
        "content": row["content"],
        "author": row["author"],
        "scan_id": row["scan_id"],
        "device_ip": row["device_ip"],
        "tags": tags,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def create_note(
    note_id: str,
    title: str = "Untitled",
    content: str = "",
    author: str = "admin",
    scan_id: str | None = None,
    device_ip: str | None = None,
    tags: list[str] | None = None,
    db_path: str | Path = _DB_PATH,
) -> dict:
    """Insert a new note and return its full record."""
    now = _now_iso()
    with _connect(Path(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO notes
                (note_id, title, content, author, scan_id, device_ip, tags,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                note_id,
                title,
                content,
                author,
                scan_id,
                device_ip,
                json.dumps(list(tags)) if tags else None,
                now,
                now,
            ),
        )
    note = get_note(note_id, db_path)
    assert note is not None  # just inserted
    return note


def list_notes(
    scan_id: str | None = None,
    device_ip: str | None = None,
    author: str | None = None,
    db_path: str | Path = _DB_PATH,
) -> list[dict]:
    """List notes (newest first), optionally filtered by scan/device/author."""
    sql = "SELECT * FROM notes"
    clauses: list[str] = []
    params: list = []
    if scan_id:
        clauses.append("scan_id = ?")
        params.append(scan_id)
    if device_ip:
        clauses.append("device_ip = ?")
        params.append(device_ip)
    if author:
        clauses.append("author = ?")
        params.append(author)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY updated_at DESC"
    with _connect(Path(db_path)) as conn:
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            return []
    return [_row_to_note(r) for r in rows]


def get_note(note_id: str, db_path: str | Path = _DB_PATH) -> dict | None:
    """Return a single note by note_id or None."""
    with _connect(Path(db_path)) as conn:
        row = conn.execute(
            "SELECT * FROM notes WHERE note_id = ?", (note_id,)
        ).fetchone()
    return _row_to_note(row) if row else None


def update_note(
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
    scan_id: str | None = None,
    device_ip: str | None = None,
    db_path: str | Path = _DB_PATH,
) -> dict | None:
    """Partial-update a note. Only non-None fields are written. Bumps updated_at."""
    sets: list[str] = []
    params: list = []
    if title is not None:
        sets.append("title = ?")
        params.append(title)
    if content is not None:
        sets.append("content = ?")
        params.append(content)
    if tags is not None:
        sets.append("tags = ?")
        params.append(json.dumps(list(tags)))
    if scan_id is not None:
        sets.append("scan_id = ?")
        params.append(scan_id)
    if device_ip is not None:
        sets.append("device_ip = ?")
        params.append(device_ip)

    if not sets:
        return get_note(note_id, db_path)

    sets.append("updated_at = ?")
    params.append(_now_iso())
    params.append(note_id)

    with _connect(Path(db_path)) as conn:
        cur = conn.execute(
            f"UPDATE notes SET {', '.join(sets)} WHERE note_id = ?", params
        )
        if cur.rowcount == 0:
            return None
    return get_note(note_id, db_path)


def delete_note(note_id: str, db_path: str | Path = _DB_PATH) -> bool:
    """Delete a note by note_id. Returns True if a row was removed."""
    with _connect(Path(db_path)) as conn:
        cur = conn.execute("DELETE FROM notes WHERE note_id = ?", (note_id,))
    return cur.rowcount > 0


# ─────────────────────────────────────────────
# Diff entre scans
# ─────────────────────────────────────────────


def get_diff(
    scan_id_new: str, scan_id_old: str, db_path: str | Path = _DB_PATH
) -> dict:
    """
    Compare deux scans et retourne les différences.

    Args:
        scan_id_new: Scan le plus récent.
        scan_id_old: Scan de référence.

    Returns:
        Dict {
            new_devices:  [ Device ],   # apparus
            lost_devices: [ Device ],   # disparus
            changed_ports:[ dict ]      # ports changés
        }
    """
    path = Path(db_path)
    new_scan = load_scan(scan_id_new, path)
    old_scan = load_scan(scan_id_old, path)

    if not new_scan or not old_scan:
        return {"new_devices": [], "lost_devices": [], "changed_ports": []}

    new_devices = new_scan.get_new_devices(old_scan)
    lost_devices = new_scan.get_lost_devices(old_scan)

    # Ports changés sur les devices communs
    old_by_mac = {d.mac: d for d in old_scan.devices}
    changed_ports = []

    for device in new_scan.devices:
        old_device = old_by_mac.get(device.mac)
        if not old_device:
            continue

        old_open = {p.number for p in old_device.get_open_ports()}
        new_open = {p.number for p in device.get_open_ports()}

        opened = new_open - old_open
        closed = old_open - new_open

        if opened or closed:
            changed_ports.append(
                {
                    "ip": device.ip,
                    "mac": device.mac,
                    "opened": sorted(opened),
                    "closed": sorted(closed),
                }
            )

    return {
        "new_devices": new_devices,
        "lost_devices": lost_devices,
        "changed_ports": changed_ports,
    }


# ─────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────


def export_json(
    scan_id: str,
    output_path: str | Path | None = None,
    db_path: str | Path = _DB_PATH,
) -> str | None:
    """
    Exporte un scan en JSON.

    Args:
        scan_id:     Scan à exporter (doit être un UUID valide).
        output_path: Chemin de sortie (défaut: data/export_<scan_id[:8]>.json).

    Returns:
        Le CONTENU JSON du fichier écrit (string), ou None si le scan est
        introuvable. (Le fichier est aussi écrit sur disque à ``output_path``.)
    """
    _validate_scan_id(scan_id)
    db_p = Path(db_path)

    scan = load_scan(scan_id, db_p)
    if not scan:
        return None

    if output_path is None:
        out_p = db_p.parent / f"export_{scan_id[:8]}.json"
    else:
        out_p = Path(output_path)

    out_p.parent.mkdir(parents=True, exist_ok=True)
    with open(out_p, "w", encoding="utf-8") as f:
        json.dump(scan.to_json(), f, indent=2, ensure_ascii=False)

    print(f"[+] Export JSON : {out_p}")
    return out_p.read_text(encoding="utf-8")


def export_csv(
    scan_id: str,
    output_path: str | Path | None = None,
    db_path: str | Path = _DB_PATH,
) -> str:
    """
    Exporte un scan en CSV (une ligne par device).

    Args:
        scan_id:     Scan à exporter (doit être un UUID valide).
        output_path: Chemin de sortie (défaut: data/export_<scan_id[:8]>.csv).

    Returns:
        Le CONTENU CSV du fichier écrit (string). (Le fichier est aussi écrit
        sur disque à ``output_path``.) Lève ValueError si le scan est introuvable.
    """
    _validate_scan_id(scan_id)
    db_p = Path(db_path)

    scan = load_scan(scan_id, db_p)
    if not scan:
        raise ValueError(f"Scan introuvable : {scan_id}")

    if output_path is None:
        out_p = db_p.parent / f"export_{scan_id[:8]}.csv"
    else:
        out_p = Path(output_path)

    out_p.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "ip",
        "mac",
        "hostname",
        "mac_vendor",
        "os_family",
        "os_version",
        "device_type",
        "confidence",
        "open_ports",
        "is_online",
        "first_seen",
        "last_seen",
    ]

    with open(out_p, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for device in scan.devices:
            fp = device.fingerprint
            writer.writerow(
                {
                    "ip": device.ip,
                    "mac": device.mac,
                    "hostname": _csv_safe(device.hostname),
                    "mac_vendor": _csv_safe(device.mac_vendor),
                    "os_family": fp.os_family.value if fp else "",
                    "os_version": _csv_safe(fp.os_version) if fp else "",
                    "device_type": fp.device_type.value if fp else "",
                    "confidence": f"{fp.confidence:.0%}" if fp else "",
                    "open_ports": ";".join(
                        str(p.number) for p in device.get_open_ports()
                    ),
                    "is_online": "yes" if device.is_online else "no",
                    "first_seen": device.first_seen.isoformat(),
                    "last_seen": device.last_seen.isoformat(),
                }
            )

    print(f"[+] Export CSV : {out_p}")
    return out_p.read_text(encoding="utf-8")
