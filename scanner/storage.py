# scanner/storage.py
# Persistance des résultats de scan — SQLite + export CSV/JSON
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import csv
import json
import os
import sqlite3
import stat
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from .models import (
    Device,
    FingerprintResult,
    OSFamily,
    DeviceType,
    Port,
    PortState,
    PortProtocol,
    ScanResult,
)

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

_DB_PATH = Path(
    os.environ.get("SCANNER_DB_PATH")
    or (Path(__file__).parent / "data" / "scans.db")
)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────


def _validate_scan_id(scan_id: str) -> None:
    """Ensure scan_id is a valid UUID to prevent path traversal in export paths."""
    try:
        uuid.UUID(scan_id)
    except (ValueError, AttributeError):
        raise ValueError(f"scan_id invalide (doit être un UUID) : '{scan_id}'")


# ─────────────────────────────────────────────
# Connexion
# ─────────────────────────────────────────────


@contextmanager
def _connect(db_path: Path = _DB_PATH):
    """Context manager — ouvre et ferme la connexion SQLite proprement."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10.0)
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


def init_db(db_path: Path = _DB_PATH) -> None:
    """
    Crée les tables si elles n'existent pas.
    Appelé une fois au démarrage.
    """
    with _connect(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT    NOT NULL UNIQUE,
                network     TEXT    NOT NULL,
                timestamp   TEXT    NOT NULL,
                total_hosts INTEGER NOT NULL DEFAULT 0
            );

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
        """)

    # Restrict DB file access to owner only (mode 0600)
    try:
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    print(f"[+] Base de données initialisée : {db_path}")


# ─────────────────────────────────────────────
# Sauvegarde
# ─────────────────────────────────────────────


def save_scan(scan: ScanResult, db_path: Path = _DB_PATH) -> str:
    """
    Sauvegarde un ScanResult complet en base.

    Args:
        scan:    ScanResult à persister.
        db_path: Chemin de la base SQLite.

    Returns:
        scan_id du scan sauvegardé.
    """
    with _connect(db_path) as conn:

        # ── Table scans ───────────────────────────────────────
        conn.execute(
            """
            INSERT OR REPLACE INTO scans (scan_id, network, timestamp, total_hosts)
            VALUES (?, ?, ?, ?)
        """,
            (
                scan.scan_id,
                scan.network,
                scan.timestamp.isoformat(),
                scan.total_hosts,
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
                    confidence, fp_sources, tcp_ttl, tcp_window
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        except Exception:
            continue

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
    )


def load_scan(scan_id: str, db_path: Path = _DB_PATH) -> ScanResult | None:
    """
    Charge un ScanResult depuis la base par son scan_id.

    Returns:
        ScanResult ou None si non trouvé.
    """
    with _connect(db_path) as conn:
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

    return ScanResult(
        scan_id=scan_row["scan_id"],
        network=scan_row["network"],
        timestamp=datetime.fromisoformat(scan_row["timestamp"]),
        devices=devices,
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


def list_scans(db_path: Path = _DB_PATH) -> list[dict]:
    """
    Retourne la liste de tous les scans (métadonnées uniquement).

    Returns:
        Liste de dicts { scan_id, network, timestamp, total_hosts }.
    """
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT scan_id, network, timestamp, total_hosts FROM scans ORDER BY timestamp DESC"
        ).fetchall()

    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
# Diff entre scans
# ─────────────────────────────────────────────


def get_diff(scan_id_new: str, scan_id_old: str, db_path: Path = _DB_PATH) -> dict:
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
    new_scan = load_scan(scan_id_new, db_path)
    old_scan = load_scan(scan_id_old, db_path)

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
    scan_id: str, output_path: Path | None = None, db_path: Path = _DB_PATH
) -> Path:
    """
    Exporte un scan en JSON.

    Args:
        scan_id:     Scan à exporter (doit être un UUID valide).
        output_path: Chemin de sortie (défaut: data/export_<scan_id[:8]>.json).

    Returns:
        Chemin du fichier créé.
    """
    _validate_scan_id(scan_id)

    scan = load_scan(scan_id, db_path)
    if not scan:
        raise ValueError(f"Scan introuvable : {scan_id}")

    if output_path is None:
        output_path = _DB_PATH.parent / f"export_{scan_id[:8]}.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scan.to_json(), f, indent=2, ensure_ascii=False)

    print(f"[+] Export JSON : {output_path}")
    return output_path


def export_csv(
    scan_id: str, output_path: Path | None = None, db_path: Path = _DB_PATH
) -> Path:
    """
    Exporte un scan en CSV (une ligne par device).

    Args:
        scan_id:     Scan à exporter (doit être un UUID valide).
        output_path: Chemin de sortie (défaut: data/export_<scan_id[:8]>.csv).

    Returns:
        Chemin du fichier créé.
    """
    _validate_scan_id(scan_id)

    scan = load_scan(scan_id, db_path)
    if not scan:
        raise ValueError(f"Scan introuvable : {scan_id}")

    if output_path is None:
        output_path = _DB_PATH.parent / f"export_{scan_id[:8]}.csv"

    output_path.parent.mkdir(parents=True, exist_ok=True)

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

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for device in scan.devices:
            fp = device.fingerprint
            writer.writerow(
                {
                    "ip": device.ip,
                    "mac": device.mac,
                    "hostname": device.hostname,
                    "mac_vendor": device.mac_vendor,
                    "os_family": fp.os_family.value if fp else "",
                    "os_version": fp.os_version if fp else "",
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

    print(f"[+] Export CSV : {output_path}")
    return output_path
