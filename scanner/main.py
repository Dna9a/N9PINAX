# scanner/main.py
# SIEM-oriented orchestrator: drives the full scan pipeline, generates alerts,
# persists structured + human-readable reports, and exposes a colourised CLI.

from __future__ import annotations

import argparse
import ipaddress
import logging
import logging.handlers
import os
import sys
import time
from typing import Callable, Iterable

try:
    from colorama import Fore, Back, Style, init as _color_init

    _color_init(autoreset=True)
    HAS_COLOR = True
except ImportError:  # pragma: no cover — runtime-only optional dep
    HAS_COLOR = False

    class Fore:  # type: ignore[no-redef]
        RED = YELLOW = GREEN = BLUE = CYAN = WHITE = MAGENTA = RESET = ""

    class Back:  # type: ignore[no-redef]
        RED = YELLOW = GREEN = BLUE = RESET = ""

    class Style:  # type: ignore[no-redef]
        BRIGHT = DIM = RESET_ALL = ""


from . import alerts as alerts_engine
from . import report as report_module
from .config import get_config
from .core.arp_scan import arp_scan, get_local_network
from .core.icmp_scan import enrich_devices as icmp_enrich
from .core.port_scan import scan_all_ports, COMMON_PORTS
from .core.udp_scan import udp_scan_into_device
from .fingerprint.dhcp_fingerprint import enrich_devices as dhcp_enrich
from .fingerprint.hostname import enrich_devices as hostname_enrich
from .fingerprint.http_banner import enrich_devices as http_enrich
from .fingerprint.mac_lookup import (
    download_oui_database,
    enrich_devices as mac_lookup_enrich,
)
from .fingerprint.os_classifier import enrich_devices as classifier_enrich
from .fingerprint.tcp_fingerprint import enrich_devices as tcp_enrich
from .models import Alert, AlertSeverity, ScanResult, merge_devices_by_mac
from .storage import (
    export_csv,
    export_json,
    get_diff,
    init_db,
    list_scans,
    load_last_scan,
    save_scan,
)

# ──────────────────────────────────────────────────────────────────────────────
# Logging — structured, rotating, file + stderr
# ──────────────────────────────────────────────────────────────────────────────


_log = logging.getLogger("scanner")


def _setup_logging(log_file: str | None = None, verbose: bool = False) -> None:
    """
    Configure structured logging.

    Rotates ``scanner.log`` at 5 MB / 5 backups so long-running deployments
    don't fill the disk.
    """
    cfg = get_config()
    target = log_file or str(cfg.log_path)

    root = logging.getLogger()
    # Prevent duplicate handlers on repeated invocations (tests, REPL).
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    file_handler = logging.handlers.RotatingFileHandler(
        target, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    if verbose:
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setFormatter(fmt)
        root.addHandler(stderr_handler)

    root.setLevel(logging.DEBUG if verbose else logging.INFO)


# ──────────────────────────────────────────────────────────────────────────────
# Tiny output helpers
# ──────────────────────────────────────────────────────────────────────────────


def _success(s: str) -> str:
    return f"{Fore.GREEN}{s}{Style.RESET_ALL}" if HAS_COLOR else s


def _warn(s: str) -> str:
    return f"{Fore.YELLOW}{s}{Style.RESET_ALL}" if HAS_COLOR else s


def _err(s: str) -> str:
    return f"{Fore.RED}{s}{Style.RESET_ALL}" if HAS_COLOR else s


def _info(s: str) -> str:
    return f"{Fore.CYAN}{s}{Style.RESET_ALL}" if HAS_COLOR else s


def _bold(s: str) -> str:
    return f"{Style.BRIGHT}{s}{Style.RESET_ALL}" if HAS_COLOR else s


def _header(text: str) -> str:
    if HAS_COLOR:
        return f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} {text} {Style.RESET_ALL}"
    bar = "=" * len(text)
    return f"\n{bar}\n{text}\n{bar}"


def _severity_color(severity: AlertSeverity) -> str:
    if not HAS_COLOR:
        return ""
    return {
        AlertSeverity.LOW: Fore.CYAN,
        AlertSeverity.MEDIUM: Fore.YELLOW,
        AlertSeverity.HIGH: Fore.RED,
        AlertSeverity.CRITICAL: f"{Back.RED}{Fore.WHITE}{Style.BRIGHT}",
    }.get(severity, "")


# ──────────────────────────────────────────────────────────────────────────────
# Pipeline orchestration
# ──────────────────────────────────────────────────────────────────────────────


def _safe_step(
    label: str,
    func: Callable[[], None],
    fatal: bool = False,
    progress: Callable[[str, str], None] | None = None,
) -> None:
    """
    Run a pipeline step inside an isolated try/except so one failure does not
    poison the whole scan. Set ``fatal=True`` for steps the rest of the
    pipeline depends on.
    """
    print(_info(f"\n[*] {label} ..."))
    if progress:
        progress(label, "running")
    try:
        func()
        print(_success(f"    ✓ {label} terminé"))
        if progress:
            progress(label, "ok")
    except PermissionError as e:
        msg = f"permission refusée: {e}"
        print(_err(f"    ✗ {label} — {msg}"))
        _log.error("%s failed: %s", label, e)
        if progress:
            progress(label, "permission")
        if fatal:
            raise
    except Exception as e:
        msg = f"erreur non bloquante: {e}"
        print(_warn(f"    ⚠ {label} — {msg}"))
        _log.warning("%s failed: %s", label, e, exc_info=True)
        if progress:
            progress(label, "warning")
        if fatal:
            raise


def run_scan(
    network: str | None = None,
    port_timeout: float | None = None,
    resolve_hostnames: bool = True,
    save_to_db: bool = True,
    write_report: bool = True,
    max_workers: int | None = None,
    enable_dhcp: bool = False,
    enable_udp: bool = False,
    skip_classifier: bool = False,
    progress: Callable[[str, str], None] | None = None,
    on_device: Callable[["Device", bool], None] | None = None,
) -> ScanResult:
    """
    Orchestrate the full scan pipeline.

    Each phase is isolated — a failure in one phase logs a warning but does
    not abort the rest of the pipeline (the only exception being ARP, which
    is required to know what to scan).
    """
    cfg = get_config()
    if port_timeout is None:
        port_timeout = cfg.port_timeout
    if max_workers is None:
        max_workers = cfg.max_workers_ports

    def _emit_devices(device_list: list, is_update: bool) -> None:
        """Fire the on_device callback for each device, swallowing errors."""
        if not on_device:
            return
        for dev in device_list:
            try:
                on_device(dev, is_update)
            except Exception:  # never let a live-update callback abort a scan
                _log.debug("on_device callback failed", exc_info=True)

    started = time.perf_counter()
    print(_header("SIEM Network Scanner — Pipeline"))
    _log.info(
        "Scan started network=%s workers=%d dhcp=%s udp=%s",
        network,
        max_workers,
        enable_dhcp,
        enable_udp,
    )

    # ── 1. Network detection ──────────────────────────────────────────────
    if network is None:
        try:
            network = get_local_network()
            print(_success(f"    ✓ Réseau détecté : {network}"))
        except RuntimeError as e:
            print(_err(f"    ✗ {e}"))
            _log.error("Network detection failed: %s", e)
            return ScanResult(network="0.0.0.0/32")
    else:
        print(_success(f"    ✓ Réseau spécifié : {network}"))

    # ── 2. ARP scan (fatal) ───────────────────────────────────────────────
    devices: list = []

    def _arp() -> None:
        nonlocal devices
        # Wire the configured ARP timeout through — it was previously a dead
        # knob (SCANNER_ARP_TIMEOUT had no effect from the pipeline, audit F-035).
        devices = arp_scan(
            network=network, timeout=cfg.arp_timeout, resolve_hostnames=False
        )

    try:
        _safe_step("Étape 1 : ARP scan", _arp, fatal=True, progress=progress)
    except Exception:
        return ScanResult(network=network)
    if not devices:
        print(_warn("    ⚠ Aucun hôte découvert."))
        return ScanResult(network=network)
    print(_success(f"    ✓ {len(devices)} hôte(s) découvert(s)"))

    # Live feed: announce each host the instant ARP finds it.
    _emit_devices(devices, is_update=False)

    # ── 3. ICMP enrichment (TTL, latency) ────────────────────────────────
    _safe_step(
        "Étape 2 : ICMP / latency",
        lambda: icmp_enrich(devices),
        progress=progress,
    )

    # ── 4. MAC vendor lookup ─────────────────────────────────────────────
    _safe_step(
        "Étape 3 : MAC OUI lookup",
        lambda: mac_lookup_enrich(devices),
        progress=progress,
    )

    # ── 5. Reverse DNS hostname resolution ───────────────────────────────
    if resolve_hostnames:
        _safe_step(
            "Étape 4 : Reverse DNS",
            lambda: hostname_enrich(devices, timeout=cfg.dns_timeout),
            progress=progress,
        )

    # ── 6. TCP port scan ─────────────────────────────────────────────────
    _safe_step(
        "Étape 5 : TCP port scan",
        lambda: scan_all_ports(
            devices=devices,
            ports=list(COMMON_PORTS.keys()),
            timeout=port_timeout,
            max_workers=max_workers,
            only_open=True,
        ),
        progress=progress,
    )

    # ── 7. Optional UDP scan ─────────────────────────────────────────────
    if enable_udp:

        def _udp() -> None:
            for d in devices:
                udp_scan_into_device(d, only_open=True)

        _safe_step("Étape 6 : UDP scan", _udp, progress=progress)

    # ── 8. TCP fingerprinting ────────────────────────────────────────────
    _safe_step(
        "Étape 7 : TCP fingerprint", lambda: tcp_enrich(devices), progress=progress
    )

    # ── 9. Optional DHCP fingerprinting ─────────────────────────────────
    if enable_dhcp:
        _safe_step(
            "Étape 8 : DHCP fingerprint (5s passive)",
            lambda: dhcp_enrich(devices, timeout=5),
            progress=progress,
        )

    # ── 10. HTTP banner grabbing ────────────────────────────────────────
    _safe_step(
        "Étape 9 : HTTP banners",
        lambda: http_enrich(devices, max_workers=max(5, max_workers // 4)),
        progress=progress,
    )

    # ── 11. OS classification ───────────────────────────────────────────
    if not skip_classifier:
        _safe_step(
            "Étape 10 : OS classification",
            lambda: classifier_enrich(devices),
            progress=progress,
        )

    # ── 12. Build the result ────────────────────────────────────────────
    before_dedup = len(devices)
    devices = merge_devices_by_mac(devices)
    after_dedup = len(devices)
    if after_dedup < before_dedup:
        collapsed = before_dedup - after_dedup
        msg = f"    ✓ Déduplication MAC: {collapsed} doublon(s) fusionné(s)"
        print(_success(msg))
        _log.info("Merged %d duplicate device rows by MAC", collapsed)

    # Live feed: push the fully-enriched (deduped, fingerprinted) devices.
    _emit_devices(devices, is_update=True)

    duration = round(time.perf_counter() - started, 3)
    result = ScanResult(network=network, devices=devices, duration_seconds=duration)

    # ── 13. Alerting ────────────────────────────────────────────────────
    if cfg.enable_alerts:
        try:
            alerts = alerts_engine.evaluate(result)
            # The historical diff is best-effort. On the very first scan the DB
            # tables don't exist yet, and load_last_scan() raised — which used
            # to be caught by the OUTER except and silently discard EVERY alert
            # for that scan (audit QA-002). Isolate it so current-scan alerts
            # always survive.
            prev = None
            try:
                prev = load_last_scan(cfg.db_path)
            except Exception as diff_err:
                _log.debug("No previous scan for diff alerts: %s", diff_err)
            if prev is not None:
                alerts.extend(
                    alerts_engine.evaluate_diff(
                        result, {d.mac: d for d in prev.devices}
                    )
                )
            result.alerts = alerts
            _log.info("Generated %d alerts", len(alerts))
        except Exception as e:
            _log.warning("Alert engine failed: %s", e, exc_info=True)

    # ── 14. Persistence ────────────────────────────────────────────────
    if save_to_db:
        try:
            init_db(cfg.db_path)
            save_scan(result, cfg.db_path)
            _log.info("Saved scan %s to DB", result.scan_id)
        except Exception as e:
            print(_warn(f"    ⚠ DB save failed: {e}"))
            _log.warning("DB save error: %s", e, exc_info=True)

    if write_report:
        try:
            report_path = report_module.append_scan(result)
            print(_success(f"    ✓ Rapport ajouté : {report_path}"))
        except Exception as e:
            print(_warn(f"    ⚠ Report write failed: {e}"))
            _log.warning("Report write failed: %s", e, exc_info=True)

    # ── 15. Summary ────────────────────────────────────────────────────
    print_scan_summary(result)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Pretty-print summary
# ──────────────────────────────────────────────────────────────────────────────


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _ip_sort_key(ip: str) -> tuple[int, int]:
    """Sort key that orders IPv4 numerically and never crashes on IPv6.

    The old key parsed ``ip.split(".")`` as ints, which raised on any IPv6
    address the model now accepts (F-008). Using :mod:`ipaddress` sorts both
    families correctly (v4 before v6) and degrades gracefully on junk.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (9, 0)


def print_scan_summary(result: ScanResult) -> None:
    print(_header("RÉSUMÉ DU SCAN"))
    print(f"  Réseau      : {_bold(result.network)}")
    print(f"  Scan ID     : {result.scan_id}")
    print(f"  Timestamp   : {result.timestamp.isoformat(timespec='seconds')}")
    print(f"  Durée       : {_bold(f'{result.duration_seconds:.2f}s')}")
    print(f"  Hôtes       : {_bold(str(result.total_hosts))}")

    if not result.devices:
        print(_warn("  Aucun hôte découvert."))
        return

    headers = ["IP", "MAC", "Vendor", "Hostname", "OS", "Ports", "Lat(ms)"]
    widths = [15, 18, 18, 18, 24, 18, 7]
    line = "  " + " | ".join(
        _bold(h).ljust(w + 9 if HAS_COLOR else w) for h, w in zip(headers, widths)
    )
    print(line)
    print("  " + "─" * (sum(widths) + len(widths) * 3))

    for d in sorted(result.devices, key=lambda x: _ip_sort_key(x.ip)):
        fp = d.fingerprint
        os_str = fp.os_family.value if fp else "Unknown"
        conf = fp.confidence if fp else 0.0
        os_display = f"{os_str} ({conf:.0%})"
        if conf >= 0.8:
            os_display = _success(os_display)
        elif conf >= 0.5:
            os_display = _warn(os_display)
        else:
            os_display = _err(os_display)

        ports = [f"{p.number}/{p.protocol.value[0]}" for p in d.get_open_ports()[:4]]
        ports_str = ", ".join(ports)
        if d.open_ports_count > 4:
            ports_str += f", +{d.open_ports_count - 4}"
        if not ports:
            ports_str = "(none)"

        latency = f"{d.latency_ms:.1f}" if d.latency_ms is not None else "-"

        print(
            f"  {d.ip:<15} | "
            f"{d.mac:<18} | "
            f"{_truncate(d.mac_vendor, 18):<18} | "
            f"{_truncate(d.hostname or 'unknown', 18):<18} | "
            f"{os_display:<24} | "
            f"{_truncate(ports_str, 18):<18} | "
            f"{latency:<7}"
        )

    _print_stats(result)
    _print_alerts(result.alerts)


def _print_stats(result: ScanResult) -> None:
    open_ports_total = sum(d.open_ports_count for d in result.devices)
    devices_with_os = sum(
        1
        for d in result.devices
        if d.fingerprint and d.fingerprint.os_family.value != "Unknown"
    )

    print()
    print(f"  {_bold('Statistiques')} :")
    print(
        f"    • Hôtes avec OS identifié  : {_success(str(devices_with_os))} / {result.total_hosts}"
    )
    print(f"    • Ports ouverts au total   : {_warn(str(open_ports_total))}")

    services: dict[str, int] = {}
    os_families: dict[str, int] = {}
    for d in result.devices:
        if d.fingerprint:
            os_families[d.fingerprint.os_family.value] = (
                os_families.get(d.fingerprint.os_family.value, 0) + 1
            )
        for p in d.get_open_ports():
            services[p.service] = services.get(p.service, 0) + 1

    if services:
        top = sorted(services.items(), key=lambda x: -x[1])[:5]
        print(
            f"    • Services principaux      : "
            f"{', '.join(f'{svc} ({n})' for svc, n in top)}"
        )
    if os_families:
        top = sorted(os_families.items(), key=lambda x: -x[1])[:5]
        print(
            f"    • OS détectés              : "
            f"{', '.join(f'{os} ({n})' for os, n in top)}"
        )


def _print_alerts(alerts: Iterable[Alert]) -> None:
    alerts = list(alerts)
    if not alerts:
        return
    print()
    print(f"  {_bold('Alertes')} ({len(alerts)}) :")
    for a in sorted(alerts, key=lambda x: -alerts_engine.severity_rank(x.severity))[
        :12
    ]:
        tag = (
            _severity_color(a.severity)
            + a.severity.value.upper().ljust(8)
            + (Style.RESET_ALL if HAS_COLOR else "")
        )
        target = f" [{a.ip}]" if a.ip else ""
        print(f"    {tag} {a.title}{target}")
    if len(alerts) > 12:
        print(f"    … (+{len(alerts) - 12} more)")


# ──────────────────────────────────────────────────────────────────────────────
# Sub-commands
# ──────────────────────────────────────────────────────────────────────────────


def list_all_scans() -> None:
    print(_header("SCANS PRÉCÉDENTS"))
    cfg = get_config()
    try:
        init_db(cfg.db_path)
        scans = list_scans(cfg.db_path)
    except Exception as e:
        print(_err(f"  Erreur : {e}"))
        return
    if not scans:
        print(_warn("  Aucun scan enregistré."))
        return
    for s in scans:
        print(
            f"  {_info(s['scan_id'])} | "
            f"{s['network']:<16} | "
            f"{s['timestamp']:<20} | "
            f"{s['total_hosts']:>3} hôte(s)"
        )


def run_diff(scan_id_new: str, scan_id_old: str) -> None:
    print(_header("DIFF ENTRE SCANS"))
    cfg = get_config()
    try:
        init_db(cfg.db_path)
        diff = get_diff(scan_id_new, scan_id_old, cfg.db_path)
    except Exception as e:
        print(_err(f"  Erreur : {e}"))
        return

    new_devices = diff.get("new_devices", [])
    lost_devices = diff.get("lost_devices", [])
    changed_ports = diff.get("changed_ports", [])

    print(f"  Nouveau : {_info(scan_id_new)}")
    print(f"  Ancien  : {_info(scan_id_old)}")
    print()

    if new_devices:
        print(_success(f"  [+] {len(new_devices)} hôte(s) apparu(s) :"))
        for d in new_devices:
            print(f"      {d.ip:<16} | {d.mac} | {d.mac_vendor}")
    else:
        print("  Aucun nouvel hôte.")
    print()
    if lost_devices:
        print(_err(f"  [-] {len(lost_devices)} hôte(s) disparu(s) :"))
        for d in lost_devices:
            print(f"      {d.ip:<16} | {d.mac} | {d.mac_vendor}")
    else:
        print("  Aucun hôte disparu.")
    print()
    if changed_ports:
        print(_warn(f"  [~] {len(changed_ports)} hôte(s) avec ports modifiés :"))
        for entry in changed_ports:
            print(f"      {entry['ip']}")
            if entry["opened"]:
                print(f"        + ouvert : {entry['opened']}")
            if entry["closed"]:
                print(f"        - fermé  : {entry['closed']}")
    else:
        print("  Aucun changement de ports.")


def run_export(scan_id: str, fmt: str = "json") -> None:
    print(_header("EXPORT DU SCAN"))
    cfg = get_config()
    try:
        init_db(cfg.db_path)
        result = (
            export_csv(scan_id, db_path=cfg.db_path)
            if fmt == "csv"
            else export_json(scan_id, db_path=cfg.db_path)
        )
        if result is None:
            print(_err(f"  ✗ Scan introuvable : {scan_id}"))
            return
        print(_success(f"  ✓ Exporté ({len(result)} octets)"))
    except ValueError as e:
        print(_err(f"  ✗ {e}"))
    except Exception as e:
        print(_err(f"  ✗ Erreur : {e}"))
        _log.error("Export error: %s", e, exc_info=True)


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SIEM Network Scanner — discovery, fingerprinting, alerting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python -m scanner                              # auto-detect network
  sudo python -m scanner --network 192.168.1.0/24    # specific subnet
  sudo python -m scanner --udp                       # add UDP scan
  sudo python -m scanner --no-resolve                # skip reverse DNS
  python -m scanner --list                           # historical scans
  python -m scanner --diff NEW_ID OLD_ID             # compare scans
  python -m scanner --export SCAN_ID --format csv    # export
        """,
    )
    parser.add_argument("--network", default=None)
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Port scan timeout in seconds (0.01–30).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="Concurrent port-scan threads (1–500).",
    )
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="Skip reverse DNS hostname resolution.",
    )
    parser.add_argument(
        "--dhcp", action="store_true", help="Enable passive DHCP fingerprinting (5s)."
    )
    parser.add_argument(
        "--udp", action="store_true", help="Run UDP scan on common UDP services."
    )
    parser.add_argument(
        "--no-db", action="store_true", help="Do not persist the scan to SQLite."
    )
    parser.add_argument(
        "--no-report", action="store_true", help="Do not append to scan_report.txt."
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--list", action="store_true", help="List previous scans and exit."
    )
    parser.add_argument(
        "--diff", nargs=2, metavar=("NEW", "OLD"), help="Compare two scans by ID."
    )
    parser.add_argument(
        "--export", metavar="SCAN_ID", help="Export a saved scan to JSON/CSV."
    )
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--log-file", default=None)
    parser.add_argument(
        "--update-oui",
        action="store_true",
        help="Refresh the OUI vendor database from IEEE and exit.",
    )
    return parser


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.network is not None:
        try:
            net = ipaddress.ip_network(args.network, strict=False)
        except ValueError:
            parser.error(f"Invalid CIDR network: {args.network!r}")
        else:
            max_hosts = get_config().max_scan_hosts
            if max_hosts and max_hosts > 0 and net.num_addresses > max_hosts:
                parser.error(
                    f"--network {args.network} expands to {net.num_addresses} "
                    f"addresses, over the {max_hosts}-host safety cap. Use a "
                    "smaller CIDR or raise SCANNER_MAX_SCAN_HOSTS."
                )

    if args.timeout is not None and not (0.01 <= args.timeout <= 30):
        parser.error("--timeout must be between 0.01 and 30 seconds")

    if args.max_workers is not None and not (1 <= args.max_workers <= 500):
        parser.error("--max-workers must be between 1 and 500")

    # Sanity-check the log file path — never accept paths containing null bytes.
    if args.log_file and "\x00" in args.log_file:
        parser.error("--log-file contains a NUL byte")


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    _validate_args(args, parser)

    _setup_logging(args.log_file, verbose=args.verbose)
    _log.info("Scanner CLI invoked PID=%d uid=%d", os.getpid(), os.geteuid())

    # Privileged actions require root.
    if args.update_oui:
        ok = download_oui_database(force=True)
        print(
            _success("    ✓ OUI database refreshed.")
            if ok
            else _err("    ✗ refresh failed.")
        )
        sys.exit(0 if ok else 1)

    if args.list:
        list_all_scans()
        return
    if args.diff:
        run_diff(args.diff[0], args.diff[1])
        return
    if args.export:
        run_export(args.export, args.format)
        return

    # The actual scan needs raw-socket privileges (root or CAP_NET_RAW).
    from .core.arp_scan import _has_raw_socket_access
    if not _has_raw_socket_access():
        print(_err("✗ Cette commande nécessite les droits root ou CAP_NET_RAW."))
        print(_warn("  → Relancez avec : sudo python -m scanner"))
        sys.exit(1)

    try:
        run_scan(
            network=args.network,
            port_timeout=args.timeout,
            resolve_hostnames=not args.no_resolve,
            save_to_db=not args.no_db,
            write_report=not args.no_report,
            max_workers=args.max_workers,
            enable_dhcp=args.dhcp,
            enable_udp=args.udp,
        )
    except KeyboardInterrupt:
        print(_err("\n\n✗ Scan interrompu par l'utilisateur."))
        sys.exit(130)
    except Exception as e:
        print(_err(f"\n✗ Erreur fatale : {e}"))
        _log.exception("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
