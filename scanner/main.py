# scanner/main.py
# Orchestrateur principal du scan réseau avec output colorisé
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import argparse
import ipaddress
import logging as _logging
import os
import sys
import time

try:
    from colorama import Fore, Back, Style, init

    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class Fore:
        RED = YELLOW = GREEN = BLUE = CYAN = WHITE = ""

    class Back:
        RED = YELLOW = GREEN = ""

    class Style:
        BRIGHT = RESET_ALL = ""


# Core modules
from .core.arp_scan import get_local_network, arp_scan
from .core.port_scan import scan_all_ports, COMMON_PORTS
from .fingerprint.mac_lookup import enrich_devices as mac_lookup_enrich
from .fingerprint.tcp_fingerprint import enrich_devices as tcp_enrich
from .fingerprint.dhcp_fingerprint import enrich_devices as dhcp_enrich
from .fingerprint.http_banner import enrich_devices as http_enrich
from .fingerprint.os_classifier import enrich_devices as classifier_enrich
from .models import Device, ScanResult
from .storage import init_db, save_scan, list_scans, export_json, export_csv, get_diff

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────

_log = _logging.getLogger(__name__)


def _setup_logging(log_file: str = "scanner.log") -> None:
    _logging.basicConfig(
        filename=log_file,
        level=_logging.INFO,
        format="%(asctime)s %(levelname)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ─────────────────────────────────────────────
# Couleurs et formatage
# ─────────────────────────────────────────────


def _bold(text: str) -> str:
    if HAS_COLOR:
        return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"
    return text


def _success(text: str) -> str:
    if HAS_COLOR:
        return f"{Fore.GREEN}{text}{Fore.RESET}"
    return text


def _warning(text: str) -> str:
    if HAS_COLOR:
        return f"{Fore.YELLOW}{text}{Fore.RESET}"
    return text


def _error(text: str) -> str:
    if HAS_COLOR:
        return f"{Fore.RED}{text}{Fore.RESET}"
    return text


def _info(text: str) -> str:
    if HAS_COLOR:
        return f"{Fore.CYAN}{text}{Fore.RESET}"
    return text


def _header(text: str) -> str:
    if HAS_COLOR:
        return f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} {text} {Style.RESET_ALL}\n"
    return f"\n{'='*len(text)}\n{text}\n{'='*len(text)}\n"


# ─────────────────────────────────────────────
# Pipeline de scan
# ─────────────────────────────────────────────


def run_scan(
    network: str | None = None,
    port_timeout: float = 0.5,
    resolve_hostnames: bool = False,
    save_to_db: bool = True,
    max_workers: int = 50,
    enable_dhcp: bool = False,
) -> ScanResult:
    """
    Lance un scan réseau complet avec orchestration.

    Pipeline :
      1. Auto-détection du réseau (ou usage du paramètre)
      2. ARP scan → découverte des hôtes
      3. MAC OUI lookup → vendor identification
      4. Port scan → services sur les hôtes
      5. TCP fingerprinting → analyse stack TCP/IP
      6. DHCP fingerprinting → passif, activé via --dhcp
      7. HTTP banner grabbing → headers web
      8. OS classification → verdict final
      9. Sauvegarde en BD
     10. Rapport résumé
    """
    print(_header("NETWORK SCANNER — Cybersecurity Scan Pipeline"))
    _log.info("Scan started — network=%s max_workers=%d dhcp=%s", network, max_workers, enable_dhcp)

    # ── 1. Détection réseau ───────────────────────────────────
    print(_info("[*] Étape 1 : Détection du réseau local ..."))
    try:
        if network is None:
            network = get_local_network()
            print(_success(f"    ✓ Réseau détecté : {network}"))
        else:
            print(_success(f"    ✓ Réseau spécifié : {network}"))
        _log.info("Network: %s", network)
    except RuntimeError as e:
        print(_error(f"    ✗ Erreur : {e}"))
        _log.error("Network detection failed: %s", e)
        return ScanResult(network="unknown")

    # ── 2. ARP scan ───────────────────────────────────────────
    print(_info(f"\n[*] Étape 2 : Scan ARP sur {network} ..."))
    try:
        devices = arp_scan(network=network, resolve_hostnames=resolve_hostnames)
        if not devices:
            print(_warning("    ⚠ Aucun hôte découvert. Vérifiez le réseau."))
            return ScanResult(network=network)
        print(_success(f"    ✓ {len(devices)} hôte(s) découvert(s)"))
        _log.info("ARP scan: %d hosts found", len(devices))
    except PermissionError as e:
        print(_error(f"    ✗ Permission refusée : {e}"))
        print(_warning("    → Lancez avec sudo ou vérifiez les droits CAP_NET_RAW"))
        _log.error("ARP permission error: %s", e)
        return ScanResult(network=network)
    except Exception as e:
        print(_error(f"    ✗ Erreur ARP : {e}"))
        _log.error("ARP scan error: %s", e)
        return ScanResult(network=network)

    # ── 3. MAC OUI lookup ─────────────────────────────────────
    print(_info("\n[*] Étape 3 : MAC OUI lookup ..."))
    try:
        devices = mac_lookup_enrich(devices)
        print(_success(f"    ✓ {len(devices)} hôte(s) enrichi(s) avec vendor"))
        _log.info("MAC OUI lookup complete")
    except Exception as e:
        print(_warning(f"    ⚠ Erreur MAC lookup (non bloquant) : {e}"))
        _log.warning("MAC OUI lookup error: %s", e)

    # ── 4. Port scan ──────────────────────────────────────────
    print(_info("\n[*] Étape 4 : Scan des ports ..."))
    try:
        devices = scan_all_ports(
            devices=devices,
            ports=list(COMMON_PORTS.keys()),
            timeout=port_timeout,
            max_workers=max_workers,
            only_open=True,
        )
        total_open = sum(d.open_ports_count for d in devices)
        print(_success(f"    ✓ Scan terminé : {total_open} port(s) ouvert(s) au total"))
        _log.info("Port scan complete: %d open ports total", total_open)
    except Exception as e:
        print(_warning(f"    ⚠ Erreur port scan (non bloquant) : {e}"))
        _log.warning("Port scan error: %s", e)

    # ── 5. TCP fingerprinting ─────────────────────────────────
    print(_info("\n[*] Étape 5 : TCP fingerprinting ..."))
    try:
        devices = tcp_enrich(devices)
        print(_success("    ✓ TCP fingerprinting terminé"))
        _log.info("TCP fingerprinting complete")
    except Exception as e:
        print(_warning(f"    ⚠ Erreur TCP fingerprint (non bloquant) : {e}"))
        _log.warning("TCP fingerprint error: %s", e)

    # ── 6. DHCP fingerprinting (passif, optionnel) ────────────
    if enable_dhcp:
        print(_info("\n[*] Étape 6 : DHCP fingerprinting (passif, 5s) ..."))
        try:
            devices = dhcp_enrich(devices, timeout=5)
            print(_success("    ✓ DHCP fingerprinting terminé"))
            _log.info("DHCP fingerprinting complete")
        except Exception as e:
            print(_warning(f"    ⚠ Erreur DHCP (non bloquant) : {e}"))
            _log.warning("DHCP fingerprint error: %s", e)
    else:
        print(_info("\n[*] Étape 6 : DHCP fingerprinting (désactivé — utilisez --dhcp pour activer)"))

    # ── 7. HTTP banner grabbing ───────────────────────────────
    print(_info("\n[*] Étape 7 : HTTP banner grabbing ..."))
    try:
        devices = http_enrich(devices, max_workers=10)
        print(_success("    ✓ HTTP banner grabbing terminé"))
        _log.info("HTTP banner grabbing complete")
    except Exception as e:
        print(_warning(f"    ⚠ Erreur HTTP banner (non bloquant) : {e}"))
        _log.warning("HTTP banner error: %s", e)

    # ── 8. OS classification ──────────────────────────────────
    print(_info("\n[*] Étape 8 : Classification OS finale ..."))
    try:
        devices = classifier_enrich(devices)
        print(_success("    ✓ Classification OS terminée"))
        _log.info("OS classification complete")
    except Exception as e:
        print(_warning(f"    ⚠ Erreur classification (non bloquant) : {e}"))
        _log.warning("OS classification error: %s", e)

    # ── 9. Création du résultat ───────────────────────────────
    result = ScanResult(network=network, devices=devices)

    # ── 10. Sauvegarde en BD ──────────────────────────────────
    if save_to_db:
        print(_info("\n[*] Étape 9 : Sauvegarde en base de données ..."))
        try:
            init_db()
            scan_id = save_scan(result)
            print(_success(f"    ✓ Résultat sauvegardé — Scan ID: {scan_id}"))
            _log.info("Scan saved — ID: %s", scan_id)
        except Exception as e:
            print(_warning(f"    ⚠ Erreur BD (non bloquant) : {e}"))
            _log.warning("DB save error: %s", e)

    # ── 11. Rapport résumé ────────────────────────────────────
    print_scan_summary(result)
    _log.info(
        "Scan finished — %d hosts, %d open ports",
        result.total_hosts,
        sum(d.open_ports_count for d in result.devices),
    )

    return result


# ─────────────────────────────────────────────
# Rapports et affichage
# ─────────────────────────────────────────────


def print_scan_summary(result: ScanResult) -> None:
    """Affiche un résumé colorisé du scan."""
    print(_header("RÉSUMÉ DU SCAN"))

    print(f"  Réseau         : {_bold(result.network)}")
    print(f"  Timestamp      : {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Hôtes découverts: {_bold(str(result.total_hosts))}")
    print()

    if not result.devices:
        print(_warning("  ⚠ Aucun hôte découvert."))
        return

    print(
        f"  {_bold('IP'):16} | {_bold('MAC'):18} | {_bold('Hostname'):20} | {_bold('OS'):15} | {_bold('Ports')}"
    )
    print("  " + "─" * 100)

    for device in sorted(result.devices, key=lambda d: d.ip):
        ip = device.ip
        mac = device.mac
        hostname = (device.hostname if device.hostname != "unknown" else "N/A")[:20]

        if device.fingerprint:
            os_str = device.fingerprint.os_family.value
            conf = device.fingerprint.confidence
            if conf >= 0.8:
                os_str = _success(f"{os_str} ({conf:.0%})")
            elif conf >= 0.5:
                os_str = _warning(f"{os_str} ({conf:.0%})")
            else:
                os_str = f"{os_str} ({conf:.0%})"
        else:
            os_str = _warning("Unknown (0%)")

        open_ports = [p.number for p in device.get_open_ports()]
        ports_str = ", ".join(str(p) for p in open_ports[:5])
        if len(open_ports) > 5:
            ports_str += f", +{len(open_ports) - 5}"
        if not open_ports:
            ports_str = _warning("(none)")

        print(
            f"  {_info(ip):16} | {mac:18} | {hostname:20} | {os_str:15} | {ports_str}"
        )

    print()
    print(f"  {_bold('Statistiques')} :")
    open_ports_total = sum(d.open_ports_count for d in result.devices)
    devices_with_os = sum(
        1
        for d in result.devices
        if d.fingerprint and d.fingerprint.os_family.value != "Unknown"
    )
    print(f"    • Hôtes avec OS identifié  : {_success(str(devices_with_os))} / {result.total_hosts}")
    print(f"    • Ports ouverts au total   : {_warning(str(open_ports_total))}")
    print(
        f"    • Services détectés        : "
        f"{len(set(p.service for d in result.devices for p in d.get_open_ports()))}"
    )

    services: dict[str, int] = {}
    for device in result.devices:
        for port in device.get_open_ports():
            services[port.service] = services.get(port.service, 0) + 1
    if services:
        print(
            f"    • Services courants        : "
            f"{', '.join(f'{svc} ({cnt})' for svc, cnt in sorted(services.items(), key=lambda x: -x[1])[:5])}"
        )

    os_families: dict[str, int] = {}
    for device in result.devices:
        if device.fingerprint:
            os = device.fingerprint.os_family.value
            os_families[os] = os_families.get(os, 0) + 1
    if os_families:
        print(
            f"    • OS détectés              : "
            f"{', '.join(f'{os} ({cnt})' for os, cnt in sorted(os_families.items(), key=lambda x: -x[1])[:5])}"
        )

    print()
    print(_success("✓ Scan terminé avec succès."))


def list_all_scans() -> None:
    """Affiche la liste des scans précédents."""
    print(_header("SCANS PRÉCÉDENTS"))
    try:
        init_db()
        scans = list_scans()
        if not scans:
            print(_warning("  Aucun scan enregistré."))
            return
        for scan in scans:
            print(
                f"  {_info(scan['scan_id'])} | {scan['network']:16} | {scan['timestamp']} | {scan['total_hosts']} hôte(s)"
            )
    except Exception as e:
        print(_error(f"  Erreur : {e}"))


def run_diff(scan_id_new: str, scan_id_old: str) -> None:
    """Affiche les différences entre deux scans."""
    print(_header("DIFF ENTRE SCANS"))
    try:
        init_db()
        diff = get_diff(scan_id_new, scan_id_old)

        new_devices = diff.get("new_devices", [])
        lost_devices = diff.get("lost_devices", [])
        changed_ports = diff.get("changed_ports", [])

        print(f"  Nouveau scan : {_info(scan_id_new)}")
        print(f"  Ancien scan  : {_info(scan_id_old)}")
        print()

        if new_devices:
            print(_success(f"  [+] {len(new_devices)} nouvel(s) hôte(s) apparu(s) :"))
            for d in new_devices:
                print(f"      {_info(d.ip):16} | {d.mac} | {d.hostname}")
        else:
            print("  Aucun nouvel hôte.")

        print()
        if lost_devices:
            print(_error(f"  [-] {len(lost_devices)} hôte(s) disparu(s) :"))
            for d in lost_devices:
                print(f"      {_info(d.ip):16} | {d.mac} | {d.hostname}")
        else:
            print("  Aucun hôte disparu.")

        print()
        if changed_ports:
            print(_warning(f"  [~] {len(changed_ports)} hôte(s) avec ports modifiés :"))
            for entry in changed_ports:
                print(f"      {_info(entry['ip'])}")
                if entry["opened"]:
                    print(f"        + ouvert  : {entry['opened']}")
                if entry["closed"]:
                    print(f"        - fermé   : {entry['closed']}")
        else:
            print("  Aucun changement de ports.")

    except Exception as e:
        print(_error(f"  Erreur lors du diff : {e}"))
        _log.error("Diff error: %s", e)


def run_export(scan_id: str, fmt: str = "json") -> None:
    """Exporte un scan vers un fichier."""
    print(_header("EXPORT DU SCAN"))
    try:
        init_db()
        path = export_csv(scan_id) if fmt == "csv" else export_json(scan_id)
        print(_success(f"  ✓ Fichier exporté : {path}"))
        _log.info("Export complete: %s", path)
    except ValueError as e:
        print(_error(f"  ✗ {e}"))
    except Exception as e:
        print(_error(f"  ✗ Erreur d'export : {e}"))
        _log.error("Export error: %s", e)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────


def main():
    """Point d'entrée principal."""
    if os.geteuid() != 0:
        print(_error("✗ Ce scanner nécessite les droits root."))
        print(_warning("  → Relancez avec : sudo python -m scanner"))
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Network Scanner — Cybersecurity Fingerprinting & Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                 # Auto-détecte le réseau
  python main.py --network 192.168.1.0/24        # Scanne le réseau spécifié
  python main.py --dhcp                          # Active le fingerprinting DHCP
  python main.py --max-workers 20                # Limite les threads de port scan
  python main.py --list                          # Liste les anciens scans
  python main.py --diff NEW_ID OLD_ID            # Compare deux scans
  python main.py --export SCAN_ID                # Exporte un scan en JSON
  python main.py --export SCAN_ID --format csv   # Exporte en CSV
        """,
    )
    parser.add_argument(
        "--network",
        type=str,
        default=None,
        help="Plage CIDR à scanner (ex: 192.168.1.0/24). Auto si non spécifié.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout pour le scan de ports en secondes (défaut: 0.5, plage: 0.01–30).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=50,
        help="Threads parallèles pour le scan de ports (défaut: 50, plage: 1–200).",
    )
    parser.add_argument(
        "--resolve-hostnames",
        action="store_true",
        help="Résout les hostnames via DNS inverse (plus lent).",
    )
    parser.add_argument(
        "--dhcp",
        action="store_true",
        help="Active le fingerprinting DHCP passif (écoute 5 secondes).",
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="N'enregistre pas le scan en base de données.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Liste les scans précédents et quitte.",
    )
    parser.add_argument(
        "--diff",
        nargs=2,
        metavar=("NEW_ID", "OLD_ID"),
        help="Compare deux scans et affiche les différences.",
    )
    parser.add_argument(
        "--export",
        type=str,
        metavar="SCAN_ID",
        help="Exporte un scan sauvegardé (JSON par défaut).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Format pour --export : json ou csv (défaut: json).",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default="scanner.log",
        help="Chemin du fichier de log (défaut: scanner.log).",
    )

    args = parser.parse_args()

    _setup_logging(args.log_file)
    _log.info("Scanner started — PID %d", os.getpid())

    # ── Input validation ──────────────────────────────────────
    if args.network is not None:
        try:
            ipaddress.ip_network(args.network, strict=False)
        except ValueError:
            parser.error(f"Réseau CIDR invalide : '{args.network}'")

    if not (0.01 <= args.timeout <= 30):
        parser.error("--timeout doit être entre 0.01 et 30 secondes.")

    if not (1 <= args.max_workers <= 200):
        parser.error("--max-workers doit être entre 1 et 200.")

    # ── Subcommands ───────────────────────────────────────────
    if args.list:
        list_all_scans()
        return

    if args.diff:
        run_diff(args.diff[0], args.diff[1])
        return

    if args.export:
        run_export(args.export, args.format)
        return

    # ── Scan principal ────────────────────────────────────────
    try:
        start = time.time()
        result = run_scan(
            network=args.network,
            port_timeout=args.timeout,
            resolve_hostnames=args.resolve_hostnames,
            save_to_db=not args.no_db,
            max_workers=args.max_workers,
            enable_dhcp=args.dhcp,
        )
        elapsed = time.time() - start
        print(_info(f"\n⏱ Scan complété en {elapsed:.1f}s"))
        _log.info("Scan completed in %.1fs — %d hosts", elapsed, result.total_hosts)
    except KeyboardInterrupt:
        print(_error("\n\n✗ Scan annulé par l'utilisateur."))
        _log.info("Scan cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(_error(f"\n✗ Erreur fatale : {e}"))
        import traceback
        traceback.print_exc()
        _log.exception("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
