# scanner/fingerprint/http_banner.py
# Identification OS/service via HTTP headers et bannières
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import socket
import ssl
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import Device, FingerprintResult, OSFamily, DeviceType


# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

_HTTP_PORTS  = [80, 8080, 8000, 8888]
_HTTPS_PORTS = [443, 8443]
_TIMEOUT     = 3.0
_MAX_BYTES   = 2048


# ─────────────────────────────────────────────
# Requête HTTP brute
# ─────────────────────────────────────────────

def _http_request(ip: str, port: int, timeout: float = _TIMEOUT) -> str | None:
    """
    Envoie une requête HEAD HTTP/1.0 et retourne les headers bruts.

    On utilise des sockets directs (pas requests/urllib)
    pour garder le contrôle total sur ce qu'on envoie.

    Returns:
        Headers HTTP bruts en string, ou None si échec.
    """
    sock = None
    ssock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Wrap socket with TLS for HTTPS ports
        if port in _HTTPS_PORTS:
            context = ssl.create_default_context()
            ssock = context.wrap_socket(sock, server_hostname=ip)
            conn = ssock
        else:
            conn = sock

        request = (
            f"HEAD / HTTP/1.0\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: NetworkScanner/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        conn.send(request.encode())

        response = b""
        while True:
            chunk = conn.recv(512)
            if not chunk:
                break
            response += chunk
            if len(response) >= _MAX_BYTES:
                break
            if b"\r\n\r\n" in response:
                break

        return response.decode("utf-8", errors="replace")

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None
    finally:
        try:
            if ssock:
                ssock.close()
        except Exception:
            pass
        try:
            if sock:
                sock.close()
        except Exception:
            pass


# ─────────────────────────────────────────────
# Parsing des headers
# ─────────────────────────────────────────────

def _extract_headers(raw: str) -> dict[str, str]:
    """
    Parse les headers HTTP bruts en dict insensible à la casse.

    Ex: "Server: Apache/2.4 (Ubuntu)" → { "server": "Apache/2.4 (Ubuntu)" }
    """
    headers: dict[str, str] = {}

    for line in raw.splitlines()[1:]:   # skip la première ligne (status)
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()

    return headers


# ─────────────────────────────────────────────
# Analyse des headers
# ─────────────────────────────────────────────

# Patterns : (regex sur header value, os_family, os_version, device_type, confidence)
_SERVER_PATTERNS: list[tuple[str, str, str, str, float]] = [
    # ── Windows / IIS ────────────────────────────────────────
    (r"IIS/10\.0",            "Windows", "Windows Server 2016/2019 or Win10+", "Server",   0.90),
    (r"IIS/8\.5",             "Windows", "Windows Server 2012 R2",             "Server",   0.88),
    (r"IIS/8\.0",             "Windows", "Windows Server 2012",                "Server",   0.88),
    (r"IIS/7\.5",             "Windows", "Windows Server 2008 R2",             "Server",   0.85),

    # ── Linux / Apache ───────────────────────────────────────
    (r"Apache/2\.4.*Ubuntu",  "Linux",   "Ubuntu (Apache 2.4)",                "Server",   0.88),
    (r"Apache/2\.4.*Debian",  "Linux",   "Debian (Apache 2.4)",                "Server",   0.88),
    (r"Apache/2\.4.*CentOS",  "Linux",   "CentOS/RHEL (Apache 2.4)",           "Server",   0.88),
    (r"Apache/2\.4.*Fedora",  "Linux",   "Fedora (Apache 2.4)",                "Server",   0.85),
    (r"Apache/2\.2.*CentOS",  "Linux",   "CentOS 6 / RHEL 6 (EOL)",           "Server",   0.85),
    (r"Apache",               "Linux",   "Linux (Apache)",                     "Server",   0.65),

    # ── Linux / Nginx ─────────────────────────────────────────
    (r"nginx/1\.1[89]",       "Linux",   "Ubuntu 20.04 / Debian 11 (Nginx)",   "Server",   0.82),
    (r"nginx/1\.14",          "Linux",   "Ubuntu 18.04 (Nginx)",               "Server",   0.80),
    (r"nginx",                "Linux",   "Linux (Nginx)",                      "Server",   0.65),

    # ── Embedded / IoT ────────────────────────────────────────
    (r"lighttpd",             "Linux",   "Embedded Linux (lighttpd)",          "IoT Device", 0.75),
    (r"mini_httpd",           "Linux",   "Embedded Device",                   "IoT Device", 0.70),
    (r"GoAhead",              "Linux",   "IoT / Embedded (GoAhead)",          "IoT Device", 0.72),
    (r"Boa/",                 "Linux",   "Embedded Linux (Boa)",              "IoT Device", 0.70),
    (r"RomPager",             "Network Device", "DSL Router / Modem",         "Router",    0.80),
    (r"ZyXEL",                "Network Device", "ZyXEL Router",               "Router",    0.85),
    (r"DD-WRT",               "Linux",   "DD-WRT Router",                     "Router",    0.88),
    (r"OpenWrt",              "Linux",   "OpenWrt Router",                    "Router",    0.88),
    (r"MikroTik",             "Network Device", "MikroTik RouterOS",          "Router",    0.90),

    # ── macOS ─────────────────────────────────────────────────
    (r"AirTunes",             "macOS",   "Apple AirTunes / AirPlay",          "IoT Device", 0.90),
    (r"WebKit",               "macOS",   "macOS / iOS (WebKit)",              "Laptop",    0.65),

    # ── Java / App servers ────────────────────────────────────
    (r"Apache-Coyote",        "Linux",   "Apache Tomcat (Java)",              "Server",    0.75),
    (r"Jetty",                "Linux",   "Jetty (Java)",                      "Server",    0.75),
]

_X_POWERED_PATTERNS: list[tuple[str, str, str, str, float]] = [
    (r"PHP/5\.",   "Linux", "PHP 5.x (EOL — vulnérable!)", "Server", 0.70),
    (r"PHP/7\.",   "Linux", "PHP 7.x",                     "Server", 0.65),
    (r"PHP/8\.",   "Linux", "PHP 8.x",                     "Server", 0.65),
    (r"ASP\.NET",  "Windows", "ASP.NET / IIS",             "Server", 0.85),
]


def _analyze_headers(headers: dict[str, str], port: int) -> FingerprintResult | None:
    """
    Analyse les headers HTTP pour déduire OS, version, type d'appareil.

    Returns:
        FingerprintResult ou None si rien de concluant.
    """
    sources: dict[str, str] = {}
    best_result = None
    best_conf   = 0.0

    # ── Server header ─────────────────────────────────────────
    server = headers.get("server", "")
    if server:
        sources["http_server"] = server
        for pattern, os_fam, os_ver, dev_type, conf_val in _SERVER_PATTERNS:
            if re.search(pattern, server, re.IGNORECASE):
                if conf_val > best_conf:
                    best_conf   = conf_val
                    best_result = (os_fam, os_ver, dev_type)
                break

    # ── X-Powered-By header ──────────────────────────────────
    powered = headers.get("x-powered-by", "")
    if powered:
        sources["http_powered"] = powered
        for pattern, os_fam, os_ver, dev_type, conf_val in _X_POWERED_PATTERNS:
            if re.search(pattern, powered, re.IGNORECASE):
                if conf_val > best_conf:
                    best_conf   = conf_val
                    best_result = (os_fam, os_ver, dev_type)
                break

    # ── WWW-Authenticate (révèle parfois l'OS) ───────────────
    auth = headers.get("www-authenticate", "")
    if "Windows" in auth or "NTLM" in auth:
        sources["http_auth"] = auth[:64]
        if 0.80 > best_conf:
            best_conf   = 0.80
            best_result = ("Windows", "Windows (NTLM Auth)", "Server")

    if best_result is None:
        return None

    os_fam, os_ver, dev_type = best_result

    try:
        os_family   = OSFamily(os_fam)
        device_type = DeviceType(dev_type)
    except ValueError:
        os_family   = OSFamily.UNKNOWN
        device_type = DeviceType.UNKNOWN

    return FingerprintResult(
        os_family    = os_family,
        os_version   = os_ver,
        device_type  = device_type,
        confidence   = round(best_conf, 2),
        sources      = sources,
    )


# ─────────────────────────────────────────────
# Fonction principale
# ─────────────────────────────────────────────

def http_banner(device: Device) -> FingerprintResult | None:
    """
    Tente de fingerprinter un Device via ses headers HTTP.

    Sonde uniquement les ports HTTP/HTTPS ouverts sur le Device.
    Si aucun port HTTP n'est ouvert, retourne None.

    Args:
        device: Device à analyser (doit avoir ses ports scannés).

    Returns:
        FingerprintResult ou None.
    """
    # Ports HTTP ouverts sur ce device
    open_ports = {p.number for p in device.get_open_ports()}
    http_ports  = [p for p in _HTTP_PORTS  if p in open_ports]
    https_ports = [p for p in _HTTPS_PORTS if p in open_ports]
    ports_to_try = http_ports + https_ports

    if not ports_to_try:
        return None

    print(f"  [*] HTTP banner sur {device.ip} (ports: {ports_to_try}) ...")

    for port in ports_to_try:
        raw = _http_request(device.ip, port)
        if not raw:
            continue

        # Skip 5xx responses — server errors rarely carry useful fingerprint headers
        first_line = raw.splitlines()[0] if raw else ""
        if first_line.startswith("HTTP/"):
            parts = first_line.split(None, 2)
            if len(parts) >= 2 and parts[1].startswith("5"):
                continue

        headers = _extract_headers(raw)
        result  = _analyze_headers(headers, port)

        if result:
            print(f"  [+] {device.ip}:{port} — {result.summary()} ({result.confidence:.0%})")
            return result

    print(f"  [-] {device.ip} — aucun indice HTTP exploitable")
    return None


# ─────────────────────────────────────────────
# Enrichissement Device
# ─────────────────────────────────────────────

def enrich_devices(devices: list[Device], max_workers: int = 10) -> list[Device]:
    """
    Lance http_banner() en parallèle sur une liste de Device.

    Fusionne avec le fingerprint existant si présent.

    Args:
        devices:     Liste de Device à enrichir.
        max_workers: Threads parallèles.

    Returns:
        La même liste enrichie.
    """
    print(f"\n[*] HTTP banner grabbing sur {len(devices)} hôte(s) ...\n")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_device = {
            executor.submit(http_banner, d): d for d in devices
        }
        for future in as_completed(future_to_device):
            device = future_to_device[future]
            try:
                result = future.result()
                if result is None:
                    continue
                if device.fingerprint is None:
                    device.fingerprint = result
                else:
                    device.fingerprint = device.fingerprint.merge(result)
            except Exception as e:
                print(f"  [!] Erreur HTTP banner {device.ip} : {e}")

    return devices
