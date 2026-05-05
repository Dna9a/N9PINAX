# scanner/models.py
# Pydantic v2 — Device fingerprinting models
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# ─────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────


class OSFamily(str, Enum):
    """Famille d'OS détectée par fingerprinting."""

    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "macOS"
    IOS = "iOS"
    ANDROID = "Android"
    NETWORK_DEVICE = "Network Device"
    IOT = "IoT"
    UNKNOWN = "Unknown"
    OTHER = "Other"


class PortState(str, Enum):
    """État d'un port TCP/UDP après scan."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class PortProtocol(str, Enum):
    """Protocole de transport du port."""

    TCP = "tcp"
    UDP = "udp"
    UNKNOWN = "unknown"


class DeviceType(str, Enum):
    """Type d'appareil identifié."""

    SMARTPHONE = "Smartphone"
    LAPTOP = "Laptop"
    DESKTOP = "Desktop"
    ROUTER = "Router"
    SWITCH = "Switch"
    ACCESS_POINT = "Access Point"
    SMART_TV = "Smart TV"
    IOT_DEVICE = "IoT Device"
    PRINTER = "Printer"
    SERVER = "Server"
    UNKNOWN = "Unknown"
    OTHER = "Other"


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────


def _normalize_mac(raw: str) -> str:
    """
    Normalise une adresse MAC vers le format AA:BB:CC:DD:EE:FF.

    Accepte :
      - aa:bb:cc:dd:ee:ff
      - AA-BB-CC-DD-EE-FF
      - aabb.ccdd.eeff      (format Cisco)
      - aabbccddeeff        (format brut)
    """
    if not raw or not raw.strip():
        raise ValueError("Adresse MAC vide ou manquante.")

    # Retire séparateurs connus
    cleaned = raw.strip().upper().replace(":", "").replace("-", "").replace(".", "")

    if len(cleaned) != 12 or not all(c in "0123456789ABCDEF" for c in cleaned):
        raise ValueError(f"Format MAC invalide : '{raw}'")

    # Regroupe par paires
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


# ─────────────────────────────────────────────
# Port
# ─────────────────────────────────────────────


class Port(BaseModel):
    """Représente un port réseau scanné sur un Device."""

    number: int = Field(
        ...,
        ge=1,
        le=65535,
        description="Numéro de port (1–65535).",
        examples=[80, 443, 22],
    )
    state: PortState = Field(
        PortState.UNKNOWN,
        description="État du port après scan.",
    )
    protocol: PortProtocol = Field(
        PortProtocol.TCP,
        description="Protocole de transport.",
    )
    service: str = Field(
        "unknown",
        max_length=64,
        description="Nom du service détecté (ex: HTTP, SSH).",
        examples=["HTTP", "SSH", "unknown"],
    )
    banner: Optional[str] = Field(
        None,
        max_length=512,
        description="Bannière brute renvoyée par le service (tronquée à 512 chars).",
        examples=["Apache/2.4.54 (Ubuntu)"],
    )
    os_hint: Optional[str] = Field(
        None,
        max_length=128,
        description="Indice OS/version déduit de la bannière du service.",
        examples=["Ubuntu 20.04 likely", "Windows Server 2016"],
    )

    @field_validator("service")
    @classmethod
    def sanitize_service(cls, v: str) -> str:
        """Retire les caractères non imprimables du nom de service."""
        return "".join(c for c in v if c.isprintable()).strip() or "unknown"


# ─────────────────────────────────────────────
# FingerprintResult
# ─────────────────────────────────────────────


class FingerprintResult(BaseModel):
    """
    Résultat agrégé du fingerprinting d'un Device.

    Combine les résultats de :
      - MAC OUI lookup
      - TCP/IP stack fingerprinting
      - DHCP fingerprinting
      - HTTP banner grabbing
    """

    os_family: OSFamily = Field(
        OSFamily.UNKNOWN,
        description="Famille d'OS détectée.",
    )
    os_version: Optional[str] = Field(
        None,
        max_length=64,
        description="Version précise de l'OS si identifiable (ex: 'Windows 11', 'iOS 16.2').",
        examples=["Windows 11", "iOS 16.2", "Ubuntu 22.04"],
    )
    device_vendor: Optional[str] = Field(
        None,
        max_length=128,
        description="Fabricant de l'appareil (ex: Apple, Samsung).",
        examples=["Apple", "Samsung", "Dell"],
    )
    device_type: DeviceType = Field(
        DeviceType.UNKNOWN,
        description="Type d'appareil identifié.",
    )
    confidence: float = Field(
        0.0,
        ge=0.0,
        le=1.0,
        description="Niveau de confiance global entre 0.0 et 1.0.",
        examples=[0.85, 0.5],
    )
    sources: dict[str, str] = Field(
        default_factory=dict,
        description="Détail par technique : {'mac': 'Apple Inc.', 'tcp': 'iOS/macOS'}.",
    )

    # Données brutes TCP (utiles pour le rapport PFE)
    tcp_ttl: Optional[int] = Field(None, description="TTL mesuré dans la réponse TCP.")
    tcp_window: Optional[int] = Field(
        None, description="Taille de fenêtre TCP annoncée."
    )
    tcp_options: Optional[list[str]] = Field(
        None, description="Liste des options TCP (ex: ['MSS','NOP','TS'])."
    )
    icmp_response: Optional[bool] = Field(
        None, description="True si ICMP ping a répondu."
    )

    # ── Validators ───────────────────────────────────────────

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        """Garde confidence strictement dans [0.0, 1.0]."""
        return max(0.0, min(1.0, v))

    # ── Helpers ──────────────────────────────────────────────

    def summary(self) -> str:
        """Résumé lisible pour le dashboard."""
        base = self.os_version or self.os_family.value
        if self.device_vendor:
            return f"{self.device_vendor} — {base}"
        return base

    def __str__(self) -> str:
        return f"[{self.confidence:.0%}] {self.summary()} ({self.device_type.value})"

    def update_confidence(self, delta: float) -> None:
        """
        Ajuste la confiance de `delta` (positif ou négatif).
        Reste bornée entre 0.0 et 1.0.
        """
        self.confidence = max(0.0, min(1.0, self.confidence + delta))

    def merge(self, other: FingerprintResult) -> FingerprintResult:
        """
        Fusionne deux FingerprintResult.

        Règle : on garde les champs du résultat avec la confidence
        la plus haute. Les sources ne sont fusionnées que si les deux
        résultats ont des OS families compatibles (évite de mélanger
        des indices Windows et Linux contradictoires).
        """
        base = self if self.confidence >= other.confidence else other
        loser = other if self.confidence >= other.confidence else self

        os_compatible = (
            base.os_family == loser.os_family
            or base.os_family == OSFamily.UNKNOWN
            or loser.os_family == OSFamily.UNKNOWN
        )
        merged_sources = (
            {**loser.sources, **base.sources} if os_compatible else {**base.sources}
        )

        return FingerprintResult(
            os_family=base.os_family,
            os_version=base.os_version,
            device_vendor=base.device_vendor,
            device_type=base.device_type,
            confidence=max(self.confidence, other.confidence),
            sources=merged_sources,
            tcp_ttl=self.tcp_ttl or other.tcp_ttl,
            tcp_window=self.tcp_window or other.tcp_window,
            tcp_options=self.tcp_options or other.tcp_options,
            icmp_response=(
                self.icmp_response
                if self.icmp_response is not None
                else other.icmp_response
            ),
        )


# ─────────────────────────────────────────────
# Device
# ─────────────────────────────────────────────


class Device(BaseModel):
    """
    Représente un équipement réseau découvert sur le LAN.

    Enrichi progressivement par chaque module du scanner :
    arp_scan → port_scan → fingerprint/* → os_classifier
    """

    ip: str = Field(
        ...,
        description="Adresse IPv4 ou IPv6 de l'équipement.",
        examples=["192.168.1.42", "fe80::1"],
    )
    mac: str = Field(
        ...,
        description="Adresse MAC normalisée (AA:BB:CC:DD:EE:FF).",
        examples=["A4:C3:F0:12:34:56"],
    )
    hostname: str = Field(
        "unknown",
        max_length=253,
        description="Nom d'hôte résolu via reverse DNS.",
        examples=["router.home", "unknown"],
    )
    mac_vendor: str = Field(
        "Unknown",
        max_length=128,
        description="Fabricant issu du lookup OUI/IEEE.",
        examples=["Apple Inc.", "Raspberry Pi Foundation"],
    )
    fingerprint: Optional[FingerprintResult] = Field(
        None,
        description="Résultat complet du fingerprinting OS/device.",
    )
    ports: list[Port] = Field(
        default_factory=list,
        description="Ports scannés sur cet équipement.",
    )
    is_online: bool = Field(
        True,
        description="True si l'équipement a répondu lors du dernier scan.",
    )
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Horodatage de la première découverte.",
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Horodatage du dernier scan où l'équipement était actif.",
    )

    # ── Validators ───────────────────────────────────────────

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """
        Valide via ipaddress — gère les limites d'octets et IPv6.
        Lève ValueError si invalide.
        """
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError(f"Adresse IP invalide : '{v}'")
        return v.strip()

    @field_validator("mac")
    @classmethod
    def normalize_mac(cls, v: str) -> str:
        """Normalise le MAC via _normalize_mac()."""
        return _normalize_mac(v)

    @field_validator("hostname")
    @classmethod
    def sanitize_hostname(cls, v: str) -> str:
        """Retire les caractères non imprimables du hostname."""
        return "".join(c for c in v if c.isprintable()).strip() or "unknown"

    # ── Properties ───────────────────────────────────────────

    @property
    def open_ports_count(self) -> int:
        """Nombre de ports en état OPEN."""
        return sum(1 for p in self.ports if p.state == PortState.OPEN)

    @property
    def age(self) -> float:
        """Durée en secondes depuis first_seen."""
        now = datetime.now(timezone.utc)
        fs = self.first_seen
        if fs.tzinfo is None:
            fs = fs.replace(tzinfo=timezone.utc)
        return (now - fs).total_seconds()

    # ── Port helpers ─────────────────────────────────────────

    def get_open_ports(self) -> list[Port]:
        """Retourne uniquement les ports ouverts."""
        return [p for p in self.ports if p.state == PortState.OPEN]

    def find_port(self, number: int) -> Optional[Port]:
        """Retourne le Port correspondant au numéro, ou None."""
        return next((p for p in self.ports if p.number == number), None)

    def add_or_update_port(self, port: Port) -> None:
        """
        Ajoute le port s'il n'existe pas encore,
        ou remplace l'entrée existante avec le même numéro.
        """
        for i, p in enumerate(self.ports):
            if p.number == port.number:
                self.ports[i] = port
                return
        self.ports.append(port)

    # ── Device helpers ───────────────────────────────────────

    def display_name(self) -> str:
        """Nom lisible pour le dashboard."""
        if self.fingerprint and self.fingerprint.device_vendor:
            return f"{self.fingerprint.device_vendor} ({self.ip})"
        if self.hostname != "unknown":
            return f"{self.hostname} ({self.ip})"
        return self.ip

    def mark_offline(self) -> None:
        """Marque l'équipement comme hors ligne."""
        self.is_online = False
        self.last_seen = datetime.now(timezone.utc)

    # ── Serialization ────────────────────────────────────────

    def to_json(self, exclude_none: bool = True) -> dict:
        """
        Sérialise en dict JSON-compatible.
        Par défaut, exclut les champs None pour alléger la réponse API.
        """
        return self.model_dump(mode="json", exclude_none=exclude_none)


# ─────────────────────────────────────────────
# ScanResult
# ─────────────────────────────────────────────


class ScanResult(BaseModel):
    """
    Résultat complet d'un scan réseau.

    Contient tous les Device découverts et les métadonnées du scan.
    Persiste via storage.py (SQLite).
    """

    network: str = Field(
        ...,
        description="Plage réseau scannée (ex: '192.168.1.0/24').",
        examples=["192.168.1.0/24", "10.0.0.0/8"],
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Horodatage du début du scan.",
    )
    devices: list[Device] = Field(
        default_factory=list,
        description="Liste des équipements découverts.",
    )
    total_hosts: int = Field(
        0,
        description="Nombre total d'hôtes actifs (calculé automatiquement).",
    )
    scan_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Identifiant unique du scan (UUID v4, auto-généré).",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )

    # ── Validators ───────────────────────────────────────────

    @field_validator("network")
    @classmethod
    def validate_network(cls, v: str) -> str:
        """Valide la plage réseau via ipaddress."""
        try:
            ipaddress.ip_network(v.strip(), strict=False)
        except ValueError:
            raise ValueError(f"Réseau invalide : '{v}'")
        return v.strip()

    def model_post_init(self, __context) -> None:
        """Recalcule total_hosts après chaque init ou update."""
        self.total_hosts = len(self.devices)

    # ── Device helpers ───────────────────────────────────────

    def find_device_by_mac(self, mac: str) -> Optional[Device]:
        """
        Cherche un Device par adresse MAC (insensible à la casse / format).
        Retourne None si non trouvé.
        """
        try:
            normalized = _normalize_mac(mac)
        except ValueError:
            return None
        return next((d for d in self.devices if d.mac == normalized), None)

    def find_device_by_ip(self, ip: str) -> Optional[Device]:
        """Cherche un Device par adresse IP."""
        return next((d for d in self.devices if d.ip == ip.strip()), None)

    def get_new_devices(self, previous: ScanResult) -> list[Device]:
        """Retourne les devices présents ici mais absents dans `previous`."""
        previous_macs = {d.mac for d in previous.devices}
        return [d for d in self.devices if d.mac not in previous_macs]

    def get_lost_devices(self, previous: ScanResult) -> list[Device]:
        """Retourne les devices présents dans `previous` mais disparus ici."""
        current_macs = {d.mac for d in self.devices}
        return [d for d in previous.devices if d.mac not in current_macs]

    # ── Serialization ────────────────────────────────────────

    def to_json(self, exclude_none: bool = True) -> dict:
        """Sérialise en dict JSON-compatible, champs None exclus par défaut."""
        return self.model_dump(mode="json", exclude_none=exclude_none)
