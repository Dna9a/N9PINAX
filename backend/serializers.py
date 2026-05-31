# backend/serializers.py
# Shared API serialization for scanner models. Lives here (not in app.py) so
# both the REST routes and the SSE/scan-service layer emit the SAME device
# shape, without a circular import on app.py.

from __future__ import annotations

from typing import Optional


def device_to_api(device, alerts: Optional[list] = None) -> dict:
    """Serialize a Device into the dict shape the frontend expects.

    ``risk`` is computed in scanner.models (alert-aware when ``alerts`` is
    provided, port-heuristic otherwise).
    """
    fp = device.fingerprint
    return {
        "ip": device.ip,
        "mac": device.mac,
        "hostname": device.hostname,
        "vendor": device.mac_vendor,
        "is_online": device.is_online,
        "latency_ms": device.latency_ms,
        "os_family": fp.os_family.value if fp else "Unknown",
        "os_version": fp.os_version if fp else None,
        "device_type": fp.device_type.value if fp else "Unknown",
        "confidence": fp.confidence if fp else 0.0,
        "open_ports": [
            {
                "number": p.number,
                "protocol": p.protocol.value,
                "service": p.service,
                "banner": p.banner,
            }
            for p in device.get_open_ports()
        ],
        "risk": device.risk_label(alerts),
    }
