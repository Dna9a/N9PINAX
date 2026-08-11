# backend/app.py
from __future__ import annotations
import asyncio
import json
import logging
import os
import re
import secrets
import time
import uuid
import bcrypt
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt as pyjwt
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Path as PathParam,
    Query,
    Request,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    JSONResponse,
    StreamingResponse,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

try:
    from sse_starlette.sse import EventSourceResponse
except ImportError as e:
    raise RuntimeError("sse-starlette is required. pip install sse-starlette") from e

from scanner import (
    create_note,
    create_user,
    delete_note,
    delete_user,
    get_diff,
    get_note,
    get_user_by_email,
    get_user_by_id,
    init_db,
    list_alerts,
    list_notes,
    list_scans,
    list_users,
    load_last_scan,
    load_scan,
    mark_alert_resolved,
    update_note,
)
from scanner.config import get_config
from scanner.report import parse_reports

from .events import BUS
from .rate_limit import enforce_rate_limit
from .redis_client import cache_delete, cache_get, cache_set, close_redis
from .scan_service import SERVICE
from .serializers import device_to_api as _device_to_api
from .schemas import (
    HealthResponse,
    NoteCreate,
    NoteUpdate,
    ScanJobResponse,
    ScanRequest,
)

_log = logging.getLogger(__name__)
VERSION = "2.0.0"
_STARTED_AT = time.time()
_FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
# Local dev fallback: Docker copies "Frontend  2/" → "frontend/", but when
# running outside a container that target doesn't exist. Fall back to the
# source tree so `make run-backend` works without any manual symlink.
if not _FRONTEND_DIR.exists():
    _alt = Path(__file__).resolve().parent.parent / "Frontend  2"
    if _alt.exists():
        _FRONTEND_DIR = _alt

# Cached-response keys / TTLs (see scanner caching layer).
_LAST_SCAN_CACHE_KEY = "cache:last_scan"
_LAST_SCAN_CACHE_TTL = 30  # seconds

# Users are persisted in SQLite (see scanner.storage). The default admin
# account ("na9a" / "1234") is seeded by init_db() on first run. Activity log
# stays in-memory — it is operational telemetry, not source-of-truth data.
_ACTIVITY_LOG: list[dict] = []
_bearer = HTTPBearer(auto_error=False)

# ── Auth helpers ──────────────────────────────────────────────────────────


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# Values that must NEVER be accepted as a real signing secret. The first three
# are placeholders that have appeared in this repo's docs / example env files
# and are therefore public knowledge — a token signed with any of them is
# trivially forgeable by anyone who has seen the source.
_PLACEHOLDER_SECRETS = frozenset(
    {
        "",
        "n9pinax-jwt-secret-change-in-prod",
        "replace-with-a-strong-random-secret",
        "change-me-before-deploying",
        "change-me",
        "changeme",
        "secret",
        "changethis",
    }
)


def _resolve_jwt_secret() -> str:
    """Resolve the JWT signing secret, failing closed in production.

    A secret is only accepted when it is explicitly set, not a known
    placeholder, and at least 16 chars long. When no usable secret is present
    we EITHER refuse to start (``SCANNER_ENV=production``) OR generate a random
    ephemeral secret for this process (dev/local/test). Crucially, we never
    fall back to a hardcoded constant, so tokens can never be forged from
    values baked into the source tree.
    """
    raw = (os.environ.get("SCANNER_JWT_SECRET") or "").strip()
    if raw and raw.lower() not in _PLACEHOLDER_SECRETS and len(raw) >= 16:
        return raw

    env = (os.environ.get("SCANNER_ENV") or "").strip().lower()
    if env in ("prod", "production"):
        raise RuntimeError(
            "SCANNER_JWT_SECRET is unset, a known placeholder, or too short. "
            "Refusing to start in production. Generate a strong secret with:\n"
            '  python3 -c "import secrets; print(secrets.token_hex(32))"\n'
            "and set it via the SCANNER_JWT_SECRET environment variable."
        )

    ephemeral = secrets.token_hex(32)
    logging.getLogger(__name__).warning(
        "SCANNER_JWT_SECRET is not set to a strong value — generated a RANDOM "
        "ephemeral secret for this process. All tokens will be invalidated on "
        "restart. Set SCANNER_JWT_SECRET for a stable secret; set "
        "SCANNER_ENV=production to require one and fail closed."
    )
    return ephemeral


_JWT_SECRET = _resolve_jwt_secret()

# ── SSE stream tickets ──────────────────────────────────────────────────────
# EventSource cannot send an Authorization header, so the old code passed the
# long-lived JWT in the URL query string — where it ended up in access logs,
# proxy logs, and browser history. Instead we mint a short-lived, single-use
# ticket (authenticated via the normal Bearer header) and the browser opens the
# stream with ?ticket=. A leaked ticket is useless within seconds and grants
# read-only stream access, not full account access.
_SSE_TICKETS: dict[str, tuple[dict, float]] = {}
_SSE_TICKET_TTL = 30.0  # seconds


def _prune_sse_tickets(now: float) -> None:
    expired = [t for t, (_, exp) in _SSE_TICKETS.items() if exp < now]
    for t in expired:
        _SSE_TICKETS.pop(t, None)


def _make_token(user: dict) -> str:
    payload = {
        "sub": user["user_id"],
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }
    return pyjwt.encode(payload, _JWT_SECRET, algorithm="HS256")


def _decode_token(token: str) -> dict:
    try:
        return pyjwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def _get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    return _decode_token(credentials.credentials)


def _require_admin(user: dict = Depends(_get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _log_activity(user: dict, action: str, detail: str = "", ip: str = "") -> None:
    _ACTIVITY_LOG.append(
        {
            "log_id": str(uuid.uuid4()),
            "user_email": user.get("email", "unknown"),
            "role": user.get("role", "unknown"),
            "action": action,
            "detail": detail,
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# ── Path validation ───────────────────────────────────────────────────────
def _validated_scan_id(
    scan_id: str = PathParam(..., min_length=36, max_length=36)
) -> str:
    try:
        val = uuid.UUID(scan_id)
        if str(val) != scan_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail=f"scan_id invalide: '{scan_id}'")
    return scan_id


def _validated_alert_id(
    alert_id: str = PathParam(..., min_length=36, max_length=36)
) -> str:
    try:
        val = uuid.UUID(alert_id)
        if str(val) != alert_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail=f"alert_id invalide: '{alert_id}'")
    return alert_id


def _validated_note_id(
    note_id: str = PathParam(..., min_length=36, max_length=36)
) -> str:
    try:
        val = uuid.UUID(note_id)
        if str(val) != note_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail=f"note_id invalide: '{note_id}'")
    return note_id


# ── Request models ────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., max_length=128)


class LoginResponse(BaseModel):
    token: str
    user_id: str
    email: str
    role: str


# Deliberately strict: forbids whitespace and the HTML metacharacters that
# would otherwise let a crafted email become a stored-XSS payload downstream.
_EMAIL_RE = re.compile(r"^[^@\s<>\"'&/\\]+@[^@\s<>\"'&/\\]+\.[^@\s<>\"'&/\\]{2,}$")


class CreateUserRequest(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field("analyst", pattern="^(analyst|admin)$")

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("invalid email address")
        return v


# ── App factory ───────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    cfg = get_config()
    cfg.ensure_dirs()
    init_db(cfg.db_path)

    # API docs are an information-disclosure surface (they enumerate every
    # route + schema). Off by default; opt in with SCANNER_ENABLE_DOCS=1.
    _docs_enabled = _env_bool("SCANNER_ENABLE_DOCS", False)
    app = FastAPI(
        title="N9pinax — SIEM Scanner API",
        version=VERSION,
        docs_url="/docs" if _docs_enabled else None,
        redoc_url="/redoc" if _docs_enabled else None,
        openapi_url="/openapi.json" if _docs_enabled else None,
    )
    app.router.add_event_handler("shutdown", close_redis)

    # CORS: never combine a wildcard origin with credentials (the browser
    # rejects it, and it signals an unsafe default). Auth here is via the
    # Authorization header, not cookies, so credentials are unnecessary; we
    # only enable them when an explicit origin allowlist is configured.
    cors_origins = list(cfg.api_cors_origins) or ["*"]
    allow_all_origins = "*" in cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=not allow_all_origins,
        allow_methods=["GET", "POST", "DELETE", "PATCH"],
        allow_headers=["Content-Type", "Authorization"],
    )

    # Health
    @app.get("/api/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(
            status="ok",
            version=VERSION,
            uptime_seconds=round(time.time() - _STARTED_AT, 3),
        )

    # Auth
    @app.post(
        "/api/auth/login",
        response_model=LoginResponse,
        dependencies=[Depends(enforce_rate_limit)],
    )
    async def login(payload: LoginRequest, request: Request):
        user = get_user_by_email(payload.email.lower().strip())
        if user is None or not bcrypt.checkpw(
            payload.password.encode(), user["password_hash"].encode()
        ):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = _make_token(user)
        _log_activity(user, "login", ip=request.client.host if request.client else "")
        return LoginResponse(
            token=token, user_id=user["user_id"], email=user["email"], role=user["role"]
        )

    @app.get("/api/auth/me", dependencies=[Depends(enforce_rate_limit)])
    async def me(user: dict = Depends(_get_current_user)):
        return {"user_id": user["sub"], "email": user["email"], "role": user["role"]}

    # Scan control
    @app.post(
        "/api/scan",
        response_model=ScanJobResponse,
        dependencies=[Depends(enforce_rate_limit)],
    )
    async def start_scan(payload: ScanRequest, user: dict = Depends(_get_current_user)):
        loop = asyncio.get_running_loop()
        try:
            job = SERVICE.submit(
                network=payload.network,
                enable_udp=payload.udp,
                enable_dhcp=payload.dhcp,
                resolve_hostnames=payload.resolve_hostnames,
                loop=loop,
                owner=user.get("sub"),
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        _log_activity(user, "start_scan", detail=payload.network or "auto")
        return ScanJobResponse(**job.to_json())

    @app.get("/api/jobs", dependencies=[Depends(enforce_rate_limit)])
    async def list_jobs(user: dict = Depends(_get_current_user)):
        return SERVICE.list_jobs()

    @app.get("/api/jobs/{job_id}", dependencies=[Depends(enforce_rate_limit)])
    async def get_job(
        job_id: str = PathParam(..., min_length=32, max_length=32),
        user: dict = Depends(_get_current_user),
    ):
        if not job_id.isalnum():
            raise HTTPException(status_code=400, detail="invalid job_id")
        job = SERVICE.get_job(job_id)
        if job is not None:
            return job.to_json()
        # Not in memory (e.g. after a restart) — try the Redis snapshot.
        cached = await cache_get(f"job:{job_id}")
        if cached:
            return json.loads(cached)
        raise HTTPException(status_code=404, detail="job not found")

    # Historical scans
    @app.get("/api/scans", dependencies=[Depends(enforce_rate_limit)])
    async def get_scans(
        limit: int = Query(50, ge=1, le=500), user: dict = Depends(_get_current_user)
    ):
        return list_scans()[:limit]

    @app.get("/api/scans/last", dependencies=[Depends(enforce_rate_limit)])
    async def get_last_scan(user: dict = Depends(_get_current_user)):
        # Hot path (dashboard polls it) — serve from the Redis cache when warm.
        cached = await cache_get(_LAST_SCAN_CACHE_KEY)
        if cached:
            return json.loads(cached)
        scan = load_last_scan()
        if scan is None:
            raise HTTPException(status_code=404, detail="no scans recorded")
        data = _scan_to_api(scan)
        await cache_set(
            _LAST_SCAN_CACHE_KEY, json.dumps(data, default=str), _LAST_SCAN_CACHE_TTL
        )
        return data

    # NOTE: registered before /api/scans/{scan_id} so the static "diff" path
    # is not swallowed by the {scan_id} matcher.
    @app.get("/api/scans/diff", dependencies=[Depends(enforce_rate_limit)])
    async def get_scans_diff(
        scan_id_new: str = Query(..., min_length=36, max_length=36),
        scan_id_old: str = Query(..., min_length=36, max_length=36),
        user: dict = Depends(_get_current_user),
    ):
        for sid in (scan_id_new, scan_id_old):
            try:
                if str(uuid.UUID(sid)) != sid:
                    raise ValueError
            except (ValueError, TypeError, AttributeError):
                raise HTTPException(status_code=400, detail=f"scan_id invalide: '{sid}'")
        diff = get_diff(scan_id_new, scan_id_old)
        return {
            "new_devices": [_device_to_api(d) for d in diff["new_devices"]],
            "lost_devices": [_device_to_api(d) for d in diff["lost_devices"]],
            "changed_ports": diff["changed_ports"],
        }

    @app.get("/api/scans/{scan_id}", dependencies=[Depends(enforce_rate_limit)])
    async def get_scan(
        scan_id: str = Depends(_validated_scan_id),
        user: dict = Depends(_get_current_user),
    ):
        scan = load_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return _scan_to_api(scan)

    # Alerts
    @app.get("/api/alerts", dependencies=[Depends(enforce_rate_limit)])
    async def get_alerts(
        limit: int = Query(100, ge=1, le=500),
        severity: Optional[str] = Query(None, max_length=16),
        only_unresolved: bool = Query(False),
        user: dict = Depends(_get_current_user),
    ):
        if severity and severity.lower() not in ("low", "medium", "high", "critical"):
            raise HTTPException(status_code=400, detail="invalid severity")
        return list_alerts(
            limit=limit,
            severity=severity.lower() if severity else None,
            only_unresolved=only_unresolved,
        )

    @app.post(
        "/api/alerts/{alert_id}/resolve", dependencies=[Depends(enforce_rate_limit)]
    )
    async def resolve_alert(
        alert_id: str = Depends(_validated_alert_id),
        user: dict = Depends(_get_current_user),
    ):
        ok = mark_alert_resolved(alert_id)
        if not ok:
            raise HTTPException(status_code=404, detail="alert not found")
        await BUS.publish("alert_resolved", {"alert_id": alert_id})
        _log_activity(user, "resolve_alert", detail=alert_id)
        return {"alert_id": alert_id, "resolved": True}

    # Reports
    @app.get("/api/reports", dependencies=[Depends(enforce_rate_limit)])
    async def get_reports(
        limit: int = Query(50, ge=1, le=500), user: dict = Depends(_get_current_user)
    ):
        return parse_reports()[-limit:]

    @app.get("/api/reports/{scan_id}/pdf", dependencies=[Depends(enforce_rate_limit)])
    async def download_pdf(
        scan_id: str = Depends(_validated_scan_id),
        user: dict = Depends(_get_current_user),
    ):
        scan = load_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        try:
            pdf_bytes = _generate_pdf(scan)
        except Exception as exc:
            _log.error("PDF generation failed: %s", exc)
            raise HTTPException(status_code=500, detail="PDF generation failed")
        ts_part = (
            scan.timestamp.strftime("%Y%m%d_%H%M%S")
            if hasattr(scan.timestamp, "strftime") else scan_id[:8]
        )
        filename = f"n9pinax_scan_{ts_part}.pdf"
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/scans/{scan_id}/csv", dependencies=[Depends(enforce_rate_limit)])
    async def download_csv(
        scan_id: str = Depends(_validated_scan_id),
        user: dict = Depends(_get_current_user),
    ):
        from scanner.storage import export_csv

        try:
            csv_text = export_csv(scan_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="scan not found")
        return StreamingResponse(
            iter([csv_text.encode()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="scan_{scan_id[:8]}.csv"'
            },
        )

    # Export endpoints — canonical /api/scan/{id}/export/{format} paths
    # These provide structured downloads directly from a scan result.

    @app.get("/api/scan/{scan_id}/export/json", dependencies=[Depends(enforce_rate_limit)])
    async def export_scan_json(
        scan_id: str = Depends(_validated_scan_id),
        user: dict = Depends(_get_current_user),
    ):
        scan = load_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        payload = {
            "meta": {
                "scan_id": scan.scan_id,
                "network": scan.network,
                "timestamp": scan.timestamp.isoformat(),
                "duration_seconds": scan.duration_seconds,
                "total_hosts": scan.total_hosts,
                "alert_count": len(scan.alerts),
            },
            "devices": [_device_to_api(d, scan.alerts) for d in scan.devices],
            "alerts": [a.to_json() for a in scan.alerts],
        }
        json_text = json.dumps(payload, indent=2, default=str)
        filename = f"scan_{scan_id[:8]}.json"
        return StreamingResponse(
            iter([json_text.encode()]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/scan/{scan_id}/export/csv", dependencies=[Depends(enforce_rate_limit)])
    async def export_scan_csv(
        scan_id: str = Depends(_validated_scan_id),
        user: dict = Depends(_get_current_user),
    ):
        from scanner.storage import export_csv

        try:
            csv_text = export_csv(scan_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="scan not found")
        filename = f"scan_{scan_id[:8]}.csv"
        return StreamingResponse(
            iter([csv_text.encode()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/scan/{scan_id}/export/pdf", dependencies=[Depends(enforce_rate_limit)])
    async def export_scan_pdf(
        scan_id: str = Depends(_validated_scan_id),
        user: dict = Depends(_get_current_user),
    ):
        scan = load_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        try:
            pdf_bytes = _generate_pdf(scan)
        except Exception as exc:
            _log.error("PDF generation failed: %s", exc)
            raise HTTPException(status_code=500, detail="PDF generation failed")
        ts_part = (
            scan.timestamp.strftime("%Y%m%d_%H%M%S")
            if hasattr(scan.timestamp, "strftime") else scan_id[:8]
        )
        filename = f"n9pinax_scan_{ts_part}.pdf"
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Notes
    # Object-level authorization (audit F-068): a note belongs to its author.
    # Non-admins may only read/modify/delete their own notes; admins see all.
    # We return 404 (not 403) for someone else's note so its existence isn't
    # disclosed to non-owners.
    def _note_owned_or_404(note_id: str, user: dict) -> dict:
        note = get_note(note_id)
        if note is None:
            raise HTTPException(status_code=404, detail="note not found")
        if user.get("role") != "admin" and note.get("author") != user.get("email"):
            raise HTTPException(status_code=404, detail="note not found")
        return note

    @app.post("/api/notes", dependencies=[Depends(enforce_rate_limit)])
    async def create_note_endpoint(
        payload: NoteCreate, user: dict = Depends(_get_current_user)
    ):
        note = create_note(
            note_id=str(uuid.uuid4()),
            title=payload.title,
            content=payload.content,
            author=user.get("email", "unknown"),
            scan_id=payload.scan_id,
            device_ip=payload.device_ip,
            tags=payload.tags,
        )
        _log_activity(user, "create_note", detail=note["note_id"])
        return note

    @app.get("/api/notes", dependencies=[Depends(enforce_rate_limit)])
    async def list_notes_endpoint(
        scan_id: Optional[str] = Query(None, max_length=36),
        device_ip: Optional[str] = Query(None, max_length=45),
        user: dict = Depends(_get_current_user),
    ):
        author = None if user.get("role") == "admin" else user.get("email")
        return list_notes(scan_id=scan_id, device_ip=device_ip, author=author)

    # NOTE: registered before /api/notes/{note_id}/pdf so the static "export"
    # path is not swallowed by the {note_id} matcher.
    @app.get("/api/notes/export/pdf", dependencies=[Depends(enforce_rate_limit)])
    async def export_notes_pdf(
        scan_id: Optional[str] = Query(None, max_length=36),
        device_ip: Optional[str] = Query(None, max_length=45),
        user: dict = Depends(_get_current_user),
    ):
        author = None if user.get("role") == "admin" else user.get("email")
        notes = list_notes(scan_id=scan_id, device_ip=device_ip, author=author)
        try:
            pdf_bytes = _generate_notes_pdf(notes)
        except Exception as exc:
            _log.error("Notes PDF generation failed: %s", exc)
            raise HTTPException(status_code=500, detail="PDF generation failed")
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="notes.pdf"'},
        )

    @app.get("/api/notes/{note_id}", dependencies=[Depends(enforce_rate_limit)])
    async def get_note_endpoint(
        note_id: str = Depends(_validated_note_id),
        user: dict = Depends(_get_current_user),
    ):
        return _note_owned_or_404(note_id, user)

    @app.patch("/api/notes/{note_id}", dependencies=[Depends(enforce_rate_limit)])
    async def update_note_endpoint(
        payload: NoteUpdate,
        note_id: str = Depends(_validated_note_id),
        user: dict = Depends(_get_current_user),
    ):
        _note_owned_or_404(note_id, user)
        note = update_note(
            note_id,
            title=payload.title,
            content=payload.content,
            tags=payload.tags,
            scan_id=payload.scan_id,
            device_ip=payload.device_ip,
        )
        if note is None:
            raise HTTPException(status_code=404, detail="note not found")
        return note

    @app.delete("/api/notes/{note_id}", dependencies=[Depends(enforce_rate_limit)])
    async def delete_note_endpoint(
        note_id: str = Depends(_validated_note_id),
        user: dict = Depends(_get_current_user),
    ):
        _note_owned_or_404(note_id, user)
        if not delete_note(note_id):
            raise HTTPException(status_code=404, detail="note not found")
        _log_activity(user, "delete_note", detail=note_id)
        return {"deleted": True, "note_id": note_id}

    @app.get("/api/notes/{note_id}/pdf", dependencies=[Depends(enforce_rate_limit)])
    async def download_note_pdf(
        note_id: str = Depends(_validated_note_id),
        user: dict = Depends(_get_current_user),
    ):
        note = _note_owned_or_404(note_id, user)
        try:
            pdf_bytes = _generate_notes_pdf([note])
        except Exception as exc:
            _log.error("Note PDF generation failed: %s", exc)
            raise HTTPException(status_code=500, detail="PDF generation failed")
        filename = f"note_{note_id[:8]}.pdf"
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Admin — user management
    @app.get("/api/admin/users", dependencies=[Depends(enforce_rate_limit)])
    async def admin_list_users(admin: dict = Depends(_require_admin)):
        return [
            {"user_id": u["user_id"], "email": u["email"], "role": u["role"]}
            for u in list_users()
        ]

    @app.post("/api/admin/users", dependencies=[Depends(enforce_rate_limit)])
    async def admin_create_user(
        payload: CreateUserRequest, admin: dict = Depends(_require_admin)
    ):
        email = payload.email.lower().strip()
        if get_user_by_email(email) is not None:
            raise HTTPException(status_code=409, detail="User already exists")
        password_hash = bcrypt.hashpw(
            payload.password.encode(), bcrypt.gensalt()
        ).decode()
        new_user = create_user(
            user_id=str(uuid.uuid4()),
            email=email,
            password_hash=password_hash,
            role=payload.role,
        )
        _log_activity(admin, "create_user", detail=email)
        return new_user

    @app.delete(
        "/api/admin/users/{user_id}", dependencies=[Depends(enforce_rate_limit)]
    )
    async def admin_delete_user(
        user_id: str = PathParam(..., min_length=36, max_length=36),
        admin: dict = Depends(_require_admin),
    ):
        target = get_user_by_id(user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="user not found")
        if target["email"] == admin.get("email"):
            raise HTTPException(status_code=400, detail="Cannot delete yourself")
        # Don't allow removing the last admin — that would lock everyone out of
        # user management with no way back (audit F-076).
        if target.get("role") == "admin":
            admin_count = sum(1 for u in list_users() if u.get("role") == "admin")
            if admin_count <= 1:
                raise HTTPException(
                    status_code=400, detail="Cannot delete the last admin account"
                )
        delete_user(user_id)
        _log_activity(admin, "delete_user", detail=target["email"])
        return {"deleted": True, "user_id": user_id}

    # Admin — activity log
    @app.get("/api/admin/activity", dependencies=[Depends(enforce_rate_limit)])
    async def admin_activity(
        limit: int = Query(200, ge=1, le=1000), admin: dict = Depends(_require_admin)
    ):
        return _ACTIVITY_LOG[-limit:][::-1]

    # Mint a short-lived SSE ticket. Authenticated with the normal Bearer
    # header so the JWT never travels in a URL.
    @app.post("/api/stream/ticket", dependencies=[Depends(enforce_rate_limit)])
    async def stream_ticket(user: dict = Depends(_get_current_user)):
        now = time.time()
        _prune_sse_tickets(now)
        ticket = secrets.token_urlsafe(32)
        _SSE_TICKETS[ticket] = (user, now + _SSE_TICKET_TTL)
        return {"ticket": ticket, "expires_in": int(_SSE_TICKET_TTL)}

    def _get_stream_user(
        request: Request,
        ticket: Optional[str] = Query(None, max_length=128),
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    ) -> dict:
        """Auth for SSE — accepts a Bearer header (API clients) OR a ?ticket=.

        The long-lived JWT is deliberately NOT accepted as a query param.
        """
        if credentials is not None:
            return _decode_token(credentials.credentials)
        if ticket:
            entry = _SSE_TICKETS.pop(ticket, None)  # single-use
            if entry is not None and entry[1] >= time.time():
                return entry[0]
            raise HTTPException(
                status_code=401, detail="Invalid or expired stream ticket"
            )
        raise HTTPException(status_code=401, detail="Missing authorization")

    # SSE stream
    @app.get("/api/stream", dependencies=[Depends(enforce_rate_limit)])
    async def stream(request: Request, user: dict = Depends(_get_stream_user)):
        uid = user.get("sub")
        is_admin = user.get("role") == "admin"

        async def event_generator():
            yield {
                "event": "hello",
                "data": '{"type":"hello","version":"' + VERSION + '"}',
            }
            async for evt in BUS.subscribe():
                if await request.is_disconnected():
                    break
                # Object-level authorization: job-scoped events (scan logs,
                # progress, live device feed, completion) are only delivered to
                # the user who started that scan, or to an admin. Events with no
                # job_id (e.g. SIEM alerts) are network-wide and go to everyone.
                data = evt.data if isinstance(evt.data, dict) else {}
                job_id = data.get("job_id")
                if job_id and not is_admin:
                    owner = SERVICE.job_owner(job_id)
                    if owner != uid:
                        continue
                yield evt.to_sse()

        return EventSourceResponse(event_generator(), ping=15)

    # Static frontend — mounted LAST so the explicit /api/* routes above always
    # win. html=True serves index.html at "/" and resolves the site's relative
    # asset paths (css/, js/, pages/) against the frontend root.
    if _FRONTEND_DIR.exists():
        app.mount(
            "/",
            StaticFiles(directory=str(_FRONTEND_DIR), html=True),
            name="static",
        )
    else:

        @app.get("/", include_in_schema=False)
        async def index_missing():
            return JSONResponse(status_code=503, content={"error": "frontend missing"})

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError):
        # Treat malformed request bodies/params (incl. invalid CIDR rejected by
        # the ScanRequest validator) as a 400 Bad Request rather than 422.
        detail = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg", "")}
            for e in exc.errors()
        ]
        return JSONResponse(status_code=400, content={"error": "validation error", "detail": detail})

    @app.exception_handler(Exception)
    async def _all_errors(_request: Request, exc: Exception):
        _log.exception("unhandled error: %s", exc)
        return JSONResponse(status_code=500, content={"error": "internal server error"})

    return app


# ── Internal helpers ──────────────────────────────────────────────────────
def _scan_to_api(scan) -> dict:
    return {
        "scan_id": scan.scan_id,
        "network": scan.network,
        "timestamp": scan.timestamp.isoformat(),
        "duration_seconds": scan.duration_seconds,
        "total_hosts": scan.total_hosts,
        "devices": [_device_to_api(d, scan.alerts) for d in scan.devices],
        "alerts": [a.to_json() for a in scan.alerts],
    }


def _generate_pdf(scan) -> bytes:
    try:
        import html as _html
        import io

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        PAGE_W, _ = A4
        MARGIN = 1.8 * cm
        W = PAGE_W - 2 * MARGIN  # ~17.4 cm usable

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=MARGIN, bottomMargin=MARGIN,
        )
        styles = getSampleStyleSheet()

        def _p(name, **kw) -> ParagraphStyle:
            return ParagraphStyle(name, parent=styles["Normal"], **kw)

        def _e(v) -> str:
            return _html.escape(str(v) if v is not None else "")

        # ── Text styles ────────────────────────────────────────────────────
        cell  = _p("cell",  fontSize=7.5, leading=10)
        mono  = _p("mono",  fontName="Courier", fontSize=7, leading=9)
        bold  = _p("bold",  fontName="Helvetica-Bold", fontSize=7.5, leading=10)
        hdr   = _p("hdr",   fontName="Helvetica-Bold", fontSize=8,
                            textColor=colors.white, leading=11)
        label = _p("label", fontName="Helvetica-Bold", fontSize=7.5,
                            textColor=colors.HexColor("#6b7280"), leading=10)

        # ── Colours ────────────────────────────────────────────────────────
        DARK   = colors.HexColor("#0d1318")
        ACCENT = colors.HexColor("#00e5ff")
        ROW1   = colors.white
        ROW2   = colors.HexColor("#f3f4f6")
        BORDER = colors.HexColor("#d1d5db")
        MUTED  = colors.HexColor("#9ca3af")

        SEV_C = {
            "critical": colors.HexColor("#dc2626"),
            "high":     colors.HexColor("#ea580c"),
            "medium":   colors.HexColor("#d97706"),
            "low":      colors.HexColor("#2563eb"),
        }
        RISK_C = {
            "high":   colors.HexColor("#dc2626"),
            "medium": colors.HexColor("#d97706"),
            "low":    colors.HexColor("#16a34a"),
        }

        def _tbl_style(has_header: bool = True) -> TableStyle:
            cmds = [
                ("ROWBACKGROUNDS", (0, 1 if has_header else 0), (-1, -1), [ROW1, ROW2]),
                ("BOX",       (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
            if has_header:
                cmds.append(("BACKGROUND", (0, 0), (-1, 0), DARK))
            return TableStyle(cmds)

        ts = scan.timestamp
        ts_display = (
            ts.strftime("%Y-%m-%d  %H:%M:%S  UTC")
            if hasattr(ts, "strftime") else str(ts)
        )

        story = []

        # ── Cover ─────────────────────────────────────────────────────────
        story += [
            Paragraph("N9pinax",
                      _p("brand", fontSize=10, fontName="Helvetica-Bold",
                         textColor=ACCENT, spaceAfter=2)),
            Paragraph("Network Scan Report",
                      _p("title", fontSize=22, fontName="Helvetica-Bold",
                         textColor=DARK, spaceAfter=6)),
            HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=10),
        ]

        # Metadata 2-column table
        meta_pairs = [
            ("Scan ID",     scan.scan_id),
            ("Network",     scan.network or "auto-detect"),
            ("Timestamp",   ts_display),
            ("Duration",    f"{scan.duration_seconds:.1f} s"),
            ("Total Hosts", str(scan.total_hosts)),
            ("Alerts",      str(len(scan.alerts))),
        ]
        half = W / 2
        meta_rows = []
        for i in range(0, len(meta_pairs), 2):
            a_k, a_v = meta_pairs[i]
            b_k, b_v = meta_pairs[i + 1] if i + 1 < len(meta_pairs) else ("", "")
            meta_rows.append([
                Paragraph(_e(a_k), label), Paragraph(_e(a_v), mono),
                Paragraph(_e(b_k), label), Paragraph(_e(b_v), cell),
            ])
        meta_tbl = Table(
            meta_rows,
            colWidths=[2.5 * cm, half - 2.5 * cm, 2.5 * cm, half - 2.5 * cm],
        )
        meta_tbl.setStyle(_tbl_style(has_header=False))
        story += [meta_tbl, Spacer(1, 0.6 * cm)]

        # ── Device table ──────────────────────────────────────────────────
        # Columns:  IP | MAC | Vendor/Hostname | OS | Risk | Ports
        # Fixed widths: 2.8 + 3.5 + ? + 3.0 + 1.8 + 2.5 = W
        D_FIXED = 2.8 + 3.5 + 3.0 + 1.8 + 2.5  # cm
        D_COL = [
            2.8 * cm,
            3.5 * cm,
            (W - D_FIXED * cm),   # vendor stretches to fill
            3.0 * cm,
            1.8 * cm,
            2.5 * cm,
        ]

        if scan.devices:
            story.append(
                Paragraph("Discovered Devices",
                          _p("dh", fontSize=12, fontName="Helvetica-Bold",
                             spaceBefore=4, spaceAfter=6))
            )
            dev_rows = [[
                Paragraph("IP Address",         hdr),
                Paragraph("MAC Address",        hdr),
                Paragraph("Vendor / Hostname",  hdr),
                Paragraph("OS",                 hdr),
                Paragraph("Risk",               hdr),
                Paragraph("Ports",              hdr),
            ]]
            for d in scan.devices:
                risk    = d.risk_label(scan.alerts)
                rc      = RISK_C.get(risk.lower(), MUTED)
                ports   = ", ".join(str(p.number) for p in d.get_open_ports()) or "—"
                vendor  = _e(d.mac_vendor or "—")
                host    = _e(d.hostname or "")
                vc      = (f'{vendor}<br/>'
                           f'<font size="6.5" color="#6b7280">{host}</font>'
                           if host else vendor)
                os_txt  = "Unknown"
                if d.fingerprint:
                    os_txt = _e(d.fingerprint.os_family.value)
                    if d.fingerprint.os_version:
                        os_txt += f" {_e(d.fingerprint.os_version)}"
                dev_rows.append([
                    Paragraph(_e(d.ip  or "—"), mono),
                    Paragraph(_e(d.mac or "—"), mono),
                    Paragraph(vc,               cell),
                    Paragraph(os_txt,           cell),
                    Paragraph(risk.upper(),
                              _p(f"r{risk}", fontName="Helvetica-Bold",
                                 fontSize=7.5, textColor=rc, leading=10)),
                    Paragraph(ports, cell),
                ])

            dev_tbl = Table(dev_rows, colWidths=D_COL, repeatRows=1)
            dev_tbl.setStyle(_tbl_style())
            story += [dev_tbl, Spacer(1, 0.5 * cm)]

        # ── Alert table ───────────────────────────────────────────────────
        # Columns:  Severity | Title | Description | IP
        A_FIXED = 2.2 + 4.0 + 3.0  # cm
        A_COL = [
            2.2 * cm,
            4.0 * cm,
            (W - A_FIXED * cm),   # description stretches to fill
            3.0 * cm,
        ]

        if scan.alerts:
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_alerts = sorted(
                scan.alerts,
                key=lambda a: sev_order.get(
                    (a.severity.value if hasattr(a.severity, "value")
                     else str(a.severity)).lower(), 9,
                ),
            )
            story.append(
                Paragraph("Security Alerts",
                          _p("ah", fontSize=12, fontName="Helvetica-Bold",
                             spaceBefore=4, spaceAfter=6))
            )
            alert_rows = [[
                Paragraph("Severity",    hdr),
                Paragraph("Title",       hdr),
                Paragraph("Description", hdr),
                Paragraph("Device IP",   hdr),
            ]]
            for a in sorted_alerts:
                sev = (
                    a.severity.value if hasattr(a.severity, "value")
                    else str(a.severity)
                ).lower()
                sc  = SEV_C.get(sev, MUTED)
                ip  = _e(getattr(a, "ip", None) or "—")
                alert_rows.append([
                    Paragraph(sev.upper(),
                              _p(f"s{sev}", fontName="Helvetica-Bold",
                                 fontSize=7.5, textColor=sc, leading=10)),
                    Paragraph(_e(a.title or ""),       cell),
                    Paragraph(_e(a.description or ""), cell),
                    Paragraph(ip, mono),
                ])

            alert_tbl = Table(alert_rows, colWidths=A_COL, repeatRows=1)
            alert_tbl.setStyle(_tbl_style())
            story += [alert_tbl, Spacer(1, 0.4 * cm)]

        # ── Footer ────────────────────────────────────────────────────────
        story += [
            HRFlowable(width="100%", thickness=0.5, color=BORDER),
            Paragraph(
                f"Generated by N9pinax v{VERSION}  ·  {ts_display}",
                _p("foot", fontSize=7, textColor=MUTED),
            ),
        ]

        doc.build(story)
        return buf.getvalue()
    except ImportError:
        return _minimal_pdf(scan)


def _minimal_pdf(scan) -> bytes:
    lines = [
        "N9pinax Network Scan Report",
        f"Scan: {scan.scan_id}  Network: {scan.network}",
        f"Time: {scan.timestamp.isoformat()}  Hosts: {scan.total_hosts}",
        "",
        "Devices:",
    ]
    for d in scan.devices:
        ports = ", ".join(str(p.number) for p in d.get_open_ports()) or "none"
        lines.append(
            f"  {d.ip}  {d.mac}  {d.mac_vendor}  risk:{d.risk_label(scan.alerts)}  ports:{ports}"
        )
    if scan.alerts:
        lines += ["", "Alerts:"]
        for a in scan.alerts:
            sev = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
            lines.append(f"  [{sev.upper()}] {a.title}")
    return _text_lines_to_pdf(lines)


def _text_lines_to_pdf(lines: list[str]) -> bytes:
    """Render plain text lines into a minimal single-page PDF (no deps)."""
    stream_content = "BT\n/F1 10 Tf\n"
    y = 800
    for line in lines:
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")[:120]
        stream_content += f"30 {y} Td ({safe}) Tj T*\n"
        y -= 14
        if y < 40:
            break
    stream_content += "ET"
    sb = stream_content.encode("latin-1", errors="replace")
    objects = [
        b"1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n",
        b"2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n",
        b"3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>\nendobj\n",
        f"4 0 obj\n<</Length {len(sb)}>>\nstream\n".encode()
        + sb
        + b"\nendstream\nendobj\n",
        b"5 0 obj\n<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>\nendobj\n",
    ]
    pdf = b"%PDF-1.4\n"
    offsets = []
    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj
    xref_offset = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        pdf += f"{off:010d} 00000 n \n".encode()
    pdf += f"trailer\n<</Size {len(objects) + 1}/Root 1 0 R>>\nstartxref\n{xref_offset}\n%%EOF\n".encode()
    return pdf


def _generate_notes_pdf(notes: list[dict]) -> bytes:
    """Render one or more notes into a formatted PDF (reportlab, with fallback)."""
    try:
        import html as _html
        import io

        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
        )

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        story = [Paragraph("N9pinax — Notes", styles["Title"]), Spacer(1, 0.4 * cm)]

        if not notes:
            story.append(Paragraph("No notes.", styles["Normal"]))

        for i, n in enumerate(notes):
            if i:
                story += [
                    Spacer(1, 0.3 * cm),
                    HRFlowable(width="100%"),
                    Spacer(1, 0.3 * cm),
                ]
            story.append(
                Paragraph(_html.escape(n.get("title") or "Untitled"), styles["Heading2"])
            )
            meta = [f"Author: {_html.escape(str(n.get('author') or 'unknown'))}"]
            if n.get("scan_id"):
                meta.append(f"Scan: {_html.escape(str(n['scan_id']))}")
            if n.get("device_ip"):
                meta.append(f"Device: {_html.escape(str(n['device_ip']))}")
            if n.get("tags"):
                meta.append("Tags: " + _html.escape(", ".join(n["tags"])))
            if n.get("updated_at"):
                meta.append(f"Updated: {_html.escape(str(n['updated_at']))}")
            story.append(Paragraph("  |  ".join(meta), styles["Italic"]))
            story.append(Spacer(1, 0.2 * cm))
            body = _html.escape(n.get("content") or "").replace("\n", "<br/>")
            story.append(Paragraph(body or "<i>(empty)</i>", styles["Normal"]))

        doc.build(story)
        return buf.getvalue()
    except ImportError:
        return _minimal_notes_pdf(notes)


def _minimal_notes_pdf(notes: list[dict]) -> bytes:
    lines = ["N9pinax — Notes", ""]
    if not notes:
        lines.append("No notes.")
    for n in notes:
        lines.append(f"# {n.get('title') or 'Untitled'}")
        meta = f"  author:{n.get('author') or 'unknown'}"
        if n.get("scan_id"):
            meta += f"  scan:{n['scan_id'][:8]}"
        if n.get("tags"):
            meta += f"  tags:{','.join(n['tags'])}"
        lines.append(meta)
        for content_line in (n.get("content") or "").splitlines() or ["(empty)"]:
            lines.append(f"  {content_line}")
        lines.append("")
    return _text_lines_to_pdf(lines)


app = create_app()
