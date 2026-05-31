# tests/conftest.py
# Shared fixtures for the API/backend tests. Configures a throwaway SQLite DB
# and a high rate limit BEFORE importing the app, and mocks SERVICE.submit so
# tests never trigger a real network scan.

import os
import tempfile

# These MUST be set before backend.app (→ scanner.config) is imported, because
# the config singleton snapshots env at import time.
os.environ["SCANNER_DB_PATH"] = tempfile.mktemp(suffix="_test.db")
os.environ["SCANNER_API_RATE_PER_MIN"] = "100000"  # avoid 429s during tests
os.environ.setdefault(
    "SCANNER_JWT_SECRET", "test-secret-key-that-is-long-enough-0123456789"
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.app import create_app  # noqa: E402
from backend.scan_service import SERVICE, ScanJob  # noqa: E402


@pytest.fixture(scope="session")
def app():
    return create_app()


@pytest.fixture()
def client(app, monkeypatch):
    """TestClient with SERVICE.submit mocked (no real scans, no threads)."""
    def fake_submit(network=None, **kwargs):
        return ScanJob(
            job_id="deadbeefdeadbeefdeadbeefdeadbeef",
            network=network or "auto",
            status="pending",
        )

    monkeypatch.setattr(SERVICE, "submit", fake_submit)
    return TestClient(app)


@pytest.fixture()
def admin_token(client):
    resp = client.post("/api/auth/login", json={"email": "na9a", "password": "1234"})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


@pytest.fixture()
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
