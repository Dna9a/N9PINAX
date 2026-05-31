# tests/test_api.py
# Backend API tests using fastapi.testclient.TestClient. SERVICE.submit is
# mocked (see conftest) so no real network scan ever runs.

import warnings

warnings.filterwarnings("ignore")


# ── Auth ────────────────────────────────────────────────────────────────────
def test_login_valid_returns_token(client):
    r = client.post("/api/auth/login", json={"email": "na9a", "password": "1234"})
    assert r.status_code == 200
    body = r.json()
    assert body["token"] and body["role"] == "admin" and body["email"] == "na9a"


def test_login_wrong_password_401(client):
    r = client.post("/api/auth/login", json={"email": "na9a", "password": "nope"})
    assert r.status_code == 401


def test_login_unknown_user_401(client):
    r = client.post("/api/auth/login", json={"email": "ghost", "password": "x"})
    assert r.status_code == 401


# ── Health ──────────────────────────────────────────────────────────────────
def test_health_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── Auth enforcement ─────────────────────────────────────────────────────────
def test_scans_requires_auth(client):
    assert client.get("/api/scans").status_code == 401


def test_scans_with_auth_ok(client, auth_headers):
    r = client.get("/api/scans", headers=auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ── Scan submission (mocked) ─────────────────────────────────────────────────
def test_scan_valid_cidr_accepted(client, auth_headers):
    r = client.post("/api/scan", headers=auth_headers, json={"network": "10.0.0.0/24"})
    assert r.status_code == 200
    assert r.json()["status"] == "pending"


def test_scan_omitted_network_accepted(client, auth_headers):
    r = client.post("/api/scan", headers=auth_headers, json={})
    assert r.status_code == 200


def test_scan_invalid_cidr_400(client, auth_headers):
    r = client.post("/api/scan", headers=auth_headers, json={"network": "not-a-cidr"})
    assert r.status_code == 400


# ── Alerts ───────────────────────────────────────────────────────────────────
def test_alerts_bad_severity_400(client, auth_headers):
    r = client.get("/api/alerts?severity=bogus", headers=auth_headers)
    assert r.status_code == 400


def test_alerts_valid_severity_ok(client, auth_headers):
    r = client.get("/api/alerts?severity=high", headers=auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ── Admin RBAC ───────────────────────────────────────────────────────────────
def test_admin_create_user_non_admin_403(client, auth_headers):
    # Create an analyst, log in as them, then attempt an admin-only action.
    import uuid

    email = f"analyst_{uuid.uuid4().hex[:8]}@x.com"
    r = client.post(
        "/api/admin/users",
        headers=auth_headers,
        json={"email": email, "password": "secret1", "role": "analyst"},
    )
    assert r.status_code == 200, r.text

    tok = client.post(
        "/api/auth/login", json={"email": email, "password": "secret1"}
    ).json()["token"]
    analyst_headers = {"Authorization": f"Bearer {tok}"}

    r2 = client.post(
        "/api/admin/users",
        headers=analyst_headers,
        json={"email": "x@y.com", "password": "secret1", "role": "analyst"},
    )
    assert r2.status_code == 403


def test_admin_list_users_requires_admin(client, auth_headers):
    r = client.get("/api/admin/users", headers=auth_headers)
    assert r.status_code == 200
    assert any(u["email"] == "na9a" for u in r.json())


# ── Notes round-trip ─────────────────────────────────────────────────────────
def test_notes_crud(client, auth_headers):
    created = client.post(
        "/api/notes", headers=auth_headers, json={"title": "T", "content": "body"}
    ).json()
    nid = created["note_id"]
    assert client.get(f"/api/notes/{nid}", headers=auth_headers).json()["title"] == "T"
    patched = client.patch(
        f"/api/notes/{nid}", headers=auth_headers, json={"content": "new"}
    ).json()
    assert patched["content"] == "new"
    pdf = client.get(f"/api/notes/{nid}/pdf", headers=auth_headers)
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    assert client.delete(f"/api/notes/{nid}", headers=auth_headers).status_code == 200
