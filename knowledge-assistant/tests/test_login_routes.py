import re

import pytest
from fastapi.testclient import TestClient

import db
from auth_service import register_user

GOOD = "correct horse battery staple"
WRONG = "this is definitely wrong"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    db.init_db()
    conn = db.get_conn()
    register_user(conn, "alice", GOOD)
    conn.close()
    from app import app
    return TestClient(app)


def _csrf(client):
    client.get("/login")
    return client.cookies.get("csrf_token")


def _login(client, password=GOOD, username="alice"):
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": _csrf(client)},
        follow_redirects=False,
    )


def _cookie_header(resp, name):
    for header in resp.headers.get_list("set-cookie"):
        if header.startswith(name + "="):
            return header
    return None


def test_login_page_has_csrf_token(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert f'value="{client.cookies.get("csrf_token")}"' in resp.text


def test_login_without_csrf_is_rejected(client):
    client.get("/login")
    resp = client.post(
        "/login", data={"username": "alice", "password": GOOD}, follow_redirects=False
    )
    assert resp.status_code == 403


def test_login_sets_session_cookie_with_flags(client):
    resp = _login(client)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/me"
    header = _cookie_header(resp, "session").lower()
    assert "httponly" in header
    assert "samesite=lax" in header
    assert "path=/" in header
    assert "max-age=28800" in header
    assert "domain" not in header


def test_secure_mode_uses_host_prefix_and_secure_flag(client, monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "1")
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    resp = client.post(
        "/login",
        data={"username": "alice", "password": GOOD, "csrf_token": token},
        headers={"Cookie": f"csrf_token={token}"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    header = _cookie_header(resp, "__Host-session").lower()
    assert "secure" in header
    assert "httponly" in header
    assert "samesite=lax" in header
    assert "path=/" in header
    assert "domain" not in header


def test_wrong_password_401_generic_no_cookie_no_echo(client):
    resp = _login(client, WRONG)
    assert resp.status_code == 401
    assert "Invalid username or password." in resp.text
    assert WRONG not in resp.text
    assert _cookie_header(resp, "session") is None


def test_throttle_after_5_failures_returns_429(client):
    for _ in range(5):
        assert _login(client, WRONG).status_code == 401
    resp = _login(client, GOOD)
    assert resp.status_code == 429
    assert resp.headers["retry-after"] == "900"
    assert _cookie_header(resp, "session") is None


def test_me_requires_login(client):
    resp = client.get("/me", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_me_after_login_shows_user(client):
    _login(client)
    resp = client.get("/me")
    assert resp.status_code == 200
    assert "alice" in resp.text


def test_login_rotates_csrf_token(client):
    before = _csrf(client)
    _login(client)
    assert client.cookies.get("csrf_token") != before


def test_logout_revokes_session_on_server(client):
    _login(client)
    old_cookie = client.cookies.get("session")
    assert old_cookie
    resp = client.post(
        "/logout", data={"csrf_token": client.cookies.get("csrf_token")}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    # Replay the old cookie value: it must be useless now.
    replay = client.get(
        "/me", headers={"Cookie": f"session={old_cookie}"}, follow_redirects=False
    )
    assert replay.status_code == 303
    assert replay.headers["location"] == "/login"

    conn = db.get_conn()
    revoked = conn.execute("SELECT revoked_at FROM sessions").fetchone()[0]
    conn.close()
    assert revoked is not None


def test_logout_without_csrf_is_rejected_and_session_survives(client):
    _login(client)
    resp = client.post("/logout", data={}, follow_redirects=False)
    assert resp.status_code == 403
    assert client.get("/me").status_code == 200
