import pytest
from fastapi.testclient import TestClient

import db

GOOD = "correct horse battery staple"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    from app import app
    return TestClient(app)


def _token(client):
    client.get("/register")
    return client.cookies.get("csrf_token")


def _user_count():
    conn = db.get_conn()
    try:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    finally:
        conn.close()


def test_register_page_loads_with_csrf_cookie_and_token(client):
    resp = client.get("/register")
    assert resp.status_code == 200
    token = client.cookies.get("csrf_token")
    assert token
    assert f'value="{token}"' in resp.text


def test_post_without_csrf_token_is_rejected(client):
    client.get("/register")
    resp = client.post("/register", data={"username": "alice", "password": GOOD})
    assert resp.status_code == 403
    assert _user_count() == 0


def test_register_success(client):
    resp = client.post(
        "/register",
        data={"username": "alice", "password": GOOD, "csrf_token": _token(client)},
    )
    assert resp.status_code == 201
    conn = db.get_conn()
    row = conn.execute("SELECT * FROM users WHERE username = 'alice'").fetchone()
    conn.close()
    assert row["role"] == "user"
    assert row["password_hash"].startswith("$argon2id$")


def test_weak_password_rejected_and_not_echoed(client):
    resp = client.post(
        "/register",
        data={"username": "alice", "password": "tooshort", "csrf_token": _token(client)},
    )
    assert resp.status_code == 400
    assert "at least 15 characters" in resp.text.lower()
    assert "tooshort" not in resp.text
    assert _user_count() == 0


def test_role_field_in_form_is_ignored(client):
    client.post(
        "/register",
        data={
            "username": "mallory", "password": GOOD,
            "role": "admin", "csrf_token": _token(client),
        },
    )
    conn = db.get_conn()
    row = conn.execute("SELECT role FROM users WHERE username = 'mallory'").fetchone()
    conn.close()
    assert row["role"] == "user"


def test_username_is_escaped_in_error_page(client):
    payload = "<script>alert(1)</script>"
    resp = client.post(
        "/register",
        data={"username": payload, "password": GOOD, "csrf_token": _token(client)},
    )
    assert resp.status_code == 400
    assert payload not in resp.text
    assert "&lt;script&gt;" in resp.text
