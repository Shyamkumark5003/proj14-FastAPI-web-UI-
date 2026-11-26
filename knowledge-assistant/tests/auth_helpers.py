from fastapi.testclient import TestClient

import db
from auth_service import register_user

GOOD = "correct horse battery staple"


def setup_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    db.init_db()


def create_user(username, role="user", password=GOOD):
    conn = db.get_conn()
    user_id = register_user(conn, username, password)
    if role != "user":
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
    conn.close()
    return user_id


def new_client():
    from app import app
    return TestClient(app)


def logged_in_client(username, password=GOOD):
    client = new_client()
    client.get("/login")
    resp = client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": client.cookies.get("csrf_token"),
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    return client


def csrf(client):
    return {"X-CSRF-Token": client.cookies.get("csrf_token", "")}


def audit_events():
    conn = db.get_conn()
    rows = conn.execute("SELECT event, detail FROM audit_events ORDER BY id").fetchall()
    conn.close()
    return [(r["event"], r["detail"]) for r in rows]
