import pytest

import db
from security import hash_password
from tests.auth_helpers import GOOD, audit_events, create_user, logged_in_client, new_client, setup_db

NEW = "a brand new long passphrase"
WRONG = "this is definitely wrong"


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)


def _change(client, current, new, confirm=None):
    client.get("/change-password")
    return client.post(
        "/change-password",
        data={
            "current_password": current,
            "new_password": new,
            "confirm_password": new if confirm is None else confirm,
            "csrf_token": client.cookies.get("csrf_token"),
        },
        follow_redirects=False,
    )


def _login_status(username, password):
    client = new_client()
    client.get("/login")
    return client.post(
        "/login",
        data={"username": username, "password": password,
              "csrf_token": client.cookies.get("csrf_token")},
        follow_redirects=False,
    ).status_code


def _hash(username):
    conn = db.get_conn()
    try:
        return conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()[0]
    finally:
        conn.close()


def _add_weak_user():
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        ("weak", hash_password("passwordpassword")),
    )
    conn.commit()
    conn.close()


def test_change_page_requires_login():
    resp = new_client().get("/change-password", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_anonymous_post_is_redirected_to_login():
    client = new_client()
    client.get("/login")
    resp = client.post(
        "/change-password",
        data={"current_password": GOOD, "new_password": NEW, "confirm_password": NEW,
              "csrf_token": client.cookies.get("csrf_token")},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_change_without_csrf_is_rejected():
    create_user("alice")
    client = logged_in_client("alice")
    resp = client.post(
        "/change-password",
        data={"current_password": GOOD, "new_password": NEW, "confirm_password": NEW},
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert _login_status("alice", GOOD) == 303


def test_success_changes_password_and_revokes_old_sessions():
    create_user("alice")
    client = logged_in_client("alice")
    old_cookie = client.cookies.get("session")

    resp = _change(client, GOOD, NEW)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/me"

    # This device got a fresh session and keeps working.
    assert client.cookies.get("session") != old_cookie
    assert client.get("/me").status_code == 200

    # The old cookie value is dead.
    replay = new_client().get("/me", headers={"Cookie": f"session={old_cookie}"}, follow_redirects=False)
    assert replay.status_code == 303
    assert replay.headers["location"] == "/login"

    # Old password is dead, new one works.
    assert _login_status("alice", GOOD) == 401
    assert _login_status("alice", NEW) == 303
    assert "password_changed" in [e for e, _ in audit_events()]


def test_wrong_current_password_rejected_and_hash_unchanged():
    create_user("alice")
    client = logged_in_client("alice")
    before = _hash("alice")
    resp = _change(client, WRONG, NEW)
    assert resp.status_code == 400
    assert "current password is incorrect" in resp.text.lower()
    assert _hash("alice") == before
    assert "password_change_failed" in [e for e, _ in audit_events()]


def test_weak_new_password_rejected_and_not_echoed():
    create_user("alice")
    client = logged_in_client("alice")
    before = _hash("alice")
    resp = _change(client, GOOD, "tooshort")
    assert resp.status_code == 400
    assert "at least 15 characters" in resp.text.lower()
    assert "tooshort" not in resp.text
    assert _hash("alice") == before


def test_blocklisted_new_password_rejected():
    create_user("alice")
    client = logged_in_client("alice")
    assert _change(client, GOOD, "passwordpassword").status_code == 400


def test_mismatched_confirmation_rejected():
    create_user("alice")
    client = logged_in_client("alice")
    before = _hash("alice")
    resp = _change(client, GOOD, NEW, confirm="something else entirely")
    assert resp.status_code == 400
    assert _hash("alice") == before


def test_new_password_must_differ_from_current():
    create_user("alice")
    client = logged_in_client("alice")
    assert _change(client, GOOD, GOOD).status_code == 400


def test_guessing_current_password_is_throttled():
    create_user("alice")
    client = logged_in_client("alice")
    for _ in range(5):
        assert _change(client, WRONG, NEW).status_code == 400
    resp = _change(client, GOOD, NEW)
    assert resp.status_code == 429
    assert resp.headers["retry-after"] == "900"
    # The real password was not changed by the blocked attempt.
    assert _hash("alice") != hash_password(NEW)


def test_forced_change_blocks_api_until_password_is_changed():
    _add_weak_user()
    client = logged_in_client("weak", "passwordpassword")

    blocked = client.get("/records")
    assert blocked.status_code == 403
    assert "Password change required" in blocked.text

    # The pages needed to fix it still work.
    assert client.get("/me").status_code == 200
    assert client.get("/change-password").status_code == 200

    assert _change(client, "passwordpassword", NEW).status_code == 303
    assert client.get("/records").status_code == 200


def test_forced_change_redirects_home_page_and_blocks_ask():
    _add_weak_user()
    client = logged_in_client("weak", "passwordpassword")

    home = client.get("/", follow_redirects=False)
    assert home.status_code == 303
    assert home.headers["location"] == "/change-password"

    asked = client.post("/ask", data={"question": "password", "csrf_token": client.cookies.get("csrf_token", "")})
    assert asked.status_code == 403


def test_passwords_never_reach_audit_or_attempt_logs():
    create_user("alice")
    client = logged_in_client("alice")
    _change(client, WRONG, NEW)
    _change(client, GOOD, NEW)

    conn = db.get_conn()
    text = " ".join(f"{e} {d}" for e, d in audit_events())
    text += " ".join(
        str(v) for r in conn.execute("SELECT * FROM login_attempts") for v in tuple(r)
    )
    conn.close()
    for secret in (GOOD, NEW, WRONG):
        assert secret not in text
