import pytest

import db
from login_service import LoginError, login_user
from tests.auth_helpers import audit_events, create_user, setup_db


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)


def _logged_text():
    conn = db.get_conn()
    text = " ".join(f"{event} {detail}" for event, detail in audit_events())
    text += " ".join(
        str(value) for row in conn.execute("SELECT * FROM login_attempts") for value in tuple(row)
    )
    conn.close()
    return text


def test_password_typed_into_username_box_is_never_stored():
    create_user("alice")
    typed = "my secret passphrase typed by mistake"
    conn = db.get_conn()
    with pytest.raises(LoginError):
        login_user(conn, typed, "whatever", ip="10.0.0.1")
    conn.close()

    text = _logged_text()
    assert typed not in text
    assert "secret passphrase" not in text
    assert "unknown:" in text


def test_unknown_username_is_throttled_like_a_real_one():
    conn = db.get_conn()
    for _ in range(5):
        with pytest.raises(LoginError):
            login_user(conn, "ghost", "x", ip="10.0.0.2")
    with pytest.raises(LoginError) as exc:
        login_user(conn, "ghost", "x", ip="10.0.0.2")
    conn.close()
    assert exc.value.throttled is True


def test_real_username_is_still_logged_for_failed_login():
    create_user("alice")
    conn = db.get_conn()
    with pytest.raises(LoginError):
        login_user(conn, "alice", "wrong wrong wrong", ip="10.0.0.3")
    conn.close()
    assert ("login_failed", "username=alice reason=bad_password") in audit_events()
