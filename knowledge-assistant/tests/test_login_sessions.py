from datetime import timedelta

import pytest

import db
from auth_service import register_user
from login_service import LoginError, login_user, logout_user
from security import hash_password
from sessions import get_session_user, utc_now

GOOD = "correct horse battery staple"
WRONG = "this is definitely wrong"


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    connection = db.get_conn()
    register_user(connection, "alice", GOOD)
    yield connection
    connection.close()


def _events(conn):
    return [r["event"] for r in conn.execute("SELECT event FROM audit_events")]


def _fail(conn, username="alice", ip="10.0.0.1", now=None):
    with pytest.raises(LoginError):
        login_user(conn, username, WRONG, ip=ip, now=now)


# ---- login ----

def test_login_success_creates_session_and_audit(conn):
    result = login_user(conn, "alice", GOOD, ip="10.0.0.1")
    assert result.role == "user"
    row = conn.execute("SELECT token_hash FROM sessions").fetchone()
    assert len(row["token_hash"]) == 64
    assert result.token != row["token_hash"]
    assert result.token not in row["token_hash"]
    assert "login_success" in _events(conn)


def test_login_username_is_case_insensitive(conn):
    assert login_user(conn, "  ALICE ", GOOD).username == "alice"


def test_wrong_password_generic_error_and_audit(conn):
    with pytest.raises(LoginError) as exc:
        login_user(conn, "alice", WRONG)
    assert exc.value.message == "Invalid username or password."
    assert exc.value.throttled is False
    assert "login_failed" in _events(conn)


def test_unknown_user_gets_same_error_as_wrong_password(conn):
    with pytest.raises(LoginError) as wrong_pw:
        login_user(conn, "alice", WRONG)
    with pytest.raises(LoginError) as no_user:
        login_user(conn, "nobody", WRONG)
    assert wrong_pw.value.message == no_user.value.message


# ---- sessions ----

def test_session_lookup_valid_invalid_empty(conn):
    result = login_user(conn, "alice", GOOD)
    assert get_session_user(conn, result.token)["username"] == "alice"
    assert get_session_user(conn, "not-a-real-token") is None
    assert get_session_user(conn, "") is None
    assert get_session_user(conn, None) is None


def test_expired_session_is_rejected(conn):
    nine_hours_ago = utc_now() - timedelta(hours=9)
    result = login_user(conn, "alice", GOOD, now=nine_hours_ago)
    assert get_session_user(conn, result.token) is None


def test_each_login_issues_new_token(conn):
    first = login_user(conn, "alice", GOOD)
    second = login_user(conn, "alice", GOOD)
    assert first.token != second.token


# ---- logout ----

def test_logout_invalidates_session_on_server(conn):
    result = login_user(conn, "alice", GOOD)
    assert get_session_user(conn, result.token) is not None
    assert logout_user(conn, result.token) is True
    # The old cookie value is now useless.
    assert get_session_user(conn, result.token) is None
    revoked = conn.execute("SELECT revoked_at FROM sessions").fetchone()["revoked_at"]
    assert revoked is not None
    assert "logout" in _events(conn)


def test_logout_twice_and_unknown_token_are_harmless(conn):
    result = login_user(conn, "alice", GOOD)
    assert logout_user(conn, result.token) is True
    assert logout_user(conn, result.token) is False
    assert logout_user(conn, "garbage") is False
    assert logout_user(conn, None) is False


# ---- throttling ----

def test_lockout_after_5_failures_even_with_correct_password(conn):
    for _ in range(5):
        _fail(conn)
    with pytest.raises(LoginError) as exc:
        login_user(conn, "alice", GOOD, ip="10.0.0.1")
    assert exc.value.throttled is True
    assert "login_throttled" in _events(conn)


def test_lockout_ends_after_window(conn):
    t0 = utc_now()
    for _ in range(5):
        _fail(conn, now=t0)
    result = login_user(conn, "alice", GOOD, ip="10.0.0.1", now=t0 + timedelta(minutes=16))
    assert result.username == "alice"


def test_success_resets_username_failures(conn):
    for _ in range(4):
        _fail(conn)
    login_user(conn, "alice", GOOD, ip="10.0.0.1")
    for _ in range(4):
        _fail(conn)
    # 4 + 4 failures in total, but never 5 in a row since the last success.
    assert login_user(conn, "alice", GOOD, ip="10.0.0.1").username == "alice"


def test_ip_throttle_across_usernames(conn):
    for i in range(20):
        _fail(conn, username=f"ghost{i}", ip="10.0.0.9")
    with pytest.raises(LoginError) as exc:
        login_user(conn, "alice", GOOD, ip="10.0.0.9")
    assert exc.value.throttled is True
    # The same account from another IP is fine.
    assert login_user(conn, "alice", GOOD, ip="10.0.0.10").username == "alice"


# ---- forced change only on evidence of compromise ----

def test_blocklisted_password_flags_forced_change(conn):
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        ("weak", hash_password("passwordpassword")),
    )
    conn.commit()
    result = login_user(conn, "weak", "passwordpassword")
    assert result.must_change_password is True
    flag = conn.execute("SELECT must_change_password FROM users WHERE username = 'weak'").fetchone()[0]
    assert flag == 1
    assert "password_flagged" in _events(conn)


def test_no_forced_rotation_for_old_strong_password(conn):
    in_400_days = utc_now() + timedelta(days=400)
    result = login_user(conn, "alice", GOOD, now=in_400_days)
    assert result.must_change_password is False


# ---- secrets never logged ----

def test_secrets_not_in_audit_or_attempts(conn):
    login_user(conn, "alice", GOOD)
    _fail(conn)
    text = " ".join(
        str(v) for r in conn.execute("SELECT * FROM audit_events") for v in tuple(r)
    ) + " ".join(
        str(v) for r in conn.execute("SELECT * FROM login_attempts") for v in tuple(r)
    )
    assert GOOD not in text
    assert WRONG not in text
