import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Optional

from audit import log_event
from security import hash_password, is_blocklisted, verify_password
from sessions import create_session, fmt, revoke_session, utc_now

WINDOW = timedelta(minutes=15)
MAX_FAILURES_PER_USERNAME = 5
MAX_FAILURES_PER_IP = 20

GENERIC_ERROR = "Invalid username or password."
THROTTLE_ERROR = "Too many failed attempts. Please try again later."


class LoginError(Exception):
    def __init__(self, message: str, throttled: bool = False):
        super().__init__(message)
        self.message = message
        self.throttled = throttled


@dataclass
class LoginResult:
    token: str
    user_id: int
    username: str
    role: str
    must_change_password: bool


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    # Used when the username does not exist, so the response time looks the same.
    return hash_password("dummy password used only for timing")


def _record_attempt(conn, username: str, ip: str, success: bool, now: datetime) -> None:
    conn.execute(
        "INSERT INTO login_attempts (username, ip, success, created_at) VALUES (?, ?, ?, ?)",
        (username, ip, int(success), fmt(now)),
    )


def _username_failures(conn, username: str, since: str) -> int:
    # Failures since the window start AND since the last successful login.
    return conn.execute(
        """
        SELECT COUNT(*) FROM login_attempts
        WHERE username = ? AND success = 0 AND created_at >= ?
          AND id > COALESCE(
              (SELECT MAX(id) FROM login_attempts WHERE username = ? AND success = 1), 0)
        """,
        (username, since, username),
    ).fetchone()[0]


def _ip_failures(conn, ip: str, since: str) -> int:
    # No reset on success: an attacker must not reset the counter with their own account.
    return conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND success = 0 AND created_at >= ?",
        (ip, since),
    ).fetchone()[0]


def is_throttled(conn, username: str, ip: str, now: Optional[datetime] = None) -> bool:
    now = now or utc_now()
    since = fmt(now - WINDOW)
    return (
        _username_failures(conn, username, since) >= MAX_FAILURES_PER_USERNAME
        or _ip_failures(conn, ip, since) >= MAX_FAILURES_PER_IP
    )


def login_user(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    ip: str = "unknown",
    now: Optional[datetime] = None,
) -> LoginResult:
    now = now or utc_now()
    name = username.strip().lower()[:64]

    # 1. Throttle check first: even a correct password is refused while blocked.
    if is_throttled(conn, name, ip, now):
        log_event(conn, "login_throttled", ip=ip, detail=f"username={name}")
        conn.commit()
        raise LoginError(THROTTLE_ERROR, throttled=True)

    # 2. Always run one argon2 verification, even for unknown users.
    user = conn.execute("SELECT * FROM users WHERE username = ?", (name,)).fetchone()
    stored_hash = user["password_hash"] if user else _dummy_hash()
    valid, needs_rehash = verify_password(stored_hash, password)
    if user is None:
        valid = False

    # 3. Failure: same message for wrong password and unknown user.
    if not valid:
        _record_attempt(conn, name, ip, False, now)
        reason = "unknown_user" if user is None else "bad_password"
        log_event(
            conn, "login_failed",
            user_id=user["id"] if user else None, ip=ip, detail=f"username={name} reason={reason}",
        )
        conn.commit()
        raise LoginError(GENERIC_ERROR)

    # 4. Success.
    _record_attempt(conn, name, ip, True, now)

    if needs_rehash:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user["id"])
        )

    # Forced change only on evidence of compromise (blocklist match), never on age.
    must_change = bool(user["must_change_password"])
    if is_blocklisted(password) and not must_change:
        conn.execute("UPDATE users SET must_change_password = 1 WHERE id = ?", (user["id"],))
        log_event(conn, "password_flagged", user_id=user["id"], ip=ip, detail="blocklist_match")
        must_change = True

    # A brand new token for every login (no session fixation).
    token = create_session(conn, user["id"], now)
    log_event(conn, "login_success", user_id=user["id"], ip=ip)
    conn.commit()

    return LoginResult(
        token=token,
        user_id=user["id"],
        username=user["username"],
        role=user["role"],
        must_change_password=must_change,
    )


def logout_user(
    conn: sqlite3.Connection,
    token: Optional[str],
    ip: str = "unknown",
    now: Optional[datetime] = None,
) -> bool:
    """Revoke the session on the server. Returns True if a live session was revoked."""
    user_id = revoke_session(conn, token, now)
    if user_id is None:
        return False
    log_event(conn, "logout", user_id=user_id, ip=ip)
    conn.commit()
    return True


def record_failed_attempt(
    conn: sqlite3.Connection, username: str, ip: str, now: Optional[datetime] = None
) -> None:
    """Count a failed password check that did not come from the login form."""
    _record_attempt(conn, username, ip, False, now or utc_now())
