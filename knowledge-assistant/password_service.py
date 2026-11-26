import sqlite3
from datetime import datetime
from typing import Optional

from audit import log_event
from login_service import is_throttled, record_failed_attempt
from security import check_password_policy, hash_password, normalize, verify_password
from sessions import create_session, fmt, utc_now


class PasswordChangeError(Exception):
    def __init__(self, problems: list, throttled: bool = False):
        super().__init__("; ".join(problems))
        self.problems = problems
        self.throttled = throttled


def change_password(
    conn: sqlite3.Connection,
    user_id: int,
    current_password: str,
    new_password: str,
    ip: str = "unknown",
    now: Optional[datetime] = None,
) -> str:
    """Change the password, revoke every session, and return a new session token."""
    now = now or utc_now()
    user = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        raise PasswordChangeError(["Account not found."])
    name = user["username"]

    # A stolen session must not allow unlimited guessing of the current password.
    if is_throttled(conn, name, ip, now):
        log_event(conn, "password_change_throttled", user_id=user_id, ip=ip)
        conn.commit()
        raise PasswordChangeError(["Too many failed attempts. Please try again later."], throttled=True)

    valid, _ = verify_password(user["password_hash"], current_password)
    if not valid:
        record_failed_attempt(conn, name, ip, now)
        log_event(conn, "password_change_failed", user_id=user_id, ip=ip, detail="bad_current_password")
        conn.commit()
        raise PasswordChangeError(["The current password is incorrect."])

    problems = check_password_policy(new_password, name)
    if normalize(new_password) == normalize(current_password):
        problems.append("The new password must differ from the current one.")
    if problems:
        log_event(conn, "password_change_rejected", user_id=user_id, ip=ip, detail="policy")
        conn.commit()
        raise PasswordChangeError(problems)

    conn.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
        (hash_password(new_password), user_id),
    )
    conn.execute(
        "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        (fmt(now), user_id),
    )
    token = create_session(conn, user_id, now)
    log_event(conn, "password_changed", user_id=user_id, ip=ip)
    conn.commit()
    return token
