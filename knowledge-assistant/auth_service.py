import re
import sqlite3
from typing import Optional

from audit import log_event
from security import check_password_policy, hash_password

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")


class RegistrationError(Exception):
    def __init__(self, problems: list):
        super().__init__("; ".join(problems))
        self.problems = problems


def register_user(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    ip: Optional[str] = None,
) -> int:
    """Create a normal user. The role is always 'user', never taken from input."""
    username = username.strip().lower()

    problems = []
    if not USERNAME_RE.match(username):
        problems.append("Username must be 3-32 characters: letters, digits, dot, dash, underscore.")
    problems += check_password_policy(password, username)

    if problems:
        log_event(conn, "register_rejected", ip=ip, detail="policy")
        conn.commit()
        raise RegistrationError(problems)

    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
            (username, hash_password(password)),
        )
    except sqlite3.IntegrityError:
        log_event(conn, "register_rejected", ip=ip, detail="username_taken")
        conn.commit()
        raise RegistrationError(["That username is not available."])

    user_id = cur.lastrowid
    log_event(conn, "register_success", user_id=user_id, ip=ip)
    conn.commit()
    return user_id
