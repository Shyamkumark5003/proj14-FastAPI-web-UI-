import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

SESSION_TTL = timedelta(hours=8)
_TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def fmt(ts: datetime) -> str:
    """Format a time the same way SQLite CURRENT_TIMESTAMP does (UTC)."""
    return ts.astimezone(timezone.utc).strftime(_TS_FORMAT)


def hash_token(token: str) -> str:
    # The token is 256-bit random, so a fast hash is enough here.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(conn: sqlite3.Connection, user_id: int, now: Optional[datetime] = None) -> str:
    """Create a session and return the raw token. Only its hash is stored."""
    now = now or utc_now()
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (hash_token(token), user_id, fmt(now), fmt(now + SESSION_TTL)),
    )
    return token


def get_session_user(conn: sqlite3.Connection, token: Optional[str], now: Optional[datetime] = None):
    """Return the user row for a live session, or None."""
    if not token:
        return None
    now = now or utc_now()
    return conn.execute(
        """
        SELECT u.id, u.username, u.role, u.must_change_password, s.id AS session_id
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ?
        """,
        (hash_token(token), fmt(now)),
    ).fetchone()


def revoke_session(conn: sqlite3.Connection, token: Optional[str], now: Optional[datetime] = None) -> Optional[int]:
    """Revoke a live session on the server. Return its user id, or None if nothing was revoked."""
    if not token:
        return None
    now = now or utc_now()
    row = conn.execute(
        "SELECT id, user_id FROM sessions WHERE token_hash = ? AND revoked_at IS NULL",
        (hash_token(token),),
    ).fetchone()
    if row is None:
        return None
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (fmt(now), row["id"]))
    return row["user_id"]
