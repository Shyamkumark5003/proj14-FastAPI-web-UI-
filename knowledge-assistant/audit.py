import sqlite3
from typing import Optional


def log_event(
    conn: sqlite3.Connection,
    event: str,
    user_id: Optional[int] = None,
    ip: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    """Write one audit event. The caller commits.

    Never put passwords, tokens or session ids in detail.
    """
    conn.execute(
        "INSERT INTO audit_events (user_id, event, ip, detail) VALUES (?, ?, ?, ?)",
        (user_id, event, ip, detail),
    )
