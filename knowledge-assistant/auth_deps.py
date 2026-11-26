import os

from fastapi import HTTPException, Request

import db
from sessions import get_session_user


def cookie_secure() -> bool:
    """Secure flag for cookies. Set COOKIE_SECURE=1 when served over HTTPS."""
    return os.getenv("COOKIE_SECURE", "0") == "1"


def session_cookie_name() -> str:
    # The __Host- prefix makes browsers require Secure, Path=/ and no Domain.
    return "__Host-session" if cookie_secure() else "session"


def get_current_user(request: Request):
    """Return the logged-in user row, or None."""
    token = request.cookies.get(session_cookie_name())
    conn = db.get_conn()
    try:
        return get_session_user(conn, token)
    finally:
        conn.close()


def require_user(request: Request):
    """Dependency for protected routes: 401 when there is no valid session."""
    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user
