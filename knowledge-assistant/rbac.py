"""Role-based access control. Every role check lives in this file."""
from typing import Optional

from fastapi import HTTPException, Request

import db
from audit import log_event
from auth_deps import get_current_user

# Single source of truth: which role may do what. Unknown roles get nothing.
ROLE_PERMISSIONS = {
    "user": frozenset({
        "records:create",
        "records:list_own",
        "records:read",
        "records:delete",
    }),
    "admin": frozenset({
        "records:create",
        "records:list_own",
        "records:read",
        "records:delete",
        "records:read_any",   # may read other users' records (audited)
        "users:list",
    }),
}


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _audit(event: str, user_id: Optional[int], ip: str, detail: str) -> None:
    conn = db.get_conn()
    try:
        log_event(conn, event, user_id=user_id, ip=ip, detail=detail)
        conn.commit()
    finally:
        conn.close()


def require_permission(permission: str):
    """FastAPI dependency: 401 if not logged in, 403 if the role lacks the permission."""

    def dependency(request: Request):
        user = get_current_user(request)
        if user is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if not has_permission(user["role"], permission):
            _audit(
                "access_denied", user["id"], _client_ip(request),
                f"permission={permission} path={request.url.path}",
            )
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    # Lets a test prove that every protected route declares a permission.
    dependency.required_permission = permission
    return dependency


def get_record_or_404(conn, user, record_id: int, ip: str, any_permission: Optional[str] = None):
    """Object-level check: only the owner, unless the role holds `any_permission`.

    A missing record and someone else's record give the same 404,
    so record ids cannot be probed.
    """
    row = conn.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Record not found")

    if row["owner_id"] == user["id"]:
        return row

    if any_permission and has_permission(user["role"], any_permission):
        log_event(
            conn, "record_access_other", user_id=user["id"], ip=ip,
            detail=f"record={record_id} owner={row['owner_id']}",
        )
        conn.commit()
        return row

    log_event(conn, "ownership_denied", user_id=user["id"], ip=ip, detail=f"record={record_id}")
    conn.commit()
    raise HTTPException(status_code=404, detail="Record not found")
