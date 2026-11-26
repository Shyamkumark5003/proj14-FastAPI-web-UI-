import hmac

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

import db
from audit import log_event
from rbac import get_record_or_404, require_permission

router = APIRouter()


class RecordIn(BaseModel):
    # No owner_id here on purpose: the owner always comes from the session.
    question: str = Field(min_length=1, max_length=2000)
    answer: str = Field(min_length=1, max_length=8000)


def csrf_header(request: Request) -> None:
    """Double-submit check for JSON requests: X-CSRF-Token must equal the csrf cookie."""
    cookie = request.cookies.get("csrf_token", "")
    header = request.headers.get("x-csrf-token", "")
    if not cookie or not hmac.compare_digest(cookie.encode("utf-8"), header.encode("utf-8")):
        raise HTTPException(status_code=403, detail="CSRF check failed")


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/records", status_code=201)
def create_record(
    body: RecordIn,
    request: Request,
    user=Depends(require_permission("records:create")),
    _csrf=Depends(csrf_header),
):
    conn = db.get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO records (owner_id, question, answer) VALUES (?, ?, ?)",
            (user["id"], body.question, body.answer),
        )
        log_event(conn, "record_created", user_id=user["id"], ip=_ip(request), detail=f"record={cur.lastrowid}")
        conn.commit()
        return {"id": cur.lastrowid}
    finally:
        conn.close()


@router.get("/records")
def list_own_records(user=Depends(require_permission("records:list_own"))):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT id, owner_id, question, answer, created_at FROM records WHERE owner_id = ? ORDER BY id",
            (user["id"],),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/records/{record_id}")
def read_record(
    record_id: int,
    request: Request,
    user=Depends(require_permission("records:read")),
):
    conn = db.get_conn()
    try:
        row = get_record_or_404(
            conn, user, record_id, ip=_ip(request), any_permission="records:read_any"
        )
        return {k: row[k] for k in ("id", "owner_id", "question", "answer", "created_at")}
    finally:
        conn.close()


@router.delete("/records/{record_id}", status_code=204)
def delete_record(
    record_id: int,
    request: Request,
    user=Depends(require_permission("records:delete")),
    _csrf=Depends(csrf_header),
):
    conn = db.get_conn()
    try:
        # Owner only: no *_any permission is passed, so even an admin gets 404 here.
        get_record_or_404(conn, user, record_id, ip=_ip(request))
        conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        log_event(conn, "record_deleted", user_id=user["id"], ip=_ip(request), detail=f"record={record_id}")
        conn.commit()
        return Response(status_code=204)
    finally:
        conn.close()


@router.get("/admin/users")
def list_users(user=Depends(require_permission("users:list"))):
    conn = db.get_conn()
    try:
        # Never select password_hash.
        rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
