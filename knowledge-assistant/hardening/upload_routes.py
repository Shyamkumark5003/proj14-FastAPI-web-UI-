"""POST /upload: authenticated, CSRF-protected, safe file upload."""

import os
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from hardening.uploads import UploadError, save_upload
from rbac import require_permission
from records_routes import csrf_header

# Files are stored outside any static or template folder, so they are never served directly.
UPLOAD_DIR = Path(
    os.getenv("UPLOAD_DIR", str(Path(__file__).resolve().parent.parent / "uploads_store"))
)

router = APIRouter()


@router.post("/upload", status_code=201)
async def upload_file(
    file: UploadFile = File(...),
    user=Depends(require_permission("records:create")),
    _csrf=Depends(csrf_header),
):
    try:
        saved = await save_upload(file, UPLOAD_DIR)
    except UploadError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    return {
        "id": saved.stored_name,
        "content_type": saved.content_type,
        "size": saved.size,
    }
