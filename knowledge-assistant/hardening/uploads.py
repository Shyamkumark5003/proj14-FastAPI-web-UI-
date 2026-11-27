"""Safe file upload helper.

Rules:
1. The declared content type must be in an allowlist.
2. The real file content (magic bytes) must match the declared type.
3. The file must not be empty and must not exceed the size cap.
4. The stored name is random (uuid4) and the extension comes from the
   detected type. The user-supplied filename is never used as a path.
"""

import os
import uuid
from dataclasses import dataclass
from pathlib import Path

CHUNK_SIZE = 64 * 1024
MAX_UPLOAD_BYTES = 5_000_000

# Allowed content types and the extension we store them with.
# SVG and HTML are not allowed on purpose (they can carry scripts).
ALLOWED_TYPES = {
    "application/pdf": ".pdf",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "text/plain": ".txt",
}


class UploadError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


@dataclass(frozen=True)
class SavedUpload:
    stored_name: str
    content_type: str
    size: int


def _normalize_content_type(value) -> str:
    return (value or "").split(";")[0].strip().lower()


def _content_matches_type(content_type: str, data: bytes) -> bool:
    if content_type == "application/pdf":
        return data.startswith(b"%PDF-")
    if content_type == "image/png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if content_type == "image/jpeg":
        return data.startswith(b"\xff\xd8\xff")
    if content_type == "text/plain":
        if b"\x00" in data:
            return False
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True
    return False


async def save_upload(upload, dest_dir, max_bytes: int = MAX_UPLOAD_BYTES) -> SavedUpload:
    content_type = _normalize_content_type(upload.content_type)
    if content_type not in ALLOWED_TYPES:
        raise UploadError(415, "File type not allowed")

    data = bytearray()
    while True:
        chunk = await upload.read(CHUNK_SIZE)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > max_bytes:
            raise UploadError(413, "File too large")

    if not data:
        raise UploadError(400, "Empty file")

    data = bytes(data)
    if not _content_matches_type(content_type, data):
        raise UploadError(415, "File content does not match its type")

    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)

    stored_name = f"{uuid.uuid4().hex}{ALLOWED_TYPES[content_type]}"
    target = dest / stored_name
    if target.resolve().parent != dest.resolve():
        raise UploadError(400, "Invalid upload path")

    with open(target, "xb") as f:
        f.write(data)
    os.chmod(target, 0o600)

    return SavedUpload(stored_name=stored_name, content_type=content_type, size=len(data))
