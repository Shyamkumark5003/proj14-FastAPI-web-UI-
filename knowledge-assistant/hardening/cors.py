"""CORS allowlist configuration.

Origins come from the ALLOWED_ORIGINS environment variable
(comma separated). Wildcard "*" is rejected on purpose.
"""

import os

from fastapi.middleware.cors import CORSMiddleware

DEFAULT_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000"]


def load_allowed_origins() -> list[str]:
    raw = os.getenv("ALLOWED_ORIGINS", "")
    if not raw.strip():
        return DEFAULT_ORIGINS

    origins = [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]
    if "*" in origins:
        raise ValueError("Wildcard '*' is not allowed in ALLOWED_ORIGINS")
    return origins


def add_cors(app) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=load_allowed_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-API-Key", "HX-Request"],
        max_age=600,
    )
