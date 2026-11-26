import hmac
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from auth_deps import get_current_user
from rbac import require_permission
from services.search import search

BASE_DIR = Path(__file__).resolve().parent
CSRF_COOKIE = "csrf_token"

app = FastAPI(title="Knowledge Assistant")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Show the full page and issue a CSRF token. Login required."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user["must_change_password"]:
        return RedirectResponse("/change-password", status_code=303)
    token = request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(32)
    response = templates.TemplateResponse(
        request, "index.html", {"page_title": "Knowledge Assistant", "csrf_token": token}
    )
    response.set_cookie(CSRF_COOKIE, token, httponly=True, samesite="strict")
    return response


@app.post("/ask", response_class=HTMLResponse)
async def ask(
    request: Request,
    question: str = Form(""),
    csrf_token: str = Form(""),
    user=Depends(require_permission("ask:use")),
):
    """Return the answer fragment. Needs a session, the ask:use permission and a CSRF token."""
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    if not cookie_token or not hmac.compare_digest(cookie_token, csrf_token):
        return templates.TemplateResponse(
            request,
            "_answer.html",
            {"error": "Your session expired. Please reload the page and try again."},
            status_code=403,
        )

    question = question.strip()
    if not question:
        context = {
            "error": "Your question is empty. Please type a question and press Ask."
        }
    else:
        context = {"question": question, "result": search(question)}
    return templates.TemplateResponse(request, "_answer.html", context)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add the Content-Security-Policy and related headers to every response."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# ---- JSON API for n8n and Langflow ----
import os
import re

from fastapi import Header, HTTPException
from pydantic import BaseModel, Field

API_KEY_ENV = "ASK_API_KEY"
MAX_QUESTION_LENGTH = 500

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")


class AskRequest(BaseModel):
    question: str = Field(..., max_length=MAX_QUESTION_LENGTH)


def redact_pii(text: str) -> str:
    """Mask emails and phone numbers before the text is used anywhere else."""
    text = EMAIL_RE.sub("[email removed]", text)
    return PHONE_RE.sub("[phone removed]", text)


def check_api_key(supplied: str) -> None:
    """Reject the request unless the API key matches. Fail closed if unset."""
    expected = os.environ.get(API_KEY_ENV, "")
    if not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/api/ask")
async def api_ask(payload: AskRequest, x_api_key: str = Header(default="")):
    """JSON endpoint for tools like n8n and Langflow. Uses an API key, not CSRF."""
    check_api_key(x_api_key)

    question = redact_pii(payload.question.strip())
    if not question:
        raise HTTPException(status_code=422, detail="Question is empty")

    result = search(question)
    if result is None:
        return {"found": False, "answer": "No answer found.", "sources": []}
    return {
        "found": True,
        "answer": redact_pii(result["answer"]),
        "sources": result["citations"],
    }


# --- Task 16: authentication ---
from auth_routes import router as auth_router  # noqa: E402
from db import init_db  # noqa: E402

init_db()
app.include_router(auth_router)

from records_routes import router as records_router  # noqa: E402

app.include_router(records_router)
