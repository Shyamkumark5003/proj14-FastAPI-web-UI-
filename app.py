import hmac
import secrets
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from services.search import search

BASE_DIR = Path(__file__).resolve().parent
CSRF_COOKIE = "csrf_token"

app = FastAPI(title="Knowledge Assistant")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Show the full page and issue a CSRF token."""
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
):
    """Return only the answer fragment, after checking the CSRF token."""
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
