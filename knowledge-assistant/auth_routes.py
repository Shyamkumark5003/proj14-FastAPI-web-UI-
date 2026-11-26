import hmac
import secrets
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import db
from auth_deps import cookie_secure, get_current_user, session_cookie_name
from auth_service import RegistrationError, register_user
from login_service import LoginError, login_user, logout_user
from sessions import SESSION_TTL

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")
router = APIRouter()

CSRF_COOKIE = "csrf_token"  # same cookie name as the main page


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _set_csrf_cookie(response, token: str) -> None:
    response.set_cookie(
        CSRF_COOKIE, token, httponly=True, samesite="lax", secure=cookie_secure(), path="/"
    )


def _csrf_token(request: Request) -> str:
    return request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(32)


def _check_csrf(request: Request, form_token: str) -> str:
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    if not cookie_token or not hmac.compare_digest(
        cookie_token.encode("utf-8"), form_token.encode("utf-8")
    ):
        raise HTTPException(status_code=403, detail="CSRF check failed")
    return cookie_token


def _page(request: Request, template: str, token: str, status_code: int = 200, **context):
    response = templates.TemplateResponse(
        request, template, {"csrf_token": token, **context}, status_code=status_code
    )
    _set_csrf_cookie(response, token)
    return response


# ---------------- register ----------------

@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return _page(
        request, "register.html", _csrf_token(request),
        problems=[], username="", success=False,
    )


@router.post("/register", response_class=HTMLResponse)
def register_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
):
    cookie_token = _check_csrf(request, csrf_token)

    conn = db.get_conn()
    try:
        register_user(conn, username, password, ip=_client_ip(request))
    except RegistrationError as exc:
        # The password is never sent back to the page.
        return _page(
            request, "register.html", cookie_token, status_code=400,
            problems=exc.problems, username=username.strip(), success=False,
        )
    finally:
        conn.close()

    return _page(
        request, "register.html", cookie_token, status_code=201,
        problems=[], username="", success=True,
    )


# ---------------- login ----------------

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if get_current_user(request):
        return RedirectResponse("/me", status_code=303)
    return _page(request, "login.html", _csrf_token(request), error="", username="")


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
):
    cookie_token = _check_csrf(request, csrf_token)

    conn = db.get_conn()
    try:
        result = login_user(conn, username, password, ip=_client_ip(request))
    except LoginError as exc:
        status = 429 if exc.throttled else 401
        response = _page(
            request, "login.html", cookie_token, status_code=status,
            error=exc.message, username=username.strip()[:64],
        )
        if exc.throttled:
            response.headers["Retry-After"] = "900"
        return response
    finally:
        conn.close()

    response = RedirectResponse("/me", status_code=303)
    response.set_cookie(
        key=session_cookie_name(),
        value=result.token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        secure=cookie_secure(),
        samesite="lax",
        path="/",
    )
    # Fresh CSRF token after login.
    _set_csrf_cookie(response, secrets.token_urlsafe(32))
    return response


# ---------------- logout ----------------

@router.post("/logout")
def logout_submit(request: Request, csrf_token: str = Form("")):
    _check_csrf(request, csrf_token)

    conn = db.get_conn()
    try:
        logout_user(conn, request.cookies.get(session_cookie_name()), ip=_client_ip(request))
    finally:
        conn.close()

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(
        session_cookie_name(), path="/", secure=cookie_secure(), httponly=True, samesite="lax"
    )
    return response


# ---------------- who am I ----------------

@router.get("/me", response_class=HTMLResponse)
def me_page(request: Request):
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return _page(
        request, "me.html", _csrf_token(request),
        username=user["username"], role=user["role"],
        must_change_password=bool(user["must_change_password"]),
    )
