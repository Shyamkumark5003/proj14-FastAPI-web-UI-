"""Security headers middleware.

Adds baseline security headers to every response.
It never overwrites a header that the app already set
(for example the Content-Security-Policy from Project 14).
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

DEFAULT_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

# Only send HSTS when the site is served over HTTPS.
HSTS_VALUE = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, enable_hsts: bool = False):
        super().__init__(app)
        self.enable_hsts = enable_hsts

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        for name, value in DEFAULT_HEADERS.items():
            if name not in response.headers:
                response.headers[name] = value

        if self.enable_hsts and "Strict-Transport-Security" not in response.headers:
            response.headers["Strict-Transport-Security"] = HSTS_VALUE

        return response
