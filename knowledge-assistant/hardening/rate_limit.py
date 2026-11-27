"""In-memory sliding-window rate limiter.

Returns 429 with a Retry-After header when a client goes over the limit.

Notes:
- State is kept per process. With several workers, use a shared store (for example Redis).
- The client key is the direct peer IP. X-Forwarded-For is NOT trusted here.
"""

import math
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


@dataclass(frozen=True)
class Rule:
    name: str
    limit: int
    window: int  # seconds
    paths: tuple = ()  # empty means every path
    methods: tuple = ()  # empty means every method

    def matches(self, path: str, method: str) -> bool:
        path_ok = not self.paths or any(
            path == p or path.startswith(p + "/") for p in self.paths
        )
        method_ok = not self.methods or method in self.methods
        return path_ok and method_ok


def default_rules() -> list:
    return [
        Rule("auth", 10, 60, paths=("/login", "/register", "/change-password"), methods=("POST",)),
        Rule("ask", 30, 60, paths=("/ask", "/api/ask"), methods=("POST",)),
        Rule("default", 120, 60),
    ]


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, rules=None, enabled=None, clock=time.monotonic,
                 exempt_prefixes=("/static",)):
        super().__init__(app)
        self.rules = rules or default_rules()
        self.enabled = enabled
        self.clock = clock
        self.exempt_prefixes = tuple(exempt_prefixes)
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()
        self._calls = 0
        self._max_window = max(r.window for r in self.rules)

    def _is_enabled(self) -> bool:
        if self.enabled is not None:
            return self.enabled
        return os.getenv("RATE_LIMIT_DISABLED", "") != "1"

    def _rule_for(self, request: Request):
        for rule in self.rules:
            if rule.matches(request.url.path, request.method):
                return rule
        return None

    def _purge(self, now: float) -> None:
        stale = [k for k, q in self._hits.items() if not q or q[-1] <= now - self._max_window]
        for key in stale:
            del self._hits[key]

    def _hit(self, key, rule: Rule):
        now = self.clock()
        with self._lock:
            self._calls += 1
            if self._calls % 1000 == 0:
                self._purge(now)
            q = self._hits[key]
            while q and q[0] <= now - rule.window:
                q.popleft()
            if len(q) >= rule.limit:
                retry_after = max(1, math.ceil(q[0] + rule.window - now))
                return False, retry_after
            q.append(now)
            return True, 0

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self._is_enabled() or request.url.path.startswith(self.exempt_prefixes):
            return await call_next(request)

        rule = self._rule_for(request)
        if rule is None:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        allowed, retry_after = self._hit((client_ip, rule.name), rule)
        if not allowed:
            return JSONResponse(
                {"detail": "Too many requests"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)
