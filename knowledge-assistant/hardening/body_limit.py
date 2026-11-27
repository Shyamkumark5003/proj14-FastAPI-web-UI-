"""Request body size limit.

Checks the Content-Length header first (fast reject), and also counts the
bytes while streaming, so chunked requests without Content-Length are limited too.
Returns 413 when the body is too large.
"""

from starlette.responses import JSONResponse


class BodyTooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    def __init__(self, app, max_bytes: int = 1_000_000, path_limits: dict | None = None):
        self.app = app
        self.max_bytes = max_bytes
        self.path_limits = path_limits or {}

    def _limit_for(self, path: str) -> int:
        for prefix, limit in self.path_limits.items():
            if path == prefix or path.startswith(prefix + "/"):
                return limit
        return self.max_bytes

    async def _reject(self, scope, receive, send, status: int, detail: str) -> None:
        response = JSONResponse({"detail": detail}, status_code=status)
        await response(scope, receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self._limit_for(scope["path"])

        headers = dict(scope["headers"])
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                await self._reject(scope, receive, send, 400, "Invalid Content-Length")
                return
            if declared > limit:
                await self._reject(scope, receive, send, 413, "Request body too large")
                return

        received = 0
        response_started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLarge()
            return message

        async def tracking_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except BodyTooLarge:
            if not response_started:
                await self._reject(scope, receive, send, 413, "Request body too large")
