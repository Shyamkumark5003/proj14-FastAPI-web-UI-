from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from hardening.body_limit import BodySizeLimitMiddleware


def build():
    app = FastAPI()

    @app.post("/echo")
    async def echo(request: Request):
        body = await request.body()
        return {"size": len(body)}

    @app.post("/upload")
    async def upload(request: Request):
        body = await request.body()
        return {"size": len(body)}

    app.add_middleware(
        BodySizeLimitMiddleware, max_bytes=100, path_limits={"/upload": 1000}
    )
    return TestClient(app)


def test_small_body_is_accepted():
    r = build().post("/echo", content=b"x" * 50)
    assert r.status_code == 200
    assert r.json() == {"size": 50}


def test_large_content_length_gets_413():
    r = build().post("/echo", content=b"x" * 101)
    assert r.status_code == 413


def test_upload_path_has_its_own_bigger_limit():
    client = build()
    assert client.post("/upload", content=b"x" * 500).status_code == 200
    assert client.post("/upload", content=b"x" * 1001).status_code == 413


def test_chunked_body_without_content_length_is_limited():
    def chunks():
        for _ in range(3):
            yield b"x" * 60

    r = build().post("/echo", content=chunks())
    assert r.status_code == 413
