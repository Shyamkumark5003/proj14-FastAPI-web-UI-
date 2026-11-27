from fastapi.testclient import TestClient

from app import app

client = TestClient(app)

PNG = b"\x89PNG\r\n\x1a\n" + b"fake image body"


def test_upload_route_exists_in_openapi():
    assert "/upload" in client.get("/openapi.json").json()["paths"]


def test_anonymous_upload_is_rejected():
    r = client.post("/upload", files={"file": ("cat.png", PNG, "image/png")})
    assert r.status_code in (401, 403)


def test_anonymous_upload_saves_nothing():
    from hardening.upload_routes import UPLOAD_DIR

    before = set(UPLOAD_DIR.glob("*")) if UPLOAD_DIR.exists() else set()
    client.post("/upload", files={"file": ("cat.png", PNG, "image/png")})
    after = set(UPLOAD_DIR.glob("*")) if UPLOAD_DIR.exists() else set()
    assert before == after
