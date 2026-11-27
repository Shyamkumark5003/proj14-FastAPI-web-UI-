from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


def test_allowed_origin_gets_cors_header():
    r = client.get("/login", headers={"Origin": "http://localhost:8000"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:8000"


def test_unknown_origin_gets_no_cors_header():
    r = client.get("/login", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_preflight_from_unknown_origin_is_rejected():
    r = client.options(
        "/api/ask",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert r.status_code == 400
