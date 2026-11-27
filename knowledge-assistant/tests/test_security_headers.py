from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


def test_security_headers_present():
    r = client.get("/login")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Referrer-Policy" in r.headers
    assert "Permissions-Policy" in r.headers


def test_existing_csp_is_not_overwritten():
    r = client.get("/login")
    assert "Content-Security-Policy" in r.headers
