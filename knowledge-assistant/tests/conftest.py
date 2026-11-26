import re

import pytest
from fastapi.testclient import TestClient

import db
from app import app
from auth_service import register_user

TEST_USER = "tester"
TEST_PASSWORD = "correct horse battery staple"


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A logged-in client. It uses a temporary database, never the real app.db."""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    db.init_db()
    conn = db.get_conn()
    register_user(conn, TEST_USER, TEST_PASSWORD)
    conn.close()

    with TestClient(app) as test_client:
        test_client.get("/login")
        response = test_client.post(
            "/login",
            data={
                "username": TEST_USER,
                "password": TEST_PASSWORD,
                "csrf_token": test_client.cookies.get("csrf_token"),
            },
            follow_redirects=False,
        )
        assert response.status_code == 303, "test login failed"
        yield test_client


@pytest.fixture
def token(client):
    """Load the page once and return the CSRF token from the form."""
    html = client.get("/").text
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF hidden field not found in the page"
    return match.group(1)
