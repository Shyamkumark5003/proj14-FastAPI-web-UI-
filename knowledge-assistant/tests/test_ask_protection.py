import pytest

import rbac
from tests.auth_helpers import create_user, logged_in_client, new_client, setup_db


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)


def _ask(client, question="What is RBAC?", token=None):
    if token is None:
        token = client.cookies.get("csrf_token", "")
    return client.post("/ask", data={"question": question, "csrf_token": token})


def test_anonymous_home_redirects_to_login():
    resp = new_client().get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_anonymous_ask_is_401_even_with_a_valid_csrf_token():
    client = new_client()
    client.get("/login")  # gives this client a csrf cookie
    assert _ask(client).status_code == 401


def test_logged_in_home_loads_and_issues_csrf_cookie():
    create_user("alice")
    client = logged_in_client("alice")
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 200
    assert client.cookies.get("csrf_token")


def test_logged_in_ask_works():
    create_user("alice")
    client = logged_in_client("alice")
    client.get("/")
    assert _ask(client).status_code == 200


def test_logged_in_ask_without_valid_csrf_is_403():
    create_user("alice")
    client = logged_in_client("alice")
    assert _ask(client, token="wrong-token").status_code == 403


def test_ask_is_controlled_by_rbac_in_one_place(monkeypatch):
    create_user("alice")
    client = logged_in_client("alice")
    client.get("/")
    monkeypatch.setattr(rbac, "ROLE_PERMISSIONS", {"user": frozenset(), "admin": frozenset()})
    assert _ask(client).status_code == 403


def test_api_ask_still_uses_api_key_not_a_session(monkeypatch):
    from app import API_KEY_ENV

    monkeypatch.setenv(API_KEY_ENV, "test-key")
    client = new_client()
    ok = client.post("/api/ask", json={"question": "What is RBAC?"}, headers={"X-API-Key": "test-key"})
    assert ok.status_code == 200
    assert client.post("/api/ask", json={"question": "x"}).status_code == 401
    assert client.post("/api/ask", json={"question": "x"}, headers={"X-API-Key": "wrong"}).status_code == 401
