import re

import pytest

import rbac
from tests.auth_helpers import create_user, csrf, logged_in_client, new_client, setup_db

PROTECTED_PREFIXES = ("/records", "/admin")
HTTP_METHODS = ("get", "post", "put", "patch", "delete")
BODY_METHODS = ("POST", "PUT", "PATCH")
BODY = {"question": "q", "answer": "a"}


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)


def _protected_endpoints():
    """List (METHOD, path) for every records/admin route, using the public OpenAPI schema."""
    from app import app

    endpoints = []
    for path, methods in app.openapi()["paths"].items():
        if not path.startswith(PROTECTED_PREFIXES):
            continue
        concrete = re.sub(r"\{[^}]+\}", "1", path)
        for method in methods:
            if method in HTTP_METHODS:
                endpoints.append((method.upper(), concrete))
    return endpoints


def _call(client, method, path, headers=None):
    body = BODY if method in BODY_METHODS else None
    return client.request(method, path, json=body, headers=headers or {})


def test_protected_routes_are_found():
    # Guards against a silent pass: the five records/admin routes must exist.
    assert len(_protected_endpoints()) >= 5, _protected_endpoints()


def test_anonymous_gets_401_on_every_protected_route():
    client = new_client()
    wrong = []
    for method, path in _protected_endpoints():
        status = _call(client, method, path).status_code
        if status != 401:
            wrong.append((method, path, status))
    assert not wrong, f"expected 401 for anonymous, got: {wrong}"


def test_every_protected_route_checks_a_permission(monkeypatch):
    create_user("alice")
    alice = logged_in_client("alice")

    # Remove every permission from every role: now nothing may be allowed.
    monkeypatch.setattr(rbac, "ROLE_PERMISSIONS", {"user": frozenset(), "admin": frozenset()})

    wrong = []
    for method, path in _protected_endpoints():
        status = _call(alice, method, path, headers=csrf(alice)).status_code
        if status != 403:
            wrong.append((method, path, status))
    assert not wrong, f"these routes ignore permissions (expected 403): {wrong}"
