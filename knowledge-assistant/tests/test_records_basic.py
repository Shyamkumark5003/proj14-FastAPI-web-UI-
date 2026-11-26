from pathlib import Path

import pytest
from fastapi.routing import APIRoute

from tests.auth_helpers import (
    audit_events, create_user, csrf, logged_in_client, new_client, setup_db,
)

Q = {"question": "What is RBAC?", "answer": "Role-based access control."}


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)


def test_anonymous_cannot_list_records():
    assert new_client().get("/records").status_code == 401


def test_user_creates_and_lists_own_record():
    create_user("alice")
    alice = logged_in_client("alice")
    resp = alice.post("/records", json=Q, headers=csrf(alice))
    assert resp.status_code == 201
    listing = alice.get("/records").json()
    assert [r["question"] for r in listing] == [Q["question"]]


def test_owner_id_in_body_is_ignored():
    alice_id = create_user("alice")
    create_user("bob")
    alice = logged_in_client("alice")
    resp = alice.post("/records", json={**Q, "owner_id": 999}, headers=csrf(alice))
    assert resp.status_code == 201
    assert alice.get(f"/records/{resp.json()['id']}").json()["owner_id"] == alice_id


def test_post_without_csrf_header_is_rejected():
    create_user("alice")
    alice = logged_in_client("alice")
    assert alice.post("/records", json=Q).status_code == 403
    assert alice.get("/records").json() == []


def test_user_reads_own_record():
    create_user("alice")
    alice = logged_in_client("alice")
    rid = alice.post("/records", json=Q, headers=csrf(alice)).json()["id"]
    assert alice.get(f"/records/{rid}").status_code == 200


def test_other_users_record_is_404_and_audited():
    create_user("alice")
    bob_id = create_user("bob")
    alice = logged_in_client("alice")
    rid = alice.post("/records", json=Q, headers=csrf(alice)).json()["id"]

    bob = logged_in_client("bob")
    resp = bob.get(f"/records/{rid}")
    assert resp.status_code == 404
    assert Q["answer"] not in resp.text
    assert ("ownership_denied", f"record={rid}") in audit_events()


def test_foreign_and_missing_records_look_identical():
    create_user("alice")
    create_user("bob")
    alice = logged_in_client("alice")
    rid = alice.post("/records", json=Q, headers=csrf(alice)).json()["id"]
    bob = logged_in_client("bob")
    foreign = bob.get(f"/records/{rid}")
    missing = bob.get("/records/99999")
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_user_forbidden_on_admin_endpoint_and_audited():
    create_user("alice")
    alice = logged_in_client("alice")
    assert alice.get("/admin/users").status_code == 403
    assert any(e == "access_denied" for e, _ in audit_events())


def test_admin_lists_users_without_password_hashes():
    create_user("root", role="admin")
    create_user("alice")
    root = logged_in_client("root")
    resp = root.get("/admin/users")
    assert resp.status_code == 200
    assert "password_hash" not in resp.text
    assert "$argon2" not in resp.text


# ---- RBAC lives in one place, deny by default ----

def test_role_comparisons_live_only_in_rbac_py():
    root = Path(__file__).resolve().parent.parent
    for name in ("records_routes.py", "auth_routes.py", "auth_deps.py", "app.py"):
        text = (root / name).read_text(encoding="utf-8")
        assert "role ==" not in text and 'role"] ==' not in text, name
