"""Access matrix: role x endpoint x own-or-other record."""
import pytest

import db
from tests.auth_helpers import (
    audit_events, create_user, csrf, logged_in_client, new_client, setup_db,
)

SECRET = "secret-answer"

# "user" acts as bob and "admin" acts as root. The "other" record is always alice's.
ACTOR_USERNAME = {"user": "bob", "admin": "root"}

# (actor, method, route, target, expected status)
MATRIX = [
    # anonymous: always 401
    ("anonymous", "POST",   "/records",       "none",  401),
    ("anonymous", "GET",    "/records",       "none",  401),
    ("anonymous", "GET",    "/records/{id}",  "other", 401),
    ("anonymous", "DELETE", "/records/{id}",  "other", 401),
    ("anonymous", "GET",    "/admin/users",   "none",  401),
    # normal user
    ("user", "POST",   "/records",       "none",  201),
    ("user", "GET",    "/records",       "none",  200),
    ("user", "GET",    "/records/{id}",  "own",   200),
    ("user", "GET",    "/records/{id}",  "other", 404),
    ("user", "DELETE", "/records/{id}",  "own",   204),
    ("user", "DELETE", "/records/{id}",  "other", 404),
    ("user", "GET",    "/admin/users",   "none",  403),
    # admin
    ("admin", "POST",   "/records",       "none",  201),
    ("admin", "GET",    "/records",       "none",  200),
    ("admin", "GET",    "/records/{id}",  "own",   200),
    ("admin", "GET",    "/records/{id}",  "other", 200),
    ("admin", "DELETE", "/records/{id}",  "own",   204),
    ("admin", "DELETE", "/records/{id}",  "other", 404),
    ("admin", "GET",    "/admin/users",   "none",  200),
]


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Three users, each owning one record. Returns record ids by owner name."""
    setup_db(tmp_path, monkeypatch)
    ids = {
        "alice": create_user("alice"),
        "bob": create_user("bob"),
        "root": create_user("root", role="admin"),
    }
    conn = db.get_conn()
    records = {}
    for name, user_id in ids.items():
        cur = conn.execute(
            "INSERT INTO records (owner_id, question, answer) VALUES (?, ?, ?)",
            (user_id, f"question of {name}", f"{SECRET} {name}"),
        )
        records[name] = cur.lastrowid
    conn.commit()
    conn.close()
    return {"records": records, "users": ids}


def _record_exists(record_id):
    conn = db.get_conn()
    try:
        return conn.execute("SELECT 1 FROM records WHERE id = ?", (record_id,)).fetchone() is not None
    finally:
        conn.close()


@pytest.mark.parametrize(
    "actor,method,route,target,expected",
    MATRIX,
    ids=[f"{a}-{m}-{r}-{t}" for a, m, r, t, _ in MATRIX],
)
def test_access_matrix(world, actor, method, route, target, expected):
    records, users = world["records"], world["users"]
    name = ACTOR_USERNAME.get(actor)

    client = new_client() if actor == "anonymous" else logged_in_client(name)

    record_id = None
    if target == "own":
        record_id = records[name]
    elif target == "other":
        record_id = records["alice"]
    path = route.replace("{id}", str(record_id))

    headers = csrf(client) if method in ("POST", "DELETE") else {}
    body = {"question": "new question", "answer": "new answer"} if method == "POST" else None

    resp = client.request(method, path, json=body, headers=headers)
    assert resp.status_code == expected, resp.text

    events = audit_events()

    # ---- no data leaks on any denied request ----
    if expected in (401, 403, 404):
        assert SECRET not in resp.text

    # ---- DELETE side effects ----
    if method == "DELETE" and expected == 204:
        assert not _record_exists(record_id)
    if method == "DELETE" and expected == 404:
        assert _record_exists(record_id), "a denied delete must not remove the record"

    # ---- list shows own records only ----
    if method == "GET" and route == "/records" and expected == 200:
        assert {r["owner_id"] for r in resp.json()} == {users[name]}
        assert f"{SECRET} alice" not in resp.text

    # ---- create: owner comes from the session ----
    if method == "POST" and expected == 201:
        conn = db.get_conn()
        owner = conn.execute(
            "SELECT owner_id FROM records WHERE id = ?", (resp.json()["id"],)
        ).fetchone()[0]
        conn.close()
        assert owner == users[name]

    # ---- audit trail ----
    if actor == "user" and target == "other":
        assert ("ownership_denied", f"record={record_id}") in events
    if actor == "user" and route == "/admin/users":
        assert any(event == "access_denied" for event, _ in events)
    if actor == "admin" and target == "other" and method == "GET":
        assert any(
            event == "record_access_other" and detail.startswith(f"record={record_id} ")
            for event, detail in events
        )
    if actor == "admin" and target == "other" and method == "DELETE":
        assert ("ownership_denied", f"record={record_id}") in events


def test_matrix_covers_every_protected_route():
    """If someone adds a route under /records or /admin, the matrix must grow too."""
    from app import app

    in_app = set()
    for path, methods in app.openapi()["paths"].items():
        if path.startswith(("/records", "/admin")):
            for method in methods:
                if method in ("get", "post", "put", "patch", "delete"):
                    in_app.add((method.upper(), path))

    in_matrix = {(m, r.replace("{id}", "{record_id}")) for _, m, r, _, _ in MATRIX}
    assert in_app == in_matrix, f"matrix out of sync. In app only: {in_app - in_matrix}; in matrix only: {in_matrix - in_app}"
