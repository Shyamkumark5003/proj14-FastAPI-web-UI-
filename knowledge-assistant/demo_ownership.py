"""Demo: Bob tries to read Alice's record and fails. Uses a temporary database."""
import os
import tempfile
from pathlib import Path

import db

os.environ.pop("COOKIE_SECURE", None)

ALICE_PW = "orange kettle drifts over quiet hills"
BOB_PW = "seven lanterns glow beside the harbour"


def show(title, resp):
    print(f"\n{title}\n  -> HTTP {resp.status_code}  {resp.text.strip()}")


with tempfile.TemporaryDirectory() as tmp:
    db.DB_PATH = Path(tmp) / "demo.db"
    db.init_db()

    from fastapi.testclient import TestClient

    from app import app
    from auth_service import register_user

    conn = db.get_conn()
    register_user(conn, "alice", ALICE_PW)
    register_user(conn, "bob", BOB_PW)
    conn.close()

    def login(username, password):
        client = TestClient(app)
        client.get("/login")
        resp = client.post(
            "/login",
            data={"username": username, "password": password,
                  "csrf_token": client.cookies.get("csrf_token")},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        return client

    def csrf(client):
        return {"X-CSRF-Token": client.cookies.get("csrf_token")}

    alice = login("alice", ALICE_PW)
    bob = login("bob", BOB_PW)

    created = alice.post(
        "/records",
        json={"question": "What is the launch code?", "answer": "ALICE-PRIVATE-ANSWER"},
        headers=csrf(alice),
    )
    record_id = created.json()["id"]
    show(f"1. Alice creates record {record_id}", created)
    show(f"2. Alice reads her own record {record_id}", alice.get(f"/records/{record_id}"))

    show(f"3. BOB tries to read ALICE's record {record_id}", bob.get(f"/records/{record_id}"))
    show("4. Bob reads a record id that does not exist (99999)", bob.get("/records/99999"))
    show(f"5. BOB tries to delete ALICE's record {record_id}",
         bob.delete(f"/records/{record_id}", headers=csrf(bob)))
    show("6. Alice checks: her record is still there", alice.get(f"/records/{record_id}"))
    show("7. Bob lists his records (Alice's is not in there)", bob.get("/records"))
    show("8. Bob calls the admin endpoint", bob.get("/admin/users"))

    print("\nAudit trail:")
    conn = db.get_conn()
    for row in conn.execute(
        "SELECT event, user_id, detail FROM audit_events "
        "WHERE event IN ('ownership_denied', 'access_denied', 'record_created', 'record_deleted') "
        "ORDER BY id"
    ):
        print(f"  {row['event']:<17} user_id={row['user_id']} {row['detail']}")
    conn.close()
