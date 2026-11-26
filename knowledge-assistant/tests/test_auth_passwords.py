import pytest

import db
from auth_service import RegistrationError, register_user
from security import check_password_policy, hash_password, verify_password

GOOD = "correct horse battery staple"


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    connection = db.get_conn()
    yield connection
    connection.close()


# ---- NIST password rules ----

def test_14_chars_rejected():
    assert check_password_policy("a" * 14)


def test_exactly_15_chars_accepted():
    assert check_password_policy("abcdefghijklmno") == []


def test_64_chars_accepted():
    assert check_password_policy("ab" * 32) == []


def test_128_chars_accepted_and_129_rejected():
    assert check_password_policy("x" * 128) == []
    assert check_password_policy("x" * 129)


def test_no_composition_rules():
    # all lowercase, no digit, no symbol: still fine when long enough
    assert check_password_policy("alllowercasepassphrase") == []


def test_spaces_and_unicode_allowed():
    assert check_password_policy("this is a long phrase with spaces") == []
    assert check_password_policy("நல்ல கடவுச்சொல் வாக்கியம் இது") == []


def test_blocklist_rejects_common_password():
    assert check_password_policy("PasswordPassword")  # case-insensitive match


def test_password_containing_username_rejected():
    assert check_password_policy("my-shyamkumar-secret-phrase", "shyamkumar")


# ---- argon2id ----

def test_hash_is_argon2id_and_not_plaintext():
    h = hash_password(GOOD)
    assert h.startswith("$argon2id$")
    assert GOOD not in h


def test_verify_correct_and_wrong_password():
    h = hash_password(GOOD)
    assert verify_password(h, GOOD)[0] is True
    assert verify_password(h, "wrong password entirely") == (False, False)


def test_same_password_gives_different_hashes():
    assert hash_password(GOOD) != hash_password(GOOD)


# ---- registration ----

def test_register_success_stores_hash_and_user_role(conn):
    user_id = register_user(conn, "Alice_01", GOOD, ip="127.0.0.1")
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    assert row["username"] == "alice_01"
    assert row["role"] == "user"
    assert row["password_hash"].startswith("$argon2id$")
    assert GOOD not in row["password_hash"]


def test_register_writes_audit_event(conn):
    user_id = register_user(conn, "alice", GOOD, ip="127.0.0.1")
    events = [r["event"] for r in conn.execute("SELECT event FROM audit_events")]
    assert "register_success" in events


def test_register_weak_password_rejected_and_audited(conn):
    with pytest.raises(RegistrationError):
        register_user(conn, "alice", "short")
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    events = [r["event"] for r in conn.execute("SELECT event FROM audit_events")]
    assert "register_rejected" in events


def test_register_duplicate_username_rejected(conn):
    register_user(conn, "alice", GOOD)
    with pytest.raises(RegistrationError):
        register_user(conn, "ALICE", GOOD)


def test_audit_log_never_contains_password(conn):
    register_user(conn, "alice", GOOD)
    with pytest.raises(RegistrationError):
        register_user(conn, "bob", "short")
    details = " ".join(str(r["detail"]) for r in conn.execute("SELECT detail FROM audit_events"))
    assert GOOD not in details and "short" not in details
