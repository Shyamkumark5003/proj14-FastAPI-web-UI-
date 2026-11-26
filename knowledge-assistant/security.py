import unicodedata
from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 15   # NIST: password used alone (no MFA)
MAX_LENGTH = 128  # must be at least 64; upper cap only to stop abuse
BLOCKLIST_PATH = Path(__file__).parent / "common_passwords.txt"

# argon2id with the library's recommended default parameters
_hasher = PasswordHasher()


def normalize(password: str) -> str:
    """Unicode NFKC normalization, as NIST recommends."""
    return unicodedata.normalize("NFKC", password)


@lru_cache(maxsize=1)
def load_blocklist() -> frozenset:
    if not BLOCKLIST_PATH.exists():
        return frozenset()
    lines = BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip().lower() for line in lines if line.strip())


def check_password_policy(password: str, username: str = "") -> list:
    """Return a list of problems. Empty list means the password is acceptable.

    Only length, blocklist and context checks. No composition rules.
    """
    pw = normalize(password)
    problems = []

    if len(pw) < MIN_LENGTH:
        problems.append(f"Use at least {MIN_LENGTH} characters.")
    if len(pw) > MAX_LENGTH:
        problems.append(f"Use at most {MAX_LENGTH} characters.")
    if pw.lower() in load_blocklist():
        problems.append("This password is too common or known from breaches. Choose another one.")

    name = username.strip().lower()
    if len(name) >= 4 and name in pw.lower():
        problems.append("The password must not contain your username.")

    return problems


def hash_password(password: str) -> str:
    return _hasher.hash(normalize(password))


def verify_password(stored_hash: str, password: str):
    """Return (is_valid, needs_rehash)."""
    try:
        _hasher.verify(stored_hash, normalize(password))
    except (VerificationError, InvalidHashError):
        return False, False
    return True, _hasher.check_needs_rehash(stored_hash)


def is_blocklisted(password: str) -> bool:
    """True if the password is on the blocklist (evidence of compromise)."""
    return normalize(password).lower() in load_blocklist()
