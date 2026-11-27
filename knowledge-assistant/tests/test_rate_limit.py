from fastapi import FastAPI
from fastapi.testclient import TestClient

from hardening.rate_limit import RateLimitMiddleware, Rule


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def build(rules, clock=None, enabled=True):
    app = FastAPI()

    @app.get("/ping")
    def ping():
        return {"ok": True}

    @app.post("/login")
    def login():
        return {"ok": True}

    app.add_middleware(
        RateLimitMiddleware, rules=rules, enabled=enabled, clock=clock or FakeClock()
    )
    return TestClient(app)


def test_over_limit_returns_429_with_retry_after():
    client = build([Rule("default", 3, 60)])
    for _ in range(3):
        assert client.get("/ping").status_code == 200
    r = client.get("/ping")
    assert r.status_code == 429
    assert 1 <= int(r.headers["Retry-After"]) <= 60


def test_login_rule_is_stricter_than_default():
    rules = [
        Rule("auth", 2, 60, paths=("/login",), methods=("POST",)),
        Rule("default", 100, 60),
    ]
    client = build(rules)
    assert client.post("/login").status_code == 200
    assert client.post("/login").status_code == 200
    assert client.post("/login").status_code == 429
    assert client.get("/ping").status_code == 200


def test_allowed_again_after_window_passes():
    clock = FakeClock()
    client = build([Rule("default", 3, 60)], clock=clock)
    for _ in range(3):
        client.get("/ping")
    assert client.get("/ping").status_code == 429
    clock.now += 61
    assert client.get("/ping").status_code == 200


def test_limiter_can_be_disabled_by_env(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_DISABLED", "1")
    client = build([Rule("default", 2, 60)], enabled=None)
    for _ in range(10):
        assert client.get("/ping").status_code == 200
