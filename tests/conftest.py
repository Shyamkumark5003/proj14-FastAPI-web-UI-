import re

import pytest
from fastapi.testclient import TestClient

from app import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def token(client):
    """Load the page once and return the CSRF token from the form."""
    html = client.get("/").text
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF hidden field not found in the page"
    return match.group(1)
