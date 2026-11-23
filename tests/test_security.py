def test_script_tag_in_document_is_rendered_as_text(client, token):
    response = client.post("/ask", data={"question": "script", "csrf_token": token})
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "<script>alert(1)</script>" not in response.text


def test_post_without_csrf_token_is_rejected(client):
    response = client.post("/ask", data={"question": "password"})
    assert response.status_code == 403


def test_post_with_wrong_csrf_token_is_rejected(client, token):
    response = client.post("/ask", data={"question": "password", "csrf_token": "wrong"})
    assert response.status_code == 403


def test_csp_header_is_sent(client):
    response = client.get("/")
    policy = response.headers["content-security-policy"]
    assert "script-src 'self'" in policy
    assert "object-src 'none'" in policy


def test_csrf_cookie_is_httponly_and_samesite(client):
    response = client.get("/")
    cookie_header = response.headers["set-cookie"].lower()
    assert "httponly" in cookie_header
    assert "samesite=strict" in cookie_header
