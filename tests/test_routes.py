def test_index_page_loads_with_labelled_field(client):
    response = client.get("/")
    assert response.status_code == 200
    assert 'for="question"' in response.text
    assert 'id="question"' in response.text


def test_ask_returns_answer_and_citations(client, token):
    response = client.post("/ask", data={"question": "password", "csrf_token": token})
    assert response.status_code == 200
    assert "Answer" in response.text
    assert "Sources" in response.text
    assert "Password reset" in response.text


def test_empty_question_gives_helpful_error(client, token):
    response = client.post("/ask", data={"question": "   ", "csrf_token": token})
    assert response.status_code == 200
    assert "Please type a question" in response.text


def test_unknown_question_gives_helpful_message(client, token):
    response = client.post("/ask", data={"question": "banana", "csrf_token": token})
    assert response.status_code == 200
    assert "No answer found" in response.text
