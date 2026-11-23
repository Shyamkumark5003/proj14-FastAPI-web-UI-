import json
import re
from pathlib import Path

DOCS_PATH = Path(__file__).resolve().parent.parent / "data" / "documents.json"

STOP_WORDS = {
    "a", "an", "the", "is", "are", "how", "do", "i", "to", "what",
    "my", "can", "of", "in", "for", "and", "or",
}


def load_documents():
    return json.loads(DOCS_PATH.read_text(encoding="utf-8"))


def tokenize(text):
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def search(question):
    """Return the best answer and its citations, or None if nothing matches."""
    question_words = tokenize(question) - STOP_WORDS
    scored = []
    for doc in load_documents():
        doc_words = tokenize(doc["title"] + " " + doc["text"])
        score = len(question_words & doc_words)
        if score > 0:
            scored.append((score, doc))

    if not scored:
        return None

    scored.sort(key=lambda item: item[0], reverse=True)
    top_docs = [doc for _, doc in scored[:2]]
    return {
        "answer": top_docs[0]["text"],
        "citations": [{"id": d["id"], "title": d["title"]} for d in top_docs],
    }
