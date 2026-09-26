from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_routes_mounted():
    assert any(r.path == "/models" for r in app.routes)
    assert any(r.path == "/chat" for r in app.routes)