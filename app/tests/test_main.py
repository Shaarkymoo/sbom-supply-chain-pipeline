from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_routes_mounted() -> None:
    assert any(getattr(r, "path", None) == "/models" for r in app.routes)
    assert any(getattr(r, "path", None) == "/chat" for r in app.routes)
