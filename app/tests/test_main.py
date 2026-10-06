from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_routes_mounted() -> None:
    paths = set(app.openapi()["paths"].keys())
    assert "/models" in paths
    assert "/models/upload" in paths
    assert "/chat" in paths
