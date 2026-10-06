from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.registry import router


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_list_models_empty_initially() -> None:
    client = _client()
    assert client.get("/models").json() == []


def test_upload_accepts_any_file_without_verification() -> None:
    client = _client()
    files = {"file": ("poisoned.bin", b"\x00\x01model", "application/octet-stream")}
    res = client.post("/models/upload", files=files)
    assert res.status_code == 200
    rec = res.json()
    assert rec["name"] == "poisoned.bin"
    assert rec["sha256"]
    assert client.get("/models").json()  # now listed


def test_fetch_documents_ssrf_behavior() -> None:
    # A local HTTP server is the SSRF target: the registry fetches an internal
    # URL the client controls, with no scheme/host allowlist (documented vuln).
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    captured = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            captured["path"] = self.path
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"internal-secret")

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        target = f"http://127.0.0.1:{port}/internal-secret"
        client = _client()
        res = client.post("/models/fetch", json={"url": target})
        assert res.status_code == 200
        assert res.json()["fetched_from"] == target
        assert captured.get("path") == "/internal-secret"  # internal URL was fetched
    finally:
        server.shutdown()


def test_serve_documents_path_traversal_behavior() -> None:
    client = _client()
    # traversal-style id (documented vuln surface)
    res = client.get("/models/..%2F..%2Fetc%2Fpasswd/serve")
    assert res.status_code in (200, 404)
