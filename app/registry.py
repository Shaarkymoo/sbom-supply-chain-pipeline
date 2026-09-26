"""Model registry. Vulnerable by design: unverified ingestion, SSRF, path traversal."""

import hashlib
import json
import uuid
from pathlib import Path

import httpx
from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

MODEL_DIR = Path(__file__).parent / "models" / "storage"
MODEL_DIR.mkdir(parents=True, exist_ok=True)


def _load_index() -> dict:
    index_file = MODEL_DIR / "index.json"
    if index_file.exists():
        return json.loads(index_file.read_text())
    return {}


def _save_index(index: dict) -> None:
    (MODEL_DIR / "index.json").write_text(json.dumps(index, indent=2))


class ModelRecord(BaseModel):
    id: str
    name: str
    filename: str
    sha256: str | None = None


class FetchRequest(BaseModel):
    url: str


router = APIRouter(prefix="/models", tags=["models"])


@router.get("")
def list_models() -> list[ModelRecord]:
    return [ModelRecord(**rec) for rec in _load_index().values()]


@router.post("/upload")
async def upload_model(file: UploadFile = File(...)) -> ModelRecord:
    """VULNERABILITY: accepts any file with zero verification (hash, source, license)."""
    record_id = uuid.uuid4().hex[:12]
    data = await file.read()
    dest = MODEL_DIR / f"{record_id}_{file.filename}"
    dest.write_bytes(data)
    index = _load_index()
    index[record_id] = {
        "id": record_id,
        "name": file.filename,
        "filename": dest.name,
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    _save_index(index)
    return ModelRecord(**index[record_id])


@router.post("/fetch")
def fetch_model(req: FetchRequest) -> dict:
    """VULNERABILITY: SSRF — fetches any user-supplied URL with no scheme/host allowlist."""
    resp = httpx.get(req.url, timeout=10.0, follow_redirects=True)
    record_id = uuid.uuid4().hex[:12]
    dest = MODEL_DIR / f"{record_id}_fetched.bin"
    dest.write_bytes(resp.content)
    index = _load_index()
    index[record_id] = {
        "id": record_id,
        "name": req.url.split("/")[-1] or "fetched",
        "filename": dest.name,
        "sha256": hashlib.sha256(resp.content).hexdigest(),
    }
    _save_index(index)
    return {"id": record_id, "fetched_from": req.url, "size_bytes": len(resp.content)}


@router.get("/{model_id}/serve")
def serve_model(model_id: str) -> dict:
    """VULNERABILITY: path traversal — model_id is interpolated into the path unchecked."""
    path = MODEL_DIR / model_id
    if not path.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return {"served": str(path), "exists": True}