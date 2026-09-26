"""FastAPI application: model registry + chat. Intentionally vulnerable."""

from fastapi import FastAPI

from app.chat import router as chat_router
from app.registry import router as registry_router

app = FastAPI(title="AI Model Registry & Chat", version="0.1.0")
app.include_router(registry_router)
app.include_router(chat_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
