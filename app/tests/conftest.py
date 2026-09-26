import pytest

from app import registry


@pytest.fixture(autouse=True)
def isolated_registry_dir(tmp_path, monkeypatch):
    """Give every test an isolated model-storage directory."""
    monkeypatch.setattr(registry, "MODEL_DIR", tmp_path)