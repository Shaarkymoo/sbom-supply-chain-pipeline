from pathlib import Path

import pytest

from app import registry


@pytest.fixture(autouse=True)
def isolated_registry_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test an isolated model-storage directory."""
    monkeypatch.setattr(registry, "MODEL_DIR", tmp_path)
