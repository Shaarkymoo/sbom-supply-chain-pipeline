import json
from pathlib import Path

from scripts.build_aibom import load_manifest, model_component, merge

FIXTURE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [{"type": "library", "name": "fastapi", "purl": "pkg:pypi/fastapi@0.115.6"}],
}


def test_load_manifest_requires_license() -> None:
    bad = {"model": {"name": "m", "version": "1", "framework": "f"}, "artifact": {"source_url": "u"}}
    p = Path("/tmp/bad-manifest.json")
    p.write_text(json.dumps(bad))
    try:
        load_manifest(p)  # missing model.license
    except SystemExit as e:
        assert "license" in str(e)
    else:
        raise AssertionError("expected SystemExit")


def test_model_component_emits_provenance_properties() -> None:
    manifest = {
        "model": {"name": "m", "version": "1", "framework": "f", "license": "MIT"},
        "artifact": {"sha256": "abc", "source_url": "https://example.com/m"},
        "datasets": [{"name": "attacks", "sha256": "def"}],
    }
    comp = model_component(manifest)
    assert comp["type"] == "model"
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["cdx:model:sha256"] == "abc"
    assert props["cdx:model:source_url"] == "https://example.com/m"
    assert props["cdx:model:dataset:attacks:sha256"] == "def"


def test_merge_adds_model_component_once(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(json.dumps(FIXTURE_SBOM))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "model": {"name": "m", "version": "1", "framework": "f", "license": "MIT"},
                "artifact": {"sha256": "abc", "source_url": "https://example.com/m"},
                "datasets": [],
            }
        )
    )
    out = tmp_path / "out.json"
    merge(sbom, manifest, out)
    result = json.loads(out.read_text())
    models = [c for c in result["components"] if c["type"] == "model"]
    assert len(models) == 1