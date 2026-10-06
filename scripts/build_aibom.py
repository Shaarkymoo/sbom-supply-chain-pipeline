#!/usr/bin/env python3
"""Merge AI model metadata (AIBOM) into a CycloneDX SBOM.

Reads an SBOM (CycloneDX JSON) plus a model manifest and emits the SBOM
extended with CycloneDX 1.5 'model' components. Fails if the manifest is
missing/incomplete or the SBOM is invalid.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    model = data.get("model") or {}
    artifact = data.get("artifact") or {}
    for key in ("name", "version", "framework", "license"):
        if not model.get(key):
            sys.exit(f"manifest missing model.{key}")
    if not artifact.get("source_url"):
        sys.exit("manifest missing artifact.source_url")
    return data


def resolve_hashes(data: dict[str, Any], app_dir: Path | None) -> dict[str, Any]:
    artifact = data["artifact"]
    if not artifact.get("sha256"):
        if app_dir is None:
            sys.exit("artifact.sha256 missing and no app_dir provided")
        artifact_file = app_dir / "models" / artifact.get("file", "tiny-model.json")
        if not artifact_file.is_file():
            sys.exit(f"artifact.sha256 missing and {artifact_file} not found")
        artifact["sha256"] = sha256(artifact_file)
    data["artifact"] = artifact

    datasets = []
    for ds in data.get("datasets", []):
        if not ds.get("sha256"):
            if app_dir is None:
                sys.exit(f"dataset {ds['name']} missing sha256 and no app_dir provided")
            ds_file = app_dir / "data" / ds["file"]
            if not ds_file.is_file():
                sys.exit(f"dataset {ds['name']} missing sha256 and file not found")
            ds["sha256"] = sha256(ds_file)
        datasets.append(ds)
    data["datasets"] = datasets
    return data


def model_component(data: dict[str, Any]) -> dict[str, Any]:
    model = data["model"]
    artifact = data["artifact"]
    props: list[dict[str, str]] = [
        {"name": "cdx:model:sha256", "value": artifact["sha256"]},
        {"name": "cdx:model:source_url", "value": artifact["source_url"]},
        {"name": "cdx:model:framework", "value": model["framework"]},
    ]
    for ds in data.get("datasets", []):
        props.append({"name": f"cdx:model:dataset:{ds['name']}:sha256", "value": ds["sha256"]})
    return {
        "type": "model",
        "bom-ref": f"model-{model['name']}",
        "name": model["name"],
        "version": model["version"],
        "licenses": [{"license": {"id": model["license"]}}],
        "properties": props,
    }


def merge(
    sbom_path: Path,
    manifest_path: Path,
    output_path: Path,
    app_dir: Path | None = None,
) -> None:
    sbom = json.loads(sbom_path.read_text())
    if sbom.get("bomFormat") != "CycloneDX":
        sys.exit("input is not a CycloneDX SBOM")
    data = resolve_hashes(load_manifest(manifest_path), app_dir)
    comp = model_component(data)
    components = sbom.setdefault("components", [])
    if not any(c.get("bom-ref") == comp["bom-ref"] for c in components):
        components.append(comp)
    output_path.write_text(json.dumps(sbom, indent=2))
    print(f"wrote {output_path} with {len(components)} components")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    merge(Path(args.sbom), Path(args.manifest), Path(args.output), repo_root / "app")


if __name__ == "__main__":
    main()
