package main

import future.keywords.in

# --- Passing cases ---

test_clean_sbom_passes {
	no_violations(clean_sbom)
}

test_model_without_provenance_denied {
	some msg in deny with input as missing_provenance_sbom
	msg == "model registry-demo-tiny lacks provenance (cdx:model:sha256 / cdx:model:source_url)"
}

test_missing_aibom_denied {
	some msg in deny with input as no_model_sbom
	msg == "SBOM contains no model component (AIBOM missing)"
}

test_unlicensed_pypi_denied {
	some msg in deny with input as unlicensed_sbom
	startswith(msg, "component pybad has no declared SPDX license")
}

test_forbidden_license_denied {
	some msg in deny with input as agpl_sbom
	msg == "component evil-tool uses forbidden license AGPL-3.0-only"
}

test_license_name_accepted {
	# Syft emits some licenses as free-text `name` (e.g. LGPLv3) — must pass rule 1.
	no_violations(name_only_license_sbom)
}

test_forbidden_license_by_name_denied {
	some msg in deny with input as agpl_by_name_sbom
	contains(msg, "component evil-by-name uses forbidden license")
}

no_violations(sbom) {
	count(deny) == 0 with input as sbom
}

# --- Fixtures ---

clean_sbom := {
	"bomFormat": "CycloneDX",
	"components": [
		{
			"type": "library",
			"name": "fastapi",
			"purl": "pkg:pypi/fastapi@0.115.6",
			"licenses": [{"license": {"id": "MIT"}}],
		},
		{
			"type": "model",
			"name": "registry-demo-tiny",
			"version": "1.0.0",
			"properties": [
				{"name": "cdx:model:sha256", "value": "abc"},
				{"name": "cdx:model:source_url", "value": "https://example.com/model"},
			],
		},
	],
}

missing_provenance_sbom := {
	"components": [
		{
			"type": "model",
			"name": "registry-demo-tiny",
			"properties": [{"name": "cdx:model:framework", "value": "demo-inference"}],
		},
	],
}

no_model_sbom := {
	"components": [
		{
			"type": "library",
			"name": "fastapi",
			"purl": "pkg:pypi/fastapi@0.115.6",
			"licenses": [{"license": {"id": "MIT"}}],
		},
	],
}

unlicensed_sbom := {
	"components": [
		{
			"type": "library",
			"name": "pybad",
			"purl": "pkg:pypi/pybad@1.0",
			"licenses": [],
		},
	],
}

agpl_sbom := {
	"components": [
		{
			"type": "library",
			"name": "evil-tool",
			"purl": "pkg:pypi/evil-tool@1.0",
			"licenses": [{"license": {"id": "AGPL-3.0-only"}}],
		},
	],
}

name_only_license_sbom := {
	"components": [
		{
			"type": "library",
			"name": "autocommand",
			"purl": "pkg:pypi/autocommand@2.2.2",
			"licenses": [{"license": {"name": "LGPLv3"}}],
		},
		{
			"type": "model",
			"name": "registry-demo-tiny",
			"properties": [
				{"name": "cdx:model:sha256", "value": "abc"},
				{"name": "cdx:model:source_url", "value": "https://example.com/model"},
			],
		},
	],
}

agpl_by_name_sbom := {
	"components": [
		{
			"type": "library",
			"name": "evil-by-name",
			"purl": "pkg:pypi/evil-by-name@1.0",
			"licenses": [{"license": {"name": "AGPLv3"}}],
		},
	],
}