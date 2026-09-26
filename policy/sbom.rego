package main

import future.keywords.in

# Standard-driven data: SPDX license IDs (spdx.org), OSI-approved set,
# and a deny-list of licenses this project forbids.
forbidden_licenses := {"AGPL-3.0-only", "AGPL-3.0-or-later", "BUSL-1.1", "Elastic-2.0"}

# 1. Language-package components must declare an SPDX license.
deny[msg] {
	comp := input.components[_]
	startswith(comp.purl, "pkg:pypi/")
	not has_declared_license(comp)
	msg := sprintf("component %s has no declared SPDX license", [comp.name])
}

has_declared_license(comp) {
	comp.licenses[_].license.id
}

has_declared_license(comp) {
	comp.licenses[_].expression
}

# 2. No component may use a forbidden license.
deny[msg] {
	comp := input.components[_]
	lic := comp.licenses[_].license.id
	forbidden_licenses[lic]
	msg := sprintf("component %s uses forbidden license %s", [comp.name, lic])
}

# 3. AIBOM: at least one model component must exist.
deny[msg] {
	count([c | c := input.components[_]; c.type == "model"]) == 0
	msg := "SBOM contains no model component (AIBOM missing)"
}

# 4. Every model component must carry provenance (sha256 + source_url).
deny[msg] {
	comp := input.components[_]
	comp.type == "model"
	not has_provenance(comp)
	msg := sprintf("model %s lacks provenance (cdx:model:sha256 / cdx:model:source_url)", [comp.name])
}

has_provenance(comp) {
	comp.properties[_].name == "cdx:model:sha256"
	comp.properties[_].name == "cdx:model:source_url"
}