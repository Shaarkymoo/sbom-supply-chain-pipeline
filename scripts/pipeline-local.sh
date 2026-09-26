#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-ghcr.io/<username>/ai-model-registry:dev}"
ART="$REPO_ROOT/artifacts"
mkdir -p "$ART" "$REPO_ROOT/devlog"

step() { printf '\n=== %s ===\n' "$*"; }

step "1/8 Build image"
docker build -t "$IMAGE" -f "$REPO_ROOT/app/Dockerfile" "$REPO_ROOT"

step "2/8 SBOM (Syft, CycloneDX)"
syft "$IMAGE" -o cyclonedx-json > "$ART/sbom.cdx.json"

step "3/8 AIBOM merge"
python "$REPO_ROOT/scripts/build_aibom.py" \
  --sbom "$ART/sbom.cdx.json" \
  --manifest "$REPO_ROOT/app/models/manifest.json" \
  --output "$ART/sbom-aibom.cdx.json"

step "4/8 Trivy scan (CVSS CRITICAL/HIGH gate)"
trivy image --exit-code 1 --severity CRITICAL,HIGH --format json --output "$ART/trivy.json" "$IMAGE"

step "5/8 CISA KEV gate"
python "$REPO_ROOT/scripts/kev-gate.py" "$ART/trivy.json"

step "6/8 Policy gate (Conftest, SPDX/OSI + AIBOM)"
conftest test "$ART/sbom-aibom.cdx.json" -p "$REPO_ROOT/policy"

if [[ "${SKIP_SIGN:-0}" == "1" ]]; then
  step "7-8/8 SKIPPED (SKIP_SIGN=1) - keyless signing/attestation is interactive"
else
  step "7/8 Keyless sign (cosign, personal OIDC -> Rekor)"
  cosign sign --yes "$IMAGE"

  step "8/8 SLSA attestation (cosign attest, SLSA v1 predicate)"
  DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE" | cut -d@ -f2)"
  cat > "$ART/slsa-provenance.json" <<EOF
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [{"name": "$IMAGE", "digest": {"sha256": "${DIGEST#sha256:}"}}],
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/<username>/sbom-supply-chain-pipeline/local-pipeline/v1",
      "externalParameters": {},
      "internalParameters": {"script": "scripts/pipeline-local.sh"}
    },
    "runDetails": {
      "builder": {"id": "local"},
      "metadata": {"invocationId": "$(date -u +%Y%m%dT%H%M%SZ)"}
    }
  }
}
EOF
  cosign attest --yes --predicate "$ART/slsa-provenance.json" --type slsaprovenance "$IMAGE"
fi

step "PIPELINE GREEN"
cp "$ART"/*.json "$REPO_ROOT/devlog/"
echo "Evidence saved to devlog/"