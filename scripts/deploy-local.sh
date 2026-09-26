#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-ghcr.io/<username>/ai-model-registry:dev}"
PORT="${PORT:-8000}"
CONTAINER="${CONTAINER:-ai-model-registry}"

# Keyless verification identity. Defaults match the GitHub Actions workflow
# identity (repo signed on push). For local personal-OIDC signing, override:
#   CERT_IDENTITY=you@example.com CERT_ISSUER=https://accounts.google.com
CERT_IDENTITY="${CERT_IDENTITY:-https://github.com/<username>/sbom-supply-chain-pipeline/.github/workflows/*}"
CERT_ISSUER="${CERT_ISSUER:-https://token.actions.githubusercontent.com}"

step() { printf '\n=== %s ===\n' "$*"; }

step "1/3 Verify signature (Rekor-backed)"
cosign verify --certificate-identity "$CERT_IDENTITY" --certificate-oidc-issuer "$CERT_ISSUER" "$IMAGE"

step "2/3 Verify SLSA attestation"
cosign verify-attestation --type slsaprovenance \
  --certificate-identity "$CERT_IDENTITY" --certificate-oidc-issuer "$CERT_ISSUER" "$IMAGE"

step "3/3 Deploy (only signed + attested images reach runtime)"
docker rm -f "$CONTAINER" 2>/dev/null || true
docker run -d --name "$CONTAINER" -p "$PORT:8000" "$IMAGE"
echo "Deployed $IMAGE on http://localhost:$PORT"