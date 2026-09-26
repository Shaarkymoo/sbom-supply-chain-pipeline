#!/usr/bin/env bash
# Third-party audit: verify signature, attestation, and vulnerabilities.
set -euo pipefail
IMAGE="${1:-ghcr.io/<username>/ai-model-registry:dev}"

# Keyless verification identity. Defaults match the GitHub Actions workflow
# identity (repo signed on push). For local personal-OIDC signing, override:
#   CERT_IDENTITY=you@example.com CERT_ISSUER=https://accounts.google.com
CERT_IDENTITY="${CERT_IDENTITY:-https://github.com/<username>/sbom-supply-chain-pipeline/.github/workflows/*}"
CERT_ISSUER="${CERT_ISSUER:-https://token.actions.githubusercontent.com}"

echo "== Signature (cosign, Rekor) =="
cosign verify --certificate-identity "$CERT_IDENTITY" --certificate-oidc-issuer "$CERT_ISSUER" "$IMAGE"

echo "== SLSA attestation =="
cosign verify-attestation --type slsaprovenance \
  --certificate-identity "$CERT_IDENTITY" --certificate-oidc-issuer "$CERT_ISSUER" "$IMAGE"

echo "== Vulnerabilities (CRITICAL/HIGH) =="
trivy image --severity CRITICAL,HIGH "$IMAGE"