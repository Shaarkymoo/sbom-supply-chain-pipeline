# How This Pipeline Works

I built this pipeline because I wanted to answer one question for myself: *how do you actually know that the software you're about to deploy is the software you think you built?* The xz backdoor in 2024 was a reminder that the most dangerous code is the code you never looked at — the transitive dependency, the model file pulled from a URL, the image that could have been swapped between build and run.

This document explains every stage of the pipeline, why it exists, which attack class it catches, and how to read its outputs. It's written the way I reasoned through it — each decision has a reason, and the reasons are grounded in public standards rather than my opinion.

## The mental model: inventory → vet → sign → prove → deploy

The whole pipeline is five ideas in order. You can't skip a stage:

1. **Inventory** — you can't secure what you can't list. The SBOM is the inventory.
2. **Vet** — every item in the inventory gets checked: known vulnerabilities, licenses, provenance.
3. **Sign** — bind the artifact to an identity so it can't be swapped or replayed.
4. **Prove** — record *who built it, from what source, with what process* (provenance), publicly.
5. **Deploy** — only artifacts that survived all four previous stages are allowed to run.

Everything else in this repo is a concrete implementation of those five ideas.

---

## Stage 1 — Build

The demo target is an intentionally vulnerable AI app: a model registry with a chat endpoint. It's built into a container image with `python:3.12-slim` as the base.

**Why I made these choices:**

- **Slim base, non-root user, pinned exact versions.** A smaller image is a smaller attack surface; a non-root runtime user means a compromised app doesn't get root in the container; exact pins mean the build is reproducible and the SBOM is deterministic.
- **`gunicorn` with the `uvicorn` worker.** FastAPI is ASGI, and gunicorn's default worker is WSGI-only — running FastAPI under the wrong worker breaks request handling. The `-k uvicorn.workers.UvicornWorker` flag is the canonical production setup.
- **No torch, no GPU, no model downloads in CI.** The chat endpoint runs in a deterministic "demo mode" so the pipeline is hermetic — anyone can reproduce it without credentials or hardware. A real model is optional via `OLLAMA_BASE_URL`.

**What this stage catches:** nothing yet — but it establishes the foundation the later stages verify. You can only meaningfully scan, sign, and attest an image that was built in a known, reproducible way.

## Stage 2 — SBOM (Syft / CycloneDX)

I generate a Software Bill of Materials with **Syft** in the **CycloneDX** format:

```
syft <image> -o cyclonedx-json > sbom.cdx.json
```

**Why CycloneDX and not SPDX?** CycloneDX has a first-class `model` component type for machine-learning artifacts, which is exactly what I need for the AIBOM stage. The format is a JSON schema standard, so I can validate against it.

**Why this matters:** this is the *inventory*. The current image produces 130 components — the OS packages, the Python dependencies, and the model. Every one of those is a potential attack surface. Without this list, the rest of the pipeline is guessing.

## Stage 3 — AIBOM (model provenance)

This is the part that makes the project about AI specifically. A plain SBOM lists libraries; it says nothing about the *model*. My `scripts/build_aibom.py` reads `app/models/manifest.json` and merges CycloneDX `model` components into the SBOM, each carrying:

- `cdx:model:sha256` — the hash of the model artifact
- `cdx:model:source_url` — where the model came from
- `cdx:model:framework` — the runtime framework
- dataset hashes — what data the model was built against

The hashes are computed at build time from the actual shipped files, so the AIBOM records what's *really* in the image — not what we wish was there.

**Why this matters:** the AI analog of "you deploy what you built" is "you deploy the model you validated." If someone swaps a model between validation and deployment, the sha256 recorded here is how you'd catch it. The policy gate in Stage 6 *requires* these fields — a model without a hash or a source is rejected. That's the same discipline the app's vulnerable `/models/upload` endpoint fails to enforce, which is the point: the pipeline enforces what the application doesn't.

This also maps directly to India's CERT-In CISG-2024-02 guidance on AIBOMs, which I used as a reference.

## Stage 4 — Vulnerability scan (Trivy + CVSS)

**Trivy** compares every component in the image against public vulnerability databases:

```
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignorefile .trivyignore <image>
```

The gate fails the build on any **CRITICAL or HIGH** finding — the standard **CVSS** severity bands (FIRST.org).

**The honest part — my baseline.** When I first ran this, the gate found 40+ CRITICAL/HIGH findings. Most were real and fixable: `gunicorn` 20.1.0 had CVE-2024-1135 (HTTP request smuggling), plus CVEs in `fastapi`'s `starlette`, `python-multipart`, `setuptools`, and `wheel`. I fixed all of those by bumping pins — that's the "the gate caught a real problem" story, and it's in the git history.

But the base image itself (`python:3.12-slim` / Debian 13) ships with 8 unfixable HIGHs — `util-linux`, `ncurses`, `systemd`, `acl`, `perl` — **no upstream fix exists yet**. I made a deliberate choice: rather than either (a) hiding them with `--ignore-unfixed` or (b) letting the build be permanently red, I wrote an explicit **`.trivyignore`** listing exactly those 8 CVEs with a comment explaining each. The gate now fails on anything *new* or *fixable*, and the baseline is auditable — anyone can see exactly what I accepted and why. If one of those CVEs ever lands on the CISA KEV list (actively exploited), the next stage fails the build anyway.

## Stage 5 — CISA KEV gate

The `kev-gate.py` script reads Trivy's JSON output and fails the build if **any** vulnerability is present in the **CISA Known Exploited Vulnerabilities** catalog — the list of CVEs attackers are *actually using right now*.

**Why this is separate from CVSS:** CVSS scores severity ("how bad *could* this be?"). KEV answers a different question ("are attackers using it *today*?"). A CVE can be HIGH severity but never exploited; a MEDIUM can be in active weaponization. I want both signals. The KEV gate is deliberately strict — it ignores my baseline, because "actively exploited" trumps "no fix available yet."

## Stage 6 — Policy gate (Conftest / OPA)

**Conftest** runs Rego policies against the SBOM/AIBOM. This is where organizational rules get enforced as code. My policies (`policy/sbom.rego`) are driven by **public standards**, not my preferences:

- **License policy — SPDX + OSI.** Every Python component must declare a license (an SPDX ID, an SPDX expression, or a declared name — I learned syft emits all three forms). The policy denies a forbidden set (AGPL, BUSL, Elastic License, SSPL — strong copyleft / source-available licenses I don't want in this project). This is the same data source commercial license-compliance tools use.
- **AIBOM provenance.** At least one `model` component must exist, and every model must carry `cdx:model:sha256` and `cdx:model:source_url`. This is the policy counterpart to the app's vulnerable upload endpoint.
- **Tests.** `policy/sbom_test.rego` has 7 test cases covering each rule, including the name-based license form that tripped me up. Policies are code; they get tests.

The policy caught a real false positive during development — `autocommand` ships its license as the name `LGPLv3` (free text) rather than an SPDX ID, and my first policy only checked IDs. That was a genuine policy bug, and the fix (accept declared names, match the forbidden list against names too) is the kind of thing only real usage surfaces.

## Stage 7 — Sign (cosign / Sigstore, keyless)

```
cosign sign --yes <image>
```

**Keyless** means there is no long-lived private key to lose or leak. Identity comes from a short-lived certificate issued by Sigstore's **Fulcio** CA, bound to an OIDC identity:

- **Locally**, cosign picks up ambient GitHub credentials, so the certificate is bound to my GitHub identity (`<id>+Shaarkymoo@users.noreply.github.com`). No browser dance needed.
- **In GitHub Actions**, the workflow signs with the GitHub Actions OIDC identity — the certificate is bound to the *workflow*, not a person.

Every signature is written to **Rekor**, Sigstore's public transparency log, so there's a timestamped, auditable record that the image was signed at time T. My local runs have real Rekor entries.

**Why this matters:** a tampered image fails signature verification. And because it's keyless, the operational excuse "signing is too hard, we'd have to manage keys" disappears.

## Stage 8 — Attest (SLSA provenance)

```
cosign attest --type slsaprovenance1 --predicate slsa-provenance.json <image>
```

This attaches an **in-toto attestation** with an **SLSA v1 provenance predicate**: what built the image, from what source, with what process, at what time. It answers "who built this, from what, how" — the provenance half of SLSA.

**A trap I hit:** `cosign attest` expects the *bare predicate* — not the full in-toto Statement wrapper (that's `sigstore/cosign#3757`). The predicate file must be just `buildDefinition` + `runDetails`, and cosign builds the statement around it. Getting this wrong produces the cryptic "provenance predicate: required field builder missing."

I claim **SLSA Level 1–2** honestly: Level 1 (scripted, reproducible build) and Level 2 (provenance attesting to source and build process). Level 3–4 would require hardened, isolated build infrastructure — a real investment I'm not claiming.

## Stage 9 — Deploy (the gate)

```
scripts/deploy-local.sh   # cosign verify + verify-attestation, then docker run
```

Deployment is the last gate, not an afterthought. `deploy-local.sh` **refuses to run an image that isn't both signed and attested**. I tested this literally: an unsigned image fails with `no signatures found` and exits 10. When the GitHub workflow pushes to GHCR, the same verify happens in CI, and a documented optional path exists for Cloud Run using the identical gated pattern.

## How to audit this project yourself

You don't need to trust me — `scripts/verify.sh` is written for a stranger:

```bash
IMAGE=localhost:5000/ai-model-registry:dev \
  CERT_IDENTITY="<my-github-noreply-identity>" \
  CERT_ISSUER=https://github.com/login/oauth \
  bash scripts/verify.sh
```

It verifies the signature against the transparency log, verifies the SLSA attestation, and scans for CRITICAL/HIGH vulnerabilities — three checks, no secrets, no keys.

## Standards index

| Standard | Where I use it |
|---|---|
| SPDX (spdx.org) | License identifiers in the SBOM + policy |
| OSI (opensource.org) | Approved-license reference for policy |
| CVSS (FIRST.org) | Severity bands for the Trivy gate |
| CISA KEV | Actively-exploited gate |
| CycloneDX | SBOM format + `model` components (AIBOM) |
| SLSA (slsa.dev) | Provenance level claim (1–2) |
| NIST SSDF (SP 800-218) | Framework the case study maps controls to |
| CERT-In CISG-2024-02 | AIBOM guidance the AIBOM stage follows |