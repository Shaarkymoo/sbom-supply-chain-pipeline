# Case Study — Securing an AI Application's Supply Chain

## The hook

In March 2024, a backdoor was planted in `xz-utils` — a compression library so ubiquitous it ships with almost every Linux distribution. It was caught by a developer noticing a two-year-old slowdown of a few hundred milliseconds on his SSH logins. Most organizations won't have that luck. I built this pipeline because I wanted to know, for my own projects: *how do you verify that the software you deploy is the software you actually built?*

This is the story of that pipeline, how I used it, and what it caught.

## The problem

Software has a supply chain, and most of it is invisible. When you build a container image, you're inheriting hundreds of components you never wrote — OS packages, language libraries, and for AI applications, model files. Attackers know this. The attack classes are well-documented:

- **Dependency compromise** — a malicious or compromised package enters the build
- **Tampered artifact** — the image is modified between build and deploy
- **Model poisoning** — the AI artifact is swapped after validation
- **Unverified ingestion** — the app accepts artifacts nobody checked (this one is literally a feature of my demo app)

Against that, "we use Docker" isn't an answer. The answer is: inventory, verify, sign, attest, deploy — and make every step checkable.

## The pipeline — what I built and how I used it

I wrote a deliberately vulnerable AI application — a model registry with a chat endpoint — and wrapped it in an eight-stage pipeline. Running it is one command:

```bash
bash scripts/pipeline-local.sh
```

**Stage by stage, what happened when I actually used it:**

**1. Build.** `python:3.12-slim`, non-root runtime user, exact pins.

**2. SBOM.** Syft produced a CycloneDX inventory — 130 components in my image. You can't scan what you don't list.

**3. AIBOM.** My `build_aibom.py` merged the model's metadata — hash, source, framework, dataset hashes — into the SBOM as CycloneDX `model` components. This is the AI-specific part, and it follows India's CERT-In CISG-2024-02 guidance.

**4. Trivy scan.** This is where the pipeline earned its keep. The first run failed with **40+ CRITICAL/HIGH findings**. The gate had caught real problems in dependencies I'd pinned: `gunicorn` 20.1.0 (CVE-2024-1135, HTTP request smuggling), CVEs in `starlette`, `python-multipart`, `setuptools`, and `wheel`. I bumped every one of them — that remediation is a visible commit in the history, not a claim.

**5. CISA KEV gate.** A second, stricter check: does any finding appear in the list of *actively exploited* CVEs? CVSS says how bad something could be; KEV says attackers are using it today.

**6. Policy gate.** Conftest enforced license and provenance rules grounded in SPDX/OSI data — and caught its own false positive during development (a package whose license is stored as a name, not an ID). The policy now has 7 test cases.

**7. Sign.** Keyless cosign signing — no private key to leak. Locally it bound to my GitHub identity; in CI it binds to the workflow. Every signature lands in Rekor, the public transparency log.

**8. Attest.** SLSA v1 provenance: who built it, from what source, with what process.

Then the deploy gate: only signed + attested images run. I tested the refusal path — an unsigned image fails with `no signatures found`.

## The verification demo — you can check me

The point of keyless signing is that verification needs no secrets. Run this yourself:

```bash
IMAGE=localhost:5000/ai-model-registry:dev \
  CERT_IDENTITY="142115441+Shaarkymoo@users.noreply.github.com" \
  CERT_ISSUER=https://github.com/login/oauth \
  bash scripts/verify.sh
```

Three checks: signature verified against the transparency log, SLSA attestation verified, vulnerabilities scanned. My local runs have real Rekor entries — the `logIndex` is public.

## Alignment with recognized frameworks

This isn't a set of invented rules. Each control maps to a standard an auditor would recognize:

| Control | Framework |
|---|---|
| Provenance + build integrity | SLSA Level 1–2 |
| SBOM generation | US EO 14028 / EU CRA requirement; CERT-In CISG-2024-02 |
| AIBOM (model components) | CERT-In CISG-2024-02 |
| Secure development lifecycle | NIST SSDF (SP 800-218) — inventory (PW.4), verify (PS.1/PS.2), provenance (RV.1) |
| License compliance | SPDX + OSI data |
| Vulnerability severity | CVSS (FIRST.org) |
| Actively-exploited awareness | CISA KEV catalog |

## Honest limitations

- **The app is still vulnerable by design.** The pipeline secures the supply chain; it doesn't fix prompt injection or SSRF in the app. That boundary is intentional and documented in the threat model.
- **I claim SLSA Level 1–2.** Level 3–4 requires hardened, isolated build infrastructure — a real investment, and I'm not pretending otherwise.
- **The base image carries unfixable CVEs.** I baseline them in an explicit, commented `.trivyignore` rather than hiding them — and the KEV gate overrides the baseline if any is ever actively exploited.
- **No runtime detection.** The pipeline guarantees what you deploy is what you built; it doesn't watch what the app does afterward.

## What I learned

- **Supply-chain security is mostly inventory + verification, not magic.** The SBOM makes the invisible visible; the signatures make claims checkable. Everything else is discipline around those two facts.
- **The gate catching real findings is the feature.** My "clean" dependency pins had 40+ CRITICAL/HIGH issues. The pipeline turned that from a surprise into a fix.
- **Keyless signing removes the biggest excuse.** "We don't sign because key management is hard" doesn't survive contact with Sigstore.
- **For AI, provenance starts with the model.** A model registry that accepts unverified uploads has a supply-chain vulnerability in its core — and the same discipline that secures libraries extends to models.