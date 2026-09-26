# Threat Model

This is my working threat model for the pipeline: the supply-chain attack scenarios I care about, and the specific control that catches each one. I wrote it as a mapping to public standards so the controls are auditable, not vibes.

## Attack scenarios → controls

| Scenario | What the attacker does | Control | Standard it's grounded in |
|---|---|---|---|
| Known vulnerable dependency | Ships a package with a published CVE | Trivy gate (CRITICAL/HIGH) | CVSS severity bands |
| Actively-exploited CVE | Uses a CVE attackers are weaponizing *today* | CISA KEV gate | CISA KEV catalog |
| Tampered artifact | Swaps/modifies the image after build | `cosign sign` + `cosign verify` | Sigstore / Rekor |
| Model poisoning | Replaces the model between validation and deploy | AIBOM sha256 + provenance policy | CycloneDX `model` components |
| Unlicensed / forbidden dependency | Ships code with a license the org can't accept | Conftest license policy | SPDX / OSI |
| Unknown contents | Ships an image with no inventory | SBOM (Syft) + CycloneDX schema validation | CycloneDX |
| Unverified model ingestion | Uploads a model with no provenance to the app | Policy denies models missing hash/source | SLSA provenance discipline |
| Repudiated build | "That's not the build we made" | SLSA provenance attestation | SLSA Levels 1–2 |
| Secret leak in repo | Commits a credential | Gitleaks (pre-commit + CI) + gitignore | — |

## Application-layer vulnerabilities (the demo target, intentionally unfixed)

These are in the app *on purpose* — the app is the victim, not the product:

| Vulnerability | Where | Why it's there |
|---|---|---|
| Prompt injection | `POST /chat` — "ignore previous instructions" leaks the hidden system prompt | The recognizable AI vulnerability; the two-layer evaluator flags the leak |
| Unverified model ingestion | `POST /models/upload` — accepts any file | The supply-chain vuln: the app's flaw and the pipeline's fix are the same discipline |
| SSRF | `POST /models/fetch` — fetches any URL | Demonstrated against a local target in tests |
| Path traversal | `GET /models/{id}/serve` — id interpolated into a path | Classic web vuln, documented via tests |

The case study is honest about this boundary: the pipeline secures the *supply chain* (what's in the image, where it came from, whether it's signed and attested). It does **not** fix application-layer bugs. "Attack the app's own bugs all you want — you can only ever deploy the exact artifact we built, scanned, signed, and attested."

## Controls that intentionally do NOT fail the build

The `.trivyignore` baseline. I accept 8 CVEs inherited from the `python:3.12-slim` base image (`util-linux`, `ncurses`, `systemd`, `acl`, `perl`) because **no upstream fix exists** — failing the build on them would make the pipeline permanently red without changing anything. The baseline is explicit and commented so it can be audited, and the CISA KEV gate overrides it: if any of those CVEs is ever added to the actively-exploited catalog, the build fails regardless.

## What this does NOT cover (honest scope)

- **Runtime detection** — the pipeline stops at deployment. What the app does at runtime (anomaly detection, drift) is out of scope.
- **SLSA Level 3–4** — hardened, isolated, hermetic build infrastructure. I claim 1–2.
- **Upstream maintainer compromise** — if the `transformers` maintainer ships malware, the scan catches the CVE *after* publication; it can't prevent the compromise itself. The SBOM's job is to make the blast radius visible.
- **Application-layer fixes** — deliberately out of scope (see above).

## Why this map is useful

Every control in the left column is checkable: run the command, read the output, see the Rekor entry. That's the difference between "I added security tools" and "I can show you, step by step, which control catches which attack."