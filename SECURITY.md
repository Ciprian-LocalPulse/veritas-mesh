# Security Policy

Veritas Mesh is designed for use by institutions — banks, hospitals, government agencies — for whom a security failure is not an inconvenience but a potential breach of financial, medical, or national-security consequence. This policy exists to make sure that vulnerabilities reach the people who can fix them before they reach anyone who could exploit them.

**Founding author & maintainer:** Ciprian Ştefan Pleşca, independent Romanian researcher and freelance software engineer, developed as public-interest research for the benefit of humanity, with no institutional affiliation.

---

## Project Status Notice

Veritas Mesh is currently in an early, pre-audit research stage (see the [Project Status](README.md#project-status) table in the README). **No component of this project has undergone independent security audit.** Nothing in this repository should be deployed for a real compliance, financial, medical, or governmental decision until an audit has been completed and published under [`docs/audits/`](docs/audits/). This section will be updated the moment that changes.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue, pull request, or discussion for a security vulnerability.** Public disclosure before a fix is available puts every downstream institutional user at risk.

### How to report

1. **Preferred: private security advisory.** Use GitHub's [private vulnerability reporting](../../security/advisories/new) feature on this repository. This creates a private channel between you and the maintainers and lets us coordinate a fix and disclosure timeline directly.
2. **Alternative: encrypted email.** Send a report to the security contact listed in [`SECURITY_CONTACTS.md`](SECURITY_CONTACTS.md), encrypted with the PGP key published there. Do not send vulnerability details over an unencrypted channel.

### What to include

To help us triage quickly, please include as much of the following as you can:

- A clear description of the vulnerability and its potential impact.
- The affected component (`core/`, `analysis/`, `mesh/`, `dashboard/`, `sdk/`, or the protocol specification itself).
- Steps to reproduce, a proof-of-concept, or a minimal failing case.
- Whether the issue affects the *protocol design* (i.e., it would exist in any correct implementation) or a *specific implementation bug*.
- Your assessment of severity, and why — we use this as a starting point, not a final answer.

### What happens next

| Stage | Target timeline |
|---|---|
| Acknowledgment of your report | Within 72 hours |
| Initial severity assessment and triage | Within 7 days |
| Regular status updates to the reporter | At least every 14 days until resolution |
| Fix developed and privately reviewed | Timeline depends on severity — see below |
| Coordinated disclosure | By mutual agreement, typically 90 days from initial report, or sooner once a fix ships |

We follow coordinated disclosure norms consistent with [CVE](https://www.cve.org/) practice and the disclosure guidelines used by major open-source foundations (CNCF, Apache Software Foundation). If a fix genuinely requires more than 90 days — for example, a flaw in the underlying protocol specification rather than a single implementation — we will communicate that explicitly to the reporter rather than let the deadline pass silently.

### Severity guidance

We use a framework based on [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document), with additional weight given to:

- **Soundness failures in the proof engine** (a false attestation can be generated or a valid one forged) — treated as **Critical**, regardless of CVSS score, because they undermine the entire trust model of the protocol.
- **Privacy failures** (private inputs to a proof are recoverable, even partially, from a published attestation) — treated as **Critical**, for the same reason.
- **Implementation bugs that don't affect protocol soundness** (a denial-of-service in a reference `mesh` node, a dashboard rendering issue) — scored normally under CVSS.

### Recognition

Reporters of valid vulnerabilities will be credited in the fix's release notes and in [`docs/audits/hall-of-fame.md`](docs/audits/hall-of-fame.md), unless they prefer to remain anonymous. This project does not currently offer a paid bug bounty — see [DONATE.md](DONATE.md) if you'd like to help change that.

---

## Supported Versions

Veritas Mesh has not yet reached a `1.0` release. Until it does, only the `main` branch is supported, and there are no compatibility or backport guarantees. This table will be populated with a real support matrix at the first tagged pre-release.

| Version | Supported |
|---|---|
| `main` (unreleased) | ✅ |
| — | — |

---

## Scope

### In scope

- The protocol specification in [`spec/`](spec/), including its formal-methods artifacts.
- All reference implementation code in `core/`, `analysis/`, `mesh/`, `dashboard/`, and `sdk/`.
- Build, packaging, and release infrastructure (CI workflows, dependency manifests, container images, signing/attestation of releases).
- Documentation, where inaccurate security claims could mislead an adopter into an unsafe deployment.

### Out of scope

- Third-party dependencies with their own upstream security process — please report these directly upstream, though we'd appreciate a heads-up so we can track exposure.
- Vulnerabilities requiring physical access to a deployed institution's infrastructure, which are the responsibility of that institution's own security program.
- Social engineering of maintainers or contributors.

### Explicitly out of bounds for this project's design

Consistent with the project's [threat model](spec/THREAT_ANALYSIS.md), Veritas Mesh will not accept, and does not want, contributions or reports oriented toward offensive capability, weapons systems, or operational targeting of any kind — including from government or defense-sector contributors. The project's defense- and government-relevant scope is limited strictly to defensive integrity verification (supply-chain attestation, security-control verification, audit-trail integrity). Reports attempting to extend the project beyond that scope will be declined regardless of severity framing.

---

## Supply Chain & Release Integrity

As the project matures toward its first releases, the following controls are planned and will be documented here as they land:

- Signed releases via [Sigstore](https://www.sigstore.dev/)/`cosign`.
- A Software Bill of Materials (SBOM) published with every release.
- Reproducible builds for the `core/` proof engine.
- Dependency review automation in CI for all five language ecosystems in this repository.

### Dependency alert triage log

Routine dependency-vulnerability triage, not a formal audit (see
[`docs/audits/`](docs/audits/) for what that means once Phase 4 is
reached) — logged here because "we looked into the alerts" is a claim
that should be checkable, not just asserted.

- **2026-08.** GitHub reported 5 alerts (1 critical, 1 high, 3 moderate)
  on `main`. Root-caused to a single upstream issue:
  [GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99)
  (esbuild ≤0.24.2, dev-server CORS, upstream-rated Moderate) — pulled in
  transitively by `vite@^5.4.0` in both `dashboard/package.json` and
  `sdk/typescript/package.json`. `npm`'s advisory graph assigns
  higher severity labels to several packages downstream in the same
  chain (`vite`, `vite-node`, `@vitest/mocker`, `vitest`) that merely
  *depend on* the vulnerable `esbuild`, which is why 1 root cause showed
  up as 5 separate alerts. **Fix applied:** an `overrides` entry pinning
  `esbuild` to `^0.25.0` in both `package.json` files, keeping
  `vite@5.4.21` (already the version that fixes the unrelated
  [CVE-2025-62522](https://github.com/advisories/GHSA-93m4-6634-74q7)
  Windows path-traversal issue, so no separate action needed there).
  Verified, not assumed: `npm install`, `tsc --noEmit`, and the existing
  test suites pass in both packages after the override.
  **Explicitly rejected:** `npm audit fix --force` (which upgrades to
  `vite@8.2.0`/`vitest@4.1.10`) resolves every alert on paper, but was
  tested and found to genuinely break `dashboard/`'s production build
  (`vite build` fails with `Cannot resolve entry module index.html`) and
  carries an unresolved peer-dependency conflict (`@vitejs/plugin-react@4.7.0`
  does not declare support for `vite@8`). Left as a real, larger
  migration for whenever `dashboard/` is actively worked on next, not
  applied blindly for the sake of a clean `npm audit` output.
  **Separate finding, not a dependency issue:** `dashboard/` has no
  `index.html` at all, so `vite build` fails regardless of dependency
  versions — a pre-existing gap in the scaffold, unrelated to this
  triage, flagged here because it surfaced while testing the fix above.

## Questions

For anything that isn't a vulnerability report — general security architecture questions, threat-model discussion, audit coordination — please open a public [GitHub Discussion](../../discussions) instead. Keeping that separate from the private reporting channel helps us keep genuine vulnerability reports moving fast.
