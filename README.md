<p align="center">
  <img src="assets/veritas-mesh.png" alt="Veritas Mesh banner" width="100%">
</p>

<h1 align="center">Veritas Mesh</h1>

<p align="center">
  <strong>An open protocol for verifiable institutional compliance —<br>proving that a rule was followed, without exposing the data behind it.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <a href="SECURITY.md"><img alt="Security Policy" src="https://img.shields.io/badge/security-policy-green"></a>
  <a href="GOVERNANCE.md"><img alt="Governance" src="https://img.shields.io/badge/governance-RFC--driven-purple"></a>
  <a href="ROADMAP.md"><img alt="Status" src="https://img.shields.io/badge/status-pre--alpha%20research-orange"></a>
  <a href="CITATION.cff"><img alt="Citation" src="https://img.shields.io/badge/cite-CITATION.cff-lightgrey"></a>
  <a href="DONATE.md"><img alt="Sponsor" src="https://img.shields.io/badge/sponsor-open%20collective-ff69b4"></a>
</p>

---

## Why this project exists

Every regulated institution — a bank, a hospital, a public agency — is routinely asked to *prove* that it followed a rule: an anti-money-laundering check, a patient-safety protocol, a supply-chain integrity control, a security audit. Today that proof almost always takes one of two forms:

1. A **document trail** that a human auditor reads, trusts, and signs off on, or
2. A **raw data disclosure** — the transaction, the patient record, the internal system log — handed to a third party so they can verify it themselves.

Both are expensive, slow, and — more importantly — both force the institution to choose between *proving compliance* and *protecting the people and data it is responsible for*. There is no mature, open, cryptographically verifiable standard that lets an institution do both at once: generate a mathematical proof that a rule was satisfied, publishable and independently verifiable by any auditor or regulator, without revealing the underlying record.

The cryptographic primitives to do this — zero-knowledge proofs, verifiable computation — have existed for years. What does not yet exist is an open, audited, production-oriented **protocol and reference implementation** that applies them to institutional compliance as a first-class citizen, the way TLS did for transport security or OAuth did for authorization.

**Veritas Mesh is an attempt to build that missing layer.**

## What it is — and what it is not

Veritas Mesh is a protocol and reference implementation for **verifiable attestations**: cryptographically signed proofs that a specific rule, policy, or invariant held true for a specific institutional action, without disclosing the private inputs to that action.

- It is **not** a blockchain, a cryptocurrency, or a token.
- It is **not** a compliance product for a single jurisdiction — it is designed so that jurisdiction-specific rules (Basel III, HIPAA, GDPR, NIST 800-53, supply-chain attestation frameworks) can be expressed as pluggable rule modules on top of a common, formally specified core.
- It has **no offensive security or weapons-related capability**, and none will be added. Where the project intersects with defense and government use cases, it is scoped strictly to defensive and integrity-verification concerns — supply-chain attestation, security-control verification, audit-trail integrity — never to operational or targeting systems of any kind.
- It is, today, a **research-stage project**. See [Project Status](#project-status) below for an unvarnished account of what exists and what does not.

## Design philosophy

- **Formal specification before implementation.** Security-relevant properties are stated and, where feasible, mechanically checked (TLA+ / formal methods) *before* the corresponding code is written — not asserted afterward.
- **The heavy lifting is done in the language built for it.** Following the same division of labor used by the largest infrastructure projects in the world: cryptographic and performance-critical code is written in a memory-safe systems language; orchestration, integration, and interfaces are written in the languages best suited to those jobs. See [Architecture](#architecture).
- **Verifiability over trust.** Every claim this project makes about itself — build status, test coverage, security posture, protocol properties — is meant to be independently checkable by a stranger, not taken on faith.
- **Radical honesty about maturity.** This README will always describe the current state of the code accurately, including what is incomplete, unproven, or merely planned. A project asking institutions to trust cryptographic proofs cannot itself be built on overstated claims.
- **Public good, openly governed.** Veritas Mesh is released under Apache-2.0 with an explicit patent grant, developed in the open, and governed through a public RFC process (see [GOVERNANCE.md](GOVERNANCE.md)).

## Architecture

The system is deliberately polyglot, with each layer implemented in the language best matched to its constraints:

| Layer | Language | Why |
|---|---|---|
| **Proof engine & cryptographic core** (`core/`) | **Rust** | Security-critical, memory-safety-critical code. A single memory-safety bug in a proof engine that banks and hospitals rely on is not an acceptable risk — the same reasoning that led the Linux kernel to accept Rust for driver code. |
| **Risk analysis & institutional connectors** (`analysis/`) | **Python** | Fast iteration on scoring models and anomaly detection, and the most practical language for integrating with the legacy systems that banks and hospitals actually run today. |
| **Attestation mesh network** (`mesh/`) | **Go** | A network of institutions, auditors, and regulators exchanging proofs needs massive concurrency and partition tolerance — the same requirements that shaped Kubernetes and Docker. |
| **Auditor & regulator dashboard** (`dashboard/`) | **TypeScript + React** | Strict typing for an interface where a rendering bug could lead to a misread compliance decision. |
| **Cross-language contracts** (`proto/`) | **Protocol Buffers / gRPC** | Every message format is defined once, language-agnostically, so any institution or vendor can build a conformant client in the language of their choice. |

```text
veritas-mesh/
├── core/            Rust — proof engine, attestation state machine, crypto primitives
├── analysis/         Python — risk scoring, anomaly detection, institutional connectors
├── mesh/             Go — peer-to-peer attestation network
├── dashboard/        TypeScript/React — auditor & regulator interface
├── proto/            Protocol Buffers — the cross-language contract
├── spec/             Formal protocol specification, threat model, formal-methods artifacts
├── compliance-mappings/   How the protocol maps to real regulatory frameworks
├── sdk/              Per-language SDKs generated from proto/
├── rfcs/             RFC process and accepted/proposed changes
└── docs/             Project and protocol documentation
```

## Project Status

| Area | Status |
|---|---|
| Protocol specification | Early draft — core attestation model defined, formal proofs in progress |
| Proof engine (`core/`) | Design phase — no production code yet |
| Risk/analysis layer (`analysis/`) | Not started |
| Mesh network (`mesh/`) | Not started |
| Dashboard | Not started |
| Compliance mappings | Not started |
| Formal verification (TLA+) | Not started |
| Security audit | Not performed — **do not use in production or for any real compliance decision until an independent audit has been completed and published** |

This project is at the earliest possible stage: a specification and an architecture, not yet a working system. Anyone contributing code, reviewing the specification, or simply pointing out where this document overpromises is doing exactly the kind of work the project needs most right now.

## Getting Involved

Veritas Mesh needs cryptographers, formal-methods researchers, Rust and Go engineers, people with real-world experience in banking compliance, healthcare data governance, or government supply-chain security, and technical writers willing to keep this project honest as it grows.

- Read [GOVERNANCE.md](GOVERNANCE.md) for how decisions are made and how the RFC process works.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
- Read [SECURITY.md](SECURITY.md) before reporting anything security-relevant — **please do not open a public issue for a security concern.**
- Read [spec/THREAT_ANALYSIS.md](spec/THREAT_ANALYSIS.md) to understand what this protocol is, and is explicitly not, designed to defend against.
- Read [BENCHMARKS.md](BENCHMARKS.md) for real, actually-executed timing numbers on the parts of this repository that are real cryptography today — and an explicit note on which parts are deliberately not benchmarked as if they were (see `core/`'s documented placeholder backends in [STATUS.md](STATUS.md)).

## Support the Project

Veritas Mesh is independent, self-funded, public-interest research. It is not backed by a corporation, a government grant, or a venture fund. Contributions — of time, code, review, or funding — directly determine how fast this becomes real. See [DONATE.md](DONATE.md) for current, official funding channels.

## Author & Maintainer

Veritas Mesh was founded and is maintained by **Ciprian Ştefan Pleşca**, an independent Romanian researcher and freelance software engineer, developed as public-interest, self-funded research for the benefit of humanity, with no institutional affiliation. See [AUTHORS.md](AUTHORS.md) for the full contributor list and [CITATION.cff](CITATION.cff) for how to cite this work.

## License

Released under the [Apache License 2.0](LICENSE), chosen specifically for its explicit patent grant — a deliberate choice for a project whose founder intends this to remain free, in perpetuity, for any individual, institution, or government to use, study, modify, and redistribute.
