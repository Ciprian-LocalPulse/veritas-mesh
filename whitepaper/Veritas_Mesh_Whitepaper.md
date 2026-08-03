# Veritas Mesh
### An Open Protocol for Verifiable Institutional Compliance

**Version 0.1 — Draft**

**Author:** Ciprian Ştefan Pleşca, Independent Researcher, Romania
**License:** Apache-2.0
**Status:** Research draft. This document describes a proposed protocol and target architecture. As stated plainly in the project [README](../README.md), no component has been implemented or audited yet. Every claim below is a design goal or a proposed mechanism, not a demonstrated result, unless explicitly marked otherwise.

---

## Abstract

Regulated institutions — banks, hospitals, and government agencies — are routinely required to prove that they followed a rule, without a practical way to do so that protects the underlying data. The dominant model today forces a binary choice: either a human auditor trusts a document trail, or the institution discloses raw records — transactions, patient data, internal logs — to a third party so the third party can check them directly. Neither option scales, and both create unnecessary exposure of sensitive data as a side effect of proving something that, in principle, requires no such exposure.

This paper proposes **Veritas Mesh**, an open protocol for generating and verifying cryptographic **attestations**: machine-checkable proofs that a specific institutional action satisfied a specific rule, without revealing the private inputs to that action. The protocol is built on established zero-knowledge and verifiable-computation primitives, applied not as a novel cryptographic contribution but as an engineering and standardization effort — the goal is to do for verifiable compliance what TLS did for transport security: take primitives that already exist and turn them into a boring, well-specified, widely adopted layer that institutions can build on without having to become cryptography experts themselves.

We describe the problem in detail, survey the closest existing approaches and why none of them close the gap, propose a protocol architecture and threat model, and lay out a phased, formally-grounded implementation plan. We are explicit throughout about what is proposed versus proven, and we treat the absence of a working implementation and independent audit as a first-class fact about the project's current state, not a footnote.

---

## 1. The Problem

### 1.1 Compliance is a disclosure problem disguised as a trust problem

When a bank must show a regulator that a transaction cleared an anti-money-laundering (AML) check, or a hospital must show an auditor that a treatment followed a patient-safety protocol, or a government contractor must show a procurement office that a hardware component came through a verified supply chain, the institution is not actually being asked "did you comply?" — it is being asked "*prove* you complied, in a way I can check."

Today, that proof-of-compliance almost always requires one of two costly moves:

1. **Document-trail auditing.** A human auditor reviews logs, forms, and attestations, and applies professional judgment. This is slow, expensive, inconsistent between auditors, and fundamentally a trust relationship — the regulator is trusting the auditor's read of the evidence, not verifying the underlying fact directly.
2. **Raw data disclosure.** The institution hands over the transaction record, the patient chart, or the component's full provenance log to the verifying party, who checks it themselves. This is faster and more direct, but it means every audit is also a data breach risk — the verifying party now holds sensitive data it did not need to hold, purely as a side effect of the verification process.

Both approaches conflate two things that are, mathematically, separable: **the fact that a rule was satisfied**, and **the private data that makes the fact true**. Zero-knowledge proof systems exist specifically to separate these two things — a prover can convince a verifier that a statement is true without revealing anything beyond the truth of the statement itself. This is not new cryptography; zk-SNARK and zk-STARK constructions have been studied since the 1980s (Goldwasser, Micali, and Rackoff's original zero-knowledge interactive proof work) and have seen a decade of intense practical development, primarily driven by blockchain scaling and private-transaction use cases.

### 1.2 The gap: no open, institution-grade compliance protocol exists

What is missing is not the cryptography. It is a **protocol layer** purpose-built for institutional compliance: a common way to express "this action satisfies this rule," a common attestation format that a bank's proof and a hospital's proof can both be validated against by generic tooling, a common threat model that accounts for regulators, auditors, and adversarial institutions alike, and reference implementations mature enough that a compliance team — not a cryptography team — can adopt them.

Zero-knowledge tooling today is overwhelmingly oriented toward blockchain applications: private transactions, rollup scaling, anonymous credentials. These are adjacent problems, and Veritas Mesh will draw heavily on the engineering lessons of that ecosystem (proof systems, circuit design, trusted-setup ceremonies where applicable), but none of the major existing projects are designed around the specific requirements of regulated institutional compliance: long-lived rule sets that change on a regulatory calendar, multi-party verification (an internal auditor, an external auditor, and a regulator may all need to verify the same attestation independently), and integration with the legacy systems that banks and hospitals actually run.

### 1.3 Why this matters for defense and public-sector integrity

The same structural problem appears, in a different form, in government and defense-adjacent contexts: proving that a piece of hardware passed through a verified supply chain, or that a system passed a security control, without disclosing the sensitive operational details of *how* the check was performed. Veritas Mesh's relevance here is deliberately narrow and defensive: **integrity verification, not operational or offensive capability**. This boundary is treated as a hard design constraint throughout this document and the project's [threat model](../spec/THREAT_ANALYSIS.md), not an afterthought.

---

## 2. Related Work

This section situates Veritas Mesh relative to existing work, honestly assessing what each contributes and what gap remains.

- **General-purpose zk-SNARK/zk-STARK toolkits** (e.g., circuit-construction frameworks and proving systems from the blockchain ecosystem) provide the cryptographic primitives Veritas Mesh intends to build on. They do not provide a compliance-specific attestation format, rule-expression language, or institutional trust model.
- **Confidential computing approaches** (trusted execution environments) solve an adjacent but distinct problem: they protect data *during processing* via hardware trust roots, rather than producing a portable, independently verifiable mathematical proof that anyone can check without trusting a hardware vendor. Veritas Mesh treats TEEs as a possible complementary tool for specific deployment scenarios, not a substitute for the cryptographic verifiability that is the core of this protocol.
- **Traditional GRC (governance, risk, compliance) software** digitizes the document-trail model described in §1.1 without changing its fundamental trust structure. It is valuable operational tooling but does not address the disclosure problem this paper is concerned with.
- **Regulatory technology (RegTech) platforms** in banking automate rule-checking internally but generally do not produce externally verifiable, privacy-preserving proofs for third parties; the output is still, structurally, a report to be trusted.

Veritas Mesh's contribution is not a new cryptographic primitive. It is the protocol, specification, and reference-implementation layer that does not yet exist between mature zero-knowledge tooling and the specific, high-stakes requirements of regulated institutions.

---

## 3. Design Goals

1. **Soundness first.** It must be computationally infeasible to produce a valid-looking attestation for a rule that was not actually satisfied. This is the property on which every other design goal depends, and it is treated in this project as the single highest-severity category of failure (see [SECURITY.md](../SECURITY.md)).
2. **Zero unnecessary disclosure.** A verifier learns exactly one bit of information beyond what the protocol requires them to learn: whether the rule held. Nothing about the private inputs should be recoverable, even partially, from a valid attestation.
3. **Multi-verifier independence.** A single attestation must be independently checkable by multiple, mutually distrusting parties (an internal auditor, an external auditor, a regulator) without requiring interaction with the prover or with each other.
4. **Rule modularity.** Regulatory frameworks change on their own calendars and differ by jurisdiction and sector. The core protocol must be agnostic to the specific rule being proven; rules are expressed as pluggable modules (see §6.3) versioned independently from the core.
5. **Formal specification precedes implementation.** Protocol-level security properties are to be stated precisely and, where feasible, checked with formal methods (TLA+ or an equivalent model checker) before implementation work begins on the corresponding component — not asserted about code after the fact.
6. **No offensive capability, ever.** The protocol's threat model and governance process explicitly and permanently exclude any use oriented toward weapons systems, operational targeting, or offensive cyber capability. This is discussed further in §7.

---

## 4. Protocol Overview

At a high level, Veritas Mesh defines three roles and one artifact:

- **Prover.** The institution performing an action (a transaction, a treatment, a component shipment) that a rule applies to.
- **Verifier.** Any party checking whether the rule held — an internal compliance officer, an external auditor, or a regulator. Verification requires no interaction with the prover and no access to the private inputs.
- **Rule authority.** The entity (a regulator, a standards body, or the protocol's own governance process for generic integrity rules) that defines and versions a rule module.
- **Attestation.** The portable, cryptographically signed artifact produced by the prover and checked by the verifier.

### 4.1 The attestation lifecycle

1. **Rule definition.** A rule authority publishes a versioned rule module — a precise, machine-checkable statement of what must hold (e.g., "the transaction amount did not exceed the customer's risk-adjusted threshold" or "the treatment sequence matches an approved clinical pathway").
2. **Private computation.** The institution's own systems perform the underlying action and hold the private inputs (transaction details, patient record, component provenance) locally — these never leave the institution's infrastructure as part of this protocol.
3. **Proof generation.** The institution's Veritas Mesh node constructs a zero-knowledge proof that the private inputs satisfy the rule module, without exposing the inputs themselves.
4. **Attestation publication.** The proof, together with public metadata (rule version, timestamp, institutional identity, a commitment to the private inputs), is published to the attestation mesh network and/or delivered directly to specific verifiers.
5. **Independent verification.** Any verifier — with no communication with the prover required — checks the proof against the public rule specification and either accepts or rejects it.

### 4.2 What an attestation does and does not reveal

An attestation reveals: that a specific institution, at a specific time, satisfied a specific version of a specific rule. An attestation does **not** reveal: the transaction amount, the patient's diagnosis, the specific component supplier, or any other private input — unless the rule module is explicitly designed to reveal a specific derived value (e.g., an aggregate statistic), in which case that disclosure is itself a declared, auditable part of the rule's specification, not an accidental leak.

---

## 5. Cryptographic Approach

Veritas Mesh does not propose new cryptographic constructions. The proof engine is designed to support pluggable proof systems, with the initial reference target being a zk-SNARK construction (for succinct, fast-to-verify proofs suited to high-volume settings like transaction-level banking attestations) with zk-STARK support planned as a transparent-setup alternative for contexts where eliminating any form of trusted setup is a hard institutional requirement (as is often the case for government deployments, where a trusted-setup ceremony is a governance liability regardless of its cryptographic soundness).

Three design questions are treated as open and unresolved in this draft, deliberately:

- **Proof system selection is not yet finalized.** The tradeoffs between SNARK succinctness and STARK setup-transparency are well understood in the literature; the choice for Veritas Mesh's reference implementation will be made in a public RFC (see §9), informed by the specific latency and trust requirements gathered from prospective banking, healthcare, and government adopters, not decided unilaterally in this document.
- **Circuit design for real-world rules is nontrivial and unproven at this stage.** Expressing something like "this transaction sequence did not exhibit structuring behavior across a 30-day window" as an efficient arithmetic circuit is a genuine engineering research problem, not a solved one. Early rule modules will start with narrower, more tractable statements and expand in difficulty as the proof engine matures.
- **Formal verification of the protocol's core security properties (soundness, zero-knowledge, and the multi-verifier independence property in §3) is planned but not yet done.** The intent is to model the attestation state machine in TLA+ and mechanically check these properties before the `core/` implementation is considered stable — see the [Formal Verification Roadmap](#8-roadmap).

---

## 6. System Architecture

Veritas Mesh's reference implementation follows a deliberate division of labor across languages, matching each layer to the language best suited to its constraints — the same reasoning that shapes large-scale infrastructure projects like Docker, Kubernetes, and the major machine-learning frameworks: performance- and safety-critical work is done in a systems language; orchestration, analysis, and interfaces are done in languages optimized for iteration speed and integration.

### 6.1 Proof engine and cryptographic core (`core/`, Rust)

The component responsible for proof generation, proof verification, and the attestation state machine. Written in Rust specifically because a memory-safety vulnerability in the code responsible for cryptographic soundness is not an acceptable risk for a system that banks and hospitals are meant to rely on — the same reasoning behind Rust's adoption for driver code in the Linux kernel.

### 6.2 Risk analysis and institutional connectors (`analysis/`, Python)

The layer responsible for translating an institution's existing internal risk-scoring and anomaly-detection logic into rule-module inputs, and for integrating with the legacy systems (core banking platforms, hospital information systems) that institutions already operate. Python is chosen for iteration speed and ecosystem maturity in this domain, not for anything security-critical — the actual proof generation happens exclusively in `core/`.

### 6.3 Rule modules (`compliance-mappings/`)

Rule modules are the pluggable, versioned expression of a specific regulatory requirement, mapped to a corresponding circuit or constraint system in `core/`. The initial target frameworks are:

- **Banking:** rules derived from Basel III capital and liquidity requirements, and standard AML/KYC transaction-monitoring thresholds.
- **Healthcare:** rules derived from HIPAA's minimum-necessary-disclosure principle and common clinical-pathway adherence checks.
- **Government / supply chain:** rules for component provenance attestation and security-control verification, scoped strictly to integrity checking as discussed in §7.

Each rule module is versioned independently, with its own changelog, so that a regulatory change does not require a protocol-level breaking change.

### 6.4 Attestation mesh network (`mesh/`, Go)

A peer-to-peer network layer for publishing and retrieving attestations among institutions, auditors, and regulators, designed for high concurrency and partition tolerance — requirements shared with, and informed by, the design of systems like Kubernetes and Docker's own networking layers. Go is chosen for exactly the reasons those projects chose it.

### 6.5 Auditor and regulator dashboard (`dashboard/`, TypeScript + React)

The human-facing interface for inspecting attestations and rule modules — deliberately not for inspecting private data, since none passes through this layer. Strict typing is used because a rendering bug in a compliance-decision interface is a business-critical, not merely cosmetic, class of bug.

### 6.6 Cross-language contract (`proto/`, Protocol Buffers / gRPC)

Every message format that crosses a language or organizational boundary is defined once, in a language-agnostic schema, so that any institution or vendor can implement a conformant client without depending on the reference implementation's internals.

---

## 7. Threat Model and Explicit Boundaries

A full threat model is maintained separately and evolves as the protocol matures (see [`spec/THREAT_ANALYSIS.md`](../spec/THREAT_ANALYSIS.md)); this section summarizes its core commitments.

**In scope, adversarially:** a malicious or compromised institution attempting to generate a false attestation; a malicious verifier attempting to extract private information from a valid attestation beyond the single bit of rule-satisfaction; a network adversary attempting to censor, delay, or tamper with attestation propagation across the mesh; a malicious rule-authority attempting to publish a rule module with a hidden backdoor (addressed via the public RFC and review process in §9, not purely technical means).

**Explicitly and permanently out of scope, by design commitment rather than mere convenience:** any application oriented toward offensive cyber capability, weapons systems, or operational/targeting use of any kind. Where the protocol is relevant to defense or government contexts, its scope is limited to integrity verification — proving that a supply chain or a security control was respected — never to systems involved in the use or direction of force. This boundary is treated as non-negotiable in the project's governance process, and RFCs proposing to extend the protocol beyond it will be declined regardless of technical merit.

---

## 8. Roadmap

Consistent with design goal 5 (§3), each phase below is expected to produce specification and, where applicable, formal-methods artifacts *before* the corresponding implementation work is considered complete.

| Phase | Focus | Primary deliverable |
|---|---|---|
| **0 — Specification** *(current)* | Attestation lifecycle, threat model, initial rule-module format | This whitepaper, `spec/PROTOCOL_SPEC.md`, `spec/THREAT_ANALYSIS.md` |
| **1 — Formal modeling** | TLA+ model of the attestation state machine; mechanical check of soundness, zero-knowledge, and multi-verifier independence properties | Published formal-methods artifacts under `spec/formal/` |
| **2 — Minimal proof engine** | A single, narrow rule module (e.g., a simple threshold check) implemented end-to-end: private computation → proof generation → independent verification | A working, tested `core/` crate with one real example, not a placeholder |
| **3 — First institutional pilot** | Partner with a single willing institution (bank, hospital, or public agency) on one real, narrow rule | A documented case study, published openly regardless of outcome |
| **4 — Independent security audit** | Third-party cryptographic and implementation audit of `core/` | Published audit report under `docs/audits/` — see [SECURITY.md](../SECURITY.md) |
| **5 — Mesh network and multi-institution deployment** | `mesh/` implementation, multi-verifier scenarios at scale | Production-candidate release |

No phase is considered complete, and no corresponding claim will appear in this whitepaper's future revisions or in project marketing, until its deliverable is public and independently checkable.

---

## 9. Governance and Openness

Veritas Mesh is developed under an RFC-driven governance model (see [`GOVERNANCE.md`](../GOVERNANCE.md)): protocol-level changes, new rule-module categories, and cryptographic-primitive decisions are proposed publicly, discussed openly, and require documented rough consensus before adoption — not decided unilaterally by any single contributor, including the founder. This is deliberate: a protocol asking regulated institutions to trust its outputs cannot itself be governed opaquely.

The project is released under Apache-2.0 with an explicit patent grant, self-funded and independently developed by its founder, Ciprian Ştefan Pleşca, with no institutional, corporate, or government affiliation, as public-interest research intended to remain free, in perpetuity, for any institution, researcher, or government to use, study, modify, and redistribute.

---

## 10. Limitations and Open Questions

In keeping with this project's commitment to accurate self-representation, the following are stated plainly as open problems rather than solved ones:

- **No implementation exists yet.** Every architectural claim in §6 describes an intended design, not a built or tested system.
- **Circuit efficiency for realistic, complex rules is unproven.** Simple threshold rules are tractable with current zk tooling; rules involving temporal patterns, cross-record correlation, or large state (common in real AML and clinical-pathway rules) may require research-level circuit design work whose feasibility is not yet established.
- **Institutional adoption is a governance and trust problem as much as a technical one.** A regulator accepting a cryptographic attestation in place of a traditional audit trail is a significant institutional and possibly legal change, independent of the protocol's technical soundness, and is expected to require years of pilot work, not a single release.
- **The rule-authority trust model is not fully specified.** Who is authorized to publish a rule module for a given jurisdiction, and how disputes over a rule module's correctness are resolved, remains an open governance question to be settled through the RFC process, not assumed in this document.
- **No cryptographic novelty is claimed.** This project's contribution is protocol design, specification rigor, and institutional-grade engineering discipline applied to existing zero-knowledge primitives — not a new proof system or a new cryptographic assumption.

---

## 11. Conclusion

The gap this paper describes — the absence of an open, institution-grade protocol for privacy-preserving compliance verification — is real, and the cryptographic tools to close it already exist. What is missing is the disciplined protocol design, formal specification, and honest, incremental engineering effort to turn those tools into something a bank's compliance team, a hospital's privacy officer, or a government auditor can actually adopt and trust.

Veritas Mesh is an attempt to do that work in the open, starting from a specification rather than a demo, and reporting its own progress — and its own limitations — as accurately as it asks institutions to report theirs.

---

## References

1. Goldwasser, S., Micali, S., and Rackoff, C. "The Knowledge Complexity of Interactive Proof Systems." *SIAM Journal on Computing*, 1989.
2. Ben-Sasson, E., et al. "Scalable, transparent, and post-quantum secure computational integrity." (zk-STARK construction), 2018.
3. Bank for International Settlements. "Basel III: International regulatory framework for banks."
4. U.S. Department of Health and Human Services. "Health Insurance Portability and Accountability Act (HIPAA) Privacy Rule."
5. Lamport, L. "Specifying Systems: The TLA+ Language and Tools for Hardware and Software Engineers." Addison-Wesley, 2002.

---

*This whitepaper will be revised as the project moves through the roadmap in §8. Substantive revisions are logged in [`CHANGELOG.md`](../CHANGELOG.md) and discussed as RFCs per [`GOVERNANCE.md`](../GOVERNANCE.md). Corrections, and especially challenges to any claim made here, are welcome via the process described in [`CONTRIBUTING.md`](../CONTRIBUTING.md).*
