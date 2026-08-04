# Veritas Mesh: A Manifesto for Verifiable Institutional Compliance

**A call to the research community — cryptographers, formal methods researchers, distributed systems engineers, and compliance domain experts**

**Author:** Ciprian Ștefan Pleșca
**Repository:** https://github.com/Ciprian-LocalPulse/veritas-mesh
**License:** Apache-2.0
**Status:** Open, RFC-gated, actively seeking collaborators

---

## Abstract

Regulated institutions — banks, hospitals, government agencies — are routinely required to prove that a rule was followed: an anti-money-laundering check, a patient-access-logging protocol, a supply-chain integrity control. The instruments available to make that proof today are, without exception, either **unverifiable** (a document trail a human auditor must simply trust) or **privacy-destructive** (a raw data disclosure to a third party). Zero-knowledge proof systems have existed, in a form mature enough for engineering use, for close to a decade. What has not existed is an open, rigorously specified, adversarially-reviewed protocol that applies them to institutional compliance as a first-class problem — the way TLS did for transport security, or OAuth did for delegated authorization.

Veritas Mesh is an attempt to build that protocol and its reference implementation, in the open, from the first RFC onward. This document is not a product announcement. It is an invitation to the people whose scrutiny this work actually needs before it should be trusted by anyone.

## 1. The Problem, Precisely Stated

Let an institution hold a private record `x` (a transaction, a patient-access log, an audit trail) and a public rule `R`. The institution wants to convince a verifier — a regulator, an auditor, a counterparty — that `R(x)` holds, without disclosing `x`.

Today's practice collapses this into a false binary:

1. **Trust-based attestation.** The institution asserts `R(x)` holds and signs a document. The verifier's confidence is bounded by their trust in the institution's internal controls and honesty — which is precisely the thing being audited in the first place.
2. **Disclosure-based verification.** The institution reveals `x` (or a redacted approximation of it) so the verifier can check `R(x)` directly. This satisfies the verifier at the cost of the privacy interest the rule may itself exist to protect (patient records under HIPAA being the sharpest example: the verification mechanism can violate the very regulation being verified).

A succinct non-interactive zero-knowledge argument of knowledge — a SNARK or STARK proving `∃x. R(x) ∧ Commit(x) = c` for a public commitment `c` — dissolves this binary. This is not a novel cryptographic claim; it is a direct application of results that have been in the literature since Groth (2016) and the STARK constructions that followed. The novelty this project claims, if any, is narrower and more honest: **building the specific, audited, per-jurisdiction rule circuits, the protocol around them, and the reference implementation that makes this application usable and trustworthy** — none of which exists yet in open, reviewed form for institutional compliance specifically.

## 2. Central Thesis

> Compliance verification and data privacy are not in tension. They appear to be in tension only because the tooling to decouple them has not been built, specified, and independently reviewed for this domain.

Everything in this repository is organized around testing that thesis honestly rather than asserting it.

## 3. Current State — Reported Without Inflation

A manifesto addressed to researchers earns nothing by overstating its own results, so this section is deliberately conservative. The authoritative, continuously updated version lives in `STATUS.md` in the repository; what follows is a snapshot.

**What is implemented and independently verifiable today:**

- A complete reference architecture spanning five languages (Rust, Go, TypeScript, Python), with 75+ automated tests, including cross-language interoperability vectors that check independent implementations of the same rule predicate agree byte-for-byte — a concrete, testable instance of the *multi-verifier independence* property the protocol depends on.
- A gossip-based propagation layer demonstrating that an attestation reaching one verifier node converges, independently, to a second verifier node that reaches the same accept/reject decision without coordination.
- One real, working zero-knowledge circuit: a Groth16 argument (via `arkworks`, over BN254) proving a transaction amount did not exceed a compliance threshold, without revealing the amount. Constant-size 128-byte proofs; ~9ms proving time; ~3ms verification time on commodity hardware. Critically, the circuit's soundness was tested directly: for a false claim, *no satisfying witness exists*, so proof generation itself fails — there is no forged proof to even attempt to reject.

**What remains open — stated as research problems, not as a to-do list:**

1. **Circuit design per compliance rule.** The threshold circuit above is the simplest possible case (a bounded numeric comparison, solved via bit-decomposition range checks). Encoding rules like "every access to this record was logged and authorized" or "this audit trail is complete and untampered" as arithmetic circuits is a distinct design problem per rule, with distinct soundness and completeness proofs required for each.
2. **SNARK vs. STARK, formally decided.** The protocol currently supports either via a pluggable `ProofSystem` trait, but no default has been chosen. This is not a preference question — it trades a trusted-setup ceremony (Groth16, small proofs) against transparency with larger proofs (STARKs), and the choice constrains the commitment scheme (see RFC-0002 and RFC-0003, which are explicitly coupled).
3. **Trusted setup, if SNARKs are chosen.** A real multi-party computation ceremony, with a credible toxic-waste-destruction argument, is an operational and cryptographic-engineering problem distinct from the circuit design itself.
4. **Formal verification against the protocol's TLA+ model.** A partial TLA+ specification exists (`spec/formal/`) for protocol-level properties (attestation publication, multi-verifier convergence). Extending this to formally connect the *circuit-level* soundness claims to the *protocol-level* model is unresolved.
5. **Information-leakage analysis of predicate design.** Even a sound zero-knowledge proof of `R(x)` can leak more than intended if `R` itself is chosen carelessly (e.g., a threshold rule with a small, publicly known threshold range narrows the space of plausible `x` significantly). This is a research question in its own right, closer to differential-privacy analysis than to circuit engineering.
6. **Independent external security audit.** Cannot meaningfully begin until (1)–(4) reach a stable state; premature audit of a moving target wastes the auditor's time and produces false confidence.

## 4. Methodological Commitments

This project makes three commitments that depart from typical open-source practice, specifically because the domain requires them:

- **RFC-gated protocol changes.** No cryptographic primitive, wire format, or rule-circuit design becomes normative without an accepted RFC and public discussion (`rfcs/`). Code that anticipates an unaccepted RFC is explicitly marked as disposable.
- **Adversarial framing by default.** Every module that touches cryptography documents what it does *not* guarantee as prominently as what it does. A reviewer should not have to dig to find a proof system's honest limitations.
- **Falsifiability over demonstration.** The Groth16 proof-of-concept described above was built with an explicit negative test — proving a false claim must fail — not just a positive demonstration that valid claims succeed. Contributions are expected to hold themselves to the same standard.

## 5. Who This Invitation Is For

- **Cryptographers and ZK-circuit engineers** who can review, break, or improve the range-check construction in the existing Groth16 circuit, and who can help design circuits for the remaining rule types.
- **Formal methods researchers** who can extend the TLA+ model, or bring other verification frameworks to bear on the protocol-to-circuit soundness gap described in §3.4.
- **Distributed systems engineers** with production experience in gossip protocols, peer discovery, and Byzantine-fault considerations for the mesh networking layer, which currently has no real network transport.
- **Domain experts in banking, healthcare, or government compliance** who can assess whether the rule predicates being encoded are the ones that actually matter in practice, and where the tractability assumptions in `compliance-mappings/` are wrong.
- **Security researchers** willing to attack the protocol's stated threat model before an institution ever depends on it.

Disagreement, criticism, and identified flaws are the primary currency this project needs right now — more than code.

## 6. How to Engage

- Read `STATUS.md` first. It is the single source of truth for what is real versus aspirational.
- Open issues and RFC discussions on the repository directly.
- Review `spec/formal/` and `rfcs/` before proposing protocol-level changes.
- Cite this work via `CITATION.cff` in the repository if referencing it academically.

🔗 **https://github.com/Ciprian-LocalPulse/veritas-mesh**

## Closing Statement

This manifesto does not claim Veritas Mesh solves the compliance-privacy dilemma. It claims the dilemma is solvable, that the cryptographic primitives required are mature, and that what is missing is the specific, reviewed, adversarially-tested engineering work to apply them credibly to this domain — work that should not be done by one person, in private, and should not be trusted by anyone until it has been taken apart by people who did not build it.

That is the invitation.

---

*Ciprian Ștefan Pleșca*
*Veritas Mesh — an open protocol and reference implementation for verifiable institutional compliance*
