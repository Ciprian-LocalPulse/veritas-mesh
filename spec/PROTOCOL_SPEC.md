# Veritas Mesh Protocol Specification

**Version:** 0.1 (Draft)
**Status:** Specification only. No conformant implementation exists yet. See [Project Status](../README.md#project-status).

This document is the normative companion to the [whitepaper](../whitepaper/Veritas_Mesh_Whitepaper.md) — where the whitepaper argues *why*, this document defines *exactly what*, to the precision needed for an independent implementer to build a conformant client without consulting the reference implementation's source.

## 1. Terminology

- **Rule module**: A versioned, publicly specified predicate over a set of private inputs and public parameters. Denoted `R_id@version`.
- **Attestation**: The artifact defined in §4, produced by a Prover for a specific rule module instance.
- **Prover**: The party holding the private inputs and generating an attestation.
- **Verifier**: Any party checking an attestation against a rule module's public specification.
- **Commitment**: A binding, hiding cryptographic commitment to a value, per the scheme fixed in §3.2.

## 2. Design Constraints (Normative)

1. A conformant Verifier implementation MUST be able to check any attestation without any interaction with the Prover.
2. A conformant Verifier implementation MUST NOT require access to any private input to complete verification.
3. Two independent, non-colluding Verifiers checking the same attestation against the same rule-module version MUST reach the same accept/reject result. (Multi-verifier independence, per Design Goal 3 in the whitepaper.)
4. A rule module's specification MUST be fully public. Private inputs are never part of the rule module; they are supplied only by the Prover, only at proof-generation time, and never transmitted as part of the protocol.

## 3. Cryptographic Foundations (Draft — subject to RFC)

### 3.1 Proof system

Not yet finalized. Candidate constructions under evaluation: a zk-SNARK construction for high-volume, latency-sensitive contexts (e.g., per-transaction banking attestations), and a zk-STARK construction for contexts requiring transparent (no trusted) setup. Selection will be made via public RFC — see [`rfcs/`](../rfcs/) — informed by prospective adopters' latency and trust requirements. **This section will be updated, not silently overwritten, when a decision is reached; the RFC that makes the decision will be linked here.**

### 3.2 Commitment scheme

Not yet finalized. Any concrete construction adopted must be binding and hiding under standard cryptographic assumptions, with the specific scheme (and its assumptions) named explicitly once selected — this specification will never simply say "a commitment scheme" in a final version without naming which one and why.

### 3.3 Signature scheme (institutional identity)

Attestations are signed by the Prover institution's identity key. The signature scheme is not yet finalized; Ed25519 is the current default candidate for its simplicity and wide auditability, pending RFC confirmation.

## 4. The Attestation Artifact

An attestation is a structured object containing, at minimum:

| Field | Description |
|---|---|
| `rule_id` | Identifier of the rule module being attested to |
| `rule_version` | The specific published version of the rule module |
| `prover_identity` | The public identity of the attesting institution |
| `timestamp` | When the underlying action occurred (not when the proof was generated) |
| `input_commitment` | A commitment to the private inputs, per §3.2 — allows a Prover to later prove consistency across multiple attestations without revealing the inputs |
| `proof` | The zero-knowledge proof, per the system selected in §3.1 |
| `signature` | The Prover's signature over the above fields |

A draft, illustrative (non-final) schema is maintained in [`proto/veritas/v1/attestation.proto`](../proto/veritas/v1/attestation.proto). It is explicitly marked as a draft in that file's header and should not be treated as a stable wire format until an RFC declares it so.

## 5. The Attestation Lifecycle (Normative)

1. **Rule publication.** A rule authority publishes `R_id@version` under `compliance-mappings/`, including a precise statement of the predicate and a reference implementation of the corresponding circuit or constraint system.
2. **Private computation.** The Prover computes the private inputs required by `R_id@version` using its own systems. These inputs never leave Prover-controlled infrastructure as part of this protocol.
3. **Proof generation.** The Prover's `core/` node generates `proof` such that `proof` is valid if and only if the private inputs satisfy `R_id@version`.
4. **Attestation assembly and signing.** The Prover assembles the attestation object (§4) and signs it.
5. **Publication.** The attestation is published to the mesh network (`mesh/`) and/or delivered directly to specific Verifiers.
6. **Verification.** Any Verifier checks: (a) the signature, (b) that `proof` is valid for `rule_id@rule_version`'s public specification, and (c) any additional policy the Verifier applies locally (e.g., "I only accept attestations against rule versions published in the last 12 months"). Step (c) is explicitly a Verifier-local policy, never a protocol-level requirement — the protocol's job ends at "the proof is valid or it is not."

## 6. Versioning and Compatibility

- Rule modules are versioned independently of the core protocol (semver: a MAJOR bump changes the predicate's meaning; MINOR adds optional, backward-compatible fields; PATCH fixes the reference circuit implementation without changing the predicate).
- The core protocol (this document) is versioned independently and will maintain backward verification compatibility within a MAJOR version — an old attestation must remain verifiable by a new Verifier within the same major protocol version.

## 7. Explicit Non-Goals

This protocol does not define, and has no plans to define: a consensus mechanism, a token or cryptocurrency, or a general-purpose smart-contract execution environment. It defines an attestation format and a verification procedure — nothing more. Anything resembling those excluded categories in a future proposal requires an RFC explaining why the exclusion no longer applies, not an assumption that it's in scope.

## 8. Open Items

Tracked honestly rather than glossed over:

- [ ] Finalize proof system (§3.1)
- [ ] Finalize commitment scheme (§3.2)
- [ ] Finalize signature scheme (§3.3)
- [ ] Formalize the attestation lifecycle as a TLA+ state machine (see [Roadmap](../ROADMAP.md) Phase 1)
- [ ] Define the rule-authority trust and dispute-resolution model (currently deferred to [GOVERNANCE.md](../GOVERNANCE.md) in general terms only)
