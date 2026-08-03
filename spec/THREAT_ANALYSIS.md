# Threat Model

**Status:** Draft. This document will be revised as Phase 1 (formal modeling) and Phase 4 (independent audit) of the [Roadmap](../ROADMAP.md) proceed — treat it as the current best understanding, not a finished analysis.

## 1. Assets Being Protected

1. **Private inputs** — the transaction details, patient records, or supply-chain data underlying an attestation.
2. **Attestation integrity** — the guarantee that a valid attestation corresponds to a rule that was actually satisfied.
3. **Institutional identity** — the binding between an attestation and the institution that produced it.
4. **Protocol availability** — the ability of a legitimate Prover to generate, and a legitimate Verifier to check, attestations without being blocked by a network adversary.

## 2. Adversaries In Scope

| Adversary | Capability assumed | Primary concern |
|---|---|---|
| **Malicious or compromised Prover** | Full control over its own systems and private inputs | Producing a valid-looking attestation for a rule that was not actually satisfied |
| **Malicious Verifier** | Receives valid attestations through normal protocol operation | Attempting to extract private-input information beyond the single bit of rule-satisfaction |
| **Network adversary** | Can observe, delay, drop, or attempt to tamper with mesh network traffic | Censorship or tampering of attestation propagation |
| **Malicious rule authority** | Can propose or attempt to publish a rule module | Publishing a rule module with a hidden bias or backdoor (e.g., a circuit that appears to check X but actually always accepts) |
| **Colluding Prover + Verifier pair** | Both parties above acting together | Fabricating an attestation trail that appears independently verified but is not — this is why Design Constraint 3 in the [Protocol Spec](PROTOCOL_SPEC.md) requires *independent, non-colluding* verifiers to agree; collusion between a specific Prover-Verifier pair is a governance and audit-trail problem, addressed by requiring multiple independent verifiers for high-stakes attestations, not a purely cryptographic one |

## 3. Adversaries and Concerns Explicitly Out of Scope

- **Hardware-level side-channel attacks** against a specific Prover's proof-generation infrastructure are the responsibility of that institution's own security program, not the protocol. The protocol's security proofs (once completed, per Roadmap Phase 1) assume a Prover's local computation is not observed by an adversary during proof generation.
- **Quantum adversaries** are not assumed in the current threat model. Post-quantum proof-system migration is a known open question, tracked as a future RFC topic, not addressed in this draft.
- **Insider threats within a rule authority's governance process** are addressed through the RFC and CODEOWNERS process in [GOVERNANCE.md](../GOVERNANCE.md), not through cryptographic means — no cryptographic protocol can fully substitute for transparent governance of who gets to define what a rule means.

## 4. Non-Negotiable Scope Boundary: No Offensive Capability

This is stated here, in the threat model, as well as in [GOVERNANCE.md](../GOVERNANCE.md) and the [whitepaper](../whitepaper/Veritas_Mesh_Whitepaper.md), deliberately redundantly, because it is the single most important boundary this project maintains:

**Veritas Mesh will never incorporate, and will not accept contributions oriented toward, offensive cyber capability, weapons systems, or operational/targeting use of any kind.**

Where the protocol is relevant to defense or government contexts, that relevance is strictly limited to **defensive integrity verification** — for example:

- Proving that a hardware or software component passed through a verified, unaltered supply chain, without disclosing the specific supplier relationships or logistics details.
- Proving that a system passed a specific security control (e.g., a patch-compliance check or a configuration-baseline check) without disclosing the system's specific configuration.

It explicitly does **not** extend to, and any RFC proposing the following will be declined regardless of technical merit or the standing of the proposer:

- Any system involved in the direction, control, or use of a weapon.
- Any capability designed to compromise, disable, or gain unauthorized access to a third-party system (i.e., offensive cyber operations).
- Any targeting, surveillance, or operational-planning system.

This boundary can only be *narrowed* — never widened — and only by unanimous agreement of all active maintainers plus the Lead Maintainer, per [GOVERNANCE.md](../GOVERNANCE.md).

## 5. Security Properties (Target — Not Yet Formally Verified)

These are the properties Phase 1 of the roadmap intends to state formally in TLA+ and mechanically check. They are listed here as the target, not as an accomplished result:

- **Soundness**: no computationally bounded Prover can produce a valid attestation for a rule module instance that the private inputs do not actually satisfy, except with negligible probability.
- **Zero-knowledge / non-disclosure**: a Verifier's view of a valid attestation is simulatable without access to the private inputs — i.e., the attestation reveals nothing beyond the single bit of rule-satisfaction and the public metadata in the attestation format.
- **Multi-verifier independence**: as stated in Design Constraint 3 of the [Protocol Spec](PROTOCOL_SPEC.md).

## 6. Reporting

Vulnerabilities or newly identified threats against this model should be reported per the process in [SECURITY.md](../SECURITY.md), not as a public issue or pull request against this document until coordinated disclosure has occurred, if the finding is exploitable against a real deployment. Purely analytical gaps in this threat model (e.g., "you haven't considered adversary class X") are welcome as normal pull requests.
