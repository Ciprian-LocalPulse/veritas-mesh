# Threat Model

**Status:** Draft. This document will be revised as Phase 1 (formal modeling) and Phase 4 (independent audit) of the [Roadmap](../ROADMAP.md) proceed — treat it as the current best understanding, not a finished analysis. §5 (Attack Scenarios and Mitigations) was added to move from adversary *classes* to concrete scenarios with an explicit, honest split between what the design claims and what is actually tested today per [`STATUS.md`](../STATUS.md); it should be read alongside [RFC-0004](../rfcs/0004-verifier-api.md), which several scenarios reference.

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

## 5. Attack Scenarios and Mitigations

Section 2 names adversary *classes*. This section names concrete *attack
scenarios* against those adversaries' stated concerns, and for each: what
the protocol design (per [`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md) and
[RFC-0004](../rfcs/0004-verifier-api.md)) claims as a mitigation, and
separately — because the two are not the same thing — whether that
mitigation exists in tested code today, per
[`STATUS.md`](../STATUS.md), or is still a design intention. Conflating
"the protocol is designed to prevent this" with "this repository prevents
this today" is exactly the kind of overclaim this document exists to
avoid.

### 5.1 Replay

**Scenario:** an attestation that was valid when issued is resubmitted
later, either (a) verbatim, to a Verifier that hasn't seen it, to imply a
compliance state that may no longer hold, or (b) re-gossiped repeatedly
across the mesh to waste verification resources.

**(a) — stale-attestation replay.** This is *not* prevented by signature
or proof validity — a replayed attestation's signature and proof remain
genuinely valid, because nothing about the attestation itself became
false; what changed is whether it's still *relevant*. The `Attestation`
type (`core/src/attestation.rs`) carries `issued_at_unix`, but there is no
protocol-level expiry field, and `PROTOCOL_SPEC.md` §5 step 6(c) is
explicit that "I only accept attestations against rule versions published
in the last 12 months" is a **Verifier-local policy**, not a protocol
guarantee — deliberately, because different rule modules have different
natural validity windows (a supply-chain-integrity attestation for a
specific shipped unit never goes stale; an annual audit attestation does),
and the protocol has no way to know which is which without a rule-module-
specific answer. **Mitigation status: by design, pushed to the Verifier
policy layer, not solved at the protocol layer.** A rule module wanting a
hard expiry should say so in its `compliance-mappings/` document and its
circuit should bind an expiry into what's attested, not rely on Verifiers
remembering to check `issued_at_unix` themselves — this is flagged as a
gap: none of the three current `compliance-mappings/*.md` documents
specify an expiry policy today.

**(b) — resource-exhaustion replay.** `mesh/internal/gossip` already
dedupes on receipt via `storage.Store.Put`'s "is this new" check (real,
tested, per `STATUS.md`), so a re-gossiped duplicate does not re-trigger
verification or re-fan-out once any single node has seen it. This
mitigation is real and tested today, not aspirational — but it exists at
the mesh/storage layer, not as a `VerifierService` guarantee; a Verifier
reachable directly (bypassing mesh dedup) has no built-in rate limiting,
which is why RFC-0004 §4.6 leaves batch-size limits and rate limiting to
operator configuration rather than claiming the protocol solves this.

### 5.2 Downgrade

**Scenario:** an adversary (network adversary, or a colluding
Prover/Verifier pair) induces a Verifier to accept an attestation under a
weaker proof system, commitment scheme, or rule-module version than the
one that should apply — for example, claiming a proof was produced under
`"pending-rfc-0002"`'s eventual weaker candidate when a stronger one was
mandatory for that rule as of a given date.

Two concrete downgrade surfaces exist in the current design:

- **Proof-system downgrade.** `Attestation.proof_system`
  (`core/src/attestation.rs`) is a field the Prover sets, not something a
  Verifier independently derives. A Verifier accepting whatever
  `proof_system` value a Prover claims — instead of cross-checking it
  against the `RuleModuleManifest.proof_system` published for that
  `rule_id@rule_version` (per `rule_module.proto`, and required in
  RFC-0004 §4.3's rule that a Verifier "MUST reject ... a manifest whose
  `publisher_signature` does not verify") — could be induced to verify a
  proof under a weaker system than the rule module actually requires.
  **Mitigation status: specified in RFC-0004 as a MUST; not yet
  implemented**, because no `mesh/` server exists yet to enforce it
  (`STATUS.md`: `mesh/` has no network-backed `GetRuleModule` handler).
  This is tracked here explicitly so it is not lost between "RFC says
  MUST" and "actual code enforces it."
- **Rule-version downgrade.** A Prover could attest against an older,
  since-superseded `rule_version` of a rule module whose predicate was
  later tightened (e.g., a Basel III threshold rule module that gets a
  MAJOR version bump because a threshold changed). Per
  `PROTOCOL_SPEC.md` §6, an old attestation remains verifiable under the
  protocol's own backward-compatibility promise — that promise is about
  the *wire format* staying checkable, not about the *predicate* staying
  current. Whether a Verifier should accept an attestation against a
  superseded rule version is, again, Verifier-local policy per §5 step
  6(c) — the same mechanism as §5.1(a), and the same gap: no current
  compliance mapping states a policy on this.

### 5.3 Proof Forgery

**Scenario:** a Prover produces an attestation that verifies as valid for
a rule module whose predicate the private inputs did not actually
satisfy.

This is precisely the **soundness** property named in §6 below, and its
current mitigation status is the most layer-dependent claim in this
document:

- Against the **signature** layer: forgery is real cryptography today.
  `core/src/signature.rs` is plain Ed25519 via `ed25519-dalek`, and
  `tampered_attestation_fails_verification` / `wrong_key_fails_verification`
  in that file's own test module are exactly soundness tests for the
  signature layer — a tampered or wrongly-keyed attestation provably
  fails verification. This part of forgery resistance is not aspirational.
- Against the **proof** layer in `core/` itself: **not yet meaningful.**
  Per `STATUS.md`, `core/src/proof/groth16.rs` and `stark.rs` "prove" by
  signing a hash of the witness — a Prover who lies about the witness and
  signs anyway produces a "proof" that verifies, because nothing in that
  code path checks the witness against the predicate at verification
  time. **Any soundness claim about `core/`'s proof layer today would be
  false.**
- Against the **proof** layer in `zk-poc/`: real, and the one place this
  document can point to actual evidence rather than a target. Per
  `STATUS.md`, `zk-poc/`'s Groth16 circuit has "a soundness test that a
  false claim cannot be proven at all" — meaning forgery against that
  specific circuit (the `banking-basel-iii` `amount <= threshold`
  predicate) has been checked empirically, not just designed for.
  This does not generalize to the other two rule modules
  (`healthcare-hipaa`, `gov-supply-chain-integrity`), which have no `zk-poc/`
  equivalent yet, and it is one circuit's soundness test, not a
  mechanically checked proof of the soundness property in general — that
  remains Roadmap Phase 1 / this document's §6.

### 5.4 Side Channels

**Scenario:** an adversary learns something about the Prover's private
inputs by observing something other than the attestation's public
contents — timing of proof generation, memory access patterns, power
consumption, or metadata incidental to how an attestation was produced or
transmitted.

§3 already places *hardware-level* side channels against a Prover's own
infrastructure explicitly out of scope, on the grounds that the protocol
cannot substitute for an institution's own operational security. This
subsection narrows that: two side-channel-adjacent risks are **in scope**
because they are properties of the protocol design itself, not of a
Prover's infrastructure choices:

- **Timing/size side channels in the attestation object itself.** If
  `proof` size or `input_commitment` size varied meaningfully with the
  private input's value or magnitude (e.g., a range-proof whose byte
  length depended on how large the attested amount was, rather than being
  fixed regardless of value), that would leak information through the
  public attestation alone — no privileged observation position needed.
  `zk-poc/`'s circuit produces fixed-size (128-byte) proofs per
  `STATUS.md`, which is the right shape; this has not been checked as a
  general requirement against the other two rule modules' eventual
  circuits, and should be an explicit conformance check once RFC-0002
  lands, not an incidental property of whichever circuit happens to get
  built.
- **Metadata side channels in the mesh network layer.** Even with a
  perfectly zero-knowledge proof, *when* a Prover gossips an attestation,
  *how often*, and *to which peers first* are all mesh-layer metadata a
  network-adjacent observer could correlate against external events (e.g.,
  inferring a bank ran an AML check shortly after a specific transaction
  became public elsewhere). `mesh/` has no network transport yet
  (`STATUS.md`), so this is presently a design note for Roadmap Phase 5,
  not a checkable claim either way.

### 5.5 Key Compromise

**Scenario:** a Prover's Ed25519 identity signing key, or a rule
authority's manifest-signing key, is stolen or otherwise obtained by an
adversary.

- **Compromised Prover key.** The adversary can sign arbitrary
  attestations as that institution — a strictly stronger position than
  proof forgery (§5.3), since a valid signature over even a fabricated
  proof-and-commitment pair will pass the signature check. There is
  currently **no key-revocation or rotation mechanism anywhere in the
  protocol design** — not in `PROTOCOL_SPEC.md`, not in RFC-0001, not in
  RFC-0004. This is a real gap, not merely an unimplemented feature: even
  a fully-specified protocol as currently drafted has no answer to "this
  key is known to be compromised, treat all attestations signed with it
  after time T as invalid." Flagged here as a concrete open item for a
  future RFC, since PKI-style revocation (CRLs, OCSP-equivalent, or a
  revocation attestation type published to the mesh itself) is a
  significant design decision, not a small addition.
- **Compromised rule-authority key.** Directly enables the "malicious
  rule authority" adversary in §2's table — an adversary holding this key
  can publish a `RuleModuleManifest` (§4.3's `publisher_signature`) for a
  backdoored circuit that will be trusted by any Verifier that recognizes
  that authority, per RFC-0004 §4.3. RFC-0004 requires Verifiers to check
  the signature against "a rule authority it recognizes" but — as noted in
  that RFC's own Open Questions — does not specify how that recognition
  list is built or updated, which means it also does not yet specify how
  a Verifier *revokes* recognition of an authority whose key is known
  compromised. Same gap as above, one layer up.

## 6. Security Properties (Target — Not Yet Formally Verified)

These are the properties Phase 1 of the roadmap intends to state formally in TLA+ and mechanically check. They are listed here as the target, not as an accomplished result:

- **Soundness**: no computationally bounded Prover can produce a valid attestation for a rule module instance that the private inputs do not actually satisfy, except with negligible probability.
- **Zero-knowledge / non-disclosure**: a Verifier's view of a valid attestation is simulatable without access to the private inputs — i.e., the attestation reveals nothing beyond the single bit of rule-satisfaction and the public metadata in the attestation format.
- **Multi-verifier independence**: as stated in Design Constraint 3 of the [Protocol Spec](PROTOCOL_SPEC.md).

## 7. Reporting

Vulnerabilities or newly identified threats against this model should be reported per the process in [SECURITY.md](../SECURITY.md), not as a public issue or pull request against this document until coordinated disclosure has occurred, if the finding is exploitable against a real deployment. Purely analytical gaps in this threat model (e.g., "you haven't considered adversary class X") are welcome as normal pull requests.
