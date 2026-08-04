# Model-Checking Report: Attestation Lifecycle (Phase 1, Draft)

**Status:** Draft. This covers the *lifecycle state machine only* — it is a
first pass at Phase 1 of the [Roadmap](../../ROADMAP.md), not the finished
formal-verification milestone that phase describes. It should be read
alongside [`AttestationLifecycle.tla`](AttestationLifecycle.tla), which
contains the same caveats in its header comment.

**Tooling:** Official TLA+ tools (`tla2tools.jar`, TLC2 v2.19), run as:

```
java -cp tla2tools.jar tlc2.TLC -deadlock -config AttestationLifecycle.cfg AttestationLifecycle.tla
```

## What was modeled

The six-step lifecycle from [`spec/PROTOCOL_SPEC.md`](../PROTOCOL_SPEC.md)
§5 (rule publication → private computation → proof generation → signing →
publication → verification), for two attestation instances checked by two
independent verifiers. One of the two attestations has its Prover modeled
as adversarial — it always attempts to claim rule-satisfaction, regardless
of whether the private inputs actually satisfied the rule.

## What was checked, and what came back

TLC explored the complete reachable state space: **256 distinct states**,
depth 13, no errors. Concretely, three things were checked and held in
every reachable state:

1. **`TypeOK`** — the model's own internal consistency (a basic sanity
   check on the model, not a security property).
2. **`SoundnessLifecycle`** — no verifier ever accepted an attestation
   whose private inputs did not actually satisfy the rule. Held in all 256
   states, including every state reachable by the adversarial Prover.
3. **`MultiVerifierIndependence`** — two independent verifiers checking the
   same attestation never disagreed. Held in all 256 states.

A liveness property, `EventuallyPublished` (every attestation eventually
reaches the `Published` phase, i.e. the lifecycle doesn't get stuck), was
also checked under weak fairness and held.

## What this result does — and does not — mean

This is the part that matters most to get right, and it is stated
identically in the `.tla` file's header:

**This model assumes the cryptographic proof system's soundness as a given
input, it does not establish it.** `GenerateProof` is written so that an
honest Prover can only produce a proof claim matching the actual private
inputs. That is precisely the property a real zk-SNARK or zk-STARK
construction is supposed to guarantee computationally (with negligible
forgery probability) — not something six states and two booleans can prove
about an actual cryptosystem. What `SoundnessLifecycle` holding in this
model tells us is narrower but still useful: **assuming** the eventual
proof system is sound, nothing in how Veritas Mesh *wires the lifecycle
together* — the ordering of computation, signing, and publication —
reintroduces a bypass on top of that assumption. That is a real,
non-trivial thing to check (lifecycle bugs of exactly this kind — e.g. a
verifier accepting before a signature check, or a replay of an old
`proofClaim` — are a common class of protocol-level vulnerability
independent of whether the underlying crypto primitive is sound), but it
is a different, narrower claim than "the protocol is sound."

**Zero-knowledge / non-disclosure — the second property named in
[`spec/THREAT_ANALYSIS.md`](../THREAT_ANALYSIS.md) §6 — is not represented
in this model at all**, and is not the kind of property TLC can check by
this method. It is a statement about computational indistinguishability of
a proof object's distribution, which requires the proof object to exist as
more than a bare boolean. This model's `proofClaim` variable is a stand-in
for "the proof asserted something," with no internal structure to analyze
for leakage. Zero-knowledge has to be established by, and inherited from,
whichever concrete construction [RFC 0002](../../rfcs/0002-proof-system-selection.md)
selects, citing that construction's own published security proof — not
re-derived here.

## Bottom line

- Two of the three target properties in `THREAT_ANALYSIS.md` §6 have a
  first-pass, narrowly-scoped, mechanically-checked result at the lifecycle
  level: **soundness of the protocol wiring** (given an assumed-sound proof
  system) and **multi-verifier independence**.
- The third, **zero-knowledge / non-disclosure**, remains open and is
  correctly the responsibility of proof-system selection
  ([RFC 0002](../../rfcs/0002-proof-system-selection.md)), not of this
  lifecycle model.
- This is Phase 1 work *in progress*, not complete. Next steps: model the
  rule-publication step itself (currently folded into `Init`), model
  attestation revocation/expiry once that is specified, and — once
  RFC 0002 lands — either cite the selected construction's ZK proof here or
  extend this model if the selected construction has protocol-level
  interactions with zero-knowledge worth checking (e.g. proof malleability
  interacting with the signature scheme from
  [RFC 0003](../../rfcs/0003-commitment-scheme-selection.md)).
