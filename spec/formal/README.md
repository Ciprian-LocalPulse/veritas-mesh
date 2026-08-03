# Formal Verification Artifacts

**Status: Phase 1 draft in progress.** A first-pass TLA+ model of the
attestation *lifecycle* (the state-machine wiring in
[`PROTOCOL_SPEC.md`](../PROTOCOL_SPEC.md) §5) has been written and
mechanically checked with TLC. It is a starting point for Phase 1 of the
[Roadmap](../../ROADMAP.md), not the completed milestone that phase
describes — read [`AttestationLifecycle_report.md`](AttestationLifecycle_report.md)
before citing any result from it, particularly regarding which of the
three target properties in [`THREAT_ANALYSIS.md`](../THREAT_ANALYSIS.md)
§5 are and are not actually addressed by this model.

## What has landed

- [`AttestationLifecycle.tla`](AttestationLifecycle.tla) — the state
  machine model.
- [`AttestationLifecycle.cfg`](AttestationLifecycle.cfg) — the TLC
  model-checking configuration used to produce the results below.
- [`AttestationLifecycle_report.md`](AttestationLifecycle_report.md) — the
  plain-language translation of the results, including an explicit scope
  caveat about what this model does and does not establish.
- [`tlc_run.log`](tlc_run.log) — the raw TLC output from the run that
  produced these results (TLC2 v2.19, official `tla2tools.jar`), included
  per this directory's own rule below: no file lands here without being
  run through a model checker with the results included in the same
  change.

Result summary (details and caveats in the report): TLC explored the
model's full reachable state space (256 distinct states) with no errors.
Two of the three target properties from `THREAT_ANALYSIS.md` §5 —
soundness of the lifecycle wiring (under an explicit assumption about the
not-yet-selected proof system's cryptographic soundness) and multi-verifier
independence — held throughout. The third, zero-knowledge / non-disclosure,
is **not** represented in this model and remains genuinely open; see the
report for why that is the correct scope boundary for this kind of model,
not an oversight.

## Why this still comes largely before implementation

Per Design Goal 5 in the [whitepaper](../../whitepaper/Veritas_Mesh_Whitepaper.md),
this project's discipline is to state and check security-relevant
properties before writing the code that is supposed to have them. That
discipline still holds: this lifecycle model exists, but `core/` has no
implementation, and per [RFC 0002](../../rfcs/0002-proof-system-selection.md)
and [RFC 0003](../../rfcs/0003-commitment-scheme-selection.md) (both
currently Draft, not accepted), the concrete proof system and commitment
scheme this model's soundness assumption ultimately rests on have not been
decided yet either.

## What comes next here

- Extend the model to cover rule publication (currently folded into
  `Init`) once [RFC 0001](../../rfcs/0001-attestation-format-finalization.md)
  and the rule-authority trust model referenced in
  `PROTOCOL_SPEC.md` §8 are further along.
- Once RFC 0002 is accepted: either cite the selected proof system's own
  published zero-knowledge proof directly (the expected path for a
  well-studied construction like Groth16 or a FRI-based STARK), or extend
  this model further if the selected construction has protocol-level
  interactions with zero-knowledge worth checking independently (e.g.
  proof malleability interacting with the signature scheme).
- Model attestation revocation/expiry once a rule module actually requires
  it (see RFC 0001's Open Questions).

No file will be added to this directory that has not actually been run
through a model checker with the results included in the same pull
request.
