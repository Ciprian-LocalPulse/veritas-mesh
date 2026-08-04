# Formal Verification Artifacts

**Status: Phase 1 draft in progress.** Two TLA+ models exist so far: the
attestation *lifecycle* (the state-machine wiring in
[`PROTOCOL_SPEC.md`](../PROTOCOL_SPEC.md) §5), and a companion *witness
non-interference* model checking that lifecycle wiring for an accidental
private-input-to-verdict channel. Both have been mechanically checked with
TLC. Together they are a starting point for Phase 1 of the
[Roadmap](../../ROADMAP.md), not the completed milestone that phase
describes — read both reports before citing any result, particularly
regarding which of the three target properties in
[`THREAT_ANALYSIS.md`](../THREAT_ANALYSIS.md) §6 are and are not actually
addressed. **Neither model establishes zero-knowledge / non-disclosure —
see "What comes next here" below for why that remains open and what would
actually resolve it.**

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
- [`AttestationNonInterference.tla`](AttestationNonInterference.tla) — a
  companion model extending the same lifecycle wiring with an explicit,
  deliberately ambiguous private-input (`witness`) variable, to check
  whether the wiring itself ever routes that value into anything a
  Verifier observes. This is **not** a zero-knowledge proof — see the
  model's own header and its report for the precise, narrower claim it
  actually makes.
- [`AttestationNonInterference.cfg`](AttestationNonInterference.cfg) — TLC
  configuration for that model.
- [`AttestationNonInterference_report.md`](AttestationNonInterference_report.md) —
  plain-language results and scope caveats for that model.
- [`tlc_run_noninterference.log`](tlc_run_noninterference.log) — raw TLC
  output for that run.

Result summary (details and caveats in both reports):

- **Lifecycle model:** TLC explored the model's full reachable state space
  (256 distinct states) with no errors. Two of the three target properties
  from `THREAT_ANALYSIS.md` §6 — soundness of the lifecycle wiring (under
  an explicit assumption about the not-yet-selected proof system's
  cryptographic soundness) and multi-verifier independence — held
  throughout.
- **Non-interference model:** TLC explored 32,768 distinct states (depth
  19) with no errors, over a state space with genuine, exercised ambiguity
  in the private witness value. The lifecycle model's two properties held
  again here, plus a new one specific to this model: no attestation pair
  agreeing on ground truth and proof claim ever received different
  verdicts from the same Verifier on account of a different underlying
  witness.
- **Zero-knowledge / non-disclosure**, the third target property, is
  **not** represented in either model and remains genuinely open; see
  both reports for why that is the correct scope boundary for this kind of
  model, not an oversight.

## Why this still comes largely before implementation

Per Design Goal 5 in the [whitepaper](../../whitepaper/Veritas_Mesh_Whitepaper.md),
this project's discipline is to state and check security-relevant
properties before writing the code that is supposed to have them. That
discipline still holds: these two models exist, but `core/` has no
implementation, and per [RFC 0002](../../rfcs/0002-proof-system-selection.md)
and [RFC 0003](../../rfcs/0003-commitment-scheme-selection.md) (both
currently Draft, not accepted), the concrete proof system and commitment
scheme the lifecycle model's soundness assumption ultimately rests on have
not been decided yet either.

## What comes next here

- Extend the model(s) to cover rule publication (currently folded into
  `Init`) once [RFC 0001](../../rfcs/0001-attestation-format-finalization.md)
  and the rule-authority trust model referenced in
  `PROTOCOL_SPEC.md` §8 are further along.
- Once RFC 0002 is accepted: either cite the selected proof system's own
  published zero-knowledge proof directly (the expected path for a
  well-studied construction like Groth16 or a FRI-based STARK — this is
  the step that actually resolves the still-open third property, not
  either TLA+ model above), or extend the non-interference model further
  if the selected construction has protocol-level interactions with
  zero-knowledge worth checking independently (e.g. proof malleability
  interacting with the signature scheme).
- Model attestation revocation/expiry once a rule module actually requires
  it (see RFC 0001's Open Questions) — also relevant to the replay
  scenario in `THREAT_ANALYSIS.md` §5.1.
- Model key-revocation once a design exists for it (flagged as an open gap
  in `THREAT_ANALYSIS.md` §5.5) — there is nothing to model yet because
  there is no mechanism proposed yet.

No file will be added to this directory that has not actually been run
through a model checker with the results included in the same pull
request.
