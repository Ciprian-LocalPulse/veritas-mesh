# Model-Checking Report: Attestation Witness Non-Interference (Phase 1, Draft)

**Status:** Draft. Companion to
[`AttestationLifecycle_report.md`](AttestationLifecycle_report.md). Read
that report's "What this result does — and does not — mean" section
first if you haven't: this document repeats and sharpens the same
discipline for a narrower, specifically-scoped follow-on question, and
should not be read in isolation from it.

**Tooling:** Official TLA+ tools (`tla2tools.jar`, TLC2 v2.19), run
identically to the lifecycle model:

```
java -cp tla2tools.jar tlc2.TLC -deadlock -config AttestationNonInterference.cfg AttestationNonInterference.tla
```

## The question this model answers, precisely

`AttestationLifecycle.tla`'s own header says zero-knowledge / non-disclosure
(the second target property in
[`spec/THREAT_ANALYSIS.md`](../THREAT_ANALYSIS.md) §6) is not represented
in that model and cannot be established by this method — it's a
computational-indistinguishability property of a real proof system's
output distribution, and TLC checks finite discrete state spaces, not
distributions over an infinite space of adversary strategies. **That is
still true. This model does not change it.**

What this model asks instead is narrower and protocol-specific: *does the
lifecycle wiring itself — independent of whatever cryptographic proof
system eventually fills in `core/src/proof/`, per RFC-0002 — ever route
the private witness value into anything a Verifier can observe?* If the
wiring did that (for example, if `Verify` accidentally branched on the
witness rather than only on `proofClaim` and `satisfied`), that would be a
protocol-level information leak sitting on top of whatever guarantee the
underlying proof system provides — a bug this kind of finite-state check
*can* catch, the same way `SoundnessLifecycle` in the original model
catches lifecycle-level soundness bypasses without needing to reason about
the real cryptography underneath.

## What was modeled

The same six-step lifecycle as `AttestationLifecycle.tla`, extended with
an explicit `witness` variable per attestation: a private-input stand-in
drawn from a four-element set (`w1`..`w4`), with a fixed, deliberately
non-injective mapping to the ground-truth `satisfied` bit — `w1` and `w2`
both map to `TRUE`, `w3` and `w4` both map to `FALSE`. This guarantees real
ambiguity exists in the state space: multiple, genuinely distinct private
inputs are consistent with the same public rule-satisfaction outcome,
mirroring the real situation (many different transaction amounts all
satisfy "amount ≤ threshold"). Three attestations were modeled — one
honest-and-satisfied, one adversarial (per the same worst-case Prover
model as the lifecycle model), one honest-and-unsatisfied — checked by two
independent Verifiers.

Everything downstream of `ComputeInputs` (`GenerateProof`, `Sign`,
`Publish`, `Verify`) is textually identical to the lifecycle model's
formulas: none of them reference `witness`, only `satisfied` and
`proofClaim`.

## What was checked, and what came back

TLC explored the complete reachable state space: **32,768 distinct
states**, depth 19, no errors — a substantially larger space than the
256-state lifecycle model, entirely because of the added `witness`
dimension (4 witness values × 3 attestations' worth of combinatorial
choice, on top of the same phase/proof/verdict structure as before). Four
invariants held throughout:

1. **`TypeOK`** — internal consistency, as before.
2. **`SoundnessLifecycle`** and **`MultiVerifierIndependence`** — the same
   two properties from the lifecycle model, re-checked here. They held
   across this larger, witness-ambiguous state space too, which is a
   meaningful (if expected) strengthening: it shows these two results
   aren't artifacts of the simpler model's lack of witness structure.
3. **`WitnessNonInterference`** (new in this model) — any two attestations
   agreeing on `satisfied` and `proofClaim` received the same verdict from
   a given Verifier in every reachable state, regardless of whether their
   underlying `witness` values agreed. This is the model's actual
   contribution: TLC exploring 32,768 states, including states where two
   attestations carry different witnesses (`w1` vs. `w2`, both
   `satisfied = TRUE`), never found one where that difference showed up in
   `verdict`.

`EventuallyPublished`, the liveness sanity check, also held under weak
fairness, as in the lifecycle model.

## Was witness ambiguity actually exercised, or is this vacuous?

A property like `WitnessNonInterference` can hold "for free" if the model
never actually reaches a state where two attestations disagree on witness
but agree on `satisfied` — the invariant's premise would simply never
fire. This was checked, not assumed: `Init`'s
`\E w \in Witnesses : witness' = [witness EXCEPT ![a] = w]` ranges
independently over all four witness values for each of the three
attestations, so TLC's exhaustive (not sampled) search generates every
combination as part of computing initial states (64 distinct initial
states alone, per the raw log, before any lifecycle transitions even
run) — and since two witnesses map to `TRUE` and two to `FALSE`, most of
those 64 initial states already have at least one pair of attestations
agreeing on `satisfied` while disagreeing on `witness`. `TypeOK`,
`SoundnessLifecycle`, `MultiVerifierIndependence`, and
`WitnessNonInterference` are checked by TLC against literally every one of
the 32,768 reachable states downstream of those initial states — including
the ambiguous ones — not against a hand-picked subset. See
`AttestationNonInterference.tla`'s closing comment for why an explicit
"ambiguity is reachable" formula was deliberately *not* added as a
separate PROPERTY: it would be the wrong kind of claim (an
existential-eventually statement isn't a validity across all fair
behaviors), and it isn't needed to support the point above regardless.

## What this result does — and does not — mean

- **It does not establish zero-knowledge.** See the question section
  above and `AttestationLifecycle.tla`'s own header — both still apply in
  full. `witness` here is an uninterpreted symbol, not a real circuit
  input; nothing about real proof byte size, timing, or any side channel
  named in `THREAT_ANALYSIS.md` §5.4 is represented, and that section
  explicitly remains the open, out-of-scope-for-TLC risk it already was.
- **It does not establish anything about `input_commitment`'s hiding
  property.** That's a property of whichever commitment scheme RFC-0003
  selects, to be inherited by citing that scheme's own security proof, not
  modeled here — same pattern as how `AttestationLifecycle.tla` treats
  proof-system soundness.
- **What it does establish, narrowly:** the *specific finite-state
  abstraction* of the lifecycle's wiring — the same one already checked
  for soundness and multi-verifier independence — has no accidental
  witness-to-verdict channel. This is a real bug class worth ruling out
  (a `Verify` implementation that, say, logged or branched on a raw
  witness value during debugging and shipped that way would violate this
  property immediately, and would be a genuine protocol-level leak
  regardless of how strong the underlying SNARK/STARK's own
  zero-knowledge guarantee is) — but it is a much narrower claim than "the
  protocol is zero-knowledge," and should never be cited as if it were.

## Bottom line

- This model adds a fourth mechanically-checked result to the two the
  lifecycle model already had (soundness-of-wiring, multi-verifier
  independence): **no witness-to-verdict channel in the lifecycle wiring
  itself**, checked against a state space with genuine, exercised witness
  ambiguity.
- **Zero-knowledge / non-disclosure remains open** exactly as
  `THREAT_ANALYSIS.md` §6 and `AttestationLifecycle_report.md` already
  state, and remains correctly the responsibility of proof-system
  selection ([RFC 0002](../../rfcs/0002-proof-system-selection.md)), to be
  established by citation to that construction's own published security
  proof once selected — not by any TLA+ model in this directory.
- This is a useful bar for RFC-0002/RFC-0003's eventual integration work
  in `core/`: whatever proof and commitment layer gets wired in should not
  regress below the wiring-level non-interference checked here, even
  though it will need to separately establish the much stronger
  cryptographic property this model cannot touch.
