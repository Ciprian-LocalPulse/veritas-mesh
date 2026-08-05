# RFC 0003: Commitment Scheme Selection

- **Status:** Draft
- **Author(s):** Ciprian Ştefan Pleşca
- **Discussion:** <link to the pull request once opened>

## Summary

This RFC proposes Pedersen commitments over the same curve family already
introduced for the SNARK track in
[RFC 0002](0002-proof-system-selection.md) (BN254, per that RFC's
amended curve choice — see its "Curve choice for the SNARK track"
subsection) as the default commitment scheme for the `input_commitment`
field defined in [RFC 0001](0001-attestation-format-finalization.md),
with a hash-based commitment (matching whichever hash the STARK track in
RFC 0002 settles on) as the companion scheme for attestations produced
under the transparent-setup track — so that a STARK-track attestation
never has a Pedersen (curve-based, non-transparent-setup-free) commitment
sitting inside it and quietly reintroducing a setup dependency STARK was
chosen to avoid.

## Motivation

`spec/PROTOCOL_SPEC.md` §3.2 leaves the commitment scheme open, requiring
only that "any concrete construction adopted must be binding and hiding
under standard cryptographic assumptions, with the specific scheme... named
explicitly once selected." This is the third RFC named in
`rfcs/README.md`'s expected list, and it is sequenced after
[RFC 0002](0002-proof-system-selection.md) deliberately: the commitment
scheme's algebraic structure needs to be compatible with whichever proof
system is going to prove statements *about* committed values (per
`PROTOCOL_SPEC.md` §4's description of `input_commitment` existing so a
"Prover can later prove consistency across multiple attestations without
revealing the inputs" — that later proof is exactly a circuit that takes
the commitment as a public input, so the two choices are not independent).

## Detailed Design

### Default track (paired with the Groth16/BN254 SNARK track)

**Pedersen commitments** over BN254's scalar field:

```
Commit(m, r) = m·G + r·H
```

where `G`, `H` are fixed, independently-generated (nothing-up-my-sleeve)
generators of the curve's prime-order subgroup, `m` is the committed
value, and `r` is a uniformly random blinding factor. Chosen specifically
because it is:

- **Perfectly hiding** — the commitment reveals no information about `m`
  regardless of the committer's computational power, which is the
  stronger of the two properties `PROTOCOL_SPEC.md` §3.2 requires, and a
  natural fit for a protocol whose entire purpose is non-disclosure.
- **Computationally binding** under the discrete-log assumption on the
  same curve already used by the SNARK track — reusing curve arithmetic
  the proof system already needs, rather than introducing a second,
  independent hardness assumption purely for commitments.
- **Additively homomorphic**, which directly enables the
  "prove consistency across multiple attestations without revealing the
  inputs" use case named in `PROTOCOL_SPEC.md` §4: a Verifier (or a
  Prover, in a later proof) can check a linear relationship between two
  committed values from separate attestations without either being
  opened.

### Companion track (paired with the STARK track)

A **hash-based commitment** (a straightforward salted-hash construction,
`Commit(m, r) = H(m || r)`, or a Merkle-based vector commitment if a rule
module commits to structured/multi-value inputs), using whichever hash
function [RFC 0002](0002-proof-system-selection.md)'s follow-up settles on
for the STARK track's FRI commitment. This is proposed specifically so
that an attestation produced under the transparent-setup track has no
component anywhere in it — proof or commitment — whose binding property
rests on a discrete-log-style assumption requiring curve parameters that
could, even in principle, need a setup ceremony. Consistency of hardness
assumptions within a single attestation is treated as a property worth
protecting deliberately, not an incidental detail.

### Tagging

Both schemes are identified through the `commitment_scheme_id` field
already introduced in RFC 0001: `"pedersen-bn254"` (amended from
`"pedersen-bls12-381"`, matching RFC 0002's amended curve choice) and
`"hash-based-v1"` (final identifier to be fixed once RFC 0002's STARK
follow-up names a specific hash function).

## Drawbacks

- Running two commitment schemes, like running two proof systems, doubles
  a class of implementation and audit surface in `core/` — the same
  drawback RFC 0002 accepts for the same reason, but it compounds when
  counted together (two proof systems × two commitment schemes is, in the
  worst case, four combinations to reason about, though in practice each
  proof-system track only ever pairs with its own commitment track, so the
  real surface is two paired tracks, not four independent combinations).
- Pedersen commitments' binding property is only computational (under
  discrete log), not perfect — a computationally unbounded Prover could in
  principle open a Pedersen commitment to a different value. This is a
  standard, well-understood tradeoff (hiding perfectly vs. binding
  perfectly is a real dichotomy for this class of commitment) but should
  be stated plainly rather than glossed over, consistent with this
  project's stated documentation philosophy. Concretely for the BN254
  curve named above, "computational" means specifically the ~100-110 bit
  margin discussed in RFC 0002's "Curve choice for the SNARK track"
  subsection, not the full 128 bits originally assumed for a curve this
  size — the same caveat, inherited here because binding rests on the
  same discrete-log hardness the SNARK track's curve choice already
  accepted.

## Alternatives Considered

- **A single hash-based commitment scheme for both tracks**, dropping
  Pedersen entirely. Rejected: this would forfeit the additive
  homomorphism Pedersen provides, which is the concrete mechanism enabling
  `PROTOCOL_SPEC.md` §4's cross-attestation consistency use case for the
  SNARK track; a plain hash commitment supports no such algebraic
  relationship without an additional circuit doing much more work to
  establish the same thing.
- **KZG (polynomial) commitments** instead of Pedersen for the SNARK
  track. Considered, since KZG is a natural fit for some universal-SNARK
  constructions — but rejected for *this* RFC because RFC 0002 proposes
  Groth16 specifically (not a universal SNARK) for the initial
  implementation, and KZG's main advantages (batch-opening efficiency
  across many committed values) are most valuable in exactly the
  universal-SNARK setting RFC 0002 defers. Revisit if/when the Open
  Question in RFC 0002 about a future universal-SNARK migration is taken
  up.
- **Do nothing / continue leaving §3.2 open.** Rejected: `input_commitment`
  is a required field per RFC 0001's table, and leaving its scheme
  unnamed indefinitely leaves that field permanently unimplementable,
  blocking Phase 2 in the same way an unresolved RFC 0002 would.

## Impact on Existing Work

No `core/` implementation exists yet, so nothing breaks. This RFC fixes
the second half of RFC 0001's tagged-field design (`commitment_scheme_id`
alongside `proof_system_id`) and gives
`spec/formal/AttestationLifecycle_report.md`'s Open Items a concrete
scheme to eventually extend the model with, if a future revision chooses
to model the commitment layer explicitly rather than treating
`input_commitment` as opaque.

## Open Questions

- Final hash function for the companion track is deferred to RFC 0002's
  own open question on the same point, to avoid two RFCs independently
  guessing at a value that must actually match.
- Whether rule modules should be allowed to specify *which* track's
  commitment scheme applies independently of which proof-system track they
  use (decoupling the pairing proposed above) is left open; the pairing is
  proposed here as the simpler default specifically to avoid the
  cross-assumption mixing problem described in "Companion track" above,
  but a rule module with an unusual requirement might reasonably want to
  argue for an exception in a future RFC.
- Vector/Merkle commitments for rule modules with structured
  (multi-field) private inputs are gestured at above but not fully
  specified; left for the first rule module that actually needs one, per
  this project's stated preference for concrete, motivated design over
  speculative generality.
