# RFC 0002: Proof System Selection for the Reference Implementation

- **Status:** Draft
- **Author(s):** Ciprian Ştefan Pleşca
- **Discussion:** <link to the pull request once opened>

## Summary

This RFC proposes a **dual-track** proof system for `core/`: a zk-SNARK
construction (Groth16 over BN254 initially, with a migration path to a
universal/updatable SNARK — see "Curve choice for the SNARK track" below
for why BN254 and not BLS12-381) as the default for latency-sensitive,
high-volume rule modules, and a zk-STARK construction (a hash-based STARK,
e.g. in the style of Winterfell/Miden) as the mandatory alternative for
any rule module a Prover or the rule authority marks as
`trusted_setup: forbidden`. Both are addressed through the
`proof_system_id` tagging mechanism introduced in
[RFC 0001](0001-attestation-format-finalization.md), so this RFC does not
require re-opening the format RFC.

## Motivation

`spec/PROTOCOL_SPEC.md` §3.1 and the [whitepaper](../whitepaper/Veritas_Mesh_Whitepaper.md)
§5 both leave proof-system selection explicitly open, deferring to "a
public RFC... informed by prospective adopters' latency and trust
requirements." `ROADMAP.md` Phase 0 lists this as the second expected RFC,
and it blocks real progress on three fronts simultaneously: `core/` cannot
start Phase 2 implementation work without a selected system (per
`core/README.md`'s explicit instruction not to open substantial PRs before
this RFC is accepted), the formal model in `spec/formal/` cannot cite a
concrete soundness/zero-knowledge proof to inherit from (see the scope
caveat in `AttestationLifecycle_report.md`), and no rule module in
`compliance-mappings/` can specify a concrete circuit target.

## Detailed Design

### Why not a single choice

The whitepaper's §5 framing — SNARK for succinctness in high-volume
contexts, STARK for transparent setup where a trusted-setup ceremony is a
governance liability — describes two genuinely different institutional
requirements, not two implementations of the same requirement:

- A bank running per-transaction AML attestations cares primarily about
  proof size and verification latency at high volume. A Groth16-style
  SNARK produces proofs on the order of ~200 bytes with millisecond
  verification, which is difficult for any STARK construction to match at
  the same security level, because STARK proofs are larger (typically tens
  to low hundreds of KB) in exchange for transparency.
- A government agency publishing supply-chain-integrity attestations, per
  `spec/THREAT_ANALYSIS.md` §4's defensive-integrity-verification scope,
  is likely to treat a trusted-setup ceremony (even a well-run multi-party
  computation ceremony) as an unacceptable governance dependency —
  "trust no one ceremony participant colluded" is exactly the kind of
  disclosed-trust assumption this protocol exists to eliminate. A STARK
  construction, whose only cryptographic assumption is the security of an
  underlying hash function, avoids this entirely.

A single choice would force one of these adopter classes to accept a
tradeoff that does not fit their actual threat model, for no gain to the
other. This is treated as a real, not hypothetical, tradeoff, per §5 of
the whitepaper explicitly naming it as understood-but-unresolved.

### Proposed concrete choices

| Track | Construction | Curve / field | Setup |
|---|---|---|---|
| SNARK (default) | Groth16 | BN254 (see "Curve choice for the SNARK track" below — this table originally read BLS12-381; see that subsection for why it was changed before this RFC was opened for discussion) | Per-circuit trusted setup (MPC ceremony) |
| STARK (transparent-setup-required rule modules) | A hash-based STARK (FRI-based; Winterfell/Miden-style) | Configurable field, hash-based (e.g. Rescue/Poseidon or Blake3 depending on the arithmetization chosen at implementation time) | None |

Groth16 is proposed over a universal SNARK (e.g. PLONK/Halo2-style) for
the *initial* reference implementation specifically because it needs the
smallest, most-audited trusted computing base to get a first narrow rule
module (Roadmap Phase 2's stated goal: "one narrow rule module
end-to-end") working and auditable quickly; a universal SNARK avoiding
per-circuit ceremonies is noted as a plausible **future** migration in
Open Questions below, not proposed here, to keep this RFC's blast radius
limited to what Phase 2 actually needs.

### Curve choice for the SNARK track: BN254, not BLS12-381

This RFC originally proposed BLS12-381 for the Groth16 track, matching
the whitepaper's general framing. That choice is changed here, before
this RFC is opened for discussion, for three concrete reasons — this
subsection exists specifically so that change is visible and justified,
not silently made:

1. **It contradicts already-shipped, working code.** `zk-poc/` contains
   two real Groth16 circuits (`banking-basel-iii` and `healthcare-hipaa`,
   per `STATUS.md`), both built, tested (21 passing tests), and
   benchmarked (`BENCHMARKS.md`) against `ark-bn254`. Accepting this RFC
   as originally written would mean either rewriting and re-validating
   both circuits' keys and proofs against a different curve for no
   functional gain, or accepting the RFC while `zk-poc/` silently
   continues to disagree with it — both are worse than fixing the RFC to
   match reality before it's opened for the governance discussion period
   in `GOVERNANCE.md`.
2. **Groth16 specifically pairs more naturally with BN254 than
   BLS12-381.** This isn't just a compatibility convenience: BLS12-381 is
   the standard choice for BLS signature aggregation and KZG commitments
   (per Ethereum's own usage, e.g. consensus-layer signatures and
   EIP-4844 blobs), not typically the recommended curve for Groth16 —
   Groth16's field requirements make BN254 (or BLS12-377/BW6-761) the
   usual picks for that specific proof system. Choosing BLS12-381 for a
   Groth16 track would have been swimming against the ecosystem's own
   grain, independent of what this repository already has built.
3. **BN254 has the deepest audit and tooling footprint available for
   this specific combination.** It is the only curve with precompiled
   contracts on Ethereum (EIP-196/197), which has made it the most
   widely used and scrutinized pairing-friendly curve in production
   zkSNARK deployments (Groth16 and PlonK verification in particular) —
   directly relevant to Roadmap Phase 4's goal of a tractable third-party
   security audit, since auditors are more likely to have direct
   experience with this exact curve/proof-system combination than with a
   less common pairing.

This is not a cost-free choice, and the tradeoff is stated plainly rather
than glossed over: **BN254's security margin is weaker than originally
assumed.** It was designed for an estimated 128-bit security level, but
the 2016 Kim-Barbulescu (exTNFS) discrete-log attack reduced that to a
widely-cited estimate of roughly 100-110 bits — independent security
reviews (e.g. Zcash's own 2017 analysis, cited below) converge on "at
least 110 bits, possibly closer to 128 once all attack costs are
counted," not a clean 128-bit guarantee. BLS12-381, which this RFC no
longer proposes for the *initial* implementation, sits close to the full
128-bit level and would not need this caveat. Accepting BN254 here is a
deliberate acceptance of that reduced-but-still-substantial margin for
Phase 2's stated goal (a first narrow rule module, shippable and
auditable), not a claim that the margin is unimportant — see "Migration
trigger" in Open Questions for when this should be revisited.

Sources for the security-margin claim: Kim & Barbulescu, "Extended
Tower Number Field Sieve," CRYPTO 2016; the IETF
`draft-irtf-cfrg-pairing-friendly-curves` memo's curve-by-curve security
estimates; Zcash's own 2017 public analysis of BN254's concrete security
level (`zcash/zcash` issue #2502).

### Ceremony governance for the SNARK track

Per `spec/THREAT_ANALYSIS.md` §3, insider threats within governance are
explicitly handled through `GOVERNANCE.md`'s process, not cryptographic
means. Consistent with that, any trusted-setup ceremony for a Groth16
circuit MUST: be run as a public multi-party computation with an
open-ended, publicly announced contribution window; publish all
transcripts and contribution hashes in `docs/audits/` (mirroring the
independent-audit publication commitment already made there); and be
re-run (a new ceremony, new circuit-specific parameters) whenever the
corresponding rule module has a MAJOR version bump, per
`PROTOCOL_SPEC.md` §6 — a rule module's circuit is exactly the kind of
predicate-meaning change a MAJOR bump signals.

### Circuit language / toolchain

Not fixed by this RFC. Candidate ecosystems (arkworks for the Rust/Groth16
track, Winterfell for the STARK track) are consistent with `core/`'s
Rust-only mandate in `core/README.md` and its `#![forbid(unsafe_code)]`
constraint, but the specific crate choice is left to Phase 2 implementation
PRs, reviewed under normal CODEOWNERS process rather than requiring a
further RFC, since it is a tooling choice rather than a protocol-visible
one.

## Drawbacks

- Supporting two proof systems roughly doubles the audit surface of
  `core/` relative to a single-system choice, directly working against
  Roadmap Phase 4's goal of a tractable third-party security audit. A
  single-system MVP would be faster to get to Phase 4.
- Groth16's per-circuit trusted setup means every new rule module
  effectively needs its own ceremony under the governance rule above —
  an operational cost that recurs indefinitely, not a one-time cost.
- Field/hash-function choice for the STARK track is left unresolved here,
  meaning `core/` cannot fully start on the STARK track from this RFC
  alone without a follow-up decision (see Open Questions).
- **BN254's ~100-110 bit security margin, not the full 128 bits originally
  assumed for pairing-friendly curves of this size.** See "Curve choice
  for the SNARK track" above for the full reasoning and citations. This is
  listed as a drawback deliberately, not folded silently into the
  rationale above, because accepting it is a real, if currently
  reasonable, tradeoff — not a free choice.

## Alternatives Considered

- **STARK-only.** Rejected as the sole system: STARK proof sizes are a
  genuine adoption barrier for the highest-volume banking use case named
  as a primary early target in `compliance-mappings/`
  (per-transaction AML/KYC thresholds), where proof storage and
  verification cost at scale is a real institutional objection, not a
  theoretical one.
- **SNARK-only (Groth16-only, no STARK track).** Rejected: this would
  make a trusted-setup ceremony a hard dependency for *every* deployment,
  including government supply-chain use cases where
  `spec/THREAT_ANALYSIS.md` §4 already anticipates this exact tension, and
  contradicts the whitepaper §5 framing that explicitly names transparent
  setup as "a hard institutional requirement" for some adopters, not a
  nice-to-have.
- **Universal SNARK (PLONK/Halo2-style) instead of Groth16 for the SNARK
  track**, avoiding per-circuit ceremonies entirely. Rejected for the
  *initial* implementation on complexity-budget grounds — a universal
  SNARK's toolchain and its own (still trusted, just circuit-independent)
  setup introduce their own audit surface, and Phase 2's explicit goal is
  narrow and shippable, not maximally general. Recorded as the likely
  next step once Phase 2 ships (see Open Questions).
- **BLS12-381 for the SNARK track**, as this RFC originally proposed
  before being amended (see "Curve choice for the SNARK track" above).
  Rejected for the *initial* implementation: it contradicts `zk-poc/`'s
  two already-working Groth16 circuits, and Groth16 itself pairs more
  naturally with BN254 than BLS12-381 regardless of what's already built.
  The full 128-bit security margin BLS12-381 offers over BN254's ~100-110
  bits is real and worth having eventually — this is recorded as a
  candidate future migration (alongside the universal-SNARK migration
  above), not dismissed, see Open Questions.
- **Do nothing / continue leaving §3.1 open.** Rejected: this is the
  status quo, and it is what is currently blocking `core/README.md`'s own
  stated precondition for allowing substantial implementation PRs.

## Impact on Existing Work

`zk-poc/`'s two existing circuits (`banking-basel-iii`,
`healthcare-hipaa`) already match this RFC's amended curve choice
(BN254) — no rewrite needed on that account, which is precisely why the
curve was amended before this RFC was opened for discussion rather than
after. Wiring them into `core/`'s `Proof::Groth16Bn254` (per
`zk-poc/README.md`'s "what's still needed" list) remains separate,
ordinary implementation work, not gated on anything this RFC changes.
This RFC does constrain [RFC 0001](0001-attestation-format-finalization.md)'s
`proof_system_id` field to (at minimum) the two values `"groth16-bn254"`
(amended from `"groth16-bls12-381"`) and `"stark-fri-v1"` once respective
implementations land, and it directly unblocks the soundness/zero-knowledge
caveats flagged in `spec/formal/AttestationLifecycle_report.md`, which
currently cannot cite a concrete construction's security proof.

## Open Questions

- Concrete field/hash-function selection for the STARK track (e.g.
  Rescue-Prime vs. Poseidon vs. Blake3 for the FRI commitment) is
  explicitly deferred to a follow-up RFC once a specific arithmetization
  toolchain (Winterfell vs. an alternative) is evaluated against `core/`'s
  `#![forbid(unsafe_code)]` constraint — some STARK libraries lean on
  unsafe code for performance, which would need auditing or replacement.
- Migration path from Groth16 to a universal SNARK, if/when circuit churn
  across many rule modules makes per-circuit ceremonies operationally
  unsustainable, is noted but not designed here.
- **Migration trigger for a stronger curve than BN254.** Revisit the
  BN254 choice (toward BLS12-381, BLS12-377+BW6-761, or whatever the
  academic consensus favors at the time) if either: (a) a rule module
  handling sustained high-value or long-lived-sensitivity data argues a
  128-bit margin is a hard requirement for that specific module (which
  could be resolved per-module via `proof_system_id` tagging without
  forcing every existing module to migrate), or (b) a further published
  attack meaningfully weakens BN254's already-reduced ~100-110 bit
  margin. Not designed here; tracked so it isn't forgotten now that BN254
  is the accepted starting choice.
- Post-quantum proof-system migration is explicitly out of scope, per
  `spec/THREAT_ANALYSIS.md` §3's statement that quantum adversaries are
  not in the current threat model; tracked as a future RFC topic, not
  resolved here.
