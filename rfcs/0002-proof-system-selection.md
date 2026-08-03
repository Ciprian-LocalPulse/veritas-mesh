# RFC 0002: Proof System Selection for the Reference Implementation

- **Status:** Draft
- **Author(s):** Ciprian Ştefan Pleşca
- **Discussion:** <link to the pull request once opened>

## Summary

This RFC proposes a **dual-track** proof system for `core/`: a zk-SNARK
construction (Groth16 over BLS12-381 initially, with a migration path to a
universal/updatable SNARK) as the default for latency-sensitive,
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
| SNARK (default) | Groth16 | BLS12-381 | Per-circuit trusted setup (MPC ceremony) |
| STARK (transparent-setup-required rule modules) | A hash-based STARK (FRI-based; Winterfell/Miden-style) | Configurable field, hash-based (e.g. Rescue/Poseidon or Blake3 depending on the arithmetization chosen at implementation time) | None |

Groth16 is proposed over a universal SNARK (e.g. PLONK/Halo2-style) for
the *initial* reference implementation specifically because it needs the
smallest, most-audited trusted computing base to get a first narrow rule
module (Roadmap Phase 2's stated goal: "one narrow rule module
end-to-end") working and auditable quickly; a universal SNARK avoiding
per-circuit ceremonies is noted as a plausible **future** migration in
Open Questions below, not proposed here, to keep this RFC's blast radius
limited to what Phase 2 actually needs.

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
- **Do nothing / continue leaving §3.1 open.** Rejected: this is the
  status quo, and it is what is currently blocking `core/README.md`'s own
  stated precondition for allowing substantial implementation PRs.

## Impact on Existing Work

No `core/` implementation exists yet, so nothing breaks. This RFC does
constrain [RFC 0001](0001-attestation-format-finalization.md)'s
`proof_system_id` field to (at minimum) the two values `"groth16-bls12-381"`
and `"stark-fri-v1"` once respective implementations land, and it directly
unblocks the soundness/zero-knowledge caveats flagged in
`spec/formal/AttestationLifecycle_report.md`, which currently cannot cite
a concrete construction's security proof.

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
- Post-quantum proof-system migration is explicitly out of scope, per
  `spec/THREAT_ANALYSIS.md` §3's statement that quantum adversaries are
  not in the current threat model; tracked as a future RFC topic, not
  resolved here.
