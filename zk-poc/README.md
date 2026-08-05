# `zk-poc/` — Real Groth16 Proofs of Concept

**Status: real, working, tested zero-knowledge cryptography for TWO
rules.** Neither is yet wired into `core/`'s `Attestation` pipeline. See
each circuit's module docs (`src/circuit.rs`, `src/healthcare_circuit.rs`)
for the full technical explanation; this file is the short version.

## Circuit 1: `banking-basel-iii` (`src/circuit.rs`)

That `amount <= threshold` for a real 64-bit `amount`, in zero-knowledge,
using a real Groth16 circuit over BN254 (via `arkworks`) — not a
signed-hash placeholder like `core/src/proof/groth16.rs`.

Run `cargo run --package veritas-zk-poc --example demo --release` to see
it end-to-end with real numbers, or `--example bench` for a statistical
run across many trials. Last measured on this repo's dev environment (see
`BENCHMARKS.md` at the repo root for the full numbers and hardware
caveats):

| Metric | Value |
|---|---|
| Constraints | 129 |
| Proving key size | 29,296 bytes |
| Verifying key size | 296 bytes |
| **Proof size** | **128 bytes** (constant, regardless of witness) |
| Proof generation | ~9 ms |
| Verification | ~3 ms |

The verifier in that demo never receives `amount` — only `threshold` and
the 128-byte proof. Attempting to prove a false claim (`amount >
threshold`) fails at the proving step itself: no satisfying witness
assignment exists, so there is no proof to even attempt to forge.

### How the range check works (the actual hard part)

See `src/circuit.rs`'s module doc for the full explanation. Short version:
field arithmetic wraps around, so a naive `threshold - amount = diff`
constraint alone doesn't prevent a dishonest prover from picking an
enormous, non-real `amount` that "wraps around" to a plausible-looking
`diff`. The fix is bit-decomposition range checks: both `amount` and
`diff` are constrained to be representable in exactly 64 bits, which is
astronomically smaller than the ~254-bit field modulus — making the wrap-
around trick impossible.

## Circuit 2: `healthcare-hipaa` (`src/healthcare_circuit.rs`)

That every access to a record observed by an independent system was
logged, and every logged access was authorized — `core::circuits::
healthcare_hipaa::DisclosureLoggingRule`'s predicate, in zero-knowledge.
The verifier learns only the public `record_id` and the access count;
never who accessed the record, when, or which of the circuit's fixed
`MAX_ENTRIES=16` slots were real entries versus unused padding.

Run `cargo run --package veritas-zk-poc --example demo_healthcare --release`
for the end-to-end walkthrough. Last measured (see `BENCHMARKS.md` for the
full statistical run):

| Metric | Value |
|---|---|
| Constraints | 65 |
| Proving key size | 12,560 bytes |
| Verifying key size | 328 bytes |
| **Proof size** | **128 bytes** |
| Proof generation | ~5.6 ms |
| Verification | ~3.1 ms |

### Why this circuit shape is different from the banking one

This predicate is set-shaped, not a numeric comparison: "for every entry
in a variable-length private list, a per-entry boolean must hold, AND the
list's length must equal a public count." R1CS circuits have a fixed
shape decided at setup time, so there's no native variable-length-vector
gadget — the technique used here is a fixed-capacity array
(`MAX_ENTRIES=16`) with an explicit `is_active` flag per slot marking
real entries vs. padding. **`MAX_ENTRIES` is a real, load-bearing limit**:
a record accessed more than 16 times within one attested period cannot be
proven by this exact circuit without recompiling (and re-running trusted
setup) with a larger constant. See `src/healthcare_circuit.rs`'s module
docs for the full reasoning, including why padding position needs no
extra constraint, and why `record_id` has to be a public input even
though `DisclosureLoggingRule::check` never directly constrains it (a
proof without `record_id` bound in would verify against ANY record making
the same count/authorization claim — checked directly in this circuit's
own tests).

### A subtlety worth flagging: proving does NOT auto-check satisfiability

`arkworks`' `Groth16::prove` does not itself verify that a witness
satisfies the R1CS system before producing a proof. The banking circuit's
"proving fails for a false claim" behavior comes from its range check
having no valid *bit decomposition* to assign when `amount > threshold` —
an accident of that predicate's shape, not a general guarantee. The
healthcare circuit's predicate has no equivalent natural failure point (an
individual `is_active`/`authorized` bit is always a valid Boolean
regardless of whether the overall claim holds), so `generate_constraints`
checks satisfiability explicitly in Rust before allocating any witness,
and deliberately fails every allocation via `SynthesisError::AssignmentMissing`
if the claim doesn't hold — see the function's own comments for why this
was worth stating explicitly rather than assuming it "just works" the way
it happened to for the first circuit.

## What's still needed to wire either circuit into `core/`

1. Add a `Proof::Groth16Bn254(Vec<u8>)` variant to `core::proof::Proof`
   (currently only `Proof::Toy` exists), carrying the
   canonically-serialized `ark_groth16::Proof<Bn254>` bytes (see
   `ark_serialize::CanonicalSerialize`, used in both `examples/demo*.rs`
   files).
2. Replace `core::proof::groth16::Groth16Placeholder`'s `prove`/`verify`
   bodies with calls into this crate's `prove`/`verify` (banking) or
   `prove_healthcare`/`verify_healthcare` (healthcare), dispatched on
   `rule_id`.
3. Decide where each rule's `ProvingKey`/`VerifyingKey` (this crate's
   `Keys`) get stored/distributed — they need to be published once (see
   `proto/veritas/v1/rule_module.proto`'s `RuleModuleManifest.circuit_digest`,
   which already has a field for exactly this) and reused across every
   proof for that rule, not regenerated per-attestation.
4. Replace the fixed-seed RNG in both `setup()`/`setup_healthcare()` with
   either a real multi-party trusted-setup ceremony, or switch rules to a
   transparent proof system (STARK) per RFC-0002 to avoid the ceremony
   question entirely — this repo's setup functions as written must never
   be used outside tests.
5. Do the same circuit-design work for `gov-supply-chain-integrity`'s
   predicate (`core/src/circuits/gov_supply_chain.rs`) — its hash-chain
   integrity check needs a SHA-256 R1CS gadget, which neither circuit in
   this crate uses yet; this is a structurally harder, separate problem
   from both circuits above (numeric range check, and boolean/counting
   logic respectively), not a mechanical port of either.
6. `healthcare-hipaa`'s `MAX_ENTRIES=16` cap needs a documented policy:
   either a per-rule-module-version constant chosen from real access-
   pattern data (not yet done — flagged in `src/healthcare_circuit.rs`),
   or a design that lets a record with more accesses split across
   multiple attestations for the same period.

## Toolchain notes

Several `arkworks` transitive dependencies (`rayon`/`rayon-core`,
`zeroize`/`zeroize_derive`) needed explicit older-version pins in
`Cargo.toml` to build under this repo's dev-environment Rust toolchain
(1.75) — newer releases of those crates require a newer rustc/edition.
See root `STATUS.md` for the same note applied to `core/Cargo.toml`.
Revisit these pins on a newer toolchain.
