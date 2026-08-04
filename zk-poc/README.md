# `zk-poc/` — Real Groth16 Proof of Concept

**Status: real, working, tested zero-knowledge cryptography for ONE rule.**
Not yet wired into `core/`'s `Attestation` pipeline. See `src/lib.rs` and
`src/circuit.rs` module docs for the full technical explanation; this file
is the short version.

## What this actually proves

That `amount <= threshold` for a real 64-bit `amount`, in zero-knowledge,
using a real Groth16 circuit over BN254 (via `arkworks`) — not a
signed-hash placeholder like `core/src/proof/groth16.rs`.

Run `cargo run --package veritas-zk-poc --example demo --release` to see
it end-to-end with real numbers. Last measured on this repo's dev
environment:

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

## How the range check works (the actual hard part)

See `src/circuit.rs`'s module doc for the full explanation. Short version:
field arithmetic wraps around, so a naive `threshold - amount = diff`
constraint alone doesn't prevent a dishonest prover from picking an
enormous, non-real `amount` that "wraps around" to a plausible-looking
`diff`. The fix is bit-decomposition range checks: both `amount` and
`diff` are constrained to be representable in exactly 64 bits, which is
astronomically smaller than the ~254-bit field modulus — making the wrap-
around trick impossible.

## What's still needed to wire this into `core/`

1. Add a `Proof::Groth16Bn254(Vec<u8>)` variant to `core::proof::Proof`
   (currently only `Proof::Toy` exists), carrying the
   canonically-serialized `ark_groth16::Proof<Bn254>` bytes (see
   `ark_serialize::CanonicalSerialize`, used in `examples/demo.rs`).
2. Replace `core::proof::groth16::Groth16Placeholder`'s `prove`/`verify`
   bodies with calls into this crate's `prove`/`verify`, using
   `TransactionThresholdCircuit` for `rule_id == "banking-basel-iii"`.
3. Decide where the `ProvingKey`/`VerifyingKey` (this crate's `Keys`) get
   stored/distributed — they need to be published once (see
   `proto/veritas/v1/rule_module.proto`'s `RuleModuleManifest.circuit_digest`,
   which already has a field for exactly this) and reused across every
   proof for that rule, not regenerated per-attestation.
4. Replace the fixed-seed RNG in `setup()` with either a real multi-party
   trusted-setup ceremony, or switch rules to a transparent proof system
   (STARK) per RFC-0002 to avoid the ceremony question entirely — this
   repo's `setup()` as written must never be used outside tests.
5. Do the same circuit-design work for `healthcare-hipaa` and
   `gov-supply-chain-integrity`'s predicates (`core/src/circuits/`) — each
   needs its own R1CS circuit; this isn't a mechanical port of
   `TransactionThresholdCircuit`, since the predicates themselves differ
   (hash-chain integrity and log-completeness are structurally different
   problems from a numeric threshold comparison).

## Toolchain notes

Several `arkworks` transitive dependencies (`rayon`/`rayon-core`,
`zeroize`/`zeroize_derive`) needed explicit older-version pins in
`Cargo.toml` to build under this repo's dev-environment Rust toolchain
(1.75) — newer releases of those crates require a newer rustc/edition.
See root `STATUS.md` for the same note applied to `core/Cargo.toml`.
Revisit these pins on a newer toolchain.
