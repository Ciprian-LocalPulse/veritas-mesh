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

## Circuit 3: `gov-supply-chain-integrity` (`src/supply_chain_circuit.rs`)

That an audit-log hash chain runs unbroken from a public genesis anchor
to a public final state — `core::circuits::gov_supply_chain::AuditTrailIntegrityRule`'s
predicate — in zero-knowledge, without revealing any individual
`event_hash`. This is the circuit `zk-poc/README.md` and `STATUS.md` have
both been calling "structurally harder" since the first two circuits
landed, and it's harder for a specific, concrete reason: it's the first
circuit in this crate that computes a real hash (SHA-256) *inside* the
R1CS constraints, using
[`ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget`](https://docs.rs/ark-crypto-primitives/0.4.0/ark_crypto_primitives/crh/sha256/constraints/index.html)
(a real, tested upstream gadget — not hand-rolled here; see
`src/supply_chain_circuit.rs`'s module docs for why reimplementing
SHA-256's round function in R1CS from scratch was deliberately avoided).

Run `cargo run --package veritas-zk-poc --example demo_supply_chain --release`
for the end-to-end walkthrough. Last measured (see `BENCHMARKS.md` for
the full statistical run):

| Metric | Value |
|---|---|
| Constraints | **318,668** |
| Public input variables | **514** (256 per SHA-256 digest × 2, + 1 for the entry count — see below) |
| Proving key size | **67,370,160 bytes (~64 MiB)** |
| Verifying key size | 16,680 bytes |
| **Proof size** | **128 bytes** (same as the other two circuits — a Groth16/BN254 invariant, not a coincidence) |
| Proof generation | ~8.6 s |
| Verification | ~2.8 ms |

Every number in that table except proof size is roughly two to three
orders of magnitude larger than either other circuit in this crate. This
is the real cost of computing SHA-256 in R1CS, not a bug: each of the 4
entries this circuit's fixed `MAX_ENTRIES` supports needs two 512-bit
SHA-256 compression rounds (a 72-byte preimage — 8 bytes sequence number
+ 32 bytes event hash + 32 bytes previous hash — crosses SHA-256's 64-byte
block boundary once padding is added), and each compression round costs
tens of thousands of constraints with this gadget.

**The 67 MiB proving key is the more operationally significant number.**
Unlike the other two circuits' proving keys (29 KB and 13 KB — trivial to
distribute), a proving key this size is a real deployment cost: every
institution proving compliance under this rule module needs to store and
load it. `MAX_ENTRIES=4` was chosen specifically to keep this circuit
provable and testable within this project's own dev environment at all —
see the module's own docs for what a real deployment auditing more than 4
events per period would need instead (a larger, even more expensive
`MAX_ENTRIES`, or a fundamentally different circuit design).

**Why 514 public inputs:** `ark_r1cs_std::uint8::UInt8` allocates its
value as 8 individual `Boolean` bits, not one field element — so a
32-byte `DigestVar` public input is 256 separate public inputs (one Fr
per bit), not 32. Two digests (`genesis_hash`, `final_linkage_hash`) plus
one plain field element (`active_count`) is 256+256+1 = 513... plus one
more accounting for how `ark-groth16` itself always reserves instance
variable 0 for the constant `1` = 514 total, per
`cs.num_instance_variables()`. This was the single easiest mistake to
make while wiring this circuit's public-input vector in `lib.rs`'s
`verify_supply_chain` — see that function's own doc comment (`digest_to_field_elements`)
for the exact bit-ordering that turned out to matter, found by writing
and running the integration test, not by reading the gadget's allocation
code and assuming.

### Why padding is order-sensitive here, unlike the healthcare circuit

`HealthcareDisclosureCircuit`'s predicate is a pure count-and-set
condition — padding position never matters. This predicate is a hash
*chain*: entry `i`'s constraint genuinely depends on entry `i-1`'s
computed output, so padding must be a contiguous suffix (active,
active, ..., active, inactive, inactive, ...), never an active slot
after an inactive one. This circuit enforces that directly as a real
constraint — checked in `supply_chain_circuit.rs`'s own
`active_slot_after_inactive_slot_cannot_be_proven` test.

## What's still needed to wire either circuit into `core/`

**Items 1-2 below are done** — see `core/src/proof/groth16_bn254.rs`
(`BankingGroth16Backend`, `HealthcareGroth16Backend`), 8 passing tests,
and `BENCHMARKS.md` for real numbers through the actual `ProofSystem`
trait. Kept here, marked done rather than deleted, so the list still
reads as a complete picture of what integration involves.

1. ~~Add a `Proof::Groth16Bn254(Vec<u8>)` variant to `core::proof::Proof`~~
   **Done.** Carries canonically-serialized `ark_groth16::Proof<Bn254>`
   bytes, per `core/src/proof/mod.rs`.
2. ~~Replace `core::proof::groth16::Groth16Placeholder`'s `prove`/`verify`
   bodies~~ **Done differently than originally sketched here:** rather
   than replacing the placeholder in place, two new backend structs
   (`BankingGroth16Backend`, `HealthcareGroth16Backend`) were added in a
   new file, `groth16_bn254.rs`, each rule-specific rather than dispatched
   on `rule_id` inside one shared struct — see that module's own docs for
   why (the `ProofSystem` trait has no `rule_id` parameter, and each
   rule's circuit has an incompatible witness shape and its own key
   pair). `groth16.rs`'s original placeholder is kept, not deleted — it's
   still the only backend `gov-supply-chain-integrity` has, even in
   placeholder form.
3. Decide where each rule's `ProvingKey`/`VerifyingKey` (this crate's
   `Keys`) get stored/distributed — they need to be published once (see
   `proto/veritas/v1/rule_module.proto`'s `RuleModuleManifest.circuit_digest`,
   which already has a field for exactly this) and reused across every
   proof for that rule, not regenerated per-attestation. **Still open** —
   `BankingGroth16Backend::setup`/`HealthcareGroth16Backend::setup` still
   generate fresh (non-ceremony) keys per call, exactly like this crate's
   own `setup`/`setup_healthcare`; `from_keys` exists on both backend
   structs so a caller CAN load externally-published keys instead, but
   nothing yet does.
4. Replace the fixed-seed RNG in both `setup()`/`setup_healthcare()` with
   either a real multi-party trusted-setup ceremony, or switch rules to a
   transparent proof system (STARK) per RFC-0002 to avoid the ceremony
   question entirely — this repo's setup functions as written must never
   be used outside tests. **Still open**, and now more urgent: `core/`'s
   own backend structs inherit this exact same "never use outside tests"
   caveat by construction (they call straight into `setup`/`setup_healthcare`),
   so it's no longer just this crate's problem in isolation.
5. ~~Do the same circuit-design work for `gov-supply-chain-integrity`'s
   predicate~~ **Done** — see `src/supply_chain_circuit.rs`
   (`SupplyChainIntegrityCircuit`), using a real upstream SHA-256 R1CS
   gadget (`ark_crypto_primitives::crh::sha256`). 12 passing tests
   (constraint-level + real Groth16 end-to-end), real measured numbers in
   `BENCHMARKS.md` (318,668 constraints, 67 MiB proving key — see this
   circuit's own module docs for why that's a genuine deployment cost,
   not just a large number). **Not yet wired into `core/`'s
   `ProofSystem` trait** — items 1-2's pattern (a `SupplyChainGroth16Backend`
   in `core/src/proof/groth16_bn254.rs`) hasn't been applied to this
   circuit yet; still open, now that the circuit itself exists to wire.
6. `healthcare-hipaa`'s `MAX_ENTRIES=16` cap needs a documented policy:
   either a per-rule-module-version constant chosen from real access-
   pattern data (not yet done — flagged in `src/healthcare_circuit.rs`),
   or a design that lets a record with more accesses split across
   multiple attestations for the same period. **Still open** — and now
   also enforced as a clean `Result::Err` (not a panic) at the
   `core::proof::groth16_bn254` boundary when exceeded, per that module's
   `HealthcareGroth16Backend::prove`.
7. **Found while wiring items 1-2, confirmed again by circuit 3:** none
   of the three circuits prove anything about fields outside their own
   statement (e.g. `TransactionThresholdInput::customer_id_hash`,
   `DisclosureLogEntry::accessor_id_hash`/`timestamp_unix`, and now
   `AuditTrailInput::period_start_unix`/`period_end_unix` — see
   `supply_chain_circuit.rs`'s own module docs for why those two stay
   out) — those still need RFC-0003's commitment scheme applied to the
   FULL `Rule::canonical_bytes` output, entirely separately from the ZK
   proof over the subset of fields each circuit actually constrains. No
   orchestration layer combining "commit to everything, prove the
   circuit-relevant subset in ZK" into one attestation-building call
   exists yet — see `core/src/proof/groth16_bn254.rs`'s module docs for
   the full reasoning behind why this split exists and matters.

## Toolchain notes

Several `arkworks` transitive dependencies (`rayon`/`rayon-core`,
`zeroize`/`zeroize_derive`) needed explicit older-version pins in
`Cargo.toml` to build under this repo's dev-environment Rust toolchain
(1.75) — newer releases of those crates require a newer rustc/edition.
See root `STATUS.md` for the same note applied to `core/Cargo.toml`.
Revisit these pins on a newer toolchain.
