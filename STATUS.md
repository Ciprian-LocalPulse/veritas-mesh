# Implementation Status

This file is the single source of truth for "what actually works" versus
"what's scaffolding" in this repository. Every module-level `STATUS`
comment elsewhere in the codebase (e.g. `core/src/lib.rs`,
`mesh/internal/gossip/gossip.go`) links back here. If this file and a
module comment ever disagree, trust the module comment — it's closer to
the code — and please file an issue, because it means this file is stale.

**Read this before deploying, citing, or building on top of anything in
this repo.** Nothing here has been through the security audit described in
`spec/formal/` and the project roadmap. Do not use this to attest real
regulatory compliance to a real regulator.

## What's real and tested

| Layer | What's real | Evidence |
|---|---|---|
| `core/` (Rust) | `Attestation` struct + deterministic signing-byte encoding; Ed25519 sign/verify; SHA-256 hash-based commitment scheme (real hiding + binding under RO model); 3 compliance rule *predicates* evaluated in the clear; **2 of those 3 (`banking-basel-iii`, `healthcare-hipaa`) also have a real Groth16-over-BN254 `ProofSystem` backend** (`proof::groth16_bn254`, wired to `veritas-zk-poc`) — see below | `cargo test --workspace`: **39 tests pass** (was 31; +8 from `proof::groth16_bn254`) |
| `sdk/rust/` | Thin prover/verifier wrapper over `core/` | included in the 31 above |
| `mesh/` (Go) | In-memory + JSON-lines storage; peer registry; push-based gossip with dedup; a runnable (if network-less) node binary | `go test ./...`: **6 tests pass** across `mesh/` and `sdk/go/` |
| `sdk/go/` | Audit-trail-integrity rule check, matching Rust's byte-for-byte | included above |
| `sdk/python/` | Transaction-threshold rule check; **runs the actual `core/tests/vectors/banking-basel-iii.json` fixture** to check agreement with the Rust implementation | `pytest`: **9 tests pass** |
| `analysis/` | Decimal→minor-units mapping (USD/EUR/RON/GBP only, deliberately); a real CSV-based legacy-export connector | `pytest`: **10 tests pass** |
| `dashboard/` (TS+React) | `AttestationViewer`, `RuleModuleExplorer`, typed `veritasClient.ts` | `tsc --noEmit` clean (strict mode); `vitest`: **3 tests pass** |
| `sdk/typescript/` | Transaction-threshold rule check; also runs the JSON vector fixture | `tsc --noEmit` clean; `vitest`: **10 tests pass** |
| `proto/` | `.proto` schema for attestations, rule-module publishing, and a gRPC verifier service; a `buf.gen.yaml` codegen config | Schema-valid; **not yet run** — see below |
| `zk-poc/` (Rust) | **Three real Groth16 zero-knowledge circuits** (BN254, via `arkworks`), one for each rule module: `banking-basel-iii`'s `amount <= threshold` (bit-decomposition range checks); `healthcare-hipaa`'s disclosure-logging predicate (fixed-capacity active/authorized boolean array, `MAX_ENTRIES=16`); `gov-supply-chain-integrity`'s audit-log hash-chain integrity (real SHA-256 R1CS gadget, `MAX_ENTRIES=4` — see below for why so much smaller). Only the first two are wired into `core/`'s `ProofSystem` trait so far — see `zk-poc/README.md` | `cargo test --package veritas-zk-poc`: **33 tests pass**, including soundness tests that a false claim cannot be proven at all for each circuit, a test confirming a healthcare proof doesn't verify against a different `record_id`, and one confirming a supply-chain proof doesn't verify against a different `genesis_hash`. `cargo run --example demo --release`, `--example demo_healthcare --release`, and `--example demo_supply_chain --release` print concrete metrics: banking is 129 constraints / 128-byte proofs / ~9ms prove / ~3ms verify; healthcare is 65 constraints / 128-byte proofs / ~5.6ms prove / ~3.1ms verify; **supply-chain is 318,668 constraints / 128-byte proofs / ~8.6s prove / ~2.8ms verify, with a ~64 MiB proving key** — see `BENCHMARKS.md` for the full statistical runs and why that proving key size is a real deployment cost, not just a large number |
| `.github/workflows/ci.yml` | Real per-language test jobs, one per row above | Mirrors the commands actually run while building this |

**Total: 110 automated tests across 5 languages/toolchains, all passing as
of this commit** (69 from the original scaffold + 33 from `zk-poc/`'s
three real Groth16 circuits + 8 from `core::proof::groth16_bn254`, which
wires two of those three circuits into `core/`'s `ProofSystem` trait).
Toolchain versions that were pinned to work around
sandbox/CI environment limits (documented so a real CI failure is easy to
tell apart from an environment quirk): `ed25519-dalek =2.0.0`,
`base64ct =1.6.0`, `zeroize =1.7.0` in `core/Cargo.toml` (newer releases of
these require a Rust edition the available toolchain couldn't parse); the
`core/benches` benchmarks use `std::time::Instant` instead of `criterion`
for the same reason (criterion's dependency chain has the same issue) —
note this also means they need explicit `harness = false` `[[bench]]`
entries in `Cargo.toml`, without which `cargo bench` silently no-ops them
under the default libtest harness; this was actually wrong until it was
caught and fixed (see [`BENCHMARKS.md`](BENCHMARKS.md)'s "A bug this work
found and fixed" section).
Revisit these pins on a newer toolchain — they're workarounds, not
permanent constraints.

## What's a documented placeholder — do not treat as production-grade

These are not bugs to be quietly fixed; they are architecturally
placeholder by design, so the rest of the codebase has a stable interface
to build against while the real cryptographic engineering happens as its
own workstream. Each has an inline `STATUS`/module doc at the point of
use — this is the index, not the full explanation:

- **`core/src/proof/groth16.rs`, `core/src/proof/stark.rs`** — implement
  the `ProofSystem` trait, but "prove" = sign a hash of the witness, not a
  SNARK/STARK. **No zero-knowledge or succinctness property holds in
  these two files.** **Update: this is no longer the whole story for
  `core/`.** `core/src/proof/groth16_bn254.rs` now wires REAL,
  tested Groth16-over-BN254 proving/verification (via `veritas-zk-poc`)
  into `core/`'s own `ProofSystem` trait, for `banking-basel-iii`
  (`BankingGroth16Backend`) and `healthcare-hipaa`
  (`HealthcareGroth16Backend`) — 8 passing tests, including that a proof
  correctly fails to verify against the wrong public inputs, and that a
  claim the predicate rejects cannot be proven at all. See that module's
  own docs for exactly what is and isn't bound into the ZK statement (not
  every field of each rule's `Input` struct — e.g. `customer_id_hash` is
  outside the circuit, handled by the commitment layer instead, not the
  proof). `gov-supply-chain-integrity` now has a real circuit too
  (`zk-poc/src/supply_chain_circuit.rs`, using a real SHA-256 R1CS
  gadget — 318,668 constraints, ~64 MiB proving key, ~8.6s to prove; see
  `BENCHMARKS.md`), but it is **not yet wired into `core/`'s
  `ProofSystem` trait** the way the other two are — `core/src/proof/groth16.rs`'s
  placeholder is still what `core/` itself falls back to for this rule.
  `core/src/proof/stark.rs` has no real
  implementation for any rule yet.
- **`core/src/commitment/pedersen.rs`** — falls back to the hash-based
  scheme internally. **No homomorphic property, no elliptic-curve discrete
  log hardness guarantee.** Needs a curve decision from RFC-0003, which is
  coupled to RFC-0002's choice (the commitment needs to live in the same
  field as the circuit).
- **`core/src/circuits/*.rs`** — the compliance predicates are real logic,
  evaluated *in the clear* by the prover. This proves "the prover ran this
  check and signed the result," not "this holds without revealing the
  inputs." Turning each into an actual zero-knowledge circuit (R1CS for
  Groth16, an AIR for winterfell) is separate work per rule, gated on
  RFC-0002.
- **`mesh/internal/discovery`, `mesh/internal/gossip`** — real dedup/fanout
  logic, but `Transport`/`Source` have no network-backed implementation
  (no TCP/QUIC/libp2p). `mesh/cmd/veritas-node`'s binary reads local stdin
  only; it cannot talk to another machine yet.
- **`proto/buf.gen.yaml`** — a valid config that has never actually been
  run (`buf generate`) in this repo; no `sdk/*/gen/` output is committed.
  Every hand-written type in `dashboard/src/api/veritasClient.ts`,
  `sdk/go`, `sdk/python`, `sdk/typescript` is a **manual mirror** of the
  `.proto` files and must be kept in sync by hand until codegen is wired
  into CI.
- **RFC-0001/0002/0003** — still drafts per the project's own gating
  table. Nothing above should be treated as stable until these are
  accepted; a decision reversal on RFC-0002 in particular means rewriting
  every `proof::*` module and its call sites.
- **External security audit** (Phase 4 of the roadmap) — has not happened.
  Nothing in this repository has been reviewed by anyone outside of this
  session.

## What this means in practice

If you're evaluating this repo to decide whether to build on it: the
**architecture and interfaces** (trait/interface boundaries, message
schemas, the shape of the prover/verifier split) are a reasonable
starting point and are exercised by real, passing tests end-to-end. The
**cryptography that would make an `Attestation` actually mean something to
an outside verifier** does not exist yet. Closing that gap is real
research-and-engineering work — arithmetic circuit design per compliance
rule, a trusted-setup or transparent-setup decision, an external audit —
not something that can be filled in by generating more scaffolding files.
