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
| `core/` (Rust) | `Attestation` struct + deterministic signing-byte encoding; Ed25519 sign/verify; SHA-256 hash-based commitment scheme (real hiding + binding under RO model); 3 compliance rule *predicates* evaluated in the clear; all 3 also have a real Groth16-over-BN254 `ProofSystem` backend (`proof::groth16_bn254`, wired to `veritas-zk-poc`); a real orchestration layer (`attest::attest_banking`/`attest_healthcare`/`attest_supply_chain` in `attest.rs`) tying predicate check → commitment → ZK proof → signature into one call per rule; and now, **for `banking-basel-iii` specifically, the commitment and the ZK proof are cryptographically bound to the same input** (`attest_banking` uses `BoundBankingGroth16Backend`, closing a real gap `attest.rs`'s own docs used to describe as fully open — see below) | `cargo test --workspace`: **38 unit tests pass** (`proof::groth16_bn254`: 12, `attest`: 5, covering all three rule modules end-to-end plus the unbound banking path), **46 total** including integration tests |
| `sdk/rust/` | Thin prover/verifier wrapper over `core/` | separate 2-test crate, not included in the 46 above (see total below) |
| `mesh/` (Go) | In-memory + JSON-lines storage; peer registry; push-based gossip with dedup; a runnable (if network-less) node binary | `go test ./...`: **6 tests pass** across `mesh/` and `sdk/go/` |
| `sdk/go/` | Audit-trail-integrity rule check, matching Rust's byte-for-byte | included above |
| `sdk/python/` | Transaction-threshold rule check; **runs the actual `core/tests/vectors/banking-basel-iii.json` fixture** to check agreement with the Rust implementation | `pytest`: **9 tests pass** |
| `analysis/` | Decimal→minor-units mapping (USD/EUR/RON/GBP only, deliberately); a real CSV-based legacy-export connector | `pytest`: **10 tests pass** |
| `dashboard/` (TS+React) | `AttestationViewer`, `RuleModuleExplorer`, typed `veritasClient.ts` | `tsc --noEmit` clean (strict mode); `vitest`: **3 tests pass** |
| `sdk/typescript/` | Transaction-threshold rule check; also runs the JSON vector fixture | `tsc --noEmit` clean; `vitest`: **10 tests pass** |
| `proto/` | `.proto` schema for attestations, rule-module publishing, and a gRPC verifier service; a `buf.gen.yaml` codegen config | Schema-valid; **not yet run** — see below |
| `zk-poc/` (Rust) | **Four real Groth16 zero-knowledge circuits** (BN254, via `arkworks`): `banking-basel-iii`'s `amount <= threshold` (bit-decomposition range checks) in both unbound and commitment-bound forms; `healthcare-hipaa`'s disclosure-logging predicate (fixed-capacity active/authorized boolean array, `MAX_ENTRIES=16`); `gov-supply-chain-integrity`'s audit-log hash-chain integrity (real SHA-256 R1CS gadget, `MAX_ENTRIES=4` — see below for why so much smaller). All three rule modules are wired into `core/`'s `ProofSystem` trait (`banking-basel-iii` in both forms) — see `zk-poc/README.md`. `src/bin/generate_keys.rs` generates/catalogs real key files for all four circuits, with a real load-and-reuse round-trip test; the two small circuits' keys are checked in under `zk-poc/keys/` | `cargo test --package veritas-zk-poc`: **42 tests pass**, including soundness tests that a false claim cannot be proven at all for each circuit, a test confirming a healthcare proof doesn't verify against a different `record_id`, one confirming a supply-chain proof doesn't verify against a different `genesis_hash`, one confirming a banking-bound proof doesn't verify against a different commitment, and the key save/load round-trip. `cargo run --example demo --release`, `--example demo_healthcare --release`, `--example demo_supply_chain --release`, and `--example demo_banking_bound --release` print concrete metrics — see `BENCHMARKS.md` for the full statistical runs, including why the bound circuit's ~81,600 constraints and the supply-chain circuit's ~64 MiB proving key are real deployment costs, not just large numbers |
| `.github/workflows/ci.yml` | Real per-language test jobs, one per row above (Rust workspace, `mesh`/`sdk/go` via matrix, `sdk/python`+`analysis`, `sdk/typescript`, `dashboard`) | Every command in it was individually verified to pass in this repo's dev environment before the file was written (see `.github/workflows/ci.yml`'s own header comment) — **this line previously claimed this file existed when it did not; that was false and has been corrected.** Existing here means the workflow is committed, not that it has run on GitHub's own infrastructure yet — that only becomes true the first time it actually executes there |

**Total: 131 automated tests across 5 languages/toolchains, all passing as
of this commit** — measured directly per component, all individually
re-verified while building `.github/workflows/ci.yml` (not just carried
forward from an earlier count): **46** in `core/`
(`cargo test --package veritas-core`: 38 unit + 7
`negative_cases` + 1 `roundtrip`, of which `proof::groth16_bn254` accounts
for 12 — 5 `banking-basel-iii`, 5 `healthcare-hipaa`, 2
`gov-supply-chain-integrity` — and `attest` accounts for 5, covering all
three rule modules plus a dedicated unbound-banking-path test), **42** in
`zk-poc/` (`cargo test --package veritas-zk-poc`, up from 33 —
`bound_circuit.rs`'s commitment-binding tests and the
`generate_keys`/`Keys::load_from_files` round-trip test account for the
increase), **2** in `sdk/rust`, **9** in Go
(`go test ./...`: 3 in `mesh`, 6 in `sdk/go`), **19** in Python
(`pytest`: 9 in `sdk/python`, 10 in `analysis`), **13** in TypeScript
(`npm test`: 3 in `dashboard`, 10 in `sdk/typescript`) — unchanged by any
of this session's Rust-focused
work. Toolchain versions that were pinned to work around
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
  gadget — 318,668 constraints, ~64 MiB proving key, ~8.6-10s to prove;
  see `BENCHMARKS.md`), **and it's wired into `core/`'s `ProofSystem`
  trait** the same way as the other two (`SupplyChainGroth16Backend`).
  `core/src/proof/groth16.rs`'s placeholder is no longer the fallback for
  any of the three rule modules, though it's kept as documented reference
  material — see its own updated module doc.
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
starting point and are exercised by real, passing tests end-to-end. Real
cryptography now exists for all three rule modules (Ed25519 signing, hash
commitments, and Groth16-over-BN254 proofs — see above), reachable
through a real orchestration layer (`core::attest`) that ties them
together into an `Attestation`. **What still stands between that and "an
`Attestation` actually means something to an outside verifier":**
`attest()`'s own module docs used to flag one blanket gap here — nothing
binding the commitment and the ZK proof to provably the same input. That
gap is now **closed for `banking-basel-iii`**: `attest_banking` uses
`BoundBankingGroth16Backend` (`zk-poc/src/bound_circuit.rs`), whose
circuit recomputes the commitment from the full witness inside the proof
itself and rejects any mismatch — a proof from that path genuinely cannot
be paired with a commitment to a different input, checked directly in
that circuit's own tests, not just asserted. It costs real money in
proving time to get this (~2.1s vs. ~9ms unbound — see `BENCHMARKS.md`),
which is why `attest_banking_unbound` still exists as a documented,
deliberately-gapped, cheaper alternative for callers with their own
binding mechanism. **`healthcare-hipaa` and `gov-supply-chain-integrity`
still have the gap, unclosed**: a modified `attest_healthcare`/
`attest_supply_chain` (or a different implementation of the same pattern)
could commit to one input and prove a *different* input's statement, and
neither `core/` nor `zk-poc/` would catch that for those two rules yet.
Closing it for `gov-supply-chain-integrity` specifically is expected to
be the most expensive of the three, given that circuit is already the
priciest by a wide margin (see `supply_chain_circuit.rs`'s own docs) —
adding a second SHA-256 computation on top of its existing hash chain,
not a first one. Closing those two, and the remaining gaps above
(trusted-setup ceremonies, `gov-supply-chain-integrity`'s proving-key
distribution problem, an external audit), is real research-and-engineering
work, not something fillable by generating more scaffolding files.
