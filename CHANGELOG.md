# Changelog

All notable changes to this project are documented here. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions and, once versioned releases begin, [Semantic Versioning](https://semver.org/).

Entries here describe what actually changed and what was verified — not intentions. Planned work belongs in [ROADMAP.md](ROADMAP.md), not here.

## [Unreleased]

Nothing yet since the [0.1.0-alpha] tag below.

## [0.1.0-alpha] - 2026-08-10

First tagged snapshot. **Still pre-alpha research software** — see
[STATUS.md](STATUS.md) for the authoritative, current, unvarnished state
of every component; this entry summarizes what changed, STATUS.md says
what it means. Numbers below were true at the time of tagging and are
not re-verified retroactively as the repo continues to change.

### Added — Specification & Governance

- Initial project scaffold: `README.md`, `SECURITY.md`, `LICENSE`
  (Apache-2.0), `CITATION.cff`, `AUTHORS.md`, governance and contribution
  process (`GOVERNANCE.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `CODEOWNERS`), initial whitepaper draft, protocol specification
  skeleton, compliance framework mapping drafts for all three rule
  modules, RFC process and template.
- RFC 0001 (attestation format), RFC 0002 (proof system selection), RFC
  0003 (commitment scheme selection), RFC 0004 (Verifier API). All remain
  `Status: Draft` — none has completed `GOVERNANCE.md`'s public discussion
  period yet.
- RFC 0002/0003 amended pre-discussion: proof-system curve changed from
  the originally-proposed BLS12-381 to BN254, to match what `zk-poc/`'s
  circuits actually use and because Groth16 pairs more naturally with
  BN254 specifically. Tradeoff (BN254's ~100-110 bit security margin vs.
  BLS12-381's ~128 bits) stated explicitly, with a migration trigger
  recorded for revisiting later.
- `spec/THREAT_ANALYSIS.md` expanded from an adversary-class list into 5
  concrete attack scenarios (replay, downgrade, proof forgery, side
  channels, key compromise), each graded against what's actually tested
  vs. only designed-for. Flags an unaddressed gap: no key-revocation
  mechanism exists anywhere in the protocol design.

### Added — Formal Verification

- `spec/formal/AttestationLifecycle.tla`: TLA+ model of the attestation
  lifecycle state machine. Mechanically checked with TLC (256 states, no
  errors). Two of three target security properties hold (lifecycle
  soundness, multi-verifier independence); zero-knowledge is explicitly
  out of scope for this method (a computational-indistinguishability
  property, not a finite-state one) and remains open.
- `spec/formal/AttestationNonInterference.tla`: companion model checking
  whether the lifecycle wiring itself ever routes a private witness value
  into a Verifier-observable output (32,768 states, no errors). Does
  **not** establish zero-knowledge — see the model's own header for the
  precise, narrower claim it actually makes.

### Added — Zero-Knowledge Circuits (`zk-poc/`)

Three real Groth16-over-BN254 circuits, one per rule module, each with a
real soundness property (a false claim cannot be proven at all, checked
in each circuit's own tests) and a real Rust/arkworks implementation, not
a placeholder:

- `banking-basel-iii` (`circuit.rs`): 129 constraints, 128-byte proofs,
  ~9ms to prove, ~3ms to verify.
- `healthcare-hipaa` (`healthcare_circuit.rs`): 65 constraints, 128-byte
  proofs, ~5.8ms to prove, ~3.2ms to verify. Fixed capacity
  `MAX_ENTRIES=16`.
- `gov-supply-chain-integrity` (`supply_chain_circuit.rs`): the first
  circuit here to compute a hash *inside* the R1CS constraints (a real
  SHA-256 gadget from `ark-crypto-primitives`, not hand-rolled). 318,668
  constraints, a ~64 MiB proving key, ~8.6s to prove, ~2.8ms to verify.
  Fixed capacity `MAX_ENTRIES=4` — deliberately much smaller than
  healthcare's, given SHA-256's real R1CS cost.
- `bound_circuit.rs`: a fourth circuit, for `banking-basel-iii`, proving
  BOTH the predicate AND that a public commitment is really
  `SHA256(salt || canonical_bytes)` for the same input — see "Fixed"
  below for the gap this closes. 81,591 constraints, ~16.4 MiB proving
  key, ~2.1s to prove, ~3.1ms to verify.

### Added — `core/` Implementation

- `Attestation` struct, deterministic signing-byte encoding, Ed25519
  sign/verify, SHA-256 hash-based commitment scheme (`HashBasedScheme`) —
  real hiding and binding under the random-oracle model.
- Real predicate logic (`circuits::{banking_basel_iii,healthcare_hipaa,gov_supply_chain}`)
  for all three rule modules, evaluated in the clear via `Rule::check`.
- `proof::groth16_bn254`: real `ProofSystem` backends wiring the `zk-poc/`
  circuits above into `core/`'s own trait —
  `BankingGroth16Backend`/`BoundBankingGroth16Backend`,
  `HealthcareGroth16Backend`, `SupplyChainGroth16Backend`. Supersedes
  `proof::groth16`'s placeholder (kept as documented reference material,
  not deleted) for all three rules.
- `core::attest`: the first real orchestration layer, combining
  predicate check → commitment → ZK proof → signature into one call per
  rule (`attest_banking`, `attest_healthcare`, `attest_supply_chain`,
  plus `attest_banking_unbound`). For `banking-basel-iii`,
  `attest_banking` uses the commitment-bound circuit above, so a proof
  genuinely cannot be paired with a commitment to a different input.
  `healthcare-hipaa` and `gov-supply-chain-integrity` do not have that
  binding yet — tracked explicitly, per rule, in `attest.rs`'s own module
  docs, not implied closed by omission.

### Added — Benchmarks & Infrastructure

- `BENCHMARKS.md`: real, actually-executed timing numbers (not
  projections) for every real cryptographic component above, with
  explicit hardware/reproducibility caveats.
- `.github/workflows/ci.yml`: real per-language CI (Rust workspace, Go
  via matrix, Python, TypeScript ×2), every command individually
  verified against this repo's dev environment before being committed.
  Not yet run on GitHub's own infrastructure as of this tag.
- 130 automated tests passing across 5 languages/toolchains as of this
  tag (46 in `core/`, 41 in `zk-poc/`, 2 in `sdk/rust`, 9 in Go, 19 in
  Python, 13 in TypeScript) — see `STATUS.md` for the exact breakdown.

### Security

- Fixed 5 Dependabot alerts (1 critical, 1 high, 3 moderate — all
  duplicate labels for one root cause): `esbuild <=0.24.2`'s dev-server
  CORS issue (GHSA-67mh-4wv8-2f99), pulled in transitively by
  `vite@^5.4.0` in `dashboard/` and `sdk/typescript/`. Fixed via an `npm`
  `overrides` pin, verified against both packages' typecheck/build/test.
  4 further, deeper Vite advisories remain, requiring a major-version
  migration deliberately not applied blindly — see
  `SECURITY.md`'s dependency alert triage log.

### Fixed

- `core/benches/proof_generation.rs` never actually ran via the
  documented `cargo bench` command — the default libtest harness
  silently no-op'd its `fn main()` for lack of a `harness = false`
  `[[bench]]` entry. Fixed for that bench and the new ones added above.
- `STATUS.md` claimed `.github/workflows/ci.yml` already existed when it
  did not. Corrected explicitly, not silently.
- An arithmetic error in `STATUS.md`'s running test-count total, caught
  while re-verifying every ecosystem's count for the CI workflow above.

### Notes

- Every proof-system trusted setup in this repository (`setup*` functions
  throughout `zk-poc/`) uses a fixed-seed RNG for reproducible testing —
  explicitly documented as unsafe for any use outside tests. No real
  multi-party ceremony has been run for any rule module.
- No independent security audit, no institutional pilot, and — as of
  this tag — no confirmed run of the CI workflow on GitHub's own
  infrastructure. See [ROADMAP.md](ROADMAP.md) for what's next.
