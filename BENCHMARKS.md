# Benchmarks

**Status:** Draft, Roadmap Phase 2. Every number below comes from an
actual run of the code in this repository — nothing here is estimated,
projected, or carried over from a different project. Re-running the
commands shown will reproduce (approximately — see "Hardware" below) each
result.

**What this document is not:** a claim about production performance. See
"Hardware and reproducibility" before quoting any number externally.

## What's benchmarked, and — as important — what's deliberately not

This repository has exactly three pieces of real, non-placeholder
cryptography today (per [`STATUS.md`](STATUS.md)): the Ed25519 signature
layer in `core/`, the hash-based commitment scheme in `core/`, and the
Groth16 circuits in `zk-poc/` (two of them: `banking-basel-iii` and
`healthcare-hipaa`). All three are benchmarked below.

`core/src/proof/groth16.rs` and `stark.rs` are **not** benchmarked as if
they were proof systems, because they aren't — they sign a hash of the
witness (see `STATUS.md`). Reporting a "proof generation time" for them
would misrepresent a `SHA-256` call as SNARK/STARK proving, which is
exactly the kind of overclaim this project's own discipline exists to
prevent. `core/benches/proof_generation.rs` measures them anyway, but
under a name and a doc comment that says plainly what's actually being
timed, and this document does the same: see "Placeholder backend
baseline" below, kept separate from the real numbers.

## Hardware and reproducibility

All numbers below were produced on:

- CPU: Intel(R) Xeon(R) Processor @ 2.80GHz, **1 vCPU** (a shared/virtualized
  sandbox core, not a dedicated benchmarking machine)
- RAM: ~3.9 GiB total
- OS: Ubuntu 24.04 (noble), Linux 6.18 kernel
- Toolchain: `rustc 1.75.0`, `cargo 1.75.0` (Ubuntu-packaged, not the
  latest upstream release)
- Build profile: `--release` throughout

**This is a single run on a shared, single-vCPU sandbox environment, not
dedicated benchmarking hardware.** Absolute numbers here should not be
quoted as representative of production latency on server-class hardware,
and should not be compared against any other project's numbers without
re-running both on matching hardware. What these numbers ARE useful for:
relative comparison within this repository (placeholder vs. real Groth16;
sign vs. verify), and as a regression baseline for future changes to this
same code on this same class of hardware. Re-run before citing anything
here in a paper, pitch deck, or external communication — see
`CONTRIBUTING.md` for how to reproduce.

Every benchmark below reports more than a single mean: min, p50, p95, and
max across many trials, because a single `Instant::now()` delta (as
`zk-poc/examples/demo.rs` prints) can't distinguish "this is roughly the
cost" from "I got lucky or unlucky once" — visible in the numbers below,
where max sometimes runs 2-40x the median on a shared single-vCPU host.

## Real cryptography: Ed25519 signature layer (`core/`)

```
cargo bench --package veritas-core --bench signature
```

20,000 trials each, 1,000-iteration warmup discarded:

| Operation | mean | p50 | p95 | max |
|---|---|---|---|---|
| `sign_attestation` | 51.3 µs | 46.5 µs | 75.5 µs | 1,925 µs |
| `verify_attestation` (valid) | 55.6 µs | 51.3 µs | 77.0 µs | 2,120 µs |
| `verify_attestation` (tampered, rejection path) | 55.0 µs | 50.7 µs | 79.0 µs | 2,040 µs |

This is real, unremarkable Ed25519 performance — tens of microseconds,
consistent with `ed25519-dalek`'s published characteristics on comparable
hardware. The wide max-vs-p50 gap (up to ~40x) is scheduling noise from
running on a shared single vCPU, not a property of the cryptography; see
`core/benches/signature.rs` for the full methodology, including why
valid-vs-rejected verify() latency is not, and should not be read as, a
constant-time analysis (that's `THREAT_ANALYSIS.md` §5.4's territory, out
of scope for a latency benchmark).

## Real cryptography: Groth16 circuits (`zk-poc/`)

```
cargo run --package veritas-zk-poc --release --example bench
```

### `banking-basel-iii`

Circuit: `amount <= threshold` predicate, `RANGE_BITS=64` (see
`zk-poc/src/circuit.rs`). **129 constraints, 128 witness variables, 2
public input variables.**

| Stage | trials | mean | p50 | p95 | max |
|---|---|---|---|---|---|
| Trusted setup (non-ceremony, per-run) | 5 | 33.4 ms | 32.9 ms | 35.4 ms | 35.4 ms |
| Proof generation (amount=1) | 50 | 9.4 ms | 9.1 ms | 11.1 ms | 14.3 ms |
| Proof generation (amount=threshold/2) | 50 | 10.2 ms | 9.4 ms | 14.9 ms | 17.0 ms |
| Proof generation (amount=threshold-1) | 50 | 9.3 ms | 9.1 ms | 10.3 ms | 10.8 ms |
| Verification | 200 | 3.2 ms | 3.1 ms | 4.0 ms | 7.4 ms |

Proving key: 29,296 bytes. Verifying key: 296 bytes. Proof: 128 bytes —
constant across all three witness magnitudes tested.

### `healthcare-hipaa`

Circuit: disclosure-log completeness + per-entry authorization predicate,
`MAX_ENTRIES=16` (see `zk-poc/src/healthcare_circuit.rs`). **65
constraints, 48 witness variables, 3 public input variables** — smaller
than the banking circuit, visible below in every stage running faster.

| Stage | trials | mean | p50 | p95 | max |
|---|---|---|---|---|---|
| Trusted setup (non-ceremony, per-run) | 5 | 17.6 ms | 17.5 ms | 18.5 ms | 18.5 ms |
| Proof generation (1 of 16 slots active) | 50 | 5.8 ms | 5.6 ms | 6.8 ms | 7.0 ms |
| Proof generation (8 of 16 slots active) | 50 | 5.9 ms | 5.6 ms | 7.0 ms | 7.9 ms |
| Proof generation (16 of 16 slots active) | 50 | 5.8 ms | 5.7 ms | 6.1 ms | 6.2 ms |
| Verification | 200 | 3.2 ms | 3.1 ms | 4.1 ms | 4.6 ms |

Proving key: 12,560 bytes. Verifying key: 328 bytes. Proof: 128 bytes —
constant across all three occupancy levels tested (1, 8, and 16 of the 16
available slots marked active). That last point matters for the same
reason as the banking circuit's amount-invariance: proof size and timing
not varying with *how many* of the fixed slots are real entries means the
proof doesn't leak the record's actual access count beyond what's
publicly claimed — three points on a curve, same caveat as the banking
section above about this not being a rigorous side-channel audit.

- Both circuits land at the same 128-byte proof size — expected for
  Groth16 over the same curve (BN254): proof size depends on the proof
  system and curve, not the circuit's constraint count. Constraint count
  instead shows up in proving time (129 vs. 65 constraints tracking
  roughly with ~9ms vs. ~5.8ms mean proving time) and key sizes (both
  scale with witness/constraint count — the healthcare circuit's ~48
  witness variables versus banking's 128 produces a proving key well
  under half the size).
- `gov-supply-chain-integrity` still has no circuit (needs a SHA-256 R1CS
  gadget, structurally different from both circuits above), so this
  document covers two of the three rule modules named in `STATUS.md`.

## Placeholder backend baseline (`core/`, NOT real proof generation)

```
cargo bench --package veritas-core --bench proof_generation
```

100,000 iterations each:

| Backend | ns/iter |
|---|---|
| `Groth16Placeholder::prove` (signs a hash) | 1,653 ns |
| `StarkPlaceholder::prove` (signs a hash) | 1,639 ns |

Included for exactly one reason: once RFC-0002 lands and a real backend
replaces these in `core/`, this is the number to diff against — a ~9ms
real Groth16 proof vs. a ~1.6µs hash-and-sign placeholder is roughly a
5,500x difference, which is the order of magnitude anyone integrating
`core/`'s proof interface should expect to see appear once the real thing
lands, not a regression to be alarmed by.

## A bug this work found and fixed

`core/benches/proof_generation.rs` existed before this document, with a
doc comment saying "Run with: `cargo bench --package veritas-core`." That
command compiled successfully and reported "0 measured" — Cargo's default
libtest harness was linked against the bench binary (because no
`[[bench]]` entry with `harness = false` existed in `core/Cargo.toml`),
found no `#[bench]`-annotated functions, and silently no-op'd the file's
actual `fn main()`. The benchmark had never actually run via the
documented command. Fixed in `core/Cargo.toml` by adding explicit
`[[bench]]` entries with `harness = false` for both `proof_generation` and
the new `signature` bench — both now genuinely execute via `cargo bench`,
confirmed by the numbers in this document actually coming from that
invocation, not a manual binary call.

## What's next here (Roadmap Phase 2)

- Benchmark `gov-supply-chain-integrity`'s predicate once it has a real
  circuit (still doesn't — see `zk-poc/README.md`; both circuits above
  now do).
- Re-run on dedicated (non-shared, multi-core) hardware once available,
  and report both, rather than replacing the sandbox numbers — the
  difference itself is informative for anyone reasoning about deployment
  cost on constrained hardware (e.g. an on-prem compliance appliance).
- Throughput under concurrency (proofs/sec with multiple provers running
  in parallel) — not measured here; everything above is single-threaded,
  single-process latency only.
- Once `mesh/` has a real network transport (Roadmap Phase 5), benchmark
  end-to-end gossip propagation latency, not just local proof/verify cost.
