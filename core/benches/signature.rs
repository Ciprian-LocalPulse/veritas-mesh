//! Plain `std::time`-based micro-benchmark for the ONE part of `core/`
//! that is real, working cryptography today (per STATUS.md): Ed25519
//! sign/verify over `Attestation::signing_bytes()`. Unlike
//! `proof_generation.rs`, these numbers ARE meaningful as-is -- this is
//! not a placeholder standing in for a future backend, it's the actual
//! signature layer every attestation goes through regardless of which
//! proof system RFC-0002 eventually selects.
//!
//! `harness = false` for this target in Cargo.toml -- see that file's
//! comment for why (default libtest harness silently no-ops `fn main()`
//! in a benches/ file with no `#[bench]` functions).
//!
//! Run with: `cargo bench --package veritas-core --bench signature`

use std::time::{Duration, Instant};

use veritas_core::attestation::Attestation;
use veritas_core::proof::{Proof, ProofSystemId, ToyProof};
use veritas_core::signature::{verify_attestation, Keypair};

const WARMUP_ITERS: u32 = 1_000;
const ITERS: u32 = 20_000;

fn sample_unsigned() -> Attestation {
    Attestation {
        schema_version: 1,
        rule_id: "banking-basel-iii".into(),
        proof_system: ProofSystemId::ToyHashCommitment,
        input_commitment: vec![7; 32],
        proof: Proof::Toy(ToyProof {
            payload: vec![9; 48],
        }),
        prover_public_key: [0u8; 32],
        signature: [0u8; 64],
        issued_at_unix: 1_700_000_001,
    }
}

/// Runs `f` `WARMUP_ITERS` times (discarded), then `ITERS` times, timing
/// only the second batch. Reports mean, min, max, and p50/p95/p99 over the
/// per-call latencies -- not just a single mean, since Ed25519 sign/verify
/// latency has visible tail variance under a shared, unpinned CPU (this
/// sandbox's, not necessarily representative production hardware -- see
/// BENCHMARKS.md for that caveat in full).
fn bench<F: FnMut() -> Duration>(label: &str, iters: u32, mut f: F) {
    for _ in 0..WARMUP_ITERS {
        f();
    }
    let mut samples: Vec<Duration> = Vec::with_capacity(iters as usize);
    for _ in 0..iters {
        samples.push(f());
    }
    samples.sort();

    let total: Duration = samples.iter().sum();
    let mean_ns = total.as_nanos() as f64 / iters as f64;
    let min_ns = samples.first().unwrap().as_nanos();
    let max_ns = samples.last().unwrap().as_nanos();
    let p50_ns = samples[(iters as usize) / 2].as_nanos();
    let p95_ns = samples[(iters as usize * 95) / 100].as_nanos();
    let p99_ns = samples[(iters as usize * 99) / 100].as_nanos();

    println!(
        "{label}: {iters} iterations, mean={mean_ns:.0}ns min={min_ns}ns p50={p50_ns}ns p95={p95_ns}ns p99={p99_ns}ns max={max_ns}ns"
    );
}

fn main() {
    println!("=== veritas-core: Ed25519 signature layer benchmark ===");
    println!("(real cryptography -- ed25519-dalek v2.0.0, no placeholder)\n");

    let keypair = Keypair::generate();
    let unsigned = sample_unsigned();

    bench("sign_attestation", ITERS, || {
        let u = unsigned.clone();
        let t0 = Instant::now();
        let _signed = keypair.sign_attestation(u);
        t0.elapsed()
    });

    let signed = keypair.sign_attestation(unsigned.clone());
    bench("verify_attestation (valid signature)", ITERS, || {
        let t0 = Instant::now();
        let _ = verify_attestation(&signed);
        t0.elapsed()
    });

    let mut tampered = signed.clone();
    tampered.issued_at_unix += 1;
    bench(
        "verify_attestation (tampered -- rejection path)",
        ITERS,
        || {
            let t0 = Instant::now();
            let _ = verify_attestation(&tampered);
            t0.elapsed()
        },
    );

    println!("\nNote: rejection-path timing above is NOT claimed constant-time --");
    println!("ed25519-dalek's verify() short-circuits on the first check that fails,");
    println!("so valid-vs-invalid verify() latency differing here is expected, not a");
    println!("finding. This benchmark is throughput/latency only, not a timing-side-");
    println!("channel analysis (see spec/THREAT_ANALYSIS.md S5.4 for that scope note).");
}
