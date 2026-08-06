//! Benchmarks the REAL `groth16_bn254` backends through the
//! `ProofSystem` trait -- as opposed to `proof_generation.rs` (the
//! placeholder hash-sign backends) or `zk-poc/examples/bench.rs` (the
//! same circuits called directly, without this crate's JSON
//! serialize/deserialize wrapping layer). The gap between this file's
//! numbers and `zk-poc/examples/bench.rs`'s is the actual cost of that
//! wrapping layer -- worth knowing, since `BENCHMARKS.md` said "this is
//! the number to diff against" once a real backend landed, and now one
//! has.
//!
//! `harness = false` for this target -- see `Cargo.toml`'s comment.
//!
//! Run with: `cargo bench --package veritas-core --bench groth16_bn254`

use std::time::{Duration, Instant};

use veritas_core::proof::groth16_bn254::{BankingGroth16Backend, HealthcareGroth16Backend};
use veritas_core::proof::{Proof, ProofSystem};

const SETUP_SEED: u64 = 42;
const PROVE_TRIALS: u32 = 30;
const VERIFY_TRIALS: u32 = 100;

fn stats(label: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let n = samples.len();
    let total: Duration = samples.iter().sum();
    let mean_us = total.as_micros() as f64 / n as f64;
    let min_us = samples.first().unwrap().as_micros();
    let max_us = samples.last().unwrap().as_micros();
    let p50_us = samples[n / 2].as_micros();
    println!("{label}: n={n} mean={mean_us:.0}us min={min_us}us p50={p50_us}us max={max_us}us");
}

fn main() {
    println!("=== veritas-core: real Groth16-over-BN254 backends, via ProofSystem trait ===\n");
    println!(
        "(compare against zk-poc/examples/bench.rs's numbers in BENCHMARKS.md -- the gap is"
    );
    println!("this crate's JSON witness/public-input wrapping overhead, not the ZK cost itself.)\n");

    // --- banking-basel-iii ---
    let banking = BankingGroth16Backend::setup(SETUP_SEED).expect("setup should succeed");
    let witness = br#"{"transaction_amount_minor":50000}"#;
    let public_input = br#"{"risk_adjusted_threshold_minor":100000}"#;

    let mut prove_times = Vec::with_capacity(PROVE_TRIALS as usize);
    let mut last_proof: Option<Proof> = None;
    for _ in 0..PROVE_TRIALS {
        let t0 = Instant::now();
        let proof = banking
            .prove(witness, public_input)
            .expect("proving should succeed for a compliant transaction");
        prove_times.push(t0.elapsed());
        last_proof = Some(proof);
    }
    stats("banking: prove() via ProofSystem trait", prove_times);

    let proof = last_proof.unwrap();
    let mut verify_times = Vec::with_capacity(VERIFY_TRIALS as usize);
    for _ in 0..VERIFY_TRIALS {
        let t0 = Instant::now();
        banking
            .verify(&proof, public_input)
            .expect("verification should succeed");
        verify_times.push(t0.elapsed());
    }
    stats("banking: verify() via ProofSystem trait", verify_times);
    println!();

    // --- healthcare-hipaa ---
    let healthcare = HealthcareGroth16Backend::setup(SETUP_SEED).expect("setup should succeed");
    let hc_witness =
        br#"{"entries":[{"is_active":true,"authorized":true},{"is_active":true,"authorized":true},{"is_active":false,"authorized":false}]}"#;
    let hc_public = br#"{"record_id_hash":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],"observed_access_count":2}"#;

    let mut hc_prove_times = Vec::with_capacity(PROVE_TRIALS as usize);
    let mut hc_last_proof: Option<Proof> = None;
    for _ in 0..PROVE_TRIALS {
        let t0 = Instant::now();
        let proof = healthcare
            .prove(hc_witness, hc_public)
            .expect("proving should succeed for a compliant log");
        hc_prove_times.push(t0.elapsed());
        hc_last_proof = Some(proof);
    }
    stats("healthcare: prove() via ProofSystem trait", hc_prove_times);

    let hc_proof = hc_last_proof.unwrap();
    let mut hc_verify_times = Vec::with_capacity(VERIFY_TRIALS as usize);
    for _ in 0..VERIFY_TRIALS {
        let t0 = Instant::now();
        healthcare
            .verify(&hc_proof, hc_public)
            .expect("verification should succeed");
        hc_verify_times.push(t0.elapsed());
    }
    stats("healthcare: verify() via ProofSystem trait", hc_verify_times);

    println!("\nSame single-vCPU sandbox hardware caveat as the rest of BENCHMARKS.md applies.");
}
