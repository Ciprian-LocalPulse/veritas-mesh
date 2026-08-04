//! Statistical benchmark for the REAL Groth16 circuit in this crate --
//! companion to `examples/demo.rs`, which prints one illustrative run.
//! This one runs enough trials to report mean/min/max/p50/p95, because a
//! single timing (as demo.rs prints) can't distinguish "this is roughly
//! how long it takes" from "I got lucky/unlucky once."
//!
//! Run with: `cargo run --package veritas-zk-poc --release --example bench`
//!
//! Numbers below are from THIS run, on whatever machine executed it -- see
//! BENCHMARKS.md at the repo root for the full caveat about hardware
//! representativeness before quoting them anywhere external.

use std::time::{Duration, Instant};

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use veritas_zk_poc::circuit::TransactionThresholdCircuit;
use veritas_zk_poc::{prove, setup, verify};

const SETUP_TRIALS: u32 = 5;
const PROVE_TRIALS: u32 = 50;
const VERIFY_TRIALS: u32 = 200;

fn stats(label: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let n = samples.len();
    let total: Duration = samples.iter().sum();
    let mean_us = total.as_micros() as f64 / n as f64;
    let min_us = samples.first().unwrap().as_micros();
    let max_us = samples.last().unwrap().as_micros();
    let p50_us = samples[n / 2].as_micros();
    let p95_idx = ((n * 95) / 100).min(n - 1);
    let p95_us = samples[p95_idx].as_micros();
    println!(
        "{label}: n={n} mean={mean_us:.0}us min={min_us}us p50={p50_us}us p95={p95_us}us max={max_us}us"
    );
}

fn main() {
    println!("=== Veritas Mesh zk-poc: statistical benchmark (real Groth16/BN254) ===\n");

    // Constraint shape, independent of witness values or trial count.
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    TransactionThresholdCircuit::setup_shape(0)
        .generate_constraints(cs.clone())
        .expect("constraint generation should succeed");
    println!("Circuit shape (banking-basel-iii, RANGE_BITS=64):");
    println!("  Constraints: {}", cs.num_constraints());
    println!("  Witness variables: {}", cs.num_witness_variables());
    println!("  Public input variables: {}\n", cs.num_instance_variables());

    // --- Setup ---
    let mut setup_times = Vec::with_capacity(SETUP_TRIALS as usize);
    let mut keys = None;
    for seed in 0..SETUP_TRIALS {
        let t0 = Instant::now();
        let k = setup(seed as u64).expect("setup should succeed");
        setup_times.push(t0.elapsed());
        keys = Some(k); // keep the last one for prove/verify below
    }
    let keys = keys.unwrap();
    stats("Trusted setup (per-run, NOT a ceremony)", setup_times);

    let mut pk_bytes = Vec::new();
    keys.proving_key
        .serialize_compressed(&mut pk_bytes)
        .unwrap();
    let mut vk_bytes = Vec::new();
    keys.verifying_key
        .serialize_compressed(&mut vk_bytes)
        .unwrap();
    println!("Proving key size: {} bytes", pk_bytes.len());
    println!("Verifying key size: {} bytes\n", vk_bytes.len());

    // --- Proof generation, across a spread of witness magnitudes ---
    // Varying `amount` matters for exactly one reason worth checking: this
    // circuit's proof and timing should NOT vary meaningfully with the
    // amount's magnitude, since that would itself be a side channel (see
    // spec/THREAT_ANALYSIS.md S5.4). This isn't a rigorous side-channel
    // audit -- see BENCHMARKS.md -- but wildly different timings across
    // these three would be worth investigating before ever claiming
    // otherwise.
    let threshold = 1_000_000_000_000u64;
    let witness_cases: [(&str, u64); 3] = [
        ("small (amount=1)", 1),
        ("mid (amount=threshold/2)", threshold / 2),
        ("near-boundary (amount=threshold-1)", threshold - 1),
    ];

    let mut proof_size_bytes = 0usize;
    let mut last_proof = None;
    for (case_label, amount) in witness_cases {
        let mut prove_times = Vec::with_capacity(PROVE_TRIALS as usize);
        for trial in 0..PROVE_TRIALS {
            let t0 = Instant::now();
            let proof = prove(&keys.proving_key, amount, threshold, trial as u64)
                .expect("proving should succeed for amount <= threshold");
            prove_times.push(t0.elapsed());
            if trial == 0 {
                let mut buf = Vec::new();
                proof.serialize_compressed(&mut buf).unwrap();
                proof_size_bytes = buf.len();
                last_proof = Some(proof);
            }
        }
        stats(&format!("Proof generation, {case_label}"), prove_times);
    }
    println!("Proof size (constant across all three cases above): {proof_size_bytes} bytes\n");

    // --- Verification ---
    let proof = last_proof.unwrap();
    let mut verify_times = Vec::with_capacity(VERIFY_TRIALS as usize);
    for _ in 0..VERIFY_TRIALS {
        let t0 = Instant::now();
        let valid =
            verify(&keys.verifying_key, threshold, &proof).expect("verification should not error");
        assert!(valid);
        verify_times.push(t0.elapsed());
    }
    stats("Verification", verify_times);

    println!("\nAll timings above are from a single process on whatever CPU ran this");
    println!("benchmark -- see BENCHMARKS.md for hardware details and why these numbers");
    println!("should not be treated as production-representative without re-running on");
    println!("target hardware.");
}
