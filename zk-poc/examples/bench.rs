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

use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use veritas_zk_poc::circuit::TransactionThresholdCircuit;
use veritas_zk_poc::healthcare_circuit::{EntryWitness, HealthcareDisclosureCircuit, MAX_ENTRIES};
use veritas_zk_poc::{prove, prove_healthcare, setup, setup_healthcare, verify, verify_healthcare};

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

    // ============================================================
    // Circuit 2: healthcare-hipaa
    // ============================================================
    println!("\n\n=== healthcare-hipaa: statistical benchmark ===\n");

    let cs2 = ConstraintSystem::new_ref();
    cs2.set_mode(SynthesisMode::Setup);
    HealthcareDisclosureCircuit::setup_shape(Fr::from(0u64))
        .generate_constraints(cs2.clone())
        .expect("constraint generation should succeed");
    println!(
        "Circuit shape (healthcare-hipaa, MAX_ENTRIES={}):",
        MAX_ENTRIES
    );
    println!("  Constraints: {}", cs2.num_constraints());
    println!("  Witness variables: {}", cs2.num_witness_variables());
    println!(
        "  Public input variables: {}\n",
        cs2.num_instance_variables()
    );

    let mut hc_setup_times = Vec::with_capacity(SETUP_TRIALS as usize);
    let mut hc_keys = None;
    for seed in 0..SETUP_TRIALS {
        let t0 = Instant::now();
        let k = setup_healthcare(seed as u64).expect("setup should succeed");
        hc_setup_times.push(t0.elapsed());
        hc_keys = Some(k);
    }
    let hc_keys = hc_keys.unwrap();
    stats("Trusted setup (per-run, NOT a ceremony)", hc_setup_times);

    let mut hc_pk_bytes = Vec::new();
    hc_keys
        .proving_key
        .serialize_compressed(&mut hc_pk_bytes)
        .unwrap();
    let mut hc_vk_bytes = Vec::new();
    hc_keys
        .verifying_key
        .serialize_compressed(&mut hc_vk_bytes)
        .unwrap();
    println!("Proving key size: {} bytes", hc_pk_bytes.len());
    println!("Verifying key size: {} bytes\n", hc_vk_bytes.len());

    // Spread across occupancy levels (few entries vs. full capacity), for
    // the same reason as the amount-magnitude spread above: proof
    // generation cost and proof size should not vary in a way that leaks
    // how many of the MAX_ENTRIES slots were actually real log entries.
    let record_id = Fr::from(0xC0FFEEu64);
    let occupancy_cases: [(&str, u64); 3] = [
        ("1 of 16 active", 1),
        ("8 of 16 active", 8),
        ("16 of 16 active (full)", MAX_ENTRIES as u64),
    ];

    let mut hc_proof_size_bytes = 0usize;
    let mut hc_last_proof = None;
    for (case_label, active_count) in occupancy_cases {
        let mut entries = [EntryWitness::EMPTY; MAX_ENTRIES];
        for e in entries.iter_mut().take(active_count as usize) {
            *e = EntryWitness {
                is_active: true,
                authorized: true,
            };
        }
        let mut prove_times = Vec::with_capacity(PROVE_TRIALS as usize);
        for trial in 0..PROVE_TRIALS {
            let t0 = Instant::now();
            let proof = prove_healthcare(
                &hc_keys.proving_key,
                record_id,
                active_count,
                &entries,
                trial as u64,
            )
            .expect("proving should succeed for a genuinely compliant log");
            prove_times.push(t0.elapsed());
            if trial == 0 {
                let mut buf = Vec::new();
                proof.serialize_compressed(&mut buf).unwrap();
                hc_proof_size_bytes = buf.len();
                hc_last_proof = Some((proof, active_count));
            }
        }
        stats(&format!("Proof generation, {case_label}"), prove_times);
    }
    println!(
        "Proof size (constant across all three occupancy levels above): {hc_proof_size_bytes} bytes\n"
    );

    let (hc_proof, hc_count) = hc_last_proof.unwrap();
    let mut hc_verify_times = Vec::with_capacity(VERIFY_TRIALS as usize);
    for _ in 0..VERIFY_TRIALS {
        let t0 = Instant::now();
        let valid = verify_healthcare(&hc_keys.verifying_key, record_id, hc_count, &hc_proof)
            .expect("verification should not error");
        assert!(valid);
        hc_verify_times.push(t0.elapsed());
    }
    stats("Verification", hc_verify_times);

    println!("\nSame hardware caveat as above applies to every number in this section.");
}
