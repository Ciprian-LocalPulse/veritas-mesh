//! Run with: `cargo run --package veritas-zk-poc --example demo --release`
//!
//! Prints concrete numbers (constraint count, proof size, timings) for the
//! real Groth16 circuit -- useful as evidence this isn't just "tests pass"
//! but an actual working zero-knowledge proof with measurable properties.

use std::time::Instant;

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use veritas_zk_poc::circuit::TransactionThresholdCircuit;
use veritas_zk_poc::{prove, setup, verify};

fn main() {
    println!("=== Veritas Mesh zk-poc: real Groth16 over BN254 ===\n");

    // Constraint count for the circuit shape (independent of witness values).
    // Setup mode: witness-assignment closures are not required to succeed,
    // matching what Groth16::circuit_specific_setup does internally --
    // this is why `setup()` itself works with `TransactionThresholdCircuit
    // { amount: None, .. }` but naively calling `generate_constraints` in
    // the default (proving) mode would panic on the missing assignment.
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    TransactionThresholdCircuit::setup_shape(0)
        .generate_constraints(cs.clone())
        .expect("constraint generation should succeed");
    println!("Constraint count: {}", cs.num_constraints());
    println!("Witness variables: {}", cs.num_witness_variables());
    println!("Public input variables: {}\n", cs.num_instance_variables());

    let t0 = Instant::now();
    let keys = setup(42).expect("setup should succeed");
    println!("Trusted setup: {:?}", t0.elapsed());

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

    let amount = 9_999_00u64;
    let threshold = 10_000_00u64;

    let t1 = Instant::now();
    let proof = prove(&keys.proving_key, amount, threshold, 1337).expect("proving should succeed");
    println!(
        "Proof generation (amount={amount} minor units, private): {:?}",
        t1.elapsed()
    );

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    println!("Proof size: {} bytes\n", proof_bytes.len());

    let t2 = Instant::now();
    let valid = verify(&keys.verifying_key, threshold, &proof).expect("verification should not error");
    println!(
        "Verification against public threshold={threshold}: {valid} (in {:?})",
        t2.elapsed()
    );
    println!("\nNote: the verifier above only ever saw `threshold`. `amount` was never transmitted.");

    println!("\n--- Now attempting to prove a FALSE claim (amount > threshold) ---");
    let bad_amount = threshold + 1;
    match prove(&keys.proving_key, bad_amount, threshold, 7) {
        Ok(_) => println!("UNEXPECTED: a proof was produced for a false claim -- this would be a soundness bug."),
        Err(e) => println!("Correctly failed to produce a proof: {e}"),
    }
}
