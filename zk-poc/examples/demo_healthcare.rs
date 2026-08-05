//! Run with: `cargo run --package veritas-zk-poc --example demo_healthcare --release`
//!
//! Same purpose as `examples/demo.rs`, for the second real circuit:
//! `HealthcareDisclosureCircuit` (see `src/healthcare_circuit.rs`).

use std::time::Instant;

use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use veritas_zk_poc::healthcare_circuit::{EntryWitness, HealthcareDisclosureCircuit, MAX_ENTRIES};
use veritas_zk_poc::{prove_healthcare, setup_healthcare, verify_healthcare};

fn main() {
    println!("=== Veritas Mesh zk-poc: healthcare-hipaa disclosure logging (real Groth16) ===\n");

    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    HealthcareDisclosureCircuit::setup_shape(Fr::from(0u64))
        .generate_constraints(cs.clone())
        .expect("constraint generation should succeed");
    println!("Constraint count: {}", cs.num_constraints());
    println!("Witness variables: {}", cs.num_witness_variables());
    println!("Public input variables: {}", cs.num_instance_variables());
    println!("MAX_ENTRIES (fixed circuit capacity): {}\n", MAX_ENTRIES);

    let t0 = Instant::now();
    let keys = setup_healthcare(42).expect("setup should succeed");
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

    // A record accessed 5 times, all authorized, 11 unused padding slots.
    let record_id = Fr::from(0xABCDu64);
    let mut entries = [EntryWitness::EMPTY; MAX_ENTRIES];
    for e in entries.iter_mut().take(5) {
        *e = EntryWitness {
            is_active: true,
            authorized: true,
        };
    }
    let observed_access_count = 5u64;

    let t1 = Instant::now();
    let proof = prove_healthcare(
        &keys.proving_key,
        record_id,
        observed_access_count,
        &entries,
        1337,
    )
    .expect("proving should succeed for a genuinely compliant disclosure log");
    println!(
        "Proof generation (5 accesses, all authorized, {} padding slots, private): {:?}",
        MAX_ENTRIES - 5,
        t1.elapsed()
    );

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    println!("Proof size: {} bytes\n", proof_bytes.len());

    let t2 = Instant::now();
    let valid = verify_healthcare(&keys.verifying_key, record_id, observed_access_count, &proof)
        .expect("verification should not error");
    println!(
        "Verification against public (record_id, observed_access_count=5): {valid} (in {:?})",
        t2.elapsed()
    );
    println!(
        "\nNote: the verifier above never saw WHICH slots were the 5 real entries, WHO accessed"
    );
    println!("the record, WHEN, or which of the 16 slots were unused padding.");

    println!("\n--- Now attempting to prove a FALSE claim (1 of 5 active entries unauthorized) ---");
    let mut bad_entries = entries;
    bad_entries[2].authorized = false;
    match prove_healthcare(&keys.proving_key, record_id, 5, &bad_entries, 7) {
        Ok(_) => println!(
            "UNEXPECTED: a proof was produced for a false claim -- this would be a soundness bug."
        ),
        Err(e) => println!("Correctly failed to produce a proof: {e}"),
    }

    println!("\n--- And a count mismatch (5 claimed, only 4 actually active) ---");
    let mut undercount_entries = entries;
    undercount_entries[4].is_active = false;
    match prove_healthcare(&keys.proving_key, record_id, 5, &undercount_entries, 7) {
        Ok(_) => println!(
            "UNEXPECTED: a proof was produced for a false claim -- this would be a soundness bug."
        ),
        Err(e) => println!("Correctly failed to produce a proof: {e}"),
    }
}
