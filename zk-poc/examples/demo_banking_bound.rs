//! Run with: `cargo run --package veritas-zk-poc --example demo_banking_bound --release`
//!
//! Demonstrates `BankingBoundCircuit` -- the circuit that closes
//! `core::attest`'s documented commitment/proof binding gap for
//! `banking-basel-iii`. See `src/bound_circuit.rs`'s module docs for the
//! full design.

use std::time::Instant;

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use veritas_zk_poc::bound_circuit::BankingBoundCircuit;
use veritas_zk_poc::{prove_banking_bound, setup_banking_bound, verify_banking_bound};

fn commitment(salt: &[u8; 32], amount: u64, threshold: u64, cid: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(amount.to_le_bytes());
    hasher.update(threshold.to_le_bytes());
    hasher.update(cid);
    hasher.finalize().into()
}

fn main() {
    println!("=== Veritas Mesh zk-poc: banking-basel-iii, commitment-bound (real Groth16 + real SHA-256 R1CS gadget) ===\n");

    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    BankingBoundCircuit::setup_shape(0)
        .generate_constraints(cs.clone())
        .expect("constraint generation should succeed");
    println!("Constraint count: {}", cs.num_constraints());
    println!(
        "Public input variables: {} (256 for the commitment digest + 64 for threshold's bits)\n",
        cs.num_instance_variables()
    );

    let t0 = Instant::now();
    let keys = setup_banking_bound(42).expect("setup should succeed");
    println!("Trusted setup: {:?}", t0.elapsed());

    let mut pk_bytes = Vec::new();
    keys.proving_key
        .serialize_compressed(&mut pk_bytes)
        .unwrap();
    println!("Proving key size: {} bytes\n", pk_bytes.len());

    let salt = [0x11u8; 32];
    let cid = [0x22u8; 32];
    let (amount, threshold) = (50_000u64, 100_000u64);
    let commit = commitment(&salt, amount, threshold, &cid);

    let t1 = Instant::now();
    let proof = prove_banking_bound(&keys.proving_key, commit, threshold, amount, cid, salt, 1337)
        .expect("proving should succeed for a genuinely matching commitment and predicate");
    println!("Proof generation: {:?}", t1.elapsed());

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    println!("Proof size: {} bytes\n", proof_bytes.len());

    let t2 = Instant::now();
    let valid = verify_banking_bound(&keys.verifying_key, commit, threshold, &proof)
        .expect("verification should not error");
    println!(
        "Verification against the real (commitment, threshold): {valid} (in {:?})",
        t2.elapsed()
    );

    println!("\n--- The attack this circuit exists to prevent ---");
    println!("A commitment to amount=999,999 (real), a proof attempted for amount=1 (different):");
    let mismatched_commitment = commitment(&salt, 999_999, threshold, &cid);
    match prove_banking_bound(&keys.proving_key, mismatched_commitment, threshold, 1, cid, salt, 7) {
        Ok(_) => println!(
            "UNEXPECTED: a proof was produced -- this would mean the binding doesn't work."
        ),
        Err(e) => println!("Correctly refused to produce a proof: {e}"),
    }

    println!("\n--- Compare against BENCHMARKS.md's unbound TransactionThresholdCircuit numbers ---");
    println!("(129 constraints, 128-byte proofs, ~9ms to prove) -- the gap between that and the");
    println!("numbers above is the real cost of the SHA-256 binding, not a different predicate.");
}
