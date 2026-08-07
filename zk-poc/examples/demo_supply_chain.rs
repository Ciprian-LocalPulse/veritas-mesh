//! Run with: `cargo run --package veritas-zk-poc --example demo_supply_chain --release`
//!
//! Same purpose as `examples/demo.rs`/`demo_healthcare.rs`, for the third
//! and most expensive circuit: `SupplyChainIntegrityCircuit` (see
//! `src/supply_chain_circuit.rs`) -- the first (and only, so far) circuit
//! in this crate that computes a real hash (SHA-256) inside the R1CS
//! constraints, rather than just comparing/counting booleans.

use std::time::Instant;

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use veritas_zk_poc::supply_chain_circuit::{
    entry_linkage_hash, EntryWitness, SupplyChainIntegrityCircuit, MAX_ENTRIES,
};
use veritas_zk_poc::{prove_supply_chain, setup_supply_chain, verify_supply_chain};

fn main() {
    println!("=== Veritas Mesh zk-poc: gov-supply-chain-integrity hash chain (real Groth16 + real SHA-256 R1CS gadget) ===\n");

    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    SupplyChainIntegrityCircuit::setup_shape([0u8; 32], [0u8; 32])
        .generate_constraints(cs.clone())
        .expect("constraint generation should succeed");
    println!("Constraint count: {}", cs.num_constraints());
    println!(
        "Public input variables: {} (256 per SHA-256 digest -- see lib.rs's digest_to_field_elements doc comment for why)",
        cs.num_instance_variables()
    );
    println!("MAX_ENTRIES (fixed circuit capacity): {}\n", MAX_ENTRIES);

    let t0 = Instant::now();
    let keys = setup_supply_chain(42).expect("setup should succeed");
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
    println!(
        "Verifying key size: {} bytes (large relative to the other two circuits -- \
         directly because of the 512+ public inputs above, not a different proof system)\n",
        vk_bytes.len()
    );

    // A real 3-entry audit trail, hand-built the same way
    // core::circuits::gov_supply_chain's own tests build one.
    let genesis = [0x11u8; 32];
    let event_hashes = [[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]];
    let mut running = genesis;
    let mut entries = [EntryWitness::EMPTY; MAX_ENTRIES];
    for (i, eh) in event_hashes.iter().enumerate() {
        running = entry_linkage_hash(i as u64, eh, &running);
        entries[i] = EntryWitness {
            event_hash: *eh,
            is_active: true,
        };
    }
    let final_hash = running;

    let t1 = Instant::now();
    let proof = prove_supply_chain(&keys.proving_key, genesis, final_hash, 3, &entries, 1337)
        .expect("proving should succeed for a genuinely intact 3-entry chain");
    println!(
        "Proof generation (3-entry chain, {} padding slot, private): {:?}",
        MAX_ENTRIES - 3,
        t1.elapsed()
    );

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    println!("Proof size: {} bytes\n", proof_bytes.len());

    let t2 = Instant::now();
    let valid = verify_supply_chain(&keys.verifying_key, genesis, final_hash, 3, &proof)
        .expect("verification should not error");
    println!(
        "Verification against public (genesis_hash, final_linkage_hash, active_count=3): {valid} (in {:?})",
        t2.elapsed()
    );
    println!("\nNote: the verifier above never saw any of the 3 individual event_hash values.");

    println!("\n--- Now attempting to prove a FALSE claim (tampered middle event_hash) ---");
    let mut bad_entries = entries;
    bad_entries[1].event_hash = [0xFFu8; 32];
    match prove_supply_chain(&keys.proving_key, genesis, final_hash, 3, &bad_entries, 7) {
        Ok(_) => println!(
            "UNEXPECTED: a proof was produced for a false claim -- this would be a soundness bug."
        ),
        Err(e) => println!("Correctly failed to produce a proof: {e}"),
    }

    println!("\n--- And a broken prefix (active slot after an inactive one) ---");
    let mut broken_prefix = [EntryWitness::EMPTY; MAX_ENTRIES];
    broken_prefix[1] = EntryWitness {
        event_hash: [1u8; 32],
        is_active: true,
    };
    match prove_supply_chain(&keys.proving_key, genesis, [0u8; 32], 1, &broken_prefix, 7) {
        Ok(_) => println!(
            "UNEXPECTED: a proof was produced for a false claim -- this would be a soundness bug."
        ),
        Err(e) => println!("Correctly failed to produce a proof: {e}"),
    }
}
