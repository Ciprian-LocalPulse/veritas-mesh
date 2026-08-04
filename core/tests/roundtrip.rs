//! End-to-end: build an attestation over a real rule check, commit the
//! input, "prove" (placeholder backend), sign, serialize, deserialize,
//! verify signature + commitment + proof shape. This is the full pipeline
//! every layer (mesh gossip, dashboard, SDKs) will eventually call through.

use veritas_core::attestation::{Attestation, SCHEMA_VERSION};
use veritas_core::circuits::banking_basel_iii::{TransactionThresholdInput, TransactionThresholdRule};
use veritas_core::circuits::Rule;
use veritas_core::commitment::hash_based::HashBasedScheme;
use veritas_core::commitment::CommitmentScheme;
use veritas_core::proof::groth16::Groth16Placeholder;
use veritas_core::proof::{ProofSystem, ProofSystemId};
use veritas_core::signature::{verify_attestation, Keypair};

fn sample_input() -> TransactionThresholdInput {
    use sha2::{Digest, Sha256};
    TransactionThresholdInput {
        transaction_amount_minor: 9_999_00,
        risk_adjusted_threshold_minor: 10_000_00,
        customer_id_hash: Sha256::digest(b"customer-42").into(),
    }
}

#[test]
fn full_pipeline_generate_verify_accept() {
    let input = sample_input();

    // 1. Rule must actually hold before we bother proving anything.
    TransactionThresholdRule::check(&input).expect("rule should be satisfied by sample input");

    // 2. Commit to the witness.
    let witness_bytes = TransactionThresholdRule::canonical_bytes(&input);
    let scheme = HashBasedScheme;
    let (commitment, _opening) = scheme.commit(&witness_bytes);

    // 3. Prove (placeholder backend).
    let backend = Groth16Placeholder;
    let public_input = TransactionThresholdRule::RULE_ID.as_bytes();
    let proof = backend.prove(&witness_bytes, public_input).unwrap();
    backend.verify(&proof, public_input).expect("placeholder proof should verify");

    // 4. Assemble + sign the attestation.
    let keypair = Keypair::generate();
    let unsigned = Attestation {
        schema_version: SCHEMA_VERSION,
        rule_id: TransactionThresholdRule::RULE_ID.to_string(),
        proof_system: ProofSystemId::ToyHashCommitment,
        input_commitment: commitment.0.to_vec(),
        proof,
        prover_public_key: [0u8; 32],
        signature: [0u8; 64],
        issued_at_unix: 1_700_000_000,
    };
    let signed = keypair.sign_attestation(unsigned);

    // 5. Serialize / deserialize (simulating gossip over the wire).
    let json = signed.to_json().unwrap();
    let reconstructed = Attestation::from_json(&json).unwrap();
    assert_eq!(signed, reconstructed);

    // 6. Verifier side: schema + signature + proof shape.
    reconstructed.validate_schema().unwrap();
    verify_attestation(&reconstructed).expect("signature should verify");
    backend
        .verify(&reconstructed.proof, TransactionThresholdRule::RULE_ID.as_bytes())
        .expect("proof should still verify after round trip");
}
