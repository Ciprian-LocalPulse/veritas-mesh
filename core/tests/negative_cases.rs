//! Every case here should be REJECTED. If any of these start passing, that's
//! a regression, not a feature.

use veritas_core::attestation::{Attestation, SCHEMA_VERSION};
use veritas_core::circuits::banking_basel_iii::{TransactionThresholdInput, TransactionThresholdRule};
use veritas_core::circuits::Rule;
use veritas_core::commitment::hash_based::HashBasedScheme;
use veritas_core::commitment::CommitmentScheme;
use veritas_core::proof::groth16::Groth16Placeholder;
use veritas_core::proof::{Proof, ProofSystem, ProofSystemId, ToyProof};
use veritas_core::signature::{verify_attestation, Keypair};

fn base_attestation() -> Attestation {
    use sha2::{Digest, Sha256};
    let input = TransactionThresholdInput {
        transaction_amount_minor: 100,
        risk_adjusted_threshold_minor: 1000,
        customer_id_hash: Sha256::digest(b"customer-1").into(),
    };
    let witness_bytes = TransactionThresholdRule::canonical_bytes(&input);
    let (commitment, _) = HashBasedScheme.commit(&witness_bytes);
    let backend = Groth16Placeholder;
    let proof = backend.prove(&witness_bytes, TransactionThresholdRule::RULE_ID.as_bytes()).unwrap();

    let keypair = Keypair::generate();
    keypair.sign_attestation(Attestation {
        schema_version: SCHEMA_VERSION,
        rule_id: TransactionThresholdRule::RULE_ID.to_string(),
        proof_system: ProofSystemId::ToyHashCommitment,
        input_commitment: commitment.0.to_vec(),
        proof,
        prover_public_key: [0u8; 32],
        signature: [0u8; 64],
        issued_at_unix: 1_700_000_000,
    })
}

#[test]
fn rule_violation_is_caught_before_proving() {
    use sha2::{Digest, Sha256};
    let bad_input = TransactionThresholdInput {
        transaction_amount_minor: 1_000_01,
        risk_adjusted_threshold_minor: 1_000_00,
        customer_id_hash: Sha256::digest(b"customer-1").into(),
    };
    assert!(TransactionThresholdRule::check(&bad_input).is_err());
}

#[test]
fn tampered_rule_id_fails_signature_verification() {
    let mut a = base_attestation();
    a.rule_id = "healthcare-hipaa".to_string(); // forged after signing
    assert!(verify_attestation(&a).is_err());
}

#[test]
fn tampered_commitment_fails_signature_verification() {
    let mut a = base_attestation();
    a.input_commitment[0] ^= 0xFF;
    assert!(verify_attestation(&a).is_err());
}

#[test]
fn tampered_timestamp_fails_signature_verification() {
    let mut a = base_attestation();
    a.issued_at_unix += 3600;
    assert!(verify_attestation(&a).is_err());
}

#[test]
fn substituted_proof_fails_signature_verification() {
    let mut a = base_attestation();
    a.proof = Proof::Toy(ToyProof { payload: vec![0u8; 32] });
    assert!(verify_attestation(&a).is_err());
}

#[test]
fn malformed_proof_payload_fails_backend_verification() {
    let backend = Groth16Placeholder;
    let bad_proof = Proof::Toy(ToyProof { payload: vec![1, 2, 3] }); // not 32 bytes
    assert!(backend.verify(&bad_proof, b"anything").is_err());
}

#[test]
fn old_schema_version_is_rejected() {
    let mut a = base_attestation();
    a.schema_version = 0;
    assert!(a.validate_schema().is_err());
}
