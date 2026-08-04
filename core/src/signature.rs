//! Ed25519 sign/verify over `Attestation::signing_bytes()`.
//! This layer is real: no placeholders, standard `ed25519-dalek` v2.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

use crate::attestation::Attestation;
use crate::errors::{Result, VeritasError};

pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign an attestation in place (fills `prover_public_key` + `signature`).
    pub fn sign_attestation(&self, mut attestation: Attestation) -> Attestation {
        attestation.prover_public_key = self.public_key_bytes();
        let sig: Signature = self.signing_key.sign(&attestation.signing_bytes());
        attestation.signature = sig.to_bytes();
        attestation
    }
}

/// Verify `attestation.signature` against `attestation.prover_public_key`.
pub fn verify_attestation(attestation: &Attestation) -> Result<()> {
    let vk = VerifyingKey::from_bytes(&attestation.prover_public_key)
        .map_err(|e| VeritasError::KeyMaterial(e.to_string()))?;
    let sig = Signature::from_bytes(&attestation.signature);
    vk.verify(&attestation.signing_bytes(), &sig)
        .map_err(|_| VeritasError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::{Proof, ProofSystemId, ToyProof};

    fn sample_unsigned() -> Attestation {
        Attestation {
            schema_version: crate::attestation::SCHEMA_VERSION,
            rule_id: "healthcare-hipaa".into(),
            proof_system: ProofSystemId::ToyHashCommitment,
            input_commitment: vec![4, 5, 6],
            proof: Proof::Toy(ToyProof { payload: vec![1] }),
            prover_public_key: [0u8; 32],
            signature: [0u8; 64],
            issued_at_unix: 1_700_000_001,
        }
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let kp = Keypair::generate();
        let signed = kp.sign_attestation(sample_unsigned());
        assert!(verify_attestation(&signed).is_ok());
    }

    #[test]
    fn tampered_attestation_fails_verification() {
        let kp = Keypair::generate();
        let mut signed = kp.sign_attestation(sample_unsigned());
        signed.issued_at_unix += 1; // mutate after signing
        assert!(verify_attestation(&signed).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let mut signed = kp_a.sign_attestation(sample_unsigned());
        signed.prover_public_key = kp_b.public_key_bytes();
        assert!(verify_attestation(&signed).is_err());
    }
}
