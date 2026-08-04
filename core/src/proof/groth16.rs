//! PLACEHOLDER — implements `ProofSystem` but is NOT a Groth16 SNARK.
//!
//! A real implementation here means, roughly:
//!   1. Express each compliance rule (see `core::circuits`) as an R1CS
//!      circuit using `arkworks` (`ark-relations::r1cs::ConstraintSynthesizer`).
//!   2. Run the Groth16 trusted setup (`ark-groth16::generate_random_parameters`)
//!      per-circuit, and publish/ceremony the resulting proving/verifying keys
//!      — this is a real operational concern (who runs the ceremony, how is
//!      toxic waste destroyed) not just a library call.
//!   3. `prove` = `ark_groth16::create_random_proof`, `verify` =
//!      `ark_groth16::verify_proof`.
//!   4. Proof size is ~200 bytes and verification is O(1) pairings —
//!      that succinctness is the entire point of using Groth16 over just
//!      shipping the witness; this placeholder has none of it.
//!
//! What this file actually does: commits to `witness`, signs nothing (the
//! caller signs the whole `Attestation` separately in `signature.rs`), and
//! calls that a "proof." It proves the prover *had* some witness bytes at
//! proving time and is willing to reveal a hash of them — it proves nothing
//! about the *content* of the witness, and the "public_input" isn't bound
//! into the proof at all. Do not treat `verify()` returning `Ok(())` as a
//! zero-knowledge or soundness guarantee of anything.

use sha2::{Digest, Sha256};

use super::{Proof, ProofSystem, ProofSystemId, ToyProof};
use crate::errors::{Result, VeritasError};

pub struct Groth16Placeholder;

impl ProofSystem for Groth16Placeholder {
    fn id(&self) -> ProofSystemId {
        ProofSystemId::ToyHashCommitment
    }

    fn prove(&self, witness: &[u8], public_input: &[u8]) -> Result<Proof> {
        let mut hasher = Sha256::new();
        hasher.update(b"groth16-placeholder-v0");
        hasher.update(witness);
        hasher.update(public_input);
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(Proof::Toy(ToyProof {
            payload: digest.to_vec(),
        }))
    }

    fn verify(&self, proof: &Proof, _public_input: &[u8]) -> Result<()> {
        // There is nothing sound to check here without the witness — a
        // real backend verifies against public_input + verifying key
        // without needing the witness at all. Placeholder just checks shape.
        match proof {
            Proof::Toy(p) if p.payload.len() == 32 => Ok(()),
            _ => Err(VeritasError::InvalidProof(
                "groth16 placeholder: malformed payload".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_produces_32_byte_digest() {
        let backend = Groth16Placeholder;
        let proof = backend.prove(b"secret witness", b"public claim").unwrap();
        assert!(backend.verify(&proof, b"public claim").is_ok());
    }
}
