//! PLACEHOLDER — implements `ProofSystem` but is NOT a STARK.
//!
//! A real implementation here means, roughly:
//!   1. Express each compliance rule as an AIR (algebraic intermediate
//!      representation) — a trace table + transition constraints — using
//!      `winterfell::Air`.
//!   2. `prove` = `winterfell::prove(...)` over that AIR with the witness as
//!      the execution trace.
//!   3. `verify` = `winterfell::verify(...)`, transparent (no trusted
//!      setup, unlike Groth16 — that tradeoff is exactly what RFC-0002 is
//!      supposed to decide between: STARKs are bigger proofs / no setup,
//!      Groth16 is tiny proofs / needs a ceremony per circuit).
//!
//! Same caveat as `groth16.rs`: this file exists so the `ProofSystem` trait
//! has two real call sites to develop against, not because it's a STARK.

use sha2::{Digest, Sha256};

use super::{Proof, ProofSystem, ProofSystemId, ToyProof};
use crate::errors::{Result, VeritasError};

pub struct StarkPlaceholder;

impl ProofSystem for StarkPlaceholder {
    fn id(&self) -> ProofSystemId {
        ProofSystemId::ToyHashCommitment
    }

    fn prove(&self, witness: &[u8], public_input: &[u8]) -> Result<Proof> {
        let mut hasher = Sha256::new();
        hasher.update(b"stark-placeholder-v0"); // different domain tag than groth16.rs
        hasher.update(witness);
        hasher.update(public_input);
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(Proof::Toy(ToyProof {
            payload: digest.to_vec(),
        }))
    }

    fn verify(&self, proof: &Proof, _public_input: &[u8]) -> Result<()> {
        match proof {
            Proof::Toy(p) if p.payload.len() == 32 => Ok(()),
            _ => Err(VeritasError::InvalidProof(
                "stark placeholder: malformed payload".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_produces_32_byte_digest() {
        let backend = StarkPlaceholder;
        let proof = backend.prove(b"secret witness", b"public claim").unwrap();
        assert!(backend.verify(&proof, b"public claim").is_ok());
    }

    #[test]
    fn groth16_and_stark_placeholders_diverge_on_same_input() {
        use super::super::groth16::Groth16Placeholder;
        let g = Groth16Placeholder.prove(b"w", b"p").unwrap();
        let s = StarkPlaceholder.prove(b"w", b"p").unwrap();
        assert_ne!(g, s, "domain separation between placeholder backends must hold");
    }
}
