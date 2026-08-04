//! Pluggable proof backend interface. See module-level docs in `lib.rs` and
//! in `groth16.rs`/`stark.rs` for what's real vs. placeholder today.

pub mod groth16;
pub mod stark;

use serde::{Deserialize, Serialize};

use crate::errors::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum ProofSystemId {
    /// Signed-hash-commitment placeholder used by both `groth16` and
    /// `stark` modules today. Real backends will get their own variants
    /// (e.g. `Groth16Bn254 = 2`) once RFC-0002 lands — the numbering here
    /// is deliberately left with gaps for that.
    ToyHashCommitment = 0,
}

/// Backend-tagged proof payload. Kept as an enum (not `Vec<u8>`) so
/// deserialization can't silently hand a Groth16 verifier a STARK proof
/// once real backends exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proof {
    Toy(ToyProof),
}

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Proof::Toy(p) => p.payload.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToyProof {
    pub payload: Vec<u8>,
}

/// Every proof backend implements this. `witness` is the private input;
/// `public_input` is what the verifier is allowed to see.
pub trait ProofSystem {
    fn id(&self) -> ProofSystemId;

    fn prove(&self, witness: &[u8], public_input: &[u8]) -> Result<Proof>;

    fn verify(&self, proof: &Proof, public_input: &[u8]) -> Result<()>;
}
