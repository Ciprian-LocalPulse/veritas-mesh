//! Pluggable proof backend interface. See module-level docs in `lib.rs` and
//! in `groth16.rs`/`stark.rs` for what's real vs. placeholder today.

pub mod groth16;
pub mod groth16_bn254;
pub mod stark;

use serde::{Deserialize, Serialize};

use crate::errors::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum ProofSystemId {
    /// Signed-hash-commitment placeholder used by `stark` today (and
    /// still available from `groth16` for anyone testing against the
    /// old interface, though `groth16_bn254` is the real backend now).
    ToyHashCommitment = 0,
    /// Real Groth16 over BN254 (`groth16_bn254.rs`), per RFC-0002's
    /// amended curve choice. One backend struct per rule module (see
    /// that file) -- this ID tags the proof system itself, which rule
    /// it's for is determined by which backend instance produced it,
    /// same as `zk-poc`'s `setup`/`setup_healthcare` are already
    /// separate functions rather than one parameterized by rule.
    Groth16Bn254 = 2,
}

/// Backend-tagged proof payload. Kept as an enum (not `Vec<u8>`) so
/// deserialization can't silently hand a Groth16 verifier a STARK proof
/// once real backends exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proof {
    Toy(ToyProof),
    /// Canonically-serialized (`ark_serialize::CanonicalSerialize`)
    /// `ark_groth16::Proof<ark_bn254::Bn254>` bytes. Always 128 bytes for
    /// a valid proof from either circuit in `zk-poc/` (see
    /// `BENCHMARKS.md`) -- Groth16 proof size depends on the curve and
    /// proof system, not the circuit, so this is not a coincidence.
    Groth16Bn254(Vec<u8>),
}

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Proof::Toy(p) => p.payload.clone(),
            Proof::Groth16Bn254(bytes) => bytes.clone(),
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
