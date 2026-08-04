//! Commitment schemes: bind a prover to private input data without
//! revealing it, until opened.

pub mod hash_based;
pub mod pedersen;

use crate::errors::Result;

/// Common trait so `core::circuits` doesn't care which scheme is active.
/// The concrete scheme in use is decided by RFC-0003.
pub trait CommitmentScheme {
    type Commitment: AsRef<[u8]> + Clone;
    type Opening: Clone;

    fn commit(&self, data: &[u8]) -> (Self::Commitment, Self::Opening);
    fn verify(&self, commitment: &Self::Commitment, opening: &Self::Opening, data: &[u8]) -> Result<()>;
}
