//! Real, working commitment scheme: SHA-256(salt || data), salt revealed on open.
//! Computationally binding and hiding under the random-oracle assumption on
//! SHA-256. Not succinct and not homomorphic — fine as a default, but
//! `pedersen.rs` exists for schemes that need homomorphic aggregation.

use rand::RngCore;
use sha2::{Digest, Sha256};

use super::CommitmentScheme;
use crate::errors::{Result, VeritasError};

pub const SALT_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashCommitment(pub [u8; 32]);

impl AsRef<[u8]> for HashCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct HashOpening {
    pub salt: [u8; SALT_LEN],
}

pub struct HashBasedScheme;

impl HashBasedScheme {
    fn digest(salt: &[u8], data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(data);
        hasher.finalize().into()
    }
}

impl CommitmentScheme for HashBasedScheme {
    type Commitment = HashCommitment;
    type Opening = HashOpening;

    fn commit(&self, data: &[u8]) -> (HashCommitment, HashOpening) {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let digest = Self::digest(&salt, data);
        (HashCommitment(digest), HashOpening { salt })
    }

    fn verify(&self, commitment: &HashCommitment, opening: &HashOpening, data: &[u8]) -> Result<()> {
        let recomputed = Self::digest(&opening.salt, data);
        if recomputed == commitment.0 {
            Ok(())
        } else {
            Err(VeritasError::CommitmentMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_and_open_roundtrip() {
        let scheme = HashBasedScheme;
        let data = b"account_balance=104213.55;jurisdiction=RO";
        let (c, o) = scheme.commit(data);
        assert!(scheme.verify(&c, &o, data).is_ok());
    }

    #[test]
    fn wrong_data_fails_open() {
        let scheme = HashBasedScheme;
        let (c, o) = scheme.commit(b"real data");
        assert!(scheme.verify(&c, &o, b"tampered data").is_err());
    }

    #[test]
    fn two_commitments_to_same_data_differ() {
        // Salting means commitments are not comparable for equality-of-input
        // by a verifier who doesn't have the opening — that's intentional
        // (hiding property).
        let scheme = HashBasedScheme;
        let (c1, _) = scheme.commit(b"same input");
        let (c2, _) = scheme.commit(b"same input");
        assert_ne!(c1, c2);
    }
}
