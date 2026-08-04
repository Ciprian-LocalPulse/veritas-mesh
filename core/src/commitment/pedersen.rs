//! PLACEHOLDER — not a real Pedersen commitment yet.
//!
//! A real Pedersen commitment is `C = m*G + r*H` on an elliptic curve group,
//! with `G, H` independent generators (no known discrete-log relation
//! between them, typically derived via hash-to-curve so nobody — including
//! the implementer — knows `log_G(H)`). That gives you:
//!   - perfectly hiding (given `r`, `C` reveals nothing about `m`)
//!   - computationally binding (under discrete log hardness)
//!   - *additively homomorphic*: Commit(m1)+Commit(m2) = Commit(m1+m2),
//!     which is the actual reason to prefer Pedersen over hash-based
//!     commitments for circuit-friendly proof systems (Groth16/STARK
//!     provers want commitments they can do arithmetic on inside the
//!     circuit).
//!
//! This file has the correct trait shape (`CommitmentScheme`) so the rest
//! of the codebase can be written against it today, but `commit`/`verify`
//! below fall back to the hash-based scheme internally — i.e. you get NONE
//! of the homomorphic property yet. Implementing this for real requires:
//!   1. RFC-0003 to land on a curve (likely ristretto255 via
//!      `curve25519-dalek`, or whatever curve arkworks/Groth16 needs so the
//!      commitment lives in the same field as the circuit — this is the
//!      actual hard constraint that makes RFC-0002 and RFC-0003 coupled).
//!   2. Verifiably-random generator derivation (e.g. hash-to-curve per
//!      RFC 9380) so `H` isn't a rigged generator.
//!   3. Constant-time scalar multiplication (no naive loops — timing side
//!      channels leak `r`).
//!
//! Do not use this module where the homomorphic property or a real
//! discrete-log hardness guarantee is required.

use super::hash_based::{HashBasedScheme, HashCommitment, HashOpening};
use super::CommitmentScheme;
use crate::errors::Result;

pub struct PedersenScheme; // TODO(RFC-0003): replace backing store with an EC group element.

impl CommitmentScheme for PedersenScheme {
    type Commitment = HashCommitment;
    type Opening = HashOpening;

    fn commit(&self, data: &[u8]) -> (HashCommitment, HashOpening) {
        // TODO(RFC-0003): m*G + r*H over the chosen curve.
        HashBasedScheme.commit(data)
    }

    fn verify(&self, commitment: &HashCommitment, opening: &HashOpening, data: &[u8]) -> Result<()> {
        HashBasedScheme.verify(commitment, opening, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_roundtrip_still_holds() {
        let scheme = PedersenScheme;
        let (c, o) = scheme.commit(b"placeholder input");
        assert!(scheme.verify(&c, &o, b"placeholder input").is_ok());
    }
}
