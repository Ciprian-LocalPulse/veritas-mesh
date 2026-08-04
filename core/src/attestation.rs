//! The `Attestation` type: the on-the-wire object nodes gossip and verify.
//! Field layout mirrors `proto/veritas/v1/attestation.proto` — if you change
//! one, change the other and bump `SCHEMA_VERSION`.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::errors::{Result, VeritasError};
use crate::proof::{Proof, ProofSystemId};

pub const SCHEMA_VERSION: u32 = 1;

/// A single attestation: "the prover ran rule `rule_id` over some private
/// input and the predicate held, as of `issued_at_unix`."
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attestation {
    pub schema_version: u32,
    /// e.g. "banking-basel-iii", "healthcare-hipaa" — matches
    /// compliance-mappings/<id>.md
    pub rule_id: String,
    /// Which proof backend produced `proof`.
    pub proof_system: ProofSystemId,
    /// Commitment to the (private) inputs the rule was evaluated over.
    pub input_commitment: Vec<u8>,
    /// The proof object itself (backend-specific payload).
    pub proof: Proof,
    /// Ed25519 public key of the prover, raw 32 bytes.
    pub prover_public_key: [u8; 32],
    /// Ed25519 signature over the canonical byte encoding of every other
    /// field (see `signing_bytes`).
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    pub issued_at_unix: u64,
}

impl Attestation {
    /// Deterministic byte encoding used for both signing and hashing.
    /// Excludes `signature` itself (obviously) and does NOT round-trip
    /// through serde_json's non-deterministic map ordering — every field
    /// here is either scalar or already-ordered, so this is stable across
    /// languages as long as SDKs follow the same field order.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.schema_version.to_le_bytes());
        buf.extend_from_slice(self.rule_id.as_bytes());
        buf.push(0); // separator, prevents rule_id/proof_system concatenation collisions
        buf.extend_from_slice(&(self.proof_system as u32).to_le_bytes());
        buf.extend_from_slice(&(self.input_commitment.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.input_commitment);
        buf.extend_from_slice(&self.proof.to_bytes());
        buf.extend_from_slice(&self.prover_public_key);
        buf.extend_from_slice(&self.issued_at_unix.to_le_bytes());
        buf
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    pub fn validate_schema(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(VeritasError::InvalidProof(format!(
                "unsupported schema_version {} (expected {})",
                self.schema_version, SCHEMA_VERSION
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::ToyProof;

    #[test]
    fn signing_bytes_is_deterministic() {
        let a = Attestation {
            schema_version: SCHEMA_VERSION,
            rule_id: "banking-basel-iii".into(),
            proof_system: ProofSystemId::ToyHashCommitment,
            input_commitment: vec![1, 2, 3],
            proof: Proof::Toy(ToyProof { payload: vec![9, 9] }),
            prover_public_key: [7u8; 32],
            signature: [0u8; 64],
            issued_at_unix: 1_700_000_000,
        };
        let b = a.clone();
        assert_eq!(a.signing_bytes(), b.signing_bytes());
    }
}
