//! `veritas-sdk`: what an application developer actually imports. Wraps
//! `veritas-core` so callers don't need to know about `ProofSystem`,
//! `CommitmentScheme`, etc. as separate trait objects — one `Prover` /
//! `Verifier` pair per rule.
//!
//! STATUS: real wiring over `veritas-core`, which itself has placeholder
//! proof backends (see veritas-core's `lib.rs` docs). This crate does not
//! add or hide any cryptographic assumptions beyond what `veritas-core`
//! already documents.

use veritas_core::attestation::{Attestation, SCHEMA_VERSION};
use veritas_core::circuits::banking_basel_iii::{TransactionThresholdInput, TransactionThresholdRule};
use veritas_core::circuits::Rule;
use veritas_core::commitment::hash_based::HashBasedScheme;
use veritas_core::commitment::CommitmentScheme;
use veritas_core::errors::Result;
use veritas_core::proof::groth16::Groth16Placeholder;
use veritas_core::proof::{ProofSystem, ProofSystemId};
use veritas_core::signature::{verify_attestation, Keypair};

/// Generates attestations for the `banking-basel-iii` transaction-threshold
/// rule. One `Prover` type like this per rule is the intended pattern —
/// see `veritas-core::circuits` for why each rule needs its own typed
/// input.
pub struct BaselIiiProver {
    keypair: Keypair,
}

impl BaselIiiProver {
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Checks the rule, commits + proves + signs, returns a ready-to-gossip
    /// `Attestation`. Returns `Err` if the rule itself is violated — the
    /// SDK will not let you build an attestation for a false claim.
    pub fn attest(&self, input: &TransactionThresholdInput, issued_at_unix: u64) -> Result<Attestation> {
        TransactionThresholdRule::check(input)?;

        let witness_bytes = TransactionThresholdRule::canonical_bytes(input);
        let (commitment, _opening) = HashBasedScheme.commit(&witness_bytes);

        let backend = Groth16Placeholder;
        let public_input = TransactionThresholdRule::RULE_ID.as_bytes();
        let proof = backend.prove(&witness_bytes, public_input)?;

        let unsigned = Attestation {
            schema_version: SCHEMA_VERSION,
            rule_id: TransactionThresholdRule::RULE_ID.to_string(),
            proof_system: ProofSystemId::ToyHashCommitment,
            input_commitment: commitment.0.to_vec(),
            proof,
            prover_public_key: [0u8; 32],
            signature: [0u8; 64],
            issued_at_unix,
        };
        Ok(self.keypair.sign_attestation(unsigned))
    }
}

/// Verifies attestations without needing to know which rule produced them
/// (schema + signature + proof-shape checks). Rule-specific semantic
/// checks (e.g. "was the threshold reasonable") are out of scope for a
/// generic verifier — that's a policy decision for the verifying party.
pub struct Verifier;

impl Verifier {
    pub fn verify(&self, attestation: &Attestation) -> Result<()> {
        attestation.validate_schema()?;
        verify_attestation(attestation)?;
        let backend = Groth16Placeholder;
        backend.verify(&attestation.proof, attestation.rule_id.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritas_core::circuits::banking_basel_iii::TransactionThresholdInput;

    fn hash(s: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(s.as_bytes()).into()
    }

    #[test]
    fn prover_verifier_roundtrip() {
        let prover = BaselIiiProver::new(Keypair::generate());
        let input = TransactionThresholdInput {
            transaction_amount_minor: 100,
            risk_adjusted_threshold_minor: 1000,
            customer_id_hash: hash("customer"),
        };
        let attestation = prover.attest(&input, 1_700_000_000).unwrap();
        assert!(Verifier.verify(&attestation).is_ok());
    }

    #[test]
    fn prover_refuses_to_attest_a_false_claim() {
        let prover = BaselIiiProver::new(Keypair::generate());
        let input = TransactionThresholdInput {
            transaction_amount_minor: 2000, // exceeds threshold
            risk_adjusted_threshold_minor: 1000,
            customer_id_hash: hash("customer"),
        };
        assert!(prover.attest(&input, 1_700_000_000).is_err());
    }
}
