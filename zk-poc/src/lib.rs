//! `veritas-zk-poc`: proof of concept that `core/src/proof/groth16.rs`'s
//! placeholder interface is buildable against a REAL Groth16 backend.
//!
//! STATUS: this crate is real, working zero-knowledge cryptography --
//! `setup`, `prove`, and `verify` below actually run arkworks' Groth16
//! implementation over BN254, with a real R1CS circuit (see `circuit.rs`)
//! enforcing `amount <= threshold` via bit-decomposition range checks. A
//! valid proof genuinely does not reveal `amount` beyond what the
//! constraint system leaks (nothing, beyond "some amount in [0, threshold]
//! and representable in 64 bits exists").
//!
//! What this crate is NOT (yet):
//! - It is NOT wired into `core/`'s `Attestation`/`ProofSystem` pipeline.
//!   `core::proof::groth16::Groth16Placeholder` still signs a hash; this
//!   crate is a standalone demonstration that the real thing is buildable,
//!   kept separate so it can't destabilize `core/`'s already-passing test
//!   suite while it's developed. Wiring it in is the natural next step:
//!   replace `Groth16Placeholder`'s body with calls into this crate's
//!   `setup`/`prove`/`verify`, changing `Proof::Toy` to a new
//!   `Proof::Groth16Bn254(Vec<u8>)` variant carrying the serialized
//!   `ark_groth16::Proof<Bn254>`.
//! - The trusted setup below is done with a fixed, LOCALLY-GENERATED RNG
//!   seed for reproducibility in tests -- this is explicitly NOT a real
//!   trusted setup ceremony. A real deployment needs a multi-party
//!   ceremony (or a switch to a transparent proof system per RFC-0002) so
//!   no single party ever holds the toxic waste that could forge proofs.
//!   See README.md in this directory.
//! - Only ONE rule (`banking-basel-iii`'s transaction threshold) has a
//!   real circuit. `healthcare-hipaa` and `gov-supply-chain-integrity`'s
//!   predicates (in `core/src/circuits/`) still need their own circuits,
//!   which is nontrivial per-rule work, not a mechanical port of this one.

pub mod circuit;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use ark_snark::SNARK;
use ark_std::rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use circuit::TransactionThresholdCircuit;

#[derive(Debug, thiserror::Error)]
pub enum ZkPocError {
    #[error("circuit setup failed: {0}")]
    Setup(SynthesisError),
    #[error("proving failed (this is EXPECTED when amount > threshold -- see module docs): {0}")]
    Proving(SynthesisError),
    #[error("verification failed: {0}")]
    Verification(SynthesisError),
}

/// The output of a (non-ceremony) trusted setup for a FIXED threshold.
/// Real deployments need one of these per distinct circuit shape; since
/// `threshold` is a public input (not baked into circuit shape), the same
/// keys work for any threshold value -- only `RANGE_BITS` (a compile-time
/// constant) affects circuit shape.
pub struct Keys {
    pub proving_key: ProvingKey<Bn254>,
    pub verifying_key: VerifyingKey<Bn254>,
}

/// Runs Groth16 setup over the circuit's constraint shape. Uses a
/// deterministic RNG seed (`seed`) so tests are reproducible -- see the
/// crate-level docs for why this is explicitly not a real ceremony.
pub fn setup(seed: u64) -> Result<Keys, ZkPocError> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let circuit = TransactionThresholdCircuit::setup_shape(0);
    let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
        .map_err(ZkPocError::Setup)?;
    Ok(Keys {
        proving_key,
        verifying_key,
    })
}

/// Generates a real Groth16 proof that `amount <= threshold`, without
/// revealing `amount` to whoever receives the returned `Proof`.
///
/// Returns `Err(ZkPocError::Proving(_))` if `amount > threshold` -- the
/// circuit has no satisfying witness in that case (see `circuit.rs`), so
/// proof generation itself fails. This is the soundness property in
/// action: there is no way to produce a proof for a false claim.
pub fn prove(
    proving_key: &ProvingKey<Bn254>,
    amount: u64,
    threshold: u64,
    rng_seed: u64,
) -> Result<Proof<Bn254>, ZkPocError> {
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    let circuit = TransactionThresholdCircuit::with_witness(amount, threshold);
    Groth16::<Bn254>::prove(proving_key, circuit, &mut rng).map_err(ZkPocError::Proving)
}

/// Verifies a proof against the PUBLIC `threshold` value. Note: this
/// function never sees `amount` -- that's the entire point.
pub fn verify(
    verifying_key: &VerifyingKey<Bn254>,
    threshold: u64,
    proof: &Proof<Bn254>,
) -> Result<bool, ZkPocError> {
    let pvk: PreparedVerifyingKey<Bn254> = ark_groth16::prepare_verifying_key(verifying_key);
    let public_inputs = [Fr::from(threshold)];
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, proof)
        .map_err(ZkPocError::Verification)
}

/// Convenience: a random seed for callers who don't need reproducibility
/// (real usage) vs. tests (which should pass an explicit fixed seed).
pub fn random_seed() -> u64 {
    ark_std::rand::thread_rng().gen()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed seeds throughout: this is a test suite, not a ceremony. Real
    // deployments must never reuse the setup seed pattern shown here --
    // see crate-level docs.
    const SETUP_SEED: u64 = 42;
    const PROVE_SEED: u64 = 1337;

    #[test]
    fn valid_claim_produces_a_proof_that_verifies() {
        let keys = setup(SETUP_SEED).expect("setup should succeed");

        let proof = prove(&keys.proving_key, 500, 1000, PROVE_SEED).expect("proving should succeed for amount <= threshold");

        let valid = verify(&keys.verifying_key, 1000, &proof).expect("verification should not error");
        assert!(valid, "a correctly generated proof must verify as valid");
    }

    #[test]
    fn exactly_at_threshold_produces_a_valid_proof() {
        let keys = setup(SETUP_SEED).expect("setup should succeed");
        let proof = prove(&keys.proving_key, 1000, 1000, PROVE_SEED).expect("boundary case should still be provable");
        assert!(verify(&keys.verifying_key, 1000, &proof).unwrap());
    }

    #[test]
    fn false_claim_cannot_be_proven_at_all() {
        // This is the soundness property: proving itself fails, because
        // no satisfying witness assignment exists for amount > threshold.
        // There is no proof to reject here -- the attacker never gets one.
        let keys = setup(SETUP_SEED).expect("setup should succeed");
        let result = prove(&keys.proving_key, 1001, 1000, PROVE_SEED);
        assert!(result.is_err(), "proving must fail when amount exceeds threshold");
    }

    #[test]
    fn proof_does_not_verify_against_a_different_public_threshold() {
        // A proof is bound to the specific public input it was made for.
        // Presenting it against a different threshold must be rejected --
        // otherwise a prover could get a cheap proof for a low threshold
        // and pass it off as proving compliance with a much higher one.
        let keys = setup(SETUP_SEED).expect("setup should succeed");
        let proof = prove(&keys.proving_key, 500, 1000, PROVE_SEED).unwrap();

        let valid_against_wrong_threshold = verify(&keys.verifying_key, 2000, &proof).unwrap();
        assert!(
            !valid_against_wrong_threshold,
            "a proof for threshold=1000 must not verify against threshold=2000"
        );
    }

    #[test]
    fn zero_amount_and_zero_threshold_is_a_valid_boundary_case() {
        let keys = setup(SETUP_SEED).expect("setup should succeed");
        let proof = prove(&keys.proving_key, 0, 0, PROVE_SEED).unwrap();
        assert!(verify(&keys.verifying_key, 0, &proof).unwrap());
    }

    #[test]
    fn large_but_in_range_values_work() {
        // Comfortably within RANGE_BITS=64 but large enough to exercise
        // more than a handful of bits in the decomposition.
        let keys = setup(SETUP_SEED).expect("setup should succeed");
        let threshold = 1_000_000_000_000u64;
        let proof = prove(&keys.proving_key, threshold - 1, threshold, PROVE_SEED).unwrap();
        assert!(verify(&keys.verifying_key, threshold, &proof).unwrap());
    }
}
