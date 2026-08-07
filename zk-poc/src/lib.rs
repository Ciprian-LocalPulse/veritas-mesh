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
//!   real circuit... actually now two: see `healthcare_circuit.rs` for
//!   `healthcare-hipaa`'s disclosure-logging predicate, added after this
//!   comment was first written. `gov-supply-chain-integrity`'s hash-chain
//!   predicate still has no circuit -- see that module's future home for
//!   why it's a structurally different (and harder) problem: proving a
//!   SHA-256 hash chain in zero-knowledge needs a SHA-256 R1CS gadget,
//!   which neither circuit here uses, versus this crate's two circuits so
//!   far, which only need boolean/arithmetic gadgets.

pub mod circuit;
pub mod healthcare_circuit;
pub mod supply_chain_circuit;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use ark_snark::SNARK;
use ark_std::rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use circuit::TransactionThresholdCircuit;
use healthcare_circuit::{EntryWitness, HealthcareDisclosureCircuit};
use supply_chain_circuit::{EntryWitness as ChainEntryWitness, SupplyChainIntegrityCircuit};

#[derive(Debug, thiserror::Error)]
pub enum ZkPocError {
    #[error("circuit setup failed: {0}")]
    Setup(SynthesisError),
    #[error("proving failed (EXPECTED for a false claim -- e.g. amount > threshold, or an unauthorized/miscounted access log; see the relevant circuit's module docs): {0}")]
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

// --- healthcare-hipaa: DisclosureLoggingRule ---
// Same Keys type as banking-basel-iii above (ProvingKey<Bn254>/
// VerifyingKey<Bn254> aren't circuit-specific types), so no new struct is
// needed -- only the setup/prove/verify functions differ, because they
// need to build a HealthcareDisclosureCircuit instead.

/// Runs Groth16 setup for `HealthcareDisclosureCircuit`'s shape. Same
/// non-ceremony caveat as `setup()` above applies in full.
pub fn setup_healthcare(seed: u64) -> Result<Keys, ZkPocError> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let circuit = HealthcareDisclosureCircuit::setup_shape(Fr::from(0u64));
    let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
        .map_err(ZkPocError::Setup)?;
    Ok(Keys {
        proving_key,
        verifying_key,
    })
}

/// Generates a real Groth16 proof that every observed access to
/// `record_id` was logged and every logged access was authorized,
/// without revealing which specific entries were real vs. padding, or
/// any per-entry detail.
///
/// Returns `Err(ZkPocError::Proving(_))` if `entries` doesn't actually
/// satisfy the predicate (count mismatch or an unauthorized active
/// entry) -- same soundness-via-unsatisfiable-witness pattern as `prove()`
/// above. Panics (not an `Err`) if `entries.len() > MAX_ENTRIES` -- see
/// `HealthcareDisclosureCircuit::with_witness`'s docs for why that's a
/// distinct failure mode (a circuit-capacity limit, not the predicate
/// being false) and should be checked by the caller before this point in
/// a real integration.
pub fn prove_healthcare(
    proving_key: &ProvingKey<Bn254>,
    record_id: Fr,
    observed_access_count: u64,
    entries: &[EntryWitness],
    rng_seed: u64,
) -> Result<Proof<Bn254>, ZkPocError> {
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    let circuit =
        HealthcareDisclosureCircuit::with_witness(record_id, observed_access_count, entries);
    Groth16::<Bn254>::prove(proving_key, circuit, &mut rng).map_err(ZkPocError::Proving)
}

/// Verifies a proof against the PUBLIC `record_id` and
/// `observed_access_count`. Never sees the individual log entries or
/// which slots were padding -- that's the entire point.
pub fn verify_healthcare(
    verifying_key: &VerifyingKey<Bn254>,
    record_id: Fr,
    observed_access_count: u64,
    proof: &Proof<Bn254>,
) -> Result<bool, ZkPocError> {
    let pvk: PreparedVerifyingKey<Bn254> = ark_groth16::prepare_verifying_key(verifying_key);
    let public_inputs = [record_id, Fr::from(observed_access_count)];
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, proof)
        .map_err(ZkPocError::Verification)
}

// --- gov-supply-chain-integrity: AuditTrailIntegrityRule ---

/// Converts a 32-byte digest to the 256 public-input field elements
/// `DigestVar::new_input` actually allocates for it. This is NOT "32
/// field elements, one per byte" (an assumption worth stating explicitly
/// because it's the wrong one, and an easy one to make): `UInt8` stores
/// its value as 8 individual `Boolean` bits
/// (`ark_r1cs_std::bits::uint8::UInt8`), least-significant-bit first, and
/// `AllocationMode::Input` allocates each of those 8 bits as its own
/// public input. So one digest byte = 8 public inputs (each an Fr
/// constrained to 0 or 1), not 1. Getting this wrong produces a
/// public-input vector of the wrong *length*, which
/// `Groth16::verify_with_processed_vk` would reject outright -- this was
/// caught by writing and running the integration test below, not assumed
/// correct from reading the gadget's allocation code alone.
fn digest_to_field_elements(digest: &[u8; 32]) -> Vec<Fr> {
    let mut out = Vec::with_capacity(256);
    for byte in digest {
        for bit_index in 0..8 {
            out.push(Fr::from(((byte >> bit_index) & 1) as u64));
        }
    }
    out
}

fn supply_chain_public_inputs(
    genesis_hash: [u8; 32],
    final_linkage_hash: [u8; 32],
    active_count: u64,
) -> Vec<Fr> {
    let mut v = Vec::with_capacity(256 + 256 + 1);
    v.extend(digest_to_field_elements(&genesis_hash));
    v.extend(digest_to_field_elements(&final_linkage_hash));
    v.push(Fr::from(active_count));
    v
}

/// Runs Groth16 setup for `SupplyChainIntegrityCircuit`'s shape. Same
/// non-ceremony caveat as `setup()`/`setup_healthcare()` applies in full.
pub fn setup_supply_chain(seed: u64) -> Result<Keys, ZkPocError> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let circuit = SupplyChainIntegrityCircuit::setup_shape([0u8; 32], [0u8; 32]);
    let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
        .map_err(ZkPocError::Setup)?;
    Ok(Keys {
        proving_key,
        verifying_key,
    })
}

/// Generates a real Groth16 proof that the audit-log hash chain runs
/// unbroken from `genesis_hash` to `final_linkage_hash` across
/// `active_count` entries, without revealing any individual
/// `event_hash`. Returns `Err(ZkPocError::Proving(_))` if `entries`
/// doesn't actually satisfy that claim -- same pattern as the other two
/// circuits' `prove`/`prove_healthcare`. Panics (not an `Err`) if
/// `entries.len() > MAX_ENTRIES` -- see
/// `SupplyChainIntegrityCircuit::with_witness`'s docs.
pub fn prove_supply_chain(
    proving_key: &ProvingKey<Bn254>,
    genesis_hash: [u8; 32],
    final_linkage_hash: [u8; 32],
    active_count: u64,
    entries: &[ChainEntryWitness],
    rng_seed: u64,
) -> Result<Proof<Bn254>, ZkPocError> {
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    let circuit = SupplyChainIntegrityCircuit::with_witness(
        genesis_hash,
        final_linkage_hash,
        active_count,
        entries,
    );
    Groth16::<Bn254>::prove(proving_key, circuit, &mut rng).map_err(ZkPocError::Proving)
}

/// Verifies a proof against the PUBLIC `genesis_hash`,
/// `final_linkage_hash`, and `active_count`. Never sees any individual
/// `event_hash` -- that's the entire point.
pub fn verify_supply_chain(
    verifying_key: &VerifyingKey<Bn254>,
    genesis_hash: [u8; 32],
    final_linkage_hash: [u8; 32],
    active_count: u64,
    proof: &Proof<Bn254>,
) -> Result<bool, ZkPocError> {
    let pvk: PreparedVerifyingKey<Bn254> = ark_groth16::prepare_verifying_key(verifying_key);
    let public_inputs = supply_chain_public_inputs(genesis_hash, final_linkage_hash, active_count);
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, proof)
        .map_err(ZkPocError::Verification)
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

    // --- healthcare-hipaa end-to-end tests ---
    // healthcare_circuit.rs's own tests check constraint SATISFACTION
    // directly (no proving key needed, much faster). These check the full
    // Groth16 setup -> prove -> verify pipeline, same as the tests above
    // do for banking-basel-iii -- both layers matter: a circuit can be
    // satisfiable in the abstract and still have an integration bug in
    // how setup/prove/verify wire it up (wrong public input order being
    // the classic one, checked explicitly below).

    fn entry(active: bool, authorized: bool) -> EntryWitness {
        EntryWitness {
            is_active: active,
            authorized,
        }
    }

    #[test]
    fn healthcare_valid_claim_produces_a_proof_that_verifies() {
        let keys = setup_healthcare(SETUP_SEED).expect("setup should succeed");
        let record_id = Fr::from(42u64);
        let entries = [entry(true, true), entry(true, true), entry(false, false)];

        let proof = prove_healthcare(&keys.proving_key, record_id, 2, &entries, PROVE_SEED)
            .expect("proving should succeed for a genuinely compliant log");

        let valid = verify_healthcare(&keys.verifying_key, record_id, 2, &proof)
            .expect("verification should not error");
        assert!(valid, "a correctly generated proof must verify as valid");
    }

    #[test]
    fn healthcare_count_mismatch_cannot_be_proven_at_all() {
        let keys = setup_healthcare(SETUP_SEED).expect("setup should succeed");
        let entries = [entry(true, true)];
        // Claiming 2 observed accesses but only 1 entry is actually active.
        let result = prove_healthcare(&keys.proving_key, Fr::from(1u64), 2, &entries, PROVE_SEED);
        assert!(
            result.is_err(),
            "proving must fail when the active-entry count doesn't match the public claim"
        );
    }

    #[test]
    fn healthcare_unauthorized_active_entry_cannot_be_proven_at_all() {
        let keys = setup_healthcare(SETUP_SEED).expect("setup should succeed");
        let entries = [entry(true, true), entry(true, false)];
        let result = prove_healthcare(&keys.proving_key, Fr::from(1u64), 2, &entries, PROVE_SEED);
        assert!(
            result.is_err(),
            "proving must fail when any active entry is unauthorized"
        );
    }

    #[test]
    fn healthcare_proof_does_not_verify_against_a_different_record_id() {
        // The vulnerability the module docs warn about, checked directly:
        // a proof made for one record must not verify as if it were made
        // for a different one, even with the same access count.
        let keys = setup_healthcare(SETUP_SEED).expect("setup should succeed");
        let entries = [entry(true, true)];
        let proof =
            prove_healthcare(&keys.proving_key, Fr::from(1u64), 1, &entries, PROVE_SEED).unwrap();

        let valid_against_wrong_record =
            verify_healthcare(&keys.verifying_key, Fr::from(2u64), 1, &proof).unwrap();
        assert!(
            !valid_against_wrong_record,
            "a proof for record_id=1 must not verify against record_id=2"
        );
    }

    #[test]
    fn healthcare_proof_does_not_verify_against_a_different_count() {
        let keys = setup_healthcare(SETUP_SEED).expect("setup should succeed");
        let entries = [entry(true, true)];
        let proof =
            prove_healthcare(&keys.proving_key, Fr::from(1u64), 1, &entries, PROVE_SEED).unwrap();

        let valid_against_wrong_count =
            verify_healthcare(&keys.verifying_key, Fr::from(1u64), 99, &proof).unwrap();
        assert!(
            !valid_against_wrong_count,
            "a proof for count=1 must not verify against count=99"
        );
    }

    #[test]
    fn healthcare_full_capacity_all_authorized_works() {
        let keys = setup_healthcare(SETUP_SEED).expect("setup should succeed");
        let entries = [entry(true, true); healthcare_circuit::MAX_ENTRIES];
        let proof = prove_healthcare(
            &keys.proving_key,
            Fr::from(7u64),
            healthcare_circuit::MAX_ENTRIES as u64,
            &entries,
            PROVE_SEED,
        )
        .expect("proving should succeed at full circuit capacity");
        assert!(verify_healthcare(
            &keys.verifying_key,
            Fr::from(7u64),
            healthcare_circuit::MAX_ENTRIES as u64,
            &proof
        )
        .unwrap());
    }

    // --- gov-supply-chain-integrity end-to-end tests ---
    // Same rationale as the healthcare section above: real Groth16
    // setup->prove->verify, not just constraint satisfaction (already
    // covered by supply_chain_circuit.rs's own tests). SETUP_SEED here
    // deliberately reuses the module-level constant -- a different seed
    // per circuit isn't needed since each `setup_*` call is an
    // independent circuit-specific ceremony regardless.

    fn chain_entry(event_hash: [u8; 32]) -> ChainEntryWitness {
        ChainEntryWitness {
            event_hash,
            is_active: true,
        }
    }

    fn build_test_chain(
        genesis: [u8; 32],
        event_hashes: &[[u8; 32]],
    ) -> (Vec<ChainEntryWitness>, [u8; 32]) {
        let mut running = genesis;
        let mut entries = Vec::with_capacity(event_hashes.len());
        for (i, eh) in event_hashes.iter().enumerate() {
            running = supply_chain_circuit::entry_linkage_hash(i as u64, eh, &running);
            entries.push(chain_entry(*eh));
        }
        (entries, running)
    }

    #[test]
    fn supply_chain_end_to_end_via_real_groth16() {
        let keys = setup_supply_chain(SETUP_SEED).expect("setup should succeed");
        let genesis = [3u8; 32];
        let (entries, final_hash) = build_test_chain(genesis, &[[1u8; 32], [2u8; 32]]);

        let proof = prove_supply_chain(
            &keys.proving_key,
            genesis,
            final_hash,
            2,
            &entries,
            PROVE_SEED,
        )
        .expect("proving should succeed for a genuinely intact chain");

        let valid = verify_supply_chain(&keys.verifying_key, genesis, final_hash, 2, &proof)
            .expect("verification should not error");
        assert!(valid, "a correctly generated proof must verify as valid");
    }

    #[test]
    fn supply_chain_tampered_event_cannot_be_proven() {
        let keys = setup_supply_chain(SETUP_SEED).expect("setup should succeed");
        let genesis = [3u8; 32];
        let (mut entries, final_hash) = build_test_chain(genesis, &[[1u8; 32], [2u8; 32]]);
        entries[0].event_hash = [0xEEu8; 32]; // tamper, but claim the OLD (now-wrong) final hash
        let result =
            prove_supply_chain(&keys.proving_key, genesis, final_hash, 2, &entries, PROVE_SEED);
        assert!(
            result.is_err(),
            "proving must fail once a tampered event_hash no longer produces the claimed \
             final_linkage_hash"
        );
    }

    #[test]
    fn supply_chain_proof_does_not_verify_against_a_different_genesis() {
        let keys = setup_supply_chain(SETUP_SEED).expect("setup should succeed");
        let genesis = [3u8; 32];
        let (entries, final_hash) = build_test_chain(genesis, &[[1u8; 32]]);
        let proof = prove_supply_chain(
            &keys.proving_key,
            genesis,
            final_hash,
            1,
            &entries,
            PROVE_SEED,
        )
        .unwrap();

        let wrong_genesis = [9u8; 32];
        let valid =
            verify_supply_chain(&keys.verifying_key, wrong_genesis, final_hash, 1, &proof)
                .unwrap();
        assert!(
            !valid,
            "a proof anchored to one genesis_hash must not verify against a different one"
        );
    }
}
