//! Real `ProofSystem` backends over `veritas-zk-poc`'s three working
//! Groth16 circuits (BN254, per RFC-0002's amended curve choice — see
//! that RFC's "Curve choice for the SNARK track" for why BN254 and not
//! the originally-proposed BLS12-381). Wires in `banking-basel-iii`,
//! `healthcare-hipaa`, and `gov-supply-chain-integrity` — the third one
//! added after the first two, and with a real, load-bearing operational
//! caveat the other two don't have: see `SupplyChainGroth16Backend`'s own
//! docs below for why its `~64 MiB` proving key means `setup()` should
//! basically never be called at request time in real code, unlike the
//! other two backends' much smaller (sub-30KB) keys.
//!
//! # Why one backend struct per rule, not one generic `Groth16Backend`
//!
//! `ProofSystem::prove`/`verify` take opaque `&[u8]` witness/public_input,
//! with no `rule_id` parameter — the trait doesn't know or care which rule
//! a given implementor is for. Each rule's circuit (`TransactionThresholdCircuit`,
//! `HealthcareDisclosureCircuit`) has a completely different witness shape
//! and its own proving/verifying key pair (from its own trusted setup,
//! per RFC-0002's ceremony-per-circuit requirement), so one backend
//! instance is inherently rule-specific — `BankingGroth16Backend` and
//! `HealthcareGroth16Backend` below hold their own `Keys`, and a caller
//! picks which one to use the same way it already picks which `Rule`
//! implementation to run `check()` against (i.e. by `rule_id`, at the
//! call site — there is still no rule-dispatching orchestration layer in
//! `core/`, matching `STATUS.md`'s note that no `attest()`-style top-level
//! entry point exists yet).
//!
//! # What is, and is not, bound into the ZK statement
//!
//! Each rule's `core::circuits::*::Input` struct has fields the
//! corresponding `zk-poc` circuit does NOT constrain. For
//! `TransactionThresholdInput`, `customer_id_hash` plays no role in
//! `TransactionThresholdCircuit` — the circuit only proves
//! `transaction_amount_minor <= risk_adjusted_threshold_minor`. For
//! `DisclosureLogInput`, `accessor_id_hash`/`timestamp_unix` per entry are
//! similarly outside `HealthcareDisclosureCircuit` (see that circuit's own
//! module docs for why). **This means a Groth16 proof produced here proves
//! only the numeric/boolean predicate, not "this exact `Input` struct was
//! used."** Binding the rest of an `Input` struct (e.g. `customer_id_hash`)
//! to an attestation is `commitment::hash_based`/`pedersen`'s job (RFC-0003),
//! applied to the FULL canonical input via `Rule::canonical_bytes`,
//! separately from the ZK proof over the subset of fields the circuit
//! actually constrains. Conflating "proven by the SNARK" with "committed to
//! in the attestation" would be a real error for an integrator to make; this
//! module's doc exists partly to head that off before it happens.

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::Proof as ArkGroth16Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use veritas_zk_poc::healthcare_circuit::{EntryWitness, MAX_ENTRIES};
use veritas_zk_poc::supply_chain_circuit::{
    EntryWitness as ChainEntryWitness, MAX_ENTRIES as CHAIN_MAX_ENTRIES,
};
use veritas_zk_poc::{
    prove as zk_prove_banking, prove_healthcare as zk_prove_healthcare,
    prove_supply_chain as zk_prove_supply_chain, setup as zk_setup_banking,
    setup_healthcare as zk_setup_healthcare, setup_supply_chain as zk_setup_supply_chain,
    verify as zk_verify_banking, verify_healthcare as zk_verify_healthcare,
    verify_supply_chain as zk_verify_supply_chain, Keys, ZkPocError,
};

use super::{Proof, ProofSystem, ProofSystemId};
use crate::errors::{Result, VeritasError};

fn zk_poc_err(e: ZkPocError) -> VeritasError {
    // ZkPocError::Proving is EXPECTED for a false claim (see zk-poc's own
    // error message) -- surfaced here as InvalidProof, not a generic
    // failure, so a caller attempting to prove a false claim gets the same
    // "this cannot be proven" signal the placeholder's callers would have
    // gotten from a rejected RuleViolation, not a confusing internal error.
    VeritasError::InvalidProof(format!("groth16-bn254: {e}"))
}

fn serialize_proof(proof: &ArkGroth16Proof<Bn254>) -> Result<Proof> {
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|e| VeritasError::InvalidProof(format!("groth16-bn254: serialize: {e}")))?;
    Ok(Proof::Groth16Bn254(bytes))
}

fn deserialize_proof(proof: &Proof) -> Result<ArkGroth16Proof<Bn254>> {
    match proof {
        Proof::Groth16Bn254(bytes) => ArkGroth16Proof::<Bn254>::deserialize_compressed(&bytes[..])
            .map_err(|e| {
                VeritasError::InvalidProof(format!("groth16-bn254: deserialize: {e}"))
            }),
        Proof::Toy(_) => Err(VeritasError::InvalidProof(
            "groth16-bn254: expected Proof::Groth16Bn254, got Proof::Toy \
             (wrong backend for this proof, or a placeholder proof from \
             groth16.rs was routed here by mistake)"
                .into(),
        )),
    }
}

// ============================================================
// banking-basel-iii
// ============================================================

/// Wire encoding for `BankingGroth16Backend::prove`'s `witness` bytes.
/// Deliberately narrower than `TransactionThresholdInput` -- see module
/// docs for why `customer_id_hash` isn't here.
#[derive(Serialize, Deserialize)]
pub(crate) struct BankingWitness {
    pub(crate) transaction_amount_minor: u64,
}

/// Wire encoding for `BankingGroth16Backend`'s `public_input` bytes.
#[derive(Serialize, Deserialize)]
pub(crate) struct BankingPublicInput {
    pub(crate) risk_adjusted_threshold_minor: u64,
}

/// Real Groth16-over-BN254 backend for `banking-basel-iii`
/// (`TransactionThresholdCircuit` in `zk-poc/src/circuit.rs`).
pub struct BankingGroth16Backend {
    keys: Keys,
}

impl BankingGroth16Backend {
    /// Runs the (non-ceremony, test-only) trusted setup -- see `Keys`'
    /// and `zk_poc::setup`'s own docs. A real deployment loads
    /// `Keys` from a published ceremony's output instead of calling this.
    pub fn setup(seed: u64) -> Result<Self> {
        let keys = zk_setup_banking(seed).map_err(zk_poc_err)?;
        Ok(Self { keys })
    }

    pub fn from_keys(keys: Keys) -> Self {
        Self { keys }
    }
}

impl ProofSystem for BankingGroth16Backend {
    fn id(&self) -> ProofSystemId {
        ProofSystemId::Groth16Bn254
    }

    fn prove(&self, witness: &[u8], public_input: &[u8]) -> Result<Proof> {
        let w: BankingWitness = serde_json::from_slice(witness)?;
        let p: BankingPublicInput = serde_json::from_slice(public_input)?;
        let proof = zk_prove_banking(
            &self.keys.proving_key,
            w.transaction_amount_minor,
            p.risk_adjusted_threshold_minor,
            veritas_zk_poc::random_seed(),
        )
        .map_err(zk_poc_err)?;
        serialize_proof(&proof)
    }

    fn verify(&self, proof: &Proof, public_input: &[u8]) -> Result<()> {
        let p: BankingPublicInput = serde_json::from_slice(public_input)?;
        let ark_proof = deserialize_proof(proof)?;
        let valid = zk_verify_banking(
            &self.keys.verifying_key,
            p.risk_adjusted_threshold_minor,
            &ark_proof,
        )
        .map_err(zk_poc_err)?;
        if valid {
            Ok(())
        } else {
            Err(VeritasError::InvalidProof(
                "groth16-bn254 (banking-basel-iii): proof did not verify".into(),
            ))
        }
    }
}

// ============================================================
// healthcare-hipaa
// ============================================================

/// One log entry as carried over the wire. Deliberately narrower than
/// `DisclosureLogEntry` -- see module docs for why `accessor_id_hash`/
/// `timestamp_unix` aren't here.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub(crate) struct HealthcareEntryWire {
    pub(crate) is_active: bool,
    pub(crate) authorized: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct HealthcareWitness {
    /// May be shorter than `MAX_ENTRIES`; padded internally. See
    /// `prove()` below for what happens if it's longer.
    pub(crate) entries: Vec<HealthcareEntryWire>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct HealthcarePublicInput {
    /// See module docs / `zk-poc/src/healthcare_circuit.rs`: this is
    /// reduced into the BN254 scalar field via
    /// `Fr::from_le_bytes_mod_order`, a documented simplification of a
    /// real 32-byte hash into a single field element, not a general
    /// collision-resistant hash-to-field construction.
    pub(crate) record_id_hash: [u8; 32],
    pub(crate) observed_access_count: u64,
}

fn record_id_to_field(hash: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(hash)
}

/// Real Groth16-over-BN254 backend for `healthcare-hipaa`
/// (`HealthcareDisclosureCircuit` in `zk-poc/src/healthcare_circuit.rs`).
pub struct HealthcareGroth16Backend {
    keys: Keys,
}

impl HealthcareGroth16Backend {
    pub fn setup(seed: u64) -> Result<Self> {
        let keys = zk_setup_healthcare(seed).map_err(zk_poc_err)?;
        Ok(Self { keys })
    }

    pub fn from_keys(keys: Keys) -> Self {
        Self { keys }
    }
}

impl ProofSystem for HealthcareGroth16Backend {
    fn id(&self) -> ProofSystemId {
        ProofSystemId::Groth16Bn254
    }

    fn prove(&self, witness: &[u8], public_input: &[u8]) -> Result<Proof> {
        let w: HealthcareWitness = serde_json::from_slice(witness)?;
        let p: HealthcarePublicInput = serde_json::from_slice(public_input)?;

        // A length over MAX_ENTRIES is a circuit-capacity error, not a
        // predicate-false error (see healthcare_circuit.rs's own
        // `with_witness` docs) -- returned here as an ordinary Result,
        // since panicking across this trait's boundary would be a poor
        // failure mode for a library caller, unlike `with_witness`'
        // `assert!` (an internal invariant check zk-poc's own callers are
        // expected to have validated before this point; this is exactly
        // that validation, done once, at the boundary).
        if w.entries.len() > MAX_ENTRIES {
            return Err(VeritasError::InvalidProof(format!(
                "groth16-bn254 (healthcare-hipaa): {} entries exceeds this circuit's \
                 MAX_ENTRIES={} -- this is a circuit-capacity limit, not a \
                 false claim; see zk-poc/src/healthcare_circuit.rs",
                w.entries.len(),
                MAX_ENTRIES
            )));
        }
        let entries: Vec<EntryWitness> = w
            .entries
            .iter()
            .map(|e| EntryWitness {
                is_active: e.is_active,
                authorized: e.authorized,
            })
            .collect();

        let record_id = record_id_to_field(&p.record_id_hash);
        let proof = zk_prove_healthcare(
            &self.keys.proving_key,
            record_id,
            p.observed_access_count,
            &entries,
            veritas_zk_poc::random_seed(),
        )
        .map_err(zk_poc_err)?;
        serialize_proof(&proof)
    }

    fn verify(&self, proof: &Proof, public_input: &[u8]) -> Result<()> {
        let p: HealthcarePublicInput = serde_json::from_slice(public_input)?;
        let ark_proof = deserialize_proof(proof)?;
        let record_id = record_id_to_field(&p.record_id_hash);
        let valid = zk_verify_healthcare(
            &self.keys.verifying_key,
            record_id,
            p.observed_access_count,
            &ark_proof,
        )
        .map_err(zk_poc_err)?;
        if valid {
            Ok(())
        } else {
            Err(VeritasError::InvalidProof(
                "groth16-bn254 (healthcare-hipaa): proof did not verify".into(),
            ))
        }
    }
}

// ============================================================
// gov-supply-chain-integrity
// ============================================================

/// One audit-log entry as carried over the wire. No `sequence_number`
/// field, matching `zk-poc::supply_chain_circuit::EntryWitness` — see
/// that module's docs for why position in the array (not a witnessed
/// field) determines the sequence number the circuit uses.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub(crate) struct ChainEntryWire {
    pub(crate) event_hash: [u8; 32],
    pub(crate) is_active: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SupplyChainWitness {
    /// May be shorter than `CHAIN_MAX_ENTRIES`; padded internally, and
    /// (unlike the healthcare circuit) must be an in-order prefix of
    /// active entries — see `supply_chain_circuit.rs`'s module docs.
    pub(crate) entries: Vec<ChainEntryWire>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SupplyChainPublicInput {
    pub(crate) genesis_hash: [u8; 32],
    pub(crate) final_linkage_hash: [u8; 32],
    pub(crate) active_count: u64,
}

/// Real Groth16-over-BN254 backend for `gov-supply-chain-integrity`
/// (`SupplyChainIntegrityCircuit` in `zk-poc/src/supply_chain_circuit.rs`).
///
/// **Operationally different from the other two backends in this file in
/// one important way, not just a bigger version of the same thing:** its
/// proving key is ~64 MiB (per `BENCHMARKS.md`), versus ~29 KB
/// (`BankingGroth16Backend`) and ~13 KB (`HealthcareGroth16Backend`).
/// `setup()` below calls straight into `zk_setup_supply_chain`, which
/// regenerates that entire key from scratch — fine in a test (as this
/// file's own tests do), but genuinely unsuitable to call per-request or
/// even per-process-start in anything resembling real deployment: at
/// minimum, expect `setup()` here to take on the order of tens of
/// seconds by itself, on top of whatever it costs to hold a 64 MiB key in
/// memory per loaded backend instance. `from_keys` exists precisely so a
/// real caller loads a **published** key once (see `zk-poc/README.md`'s
/// "what's still needed" item 3, still open) rather than ever calling
/// `setup()` outside tests — true of the other two backends as well, but
/// the cost of getting this wrong is far higher here.
pub struct SupplyChainGroth16Backend {
    keys: Keys,
}

impl SupplyChainGroth16Backend {
    /// See struct docs: expect this to be slow (tens of seconds) and to
    /// hold a large key in memory. Exists for tests and for generating a
    /// key to publish, not for use on any request path.
    pub fn setup(seed: u64) -> Result<Self> {
        let keys = zk_setup_supply_chain(seed).map_err(zk_poc_err)?;
        Ok(Self { keys })
    }

    pub fn from_keys(keys: Keys) -> Self {
        Self { keys }
    }
}

impl ProofSystem for SupplyChainGroth16Backend {
    fn id(&self) -> ProofSystemId {
        ProofSystemId::Groth16Bn254
    }

    fn prove(&self, witness: &[u8], public_input: &[u8]) -> Result<Proof> {
        let w: SupplyChainWitness = serde_json::from_slice(witness)?;
        let p: SupplyChainPublicInput = serde_json::from_slice(public_input)?;

        // Same circuit-capacity-vs-false-claim distinction as
        // HealthcareGroth16Backend::prove -- see that function's comment.
        if w.entries.len() > CHAIN_MAX_ENTRIES {
            return Err(VeritasError::InvalidProof(format!(
                "groth16-bn254 (gov-supply-chain-integrity): {} entries exceeds this \
                 circuit's MAX_ENTRIES={} -- this is a circuit-capacity limit, not a \
                 false claim; see zk-poc/src/supply_chain_circuit.rs",
                w.entries.len(),
                CHAIN_MAX_ENTRIES
            )));
        }
        let entries: Vec<ChainEntryWitness> = w
            .entries
            .iter()
            .map(|e| ChainEntryWitness {
                event_hash: e.event_hash,
                is_active: e.is_active,
            })
            .collect();

        let proof = zk_prove_supply_chain(
            &self.keys.proving_key,
            p.genesis_hash,
            p.final_linkage_hash,
            p.active_count,
            &entries,
            veritas_zk_poc::random_seed(),
        )
        .map_err(zk_poc_err)?;
        serialize_proof(&proof)
    }

    fn verify(&self, proof: &Proof, public_input: &[u8]) -> Result<()> {
        let p: SupplyChainPublicInput = serde_json::from_slice(public_input)?;
        let ark_proof = deserialize_proof(proof)?;
        let valid = zk_verify_supply_chain(
            &self.keys.verifying_key,
            p.genesis_hash,
            p.final_linkage_hash,
            p.active_count,
            &ark_proof,
        )
        .map_err(zk_poc_err)?;
        if valid {
            Ok(())
        } else {
            Err(VeritasError::InvalidProof(
                "groth16-bn254 (gov-supply-chain-integrity): proof did not verify".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETUP_SEED: u64 = 42;

    fn banking_witness(amount: u64) -> Vec<u8> {
        serde_json::to_vec(&BankingWitness {
            transaction_amount_minor: amount,
        })
        .unwrap()
    }

    fn banking_public(threshold: u64) -> Vec<u8> {
        serde_json::to_vec(&BankingPublicInput {
            risk_adjusted_threshold_minor: threshold,
        })
        .unwrap()
    }

    #[test]
    fn banking_end_to_end_via_proof_system_trait() {
        // Deliberately goes through the `ProofSystem` trait object, not
        // the concrete struct's methods directly -- this is the actual
        // integration point `core/` code (and eventually the Attestation
        // pipeline) would call through.
        let backend: Box<dyn ProofSystem> =
            Box::new(BankingGroth16Backend::setup(SETUP_SEED).unwrap());

        let proof = backend
            .prove(&banking_witness(500_00), &banking_public(1_000_00))
            .expect("proving should succeed for a genuinely compliant transaction");

        assert!(matches!(proof, Proof::Groth16Bn254(ref b) if b.len() == 128));

        backend
            .verify(&proof, &banking_public(1_000_00))
            .expect("a correctly generated proof must verify");
    }

    #[test]
    fn banking_false_claim_cannot_be_proven() {
        let backend = BankingGroth16Backend::setup(SETUP_SEED).unwrap();
        let result = backend.prove(&banking_witness(1_000_01), &banking_public(1_000_00));
        assert!(
            result.is_err(),
            "proving must fail for transaction_amount_minor > risk_adjusted_threshold_minor"
        );
    }

    #[test]
    fn banking_proof_rejects_wrong_threshold() {
        let backend = BankingGroth16Backend::setup(SETUP_SEED).unwrap();
        let proof = backend
            .prove(&banking_witness(500_00), &banking_public(1_000_00))
            .unwrap();
        let result = backend.verify(&proof, &banking_public(2_000_00));
        assert!(
            result.is_err(),
            "a proof for threshold=1_000_00 must not verify against threshold=2_000_00"
        );
    }

    #[test]
    fn banking_wrong_proof_variant_is_rejected_not_panicking() {
        let backend = BankingGroth16Backend::setup(SETUP_SEED).unwrap();
        let toy = Proof::Toy(super::super::ToyProof {
            payload: vec![0u8; 32],
        });
        let result = backend.verify(&toy, &banking_public(1_000_00));
        assert!(result.is_err(), "a Toy proof must be rejected, not panic");
    }

    fn healthcare_witness(entries: &[(bool, bool)]) -> Vec<u8> {
        serde_json::to_vec(&HealthcareWitness {
            entries: entries
                .iter()
                .map(|&(is_active, authorized)| HealthcareEntryWire {
                    is_active,
                    authorized,
                })
                .collect(),
        })
        .unwrap()
    }

    fn healthcare_public(record_id_hash: [u8; 32], count: u64) -> Vec<u8> {
        serde_json::to_vec(&HealthcarePublicInput {
            record_id_hash,
            observed_access_count: count,
        })
        .unwrap()
    }

    #[test]
    fn healthcare_end_to_end_via_proof_system_trait() {
        let backend: Box<dyn ProofSystem> =
            Box::new(HealthcareGroth16Backend::setup(SETUP_SEED).unwrap());
        let record_id_hash = [7u8; 32];
        let entries = [(true, true), (true, true), (false, false)];

        let proof = backend
            .prove(&healthcare_witness(&entries), &healthcare_public(record_id_hash, 2))
            .expect("proving should succeed for a genuinely compliant log");

        assert!(matches!(proof, Proof::Groth16Bn254(ref b) if b.len() == 128));

        backend
            .verify(&proof, &healthcare_public(record_id_hash, 2))
            .expect("a correctly generated proof must verify");
    }

    #[test]
    fn healthcare_count_mismatch_cannot_be_proven() {
        let backend = HealthcareGroth16Backend::setup(SETUP_SEED).unwrap();
        let entries = [(true, true)];
        let result = backend.prove(&healthcare_witness(&entries), &healthcare_public([1u8; 32], 2));
        assert!(result.is_err());
    }

    #[test]
    fn healthcare_unauthorized_active_entry_cannot_be_proven() {
        let backend = HealthcareGroth16Backend::setup(SETUP_SEED).unwrap();
        let entries = [(true, true), (true, false)];
        let result = backend.prove(&healthcare_witness(&entries), &healthcare_public([1u8; 32], 2));
        assert!(result.is_err());
    }

    #[test]
    fn healthcare_proof_rejects_wrong_record_id() {
        let backend = HealthcareGroth16Backend::setup(SETUP_SEED).unwrap();
        let entries = [(true, true)];
        let proof = backend
            .prove(&healthcare_witness(&entries), &healthcare_public([1u8; 32], 1))
            .unwrap();
        let result = backend.verify(&proof, &healthcare_public([2u8; 32], 1));
        assert!(
            result.is_err(),
            "a proof for one record_id must not verify against a different one"
        );
    }

    #[test]
    fn healthcare_exceeding_max_entries_is_a_clean_error_not_a_panic() {
        let backend = HealthcareGroth16Backend::setup(SETUP_SEED).unwrap();
        let entries = vec![(true, true); MAX_ENTRIES + 1];
        let result = backend.prove(&healthcare_witness(&entries), &healthcare_public([1u8; 32], 17));
        match result {
            Err(VeritasError::InvalidProof(msg)) => assert!(msg.contains("MAX_ENTRIES")),
            other => panic!("expected a clean InvalidProof error, got {other:?}"),
        }
    }

    #[test]
    fn banking_and_healthcare_backends_are_interchangeable_through_the_trait() {
        // Sanity check on the "one backend per rule, same trait" design:
        // both backends can sit in the same Vec<Box<dyn ProofSystem>>,
        // confirming the trait boundary is real, not just type-checked
        // per call site.
        let backends: Vec<Box<dyn ProofSystem>> = vec![
            Box::new(BankingGroth16Backend::setup(SETUP_SEED).unwrap()),
            Box::new(HealthcareGroth16Backend::setup(SETUP_SEED).unwrap()),
        ];
        for backend in &backends {
            assert_eq!(backend.id(), ProofSystemId::Groth16Bn254);
        }
    }

    // --- gov-supply-chain-integrity ---
    // Deliberately only 2 tests, each doing its own setup() call: this
    // backend's setup() takes ~20s and its proving key is ~64 MiB (see
    // SupplyChainGroth16Backend's own docs) -- every extra setup() call
    // in this test module costs real wall-clock time, so assertions that
    // don't strictly need their own fresh setup are grouped into these
    // two tests rather than split out for their own sake.

    fn chain_witness(entries: &[([u8; 32], bool)]) -> Vec<u8> {
        serde_json::to_vec(&SupplyChainWitness {
            entries: entries
                .iter()
                .map(|&(event_hash, is_active)| ChainEntryWire {
                    event_hash,
                    is_active,
                })
                .collect(),
        })
        .unwrap()
    }

    fn chain_public(genesis_hash: [u8; 32], final_linkage_hash: [u8; 32], count: u64) -> Vec<u8> {
        serde_json::to_vec(&SupplyChainPublicInput {
            genesis_hash,
            final_linkage_hash,
            active_count: count,
        })
        .unwrap()
    }

    #[test]
    fn supply_chain_end_to_end_and_wrong_public_input_rejection() {
        let backend: Box<dyn ProofSystem> =
            Box::new(SupplyChainGroth16Backend::setup(SETUP_SEED).unwrap());
        assert_eq!(backend.id(), ProofSystemId::Groth16Bn254);

        let genesis = [4u8; 32];
        let event_hashes = [[1u8; 32], [2u8; 32]];
        let final_hash = event_hashes.iter().enumerate().fold(genesis, |prev, (i, eh)| {
            veritas_zk_poc::supply_chain_circuit::entry_linkage_hash(i as u64, eh, &prev)
        });
        let entries: Vec<([u8; 32], bool)> = event_hashes.iter().map(|&h| (h, true)).collect();

        let proof = backend
            .prove(&chain_witness(&entries), &chain_public(genesis, final_hash, 2))
            .expect("proving should succeed for a genuinely intact chain");
        assert!(matches!(proof, Proof::Groth16Bn254(ref b) if b.len() == 128));

        backend
            .verify(&proof, &chain_public(genesis, final_hash, 2))
            .expect("a correctly generated proof must verify");

        // Reuse the same backend (no second setup) to check rejection
        // against a different genesis_hash -- the vulnerability class
        // this circuit's own module docs warn about, checked directly.
        let wrong_genesis = [9u8; 32];
        let result = backend.verify(&proof, &chain_public(wrong_genesis, final_hash, 2));
        assert!(
            result.is_err(),
            "a proof for one genesis_hash must not verify against a different one"
        );
    }

    #[test]
    fn supply_chain_false_claim_and_capacity_limit_are_rejected() {
        let backend = SupplyChainGroth16Backend::setup(SETUP_SEED).unwrap();
        let genesis = [4u8; 32];

        // Capacity limit: caught before ever calling into zk-poc, so this
        // check is cheap regardless of the backend's own setup cost.
        let too_many: Vec<([u8; 32], bool)> = (0..CHAIN_MAX_ENTRIES + 1)
            .map(|i| ([i as u8; 32], true))
            .collect();
        let result = backend.prove(
            &chain_witness(&too_many),
            &chain_public(genesis, [0u8; 32], (CHAIN_MAX_ENTRIES + 1) as u64),
        );
        match result {
            Err(VeritasError::InvalidProof(msg)) => assert!(msg.contains("MAX_ENTRIES")),
            other => panic!("expected a clean InvalidProof error, got {other:?}"),
        }

        // False claim: a genuinely tampered chain that no longer produces
        // the claimed final_linkage_hash. This fails fast (during R1CS
        // witness allocation, before the expensive proving step -- see
        // SupplyChainGroth16Backend's own comments), not after a full
        // ~8.6s proving attempt.
        let entries = vec![([1u8; 32], true), ([2u8; 32], true)];
        let bogus_final_hash = [0xEEu8; 32]; // does not match any real chain from genesis
        let result = backend.prove(
            &chain_witness(&entries),
            &chain_public(genesis, bogus_final_hash, 2),
        );
        assert!(
            result.is_err(),
            "proving must fail when the chain doesn't actually reach the claimed final hash"
        );
    }
}
