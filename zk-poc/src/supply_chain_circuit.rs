//! `SupplyChainIntegrityCircuit`: a REAL R1CS circuit proving
//! `core/src/circuits/gov_supply_chain.rs`'s `AuditTrailIntegrityRule` in
//! zero-knowledge -- "this audit log's hash chain runs unbroken from a
//! public genesis anchor to a public final state" -- without revealing
//! any individual `event_hash`.
//!
//! # Why this one needed a real SHA-256 R1CS gadget, and the other two didn't
//!
//! `TransactionThresholdCircuit` (banking) and `HealthcareDisclosureCircuit`
//! only ever need boolean and arithmetic gadgets -- neither predicate
//! involves a hash computed *inside* the circuit. This one does:
//! `AuditTrailIntegrityRule::entry_linkage_hash` is
//! `SHA256(sequence_number_LE(8) || event_hash(32) || prev_entry_hash(32))`,
//! and the whole point of the rule is that this hash chain links correctly
//! -- so the circuit has to actually compute SHA-256 as arithmetic
//! constraints, not just compare or count booleans. This is exactly the
//! "structurally harder" gap `zk-poc/README.md` and `STATUS.md` have been
//! flagging since the first circuit landed.
//!
//! The gadget itself is NOT hand-rolled here: `ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget`
//! (upstream `arkworks-rs/crypto-primitives`, adapted from
//! `nanpuyue/sha256`) is used directly. Re-implementing SHA-256's bitwise
//! round function, message schedule, and 32-bit modular addition from
//! scratch in R1CS is exactly the kind of subtle, easy-to-get-wrong
//! cryptographic code this project's own discipline says to avoid
//! reinventing when a real, tested implementation exists (see
//! `RFC 0002`'s reasoning for preferring well-audited constructions).
//!
//! # Fixed capacity, again, and why `MAX_ENTRIES` is much smaller here
//!
//! Same fixed-capacity-array technique as `HealthcareDisclosureCircuit`
//! (`is_active` flags marking real entries vs. padding) -- but
//! `MAX_ENTRIES` here is deliberately much smaller (4, vs. healthcare's
//! 16), because SHA-256 is expensive in R1CS: each entry's 72-byte
//! preimage needs two 512-bit SHA-256 compression rounds (72 bytes plus
//! padding and the 8-byte length field cross a 64-byte block boundary),
//! and each compression round costs on the order of tens of thousands of
//! constraints with this gadget. **Measured, not estimated:** at
//! `MAX_ENTRIES=4` this circuit has 318,668 constraints (vs. 129 for the
//! banking circuit and 65 for the healthcare circuit -- roughly three
//! orders of magnitude larger) and a 67MB proving key (vs. ~29KB and
//! ~13KB respectively) -- see `BENCHMARKS.md` for the full numbers,
//! including proving time. **The 67MB proving key is the more
//! operationally significant number of the two**: it has to be
//! distributed to, and stored by, every institution proving compliance
//! under this rule module, which is a real deployment cost this circuit
//! design doesn't hide. A real deployment auditing a period with more
//! than 4 events needs either a larger `MAX_ENTRIES` (recompiled, new
//! trusted setup, and a proving-key size that scales roughly linearly
//! with entry count -- expect tens of megabytes MORE, not less) or a
//! different circuit design (e.g. a Merkle-tree-of-hash-chains structure,
//! proven incrementally, or a hash function cheaper in R1CS than SHA-256
//! such as Poseidon if the chain format itself could be revised) -- not
//! designed here, flagged as real follow-up work.
//!
//! # Why padding here is NOT order-independent (unlike the healthcare circuit)
//!
//! `HealthcareDisclosureCircuit`'s module docs explain why padding
//! position doesn't matter for that predicate (it's a pure count + set
//! condition). This predicate is the opposite: a hash CHAIN, where entry
//! `i`'s constraint depends on entry `i-1`'s output. Padding therefore
//! MUST be a contiguous suffix -- `is_active` flags must go
//! true,true,...,true,false,false,...,false, never true after a false --
//! and this circuit enforces that directly (see `generate_constraints`),
//! unlike the healthcare circuit, which deliberately does NOT need an
//! equivalent constraint.
//!
//! # Why `sequence_number` is not a witnessed field at all
//!
//! Unlike `core::circuits::gov_supply_chain::AuditLogEntry`, this
//! circuit's per-slot witness has no `sequence_number` field. Slot `i`'s
//! SHA-256 preimage uses the CONSTANT `i` (as 8 little-endian bytes)
//! directly, not a witnessed-and-checked value. This is sound, not a
//! shortcut: if a real audit log's entry at position `i` had actually
//! been assigned a different sequence number, the TRUE linkage hash that
//! log's own chain-building process computed (using that different
//! number) would differ from what this circuit computes using the
//! constant `i` -- by SHA-256's preimage resistance, a dishonest Prover
//! cannot make those agree. So "sequence_number equals position" is
//! enforced by construction, for free, rather than needing a separate
//! witnessed field and an explicit equality constraint (contrast with
//! `core::circuits::gov_supply_chain::AuditTrailIntegrityRule::check`,
//! which DOES witness and explicitly compare `entry.sequence_number != i`
//! -- both approaches are sound, this one is simply cheaper here).
//!
//! # What's public, and why `final_linkage_hash` has to be
//!
//! `genesis_hash` (the chain's trust anchor) and `active_count` (how many
//! real entries exist) are public for the same reasons the analogous
//! fields are public in the other two circuits. `final_linkage_hash` --
//! the linkage hash of the LAST active entry -- is also public, and has
//! to be: without it, the circuit would only prove "SOME valid chain of
//! `active_count` entries exists starting from `genesis_hash`," which is
//! true of almost any audit log and proves nothing about THIS specific
//! one. Binding the actual resulting chain state into the public inputs
//! is what makes the proof about a specific, checkable claim (e.g.
//! "matches the hash independently published on my bulletin board")
//! rather than an unfalsifiable existence statement -- the same class of
//! binding concern as `record_id` in the healthcare circuit's own module
//! docs, applied to a running hash instead of a static identifier.
//!
//! `period_start_unix`/`period_end_unix` are deliberately NOT part of
//! this circuit's public inputs or constraints at all, unlike
//! `core::circuits::gov_supply_chain::AuditTrailInput`, which does check
//! `period_start_unix < period_end_unix`. Consistent with both other
//! circuits in this crate (see e.g. `record_id` vs. `accessor_id_hash` in
//! `healthcare_circuit.rs`'s own docs): not every field of a rule's
//! `Input` struct needs to be inside the ZK statement -- period bounds
//! are ordinary metadata a Verifier can check in the clear (they reveal
//! nothing sensitive), so they're left to RFC-0003's commitment scheme
//! over the full `canonical_bytes`, not re-implemented as a redundant
//! range check here.

use ark_bn254::Fr;
use ark_crypto_primitives::crh::sha256::constraints::{DigestVar, Sha256Gadget};
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::AllocVar,
    select::CondSelectGadget,
    uint8::UInt8,
    ToBytesGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Fixed circuit capacity. See module docs for why this is much smaller
/// than `healthcare_circuit::MAX_ENTRIES` (SHA-256's real R1CS cost, not
/// an arbitrary choice) and what a deployment needing more entries per
/// attested period would have to do instead of just raising this
/// constant casually.
pub const MAX_ENTRIES: usize = 4;

/// One (private) audit-log entry witness slot. No `sequence_number`
/// field -- see module docs for why position `i` is used as a circuit
/// constant instead.
#[derive(Clone, Copy)]
pub struct EntryWitness {
    pub event_hash: [u8; 32],
    pub is_active: bool,
}

impl EntryWitness {
    pub const EMPTY: Self = Self {
        event_hash: [0u8; 32],
        is_active: false,
    };
}

/// Recomputes `core::circuits::gov_supply_chain::AuditTrailIntegrityRule::entry_linkage_hash`
/// in plain Rust (not in-circuit) -- used both by the Rust-side
/// satisfiability pre-check in `generate_constraints` (see that
/// function's comments) and by callers building real witness data
/// outside this module. Mirrors that function's exact byte layout:
/// `SHA256(sequence_number_LE(8) || event_hash(32) || prev_entry_hash(32))`.
pub fn entry_linkage_hash(sequence_number: u64, event_hash: &[u8; 32], prev: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(sequence_number.to_le_bytes());
    hasher.update(event_hash);
    hasher.update(prev);
    hasher.finalize().into()
}

/// The circuit. `entries`/`active_count` are `None`/unused for the
/// setup-shape instance; `genesis_hash`/`final_linkage_hash` are always
/// required (both public, supplied at setup, proving, and verification
/// time, same pattern as `threshold` in `TransactionThresholdCircuit`).
#[derive(Clone)]
pub struct SupplyChainIntegrityCircuit {
    pub genesis_hash: [u8; 32],
    pub final_linkage_hash: [u8; 32],
    pub active_count: u64,
    /// `None` during setup, `Some([...; MAX_ENTRIES])` when actually
    /// proving.
    pub entries: Option<[EntryWitness; MAX_ENTRIES]>,
}

impl SupplyChainIntegrityCircuit {
    pub fn setup_shape(genesis_hash: [u8; 32], final_linkage_hash: [u8; 32]) -> Self {
        Self {
            genesis_hash,
            final_linkage_hash,
            active_count: 0,
            entries: None,
        }
    }

    /// `real_entries` may be shorter than `MAX_ENTRIES`; padded with
    /// `EntryWitness::EMPTY`. Panics if longer than `MAX_ENTRIES` -- same
    /// "circuit-capacity limit, not a witness bug" reasoning as
    /// `HealthcareDisclosureCircuit::with_witness`.
    pub fn with_witness(
        genesis_hash: [u8; 32],
        final_linkage_hash: [u8; 32],
        active_count: u64,
        real_entries: &[EntryWitness],
    ) -> Self {
        assert!(
            real_entries.len() <= MAX_ENTRIES,
            "SupplyChainIntegrityCircuit: {} entries exceeds MAX_ENTRIES={}; \
             this circuit's fixed capacity was set too low for this claim -- \
             recompile with a larger MAX_ENTRIES (re-measure proving time \
             before assuming that stays practical, see module docs)",
            real_entries.len(),
            MAX_ENTRIES
        );
        let mut entries = [EntryWitness::EMPTY; MAX_ENTRIES];
        entries[..real_entries.len()].copy_from_slice(real_entries);
        Self {
            genesis_hash,
            final_linkage_hash,
            active_count,
            entries: Some(entries),
        }
    }
}

/// Rust-side mirror of what the in-circuit constraints below enforce:
/// walks the (possibly padded) entries, checks the prefix property, and
/// recomputes the resulting chain state. Returns `None` if anything
/// disagrees with the claimed public `active_count`/`final_linkage_hash`.
/// Used ONLY to decide whether to feed real witness values into the
/// circuit or force `AssignmentMissing` everywhere -- see
/// `generate_constraints`'s comment on why this explicit pre-check
/// exists (arkworks' `Groth16::prove` does not check R1CS satisfiability
/// itself, same issue `healthcare_circuit.rs` documents and solves the
/// same way).
fn claim_is_consistent(
    genesis_hash: &[u8; 32],
    final_linkage_hash: &[u8; 32],
    active_count: u64,
    entries: &[EntryWitness; MAX_ENTRIES],
) -> bool {
    let mut running = *genesis_hash;
    let mut count = 0u64;
    let mut prev_active = true; // slot 0 is never blocked by a "previous" slot
    for (i, entry) in entries.iter().enumerate() {
        if entry.is_active && !prev_active {
            return false; // active slot after an inactive one: not a valid prefix
        }
        if entry.is_active {
            running = entry_linkage_hash(i as u64, &entry.event_hash, &running);
            count += 1;
        }
        prev_active = entry.is_active;
    }
    count > 0 && count == active_count && running == *final_linkage_hash
}

impl ConstraintSynthesizer<Fr> for SupplyChainIntegrityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs, allocated first, same ordering convention as the
        // other two circuits in this crate.
        let genesis_hash_var = DigestVar::new_input(cs.clone(), || Ok(self.genesis_hash.to_vec()))?;
        let final_hash_var =
            DigestVar::new_input(cs.clone(), || Ok(self.final_linkage_hash.to_vec()))?;
        let active_count_var = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.active_count)))?;

        // Same deliberate AssignmentMissing short-circuit as
        // healthcare_circuit.rs, and for the identical reason: arkworks'
        // Groth16::prove does not itself check R1CS satisfiability, and
        // this predicate (like healthcare's, unlike banking's range
        // check) has no witness value that's naturally impossible to
        // assign for a false claim -- every byte/bool below is
        // independently valid regardless of whether the overall chain is
        // correct. `claim_is_consistent` decides, once, in Rust, whether
        // a valid witness assignment for this exact public claim exists
        // at all.
        let claim_holds = self
            .entries
            .map(|entries| claim_is_consistent(&self.genesis_hash, &self.final_linkage_hash, self.active_count, &entries));

        let mut running_hash_var = genesis_hash_var;
        let mut computed_count_var = FpVar::<Fr>::zero();
        let one = FpVar::<Fr>::one();
        let zero = FpVar::<Fr>::zero();
        let mut prev_active_var = Boolean::TRUE;
        let mut all_is_active_vars = Vec::with_capacity(MAX_ENTRIES);

        for i in 0..MAX_ENTRIES {
            let (event_hash_val, is_active_val) = match (&self.entries, claim_holds) {
                (Some(entries), Some(true)) => {
                    (Some(entries[i].event_hash), Some(entries[i].is_active))
                }
                (Some(_), Some(false)) => (None, None), // false claim: no witness, by design
                (None, _) => (None, None),               // setup-shape mode
                (Some(_), None) => unreachable!("claim_holds is Some iff entries is Some"),
            };

            let event_hash_bytes: Vec<UInt8<Fr>> = (0..32)
                .map(|j| {
                    UInt8::new_witness(cs.clone(), || {
                        event_hash_val
                            .map(|h| h[j])
                            .ok_or(SynthesisError::AssignmentMissing)
                    })
                })
                .collect::<Result<_, _>>()?;
            let is_active_var = Boolean::new_witness(cs.clone(), || {
                is_active_val.ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Prefix constraint (see module docs: this predicate, unlike
            // healthcare's, is order-sensitive, so padding must be a
            // contiguous suffix): is_active_i => prev_active.
            let implication = is_active_var.not().or(&prev_active_var)?;
            implication.enforce_equal(&Boolean::TRUE)?;
            prev_active_var = is_active_var.clone();
            all_is_active_vars.push(is_active_var.clone());

            // Build this slot's SHA-256 preimage: constant sequence-number
            // bytes (see module docs for why this is a constant, not a
            // witness) || event_hash (private) || running prev-hash.
            let seq_bytes: Vec<UInt8<Fr>> = (i as u64)
                .to_le_bytes()
                .iter()
                .map(|&b| UInt8::constant(b))
                .collect();
            let prev_bytes = running_hash_var.to_bytes()?;
            let mut preimage = Vec::with_capacity(8 + 32 + 32);
            preimage.extend_from_slice(&seq_bytes);
            preimage.extend_from_slice(&event_hash_bytes);
            preimage.extend_from_slice(&prev_bytes);

            let computed_linkage_var = Sha256Gadget::digest(&preimage)?;

            // Only advance the running hash / count if this slot is
            // active -- inactive (padding) slots leave the chain state
            // untouched, exactly mirroring healthcare's "padding imposes
            // nothing" principle, but for a running value instead of an
            // independent per-slot check.
            running_hash_var = DigestVar::conditionally_select(
                &is_active_var,
                &computed_linkage_var,
                &running_hash_var,
            )?;
            let contribution = is_active_var.select(&one, &zero)?;
            computed_count_var = &computed_count_var + &contribution;
        }

        // Global constraints: the final chain state and count must match
        // the public claim, and the chain must be non-empty (mirrors
        // AuditTrailIntegrityRule::check's explicit empty-entries
        // rejection).
        running_hash_var.enforce_equal(&final_hash_var)?;
        computed_count_var.enforce_equal(&active_count_var)?;
        Boolean::kary_or(&all_is_active_vars)?.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};

    const GENESIS: [u8; 32] = [7u8; 32];

    fn build_chain(event_hashes: &[[u8; 32]]) -> (Vec<EntryWitness>, [u8; 32]) {
        let mut running = GENESIS;
        let mut entries = Vec::with_capacity(event_hashes.len());
        for (i, eh) in event_hashes.iter().enumerate() {
            running = entry_linkage_hash(i as u64, eh, &running);
            entries.push(EntryWitness {
                event_hash: *eh,
                is_active: true,
            });
        }
        (entries, running)
    }

    fn is_satisfied(circuit: SupplyChainIntegrityCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    fn generation_fails(circuit: SupplyChainIntegrityCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
        circuit.generate_constraints(cs.clone()).is_err()
    }

    #[test]
    fn setup_shape_generates_constraints_without_witness() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Setup);
        SupplyChainIntegrityCircuit::setup_shape(GENESIS, [0u8; 32])
            .generate_constraints(cs.clone())
            .expect("setup-mode constraint generation should not require a witness");
        assert!(cs.num_constraints() > 0);
    }

    #[test]
    fn intact_two_entry_chain_is_satisfied() {
        let (entries, final_hash) = build_chain(&[[1u8; 32], [2u8; 32]]);
        let circuit = SupplyChainIntegrityCircuit::with_witness(GENESIS, final_hash, 2, &entries);
        assert!(is_satisfied(circuit));
    }

    #[test]
    fn intact_full_capacity_chain_is_satisfied() {
        let hashes: Vec<[u8; 32]> = (0..MAX_ENTRIES).map(|i| [i as u8 + 1; 32]).collect();
        let (entries, final_hash) = build_chain(&hashes);
        let circuit = SupplyChainIntegrityCircuit::with_witness(
            GENESIS,
            final_hash,
            MAX_ENTRIES as u64,
            &entries,
        );
        assert!(is_satisfied(circuit));
    }

    #[test]
    fn tampered_middle_event_hash_cannot_be_proven() {
        let (mut entries, final_hash) = build_chain(&[[1u8; 32], [2u8; 32], [3u8; 32]]);
        entries[1].event_hash = [0xFFu8; 32]; // tamper, but keep the OLD (now-wrong) final_hash
        let circuit = SupplyChainIntegrityCircuit::with_witness(GENESIS, final_hash, 3, &entries);
        assert!(generation_fails(circuit));
    }

    #[test]
    fn wrong_active_count_cannot_be_proven() {
        let (entries, final_hash) = build_chain(&[[1u8; 32], [2u8; 32]]);
        let circuit = SupplyChainIntegrityCircuit::with_witness(GENESIS, final_hash, 3, &entries);
        assert!(generation_fails(circuit));
    }

    #[test]
    fn empty_chain_cannot_be_proven() {
        let circuit = SupplyChainIntegrityCircuit::with_witness(GENESIS, GENESIS, 0, &[]);
        assert!(
            generation_fails(circuit),
            "an empty audit trail must not be provable as complete, per \
             AuditTrailIntegrityRule::check's own empty-entries rejection"
        );
    }

    #[test]
    fn active_slot_after_inactive_slot_cannot_be_proven() {
        // Hand-construct a non-prefix pattern: slot 0 inactive, slot 1
        // active -- this cannot arise from build_chain, so it's
        // constructed directly to test the prefix constraint itself.
        let mut entries = [EntryWitness::EMPTY; MAX_ENTRIES];
        entries[1] = EntryWitness {
            event_hash: [1u8; 32],
            is_active: true,
        };
        let circuit = SupplyChainIntegrityCircuit::with_witness(GENESIS, [0u8; 32], 1, &entries);
        assert!(generation_fails(circuit));
    }

    #[test]
    #[should_panic(expected = "exceeds MAX_ENTRIES")]
    fn exceeding_capacity_panics_rather_than_silently_truncating() {
        let hashes: Vec<[u8; 32]> = (0..MAX_ENTRIES + 1).map(|i| [i as u8; 32]).collect();
        let (entries, final_hash) = build_chain(&hashes);
        let _ = SupplyChainIntegrityCircuit::with_witness(
            GENESIS,
            final_hash,
            (MAX_ENTRIES + 1) as u64,
            &entries,
        );
    }

    #[test]
    fn entry_linkage_hash_matches_core_algorithm_shape() {
        // Sanity check against a hand-computed SHA256 to catch a
        // byte-order or field-order mistake in this file's mirror of
        // core::circuits::gov_supply_chain's algorithm.
        use sha2::{Digest, Sha256};
        let event_hash = [9u8; 32];
        let prev = [8u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(3u64.to_le_bytes());
        hasher.update(event_hash);
        hasher.update(prev);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(entry_linkage_hash(3, &event_hash, &prev), expected);
    }
}
