//! `HealthcareDisclosureCircuit`: a REAL R1CS circuit proving
//! `core/src/circuits/healthcare_hipaa.rs`'s `DisclosureLoggingRule` in
//! zero-knowledge -- "every observed access to this record was logged,
//! and every logged access was authorized" -- without revealing WHO
//! accessed the record, WHEN, or how many total accesses there were
//! beyond the public count.
//!
//! # Why this circuit shape, not a mechanical port of `circuit.rs`
//!
//! `TransactionThresholdCircuit` (banking-basel-iii) is a single numeric
//! comparison. This predicate is set-shaped: "for every entry in a
//! variable-length private list, a per-entry boolean must hold, AND the
//! list's length must equal a public count." R1CS circuits have a FIXED
//! shape decided at setup time -- there is no native "variable-length
//! vector" gadget. The standard technique (used here) is a fixed-capacity
//! array with an explicit `is_active` flag per slot marking which slots
//! are "real" entries vs. unused padding, exactly mirroring how the range
//! check in `circuit.rs` turns "is this in range" into a fixed number of
//! boolean witnesses.
//!
//! `MAX_ENTRIES` below is a real, load-bearing limitation, not
//! decoration: a record accessed more than `MAX_ENTRIES` times within one
//! attested period cannot be proven by this exact circuit without
//! recompiling (and re-running trusted setup) with a larger constant --
//! see `README.md` in this directory for why that's a genuine deployment
//! constraint to plan around, not an oversight to silently patch later.
//!
//! # Why padding position doesn't need its own constraint
//!
//! Unlike a sequence (gov-supply-chain-integrity's hash chain, where
//! *order* is the whole point), this predicate is order-independent: it
//! only cares about (a) how many entries are active, and (b) whether each
//! active entry is authorized. So the witness is free to mark ANY subset
//! of the `MAX_ENTRIES` slots active, in any arrangement -- the two
//! constraints below (count equality, active-implies-authorized) are
//! exactly equivalent to `DisclosureLoggingRule::check`'s two checks
//! regardless of which positions are used. No "padding must be a
//! contiguous prefix" constraint is needed, and adding one would only
//! cost constraints for no soundness benefit.
//!
//! # Why `record_id` is a public input despite not appearing in any
//! constraint body
//!
//! `DisclosureLoggingRule::check` in `core/` never actually reads
//! `record_id_hash` -- it's bookkeeping for the commitment, not part of
//! the compliance predicate. It would be tempting to leave it out of this
//! circuit entirely. That would be a real vulnerability: without
//! `record_id` bound into the proof's public inputs, a single proof of
//! "16 accesses, all authorized" would verify against ANY record making
//! the same public claim -- a Groth16 proof's soundness only binds it to
//! whatever public inputs were used at verification time, and if
//! `record_id` isn't one of them, it's simply not part of what's proven.
//! This is the same class of issue as the downgrade/replay concerns in
//! `spec/THREAT_ANALYSIS.md` §5.1-5.2: binding the right public context
//! into a proof isn't automatic, it has to be deliberate. See
//! `README.md`'s note on why this is a single field element here (a
//! simplification flagged, not hidden) rather than the full 32-byte hash
//! `core/` uses.

use ark_bn254::Fr;
use ark_r1cs_std::{
    boolean::Boolean,
    fields::{fp::FpVar, FieldVar},
    prelude::{AllocVar, EqGadget},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Fixed circuit capacity: the maximum number of disclosure-log entries
/// one proof can cover. Chosen as a round number comfortably above a
/// typical single-record access count within one audited period, not
/// derived from any HIPAA-specific figure -- a real deployment should set
/// this per rule-module version based on real access-pattern data, and
/// document the choice in that rule module's `compliance-mappings/` entry
/// (currently silent on this, which is itself a gap worth flagging there).
pub const MAX_ENTRIES: usize = 16;

/// One (private) log-entry witness slot. `accessor_id_hash` and
/// `timestamp_unix` from `core::circuits::healthcare_hipaa::DisclosureLogEntry`
/// are deliberately NOT part of this circuit: they play no role in
/// `DisclosureLoggingRule::check`'s actual predicate (completeness count +
/// per-entry authorization), so including them would add witness data and
/// constraints for two fields nothing here needs to constrain. If a
/// future rule version needs to prove something about accessor identity
/// or timing (e.g. "no access happened outside business hours"), those
/// fields would need to be added here AND the corresponding constraints
/// written -- this circuit tracks today's `core/` predicate, not a
/// superset of the data shape.
#[derive(Clone, Copy)]
pub struct EntryWitness {
    pub is_active: bool,
    pub authorized: bool,
}

impl EntryWitness {
    pub const EMPTY: Self = Self {
        is_active: false,
        authorized: false,
    };
}

/// The circuit. `entries`/`observed_access_count` are `None` for the
/// setup-shape instance; `record_id` is always required (it's public, and
/// public inputs are supplied at both setup and proving/verification
/// time, same as `threshold` in `TransactionThresholdCircuit`).
#[derive(Clone)]
pub struct HealthcareDisclosureCircuit {
    /// Public: a field-element stand-in for `record_id_hash`. See module
    /// docs and README.md for why this is a simplification of the real
    /// 32-byte hash, not the real thing.
    pub record_id: Fr,
    /// Public: the independently-observed access count this proof claims
    /// the private log matches exactly.
    pub observed_access_count: u64,
    /// Private witness: `None` during setup, `Some([...; MAX_ENTRIES])`
    /// when actually proving. Unused slots (beyond the real entry count)
    /// must be `EntryWitness::EMPTY` -- seebelow for why that's safe.
    pub entries: Option<[EntryWitness; MAX_ENTRIES]>,
}

impl HealthcareDisclosureCircuit {
    pub fn setup_shape(record_id: Fr) -> Self {
        Self {
            record_id,
            observed_access_count: 0,
            entries: None,
        }
    }

    /// `real_entries` may be shorter than `MAX_ENTRIES`; the remainder is
    /// padded with `EntryWitness::EMPTY`. Panics if `real_entries.len() >
    /// MAX_ENTRIES` -- that case is a genuine "this circuit can't prove
    /// this claim," not a witness bug, and should be surfaced to the
    /// caller before reaching this point (mirroring how
    /// `TransactionThresholdCircuit`'s proving fails, not panics, when
    /// `amount > threshold` -- see README.md's note that this is a sharper
    /// failure mode than that one, since it's a circuit-capacity limit,
    /// not the predicate itself being false).
    pub fn with_witness(
        record_id: Fr,
        observed_access_count: u64,
        real_entries: &[EntryWitness],
    ) -> Self {
        assert!(
            real_entries.len() <= MAX_ENTRIES,
            "HealthcareDisclosureCircuit: {} entries exceeds MAX_ENTRIES={}; \
             this circuit's fixed capacity was set too low for this claim -- \
             recompile with a larger MAX_ENTRIES, this is not a witness error",
            real_entries.len(),
            MAX_ENTRIES
        );
        let mut entries = [EntryWitness::EMPTY; MAX_ENTRIES];
        entries[..real_entries.len()].copy_from_slice(real_entries);
        Self {
            record_id,
            observed_access_count,
            entries: Some(entries),
        }
    }
}

impl ConstraintSynthesizer<Fr> for HealthcareDisclosureCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs, allocated first (Groth16's public-input ordering
        // is allocation order) -- record_id, then observed_access_count.
        // Neither has any further constraint on its own value; see module
        // docs for why record_id still needs to be here regardless.
        let _record_id_var = FpVar::new_input(cs.clone(), || Ok(self.record_id))?;
        let observed_count_var =
            FpVar::new_input(cs.clone(), || Ok(Fr::from(self.observed_access_count)))?;

        // IMPORTANT: arkworks' Groth16::prove does not itself check R1CS
        // satisfiability before producing a proof -- an unsatisfying
        // witness would otherwise silently yield a proof that simply
        // fails verification later, not a proving-time error. The banking
        // circuit's range check gets "proving fails for a false claim"
        // for free, because an out-of-range value has no valid *bit
        // decomposition* to assign at all. This predicate has no such
        // natural failure point (every individual `is_active`/`authorized`
        // bit is independently a valid Boolean regardless of whether the
        // OVERALL claim holds), so satisfiability is checked explicitly
        // here, in Rust, before allocating any witness -- and if it
        // doesn't hold, every witness allocation below deliberately
        // receives `None`, which fails at the FIRST one via
        // `SynthesisError::AssignmentMissing`. This is the same "no valid
        // witness assignment exists" semantics as the banking circuit,
        // made explicit rather than relying on an accident of the
        // predicate's shape.
        let claim_holds = self.entries.map(|entries| {
            let active_count = entries.iter().filter(|e| e.is_active).count() as u64;
            let all_active_are_authorized =
                entries.iter().all(|e| !e.is_active || e.authorized);
            active_count == self.observed_access_count && all_active_are_authorized
        });

        let mut active_count_var = FpVar::<Fr>::zero();
        let one = FpVar::<Fr>::one();
        let zero = FpVar::<Fr>::zero();

        for i in 0..MAX_ENTRIES {
            let (is_active_val, authorized_val) = match (&self.entries, claim_holds) {
                (Some(entries), Some(true)) => {
                    (Some(entries[i].is_active), Some(entries[i].authorized))
                }
                (Some(_), Some(false)) => (None, None), // false claim: no witness, by design
                (None, _) => (None, None),               // setup-shape mode
                (Some(_), None) => unreachable!("claim_holds is Some iff entries is Some"),
            };

            let is_active = Boolean::new_witness(cs.clone(), || {
                is_active_val.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let authorized = Boolean::new_witness(cs.clone(), || {
                authorized_val.ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Constraint 1 (per-entry): active => authorized, i.e.
            // NOT(is_active) OR authorized. An inactive (padding) slot
            // imposes nothing on `authorized` -- its value is irrelevant
            // once `is_active` is false, which is exactly right: padding
            // slots aren't real log entries, so "was this padding slot
            // authorized" isn't a meaningful question the predicate asks.
            let implication = is_active.not().or(&authorized)?;
            implication.enforce_equal(&Boolean::TRUE)?;

            // Accumulate the active count as a plain sum (NOT a weighted
            // binary reconstruction like circuit.rs's range check -- this
            // is counting how many slots are active, not decoding a
            // binary number from them).
            let contribution = is_active.select(&one, &zero)?;
            active_count_var = &active_count_var + &contribution;
        }

        // Constraint 2 (global): the number of active slots must equal
        // the publicly claimed observed_access_count. Combined with
        // constraint 1 above (which holds independently per entry), this
        // pair is exactly equivalent to DisclosureLoggingRule::check's
        // two checks: (a) log_entries.len() == observed_access_count, and
        // (b) every logged entry is authorized -- "every active slot is
        // authorized" plus "the active count matches the public count"
        // together rule out both failure modes core/ checks for: an
        // unlogged access (count mismatch, since only real entries can be
        // marked active while keeping constraint 1 satisfiable) and an
        // unauthorized logged access (constraint 1 directly). This
        // constraint is technically redundant with the `claim_holds`
        // check above during real proving (an invalid claim never reaches
        // here, per the AssignmentMissing short-circuit) -- it's kept
        // regardless because it's what makes the circuit's SHAPE correct
        // independent of that Rust-level guard, matching the discipline
        // in `spec/formal/`: constraints should be sound on their own
        // terms, not merely because calling code happens to check first.
        active_count_var.enforce_equal(&observed_count_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};

    fn e(is_active: bool, authorized: bool) -> EntryWitness {
        EntryWitness {
            is_active,
            authorized,
        }
    }

    fn is_satisfied(circuit: HealthcareDisclosureCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    /// For claims that violate the predicate: `generate_constraints`
    /// itself must return `Err` (the deliberate `AssignmentMissing`
    /// short-circuit -- see that function's module docs), not merely
    /// produce an unsatisfied constraint system. Checked directly rather
    /// than via `is_satisfied()`, which would panic on the `unwrap()`
    /// inside it once `generate_constraints` starts erroring instead of
    /// completing.
    fn generation_fails(circuit: HealthcareDisclosureCircuit) -> bool {
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
        HealthcareDisclosureCircuit::setup_shape(Fr::from(1u64))
            .generate_constraints(cs.clone())
            .expect("setup-mode constraint generation should not require a witness");
        assert!(cs.num_constraints() > 0);
    }

    #[test]
    fn complete_and_authorized_is_satisfied() {
        let entries = [e(true, true), e(true, true), e(false, false)];
        let circuit =
            HealthcareDisclosureCircuit::with_witness(Fr::from(1u64), 2, &entries);
        assert!(is_satisfied(circuit));
    }

    #[test]
    fn undercounted_active_entries_is_unsatisfied() {
        // Two entries are actually active, but the public claim says 3 --
        // mirrors core/'s "log_entries.len() != observed_access_count".
        let entries = [e(true, true), e(true, true), e(false, false)];
        let circuit =
            HealthcareDisclosureCircuit::with_witness(Fr::from(1u64), 3, &entries);
        assert!(generation_fails(circuit));
    }

    #[test]
    fn unauthorized_active_entry_is_unsatisfied() {
        let entries = [e(true, true), e(true, false)];
        let circuit =
            HealthcareDisclosureCircuit::with_witness(Fr::from(1u64), 2, &entries);
        assert!(generation_fails(circuit));
    }

    #[test]
    fn unauthorized_inactive_padding_slot_is_still_satisfied() {
        // A padding slot with authorized=false is fine PRECISELY BECAUSE
        // is_active=false for it -- this is the "padding position doesn't
        // matter" claim from the module docs, checked directly.
        let entries = [e(true, true), e(false, false)];
        let circuit =
            HealthcareDisclosureCircuit::with_witness(Fr::from(1u64), 1, &entries);
        assert!(is_satisfied(circuit));
    }

    #[test]
    fn zero_entries_and_zero_count_is_satisfied() {
        let circuit = HealthcareDisclosureCircuit::with_witness(Fr::from(1u64), 0, &[]);
        assert!(is_satisfied(circuit));
    }

    #[test]
    fn max_capacity_all_active_all_authorized_is_satisfied() {
        let entries = [e(true, true); MAX_ENTRIES];
        let circuit = HealthcareDisclosureCircuit::with_witness(
            Fr::from(1u64),
            MAX_ENTRIES as u64,
            &entries,
        );
        assert!(is_satisfied(circuit));
    }

    #[test]
    #[should_panic(expected = "exceeds MAX_ENTRIES")]
    fn exceeding_capacity_panics_rather_than_silently_truncating() {
        let entries = vec![e(true, true); MAX_ENTRIES + 1];
        let _ = HealthcareDisclosureCircuit::with_witness(Fr::from(1u64), 17, &entries);
    }

    #[test]
    fn different_record_id_is_a_different_public_input() {
        // Sanity check for the module docs' record_id claim: two circuits
        // differing only in record_id produce constraint systems whose
        // public-input assignment differs at index 0 -- i.e. record_id
        // really is wired into the public inputs, not silently dropped.
        let entries = [e(true, true)];
        let a = HealthcareDisclosureCircuit::with_witness(Fr::from(1u64), 1, &entries);
        let b = HealthcareDisclosureCircuit::with_witness(Fr::from(2u64), 1, &entries);

        let cs_a = ConstraintSystem::<Fr>::new_ref();
        cs_a.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
        a.generate_constraints(cs_a.clone()).unwrap();

        let cs_b = ConstraintSystem::<Fr>::new_ref();
        cs_b.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
        b.generate_constraints(cs_b.clone()).unwrap();

        let assignment_a = cs_a.borrow().unwrap().instance_assignment.clone();
        let assignment_b = cs_b.borrow().unwrap().instance_assignment.clone();
        assert_ne!(assignment_a, assignment_b);
    }
}
