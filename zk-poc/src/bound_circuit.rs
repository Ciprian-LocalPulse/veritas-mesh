//! `BankingBoundCircuit`: closes the real, documented gap in
//! `core::attest::attest_banking` — that nothing binds the commitment and
//! the ZK proof to provably the same input. This circuit proves BOTH
//! `amount <= threshold` (exactly as `TransactionThresholdCircuit` does)
//! AND that a public `commitment` is really
//! `SHA256(salt || amount_LE(8) || threshold_LE(8) || customer_id_hash(32))`
//! — i.e. `core::commitment::hash_based::HashBasedScheme`'s exact
//! algorithm, applied to `core::circuits::banking_basel_iii::TransactionThresholdRule::canonical_bytes`'s
//! exact byte layout, computed *inside* the same proof that proves the
//! predicate. A Verifier checking a proof from this circuit is checking
//! one statement, not two independently-true-but-possibly-unrelated ones:
//! "the amount committed to here does not exceed the threshold."
//!
//! # Why this is a NEW circuit, not a change to `TransactionThresholdCircuit`
//!
//! `TransactionThresholdCircuit` already has real callers depending on its
//! exact shape (`examples/demo.rs`, `examples/bench.rs`, `lib.rs`'s
//! `setup`/`prove`/`verify`, `core::proof::groth16_bn254::BankingGroth16Backend`).
//! Changing its public-input shape would break all of them. This circuit
//! exists alongside it — `core::attest::attest_banking` is what actually
//! switches to using this one; the original stays available (and
//! documented) for anyone who genuinely only needs the predicate proof
//! without the binding, or as a smaller/cheaper option where the caller
//! has its own way of connecting a proof to a specific commitment.
//!
//! # Why proving this costs meaningfully more than `TransactionThresholdCircuit`
//!
//! The predicate part (`amount <= threshold`) is identical — same 129ish
//! constraints, reusing `TransactionThresholdCircuit::allocate_range_checked`
//! directly (see that function's own updated doc comment for why it's
//! `pub(crate)` now). What's new is a real SHA-256 computation over an
//! 80-byte preimage (32-byte salt + 48-byte `canonical_bytes`), which
//! crosses SHA-256's 64-byte block boundary once padding is added — two
//! compression rounds, the same real cost class as one entry in
//! `supply_chain_circuit.rs`'s hash chain (see that file's own docs for
//! why that's tens of thousands of constraints, not a rounding error).
//! Measured, not estimated: see `BENCHMARKS.md` for the actual constraint
//! count and proving time once run.
//!
//! # Why `amount`'s and `threshold`'s hash-preimage bytes are free
//!
//! Both `TransactionThresholdCircuit::allocate_range_checked` (for the
//! private `amount`) and this circuit's own public-value analogue (for
//! `threshold`) already decompose their value into `RANGE_BITS=64`
//! individual `Boolean` witnesses, least-significant-bit first — the
//! IDENTICAL convention `ark_r1cs_std::uint8::UInt8` uses internally for
//! each of its own 8 bits. Regrouping 64 already-allocated, already-
//! constrained bits into 8 `UInt8`s is therefore a purely mechanical
//! relabeling with no additional R1CS constraints — the expensive part is
//! entirely the SHA-256 gadget itself, not assembling its input.
//!
//! # What this circuit does NOT fix
//!
//! Only `banking-basel-iii` is bound this way so far. `healthcare-hipaa`
//! and `gov-supply-chain-integrity` still have the same unbound gap
//! `core/src/attest.rs`'s module docs describe — applying this same
//! pattern to them is real follow-up work, not done here, and would cost
//! considerably more for `gov-supply-chain-integrity` specifically (its
//! circuit is already the most expensive by a wide margin — see
//! `supply_chain_circuit.rs`'s own docs — and would need a THIRD set of
//! SHA-256 operations added on top of its existing hash chain).

use ark_bn254::Fr;
use ark_crypto_primitives::crh::sha256::constraints::{DigestVar, Sha256Gadget};
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::AllocVar,
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::circuit::{TransactionThresholdCircuit, RANGE_BITS};

/// Groups `RANGE_BITS` (64) LSB-first `Boolean`s, as produced by
/// `TransactionThresholdCircuit::allocate_range_checked`, into 8
/// little-endian `UInt8` bytes. See module docs: this costs nothing
/// extra in constraints, it's a relabeling of bits already allocated.
fn bits_to_le_bytes(bits: &[Boolean<Fr>]) -> Vec<UInt8<Fr>> {
    assert_eq!(bits.len(), RANGE_BITS);
    bits.chunks(8)
        .map(|chunk| UInt8::from_bits_le(chunk))
        .collect()
}

/// Same range-check technique as
/// `TransactionThresholdCircuit::allocate_range_checked`, but for a
/// PUBLIC value: each bit is its own public input (`new_input`, not
/// `new_witness`). `threshold` can't use `UInt8::constant` for its hash
/// bytes the way, say, a sequence number does in `supply_chain_circuit.rs`
/// -- unlike a position index, `threshold` genuinely varies per
/// attestation, so its value has to be part of what's supplied (and
/// checked) at verification time, not baked into the circuit's fixed
/// shape.
fn allocate_public_range_checked(
    cs: ConstraintSystemRef<Fr>,
    value: u64,
) -> Result<(FpVar<Fr>, Vec<Boolean<Fr>>), SynthesisError> {
    let mut bits = Vec::with_capacity(RANGE_BITS);
    for i in 0..RANGE_BITS {
        let bit_value = (value >> i) & 1 == 1;
        bits.push(Boolean::new_input(cs.clone(), || Ok(bit_value))?);
    }
    let reconstructed = Boolean::le_bits_to_fp_var(&bits)?;
    Ok((reconstructed, bits))
}

/// The circuit. `amount`/`customer_id_hash`/`salt` are `None` for the
/// setup-shape instance.
#[derive(Clone)]
pub struct BankingBoundCircuit {
    /// Public: `HashBasedScheme::commit`'s output for this exact input.
    pub commitment: [u8; 32],
    /// Public, bit-decomposed (see `allocate_public_range_checked`) —
    /// same value, same role as in `TransactionThresholdCircuit`.
    pub threshold: u64,
    pub amount: Option<u64>,
    pub customer_id_hash: Option<[u8; 32]>,
    /// The commitment's opening salt (`HashOpening::salt`) — private:
    /// nothing about a commitment's hiding property survives if its salt
    /// is public.
    pub salt: Option<[u8; 32]>,
}

impl BankingBoundCircuit {
    pub fn setup_shape(threshold: u64) -> Self {
        Self {
            commitment: [0u8; 32],
            threshold,
            amount: None,
            customer_id_hash: None,
            salt: None,
        }
    }

    pub fn with_witness(
        commitment: [u8; 32],
        threshold: u64,
        amount: u64,
        customer_id_hash: [u8; 32],
        salt: [u8; 32],
    ) -> Self {
        Self {
            commitment,
            threshold,
            amount: Some(amount),
            customer_id_hash: Some(customer_id_hash),
            salt: Some(salt),
        }
    }
}

impl ConstraintSynthesizer<Fr> for BankingBoundCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs, allocation order: commitment, then threshold's
        // 64 bits (see allocate_public_range_checked).
        let commitment_var = DigestVar::new_input(cs.clone(), || Ok(self.commitment.to_vec()))?;
        let (threshold_var, threshold_bits) =
            allocate_public_range_checked(cs.clone(), self.threshold)?;

        // IMPORTANT: same issue as healthcare_circuit.rs and
        // supply_chain_circuit.rs -- arkworks' Groth16::prove does not
        // check R1CS satisfiability itself. The predicate half of this
        // circuit gets "proving fails for a false claim" for free from
        // TransactionThresholdCircuit's range check (an out-of-range
        // amount has no valid bit decomposition to assign at all), but
        // the BINDING half does not: every byte of `salt`/
        // `customer_id_hash` is independently a valid witness regardless
        // of whether the resulting hash actually matches the claimed
        // `commitment`, so a mismatched commitment would otherwise
        // silently produce a real proof that simply fails verification
        // later, not a proving-time error. Checked explicitly here,
        // before allocating the binding witnesses, for the identical
        // reason and using the identical technique as the other two
        // circuits' documented AssignmentMissing short-circuit.
        let claim_holds = match (self.amount, self.customer_id_hash, self.salt) {
            (Some(amount), Some(cid), Some(salt)) => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(salt);
                hasher.update(amount.to_le_bytes());
                hasher.update(self.threshold.to_le_bytes());
                hasher.update(cid);
                let recomputed: [u8; 32] = hasher.finalize().into();
                Some(recomputed == self.commitment && amount <= self.threshold)
            }
            _ => None,
        };

        // Predicate: identical logic to TransactionThresholdCircuit,
        // except `self.amount` is replaced with `None` when `claim_holds
        // == Some(false)`, forcing the same AssignmentMissing path
        // TransactionThresholdCircuit already relies on for an
        // out-of-range amount -- covers a wrong-commitment claim even
        // when the amount/threshold relationship on its own would have
        // been fine.
        let gated_amount = match claim_holds {
            Some(false) => None,
            _ => self.amount,
        };
        let (amount_var, amount_bits) =
            TransactionThresholdCircuit::allocate_range_checked(cs.clone(), gated_amount)?;
        let diff_var = &threshold_var - &amount_var;
        let diff_value = match gated_amount {
            Some(amount) => self.threshold.checked_sub(amount),
            None => None,
        };
        let (diff_reconstructed, _diff_bits) =
            TransactionThresholdCircuit::allocate_range_checked(cs.clone(), diff_value)?;
        diff_reconstructed.enforce_equal(&diff_var)?;

        // Binding: recompute SHA256(salt || amount_LE(8) || threshold_LE(8)
        // || customer_id_hash(32)) and enforce it equals the public
        // commitment. Byte order here MUST exactly match
        // core::commitment::hash_based::HashBasedScheme::digest (salt
        // first) applied to
        // core::circuits::banking_basel_iii::TransactionThresholdRule::canonical_bytes
        // (amount, then threshold, then customer_id_hash) -- this is
        // checked directly by this file's own integration test, not just
        // asserted here.
        let gated_salt = match claim_holds {
            Some(false) => None,
            _ => self.salt,
        };
        let gated_cid = match claim_holds {
            Some(false) => None,
            _ => self.customer_id_hash,
        };
        let salt_bytes: Vec<UInt8<Fr>> = (0..32)
            .map(|i| {
                UInt8::new_witness(cs.clone(), || {
                    gated_salt
                        .map(|s| s[i])
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<_, _>>()?;
        let customer_id_bytes: Vec<UInt8<Fr>> = (0..32)
            .map(|i| {
                UInt8::new_witness(cs.clone(), || {
                    gated_cid
                        .map(|h| h[i])
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<_, _>>()?;

        let amount_bytes = bits_to_le_bytes(&amount_bits);
        let threshold_bytes = bits_to_le_bytes(&threshold_bits);

        let mut preimage = Vec::with_capacity(32 + 8 + 8 + 32);
        preimage.extend_from_slice(&salt_bytes);
        preimage.extend_from_slice(&amount_bytes);
        preimage.extend_from_slice(&threshold_bytes);
        preimage.extend_from_slice(&customer_id_bytes);

        let computed_commitment = Sha256Gadget::digest(&preimage)?;
        computed_commitment.enforce_equal(&commitment_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};

    fn real_commitment(salt: &[u8; 32], amount: u64, threshold: u64, cid: &[u8; 32]) -> [u8; 32] {
        // Deliberately re-derived from first principles here (matching
        // HashBasedScheme::digest and TransactionThresholdRule::canonical_bytes
        // by hand) rather than calling into `core`/`veritas-core` --
        // zk-poc/ has no dependency on core/ (core/ depends on zk-poc/,
        // not the other way around; see root Cargo.toml's workspace
        // graph), so this is an independent re-implementation used
        // specifically to catch a byte-layout mismatch between the two
        // crates, which a shared helper function could not catch.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(amount.to_le_bytes());
        hasher.update(threshold.to_le_bytes());
        hasher.update(cid);
        hasher.finalize().into()
    }

    fn is_satisfied(circuit: BankingBoundCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    /// For claims the Rust-side `claim_holds` pre-check rejects:
    /// `generate_constraints` itself returns `Err` (the deliberate
    /// `AssignmentMissing` short-circuit), not merely an unsatisfied
    /// constraint system -- see that function's own comments. Checked
    /// directly rather than via `is_satisfied()`, which would panic on
    /// the `unwrap()` inside it once `generate_constraints` starts
    /// erroring instead of completing.
    fn generation_fails(circuit: BankingBoundCircuit) -> bool {
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
        BankingBoundCircuit::setup_shape(1_000_00)
            .generate_constraints(cs.clone())
            .expect("setup-mode constraint generation should not require a witness");
        assert!(cs.num_constraints() > 0);
    }

    #[test]
    fn correct_commitment_and_valid_amount_is_satisfied() {
        let salt = [7u8; 32];
        let cid = [9u8; 32];
        let (amount, threshold) = (500_00u64, 1_000_00u64);
        let commitment = real_commitment(&salt, amount, threshold, &cid);
        let circuit = BankingBoundCircuit::with_witness(commitment, threshold, amount, cid, salt);
        assert!(is_satisfied(circuit));
    }

    #[test]
    fn wrong_commitment_cannot_be_proven() {
        // Real, valid predicate -- but a commitment that doesn't match
        // this exact (salt, amount, threshold, customer_id_hash).
        let salt = [7u8; 32];
        let cid = [9u8; 32];
        let (amount, threshold) = (500_00u64, 1_000_00u64);
        let wrong_commitment = [0xFFu8; 32];
        let circuit =
            BankingBoundCircuit::with_witness(wrong_commitment, threshold, amount, cid, salt);
        assert!(generation_fails(circuit));
    }

    #[test]
    fn commitment_to_a_different_amount_than_the_one_proven_cannot_be_proven() {
        // The exact attack this circuit exists to prevent: a commitment
        // that's real, and a predicate that's real, but about DIFFERENT
        // amounts.
        let salt = [7u8; 32];
        let cid = [9u8; 32];
        let threshold = 1_000_00u64;
        let committed_amount = 999_99u64; // what the commitment is really about
        let proven_amount = 1u64; // what the circuit is asked to prove
        let commitment = real_commitment(&salt, committed_amount, threshold, &cid);
        let circuit =
            BankingBoundCircuit::with_witness(commitment, threshold, proven_amount, cid, salt);
        assert!(
            generation_fails(circuit),
            "a proof must not be producible when the committed amount and the proven \
             amount differ, even if both individually look plausible"
        );
    }

    #[test]
    fn commitment_to_a_different_customer_id_hash_cannot_be_proven() {
        let salt = [7u8; 32];
        let (amount, threshold) = (500_00u64, 1_000_00u64);
        let committed_cid = [1u8; 32];
        let proven_cid = [2u8; 32];
        let commitment = real_commitment(&salt, amount, threshold, &committed_cid);
        let circuit =
            BankingBoundCircuit::with_witness(commitment, threshold, amount, proven_cid, salt);
        assert!(generation_fails(circuit));
    }
}
