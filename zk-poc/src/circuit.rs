//! `TransactionThresholdCircuit`: a REAL R1CS arithmetic circuit proving
//! `amount <= threshold` in zero-knowledge, over the BN254 scalar field.
//!
//! This is the circuit `core/src/circuits/banking_basel_iii.rs`'s module
//! docs said didn't exist yet. It replaces the "prove = sign a hash of the
//! witness" placeholder in `core/src/proof/groth16.rs` for exactly one
//! rule, as a proof of concept that the placeholder's interface shape is
//! actually buildable against.
//!
//! # Why this needs bit decomposition, not just `threshold - amount >= 0`
//!
//! Field arithmetic wraps around modulo a large prime `p` (~2^254 for
//! BN254's scalar field). There is no native "is this field element
//! negative" operation -- every field element is technically "positive"
//! in [0, p). If we naively encoded the constraint as a single equation
//! like `threshold - amount = diff` with no further checks, a dishonest
//! prover could pick `amount` to be an enormous field element close to
//! `p` (not a real transaction amount at all) such that
//! `threshold - amount mod p` still lands on some small "plausible"
//! `diff`, because subtraction wraps around. That would let a prover
//! "satisfy" the circuit for a transaction amount that was never a real
//! 64-bit integer.
//!
//! The fix (standard in R1CS-based systems, used for the same reason in
//! e.g. Zcash's Sapling circuit) is to constrain BOTH `amount` and
//! `diff = threshold - amount` to be representable in exactly 64 bits:
//! allocate 64 boolean witnesses per value, and constrain their weighted
//! sum (`sum(bit_i * 2^i)`) to equal the value. Since 2^64 is astronomically
//! smaller than the ~2^254 field modulus, a value that only satisfies this
//! reconstruction for a *wrapped-around* representation would need `diff`
//! or `amount` to itself be enormous (close to `p`) -- which the 64-bit
//! decomposition makes impossible to satisfy. This is what actually makes
//! the proof mean "a real 64-bit amount did not exceed a real 64-bit
//! threshold," not just "some equation over a finite field held."
//!
//! `threshold` is a PUBLIC input (the verifier plugs in the exact value
//! they're checking against, so it needs no range check -- forging it
//! would just mean checking against a different, but still exact, number).
//! `amount` is the PRIVATE witness -- this is the whole point: the
//! verifier never learns it.

use ark_bn254::Fr;
use ark_r1cs_std::{
    boolean::Boolean,
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Number of bits each value is range-checked to. 64 bits comfortably
/// covers real-world minor-currency-unit amounts (u64::MAX minor units is
/// ~1.8*10^17 in whatever currency's smallest unit -- billions of times
/// larger than any real transaction) while being astronomically smaller
/// than the ~254-bit field modulus, which is exactly the safety margin
/// the module doc above depends on.
pub const RANGE_BITS: usize = 64;

/// The circuit. `amount` is `None` when only the shape is needed (e.g.
/// during trusted setup, which must not depend on witness values) and
/// `Some(value)` when actually proving.
#[derive(Clone)]
pub struct TransactionThresholdCircuit {
    pub amount: Option<u64>,
    /// Public: known to both prover and verifier.
    pub threshold: u64,
}

impl TransactionThresholdCircuit {
    /// Shape-only instance for trusted setup -- setup must work without
    /// ever seeing a real witness value.
    pub fn setup_shape(threshold: u64) -> Self {
        Self {
            amount: None,
            threshold,
        }
    }

    pub fn with_witness(amount: u64, threshold: u64) -> Self {
        Self {
            amount: Some(amount),
            threshold,
        }
    }

    /// Decompose `value` into `RANGE_BITS` little-endian booleans, as
    /// R1CS witnesses, and return both the bits and an `FpVar`
    /// reconstructed from them (with the reconstruction constrained equal
    /// to the sum -- see module docs for why this is the actual range
    /// check, not just decoration).
    /// `pub(crate)` (not private) specifically so
    /// `bound_circuit.rs`'s `BankingBoundCircuit` can reuse the exact
    /// same range-check logic and, critically, the exact same
    /// LSB-first bit ordering — that ordering is what lets the bound
    /// circuit regroup these bits directly into `UInt8` bytes for its
    /// SHA-256 preimage with zero additional constraints (`UInt8` uses
    /// the identical LSB-first-per-byte convention internally). See
    /// `bound_circuit.rs`'s own module docs for why that reuse matters.
    pub(crate) fn allocate_range_checked(
        cs: ConstraintSystemRef<Fr>,
        value: Option<u64>,
    ) -> Result<(FpVar<Fr>, Vec<Boolean<Fr>>), SynthesisError> {
        let mut bits = Vec::with_capacity(RANGE_BITS);
        for i in 0..RANGE_BITS {
            let bit_value = value.map(|v| (v >> i) & 1 == 1);
            // Boolean::new_witness itself adds the b*(1-b)=0 constraint
            // that forces this witness to be exactly 0 or 1 -- that's
            // what makes this a real boolean, not just a hint.
            bits.push(Boolean::new_witness(cs.clone(), || {
                bit_value.ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        // Reconstructs sum(bit_i * 2^i) as a linear combination -- free
        // in R1CS (no multiplication gate needed, it's degree 1), but the
        // equality check below against `reconstructed` is what actually
        // ties this decomposition back to the value being proven about.
        let reconstructed = Boolean::le_bits_to_fp_var(&bits)?;
        Ok((reconstructed, bits))
    }
}

impl ConstraintSynthesizer<Fr> for TransactionThresholdCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // threshold: PUBLIC input. The verifier supplies this value
        // directly at verification time -- see `verify()` in lib.rs.
        let threshold_var = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.threshold)))?;

        // amount: PRIVATE witness, range-checked to RANGE_BITS.
        let (amount_var, _amount_bits) = Self::allocate_range_checked(cs.clone(), self.amount)?;

        // diff = threshold - amount. This subtraction itself is a free
        // linear operation; what makes it meaningful is the range check
        // on the RESULT below.
        let diff_var = &threshold_var - &amount_var;

        // Range-check diff into RANGE_BITS bits. If amount > threshold,
        // diff (mod p) would be an enormous field element close to p --
        // seeIt could NOT be decomposed into RANGE_BITS=64 bits with a
        // valid witness assignment satisfying the reconstruction equality
        // below, because no combination of 64 booleans can sum to a
        // ~254-bit number. That unsatisfiability IS the proof that
        // amount <= threshold.
        let diff_bits: Vec<Boolean<Fr>> = (0..RANGE_BITS)
            .map(|i| {
                // The circuit doesn't have direct access to the u64
                // value of diff (it's an abstract field element at
                // constraint-generation time for the prover's real run);
                // instead we derive the diff's bit witness values from
                // the same source data (self.amount/self.threshold) the
                // prover already knows, and let the equality constraint
                // below enforce that this matches the actual diff_var.
                let bit_value = match self.amount {
                    Some(amount) if amount <= self.threshold => {
                        let diff = self.threshold - amount;
                        Some((diff >> i) & 1 == 1)
                    }
                    Some(_) => None, // amount > threshold: no valid witness exists, by design
                    None => None,    // setup-shape mode: no witness at all
                };
                Boolean::new_witness(cs.clone(), || {
                    bit_value.ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<_, _>>()?;
        let diff_reconstructed = Boolean::le_bits_to_fp_var(&diff_bits)?;

        diff_reconstructed.enforce_equal(&diff_var)?;

        Ok(())
    }
}
