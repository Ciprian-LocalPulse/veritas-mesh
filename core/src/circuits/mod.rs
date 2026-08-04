//! One file per compliance rule, mirroring `compliance-mappings/*.md`.
//!
//! IMPORTANT: these are *predicate evaluators*, not arithmetic circuits.
//! `Rule::check` runs in the clear over a typed input struct and returns
//! pass/fail. That is real, useful logic — the compliance mapping from the
//! `.md` doc to actual code exists and is testable (see
//! `compliance-mappings/*.testvectors.json`). What's missing for
//! zero-knowledge is re-expressing each `check` body as constraints inside
//! whatever DSL the RFC-0002 proof system uses (`ark-relations` for
//! Groth16, an `Air` impl for winterfell) so the *evaluation itself* never
//! touches an untrusted verifier. Until that happens, treat
//! `ToyAttestationBuilder` (in this module) as "signed self-report," not
//! "zero-knowledge proof of compliance."

pub mod banking_basel_iii;
pub mod gov_supply_chain;
pub mod healthcare_hipaa;

use crate::errors::Result;

/// Implemented once per rule in `compliance-mappings/`.
pub trait Rule {
    type Input;

    /// Stable identifier, must match the `rule_id` used in
    /// `compliance-mappings/<id>.md` and `Attestation::rule_id`.
    const RULE_ID: &'static str;

    /// Evaluate the predicate. Returns Ok(()) if compliant,
    /// Err(RuleViolation) with a human-readable reason otherwise.
    fn check(input: &Self::Input) -> Result<()>;

    /// Canonical byte encoding of the input, fed to the commitment scheme.
    /// MUST be a pure function of `input` (no timestamps, no randomness) or
    /// two provers with identical facts will get non-comparable commitments
    /// for reasons unrelated to hiding.
    fn canonical_bytes(input: &Self::Input) -> Vec<u8>;
}
