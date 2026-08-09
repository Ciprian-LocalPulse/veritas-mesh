//! `attest()`: the first real orchestration layer combining everything
//! else in this crate into one `Attestation`.
//!
//! Every other module in `core/` has, until now, been a piece someone
//! calling it by hand had to assemble themselves: check the predicate
//! (`circuits::Rule::check`), commit to the input
//! (`commitment::hash_based::HashBasedScheme`), prove it in zero-knowledge
//! (`proof::groth16_bn254`), sign the result (`signature::Keypair`). This
//! module is the thing that actually does all four steps, in the right
//! order, for a real caller — closing the gap `zk-poc/README.md`'s "what's
//! still needed" item 7 has been flagging since the healthcare circuit
//! landed: "no orchestration layer combining 'commit to everything, prove
//! the circuit-relevant subset in ZK' into one attestation-building call
//! exists yet."
//!
//! # Why one function per rule, again
//!
//! Same reasoning as `proof::groth16_bn254`'s three separate backend
//! structs: each rule's `Input` type, ZK circuit, and witness/public-input
//! shape are all different, and there is still no crate-wide `rule_id`
//! dispatch mechanism anywhere in `core/`. `attest_banking`,
//! `attest_healthcare`, and `attest_supply_chain` below are the natural
//! continuation of that same pattern one layer up, not a new design
//! choice.
//!
//! # What gets committed vs. what gets proven — made concrete, not just documented
//!
//! `proof::groth16_bn254`'s module docs already explain, in the abstract,
//! that a Groth16 proof here only covers the fields each circuit actually
//! constrains (e.g. `TransactionThresholdInput::customer_id_hash` is
//! outside `TransactionThresholdCircuit`). This module is where that
//! distinction becomes real code: `input_commitment` below is always
//! computed over `Rule::canonical_bytes(&input)` — the FULL input, every
//! field — via `HashBasedScheme` (the only real, non-placeholder
//! commitment scheme today; see `commitment::pedersen`'s own docs for why
//! that one still falls back to hash-based internally). The ZK proof is
//! separately computed over only the subset of fields each circuit's
//! `EntryWitness`/wire types actually use. An attestation therefore
//! contains two independent claims about the same input: "the full input
//! hashes to this commitment" (real, checkable once opened) and "the
//! circuit-relevant subset of that input satisfies the rule in
//! zero-knowledge" (real, checkable via `ProofSystem::verify`) — but nothing
//! here proves those two claims are about the SAME underlying input beyond
//! the caller passing the same `input` value to both steps in the same
//! function call. A malicious prover controlling this code path could
//! commit to one input and prove a *different* one's ZK statement; that is
//! not prevented by anything in this file or elsewhere in this crate today
//! (binding the commitment into the circuit's public inputs, so the SNARK
//! itself enforces the connection, is real follow-up work, not yet done
//! anywhere in `zk-poc/`). Stated here plainly because implying otherwise
//! by omission would be exactly the kind of overclaim this project's own
//! documentation discipline exists to prevent.
//!
//! # What the caller gets back
//!
//! `(Attestation, HashOpening)` — the opening is deliberately NOT embedded
//! in the `Attestation` (it would defeat the commitment's hiding property
//! if it were published alongside it). The caller is responsible for
//! keeping it, to later prove to a specific counterparty (not every
//! Verifier) exactly what the committed input was, via
//! `commitment::hash_based::HashBasedScheme::verify`. There is no
//! selective-disclosure protocol built on top of this in `core/` yet —
//! that opening is a bare, ordinary `HashOpening`, not integrated into
//! any larger disclosure workflow.

use crate::attestation::{Attestation, SCHEMA_VERSION};
use crate::circuits::banking_basel_iii::{TransactionThresholdInput, TransactionThresholdRule};
use crate::circuits::gov_supply_chain::{AuditTrailInput, AuditTrailIntegrityRule};
use crate::circuits::healthcare_hipaa::{DisclosureLogInput, DisclosureLoggingRule};
use crate::circuits::Rule;
use crate::commitment::hash_based::{HashBasedScheme, HashOpening};
use crate::commitment::CommitmentScheme;
use crate::errors::Result;
use crate::proof::groth16_bn254::{
    BankingGroth16Backend, BankingPublicInput, BankingWitness, ChainEntryWire,
    HealthcareEntryWire, HealthcareGroth16Backend, HealthcarePublicInput, HealthcareWitness,
    SupplyChainGroth16Backend, SupplyChainPublicInput, SupplyChainWitness,
};
use crate::proof::{ProofSystem, ProofSystemId};
use crate::signature::Keypair;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs()
}

/// Runs `TransactionThresholdRule::check` (in the clear, fails fast on an
/// obviously-false claim before ever touching the expensive ZK path),
/// commits to the full `input` via `HashBasedScheme`, proves
/// `transaction_amount_minor <= risk_adjusted_threshold_minor` in
/// zero-knowledge via `backend`, and signs the result with `keypair`.
///
/// The `check()` call is a real, separate gate, not decoration: the
/// commitment and signature below would happily complete for ANY input
/// (they don't know or care about the rule's semantics), so without it, a
/// caller could accidentally produce a validly-signed, validly-committed
/// `Attestation` whose ZK proof step later fails for the right reason
/// (the claim was false) but only after paying the ~9ms Groth16 proving
/// cost — `check()` catches that immediately instead, at the cost of
/// evaluating the same predicate the circuit evaluates, once, in the
/// clear, before doing it again in zero-knowledge.
pub fn attest_banking(
    input: &TransactionThresholdInput,
    backend: &BankingGroth16Backend,
    keypair: &Keypair,
) -> Result<(Attestation, HashOpening)> {
    TransactionThresholdRule::check(input)?;

    let canonical = TransactionThresholdRule::canonical_bytes(input);
    let scheme = HashBasedScheme;
    let (commitment, opening) = scheme.commit(&canonical);

    let witness = serde_json::to_vec(&BankingWitness {
        transaction_amount_minor: input.transaction_amount_minor,
    })?;
    let public_input = serde_json::to_vec(&BankingPublicInput {
        risk_adjusted_threshold_minor: input.risk_adjusted_threshold_minor,
    })?;
    let proof = backend.prove(&witness, &public_input)?;

    let unsigned = Attestation {
        schema_version: SCHEMA_VERSION,
        rule_id: TransactionThresholdRule::RULE_ID.to_string(),
        proof_system: ProofSystemId::Groth16Bn254,
        input_commitment: commitment.0.to_vec(),
        proof,
        prover_public_key: [0u8; 32], // overwritten by sign_attestation below
        signature: [0u8; 64],         // overwritten by sign_attestation below
        issued_at_unix: now_unix(),
    };
    Ok((keypair.sign_attestation(unsigned), opening))
}

/// Same shape as [`attest_banking`], for `healthcare-hipaa`. Every
/// `log_entries` item is treated as a real (active) entry — this function
/// does not accept a shorter list plus a separate padding count; the
/// backend's own `HealthcareGroth16Backend::prove` handles padding up to
/// `healthcare_circuit::MAX_ENTRIES` internally. Returns an error (not
/// panics) if `log_entries.len() > MAX_ENTRIES`, via that same backend
/// call — this function adds no additional capacity check of its own.
pub fn attest_healthcare(
    input: &DisclosureLogInput,
    backend: &HealthcareGroth16Backend,
    keypair: &Keypair,
) -> Result<(Attestation, HashOpening)> {
    DisclosureLoggingRule::check(input)?;

    let canonical = DisclosureLoggingRule::canonical_bytes(input);
    let scheme = HashBasedScheme;
    let (commitment, opening) = scheme.commit(&canonical);

    let entries: Vec<HealthcareEntryWire> = input
        .log_entries
        .iter()
        .map(|e| HealthcareEntryWire {
            is_active: true,
            authorized: e.authorized,
        })
        .collect();
    let witness = serde_json::to_vec(&HealthcareWitness { entries })?;
    let public_input = serde_json::to_vec(&HealthcarePublicInput {
        record_id_hash: input.record_id_hash,
        observed_access_count: input.observed_access_count,
    })?;
    let proof = backend.prove(&witness, &public_input)?;

    let unsigned = Attestation {
        schema_version: SCHEMA_VERSION,
        rule_id: DisclosureLoggingRule::RULE_ID.to_string(),
        proof_system: ProofSystemId::Groth16Bn254,
        input_commitment: commitment.0.to_vec(),
        proof,
        prover_public_key: [0u8; 32],
        signature: [0u8; 64],
        issued_at_unix: now_unix(),
    };
    Ok((keypair.sign_attestation(unsigned), opening))
}

/// Same shape as [`attest_banking`], for `gov-supply-chain-integrity`.
///
/// Unlike the other two, this one has to compute a value the `Input`
/// struct doesn't carry at all: `final_linkage_hash`, the public claim
/// `SupplyChainIntegrityCircuit` proves the chain actually reaches (see
/// that circuit's own module docs for why this has to be a public input,
/// not left implicit). Computed here via
/// `zk_poc::supply_chain_circuit::entry_linkage_hash`, walking
/// `input.entries` exactly the way
/// `AuditTrailIntegrityRule::check`/`entry_linkage_hash` already does in
/// the clear — this function does not re-derive that logic independently,
/// it calls the same real function `zk-poc/`'s own circuit and tests use,
/// so there is exactly one implementation of "what a linkage hash is" in
/// this codebase, not two that could silently drift apart.
pub fn attest_supply_chain(
    input: &AuditTrailInput,
    backend: &SupplyChainGroth16Backend,
    keypair: &Keypair,
) -> Result<(Attestation, HashOpening)> {
    AuditTrailIntegrityRule::check(input)?;

    let canonical = AuditTrailIntegrityRule::canonical_bytes(input);
    let scheme = HashBasedScheme;
    let (commitment, opening) = scheme.commit(&canonical);

    let mut running = input.genesis_hash;
    for (i, entry) in input.entries.iter().enumerate() {
        running = veritas_zk_poc::supply_chain_circuit::entry_linkage_hash(
            i as u64,
            &entry.event_hash,
            &running,
        );
    }
    let final_linkage_hash = running;

    let entries: Vec<ChainEntryWire> = input
        .entries
        .iter()
        .map(|e| ChainEntryWire {
            event_hash: e.event_hash,
            is_active: true,
        })
        .collect();
    let witness = serde_json::to_vec(&SupplyChainWitness { entries })?;
    let public_input = serde_json::to_vec(&SupplyChainPublicInput {
        genesis_hash: input.genesis_hash,
        final_linkage_hash,
        active_count: input.entries.len() as u64,
    })?;
    let proof = backend.prove(&witness, &public_input)?;

    let unsigned = Attestation {
        schema_version: SCHEMA_VERSION,
        rule_id: AuditTrailIntegrityRule::RULE_ID.to_string(),
        proof_system: ProofSystemId::Groth16Bn254,
        input_commitment: commitment.0.to_vec(),
        proof,
        prover_public_key: [0u8; 32],
        signature: [0u8; 64],
        issued_at_unix: now_unix(),
    };
    Ok((keypair.sign_attestation(unsigned), opening))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::gov_supply_chain::AuditLogEntry;
    use crate::circuits::healthcare_hipaa::DisclosureLogEntry;
    use crate::signature::verify_attestation;

    const SETUP_SEED: u64 = 42;

    #[test]
    fn attest_banking_produces_a_verifiable_attestation() {
        let backend = BankingGroth16Backend::setup(SETUP_SEED).unwrap();
        let keypair = Keypair::generate();
        let input = TransactionThresholdInput {
            transaction_amount_minor: 50_000,
            risk_adjusted_threshold_minor: 100_000,
            customer_id_hash: [1u8; 32],
        };

        let (attestation, opening) = attest_banking(&input, &backend, &keypair)
            .expect("attest_banking should succeed for a genuinely compliant input");

        // Every real piece is actually checkable, independently, exactly
        // as a real Verifier would: signature, then ZK proof, then (if
        // this Verifier is also the counterparty entitled to the
        // opening) the commitment.
        verify_attestation(&attestation).expect("signature must verify");
        backend
            .verify(
                &attestation.proof,
                &serde_json::to_vec(&BankingPublicInput {
                    risk_adjusted_threshold_minor: input.risk_adjusted_threshold_minor,
                })
                .unwrap(),
            )
            .expect("ZK proof must verify");

        let scheme = HashBasedScheme;
        let canonical = TransactionThresholdRule::canonical_bytes(&input);
        let commitment = crate::commitment::hash_based::HashCommitment(
            attestation.input_commitment.clone().try_into().unwrap(),
        );
        scheme
            .verify(&commitment, &opening, &canonical)
            .expect("commitment must open to the real input");

        assert_eq!(attestation.rule_id, "banking-basel-iii");
        assert_eq!(attestation.proof_system, ProofSystemId::Groth16Bn254);
    }

    #[test]
    fn attest_banking_rejects_a_false_claim_before_any_zk_work() {
        let backend = BankingGroth16Backend::setup(SETUP_SEED).unwrap();
        let keypair = Keypair::generate();
        let input = TransactionThresholdInput {
            transaction_amount_minor: 200_000, // > threshold
            risk_adjusted_threshold_minor: 100_000,
            customer_id_hash: [1u8; 32],
        };
        let result = attest_banking(&input, &backend, &keypair);
        assert!(
            result.is_err(),
            "attest_banking must reject a claim TransactionThresholdRule::check itself rejects"
        );
    }

    #[test]
    fn attest_healthcare_produces_a_verifiable_attestation() {
        let backend = HealthcareGroth16Backend::setup(SETUP_SEED).unwrap();
        let keypair = Keypair::generate();
        let input = DisclosureLogInput {
            record_id_hash: [2u8; 32],
            log_entries: vec![
                DisclosureLogEntry {
                    accessor_id_hash: [3u8; 32],
                    authorized: true,
                    timestamp_unix: 1_700_000_000,
                },
                DisclosureLogEntry {
                    accessor_id_hash: [4u8; 32],
                    authorized: true,
                    timestamp_unix: 1_700_000_100,
                },
            ],
            observed_access_count: 2,
        };

        let (attestation, _opening) = attest_healthcare(&input, &backend, &keypair)
            .expect("attest_healthcare should succeed for a genuinely compliant input");
        verify_attestation(&attestation).expect("signature must verify");
        backend
            .verify(
                &attestation.proof,
                &serde_json::to_vec(&HealthcarePublicInput {
                    record_id_hash: input.record_id_hash,
                    observed_access_count: input.observed_access_count,
                })
                .unwrap(),
            )
            .expect("ZK proof must verify");
    }

    #[test]
    fn attest_supply_chain_produces_a_verifiable_attestation() {
        let backend = SupplyChainGroth16Backend::setup(SETUP_SEED).unwrap();
        let keypair = Keypair::generate();
        let genesis = [5u8; 32];
        let event_hash_0 = [6u8; 32];
        let event_hash_1 = [7u8; 32];
        let input = AuditTrailInput {
            period_start_unix: 1_700_000_000,
            period_end_unix: 1_700_086_400,
            genesis_hash: genesis,
            entries: vec![
                AuditLogEntry {
                    sequence_number: 0,
                    event_hash: event_hash_0,
                    prev_entry_hash: genesis,
                },
                AuditLogEntry {
                    sequence_number: 1,
                    event_hash: event_hash_1,
                    prev_entry_hash: veritas_zk_poc::supply_chain_circuit::entry_linkage_hash(
                        0,
                        &event_hash_0,
                        &genesis,
                    ),
                },
            ],
        };

        let (attestation, _opening) = attest_supply_chain(&input, &backend, &keypair)
            .expect("attest_supply_chain should succeed for a genuinely intact chain");
        verify_attestation(&attestation).expect("signature must verify");

        let final_linkage_hash = veritas_zk_poc::supply_chain_circuit::entry_linkage_hash(
            1,
            &event_hash_1,
            &veritas_zk_poc::supply_chain_circuit::entry_linkage_hash(0, &event_hash_0, &genesis),
        );
        backend
            .verify(
                &attestation.proof,
                &serde_json::to_vec(&SupplyChainPublicInput {
                    genesis_hash: genesis,
                    final_linkage_hash,
                    active_count: 2,
                })
                .unwrap(),
            )
            .expect("ZK proof must verify");
    }
}
