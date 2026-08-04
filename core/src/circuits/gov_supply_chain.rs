//! Rule: "This audit log is complete and untampered for the stated
//! period." Per `compliance-mappings/gov-supply-chain-integrity.md`, this
//! is the candidate named as the most likely first module for that sector.
//! `component provenance` and `security-control compliance` from that
//! document are explicitly flagged research-level / narrower-scope-only
//! and are intentionally NOT implemented here.
//!
//! Scope reminder from that document (§ "Scope boundary"): this and any
//! rule module derived from it is limited to defensive integrity
//! verification only — see spec/THREAT_ANALYSIS.md §4.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Rule;
use crate::errors::{Result, VeritasError};

pub const RULE_ID: &str = "gov-supply-chain-integrity";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub sequence_number: u64,
    pub event_hash: [u8; 32],
    pub prev_entry_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailInput {
    pub period_start_unix: u64,
    pub period_end_unix: u64,
    pub entries: Vec<AuditLogEntry>,
    /// Hash chaining anchor: what `entries[0].prev_entry_hash` must equal.
    pub genesis_hash: [u8; 32],
}

pub struct AuditTrailIntegrityRule;

impl AuditTrailIntegrityRule {
    fn entry_linkage_hash(entry: &AuditLogEntry) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(entry.sequence_number.to_le_bytes());
        hasher.update(entry.event_hash);
        hasher.update(entry.prev_entry_hash);
        hasher.finalize().into()
    }
}

impl Rule for AuditTrailIntegrityRule {
    type Input = AuditTrailInput;
    const RULE_ID: &'static str = RULE_ID;

    fn check(input: &Self::Input) -> Result<()> {
        if input.period_start_unix >= input.period_end_unix {
            return Err(VeritasError::RuleViolation(format!(
                "{}: period_start_unix must precede period_end_unix",
                RULE_ID
            )));
        }
        if input.entries.is_empty() {
            return Err(VeritasError::RuleViolation(format!(
                "{}: empty audit trail for a non-empty period is not attestable as complete",
                RULE_ID
            )));
        }

        let mut expected_prev = input.genesis_hash;
        for (i, entry) in input.entries.iter().enumerate() {
            if entry.sequence_number != i as u64 {
                return Err(VeritasError::RuleViolation(format!(
                    "{}: gap or reorder in sequence at index {} (got sequence_number {})",
                    RULE_ID, i, entry.sequence_number
                )));
            }
            if entry.prev_entry_hash != expected_prev {
                return Err(VeritasError::RuleViolation(format!(
                    "{}: chain break at sequence {} (tampering or missing entry)",
                    RULE_ID, entry.sequence_number
                )));
            }
            expected_prev = Self::entry_linkage_hash(entry);
        }
        Ok(())
    }

    fn canonical_bytes(input: &Self::Input) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&input.period_start_unix.to_le_bytes());
        buf.extend_from_slice(&input.period_end_unix.to_le_bytes());
        buf.extend_from_slice(&input.genesis_hash);
        buf.extend_from_slice(&(input.entries.len() as u64).to_le_bytes());
        for e in &input.entries {
            buf.extend_from_slice(&e.sequence_number.to_le_bytes());
            buf.extend_from_slice(&e.event_hash);
            buf.extend_from_slice(&e.prev_entry_hash);
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(s: &str) -> [u8; 32] {
        Sha256::digest(s.as_bytes()).into()
    }

    fn chain(events: &[&str], genesis: [u8; 32]) -> Vec<AuditLogEntry> {
        let mut prev = genesis;
        let mut out = Vec::new();
        for (i, e) in events.iter().enumerate() {
            let entry = AuditLogEntry {
                sequence_number: i as u64,
                event_hash: ev(e),
                prev_entry_hash: prev,
            };
            prev = AuditTrailIntegrityRule::entry_linkage_hash(&entry);
            out.push(entry);
        }
        out
    }

    #[test]
    fn intact_chain_passes() {
        let genesis = ev("genesis");
        let input = AuditTrailInput {
            period_start_unix: 0,
            period_end_unix: 1000,
            entries: chain(&["a", "b", "c"], genesis),
            genesis_hash: genesis,
        };
        assert!(AuditTrailIntegrityRule::check(&input).is_ok());
    }

    #[test]
    fn tampered_middle_entry_breaks_chain() {
        let genesis = ev("genesis");
        let mut entries = chain(&["a", "b", "c"], genesis);
        entries[1].event_hash = ev("tampered");
        let input = AuditTrailInput {
            period_start_unix: 0,
            period_end_unix: 1000,
            entries,
            genesis_hash: genesis,
        };
        assert!(AuditTrailIntegrityRule::check(&input).is_err());
    }

    #[test]
    fn missing_entry_breaks_sequence() {
        let genesis = ev("genesis");
        let mut entries = chain(&["a", "b", "c"], genesis);
        entries.remove(1);
        let input = AuditTrailInput {
            period_start_unix: 0,
            period_end_unix: 1000,
            entries,
            genesis_hash: genesis,
        };
        assert!(AuditTrailIntegrityRule::check(&input).is_err());
    }
}
