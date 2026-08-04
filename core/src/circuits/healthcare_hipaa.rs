//! Rule: "All disclosures of this record were logged and each logged
//! access was authorized." Per `compliance-mappings/healthcare-hipaa.md`,
//! this is the candidate flagged "plausibly tractable" and named as the
//! most likely Phase 2 healthcare candidate — implemented here for that
//! reason. `minimum-necessary access` and `de-identification adequacy`
//! from that document are explicitly flagged research-level / uncertain
//! and are intentionally NOT implemented.

use serde::{Deserialize, Serialize};

use super::Rule;
use crate::errors::{Result, VeritasError};

pub const RULE_ID: &str = "healthcare-hipaa";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureLogEntry {
    pub accessor_id_hash: [u8; 32],
    pub authorized: bool,
    pub timestamp_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureLogInput {
    pub record_id_hash: [u8; 32],
    /// Every access event the prover claims occurred for this record.
    pub log_entries: Vec<DisclosureLogEntry>,
    /// The set of accesses independently observed (e.g. by an access-control
    /// system) for the same record and period — used to check completeness
    /// (no unlogged access happened). In a real circuit this would be a
    /// Merkle-root comparison rather than an inline `Vec`.
    pub observed_access_count: u64,
}

pub struct DisclosureLoggingRule;

impl Rule for DisclosureLoggingRule {
    type Input = DisclosureLogInput;
    const RULE_ID: &'static str = RULE_ID;

    fn check(input: &Self::Input) -> Result<()> {
        // 1. Completeness: every observed access has a corresponding log entry.
        if input.log_entries.len() as u64 != input.observed_access_count {
            return Err(VeritasError::RuleViolation(format!(
                "{}: {} log entries but {} observed accesses (mismatch => unlogged or phantom access)",
                RULE_ID,
                input.log_entries.len(),
                input.observed_access_count
            )));
        }
        // 2. Every logged access was authorized.
        if let Some(bad) = input.log_entries.iter().find(|e| !e.authorized) {
            return Err(VeritasError::RuleViolation(format!(
                "{}: unauthorized access logged at timestamp {}",
                RULE_ID, bad.timestamp_unix
            )));
        }
        Ok(())
    }

    fn canonical_bytes(input: &Self::Input) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&input.record_id_hash);
        buf.extend_from_slice(&input.observed_access_count.to_le_bytes());
        buf.extend_from_slice(&(input.log_entries.len() as u64).to_le_bytes());
        for e in &input.log_entries {
            buf.extend_from_slice(&e.accessor_id_hash);
            buf.push(e.authorized as u8);
            buf.extend_from_slice(&e.timestamp_unix.to_le_bytes());
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(s: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(s.as_bytes()).into()
    }

    fn entry(who: &str, authorized: bool, ts: u64) -> DisclosureLogEntry {
        DisclosureLogEntry {
            accessor_id_hash: hash(who),
            authorized,
            timestamp_unix: ts,
        }
    }

    #[test]
    fn complete_and_authorized_passes() {
        let input = DisclosureLogInput {
            record_id_hash: hash("record-1"),
            log_entries: vec![entry("nurse-a", true, 1), entry("dr-b", true, 2)],
            observed_access_count: 2,
        };
        assert!(DisclosureLoggingRule::check(&input).is_ok());
    }

    #[test]
    fn unlogged_access_fails() {
        let input = DisclosureLogInput {
            record_id_hash: hash("record-1"),
            log_entries: vec![entry("nurse-a", true, 1)],
            observed_access_count: 2, // one access happened but wasn't logged
        };
        assert!(DisclosureLoggingRule::check(&input).is_err());
    }

    #[test]
    fn unauthorized_logged_access_fails() {
        let input = DisclosureLogInput {
            record_id_hash: hash("record-1"),
            log_entries: vec![entry("nurse-a", true, 1), entry("intruder", false, 2)],
            observed_access_count: 2,
        };
        assert!(DisclosureLoggingRule::check(&input).is_err());
    }
}
