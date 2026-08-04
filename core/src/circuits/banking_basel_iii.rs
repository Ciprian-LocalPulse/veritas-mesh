//! Rule: "Transaction amount did not exceed customer's risk-adjusted
//! threshold." Per `compliance-mappings/banking-basel-iii.md`, this is the
//! one candidate rule flagged as tractable near-term and named as the
//! Phase 2 target — so it's the one implemented here. The other candidates
//! in that document (structuring detection, capital adequacy ratio,
//! liquidity coverage ratio) are explicitly flagged there as research-level
//! and are NOT implemented — don't add them here without re-reading that
//! doc's tractability assessment.

use serde::{Deserialize, Serialize};

use super::Rule;
use crate::errors::{Result, VeritasError};

pub const RULE_ID: &str = "banking-basel-iii";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionThresholdInput {
    /// Amount in minor currency units (e.g. cents) to avoid float issues.
    pub transaction_amount_minor: u64,
    /// Customer's risk-adjusted threshold, same units.
    pub risk_adjusted_threshold_minor: u64,
    /// Opaque customer identifier (never included in `canonical_bytes` in
    /// cleartext form beyond this hash, to avoid leaking it if this struct
    /// is ever logged — but note the whole struct is still the *witness*,
    /// not something a real ZK circuit would output).
    pub customer_id_hash: [u8; 32],
}

pub struct TransactionThresholdRule;

impl Rule for TransactionThresholdRule {
    type Input = TransactionThresholdInput;
    const RULE_ID: &'static str = RULE_ID;

    fn check(input: &Self::Input) -> Result<()> {
        if input.transaction_amount_minor <= input.risk_adjusted_threshold_minor {
            Ok(())
        } else {
            Err(VeritasError::RuleViolation(format!(
                "{}: transaction_amount_minor {} exceeds risk_adjusted_threshold_minor {}",
                RULE_ID, input.transaction_amount_minor, input.risk_adjusted_threshold_minor
            )))
        }
    }

    fn canonical_bytes(input: &Self::Input) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 8 + 32);
        buf.extend_from_slice(&input.transaction_amount_minor.to_le_bytes());
        buf.extend_from_slice(&input.risk_adjusted_threshold_minor.to_le_bytes());
        buf.extend_from_slice(&input.customer_id_hash);
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

    #[test]
    fn under_threshold_passes() {
        let input = TransactionThresholdInput {
            transaction_amount_minor: 500_00,
            risk_adjusted_threshold_minor: 1_000_00,
            customer_id_hash: hash("customer-1"),
        };
        assert!(TransactionThresholdRule::check(&input).is_ok());
    }

    #[test]
    fn exactly_at_threshold_passes() {
        let input = TransactionThresholdInput {
            transaction_amount_minor: 1_000_00,
            risk_adjusted_threshold_minor: 1_000_00,
            customer_id_hash: hash("customer-1"),
        };
        assert!(TransactionThresholdRule::check(&input).is_ok());
    }

    #[test]
    fn over_threshold_fails() {
        let input = TransactionThresholdInput {
            transaction_amount_minor: 1_000_01,
            risk_adjusted_threshold_minor: 1_000_00,
            customer_id_hash: hash("customer-1"),
        };
        assert!(TransactionThresholdRule::check(&input).is_err());
    }

    #[test]
    fn canonical_bytes_is_deterministic() {
        let input = TransactionThresholdInput {
            transaction_amount_minor: 42,
            risk_adjusted_threshold_minor: 100,
            customer_id_hash: hash("customer-1"),
        };
        assert_eq!(
            TransactionThresholdRule::canonical_bytes(&input),
            TransactionThresholdRule::canonical_bytes(&input.clone())
        );
    }
}
