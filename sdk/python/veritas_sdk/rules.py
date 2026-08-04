"""Rule predicate checks, hand-mirrored from core/src/circuits/*.rs.

Only the banking-basel-iii transaction-threshold rule is implemented here
today, matching core/src/circuits/banking_basel_iii.rs -- see that file's
module docstring for why this is the one rule out of the compliance
mapping docs that's actually been implemented (it's the one each doc
flags as tractable near-term).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

RULE_ID_BANKING_BASEL_III = "banking-basel-iii"


class RuleViolation(Exception):
    """Raised when a rule's predicate does not hold for the given input.
    Mirrors VeritasError::RuleViolation in core/src/errors.rs.
    """


@dataclass(frozen=True)
class TransactionThresholdInput:
    transaction_amount_minor: int
    risk_adjusted_threshold_minor: int
    customer_id_hash: bytes  # must be exactly 32 bytes

    def __post_init__(self) -> None:
        if len(self.customer_id_hash) != 32:
            raise ValueError(
                f"customer_id_hash must be exactly 32 bytes, got {len(self.customer_id_hash)}"
            )


def check_transaction_threshold(input_: TransactionThresholdInput) -> None:
    """Raises RuleViolation if the transaction exceeds the customer's
    risk-adjusted threshold. Mirrors TransactionThresholdRule::check in
    core/src/circuits/banking_basel_iii.rs exactly (including the
    less-than-or-equal boundary: exactly-at-threshold passes).
    """
    if input_.transaction_amount_minor > input_.risk_adjusted_threshold_minor:
        raise RuleViolation(
            f"{RULE_ID_BANKING_BASEL_III}: transaction_amount_minor "
            f"{input_.transaction_amount_minor} exceeds risk_adjusted_threshold_minor "
            f"{input_.risk_adjusted_threshold_minor}"
        )


def canonical_bytes(input_: TransactionThresholdInput) -> bytes:
    """Must byte-for-byte match
    TransactionThresholdRule::canonical_bytes in Rust: two little-endian
    u64s followed by the raw 32-byte hash. This is exactly the encoding
    core/tests/vectors/banking-basel-iii.json is meant to pin down cross-
    language -- see tests/test_vectors.py in this package.
    """
    return (
        struct.pack("<Q", input_.transaction_amount_minor)
        + struct.pack("<Q", input_.risk_adjusted_threshold_minor)
        + input_.customer_id_hash
    )
