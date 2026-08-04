"""Runs core/tests/vectors/banking-basel-iii.json through this package's
own implementation. This is the actual "multi-verifier independence"
property from the whitepaper exercised as a test: if this file and the
Rust vectors it reads ever disagree on pass/fail for the same input,
that's a real interoperability bug, not a style nit.
"""

import json
from pathlib import Path

import pytest

from veritas_sdk.rules import RuleViolation, TransactionThresholdInput, check_transaction_threshold

VECTORS_PATH = (
    Path(__file__).resolve().parents[3] / "core" / "tests" / "vectors" / "banking-basel-iii.json"
)


def load_vectors():
    if not VECTORS_PATH.exists():
        pytest.skip(f"vectors file not found at {VECTORS_PATH}; run from a full repo checkout", allow_module_level=True)
    data = json.loads(VECTORS_PATH.read_text())
    return data["vectors"]


@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v["name"])
def test_vector_matches_rust_expectation(vector):
    raw = vector["input"]
    customer_hash = bytes.fromhex(raw["customer_id_hash_hex"])
    inp = TransactionThresholdInput(
        transaction_amount_minor=raw["transaction_amount_minor"],
        risk_adjusted_threshold_minor=raw["risk_adjusted_threshold_minor"],
        customer_id_hash=customer_hash,
    )

    if vector["expect_pass"]:
        check_transaction_threshold(inp)  # must not raise
    else:
        with pytest.raises(RuleViolation):
            check_transaction_threshold(inp)
