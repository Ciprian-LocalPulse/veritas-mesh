import pytest

from veritas_sdk.rules import (
    RuleViolation,
    TransactionThresholdInput,
    canonical_bytes,
    check_transaction_threshold,
)


def make_hash(seed: int) -> bytes:
    return bytes([seed % 256]) * 32


def test_under_threshold_passes():
    inp = TransactionThresholdInput(50000, 100000, make_hash(1))
    check_transaction_threshold(inp)  # should not raise


def test_exactly_at_threshold_passes():
    inp = TransactionThresholdInput(100000, 100000, make_hash(1))
    check_transaction_threshold(inp)  # should not raise


def test_over_threshold_raises():
    inp = TransactionThresholdInput(100001, 100000, make_hash(1))
    with pytest.raises(RuleViolation):
        check_transaction_threshold(inp)


def test_invalid_hash_length_rejected():
    with pytest.raises(ValueError):
        TransactionThresholdInput(1, 2, b"too short")


def test_canonical_bytes_length_and_determinism():
    inp = TransactionThresholdInput(42, 100, make_hash(7))
    a = canonical_bytes(inp)
    b = canonical_bytes(inp)
    assert a == b
    assert len(a) == 8 + 8 + 32
