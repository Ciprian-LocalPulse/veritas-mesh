from decimal import Decimal

import pytest

from veritas_analysis.risk_mapping import RawTransaction, map_transaction_to_threshold_input
from veritas_sdk.rules import RuleViolation, check_transaction_threshold


def test_maps_usd_transaction_correctly():
    tx = RawTransaction(amount=Decimal("999.99"), currency="USD", customer_id="acct-123")
    threshold_input = map_transaction_to_threshold_input(tx, risk_adjusted_threshold=Decimal("1000.00"))

    assert threshold_input.transaction_amount_minor == 99999
    assert threshold_input.risk_adjusted_threshold_minor == 100000
    assert len(threshold_input.customer_id_hash) == 32
    check_transaction_threshold(threshold_input)  # should not raise


def test_mapped_input_correctly_flags_a_violation():
    tx = RawTransaction(amount=Decimal("1500.00"), currency="EUR", customer_id="acct-456")
    threshold_input = map_transaction_to_threshold_input(tx, risk_adjusted_threshold=Decimal("1000.00"))

    with pytest.raises(RuleViolation):
        check_transaction_threshold(threshold_input)


def test_unsupported_currency_rejected_rather_than_silently_wrong():
    tx = RawTransaction(amount=Decimal("1000"), currency="JPY", customer_id="acct-789")
    with pytest.raises(ValueError, match="JPY"):
        map_transaction_to_threshold_input(tx, risk_adjusted_threshold=Decimal("500"))


def test_same_customer_id_produces_same_hash_deterministically():
    tx_a = RawTransaction(amount=Decimal("10.00"), currency="USD", customer_id="acct-same")
    tx_b = RawTransaction(amount=Decimal("20.00"), currency="USD", customer_id="acct-same")
    a = map_transaction_to_threshold_input(tx_a, Decimal("100"))
    b = map_transaction_to_threshold_input(tx_b, Decimal("100"))
    assert a.customer_id_hash == b.customer_id_hash


def test_different_customer_ids_produce_different_hashes():
    tx_a = RawTransaction(amount=Decimal("10.00"), currency="USD", customer_id="acct-a")
    tx_b = RawTransaction(amount=Decimal("10.00"), currency="USD", customer_id="acct-b")
    a = map_transaction_to_threshold_input(tx_a, Decimal("100"))
    b = map_transaction_to_threshold_input(tx_b, Decimal("100"))
    assert a.customer_id_hash != b.customer_id_hash
