"""Translates an institution's internal data representations into the
typed inputs veritas_sdk's rule checks expect.

STATUS: `map_transaction_to_threshold_input` is real, working logic for
the one rule implemented end-to-end (banking-basel-iii). It is
deliberately narrow: real risk-adjusted-threshold computation (the actual
Basel III risk model an institution uses) is the institution's own
business logic and out of scope here -- this function's job is only the
*shape* translation (decimal currency + a risk model's output -> the
integer-minor-units + hash encoding core/'s circuit expects), not
replicating a bank's risk model.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from veritas_sdk.rules import TransactionThresholdInput


@dataclass(frozen=True)
class RawTransaction:
    """What an institution's own systems are assumed to already have:
    a decimal currency amount (not minor units) and an opaque customer
    identifier string (e.g. an account number) that must never leave this
    process in cleartext.
    """

    amount: Decimal
    currency: str
    customer_id: str


def _to_minor_units(amount: Decimal) -> int:
    """Converts a decimal currency amount to integer minor units (e.g.
    cents), rounding half-up. Only correct for currencies with exactly 2
    minor-unit decimal places (USD, EUR, RON, ...); a real implementation
    needs a currency-to-exponent table (ISO 4217) for currencies like JPY
    (0 decimal places) or BHD (3) -- deliberately not included here to
    avoid silently mis-converting a currency this function was never
    tested against.
    """
    scaled = (amount * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return int(scaled)


def map_transaction_to_threshold_input(
    transaction: RawTransaction,
    risk_adjusted_threshold: Decimal,
) -> TransactionThresholdInput:
    """Builds the witness input for TransactionThresholdRule from an
    institution's raw transaction + a threshold produced by that
    institution's own risk model (not computed here -- see module
    docstring).

    Raises ValueError if `transaction.currency` isn't a 2-decimal-place
    currency this function knows it handles correctly.
    """
    if transaction.currency not in _KNOWN_TWO_DECIMAL_CURRENCIES:
        raise ValueError(
            f"currency {transaction.currency!r} is not in the supported set "
            f"{sorted(_KNOWN_TWO_DECIMAL_CURRENCIES)}; _to_minor_units assumes "
            "2 decimal places and would silently misconvert others (e.g. JPY, BHD)"
        )

    customer_id_hash = hashlib.sha256(transaction.customer_id.encode("utf-8")).digest()

    return TransactionThresholdInput(
        transaction_amount_minor=_to_minor_units(transaction.amount),
        risk_adjusted_threshold_minor=_to_minor_units(risk_adjusted_threshold),
        customer_id_hash=customer_id_hash,
    )


_KNOWN_TWO_DECIMAL_CURRENCIES = frozenset({"USD", "EUR", "RON", "GBP"})
