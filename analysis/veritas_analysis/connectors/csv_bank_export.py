"""Reference connector: reads a simple CSV export format
(amount,currency,customer_id per row) such as many legacy core-banking
systems can produce as a scheduled batch export, since that's usually the
lowest-common-denominator integration point available without a real API
integration contract with the vendor.

This is the ONE connector in this package that's actually wired to a real
data format end-to-end -- see the module docstring in __init__.py for why
vendor-specific API connectors (Fiserv, Temenos, ...) aren't included.
"""

from __future__ import annotations

import csv
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Iterator

from ..risk_mapping import RawTransaction


class CsvBankExportError(ValueError):
    """Raised for a malformed row. Includes the 1-based row number so an
    operator can find and fix the source export instead of getting a bare
    parse error.
    """


class CsvBankExportConnector:
    """Connector implementation (see connectors.base.Connector) for a CSV
    file with a header row: amount,currency,customer_id
    """

    REQUIRED_COLUMNS = ("amount", "currency", "customer_id")

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def fetch_transactions(self) -> Iterator[RawTransaction]:
        with self.path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            missing = [c for c in self.REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
            if missing:
                raise CsvBankExportError(
                    f"{self.path}: missing required column(s) {missing}; "
                    f"found {reader.fieldnames}"
                )

            for row_num, row in enumerate(reader, start=2):  # header is row 1
                yield self._parse_row(row, row_num)

    def _parse_row(self, row: dict[str, str], row_num: int) -> RawTransaction:
        try:
            amount = Decimal(row["amount"])
        except (InvalidOperation, KeyError) as e:
            raise CsvBankExportError(f"{self.path}:{row_num}: invalid amount {row.get('amount')!r}") from e

        currency = (row.get("currency") or "").strip().upper()
        if not currency:
            raise CsvBankExportError(f"{self.path}:{row_num}: missing currency")

        customer_id = (row.get("customer_id") or "").strip()
        if not customer_id:
            raise CsvBankExportError(f"{self.path}:{row_num}: missing customer_id")

        return RawTransaction(amount=amount, currency=currency, customer_id=customer_id)
