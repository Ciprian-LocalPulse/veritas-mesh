from decimal import Decimal
from pathlib import Path

import pytest

from veritas_analysis.connectors import CsvBankExportConnector
from veritas_analysis.connectors.csv_bank_export import CsvBankExportError


def write_csv(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "export.csv"
    p.write_text(content, encoding="utf-8")
    return p


def test_parses_well_formed_csv(tmp_path: Path):
    csv_path = write_csv(
        tmp_path,
        "amount,currency,customer_id\n"
        "100.50,USD,acct-1\n"
        "2000.00,EUR,acct-2\n",
    )
    connector = CsvBankExportConnector(csv_path)
    rows = list(connector.fetch_transactions())

    assert len(rows) == 2
    assert rows[0].amount == Decimal("100.50")
    assert rows[0].currency == "USD"
    assert rows[0].customer_id == "acct-1"
    assert rows[1].currency == "EUR"


def test_missing_required_column_raises(tmp_path: Path):
    csv_path = write_csv(tmp_path, "amount,currency\n100.00,USD\n")
    connector = CsvBankExportConnector(csv_path)
    with pytest.raises(CsvBankExportError, match="missing required column"):
        list(connector.fetch_transactions())


def test_invalid_amount_raises_with_row_number(tmp_path: Path):
    csv_path = write_csv(
        tmp_path,
        "amount,currency,customer_id\n"
        "100.00,USD,acct-1\n"
        "not-a-number,USD,acct-2\n",
    )
    connector = CsvBankExportConnector(csv_path)
    with pytest.raises(CsvBankExportError, match=":3:"):
        list(connector.fetch_transactions())


def test_currency_is_uppercased(tmp_path: Path):
    csv_path = write_csv(tmp_path, "amount,currency,customer_id\n10.00,usd,acct-1\n")
    connector = CsvBankExportConnector(csv_path)
    rows = list(connector.fetch_transactions())
    assert rows[0].currency == "USD"


def test_missing_customer_id_raises(tmp_path: Path):
    csv_path = write_csv(tmp_path, "amount,currency,customer_id\n10.00,USD,\n")
    connector = CsvBankExportConnector(csv_path)
    with pytest.raises(CsvBankExportError, match="missing customer_id"):
        list(connector.fetch_transactions())
