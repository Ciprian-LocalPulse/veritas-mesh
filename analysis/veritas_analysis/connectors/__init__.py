"""Adapters between legacy institutional systems and RawTransaction.

STATUS: this module defines the real, working `Connector` protocol plus a
`CsvBankExportConnector` that actually parses a real (if simple) file
format end-to-end -- see tests/test_connectors.py. It does NOT include
connectors for any specific vendor's core banking or hospital EHR system
(Fiserv, Temenos, Epic, Cerner, etc.): those each need a real integration
contract with that vendor and are out of scope for a scaffold. Implement
`Connector` for a specific system by following `CsvBankExportConnector` as
the reference shape.
"""

from .base import Connector
from .csv_bank_export import CsvBankExportConnector

__all__ = ["Connector", "CsvBankExportConnector"]
