"""Common interface every legacy-system connector implements."""

from __future__ import annotations

from typing import Iterator, Protocol

from ..risk_mapping import RawTransaction


class Connector(Protocol):
    """A source of RawTransaction records from some external system.
    Implementations own all the vendor-specific parsing/API calls;
    everything downstream (risk_mapping, veritas_sdk, core) only ever sees
    the common RawTransaction shape.
    """

    def fetch_transactions(self) -> Iterator[RawTransaction]:
        """Yields transactions. Implementations should stream rather than
        materialize a full list where the source supports it (e.g. a
        paginated API or a large file) -- RawTransaction.customer_id
        carries sensitive institutional data and shouldn't be held in
        memory longer than necessary.
        """
        ...
