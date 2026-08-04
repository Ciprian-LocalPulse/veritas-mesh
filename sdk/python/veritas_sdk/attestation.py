"""Attestation type, hand-mirrored from attestation.proto /
core/src/attestation.rs. See package __init__ docstring for the sync
obligation this creates until proto codegen is wired up.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Attestation:
    rule_id: str
    rule_version: str
    prover_identity: str
    event_timestamp_unix: int
    commitment_scheme: str
    commitment_value: bytes
    proof: bytes
    signature: bytes = field(default=b"")

    def key(self) -> str:
        """Dedup key -- matches mesh/internal/storage.Attestation.Key()
        (hex of the signature) so a Python-side gossip relay, if one is
        ever built, agrees with the Go implementation on identity.
        """
        return self.signature.hex()
