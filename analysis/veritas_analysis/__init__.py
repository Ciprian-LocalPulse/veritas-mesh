"""veritas_analysis: translates an institution's own data into the typed
witness inputs veritas_sdk's rule checks expect, and adapts legacy
banking/hospital systems' data shapes into that common form.

This package never generates or handles proofs -- it stops at producing a
validated, typed input struct (e.g.
veritas_sdk.rules.TransactionThresholdInput) that the caller then hands to
veritas_sdk / core. Keeping proof generation exclusively in core/ (per
whitepaper section 6.2) means a bug in a legacy-system adapter here can, at
worst, produce a rule violation (caught before any proof is made) -- never
a false attestation, because it has no path to signing one.
"""

from .risk_mapping import map_transaction_to_threshold_input

__all__ = ["map_transaction_to_threshold_input"]
