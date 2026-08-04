"""veritas_sdk: Python client SDK for Veritas Mesh.

STATUS: real, hand-written today. Per sdk/README.md, the Attestation
dataclass and rule-check logic here should eventually be generated from
proto/veritas/v1/*.proto (see proto/buf.gen.yaml, which already has a
Python plugin entry pointed at this package's `gen/` subdirectory) rather
than hand-mirrored across four languages. Until that codegen is wired up,
keep this file's `Attestation` and `banking.check_transaction_threshold`
in sync with core/src/attestation.rs and
core/src/circuits/banking_basel_iii.rs by hand -- a divergence here is
exactly the cross-language bug core/tests/vectors/ exists to catch, so run
that fixture against this package (see tests/test_vectors.py) whenever
either side changes.
"""

from .attestation import Attestation
from .rules import RuleViolation, check_transaction_threshold

__all__ = ["Attestation", "RuleViolation", "check_transaction_threshold"]
