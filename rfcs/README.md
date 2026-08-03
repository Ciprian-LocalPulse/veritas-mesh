# RFCs

This directory holds Requests for Comments (RFCs) for Veritas Mesh — the process by which protocol-level, security-relevant, or governance changes are proposed and decided. See [`GOVERNANCE.md`](../GOVERNANCE.md) for the full process description.

## Index

| # | Title | Status |
|---|---|---|
| [0001](0001-attestation-format-finalization.md) | Attestation Format Finalization | Draft — not yet opened for discussion |
| [0002](0002-proof-system-selection.md) | Proof System Selection (SNARK vs. STARK) | Draft — not yet opened for discussion |
| [0003](0003-commitment-scheme-selection.md) | Commitment Scheme Selection | Draft — not yet opened for discussion |

These are the three RFCs named as expected in [Roadmap](../ROADMAP.md)
Phase 0. They exist here as drafts ready for discussion — none has been
opened as a pull request or reached the minimum discussion period defined
in [`GOVERNANCE.md`](../GOVERNANCE.md), and none should be treated as
accepted, or as unblocking `core/`, `sdk/`, or `spec/formal/` work that
depends on RFC acceptance, until that process has actually run.

Sequencing note: 0001 is written to not depend on the outcome of 0002 or
0003 (it uses a scheme-tagging approach precisely so the format doesn't
need to be reopened once a concrete proof system or commitment scheme is
chosen), but 0003 does depend on 0002's outcome — see 0003's Motivation
section.

## How to propose one

1. Copy [`0000-template.md`](0000-template.md) to `NNNN-short-title.md`, where `NNNN` is the next unused four-digit number.
2. Fill it out completely — an RFC with an empty "Drawbacks" or "Alternatives Considered" section will be sent back for revision, not accepted as-is.
3. Open a pull request. Discussion stays open per the minimum periods in [`GOVERNANCE.md`](../GOVERNANCE.md).
