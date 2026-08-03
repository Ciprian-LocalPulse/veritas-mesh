# RFCs

This directory holds Requests for Comments (RFCs) for Veritas Mesh — the process by which protocol-level, security-relevant, or governance changes are proposed and decided. See [`GOVERNANCE.md`](../GOVERNANCE.md) for the full process description.

## Index

No RFCs have been proposed yet. The first expected RFCs, per the [Roadmap](../ROADMAP.md), are:

1. Attestation format finalization (extending [`spec/PROTOCOL_SPEC.md`](../spec/PROTOCOL_SPEC.md) §4)
2. Proof system selection — SNARK vs. STARK for the reference implementation (extending §3.1)
3. Commitment scheme selection (extending §3.2)

## How to propose one

1. Copy [`0000-template.md`](0000-template.md) to `NNNN-short-title.md`, where `NNNN` is the next unused four-digit number.
2. Fill it out completely — an RFC with an empty "Drawbacks" or "Alternatives Considered" section will be sent back for revision, not accepted as-is.
3. Open a pull request. Discussion stays open per the minimum periods in [`GOVERNANCE.md`](../GOVERNANCE.md).
