# Compliance Mapping: Healthcare (HIPAA)

**Status: draft mapping, no implemented rule modules yet.** See the same caveat as in [`banking-basel-iii.md`](banking-basel-iii.md) — this is a planning document, not a certification.

## Purpose

Maps categories of HIPAA-relevant requirements — particularly the Privacy Rule's minimum-necessary-disclosure principle and common clinical-pathway adherence checks — to candidate rule modules.

## Candidate rule modules

| Requirement category | Source | Candidate rule module | Tractability assessment |
|---|---|---|---|
| Clinical pathway adherence | Common hospital quality-assurance practice | "Treatment sequence for condition X matched an approved clinical pathway" | **Plausibly tractable for narrow, well-defined pathways** — a small, fixed decision tree is a reasonable circuit target. Complexity grows quickly for pathways with many branches or continuous-valued decision points. |
| Minimum-necessary access | HIPAA Privacy Rule, 45 CFR § 164.502(b) | "Staff member's data access was limited to the minimum necessary for their role in this case" | **Research-level difficulty** — "necessary" is not a purely computational predicate; formalizing it into a circuit-checkable rule requires significant domain-specific specification work before any cryptography is relevant. |
| Breach-free disclosure logging | HIPAA Security Rule audit requirements | "All disclosures of this record were logged and each logged access was authorized" | **Plausibly tractable** — closer to a completeness/consistency check over a log than a complex medical judgment. |
| De-identification adequacy | HIPAA Safe Harbor / Expert Determination methods | "Dataset meets Safe Harbor de-identification criteria" | **Uncertain** — some Safe Harbor criteria (removal of 18 specific identifier categories) are close to mechanically checkable; the Expert Determination method is explicitly a human judgment call and likely not suitable for this protocol at all. |

## Important scope note

Nothing in this document, or in Veritas Mesh generally, should be read as legal advice about HIPAA compliance, nor as a substitute for a covered entity's own compliance program and counsel. This is a technical research mapping, produced by an independent researcher with no healthcare-regulatory affiliation, intended to identify where cryptographic attestation could plausibly reduce unnecessary data disclosure during compliance verification — not a compliance product.

## Next steps

The disclosure-logging rule module is the most likely first healthcare-sector candidate for Phase 2 of the [Roadmap](../ROADMAP.md), for the same reason as the banking transaction-threshold rule: it is structurally simple enough to prove the pipeline works, not because it is the highest-value HIPAA requirement in isolation.
