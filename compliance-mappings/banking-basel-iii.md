# Compliance Mapping: Banking (Basel III & AML/KYC)

**Status: draft mapping, no implemented rule modules yet.** This document identifies *candidate* rule-module targets and explains why each is or isn't currently tractable — it is a research and planning artifact, not a certification of coverage.

## Purpose

This document maps categories of banking-regulatory requirements to the rule-module concept defined in [`spec/PROTOCOL_SPEC.md`](../spec/PROTOCOL_SPEC.md), and gives an honest assessment of how close each candidate is to being expressible as an efficient zero-knowledge circuit today.

## Candidate rule modules

| Requirement category | Source | Candidate rule module | Tractability assessment |
|---|---|---|---|
| Transaction threshold monitoring | Standard AML transaction-monitoring practice | "Transaction amount did not exceed customer's risk-adjusted threshold" | **Likely tractable near-term** — a straightforward numeric comparison, well within reach of current zk circuit design. Planned as the Phase 2 minimal proof-engine target rule (see [Roadmap](../ROADMAP.md)). |
| Structuring detection | AML practice (avoiding reporting thresholds via multiple smaller transactions) | "No pattern of transactions within a 30-day window sums to more than N while individually staying under the reporting threshold" | **Research-level difficulty** — requires proving a property over a variable-length transaction history, which is a nontrivial circuit-design problem. Explicitly flagged as unproven feasibility in the [whitepaper](../whitepaper/Veritas_Mesh_Whitepaper.md) §10. |
| Capital adequacy ratio disclosure | Basel III capital requirements | "Reported capital ratio was computed correctly from underlying risk-weighted assets, without disclosing individual asset positions" | **Research-level difficulty** — requires proving correctness of a large aggregation computation over potentially thousands of positions; circuit size and proving time are open questions. |
| Liquidity coverage ratio | Basel III liquidity requirements | Similar structure to capital adequacy above | Same assessment as above. |
| KYC completeness (without disclosing identity documents) | Standard KYC practice | "Customer onboarding included all required verification steps" | **Plausibly tractable** — closer to a checklist/workflow-completion proof than a numeric computation; complexity depends on how "verification step" is formalized. |

## What this document is not

It is not a claim that Veritas Mesh currently satisfies any part of Basel III, AML, or KYC regulatory requirements — no regulator has reviewed or endorsed this project, and no implementation exists to review. Any statement to the contrary anywhere referencing this project should be treated as false and reported.

## Next steps

The first rule module actually implemented (Phase 2 of the [Roadmap](../ROADMAP.md)) will be the transaction-threshold check above, precisely because it is the most tractable, not because it is the most regulatorily significant — the point of Phase 2 is to prove the end-to-end pipeline works at all, on the simplest real case available.
