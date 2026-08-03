# Compliance Mapping: Government & Defense-Adjacent — Supply Chain and Security-Control Integrity

**Status: draft mapping, no implemented rule modules yet.**

## Scope boundary (read this first)

This document, and any rule module that comes from it, is strictly limited to **defensive integrity verification**. See [`spec/THREAT_ANALYSIS.md`](../spec/THREAT_ANALYSIS.md) §4 for the full, non-negotiable statement of this boundary. Nothing in this document extends, or is intended to be read as a step toward, any offensive, targeting, or weapons-related capability. Any proposal to extend this mapping in that direction will be declined through the [governance process](../GOVERNANCE.md) regardless of framing.

## Purpose

Maps categories of supply-chain and security-control verification — relevant to public procurement, critical infrastructure, and defense-adjacent contractors — to candidate rule modules, focused entirely on proving integrity without disclosing sensitive operational detail.

## Candidate rule modules

| Requirement category | Context | Candidate rule module | Tractability assessment |
|---|---|---|---|
| Component provenance | Hardware/software supply-chain integrity (e.g., aligned with frameworks like NIST SP 800-161) | "This component's provenance chain matches an approved, unaltered sequence of custody, without disclosing the specific supplier identities or logistics routes" | **Research-level difficulty** — provenance chains of variable length and structure are a nontrivial circuit-design problem, structurally similar to the AML structuring-detection case in the banking mapping. |
| Security-control compliance | e.g., patch-level or configuration-baseline compliance akin to NIST 800-53 control families | "System met configuration baseline X as of date Y, without disclosing the system's specific configuration" | **Plausibly tractable for narrow, well-defined baselines** — similar in structure to the clinical-pathway case in the healthcare mapping. |
| Audit-trail integrity | General public-sector audit requirements | "This audit log is complete and untampered for the stated period" | **Plausibly tractable** — a completeness/integrity check over a log structure, similar to the healthcare disclosure-logging case. |

## What this explicitly does not cover

For absolute clarity, restating [`spec/THREAT_ANALYSIS.md`](../spec/THREAT_ANALYSIS.md) §4: this mapping does not, and will not, extend to weapons systems, targeting systems, operational planning systems, or offensive cyber capability of any kind, regardless of the customer or context proposing it.

## Next steps

The audit-trail integrity rule module is the most likely first candidate here for the same tractability reasons given in the other two mapping documents.
