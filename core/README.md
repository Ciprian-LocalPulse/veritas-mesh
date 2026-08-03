# `core/` — Proof Engine & Cryptographic Core (Rust)

**Status: not started.** No Rust code exists in this directory yet. See [Project Status](../README.md#project-status) and [Roadmap](../ROADMAP.md) Phase 2.

## Intended scope

Per the [whitepaper](../whitepaper/Veritas_Mesh_Whitepaper.md) §6.1, this crate (or workspace of crates) will implement:

- The attestation state machine defined in [`spec/PROTOCOL_SPEC.md`](../spec/PROTOCOL_SPEC.md) §5
- Proof generation and verification, once a proof system is selected via RFC (§3.1 of the spec)
- The commitment and signature primitives, once selected via RFC (§3.2, §3.3)

`#![forbid(unsafe_code)]` is intended to be a hard constraint on this crate from its first commit, not a goal to work toward — there is no acceptable reason for unsafe code in the cryptographic core of this protocol.

## Before writing code here

Per [GOVERNANCE.md](../GOVERNANCE.md), do not open a substantial pull request against this directory before the relevant RFCs (proof system, commitment scheme, signature scheme — tracked in [`rfcs/README.md`](../rfcs/README.md)) have been accepted. Foundational cryptographic choices made without going through that process would need to be redone, at real cost.
