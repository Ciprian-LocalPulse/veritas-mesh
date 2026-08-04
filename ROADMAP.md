# Roadmap

This roadmap mirrors the phased plan in [`whitepaper/Veritas_Mesh_Whitepaper.md`](whitepaper/Veritas_Mesh_Whitepaper.md#8-roadmap), kept here in a shorter, more actionable form for contributors. Each phase's "done" criterion is a public, checkable artifact — not a description in a document.

## Phase 0 — Specification (current)
- [x] Initial architecture and repository scaffold
- [x] Whitepaper v0.1
- [x] Protocol specification draft (`spec/PROTOCOL_SPEC.md`)
- [x] Threat model draft (`spec/THREAT_ANALYSIS.md`)
- [ ] First round of public RFC discussion on the attestation format
- [ ] First round of public RFC discussion on proof-system selection (SNARK vs. STARK for the reference implementation)
- [ ] First round of public RFC discussion on the Verifier API (`rfcs/0004-verifier-api.md`), ahead of Phase 5's `mesh/` implementation work

## Phase 1 — Formal Modeling
- [ ] TLA+ model of the attestation lifecycle state machine
- [ ] Mechanically checked soundness property
- [ ] Mechanically checked zero-knowledge / non-disclosure property
- [ ] Mechanically checked multi-verifier independence property
- [ ] Published under `spec/formal/`

## Phase 2 — Minimal Proof Engine
- [ ] `core/` Rust crate implementing one narrow rule module end-to-end
- [ ] Real, passing test suite (not a placeholder)
- [ ] CI running on every commit

## Phase 3 — First Institutional Pilot
- [ ] A willing pilot partner (bank, hospital, or public agency) identified
- [ ] One real, narrow rule proven and verified in a non-production pilot setting
- [ ] Case study published, regardless of outcome

## Phase 4 — Independent Security Audit
- [ ] Third-party cryptographic and implementation audit of `core/`
- [ ] Audit report published under `docs/audits/`, unredacted or with redactions clearly marked and justified

## Phase 5 — Mesh Network and Multi-Institution Deployment
- [ ] `mesh/` Go implementation
- [ ] Multi-verifier scenario demonstrated across independent parties
- [ ] Production-candidate release tagged

---

Progress against this roadmap is reflected honestly in the [Project Status](README.md#project-status) table — a checked box here should always correspond to a checked box there and a real, linkable artifact.
