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
- [x] TLA+ model of the attestation lifecycle state machine (`spec/formal/AttestationLifecycle.tla`, plus a companion `AttestationNonInterference.tla` checking the same wiring for a private-witness-to-verdict leak)
- [x] Mechanically checked soundness property (lifecycle-wiring level, under an explicit assumption of the not-yet-selected proof system's cryptographic soundness — see `spec/formal/AttestationLifecycle_report.md`)
- [ ] Mechanically checked zero-knowledge / non-disclosure property — **not achievable by TLA+/TLC by construction** (computational indistinguishability, not a finite-state property); to be resolved by citing the selected proof system's own published security proof once [RFC 0002](../rfcs/0002-proof-system-selection.md) is accepted, per `spec/formal/README.md`
- [x] Mechanically checked multi-verifier independence property
- [x] Published under `spec/formal/`

## Phase 2 — Minimal Proof Engine
- [ ] `core/` Rust crate implementing one narrow rule module end-to-end (progress: all three rule modules now have real Groth16-over-BN254 circuits in `zk-poc/` — `banking-basel-iii`, `healthcare-hipaa`, and now `gov-supply-chain-integrity` (`zk-poc/src/supply_chain_circuit.rs`, real SHA-256 R1CS gadget, 318,668 constraints, ~64 MiB proving key). Only the first two are reachable through `core/`'s own `ProofSystem` trait so far (`core::proof::groth16_bn254`) — the third circuit exists but isn't wired in yet, and no orchestration layer yet combines any proof with RFC-0003's commitment and the Ed25519 signature into one attestation-building call; see `zk-poc/README.md`'s "what's still needed")
- [ ] Real, passing test suite (not a placeholder) (110 tests passing across the repo as of the third circuit landing — real assertions, not placeholders, but Phase 2 as a whole isn't done per the item above)
- [ ] CI running on every commit
- [ ] Benchmarks against real backends as they land (covers the Ed25519 signature layer, all three standalone `zk-poc/` Groth16 circuits, AND the two of them wired through `core/`'s `ProofSystem` trait — see [`BENCHMARKS.md`](BENCHMARKS.md); not yet on dedicated hardware)

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
