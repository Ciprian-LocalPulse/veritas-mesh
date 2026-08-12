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
- [ ] `core/` Rust crate implementing one narrow rule module end-to-end (progress: all three rule modules now have real Groth16-over-BN254 circuits in `zk-poc/`, wired into `core/`'s `ProofSystem` trait, AND a real orchestration layer (`core::attest`) combining predicate check → commitment → ZK proof → signature into one call per rule. **`banking-basel-iii` is now genuinely closer to true end-to-end than the other two**: `attest_banking` uses a commitment-bound circuit (`zk-poc/src/bound_circuit.rs`) that recomputes the commitment inside the proof itself and rejects any mismatch — the binding gap `attest()`'s docs used to describe as fully open is closed for this one rule. `healthcare-hipaa` and `gov-supply-chain-integrity` still have that gap. Key generation/publishing infrastructure now real (`zk-poc/src/bin/generate_keys.rs`, `Keys::load_from_files`, checked-in keys for the two small circuits under `zk-poc/keys/`) — but `core::attest` doesn't use it yet, still calling `setup()` fresh rather than loading published keys; see `zk-poc/README.md`'s "what's still needed", items 3-4, and `STATUS.md`'s "What this means in practice")
- [ ] Real, passing test suite (not a placeholder) (131 tests passing across the repo as of the key-publishing infrastructure landing — real assertions, not placeholders, but Phase 2 as a whole isn't done per the item above)
- [ ] CI running on every commit (`.github/workflows/ci.yml` now exists, with every command in it individually verified against this repo's real dev environment before being committed — see STATUS.md, which also documents and corrects an earlier false claim that this file already existed. Left unchecked: "committed" isn't "running on every commit" until it has actually executed on GitHub's own infrastructure at least once, which requires a real push to trigger it — that hasn't happened yet as of this line)
- [ ] Benchmarks against real backends as they land (covers the Ed25519 signature layer, all three standalone `zk-poc/` Groth16 circuits (including the commitment-bound banking variant), AND all three wired through `core/`'s `ProofSystem` trait — see [`BENCHMARKS.md`](BENCHMARKS.md); not yet on dedicated hardware)

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
