# Changelog

All notable changes to this project are documented here. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions and, once versioned releases begin, [Semantic Versioning](https://semver.org/).

Entries here describe what actually changed and what was verified — not intentions. Planned work belongs in [ROADMAP.md](ROADMAP.md), not here.

## [Unreleased]

### Added
- Initial project scaffold: `README.md`, `SECURITY.md`, `LICENSE` (Apache-2.0), `CITATION.cff`, `AUTHORS.md`.
- Governance and contribution process: `GOVERNANCE.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`.
- Initial whitepaper draft: `whitepaper/Veritas_Mesh_Whitepaper.md` (v0.1).
- Protocol specification skeleton: `spec/PROTOCOL_SPEC.md`, `spec/THREAT_ANALYSIS.md`.
- Compliance framework mapping drafts for banking (Basel III / AML), healthcare (HIPAA), and government supply-chain integrity.
- RFC process and template.
- Directory scaffolding for `core/` (Rust), `analysis/` (Python), `mesh/` (Go), `dashboard/` (TypeScript/React), and `proto/` — no implementation code yet in any of these; each contains a `README.md` stating its actual status.

### Notes
- No component has been implemented, tested, or audited as of this entry. See the [Project Status](README.md#project-status) table for the authoritative, current state.
