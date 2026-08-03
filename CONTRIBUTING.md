# Contributing to Veritas Mesh

Thank you for considering a contribution. Veritas Mesh is independent, self-funded, public-interest research — every contribution, however small, directly determines how fast this becomes a real, trustworthy system rather than a specification on paper.

Please read [SECURITY.md](SECURITY.md) first if what you have is a security vulnerability — it should **not** go through a normal pull request or public issue.

## Before you start

- Check [ROADMAP.md](ROADMAP.md) and the [Project Status](README.md#project-status) table in the README so your contribution lands where the project actually is, not where the documentation someday hopes to be.
- For anything that touches the protocol specification, a security-relevant property, or a new rule-module category, read [GOVERNANCE.md](GOVERNANCE.md) — these changes require an RFC before implementation, not just a pull request.
- For everything else — bug fixes, documentation corrections, test coverage, tooling — a pull request is the right starting point.

## The single most valuable kind of contribution right now

At this stage, the project's biggest risk is not too little ambition — it's documentation or specification that outpaces working, verified code. If you find a place where this repository claims something is done, proven, or working, and it isn't, **that correction is more valuable than a new feature**, and we mean that literally: see the honesty commitment in the README. Please open an issue or PR immediately.

## Development setup

Each subsystem is a separate part of the workspace, with its own toolchain:

| Directory | Language | Toolchain |
|---|---|---|
| `core/` | Rust | stable toolchain via [rustup](https://rustup.rs/); see `core/README.md` |
| `analysis/` | Python | 3.11+, see `analysis/README.md` |
| `mesh/` | Go | 1.22+, see `mesh/README.md` |
| `dashboard/` | TypeScript/React | Node 20+, see `dashboard/README.md` |
| `proto/` | Protocol Buffers | `protoc` 3.21+ |

Because several subsystems are not yet implemented (see the status table in the README), their directories currently contain only a `README.md` describing the intended scope and a placeholder. Please do not open a pull request that adds substantial code to an unimplemented subsystem without first opening an RFC or an issue to discuss the approach — this avoids duplicated or conflicting foundational work.

## Pull request checklist

- [ ] The change is scoped to a single logical concern.
- [ ] Any new code has tests, and `cargo test` / `pytest` / `go test` / the relevant test runner passes locally.
- [ ] Any claim in a README, whitepaper, or spec document that a component "works," is "tested," or is "proven" is backed by code and tests that actually exist and actually pass — see the project's honesty commitment.
- [ ] Commit messages are clear about *why*, not just *what*.
- [ ] If the change affects the protocol specification or a security property, it references the relevant RFC.

## Code of Conduct

All participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Please read it.

## Attribution

Contributors are credited in [AUTHORS.md](AUTHORS.md) — add yourself in the same pull request as your first contribution.

## Questions

Open a [GitHub Discussion](../../discussions) for anything that isn't a specific bug or a specific proposed change.
