# Governance

Veritas Mesh is governed as an open, RFC-driven project. This document describes how decisions are made today, and how that process is expected to evolve as the contributor base grows.

## Roles

### Founder / Lead Maintainer

**Ciprian Ştefan Pleşca** founded Veritas Mesh and currently holds final decision authority as Lead Maintainer, exercised through the RFC process below rather than unilaterally. As the project grows a sustained contributor base, this document will be amended — through the RFC process itself — to distribute authority over specific subsystems (`core/`, `mesh/`, `analysis/`, `dashboard/`, rule modules) to dedicated maintainers.

### Maintainers

Maintainers have merge rights over one or more areas of the codebase, listed in [CODEOWNERS](CODEOWNERS). Maintainer status is granted by the Lead Maintainer based on a sustained record of high-quality contributions and is revocable for inactivity or violation of the [Code of Conduct](CODE_OF_CONDUCT.md).

### Contributors

Anyone who submits a pull request, issue, RFC, or review is a contributor. No special status is required to propose a change.

## The RFC Process

Any change that affects the protocol specification, a security-relevant property, the cryptographic approach, the addition of a new rule-module category, or the project's governance itself **must** go through the RFC process before implementation begins. This is deliberate: a protocol asking regulated institutions to trust its outputs cannot evolve behind closed doors.

1. **Draft.** Copy [`rfcs/0000-template.md`](rfcs/0000-template.md) to `rfcs/NNNN-short-title.md` and fill it out.
2. **Discussion.** Open a pull request. The RFC stays open for public discussion for a minimum of **14 days** for ordinary changes, or **30 days** for changes to the core protocol's security properties or the boundaries described in [`spec/THREAT_ANALYSIS.md`](spec/THREAT_ANALYSIS.md).
3. **Decision.** The RFC is accepted, rejected, or sent back for revision based on rough consensus among maintainers, with the Lead Maintainer breaking unresolved deadlocks and publishing the reasoning for the record.
4. **Implementation.** An accepted RFC is tracked as an implementation issue. The RFC document itself is never silently edited after acceptance — amendments go through a new RFC that references the original.

Changes that are purely editorial, or that fix an implementation bug without changing intended behavior, do not require an RFC — ordinary pull request review is sufficient.

## Non-Negotiable Boundaries

Certain constraints are not subject to the ordinary RFC process and cannot be overridden by rough consensus:

- **No offensive capability.** Veritas Mesh will never incorporate functionality oriented toward weapons systems, operational or targeting use, or offensive cyber capability, regardless of the technical merit of a proposal. This boundary is described in detail in [`spec/THREAT_ANALYSIS.md`](spec/THREAT_ANALYSIS.md) and can only be narrowed (never widened) by a unanimous vote of all active maintainers plus the Lead Maintainer.
- **Apache-2.0 licensing.** The project's core license will not be changed to anything less permissive or that removes the explicit patent grant.
- **Public specification.** The protocol specification will never be made available under different terms to different parties — no dual-licensing that privileges paying customers with earlier or more complete access to the specification itself (implementations and support services are a separate matter, see [DONATE.md](DONATE.md)).

## Decision Records

Significant governance decisions, including RFC outcomes, are logged in [`CHANGELOG.md`](CHANGELOG.md) and, where they affect the protocol specification, cross-referenced from [`whitepaper/Veritas_Mesh_Whitepaper.md`](whitepaper/Veritas_Mesh_Whitepaper.md).

## Amending This Document

Changes to this governance document are themselves subject to the RFC process, with the 30-day discussion period, since governance changes affect the trust properties the whole project depends on.
