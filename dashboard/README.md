# `dashboard/` — Auditor & Regulator Interface (TypeScript + React)

**Status: not started.** See [Project Status](../README.md#project-status).

## Intended scope

Per the [whitepaper](../whitepaper/Veritas_Mesh_Whitepaper.md) §6.5: a human-facing interface for inspecting attestations and rule modules. No private data passes through this layer — by protocol design, there is none available to it. Strict TypeScript typing is a hard requirement once implementation begins, given the cost of a rendering bug in a compliance-decision interface.
