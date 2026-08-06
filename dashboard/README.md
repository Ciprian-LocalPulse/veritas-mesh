# `dashboard/` — Auditor & Regulator Interface (TypeScript + React)

**Status: not started.** See [Project Status](../README.md#project-status).

## Intended scope

Per the [whitepaper](../whitepaper/Veritas_Mesh_Whitepaper.md) §6.5: a human-facing interface for inspecting attestations and rule modules. No private data passes through this layer — by protocol design, there is none available to it. Strict TypeScript typing is a hard requirement once implementation begins, given the cost of a rendering bug in a compliance-decision interface.

## Known gap in the current scaffold

`vite build` (i.e. `npm run build`) currently fails with `Cannot resolve
entry module "index.html"` — there is no `index.html` in this directory
yet. Consistent with "not started" above (nothing to build the app
around yet), not a regression; `npm run typecheck` and `npm test` are
unaffected and both pass. Whoever starts real implementation here should
add an `index.html` entry point as one of the first steps, not treat the
current `vite.config.ts`/`package.json` scaffold as complete.

See [`SECURITY.md`](../SECURITY.md#dependency-alert-triage-log) for a
dependency-vulnerability fix already applied to `package.json` here (an
`esbuild` version override) — unrelated to the gap above, found while
investigating it.
