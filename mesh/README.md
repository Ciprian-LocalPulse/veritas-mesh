# `mesh/` — Attestation Mesh Network (Go)

**Status: partially started, not deployable.** The "not started" note
this file used to carry was itself stale — `internal/discovery`,
`internal/gossip`, and `internal/storage` have real, tested local logic
(see [`STATUS.md`](../STATUS.md)), and `cmd/veritas-node` wires them into
a runnable binary. What's genuinely missing, per Roadmap Phase 5: a real
network transport (there is no TCP/QUIC/libp2p implementation of
`internal/gossip`'s `Transport` interface yet — see that package's own
doc comment) and a real cryptographic verifier (the binary's
`noopVerifier` only checks that `rule_id`/`signature` are non-empty, not
that the signature is valid). Treat this package as the wiring skeleton
the real network layer plugs into, not a deployable node — see
`cmd/veritas-node/main.go`'s own header comment, which says this in more
detail.

## Intended scope

Per the [whitepaper](../whitepaper/Veritas_Mesh_Whitepaper.md) §6.4: a peer-to-peer network layer for publishing and retrieving attestations among institutions, auditors, and regulators, designed for high concurrency and partition tolerance. Real end-to-end deployment depends on a stable attestation format from `core/` (still `Draft` per RFC 0001) and, ideally, real cryptographic verification wired in (`noopVerifier` above is a shape check, not a security boundary).

## Running it

```
go build -o veritas-node ./cmd/veritas-node
./veritas-node < attestations.jsonl
```

Or via Docker (see [`Dockerfile`](Dockerfile) for exactly what this does
and doesn't package — no network port is exposed, because there is no
network listener yet):

```
docker build -t veritas-node -f mesh/Dockerfile mesh/
docker run -i --rm veritas-node < attestations.jsonl
```

**Note:** the Dockerfile above was written and its build steps verified
individually (the exact `go build` command it uses, with the same flags,
was run standalone) in this project's dev sandbox, which does not have a
working Docker daemon available to run `docker build` itself end-to-end.
If this is the first time it's actually been built, treat that build as
real, first-time verification, not a formality — report back if it fails
so this note can be corrected.
