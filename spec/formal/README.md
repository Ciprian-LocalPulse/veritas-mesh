# Formal Verification Artifacts

**Status: not started.** This directory is a placeholder for Phase 1 of the [Roadmap](../../ROADMAP.md).

## Intent

Before the `core/` proof engine is considered stable, the attestation lifecycle described in [`PROTOCOL_SPEC.md`](../PROTOCOL_SPEC.md) is intended to be modeled as a state machine in [TLA+](https://lamport.azurewebsites.net/tla/tla.html) (or an equivalent model checker, chosen via RFC if TLA+ turns out not to be the best fit) and mechanically checked against the three target properties listed in [`THREAT_ANALYSIS.md`](../THREAT_ANALYSIS.md) §5: soundness, zero-knowledge/non-disclosure, and multi-verifier independence.

## Why this comes before implementation

Per Design Goal 5 in the [whitepaper](../../whitepaper/Veritas_Mesh_Whitepaper.md), this project's discipline is to state and check security-relevant properties before writing the code that is supposed to have them — not to write code and assert properties about it afterward. This directory being empty is therefore a meaningful, honest signal about the project's current stage, not an oversight.

## What will land here

- `attestation_lifecycle.tla` — the state machine model
- `attestation_lifecycle.cfg` — model-checking configuration
- A written report translating the model-checking results into plain language for non-formal-methods readers, published alongside the model itself

No file will be added to this directory that has not actually been run through a model checker with the results included in the same pull request.
