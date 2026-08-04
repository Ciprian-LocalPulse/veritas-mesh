# RFC 0004: Verifier API

- **Status:** Draft
- **Author(s):** Ciprian Ştefan Pleşca
- **Discussion:** <link to the pull request once opened>

## Summary

This RFC proposes normativizing the Verifier-facing gRPC surface already
drafted in
[`proto/veritas/v1/verifier_service.proto`](../proto/veritas/v1/verifier_service.proto) —
`Verify`, `VerifyBatch`, `GetRuleModule`, `SubscribeAttestations` — as
`veritas.v1.VerifierService`, and defines the semantics an implementation
must satisfy that the `.proto` file's types alone cannot express: error
taxonomy, authentication and authorization posture, the exact meaning of
"independence" for `Verify` as required by
[`spec/PROTOCOL_SPEC.md`](../spec/PROTOCOL_SPEC.md) Design Constraint 3,
and the availability posture required against the network adversary in
[`spec/THREAT_ANALYSIS.md`](../spec/THREAT_ANALYSIS.md) §2.

## Motivation

`verifier_service.proto` already states, in its own comment, that "every
method here has a real handler in `mesh/internal`" — that is aspirational,
not current: `mesh/README.md` marks the whole package **"not started"**,
and `mesh/internal/` today contains `discovery`, `storage`, and `gossip`
packages with no gRPC server bound to any of them. So this RFC is not
documenting an existing API; it is the specification that a first `mesh/`
implementation must be written against, which is why it is sequenced here
rather than after `mesh/` exists — writing the server first and the RFC
second would make the RFC a description of one implementation's incidental
choices rather than a normative contract.

This RFC is also blocked, in part, on RFC 0001: the `Verify` RPC's request
and response are only as meaningful as the `Attestation` format they carry,
and RFC 0001 has not been accepted (its own header still says "Draft," and
`attestation.proto` still carries the "DRAFT — NOT A STABLE WIRE FORMAT"
notice). This RFC proceeds anyway, because the *API contract* — what a
call means, what it promises, what can go wrong — is largely orthogonal to
whether `proof_system_id` says `"pending-rfc-0002"` or a concrete value;
where the two do interact, this RFC says so explicitly and marks that
interaction as an open question rather than guessing at RFC 0001's outcome.

## Detailed Design

### Scope of this RFC

This RFC fixes the **behavioral contract** of `VerifierService` — what
each RPC promises, how it fails, and what a caller may assume — not the
Go package layout of a specific `mesh/` implementation. A conformant
Verifier could be the eventual `mesh/` node, a standalone verifier used by
a regulator with no mesh participation at all, or a third-party
reimplementation; this RFC is written so that all three are valid.

### 4.1 `Verify` — single-attestation verification

**Preconditions the caller may rely on:** none beyond a well-formed
`Attestation` message. Per Design Constraint 1 and 2 in `PROTOCOL_SPEC.md`,
`Verify` MUST NOT require prior interaction with the Prover and MUST NOT
require any private input — this RFC treats those as caller-visible
guarantees, not merely implementation notes, meaning a conformant server
that requires either is a protocol violation, not an implementation
choice, and should be rejected in conformance testing.

**Response semantics:**

- `valid = true` MUST mean: the signature (field 7 of the RFC-0001
  attestation) verifies against `prover_identity`, AND `proof` is valid
  for `rule_id@rule_version`'s published circuit per `GetRuleModule`,
  AND — new in this RFC, not stated in the current `.proto` comment —
  `rule_id@rule_version` resolves to a rule module manifest that the
  Verifier itself has fetched or cached, never one supplied by the
  caller alongside the attestation. A `Verify` implementation that
  trusts a caller-supplied manifest instead of its own `GetRuleModule`
  state is not independent of that caller, which breaks Design
  Constraint 3 the moment the caller and the manifest source are the
  same untrusted party.
- `valid = false` with `reason` populated MUST distinguish, in the
  `reason` string's first token (machine-parseable prefix, human-readable
  remainder), at minimum these cases, because a Prover debugging a
  rejected attestation needs to know which one it hit:
  - `SIGNATURE_INVALID` — signature does not verify.
  - `PROOF_INVALID` — signature is fine, proof does not verify against
    the rule module's circuit.
  - `RULE_MODULE_UNKNOWN` — `rule_id@rule_version` has no manifest this
    Verifier can find (distinct from `PROOF_INVALID`; this is "I cannot
    check this," not "I checked and it's wrong," and the two must never
    be conflated into a single generic rejection, since a Prover cannot
    distinguish a real forgery from a not-yet-propagated rule module
    without this split).
  - `FORMAT_INVALID` — the `Attestation` message itself doesn't satisfy
    RFC 0001's shape (missing required field, unknown `format_version`).
- gRPC-level errors (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, etc.) are
  transport/availability failures, not verification outcomes, and MUST
  NOT be reported as `valid = false` — collapsing "I could not complete
  verification" into "verification failed" is indistinguishable, from a
  Prover's perspective, from the Verifier lying about a real proof
  failure, which is exactly the ambiguity a network adversary (in scope
  per `THREAT_ANALYSIS.md` §2) would want to exploit to make legitimate
  attestations look forged.

### 4.2 `VerifyBatch`

Same per-item semantics as `Verify`, with one added normative rule not
implied by the `.proto` file: **`VerifyBatchResponse.results` MUST be
computed as if each item were an independent `Verify` call** — no
cross-item short-circuiting (e.g., rejecting the whole batch because one
attestation references an unknown rule module) and no cross-item state
leakage (verifying item N must not be influenced by whether item N-1 was
valid). This matters specifically for the gossip-relay use case named in
the `.proto` file's own comment: a relay validating a backlog must get a
result set it can act on item-by-item, not an all-or-nothing batch
outcome.

### 4.3 `GetRuleModule`

Returns a `RuleModuleManifest` (per `rule_module.proto`). This RFC adds
one requirement the `.proto` file doesn't state: **a Verifier MUST reject,
not silently accept, a manifest whose `publisher_signature` does not
verify against a rule authority it recognizes**, before using that
manifest to accept or reject any `Verify` call — otherwise "malicious rule
authority" (`THREAT_ANALYSIS.md` §2's fourth adversary row) becomes
trivial: publish a bad manifest, have it silently accepted by every
Verifier that happens to call `GetRuleModule` against your node. This RFC
does not, however, specify *which* rule authorities a given Verifier
should recognize — that's deliberately a Verifier-local trust policy
(consistent with `PROTOCOL_SPEC.md` §5 step 6's existing statement that
policy is never protocol-level), tracked as an open question below rather
than decided here.

### 4.4 `SubscribeAttestations`

A server-streaming RPC. Two behaviors this RFC fixes that the `.proto`
comment leaves unstated:

- The stream MUST only emit attestations that have already passed this
  same server's own `Verify` logic — `SubscribeAttestations` is not a
  raw gossip firehose; it's a stream of things this Verifier is willing
  to also vouch for on a subsequent direct `Verify` call. A subscriber
  relying on the stream as an implicit verification is a documented
  anti-pattern (see Drawbacks), but making the stream pre-filtered at
  least keeps a naive subscriber's exposure to attestations for unknown
  or malformed rule modules at zero, rather than passing that burden on.
- Reconnection after a dropped stream is the subscriber's
  responsibility; the server is not required to buffer and replay missed
  attestations. A subscriber needing a durable, resumable feed should use
  `VerifyBatch` against `mesh/`'s storage layer (already real, per
  `STATUS.md`) rather than treating `SubscribeAttestations` as that
  layer.

### 4.5 Authentication and authorization

Not addressed at all in the current `.proto` file. This RFC proposes:
`Verify`, `VerifyBatch`, and `GetRuleModule` MUST be callable without
client authentication — per Design Constraint 1, any party must be able
to verify without the Prover's (or anyone else's) participation, and
requiring a credential to call `Verify` would make "who is allowed to
check compliance" a gate the protocol itself imposes, which is out of
scope per `PROTOCOL_SPEC.md` §7's non-goals. `SubscribeAttestations` MAY
be rate-limited or require a lightweight API credential purely for
operational reasons (protecting a public node's bandwidth), but that
credential MUST NOT gate `Verify` — an operator choosing to firewall
`Verify` entirely is choosing to not run a public Verifier, which is a
deployment decision this RFC does not restrict, but it must not be
achievable by silently degrading `Verify` behind an undocumented
credential check.

### 4.6 Availability posture

`THREAT_ANALYSIS.md` §1 lists "protocol availability" as an asset and §2
names a network adversary whose concern is censorship of attestation
propagation. This RFC does not attempt to solve that at the API layer —
no consensus, no leader election, nothing resembling the non-goals in
`PROTOCOL_SPEC.md` §7 — but it does require that `VerifierService` be
statelessly horizontally scalable (no RPC's correctness may depend on
being served by a specific node instance), so that availability is an
infrastructure problem an operator can solve with ordinary replication,
not a protocol-level single-point-of-failure baked into the API shape.

## Drawbacks

- Fixing `reason` string prefixes (`SIGNATURE_INVALID`, `PROOF_INVALID`,
  `RULE_MODULE_UNKNOWN`, `FORMAT_INVALID`) as a string convention rather
  than a proto `enum` is easier to extend without a schema change, but is
  also easier for a careless implementation to get wrong (typo a prefix,
  break every downstream parser silently) than an enum would be. This RFC
  accepts that tradeoff for now and flags it as a candidate MINOR
  amendment once real implementation experience exists (Roadmap Phase 2),
  consistent with RFC 0001's own extensibility rule.
- The pre-filtering requirement on `SubscribeAttestations` (§4.4) means a
  Verifier with a stale or incomplete rule-module cache will silently drop
  attestations from its stream rather than surfacing them as
  "unverifiable, here they are anyway" — a subscriber wanting the raw feed
  has no way to get it from this API. Accepted here because a raw,
  unfiltered gossip firehose is exactly what `mesh/internal/gossip`
  already provides at a lower layer (per `STATUS.md`); this RPC is
  deliberately the filtered view on top of it, not a duplicate of it.
- This RFC does not resolve rule-authority trust policy (§4.3), which
  means two conformant Verifiers with different trusted-authority lists
  can legitimately disagree on `valid` for the same attestation —
  narrowing, not violating, Design Constraint 3's independence
  requirement (independent verifiers agree given the *same* trust
  inputs), but a naive reader of Constraint 3 could mistake this for a
  violation if the distinction isn't stated plainly, so it's stated
  plainly here.

## Alternatives Considered

- **REST/JSON instead of gRPC.** Rejected: the `.proto` files already
  exist and are referenced from `sdk/README.md`'s codegen plan; switching
  transport now would be a larger, unrelated RFC, not a refinement of
  this one.
- **Making `Verify` stateful — cache verification results server-side and
  let a caller ask "have you seen this attestation before" as a cheaper
  call than full `Verify`.** Rejected for this RFC: it's a reasonable
  optimization but couples the API's correctness story to a cache's
  correctness, and this RFC would rather fix the acyclic per-call
  semantics first and treat caching as a pure implementation detail
  invisible to the contract, addressable later without an RFC (per RFC
  0001's own MINOR/MAJOR distinction, an internal cache is not
  protocol-visible at all).
- **Requiring authentication on all four RPCs, including `Verify`, and
  handling "anyone can verify" as an allow-all default credential
  instead.** Rejected: this achieves the same behavior by default but
  makes "public verifiability" a configuration choice rather than a
  protocol guarantee, which invites exactly the kind of silent
  degradation §4.5 is trying to foreclose.

## Impact on Existing Work

`verifier_service.proto` and `rule_module.proto` already match this RFC's
RPC shapes; no proto field changes are required. What changes:

- The `.proto` files' header comments claiming "every method here has a
  real handler in `mesh/internal`" should be corrected to reflect
  `mesh/README.md`'s actual "not started" status, since this RFC's
  acceptance does not itself create that handler — it specifies what the
  handler must do once `mesh/` Phase 5 work begins.
- `mesh/internal/gossip` and `mesh/internal/storage` are unaffected in
  their current (non-network-backed) form; this RFC constrains the
  eventual gRPC layer that will sit in front of them, not their internal
  logic.
- No `core/`, `sdk/*/`, or `dashboard/` code currently calls any of these
  RPCs (per `STATUS.md`, there is no network transport anywhere yet), so
  nothing existing breaks.

## Open Questions

- **Rule-authority trust policy (§4.3).** Left to a future RFC or to
  `GOVERNANCE.md`: should there be a protocol-recommended default trust
  list (e.g., "trust the authority named in the compliance mapping doc
  under `compliance-mappings/`"), or is this entirely Verifier-operator
  discretion with no recommended default at all?
- **Interaction with RFC 0001's `proof_system_id`/`commitment_scheme_id`
  placeholders.** If RFC 0002 or 0003 lands with a proof/commitment
  system that requires additional per-call parameters beyond opaque bytes
  (e.g., a STARK verifier needing explicit field-size parameters not
  implied by `proof_system_id` alone), does that require amending
  `VerifyRequest`, or can it stay entirely inside the opaque `proof`
  bytes and the rule module's manifest? Deferred until RFC 0002/0003
  converge on a concrete system.
- **Post-quantum transport (mTLS cipher choice, etc.).**
  `THREAT_ANALYSIS.md` §3 explicitly excludes quantum adversaries from
  the current threat model; this RFC does the same for the transport
  layer and does not mandate a specific TLS configuration. Revisit
  together if the threat model's exclusion is ever revisited.
- **Should `VerifyBatch` have a maximum batch size?** Unspecified here.
  An unbounded batch size is a resource-exhaustion vector against the
  availability asset in `THREAT_ANALYSIS.md` §1; a future amendment
  should likely fix a default limit, but this RFC leaves it to
  operational configuration for now rather than picking a number without
  benchmark data (see Roadmap Phase 2 / the benchmarking workstream).
