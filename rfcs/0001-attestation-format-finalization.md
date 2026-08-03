# RFC 0001: Attestation Format Finalization

- **Status:** Draft
- **Author(s):** Ciprian Ştefan Pleşca
- **Discussion:** <link to the pull request once opened>

## Summary

This RFC proposes freezing the wire format of the `Attestation` message
defined in [`proto/veritas/v1/attestation.proto`](../proto/veritas/v1/attestation.proto)
as `v1`, closing the gap between the *illustrative, explicitly-draft*
schema that exists today and the *normative* one required by
[`spec/PROTOCOL_SPEC.md`](../spec/PROTOCOL_SPEC.md) §4, and defines the
process by which the format may later change without breaking existing
verifiers.

## Motivation

`PROTOCOL_SPEC.md` §4 already lists the required fields of an attestation
in prose (`rule_id`, `rule_version`, `prover_identity`, `timestamp`,
`input_commitment`, `proof`, `signature`), and `proto/veritas/v1/attestation.proto`
already has a draft mirroring that table. But the proto file's own header
marks it non-normative, and [`sdk/README.md`](../sdk/README.md) explicitly
blocks SDK generation until "the schema is stabilized through the RFC
process" — meaning no downstream consumer (an SDK, `core/`, `mesh/`) can be
built on a stable foundation until this RFC (or one like it) is accepted.
This is the first of the three RFCs flagged as needed in
[`rfcs/README.md`](../rfcs/README.md) and in
[`ROADMAP.md`](../ROADMAP.md) Phase 0, and the other two open RFCs
(0002, 0003) both produce fields that live inside this format, so it is
sequenced first.

## Detailed Design

### Scope of this RFC

This RFC freezes the **shape and semantics** of the attestation message —
field names, types, and required/optional status — as `veritas.v1`. It
explicitly does **not** resolve the concrete cryptographic content of two
fields:

- `proof` — the byte encoding depends on the proof system selected by
  [RFC 0002](0002-proof-system-selection.md). This RFC fixes the field as
  `bytes proof = 6;` with an accompanying `string proof_system_id` tag
  field so a verifier can dispatch to the correct verification routine
  without needing to be told out-of-band which system produced a given
  attestation. Multiple proof systems co-existing during a transition
  period (e.g. a SNARK-to-STARK migration) is expected, not an edge case.
- `input_commitment` — the byte encoding depends on the scheme selected by
  [RFC 0003](0003-commitment-scheme-selection.md). Same tagging approach:
  a `string commitment_scheme_id` field alongside the opaque bytes.

### Fields (normative once accepted)

| # | Field | Type | Required | Notes |
|---|---|---|---|---|
| 1 | `rule_id` | `string` | Yes | Matches the identifier a rule module is published under in `compliance-mappings/`. |
| 2 | `rule_version` | `string` | Yes | Semver, per `PROTOCOL_SPEC.md` §6. |
| 3 | `prover_identity` | `bytes` | Yes | Public key of the Prover institution, format tied to [RFC 0003 signature-scheme companion, if split out] or defaulting to Ed25519 raw public key bytes (32 bytes) per `PROTOCOL_SPEC.md` §3.3's current default candidate. |
| 4 | `timestamp` | `int64` | Yes | Unix seconds (UTC) of when the underlying institutional action occurred — explicitly **not** proof-generation time, per `PROTOCOL_SPEC.md` §4. |
| 5 | `input_commitment` | `bytes` | Yes | Opaque; scheme identified by `commitment_scheme_id` (below). |
| 5a | `commitment_scheme_id` | `string` | Yes | e.g. `"pending-rfc-0003"` until RFC 0003 lands, then the accepted scheme's identifier. |
| 6 | `proof` | `bytes` | Yes | Opaque; system identified by `proof_system_id` (below). |
| 6a | `proof_system_id` | `string` | Yes | e.g. `"pending-rfc-0002"` until RFC 0002 lands. |
| 7 | `signature` | `bytes` | Yes | Prover's signature over the serialized encoding of fields 1–6a, using the deterministic encoding rule below. |
| 8 | `format_version` | `string` | Yes | Fixed to `"veritas.v1"` for any attestation conformant with this RFC. |

### Deterministic encoding for signing

Field 7 signs "the serialized encoding of fields 1–6a" — this must be
byte-for-byte deterministic across implementations, or two conformant
implementations could disagree on whether a signature is valid over the
*same logical attestation*, which would itself be a Design Constraint 3
(multi-verifier independence) violation at the encoding layer rather than
the cryptographic layer. This RFC proposes Protocol Buffers' deterministic
serialization mode (fields in ascending tag order, canonical varint/byte
encoding, no unknown fields) as the signing input, matching the approach
already used by systems like Google's Certificate Transparency logs for
the same reason.

### Extensibility rule (ties to `PROTOCOL_SPEC.md` §6 versioning)

- Adding an **optional** field with a new tag number is a MINOR change and
  does not require a new RFC, only a CODEOWNERS-reviewed PR against
  `proto/`.
- Changing the meaning of an existing tag number, removing a required
  field, or changing `format_version`'s semantics is a MAJOR change and
  requires a new RFC, per the versioning rule already stated in
  `PROTOCOL_SPEC.md` §6.

## Drawbacks

- Freezing the shape now, before `core/` has any real implementation
  experience (Roadmap Phase 2 has not started), risks freezing a field
  layout that turns out to be awkward once a real proof system is wired
  in — for example, some proof systems produce structured proof objects
  (multiple sub-components) rather than a single opaque byte blob, which
  the flat `bytes proof` field would force into an implementation-specific
  sub-encoding rather than a protocol-visible one.
- The two "pending-RFC" placeholder identifiers (`proof_system_id`,
  `commitment_scheme_id`) mean this RFC alone does not actually unblock
  SDK generation per `sdk/README.md` — RFC 0002 and 0003 still gate that.
  Accepting this RFC alone produces a format that is stable in *shape* but
  not yet usable end-to-end.

## Alternatives Considered

- **Do nothing — leave the proto file as a non-normative draft indefinitely.**
  Rejected: this is the status quo, and it is what is currently blocking
  RFC 0002 and 0003 from having a concrete field to slot their output
  into, and blocking `sdk/README.md`'s stated precondition from ever being
  satisfiable.
- **Wait for RFC 0002 and 0003 to land first, then write this RFC to match
  their concrete output.** Considered, but rejected in favor of the order
  proposed here: the field *shape* (is there a commitment field, what
  else is signed, how is the signing input encoded) does not depend on
  which concrete scheme is chosen, and fixing the shape first gives 0002
  and 0003 authors a fixed target to slot their output into, rather than
  each of them separately needing to also design the framing around their
  field.
- **Self-describing / tagged-union encoding for `proof` and
  `input_commitment` instead of an opaque-bytes-plus-id-string pair**
  (e.g. a `oneof` over known proof systems). Rejected for now: a `oneof`
  requires enumerating known systems in the schema itself, which
  re-couples the format to proof-system selection — exactly the coupling
  this RFC is trying to avoid so that RFC 0002 can be decided
  independently, including the possibility of supporting more than one
  proof system concurrently during a future migration.

## Impact on Existing Work

No implemented code exists yet in `core/`, `mesh/`, `dashboard/`, or
`sdk/` (per `ROADMAP.md` Phase 0/2 status), so this RFC breaks nothing in
production. It does formally supersede the "explicitly draft, non-final"
status currently marked in the header of
`proto/veritas/v1/attestation.proto` — that header should be updated to
reference this RFC once accepted, per `PROTOCOL_SPEC.md` §4's own
statement that the schema "should not be treated as a stable wire format
until an RFC declares it so."

## Open Questions

- Should `prover_identity` itself be tagged with a key-type identifier
  (mirroring `proof_system_id`/`commitment_scheme_id`), given
  `PROTOCOL_SPEC.md` §3.3 also marks the signature scheme as not yet
  finalized? Left open pending that RFC; a follow-up amendment to this
  RFC may be needed once the signature scheme is chosen, if it turns out
  Ed25519 is not the final choice.
- Should attestations support an optional `expires_at` or `revoked_at`
  field for compliance rules with a validity window (e.g. an annual audit
  attestation)? Deferred — no rule module in `compliance-mappings/` has
  been drafted with this requirement yet, and adding it later is a MINOR,
  non-breaking change under the extensibility rule above.
- Multi-signature attestations (e.g. co-signed by a rule authority and a
  Prover) are out of scope for this RFC and would need their own proposal
  if a future rule module requires them.
