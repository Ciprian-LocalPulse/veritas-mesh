// Attestation type, hand-mirrored from attestation.proto /
// core/src/attestation.rs. See package README: should eventually be
// generated from proto/veritas/v1/*.proto instead.

export interface Attestation {
  ruleId: string;
  ruleVersion: string;
  proverIdentity: string;
  eventTimestampUnix: number;
  commitmentScheme: string;
  commitmentValue: Uint8Array;
  proof: Uint8Array;
  signature: Uint8Array;
}

/** Dedup key -- matches mesh/internal/storage.Attestation.Key() (hex of signature). */
export function attestationKey(a: Attestation): string {
  return Array.from(a.signature)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
