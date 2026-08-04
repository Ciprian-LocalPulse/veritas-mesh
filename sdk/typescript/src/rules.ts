// Rule predicate checks, hand-mirrored from core/src/circuits/*.rs.
// Only banking-basel-iii's transaction-threshold rule is implemented here
// today -- see core/src/circuits/banking_basel_iii.rs's module docstring
// for why that's the one rule actually implemented across all languages.
//
// u64 fields use `bigint` (not `number`) throughout: JS numbers lose
// precision above 2^53, which real transaction-amount-in-minor-units
// values can exceed. Silently downgrading to `number` here would be a
// real correctness bug, not just a style choice.

export const RULE_ID_BANKING_BASEL_III = "banking-basel-iii";

export class RuleViolation extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RuleViolation";
  }
}

export interface TransactionThresholdInput {
  transactionAmountMinor: bigint;
  riskAdjustedThresholdMinor: bigint;
  /** Must be exactly 32 bytes. */
  customerIdHash: Uint8Array;
}

function assertValidInput(input: TransactionThresholdInput): void {
  if (input.customerIdHash.length !== 32) {
    throw new RangeError(
      `customerIdHash must be exactly 32 bytes, got ${input.customerIdHash.length}`,
    );
  }
  if (input.transactionAmountMinor < 0n || input.riskAdjustedThresholdMinor < 0n) {
    throw new RangeError("amounts must be non-negative");
  }
}

/**
 * Throws RuleViolation if the transaction exceeds the customer's
 * risk-adjusted threshold. Mirrors TransactionThresholdRule::check in
 * core/src/circuits/banking_basel_iii.rs exactly, including the boundary:
 * exactly-at-threshold passes.
 */
export function checkTransactionThreshold(input: TransactionThresholdInput): void {
  assertValidInput(input);
  if (input.transactionAmountMinor > input.riskAdjustedThresholdMinor) {
    throw new RuleViolation(
      `${RULE_ID_BANKING_BASEL_III}: transaction_amount_minor ` +
        `${input.transactionAmountMinor} exceeds risk_adjusted_threshold_minor ` +
        `${input.riskAdjustedThresholdMinor}`,
    );
  }
}

/**
 * Must byte-for-byte match TransactionThresholdRule::canonical_bytes in
 * Rust: two little-endian u64s followed by the raw 32-byte hash. Pinned
 * cross-language by core/tests/vectors/banking-basel-iii.json (see
 * tests/vectors.test.ts in this package).
 */
export function canonicalBytes(input: TransactionThresholdInput): Uint8Array {
  assertValidInput(input);
  const buf = new Uint8Array(8 + 8 + 32);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, input.transactionAmountMinor, /* littleEndian */ true);
  view.setBigUint64(8, input.riskAdjustedThresholdMinor, true);
  buf.set(input.customerIdHash, 16);
  return buf;
}
