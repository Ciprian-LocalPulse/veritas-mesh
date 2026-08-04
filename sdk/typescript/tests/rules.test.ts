import { describe, expect, it } from "vitest";
import { RuleViolation, checkTransactionThreshold, canonicalBytes } from "../src/rules";

function makeHash(seed: number): Uint8Array {
  return new Uint8Array(32).fill(seed % 256);
}

describe("checkTransactionThreshold", () => {
  it("passes when under threshold", () => {
    expect(() =>
      checkTransactionThreshold({
        transactionAmountMinor: 50000n,
        riskAdjustedThresholdMinor: 100000n,
        customerIdHash: makeHash(1),
      }),
    ).not.toThrow();
  });

  it("passes exactly at threshold", () => {
    expect(() =>
      checkTransactionThreshold({
        transactionAmountMinor: 100000n,
        riskAdjustedThresholdMinor: 100000n,
        customerIdHash: makeHash(1),
      }),
    ).not.toThrow();
  });

  it("throws RuleViolation when over threshold", () => {
    expect(() =>
      checkTransactionThreshold({
        transactionAmountMinor: 100001n,
        riskAdjustedThresholdMinor: 100000n,
        customerIdHash: makeHash(1),
      }),
    ).toThrow(RuleViolation);
  });

  it("rejects a malformed hash length", () => {
    expect(() =>
      checkTransactionThreshold({
        transactionAmountMinor: 1n,
        riskAdjustedThresholdMinor: 2n,
        customerIdHash: new Uint8Array(10),
      }),
    ).toThrow(RangeError);
  });
});

describe("canonicalBytes", () => {
  it("is deterministic and correctly sized", () => {
    const input = {
      transactionAmountMinor: 42n,
      riskAdjustedThresholdMinor: 100n,
      customerIdHash: makeHash(7),
    };
    const a = canonicalBytes(input);
    const b = canonicalBytes(input);
    expect(a).toEqual(b);
    expect(a.length).toBe(8 + 8 + 32);
  });

  it("encodes u64 fields little-endian, matching Rust's to_le_bytes", () => {
    const input = {
      transactionAmountMinor: 1n,
      riskAdjustedThresholdMinor: 0n,
      customerIdHash: new Uint8Array(32),
    };
    const bytes = canonicalBytes(input);
    // 1 as a little-endian u64 => 0x01 followed by seven 0x00 bytes.
    expect(Array.from(bytes.slice(0, 8))).toEqual([1, 0, 0, 0, 0, 0, 0, 0]);
  });
});
