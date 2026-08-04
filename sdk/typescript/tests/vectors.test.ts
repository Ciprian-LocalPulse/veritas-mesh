import { describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { RuleViolation, checkTransactionThreshold } from "../src/rules";

// Same fixture used by sdk/python/tests/test_vectors.py and, in spirit, by
// core/tests/roundtrip.rs -- this is the actual cross-language
// interoperability check, not a documentation exercise.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectorsPath = path.resolve(__dirname, "../../../core/tests/vectors/banking-basel-iii.json");

interface Vector {
  name: string;
  input: {
    transaction_amount_minor: number;
    risk_adjusted_threshold_minor: number;
    customer_id_hash_hex: string;
  };
  expect_pass: boolean;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe("cross-language vectors: banking-basel-iii", () => {
  if (!existsSync(vectorsPath)) {
    it.skip(`vectors file not found at ${vectorsPath}`, () => {});
    return;
  }

  const data = JSON.parse(readFileSync(vectorsPath, "utf-8")) as { vectors: Vector[] };

  for (const vector of data.vectors) {
    it(`matches Rust's expectation for "${vector.name}"`, () => {
      const input = {
        transactionAmountMinor: BigInt(vector.input.transaction_amount_minor),
        riskAdjustedThresholdMinor: BigInt(vector.input.risk_adjusted_threshold_minor),
        customerIdHash: hexToBytes(vector.input.customer_id_hash_hex),
      };

      if (vector.expect_pass) {
        expect(() => checkTransactionThreshold(input)).not.toThrow();
      } else {
        expect(() => checkTransactionThreshold(input)).toThrow(RuleViolation);
      }
    });
  }
});
