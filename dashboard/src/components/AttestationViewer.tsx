import { useState } from "react";
import type { Attestation, VerifyResult, VeritasClient } from "../api/veritasClient";

export interface AttestationViewerProps {
  attestation: Attestation;
  client: VeritasClient;
}

/**
 * Displays a single attestation's public fields and lets an auditor trigger
 * live verification against a VerifierService node. Deliberately renders
 * NOTHING beyond what's in the Attestation message itself — per
 * dashboard/README.md, no private data is ever available to this layer by
 * protocol design, so there is nothing to accidentally leak here as long
 * as this component only reads from `attestation`.
 */
export function AttestationViewer({ attestation, client }: AttestationViewerProps) {
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [status, setStatus] = useState<"idle" | "checking" | "done" | "error">("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  async function handleVerify() {
    setStatus("checking");
    setErrorMessage(null);
    try {
      const res = await client.verify(attestation);
      setResult(res);
      setStatus("done");
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
      setStatus("error");
    }
  }

  return (
    <section className="attestation-viewer" aria-label="Attestation details">
      <dl>
        <dt>Rule</dt>
        <dd>
          {attestation.rule.ruleId} <span className="muted">v{attestation.rule.ruleVersion}</span>
        </dd>

        <dt>Prover identity</dt>
        <dd>{attestation.proverIdentity}</dd>

        <dt>Event timestamp</dt>
        <dd>{new Date(attestation.eventTimestampUnix * 1000).toISOString()}</dd>

        <dt>Commitment scheme</dt>
        <dd>{attestation.inputCommitment.scheme}</dd>

        <dt>Commitment (hex)</dt>
        <dd className="mono">{toHex(attestation.inputCommitment.value)}</dd>

        <dt>Proof (hex, truncated)</dt>
        <dd className="mono">{toHex(attestation.proof).slice(0, 32)}…</dd>
      </dl>

      <button onClick={handleVerify} disabled={status === "checking"}>
        {status === "checking" ? "Verifying…" : "Verify against node"}
      </button>

      {status === "done" && result && (
        <p role="status" className={result.valid ? "verify-ok" : "verify-fail"}>
          {result.valid ? "✓ Valid" : `✗ Invalid${result.reason ? `: ${result.reason}` : ""}`}
        </p>
      )}
      {status === "error" && errorMessage && (
        <p role="alert" className="verify-error">
          Could not reach verifier: {errorMessage}
        </p>
      )}
    </section>
  );
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
