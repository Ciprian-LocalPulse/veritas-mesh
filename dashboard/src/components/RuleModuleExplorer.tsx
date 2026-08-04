import { useEffect, useState } from "react";
import type { RuleModuleManifest, VeritasClient } from "../api/veritasClient";

export interface RuleModuleExplorerProps {
  ruleId: string;
  ruleVersion: string;
  client: VeritasClient;
}

type LoadState =
  | { kind: "loading" }
  | { kind: "loaded"; manifest: RuleModuleManifest }
  | { kind: "error"; message: string };

/**
 * Fetches and displays a rule module's published manifest so an auditor
 * can confirm exactly which circuit/proof-system an attestation's rule_id
 * maps to, plus the human-readable tractability note carried over from
 * compliance-mappings/*.md at publish time. This is read-only by design —
 * publishing a rule module is a separate, signed, out-of-band operation
 * (see proto/veritas/v1/rule_module.proto's PublishRuleModuleRequest),
 * never something this dashboard does on someone's behalf.
 */
export function RuleModuleExplorer({ ruleId, ruleVersion, client }: RuleModuleExplorerProps) {
  const [state, setState] = useState<LoadState>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });

    client
      .getRuleModule(ruleId, ruleVersion)
      .then((manifest) => {
        if (!cancelled) setState({ kind: "loaded", manifest });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({ kind: "error", message: err instanceof Error ? err.message : String(err) });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [ruleId, ruleVersion, client]);

  if (state.kind === "loading") {
    return <p aria-busy="true">Loading rule module {ruleId}…</p>;
  }
  if (state.kind === "error") {
    return (
      <p role="alert" className="verify-error">
        Could not load rule module {ruleId}: {state.message}
      </p>
    );
  }

  const { manifest } = state;
  return (
    <article className="rule-module-explorer" aria-label={`Rule module ${manifest.rule.ruleId}`}>
      <h3>
        {manifest.rule.ruleId} <span className="muted">v{manifest.rule.ruleVersion}</span>
      </h3>
      <dl>
        <dt>Proof system</dt>
        <dd>{manifest.proofSystem}</dd>

        <dt>Circuit digest (hex)</dt>
        <dd className="mono">{toHex(manifest.circuitDigest)}</dd>

        <dt>Compliance mapping</dt>
        <dd>
          <a href={manifest.complianceMappingPath}>{manifest.complianceMappingPath}</a>
        </dd>

        <dt>Tractability note</dt>
        <dd>{manifest.tractabilityNote}</dd>
      </dl>
    </article>
  );
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
