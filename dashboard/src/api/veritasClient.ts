// veritasClient: typed client for talking to a VerifierService node.
//
// STATUS: hand-written today. Per core/README and proto/buf.gen.yaml, this
// should eventually be REPLACED by generated bindings from
// proto/veritas/v1/*.proto (via the `buf.build/community/timostamm-protobuf-ts`
// plugin) so the wire types can never drift from the .proto source of
// truth. The types below are a manual mirror of attestation.proto and
// verifier_service.proto — if you change one, change the other, exactly
// the drift risk the generated-stubs approach is meant to eliminate.
//
// The HTTP transport here (fetch against a JSON gateway) is also a stand-in
// for a real gRPC-web or grpc-gateway client; no such gateway exists yet
// on the mesh/ side, so calls against a real node will fail today. This
// file exists so AttestationViewer/RuleModuleExplorer have a stable,
// typed interface to develop against.

export interface RuleReference {
  ruleId: string;
  ruleVersion: string;
}

export interface Commitment {
  scheme: string;
  value: Uint8Array;
}

export interface Attestation {
  rule: RuleReference;
  proverIdentity: string;
  eventTimestampUnix: number;
  inputCommitment: Commitment;
  proof: Uint8Array;
  signature: Uint8Array;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
}

export interface RuleModuleManifest {
  rule: RuleReference;
  proofSystem: string;
  circuitDigest: Uint8Array;
  complianceMappingPath: string;
  tractabilityNote: string;
}

export class VeritasClientError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "VeritasClientError";
  }
}

export interface VeritasClientOptions {
  /** Base URL of a grpc-gateway/JSON bridge in front of VerifierService. */
  baseUrl: string;
  fetchImpl?: typeof fetch;
}

/**
 * Thin, typed wrapper over VerifierService's JSON-gateway surface. Every
 * method here corresponds 1:1 to an rpc in
 * proto/veritas/v1/verifier_service.proto.
 */
export class VeritasClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: VeritasClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async verify(attestation: Attestation): Promise<VerifyResult> {
    return this.post<VerifyResult>("/v1/verify", { attestation: encodeAttestation(attestation) });
  }

  async verifyBatch(attestations: Attestation[]): Promise<VerifyResult[]> {
    const body = { attestations: attestations.map(encodeAttestation) };
    const res = await this.post<{ results: VerifyResult[] }>("/v1/verify-batch", body);
    return res.results;
  }

  async getRuleModule(ruleId: string, ruleVersion: string): Promise<RuleModuleManifest> {
    return this.post<RuleModuleManifest>("/v1/rule-module", { ruleId, ruleVersion });
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch (err) {
      throw new VeritasClientError(`network error calling ${path}`, err);
    }
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new VeritasClientError(`${path} returned HTTP ${res.status}: ${text}`);
    }
    return (await res.json()) as T;
  }
}

function encodeAttestation(a: Attestation): unknown {
  return {
    rule: a.rule,
    proverIdentity: a.proverIdentity,
    eventTimestampUnix: a.eventTimestampUnix,
    inputCommitment: { scheme: a.inputCommitment.scheme, value: bytesToBase64(a.inputCommitment.value) },
    proof: bytesToBase64(a.proof),
    signature: bytesToBase64(a.signature),
  };
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
