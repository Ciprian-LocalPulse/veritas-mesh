import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AttestationViewer } from "../src/components/AttestationViewer";
import type { Attestation, VeritasClient } from "../src/api/veritasClient";

function sampleAttestation(): Attestation {
  return {
    rule: { ruleId: "banking-basel-iii", ruleVersion: "0.1.0" },
    proverIdentity: "prover-1",
    eventTimestampUnix: 1_700_000_000,
    inputCommitment: { scheme: "hash-based-v0", value: new Uint8Array([1, 2, 3]) },
    proof: new Uint8Array([9, 9, 9, 9]),
    signature: new Uint8Array([0xaa, 0xbb]),
  };
}

function fakeClient(overrides: Partial<VeritasClient> = {}): VeritasClient {
  return {
    verify: vi.fn().mockResolvedValue({ valid: true }),
    verifyBatch: vi.fn(),
    getRuleModule: vi.fn(),
    ...overrides,
  } as unknown as VeritasClient;
}

describe("AttestationViewer", () => {
  it("renders the attestation's public fields", () => {
    render(<AttestationViewer attestation={sampleAttestation()} client={fakeClient()} />);
    expect(screen.getByText("banking-basel-iii", { exact: false })).toBeTruthy();
    expect(screen.getByText("prover-1")).toBeTruthy();
  });

  it("shows a valid result after clicking verify", async () => {
    const client = fakeClient();
    render(<AttestationViewer attestation={sampleAttestation()} client={client} />);

    fireEvent.click(screen.getByText("Verify against node"));

    await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());
    expect(screen.getByRole("status").textContent).toContain("Valid");
  });

  it("shows an error if the verifier call fails", async () => {
    const client = fakeClient({ verify: vi.fn().mockRejectedValue(new Error("connection refused")) });
    render(<AttestationViewer attestation={sampleAttestation()} client={client} />);

    fireEvent.click(screen.getByText("Verify against node"));

    await waitFor(() => expect(screen.getByRole("alert")).toBeTruthy());
    expect(screen.getByRole("alert").textContent).toContain("connection refused");
  });
});
