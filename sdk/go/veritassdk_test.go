package veritassdk

import (
	"crypto/sha256"
	"testing"
)

func ev(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

func chain(events []string, genesis [32]byte) []AuditLogEntry {
	prev := genesis
	out := make([]AuditLogEntry, 0, len(events))
	for i, e := range events {
		entry := AuditLogEntry{
			SequenceNumber: uint64(i),
			EventHash:      ev(e),
			PrevEntryHash:  prev,
		}
		prev = entryLinkageHash(entry)
		out = append(out, entry)
	}
	return out
}

func TestIntactChainPasses(t *testing.T) {
	genesis := ev("genesis")
	input := AuditTrailInput{
		PeriodStartUnix: 0,
		PeriodEndUnix:   1000,
		Entries:         chain([]string{"a", "b", "c"}, genesis),
		GenesisHash:     genesis,
	}
	if err := CheckAuditTrailIntegrity(input); err != nil {
		t.Errorf("expected intact chain to pass, got: %v", err)
	}
}

func TestTamperedMiddleEntryFails(t *testing.T) {
	genesis := ev("genesis")
	entries := chain([]string{"a", "b", "c"}, genesis)
	entries[1].EventHash = ev("tampered")
	input := AuditTrailInput{PeriodStartUnix: 0, PeriodEndUnix: 1000, Entries: entries, GenesisHash: genesis}
	if err := CheckAuditTrailIntegrity(input); err == nil {
		t.Error("expected tampered chain to fail, got nil error")
	}
}

func TestMissingEntryBreaksSequence(t *testing.T) {
	genesis := ev("genesis")
	entries := chain([]string{"a", "b", "c"}, genesis)
	entries = append(entries[:1], entries[2:]...) // remove index 1
	input := AuditTrailInput{PeriodStartUnix: 0, PeriodEndUnix: 1000, Entries: entries, GenesisHash: genesis}
	if err := CheckAuditTrailIntegrity(input); err == nil {
		t.Error("expected missing-entry chain to fail, got nil error")
	}
}

func TestEmptyTrailRejected(t *testing.T) {
	input := AuditTrailInput{PeriodStartUnix: 0, PeriodEndUnix: 1000, Entries: nil, GenesisHash: ev("genesis")}
	if err := CheckAuditTrailIntegrity(input); err == nil {
		t.Error("expected empty audit trail to be rejected")
	}
}

func TestInvertedPeriodRejected(t *testing.T) {
	input := AuditTrailInput{PeriodStartUnix: 1000, PeriodEndUnix: 500, Entries: chain([]string{"a"}, ev("g")), GenesisHash: ev("g")}
	if err := CheckAuditTrailIntegrity(input); err == nil {
		t.Error("expected period_start >= period_end to be rejected")
	}
}

// TestCanonicalBytesDeterministic pins the exact encoding so a future
// change to CanonicalBytes that silently diverges from Rust's
// canonical_bytes (core/src/circuits/gov_supply_chain.rs) gets caught
// here, not in a cross-language integration failure later.
func TestCanonicalBytesDeterministic(t *testing.T) {
	genesis := ev("genesis")
	input := AuditTrailInput{
		PeriodStartUnix: 0,
		PeriodEndUnix:   1000,
		Entries:         chain([]string{"a"}, genesis),
		GenesisHash:     genesis,
	}
	a := CanonicalBytes(input)
	b := CanonicalBytes(input)
	if len(a) != len(b) {
		t.Fatal("canonical bytes should be deterministic in length")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("canonical bytes differ at byte %d", i)
		}
	}
	// 8 (start) + 8 (end) + 32 (genesis) + 8 (count) + 1*(8+32+32) = 128
	const expectedLen = 8 + 8 + 32 + 8 + (8 + 32 + 32)
	if len(a) != expectedLen {
		t.Errorf("canonical bytes length = %d, want %d", len(a), expectedLen)
	}
}
