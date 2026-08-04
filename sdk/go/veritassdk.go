// Package veritassdk is the Go client SDK for Veritas Mesh — what an
// external Go application (e.g. a gov-supply-chain integration, per
// compliance-mappings/gov-supply-chain-integrity.md) imports, instead of
// depending on mesh/internal directly (which is intentionally
// unexported/unstable).
//
// STATUS: real, working, hand-written today. Per sdk/README.md this
// package's message types are meant to eventually be generated from
// proto/veritas/v1/*.proto (see proto/buf.gen.yaml) rather than
// hand-mirrored — until that codegen is wired up, keep Attestation here in
// sync with attestation.proto and with mesh/internal/storage.Attestation
// by hand. The rule-check logic mirrors
// core/src/circuits/gov_supply_chain.rs field-for-field so this SDK's
// canonical byte encoding matches Rust's, which is exactly the property
// core/tests/vectors/ exists to pin down and test cross-language.
package veritassdk

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Attestation mirrors proto/veritas/v1/attestation.proto (see mesh's
// storage.Attestation for the same mirror on the node side).
type Attestation struct {
	RuleID             string
	RuleVersion        string
	ProverIdentity     string
	EventTimestampUnix int64
	CommitmentScheme   string
	CommitmentValue    []byte
	Proof              []byte
	Signature          []byte
}

// AuditLogEntry and AuditTrailInput mirror
// core/src/circuits/gov_supply_chain.rs's Rust structs exactly, field
// order included, because canonical byte encoding must match across
// languages for multi-verifier independence to mean anything in practice.
type AuditLogEntry struct {
	SequenceNumber uint64
	EventHash      [32]byte
	PrevEntryHash  [32]byte
}

type AuditTrailInput struct {
	PeriodStartUnix uint64
	PeriodEndUnix   uint64
	Entries         []AuditLogEntry
	GenesisHash     [32]byte
}

const GovSupplyChainRuleID = "gov-supply-chain-integrity"

// CheckAuditTrailIntegrity is the Go implementation of the same predicate
// as Rust's AuditTrailIntegrityRule::check. Keep the two in lockstep; a
// divergence here is exactly the kind of cross-language bug
// core/tests/vectors/ and this package's own tests are meant to catch.
func CheckAuditTrailIntegrity(input AuditTrailInput) error {
	if input.PeriodStartUnix >= input.PeriodEndUnix {
		return fmt.Errorf("%s: period_start_unix must precede period_end_unix", GovSupplyChainRuleID)
	}
	if len(input.Entries) == 0 {
		return fmt.Errorf("%s: empty audit trail for a non-empty period is not attestable as complete", GovSupplyChainRuleID)
	}

	expectedPrev := input.GenesisHash
	for i, entry := range input.Entries {
		if entry.SequenceNumber != uint64(i) {
			return fmt.Errorf("%s: gap or reorder in sequence at index %d (got sequence_number %d)",
				GovSupplyChainRuleID, i, entry.SequenceNumber)
		}
		if entry.PrevEntryHash != expectedPrev {
			return fmt.Errorf("%s: chain break at sequence %d (tampering or missing entry)",
				GovSupplyChainRuleID, entry.SequenceNumber)
		}
		expectedPrev = entryLinkageHash(entry)
	}
	return nil
}

func entryLinkageHash(e AuditLogEntry) [32]byte {
	h := sha256.New()
	var seqBuf [8]byte
	binary.LittleEndian.PutUint64(seqBuf[:], e.SequenceNumber)
	h.Write(seqBuf[:])
	h.Write(e.EventHash[:])
	h.Write(e.PrevEntryHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// CanonicalBytes must byte-for-byte match
// AuditTrailIntegrityRule::canonical_bytes in Rust for the same input.
func CanonicalBytes(input AuditTrailInput) []byte {
	buf := make([]byte, 0, 64)
	buf = appendU64(buf, input.PeriodStartUnix)
	buf = appendU64(buf, input.PeriodEndUnix)
	buf = append(buf, input.GenesisHash[:]...)
	buf = appendU64(buf, uint64(len(input.Entries)))
	for _, e := range input.Entries {
		buf = appendU64(buf, e.SequenceNumber)
		buf = append(buf, e.EventHash[:]...)
		buf = append(buf, e.PrevEntryHash[:]...)
	}
	return buf
}

func appendU64(buf []byte, v uint64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	return append(buf, tmp[:]...)
}

// ErrRuleViolation is returned (wrapped) by rule checks — sentinel so
// callers can errors.Is against it.
var ErrRuleViolation = errors.New("rule violation")
