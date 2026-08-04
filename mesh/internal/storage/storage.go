// Package storage provides local persistence for attestations received or
// produced by this node.
//
// STATUS: real, working implementation using an in-process, mutex-guarded
// map plus optional JSON-lines disk persistence. This is intentionally NOT
// a production datastore (no compaction, no indexes beyond rule_id, no
// concurrent-writer safety across processes) — it exists so gossip.go and
// the node's RPC handlers have something real to call, and so
// multiverifier_test.go can exercise a genuine end-to-end path. Swapping
// in BadgerDB/SQLite/etc. behind the same Store interface later shouldn't
// require touching callers.
package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Attestation mirrors proto/veritas/v1/attestation.proto's Attestation
// message (field-for-field) until the generated Go stubs (see
// proto/buf.gen.yaml) are wired in. Keep these in sync by hand until then.
type Attestation struct {
	RuleID             string `json:"rule_id"`
	RuleVersion        string `json:"rule_version"`
	ProverIdentity     string `json:"prover_identity"`
	EventTimestampUnix int64  `json:"event_timestamp_unix"`
	CommitmentScheme   string `json:"commitment_scheme"`
	CommitmentValue    []byte `json:"commitment_value"`
	Proof              []byte `json:"proof"`
	Signature          []byte `json:"signature"`
}

// Key returns a storage/gossip dedup key for this attestation. Two
// attestations with the same signature are the same attestation — the
// signature already commits to every other field (see
// core/src/attestation.rs::signing_bytes), so it's a sound dedup key
// without re-hashing.
func (a *Attestation) Key() string {
	return fmt.Sprintf("%x", a.Signature)
}

// Store is the interface gossip.go and the RPC layer depend on, so the
// backing implementation can change without touching either.
type Store interface {
	Put(a Attestation) (isNew bool, err error)
	Get(key string) (Attestation, bool)
	ListByRule(ruleID string) []Attestation
	Count() int
}

// MemStore is a real, working, concurrency-safe in-memory store with
// optional append-only JSON-lines persistence to disk (so a node doesn't
// lose everything on restart during development). Not durable against
// crashes mid-write in any ACID sense — that's out of scope for a
// scaffold.
type MemStore struct {
	mu   sync.RWMutex
	data map[string]Attestation
	// byRule indexes keys per rule_id for ListByRule without a full scan.
	byRule map[string]map[string]struct{}

	persistPath string
}

// NewMemStore creates a store. If persistPath is non-empty, existing
// entries are loaded from it on startup and every Put is appended to it.
func NewMemStore(persistPath string) (*MemStore, error) {
	s := &MemStore{
		data:        make(map[string]Attestation),
		byRule:      make(map[string]map[string]struct{}),
		persistPath: persistPath,
	}
	if persistPath == "" {
		return s, nil
	}
	f, err := os.OpenFile(persistPath, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("storage: opening persist file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var a Attestation
		if err := json.Unmarshal(scanner.Bytes(), &a); err != nil {
			return nil, fmt.Errorf("storage: corrupt persist line: %w", err)
		}
		s.indexLocked(a)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("storage: reading persist file: %w", err)
	}
	return s, nil
}

func (s *MemStore) indexLocked(a Attestation) {
	key := a.Key()
	s.data[key] = a
	if s.byRule[a.RuleID] == nil {
		s.byRule[a.RuleID] = make(map[string]struct{})
	}
	s.byRule[a.RuleID][key] = struct{}{}
}

// Put stores the attestation if not already present. Returns isNew=false
// for duplicates without error — gossip protocols see the same message
// from multiple peers constantly, that's not a failure condition.
func (s *MemStore) Put(a Attestation) (bool, error) {
	key := a.Key()

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[key]; exists {
		return false, nil
	}
	s.indexLocked(a)

	if s.persistPath != "" {
		f, err := os.OpenFile(s.persistPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return true, fmt.Errorf("storage: opening persist file for append: %w", err)
		}
		defer f.Close()
		line, err := json.Marshal(a)
		if err != nil {
			return true, fmt.Errorf("storage: marshaling attestation: %w", err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return true, fmt.Errorf("storage: writing persist line: %w", err)
		}
	}
	return true, nil
}

func (s *MemStore) Get(key string) (Attestation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.data[key]
	return a, ok
}

func (s *MemStore) ListByRule(ruleID string) []Attestation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := s.byRule[ruleID]
	out := make([]Attestation, 0, len(keys))
	for k := range keys {
		out = append(out, s.data[k])
	}
	return out
}

func (s *MemStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}
