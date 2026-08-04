// Scenario: one prover-adjacent node gossips an attestation; it must reach
// two independent verifier nodes via the mesh and each must independently
// accept it. This is the "multi-verifier independence" property named in
// spec/PROTOCOL_SPEC.md and whitepaper/Veritas_Mesh_Whitepaper.md — here
// it's exercised as an actual running test, not just a TLA+ property (see
// spec/formal/README.md for the model-checked version of the same idea).
package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/Ciprian-LocalPulse/veritas-mesh/mesh/internal/discovery"
	"github.com/Ciprian-LocalPulse/veritas-mesh/mesh/internal/gossip"
	"github.com/Ciprian-LocalPulse/veritas-mesh/mesh/internal/storage"
)

// acceptAllVerifier is a stand-in for real proof/signature verification
// (which lives in core/ + the Go SDK once proto stubs exist). It accepts
// everything except attestations explicitly tagged "invalid" by the test,
// so tests can exercise both the accept and reject paths through gossip
// without needing a real cryptographic proof end-to-end here.
type fakeVerifier struct {
	rejectRuleIDs map[string]bool
}

func (v *fakeVerifier) Verify(a storage.Attestation) error {
	if v.rejectRuleIDs[a.RuleID] {
		return errors.New("fake verifier: rule_id marked invalid for this test")
	}
	return nil
}

// inProcessTransport delivers directly to the target node's Receive,
// simulating a network without needing real sockets. Good enough to prove
// the gossip fanout + dedup logic is correct; a real Transport (TCP/QUIC)
// is a separate, later concern (see gossip.go's Transport interface doc).
type inProcessTransport struct {
	nodesByPeerID map[string]*gossip.Node
}

func (t *inProcessTransport) Send(ctx context.Context, peer discovery.Peer, a storage.Attestation) error {
	target, ok := t.nodesByPeerID[peer.ID]
	if !ok {
		return errors.New("in-process transport: unknown peer")
	}
	return target.Receive(ctx, a)
}

func sampleAttestation() storage.Attestation {
	return storage.Attestation{
		RuleID:             "banking-basel-iii",
		RuleVersion:        "0.1.0",
		ProverIdentity:     "prover-node-1",
		EventTimestampUnix: 1_700_000_000,
		CommitmentScheme:   "hash-based-v0",
		CommitmentValue:    []byte{1, 2, 3, 4},
		Proof:              []byte{9, 9, 9, 9},
		Signature:          []byte{0xAA, 0xBB, 0xCC, 0xDD}, // stand-in; real sig from core/
	}
}

func TestTwoIndependentVerifiersConverge(t *testing.T) {
	ctx := context.Background()

	storeA, err := storage.NewMemStore("")
	if err != nil {
		t.Fatalf("NewMemStore A: %v", err)
	}
	storeB, err := storage.NewMemStore("")
	if err != nil {
		t.Fatalf("NewMemStore B: %v", err)
	}

	verifier := &fakeVerifier{}
	transport := &inProcessTransport{nodesByPeerID: map[string]*gossip.Node{}}

	peerA := discovery.Peer{ID: "node-a", Address: "in-process:a"}
	peerB := discovery.Peer{ID: "node-b", Address: "in-process:b"}

	nodeA := &gossip.Node{
		Store:     storeA,
		Peers:     discovery.NewStaticSeedList([]discovery.Peer{peerB}),
		Verifier:  verifier,
		Transport: transport,
	}
	nodeB := &gossip.Node{
		Store:     storeB,
		Peers:     discovery.NewStaticSeedList([]discovery.Peer{peerA}),
		Verifier:  verifier,
		Transport: transport,
	}
	transport.nodesByPeerID["node-a"] = nodeA
	transport.nodesByPeerID["node-b"] = nodeB

	att := sampleAttestation()

	// A receives it first (e.g. directly from the prover), should fan out to B.
	if err := nodeA.Receive(ctx, att); err != nil {
		t.Fatalf("nodeA.Receive: %v", err)
	}

	if storeA.Count() != 1 {
		t.Errorf("storeA.Count() = %d, want 1", storeA.Count())
	}
	if storeB.Count() != 1 {
		t.Errorf("storeB.Count() = %d, want 1 (gossip fanout should have reached it)", storeB.Count())
	}

	got, ok := storeB.Get(att.Key())
	if !ok {
		t.Fatal("node B does not have the attestation after gossip")
	}
	if got.RuleID != att.RuleID {
		t.Errorf("node B's copy has RuleID %q, want %q", got.RuleID, att.RuleID)
	}
}

func TestDuplicateGossipDoesNotReFanOut(t *testing.T) {
	ctx := context.Background()
	storeA, _ := storage.NewMemStore("")
	storeB, _ := storage.NewMemStore("")

	sendCount := 0
	counting := &countingTransport{inner: &inProcessTransport{nodesByPeerID: map[string]*gossip.Node{}}, count: &sendCount}

	verifier := &fakeVerifier{}
	peerA := discovery.Peer{ID: "node-a"}
	peerB := discovery.Peer{ID: "node-b"}

	nodeA := &gossip.Node{Store: storeA, Peers: discovery.NewStaticSeedList([]discovery.Peer{peerB}), Verifier: verifier, Transport: counting}
	nodeB := &gossip.Node{Store: storeB, Peers: discovery.NewStaticSeedList([]discovery.Peer{peerA}), Verifier: verifier, Transport: counting}
	counting.inner.(*inProcessTransport).nodesByPeerID["node-a"] = nodeA
	counting.inner.(*inProcessTransport).nodesByPeerID["node-b"] = nodeB

	att := sampleAttestation()

	if err := nodeA.Receive(ctx, att); err != nil {
		t.Fatalf("first Receive: %v", err)
	}
	firstCount := sendCount

	// Deliver the exact same attestation to A again (simulating a slow
	// duplicate gossip message from elsewhere). It's already stored, so
	// this must NOT trigger another fan-out send.
	if err := nodeA.Receive(ctx, att); err != nil {
		t.Fatalf("duplicate Receive: %v", err)
	}
	if sendCount != firstCount {
		t.Errorf("duplicate Receive caused %d additional sends, want 0", sendCount-firstCount)
	}
}

func TestUnverifiableAttestationIsRejectedNotStored(t *testing.T) {
	ctx := context.Background()
	store, _ := storage.NewMemStore("")
	verifier := &fakeVerifier{rejectRuleIDs: map[string]bool{"banking-basel-iii": true}}
	node := &gossip.Node{
		Store:     store,
		Peers:     discovery.NewStaticSeedList(nil),
		Verifier:  verifier,
		Transport: &inProcessTransport{nodesByPeerID: map[string]*gossip.Node{}},
	}

	err := node.Receive(ctx, sampleAttestation())
	if err == nil {
		t.Fatal("expected Receive to reject an unverifiable attestation, got nil error")
	}
	if store.Count() != 0 {
		t.Errorf("store.Count() = %d, want 0 (rejected attestations must not be stored)", store.Count())
	}
}

// countingTransport wraps another Transport and counts Send calls, used to
// assert that duplicate messages don't cause redundant fan-out.
type countingTransport struct {
	inner gossip.Transport
	count *int
}

func (c *countingTransport) Send(ctx context.Context, peer discovery.Peer, a storage.Attestation) error {
	*c.count++
	return c.inner.Send(ctx, peer, a)
}
