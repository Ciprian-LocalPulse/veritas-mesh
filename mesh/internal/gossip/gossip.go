// Package gossip propagates attestations between nodes.
//
// STATUS: real, working, transport-agnostic gossip logic (push-based
// epidemic broadcast with dedup via storage.Store) and unit-tested with an
// in-process fake transport. It is NOT wired to a real network transport
// (TCP/QUIC/libp2p streams) yet — see Transport interface below; a real
// implementation is deferred for the same reason as discovery.go (network
// stack choice deserves its own RFC/PR). mesh/tests/multiverifier_test.go
// exercises this against two in-process nodes to demonstrate the
// propagation + independent-verification property end-to-end without
// needing real sockets.
package gossip

import (
	"context"
	"fmt"

	"github.com/Ciprian-LocalPulse/veritas-mesh/mesh/internal/discovery"
	"github.com/Ciprian-LocalPulse/veritas-mesh/mesh/internal/storage"
)

// Verifier is implemented by whatever validates an attestation before it's
// accepted into local storage and re-gossiped. In production this calls
// out to the proof/signature verification described in core/ (via the Go
// SDK once proto/buf.gen.yaml stubs exist); tests can supply a fake.
type Verifier interface {
	Verify(a storage.Attestation) error
}

// Transport is the pluggable send mechanism. A real implementation sends
// bytes over the network to peer.Address; FakeTransport (in
// gossip_test.go) delivers in-process for testing.
type Transport interface {
	Send(ctx context.Context, peer discovery.Peer, a storage.Attestation) error
}

// Node ties together storage, peer discovery, verification, and transport
// into the actual gossip protocol: on Receive, verify + store + fan-out to
// peers who haven't seen it (best-effort; dedup at the receiving end via
// storage.Store.Put's isNew return means a fully-connected topology still
// converges even with a naive "send to everyone" fanout).
type Node struct {
	Store     storage.Store
	Peers     discovery.Source
	Verifier  Verifier
	Transport Transport

	// Fanout caps how many peers a single Receive call forwards to, so a
	// node with thousands of peers doesn't do thousands of sends per
	// message. 0 means "all peers" (fine for small/test topologies).
	Fanout int
}

// Receive handles an attestation arriving from a peer (or from a local
// prover). It verifies, stores (deduping), and forwards to other peers if
// newly seen. Returns nil for "already had it" (not an error) as well as
// for a successful new-attestation path; only verification/storage
// failures are errors.
func (n *Node) Receive(ctx context.Context, a storage.Attestation) error {
	if err := n.Verifier.Verify(a); err != nil {
		return fmt.Errorf("gossip: rejecting attestation: %w", err)
	}

	isNew, err := n.Store.Put(a)
	if err != nil {
		return fmt.Errorf("gossip: storing attestation: %w", err)
	}
	if !isNew {
		return nil // already propagated this one, don't re-fan-out
	}

	peers := n.Peers.Peers()
	if n.Fanout > 0 && len(peers) > n.Fanout {
		peers = peers[:n.Fanout]
	}
	for _, p := range peers {
		// Best-effort: one slow/unreachable peer shouldn't block the rest.
		// A production implementation would do this concurrently with a
		// bounded worker pool and per-peer backoff; kept sequential here
		// for determinism in tests.
		if err := n.Transport.Send(ctx, p, a); err != nil {
			// Deliberately not returning: gossip protocols are supposed to
			// tolerate individual send failures, that's the whole point of
			// "propagates via multiple paths."
			continue
		}
	}
	return nil
}
