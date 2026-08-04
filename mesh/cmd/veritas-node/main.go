// Command veritas-node runs a single mesh node: local storage + gossip +
// static-seed discovery, wired together and listening for attestations.
//
// STATUS: this wires the real packages in internal/ together into a
// runnable binary with a working local flow (feed it an attestation via
// stdin JSON, it verifies-with-a-placeholder/stores/would-fan-out). It
// does NOT open a real network listener yet — there is no Transport
// implementation over TCP/QUIC/libp2p (see internal/gossip's Transport
// interface doc for why that's deliberately deferred). Treat this as the
// wiring skeleton the real network layer plugs into, not a deployable
// node.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Ciprian-LocalPulse/veritas-mesh/mesh/internal/discovery"
	"github.com/Ciprian-LocalPulse/veritas-mesh/mesh/internal/gossip"
	"github.com/Ciprian-LocalPulse/veritas-mesh/mesh/internal/storage"
)

// noopVerifier accepts everything. Replace with a real verifier that calls
// into the Go SDK (pending proto/buf.gen.yaml codegen + core/ FFI or a
// gRPC call to a Rust-backed verification service) before running this
// against untrusted input.
type noopVerifier struct{}

func (noopVerifier) Verify(a storage.Attestation) error {
	if a.RuleID == "" {
		return fmt.Errorf("attestation missing rule_id")
	}
	if len(a.Signature) == 0 {
		return fmt.Errorf("attestation missing signature")
	}
	return nil
	// NOTE: this is a shape check, not a cryptographic verification. See
	// package doc.
}

// noTransport refuses to send anywhere; used until a real network
// transport exists, so misconfiguration fails loudly instead of silently
// pretending to gossip.
type noTransport struct{}

func (noTransport) Send(ctx context.Context, peer discovery.Peer, a storage.Attestation) error {
	return fmt.Errorf("no network transport configured (peer %s); see internal/gossip.Transport doc", peer.ID)
}

func main() {
	persistPath := flag.String("store", "", "path to JSON-lines attestation store (empty = in-memory only)")
	flag.Parse()

	store, err := storage.NewMemStore(*persistPath)
	if err != nil {
		log.Fatalf("veritas-node: initializing storage: %v", err)
	}

	node := &gossip.Node{
		Store:     store,
		Peers:     discovery.NewStaticSeedList(nil), // no peers configured in this scaffold
		Verifier:  noopVerifier{},
		Transport: noTransport{},
	}

	log.Printf("veritas-node: started (storage entries so far: %d)", store.Count())
	log.Printf("veritas-node: reading newline-delimited JSON attestations from stdin (Ctrl-D to stop)")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var a storage.Attestation
		if err := json.Unmarshal(line, &a); err != nil {
			log.Printf("veritas-node: skipping malformed line: %v", err)
			continue
		}
		if err := node.Receive(context.Background(), a); err != nil {
			log.Printf("veritas-node: rejected attestation for rule %q: %v", a.RuleID, err)
			continue
		}
		log.Printf("veritas-node: accepted attestation for rule %q (store now has %d entries)", a.RuleID, store.Count())
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("veritas-node: reading stdin: %v", err)
	}
}
