// Package discovery finds and tracks peer nodes.
//
// STATUS: the peer bookkeeping (Registry) is real and tested. The actual
// network discovery mechanism is a placeholder: production Veritas Mesh
// nodes almost certainly want libp2p (Kademlia DHT + mDNS for local
// discovery, per the whitepaper §6.4), but pulling in
// github.com/libp2p/go-libp2p is a real dependency-management decision
// (pinned version, vendoring strategy, its own transitive graph) that
// belongs in an RFC/PR, not silently added by a scaffold. StaticSeedList
// below is a fully working substitute for development, tests, and small
// deployments: give it a fixed list of peer addresses and it's done.
package discovery

import (
	"sync"
	"time"
)

// Peer is a minimal, transport-agnostic peer record.
type Peer struct {
	ID           string // stable identifier (e.g. hex of the peer's public key)
	Address      string // host:port or multiaddr, depending on transport
	LastSeenUnix int64
}

// Source is what gossip.go depends on. StaticSeedList implements it today;
// a libp2p-backed implementation would implement it tomorrow without
// gossip.go needing to change.
type Source interface {
	Peers() []Peer
	MarkSeen(peerID string, atUnix int64)
}

// Registry tracks known peers in memory, safe for concurrent use. This is
// the shared bookkeeping that any Source implementation (static, libp2p,
// mDNS, ...) can wrap.
type Registry struct {
	mu    sync.RWMutex
	peers map[string]Peer
}

func NewRegistry() *Registry {
	return &Registry{peers: make(map[string]Peer)}
}

func (r *Registry) Add(p Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers[p.ID] = p
}

func (r *Registry) MarkSeen(peerID string, atUnix int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.peers[peerID]; ok {
		p.LastSeenUnix = atUnix
		r.peers[peerID] = p
	}
}

func (r *Registry) Peers() []Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Peer, 0, len(r.peers))
	for _, p := range r.peers {
		out = append(out, p)
	}
	return out
}

// StaticSeedList is a Source backed by a fixed, operator-supplied peer
// list. Good enough for a devnet or a small permissioned deployment;
// doesn't discover new peers on its own.
type StaticSeedList struct {
	*Registry
}

func NewStaticSeedList(seeds []Peer) *StaticSeedList {
	reg := NewRegistry()
	now := time.Now().Unix()
	for _, s := range seeds {
		if s.LastSeenUnix == 0 {
			s.LastSeenUnix = now
		}
		reg.Add(s)
	}
	return &StaticSeedList{Registry: reg}
}
