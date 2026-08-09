//! veritas-core — proof engine for the Veritas Mesh attestation protocol.
//!
//! STATUS (see /STATUS.md at repo root for the authoritative version):
//! - `attestation`, `signature`, `errors`: real, working implementations.
//! - `commitment::hash_based`: real, working (SHA-256 commit/open).
//! - `commitment::pedersen`: **placeholder**. A real Pedersen commitment needs
//!   a fixed elliptic-curve group (e.g. via `curve25519-dalek` or an
//!   arkworks curve) and two independent, nothing-up-my-sleeve generators.
//!   This file defines the correct trait shape but the implementation is
//!   not cryptographically binding/hiding yet — see inline `TODO(RFC-0003)`.
//! - `proof::groth16`, `proof::stark`: **architectural placeholders**,
//!   still present for `stark` (no real backend exists for any rule
//!   yet) and as a reference/comparison point for `groth16` (the
//!   original placeholder, now superseded for every rule). **Update:**
//!   `proof::groth16_bn254` now wires in REAL Groth16-over-BN254
//!   proving/verification (via `veritas-zk-poc`) for all three rule
//!   modules — `banking-basel-iii`, `healthcare-hipaa`, and
//!   `gov-supply-chain-integrity` — see that module's docs for the three
//!   backend structs and exactly what is/isn't bound into the ZK
//!   statement. The third backend
//!   (`SupplyChainGroth16Backend`) has a real operational caveat the
//!   other two don't (a ~64 MiB proving key), documented there.
//! - `circuits::*`: real *predicate logic* (the compliance rule is
//!   actually evaluated in the clear, via `Rule::check`) for all three
//!   rules, and now ALL THREE also have a real zero-knowledge
//!   re-expression of that predicate reachable through
//!   `proof::groth16_bn254` — the predicate is checked
//!   in the clear by `Rule::check` AND, separately, can be proven in
//!   zero-knowledge via the Groth16 backend; these are two different code
//!   paths proving the same fact by construction (see
//!   `zk-poc/src/circuit.rs`, `healthcare_circuit.rs`, and
//!   `supply_chain_circuit.rs`), not one calling the other.
//!
//! Do not deploy this crate to attest real regulatory compliance. It is a
//! scaffold for the real cryptographic engineering work described in
//! RFC-0001/0002/0003.

pub mod attest;
pub mod attestation;
pub mod circuits;
pub mod commitment;
pub mod errors;
pub mod proof;
pub mod signature;

pub use attestation::Attestation;
pub use errors::VeritasError;
