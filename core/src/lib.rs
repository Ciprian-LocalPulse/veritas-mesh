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
//! - `proof::groth16`, `proof::stark`: **architectural placeholders**. They
//!   implement the `ProofSystem` trait end-to-end (so the rest of the
//!   codebase, tests, and SDKs can be built and wired against a stable
//!   interface) but the "proof" they produce is a signed hash commitment,
//!   NOT a zero-knowledge succinct argument. Swapping in `arkworks`
//!   (Groth16) or `winterfell` (STARK) behind the same trait is the
//!   RFC-0002 follow-up work; no other layer should need to change.
//! - `circuits::*`: real *predicate logic* (the compliance rule is actually
//!   evaluated), but it is evaluated in the clear by the prover rather than
//!   compiled into an arithmetic circuit — so today it proves "the prover
//!   ran this check and signed the result," not "this holds without
//!   revealing the inputs." Zero-knowledge requires reimplementing each
//!   predicate inside the chosen proving system's circuit DSL.
//!
//! Do not deploy this crate to attest real regulatory compliance. It is a
//! scaffold for the real cryptographic engineering work described in
//! RFC-0001/0002/0003.

pub mod attestation;
pub mod circuits;
pub mod commitment;
pub mod errors;
pub mod proof;
pub mod signature;

pub use attestation::Attestation;
pub use errors::VeritasError;
