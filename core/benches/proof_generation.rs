//! Plain `std::time`-based micro-benchmark -- deliberately not using
//! `criterion`, because criterion's transitive dependency chain
//! (plotters -> half, rayon-core, ...) requires a newer rustc than many
//! CI/dev environments ship by default. If your toolchain is newer and you
//! want proper statistical benchmarking (warm-up, confidence intervals,
//! regression detection), swap this back to criterion -- the measurement
//! logic below is intentionally simple so that swap is easy.
//!
//! Run with: `cargo bench --package veritas-core`
//!
//! Real latency numbers for the CURRENT (placeholder) backend, so there's a
//! baseline to compare against once real Groth16/STARK backends land. Do
//! not quote these numbers as "proof generation time" in any external
//! communication -- they measure a SHA-256 call, not a SNARK/STARK prover.

use std::time::Instant;

use veritas_core::proof::groth16::Groth16Placeholder;
use veritas_core::proof::stark::StarkPlaceholder;
use veritas_core::proof::ProofSystem;

const ITERATIONS: u32 = 100_000;

fn bench<F: Fn()>(label: &str, f: F) {
    for _ in 0..1_000 {
        f();
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        f();
    }
    let elapsed = start.elapsed();
    let per_iter_ns = elapsed.as_nanos() as f64 / ITERATIONS as f64;
    println!("{label}: {ITERATIONS} iterations in {elapsed:?} ({per_iter_ns:.1} ns/iter)");
}

fn main() {
    let witness = vec![0xABu8; 256];
    let public_input = b"banking-basel-iii";

    let groth16 = Groth16Placeholder;
    bench("groth16_placeholder_prove", || {
        groth16.prove(&witness, public_input).unwrap();
    });

    let stark = StarkPlaceholder;
    bench("stark_placeholder_prove", || {
        stark.prove(&witness, public_input).unwrap();
    });
}
