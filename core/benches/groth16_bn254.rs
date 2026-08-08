//! Benchmarks the REAL `groth16_bn254` backends through the
//! `ProofSystem` trait -- as opposed to `proof_generation.rs` (the
//! placeholder hash-sign backends) or `zk-poc/examples/bench.rs` (the
//! same circuits called directly, without this crate's JSON
//! serialize/deserialize wrapping layer). The gap between this file's
//! numbers and `zk-poc/examples/bench.rs`'s is the actual cost of that
//! wrapping layer -- worth knowing, since `BENCHMARKS.md` said "this is
//! the number to diff against" once a real backend landed, and now one
//! has.
//!
//! `harness = false` for this target -- see `Cargo.toml`'s comment.
//!
//! Run with: `cargo bench --package veritas-core --bench groth16_bn254`

use std::time::{Duration, Instant};

use veritas_core::proof::groth16_bn254::{
    BankingGroth16Backend, HealthcareGroth16Backend, SupplyChainGroth16Backend,
};
use veritas_core::proof::{Proof, ProofSystem};

const SETUP_SEED: u64 = 42;
const PROVE_TRIALS: u32 = 30;
const VERIFY_TRIALS: u32 = 100;
// gov-supply-chain-integrity's circuit costs ~8.6s per proof and its
// setup() takes ~20s on its own (see SupplyChainGroth16Backend's own
// docs) -- 30 proving trials there would take minutes just for this one
// section, so it gets a deliberately smaller trial count.
const CHAIN_PROVE_TRIALS: u32 = 3;
const CHAIN_VERIFY_TRIALS: u32 = 20;

fn stats(label: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let n = samples.len();
    let total: Duration = samples.iter().sum();
    let mean_us = total.as_micros() as f64 / n as f64;
    let min_us = samples.first().unwrap().as_micros();
    let max_us = samples.last().unwrap().as_micros();
    let p50_us = samples[n / 2].as_micros();
    println!("{label}: n={n} mean={mean_us:.0}us min={min_us}us p50={p50_us}us max={max_us}us");
}

fn main() {
    println!("=== veritas-core: real Groth16-over-BN254 backends, via ProofSystem trait ===\n");
    println!(
        "(compare against zk-poc/examples/bench.rs's numbers in BENCHMARKS.md -- the gap is"
    );
    println!("this crate's JSON witness/public-input wrapping overhead, not the ZK cost itself.)\n");

    // --- banking-basel-iii ---
    let banking = BankingGroth16Backend::setup(SETUP_SEED).expect("setup should succeed");
    let witness = br#"{"transaction_amount_minor":50000}"#;
    let public_input = br#"{"risk_adjusted_threshold_minor":100000}"#;

    let mut prove_times = Vec::with_capacity(PROVE_TRIALS as usize);
    let mut last_proof: Option<Proof> = None;
    for _ in 0..PROVE_TRIALS {
        let t0 = Instant::now();
        let proof = banking
            .prove(witness, public_input)
            .expect("proving should succeed for a compliant transaction");
        prove_times.push(t0.elapsed());
        last_proof = Some(proof);
    }
    stats("banking: prove() via ProofSystem trait", prove_times);

    let proof = last_proof.unwrap();
    let mut verify_times = Vec::with_capacity(VERIFY_TRIALS as usize);
    for _ in 0..VERIFY_TRIALS {
        let t0 = Instant::now();
        banking
            .verify(&proof, public_input)
            .expect("verification should succeed");
        verify_times.push(t0.elapsed());
    }
    stats("banking: verify() via ProofSystem trait", verify_times);
    println!();

    // --- healthcare-hipaa ---
    let healthcare = HealthcareGroth16Backend::setup(SETUP_SEED).expect("setup should succeed");
    let hc_witness =
        br#"{"entries":[{"is_active":true,"authorized":true},{"is_active":true,"authorized":true},{"is_active":false,"authorized":false}]}"#;
    let hc_public = br#"{"record_id_hash":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],"observed_access_count":2}"#;

    let mut hc_prove_times = Vec::with_capacity(PROVE_TRIALS as usize);
    let mut hc_last_proof: Option<Proof> = None;
    for _ in 0..PROVE_TRIALS {
        let t0 = Instant::now();
        let proof = healthcare
            .prove(hc_witness, hc_public)
            .expect("proving should succeed for a compliant log");
        hc_prove_times.push(t0.elapsed());
        hc_last_proof = Some(proof);
    }
    stats("healthcare: prove() via ProofSystem trait", hc_prove_times);

    let hc_proof = hc_last_proof.unwrap();
    let mut hc_verify_times = Vec::with_capacity(VERIFY_TRIALS as usize);
    for _ in 0..VERIFY_TRIALS {
        let t0 = Instant::now();
        healthcare
            .verify(&hc_proof, hc_public)
            .expect("verification should succeed");
        hc_verify_times.push(t0.elapsed());
    }
    stats("healthcare: verify() via ProofSystem trait", hc_verify_times);

    println!("\nSame single-vCPU sandbox hardware caveat as the rest of BENCHMARKS.md applies.");

    // --- gov-supply-chain-integrity ---
    println!("\n=== gov-supply-chain-integrity: real backend, small trial count (see const doc) ===\n");

    let t0 = Instant::now();
    let supply_chain =
        SupplyChainGroth16Backend::setup(SETUP_SEED).expect("setup should succeed");
    println!("setup(): {:?} (includes generating a ~64 MiB proving key)", t0.elapsed());

    let genesis = [4u8; 32];
    let event_hash_0 = [1u8; 32];
    let event_hash_1 = [2u8; 32];
    let final_hash = veritas_zk_poc_final_hash(genesis, &[event_hash_0, event_hash_1]);
    let sc_witness = format!(
        r#"{{"entries":[{{"event_hash":{},"is_active":true}},{{"event_hash":{},"is_active":true}}]}}"#,
        json_byte_array(&event_hash_0),
        json_byte_array(&event_hash_1),
    );
    let sc_public = format!(
        r#"{{"genesis_hash":{},"final_linkage_hash":{},"active_count":2}}"#,
        json_byte_array(&genesis),
        json_byte_array(&final_hash),
    );

    let mut sc_prove_times = Vec::with_capacity(CHAIN_PROVE_TRIALS as usize);
    let mut sc_last_proof: Option<Proof> = None;
    for _ in 0..CHAIN_PROVE_TRIALS {
        let t0 = Instant::now();
        let proof = supply_chain
            .prove(sc_witness.as_bytes(), sc_public.as_bytes())
            .expect("proving should succeed for a genuinely intact chain");
        sc_prove_times.push(t0.elapsed());
        sc_last_proof = Some(proof);
    }
    stats("supply-chain: prove() via ProofSystem trait", sc_prove_times);

    let sc_proof = sc_last_proof.unwrap();
    let mut sc_verify_times = Vec::with_capacity(CHAIN_VERIFY_TRIALS as usize);
    for _ in 0..CHAIN_VERIFY_TRIALS {
        let t0 = Instant::now();
        supply_chain
            .verify(&sc_proof, sc_public.as_bytes())
            .expect("verification should succeed");
        sc_verify_times.push(t0.elapsed());
    }
    stats("supply-chain: verify() via ProofSystem trait", sc_verify_times);

    println!("\nSame hardware caveat applies. See BENCHMARKS.md for why this circuit's numbers");
    println!("are two to three orders of magnitude larger than the other two circuits' --");
    println!("real SHA-256-in-R1CS cost, not a bug.");
}

/// Small local helper mirroring `zk_poc::supply_chain_circuit::entry_linkage_hash`
/// so this bench doesn't need `veritas-zk-poc` as a direct dependency just
/// for one hash computation used to build a valid test chain.
fn veritas_zk_poc_final_hash(genesis: [u8; 32], event_hashes: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut running = genesis;
    for (i, eh) in event_hashes.iter().enumerate() {
        let mut hasher = Sha256::new();
        hasher.update((i as u64).to_le_bytes());
        hasher.update(eh);
        hasher.update(running);
        running = hasher.finalize().into();
    }
    running
}

fn json_byte_array(bytes: &[u8; 32]) -> String {
    let parts: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    format!("[{}]", parts.join(","))
}
