//! `generate_keys`: generates, serializes, and catalogs the Groth16
//! proving/verifying keys for every real circuit in this crate, exactly
//! once — closing (the infrastructure half of) `zk-poc/README.md`'s
//! "what's still needed" item 3: "Decide where each rule's
//! `ProvingKey`/`VerifyingKey` get stored/distributed — they need to be
//! published once [...] and reused across every proof for that rule, not
//! regenerated per-attestation."
//!
//! # What this tool does NOT solve
//!
//! **These are still non-ceremony, fixed-seed keys — running this tool
//! does not make them trustworthy for real deployment.** Every
//! `setup_*` function in this crate's `lib.rs` uses a `ChaCha20Rng`
//! seeded from a plain `u64`, which is fine for tests and for
//! demonstrating this tool's own plumbing, and explicitly documented
//! everywhere in this crate as unsafe outside that context. A real
//! multi-party ceremony (or a transparent-setup proof system per
//! RFC-0002's STARK track) is a separate, unsolved problem this tool
//! does not touch — see `zk-poc/README.md` item 4. What THIS tool solves
//! is narrower and purely operational: given SOME set of keys (from a
//! real ceremony or, as run here, from this crate's own test-only
//! setup), generate them once, write them to disk in a stable format,
//! and record a `circuit_digest` for each — rather than every caller
//! silently calling `setup()` fresh, which is both slow (the
//! `gov-supply-chain-integrity` circuit's setup alone takes ~24s, per
//! `BENCHMARKS.md`) and, more importantly, means every "instance" of a
//! circuit's keys is actually a DIFFERENT trusted-setup run with no
//! shared trust anchor at all.
//!
//! # Why the large key files aren't checked into this repository
//!
//! `gov-supply-chain-integrity`'s proving key is ~64 MiB and
//! `banking-basel-iii`'s commitment-bound variant's is ~16.4 MiB (see
//! `BENCHMARKS.md`) — checking multi-megabyte binaries into a git repo
//! that expects to be cloned frequently is poor practice regardless of
//! what they contain, and doubly so for keys nobody should trust yet
//! (see above). This tool writes to a local, `.gitignore`d directory by
//! default; publishing real keys (once a real ceremony exists) belongs
//! on a release asset or dedicated artifact store, not in the git
//! history. The two small circuits' keys (`healthcare-hipaa`, ~13KB, and
//! unbound `banking-basel-iii`, ~29KB) ARE small enough to check in
//! without meaningfully affecting repo size, and are committed under
//! `zk-poc/keys/` specifically so there's at least one real, checked-in,
//! digest-verified example of what "published" actually looks like —
//! see that directory's own README for the load-bearing caveat repeated
//! there.
//!
//! # Usage
//!
//! ```text
//! cargo run --package veritas-zk-poc --release --bin generate_keys -- <output_dir>
//! ```
//!
//! Writes, per circuit, `<rule_id>.pk` (proving key),
//! `<rule_id>.vk` (verifying key, canonical-serialized via
//! `ark_serialize::CanonicalSerialize`), and prints a manifest table
//! (rule ID, key sizes, `circuit_digest` — SHA-256 of the verifying key
//! bytes, matching `proto/veritas/v1/rule_module.proto`'s
//! `RuleModuleManifest.circuit_digest` field exactly) to stdout, plus
//! writes that same table to `<output_dir>/MANIFEST.txt`.

use std::env;
use std::fs;
use std::path::Path;
use std::time::Instant;

use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

/// Fixed seed, deliberately: this tool's whole point is "generate once,
/// reuse everywhere" — using a fixed seed here means re-running this
/// tool reproduces byte-identical keys, which is the right property for
/// a tool whose job is producing a stable, referenceable artifact (even
/// though, per the module docs above, "stable" is not the same claim as
/// "trustworthy" — a real ceremony's output would replace this seed
/// entirely, not just use a different number here).
const SETUP_SEED: u64 = 42;

struct KeyRecord {
    rule_id: &'static str,
    proof_system_id: &'static str,
    proving_key_bytes: Vec<u8>,
    verifying_key_bytes: Vec<u8>,
    setup_time: std::time::Duration,
}

impl KeyRecord {
    fn circuit_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.verifying_key_bytes).into()
    }

    fn write(&self, dir: &Path) -> std::io::Result<()> {
        fs::write(dir.join(format!("{}.pk", self.rule_id)), &self.proving_key_bytes)?;
        fs::write(dir.join(format!("{}.vk", self.rule_id)), &self.verifying_key_bytes)?;
        Ok(())
    }

    fn manifest_line(&self) -> String {
        format!(
            "{:<35} {:<16} pk={:>12} bytes  vk={:>8} bytes  setup={:>7.2}s  circuit_digest=0x{}",
            self.rule_id,
            self.proof_system_id,
            self.proving_key_bytes.len(),
            self.verifying_key_bytes.len(),
            self.setup_time.as_secs_f64(),
            hex::encode(self.circuit_digest()),
        )
    }
}

fn serialize<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .expect("canonical serialization of a Groth16 key should never fail");
    buf
}

fn generate_all() -> Vec<KeyRecord> {
    let mut records = Vec::new();

    let t0 = Instant::now();
    let keys = veritas_zk_poc::setup(SETUP_SEED).expect("banking-basel-iii setup should succeed");
    records.push(KeyRecord {
        rule_id: "banking-basel-iii",
        proof_system_id: "groth16-bn254",
        proving_key_bytes: serialize(&keys.proving_key),
        verifying_key_bytes: serialize(&keys.verifying_key),
        setup_time: t0.elapsed(),
    });

    let t0 = Instant::now();
    let keys = veritas_zk_poc::setup_banking_bound(SETUP_SEED)
        .expect("banking-basel-iii (bound) setup should succeed");
    records.push(KeyRecord {
        rule_id: "banking-basel-iii-bound",
        proof_system_id: "groth16-bn254",
        proving_key_bytes: serialize(&keys.proving_key),
        verifying_key_bytes: serialize(&keys.verifying_key),
        setup_time: t0.elapsed(),
    });

    let t0 = Instant::now();
    let keys = veritas_zk_poc::setup_healthcare(SETUP_SEED)
        .expect("healthcare-hipaa setup should succeed");
    records.push(KeyRecord {
        rule_id: "healthcare-hipaa",
        proof_system_id: "groth16-bn254",
        proving_key_bytes: serialize(&keys.proving_key),
        verifying_key_bytes: serialize(&keys.verifying_key),
        setup_time: t0.elapsed(),
    });

    println!("Generating gov-supply-chain-integrity's keys -- this one takes ~20-25s alone,");
    println!("per BENCHMARKS.md, and produces a ~64 MiB proving key. Working...");
    let t0 = Instant::now();
    let keys = veritas_zk_poc::setup_supply_chain(SETUP_SEED)
        .expect("gov-supply-chain-integrity setup should succeed");
    records.push(KeyRecord {
        rule_id: "gov-supply-chain-integrity",
        proof_system_id: "groth16-bn254",
        proving_key_bytes: serialize(&keys.proving_key),
        verifying_key_bytes: serialize(&keys.verifying_key),
        setup_time: t0.elapsed(),
    });

    records
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let Some(output_dir) = args.get(1) else {
        eprintln!("Usage: generate_keys <output_dir>");
        eprintln!();
        eprintln!("Generates Groth16 keys for all four real circuits in this crate and writes");
        eprintln!("them to <output_dir> as <rule_id>.pk / <rule_id>.vk, plus a MANIFEST.txt.");
        eprintln!();
        eprintln!("IMPORTANT: these are non-ceremony, fixed-seed keys -- see this file's own");
        eprintln!("module doc comment (src/bin/generate_keys.rs) before using them for");
        eprintln!("anything beyond local development/testing.");
        std::process::exit(2);
    };

    let dir = Path::new(output_dir);
    fs::create_dir_all(dir).expect("failed to create output directory");

    println!("=== Veritas Mesh: generating and cataloging Groth16 keys ===");
    println!("Output directory: {}", dir.display());
    println!(
        "NON-CEREMONY KEYS -- fixed seed ({SETUP_SEED}), for local dev/testing only. See this"
    );
    println!("tool's own module doc comment before using these for anything else.\n");

    let records = generate_all();

    let mut manifest = String::new();
    manifest.push_str("# Veritas Mesh Groth16 key manifest\n");
    manifest.push_str("# NON-CEREMONY KEYS -- fixed seed, dev/testing only. See\n");
    manifest.push_str("# zk-poc/src/bin/generate_keys.rs's own module doc comment.\n");
    manifest.push_str("#\n");
    manifest.push_str("# circuit_digest = SHA-256(verifying_key_bytes), matching\n");
    manifest.push_str("# proto/veritas/v1/rule_module.proto's RuleModuleManifest.circuit_digest.\n\n");

    for record in &records {
        record.write(dir).expect("failed to write key files");
        let line = record.manifest_line();
        println!("{line}");
        manifest.push_str(&line);
        manifest.push('\n');
    }

    fs::write(dir.join("MANIFEST.txt"), &manifest).expect("failed to write MANIFEST.txt");
    println!("\nWrote {} key pairs and MANIFEST.txt to {}", records.len(), dir.display());
}
