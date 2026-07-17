//! AXIOM Validator Setup Tool
//!
//! General-purpose tool for setting up any AXIOM validator.
//! Works identically for Genesis validators and new joiners.
//!
//! Usage:
//!   validator-setup --name "axiom-first-penguin-alpha" --email "alpha@local" --output genesis-validators/
//!   validator-setup --batch genesis-batch.toml --output genesis-validators/
//!
//! Generates all three cryptographic keypairs:
//!   - Ed25519 keypair (standard operational signing)
//!   - Dilithium/ML-DSA-65 keypair (quantum-resistant operational signing)
//!   - SPHINCS+/SLH-DSA-SHA2-128s keypair (VBC identity — mandatory)
//!
//! Plus:
//!   - VBC (contains SPHINCS+ PK only — no operational keys)
//!   - Lambda config
//!   - ANTIE config
//!   - Directory structure

use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "validator-setup")]
#[command(about = "AXIOM Validator Setup — generates keys, configs, and VBC for a validator")]
struct Cli {
    /// Validator display name (e.g. "axiom-first-penguin-alpha")
    #[arg(long)]
    name: Option<String>,

    /// Carrier email (e.g. "alpha@local") — used for validator_id
    #[arg(long)]
    email: Option<String>,

    /// Port number for Lambda listener (default: auto-assign)
    #[arg(long)]
    port: Option<u16>,

    /// Output base directory
    #[arg(long, default_value = ".")]
    output: PathBuf,

    /// Mark as Genesis validator (self-VBC with no issuers)
    #[arg(long)]
    genesis: bool,

    /// Batch mode: read multiple validators from TOML file
    #[arg(long)]
    batch: Option<PathBuf>,

    /// Path to Lambda binary (default: auto-detect from validator-setup location)
    #[arg(long)]
    lambda_binary: Option<PathBuf>,

    /// Generate manifest file (for batch mode)
    #[arg(long)]
    manifest: bool,
}

// ============================================================================
// Types
// ============================================================================

#[derive(Serialize, Deserialize, Clone)]
struct ValidatorInfo {
    name: String,
    email: String,
    port: u16,
    #[serde(default)]
    genesis: bool,
    /// Carrier URIs for this validator (e.g., ["email:alpha@axiom.local"])
    #[serde(default)]
    carriers: Vec<String>,
    /// Inbound FATMAMA endpoint the validator advertises via VSP
    /// (YP §27.5.2). Points at the cluster's FATMAMA receiver —
    /// today that's `scripts/fatmama.py` (dev), tomorrow a
    /// FATMAMA-protocol TCP listener. Default matches
    /// `scripts/axiom-env.py`'s loopback dev env; override per-row
    /// for cross-machine clusters.
    #[serde(default = "default_fatmama_host")]
    fatmama_host: String,
    /// Inbound FATMAMA port (default 2525 — matches scripts/fatmama.py
    /// DEFAULT_PORT). For FATMAMA-protocol deployments the operator
    /// will run a separate inbound TCP listener and set this to
    /// whatever port that listener binds.
    #[serde(default = "default_fatmama_port")]
    fatmama_port: u16,
}

fn default_fatmama_host() -> String { "127.0.0.1".into() }
fn default_fatmama_port() -> u16    { 2525 }

#[derive(Serialize, Deserialize)]
struct BatchConfig {
    output: Option<String>,
    validators: Vec<ValidatorInfo>,
}

#[derive(Serialize)]
#[allow(clippy::upper_case_acronyms)]
struct VBC {
    version: u8,
    validator_id_hex: String,
    subject_pubkey_sphincs_hex: String,
    subject_pubkey_dilithium_hex: String,
    subject_pubkey_ed25519_hex: String,
    pgp_fingerprint_hex: String,
    issuer_set: Vec<String>,
    signatures: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    chain_depth: u8,
    founding_vbc_hash: String,
    is_genesis: bool,
    notes: String,
}

#[derive(Serialize, Clone)]
struct ManifestEntry {
    name: String,
    validator_id: String,
    email: String,
    port: u16,
    sphincs_pk_hex: String,
    ed25519_pk_hex: String,
    dilithium_pk_hex: String,
    genesis: bool,
    carriers: Vec<String>,
}

#[derive(Serialize)]
struct Manifest {
    version: String,
    description: String,
    validator_count: usize,
    validators: Vec<ManifestEntry>,
}

// ============================================================================
// Crypto
// ============================================================================

/// Generate Ed25519 keypair using OS random
fn generate_ed25519() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (
        signing_key.to_bytes().to_vec(),
        verifying_key.to_bytes().to_vec(),
    )
}

/// Generate SPHINCS+ keypair (SLH-DSA-SHA2-128s)
/// Returns (secret_key_bytes, public_key_bytes)
/// PK = 32 bytes, SK = 64 bytes
fn generate_sphincs() -> (Vec<u8>, Vec<u8>) {
    use fips205::slh_dsa_sha2_128s;
    use fips205::traits::SerDes;
    
    let (pk, sk) = slh_dsa_sha2_128s::try_keygen()
        .expect("SPHINCS+ keygen failed — OS RNG error");
    
    (sk.into_bytes().to_vec(), pk.into_bytes().to_vec())
}

/// Generate Dilithium keypair (ML-DSA-65)
/// Returns (secret_key_bytes, public_key_bytes)
/// PK = 1952 bytes, SK = 4032 bytes
fn generate_dilithium() -> (Vec<u8>, Vec<u8>) {
    use fips204::ml_dsa_65;
    use fips204::traits::SerDes;
    
    let (pk, sk) = ml_dsa_65::try_keygen()
        .expect("Dilithium keygen failed — OS RNG error");
    
    (sk.into_bytes().to_vec(), pk.into_bytes().to_vec())
}

/// Compute ANTIE transport-layer validator_id: email/checksum+salt
/// This is NOT the cryptographic validator_id (which is BLAKE3(sphincs_pk) via Core).
/// This is the ANTIE routing identifier for email-based transport.
/// checksum = first 6 hex chars of BLAKE3(email || master_pk || salt_bytes)
fn compute_validator_id(email: &str, salt: &str) -> String {
    // PLACEHOLDER: must match Core's WALLET_IDENTITY_KEY after G1 ceremony.
    // Before G1, this [0u8; 32] matches the Core placeholder.
    // After G1, update to: axiom_core_logic::wallet_id::WALLET_IDENTITY_KEY
    let master_pk = [0u8; 32];
    let salt_bytes = hex::decode(salt).unwrap_or_else(|_| vec![0, 0]);

    let mut hasher = blake3::Hasher::new();
    hasher.update(email.to_lowercase().as_bytes());
    hasher.update(&master_pk);
    hasher.update(&salt_bytes);
    let hash = hasher.finalize();
    let checksum = &hex::encode(hash.as_bytes())[..6];

    format!("{}/{}{}", email.to_lowercase(), checksum, salt)
}

// ============================================================================
// Setup
// ============================================================================

fn setup_validator(
    info: &ValidatorInfo,
    output_dir: &Path,
    lambda_binary_path: &str,
) -> ManifestEntry {
    let vdir = output_dir.join(&info.name);
    let email = &info.email;
    let validator_id = compute_validator_id(email, "00");

    println!("  Setting up: {}", info.name);
    println!("    validator_id:  {}", validator_id);
    println!("    carrier:       {}", email);
    println!("    port:          {}", info.port);

    // Create directory structure
    for sub in &[
        "config",
        "data",
        "logs",
        "maildir/inbox/new",
        "maildir/inbox/cur",
        "maildir/inbox/tmp",
        "maildir/outbox/new",
        "maildir/outbox/cur",
        "maildir/outbox/tmp",
        "maildir/lambda-in/new",
        "maildir/lambda-in/cur",
        "maildir/lambda-in/tmp",
        "maildir/lambda-out/new",
        "maildir/lambda-out/cur",
        "maildir/lambda-out/tmp",
    ] {
        fs::create_dir_all(vdir.join(sub)).expect("Failed to create directory");
    }

    // Generate Ed25519 keypair (operational signing)
    let (ed25519_sk, ed25519_pk) = generate_ed25519();
    let ed25519_pk_hex = hex::encode(&ed25519_pk);

    let key_path = vdir.join("config/ed25519.key");
    fs::write(&key_path, &ed25519_sk).expect("Failed to write Ed25519 key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .expect("Failed to set key permissions");

    let ed25519_pk_path = vdir.join("config/ed25519.pub");
    fs::write(&ed25519_pk_path, &ed25519_pk).expect("Failed to write Ed25519 public key");

    // Generate SPHINCS+ keypair (VBC identity — mandatory)
    let (sphincs_sk, sphincs_pk) = generate_sphincs();
    let sphincs_pk_hex = hex::encode(&sphincs_pk);

    let sphincs_sk_path = vdir.join("config/sphincs.key");
    fs::write(&sphincs_sk_path, &sphincs_sk).expect("Failed to write SPHINCS+ secret key");
    fs::set_permissions(&sphincs_sk_path, fs::Permissions::from_mode(0o600))
        .expect("Failed to set key permissions");

    let sphincs_pk_path = vdir.join("config/sphincs.pub");
    fs::write(&sphincs_pk_path, &sphincs_pk).expect("Failed to write SPHINCS+ public key");

    // Generate Dilithium keypair (quantum-resistant operational signing)
    let (dilithium_sk, dilithium_pk) = generate_dilithium();
    let dilithium_pk_hex = hex::encode(&dilithium_pk);

    let dilithium_sk_path = vdir.join("config/dilithium.key");
    fs::write(&dilithium_sk_path, &dilithium_sk).expect("Failed to write Dilithium secret key");
    fs::set_permissions(&dilithium_sk_path, fs::Permissions::from_mode(0o600))
        .expect("Failed to set key permissions");

    let dilithium_pk_path = vdir.join("config/dilithium.pub");
    fs::write(&dilithium_pk_path, &dilithium_pk).expect("Failed to write Dilithium public key");

    // Compute validator_id = BLAKE3(sphincs_pk) — delegate to Core
    let validator_id_bytes = axiom_core_logic::compute::compute_validator_id(&sphincs_pk);
    let validator_id_hex = hex::encode(validator_id_bytes);
    
    let vbc = VBC {
        version: 0x09,
        validator_id_hex: validator_id_hex.clone(),
        subject_pubkey_sphincs_hex: sphincs_pk_hex.clone(),
        subject_pubkey_dilithium_hex: dilithium_pk_hex.clone(),
        subject_pubkey_ed25519_hex: ed25519_pk_hex.clone(),
        pgp_fingerprint_hex: String::new(),
        issuer_set: vec![],
        signatures: vec![],
        issued_at: 0,
        expires_at: if info.genesis { u64::MAX } else { 0 },
        chain_depth: 0,
        founding_vbc_hash: "0".repeat(64),  // Zero hash — set after first VBC is signed
        is_genesis: info.genesis,
        notes: if info.genesis {
            "Genesis validator. VBC pending root authority signatures.".into()
        } else {
            "VBC pending — requires 3 existing validators to sign.".into()
        },
    };
    let vbc_json = serde_json::to_string_pretty(&vbc).expect("Failed to serialize VBC");
    fs::write(vdir.join("config/vbc.json"), &vbc_json).expect("Failed to write VBC");

    // Write Lambda config
    // Paths are relative to the validator directory (CWD when launched by ANTIE)
    let lambda_config = format!(
        r#"[network]
listen = "127.0.0.1:{port}"
timeout_secs = 30

[storage]
transaction_db = "./data/lambda.db"
management_db = "./data/management.db"
max_hints = 1024

[validator]
private_key_path = "./config/ed25519.key"
dilithium_key_path = "./config/dilithium.key"
dilithium_pub_path = "./config/dilithium.pub"
sphincs_key_path = "./config/sphincs.key"
sphincs_pub_path = "./config/sphincs.pub"
vbc_path = "./config/vbc.json"
min_witnesses = 3
generate_proofs = true

[logging]
level = "info"
"#,
        port = info.port,
    );
    fs::write(vdir.join("config/lambda-config.toml"), &lambda_config)
        .expect("Failed to write Lambda config");

    // Write ANTIE config
    // Paths are relative to the validator directory because validator-ctl
    // does `cd $vdir` before starting ANTIE.
    // [carriers.fatmama] declares the cluster's INBOUND FATMAMA
    // endpoint for VSP discovery (YP §27.5.2). ANTIE does NOT open
    // a TCP listener for it — today the receiver is FATMAMA-dev
    // (scripts/fatmama.py), tomorrow the FATMAMA-protocol inbound-
    // only TCP listener. Either way, validator outbound is NEVER
    // fatmama: — replies land in maildir/outbox and the host MTA
    // dispatches. See docs/AXIOM_DESIGN_FATMAMA.md §0 "Two FATMAMAs".
    let antie_config = format!(
        r#"[carriers.maildir]
inbox = "./maildir/inbox"
outbox = "./maildir/outbox"

[carriers.fatmama]
host = "{fatmama_host}"
port = {fatmama_port}

[core]
use_embedded_avm = true

[lambda]
mode = "subprocess"
binary_path = "{lambda_bin}"
config_path = "./config/lambda-config.toml"

[validator]
public_key_hex = "{pk_hex}"
dilithium_pk_hex = "{dil_pk_hex}"
validator_id = "{validator_id}"
vbc_path = "./config/vbc.json"

[identity]
email = "{email}"
name = "{name}"

[logging]
level = "info"

poll_interval_ms = 10
"#,
        lambda_bin = lambda_binary_path,
        pk_hex = sphincs_pk_hex,
        dil_pk_hex = dilithium_pk_hex,
        validator_id = validator_id,
        email = email,
        name = info.name,
        fatmama_host = info.fatmama_host,
        fatmama_port = info.fatmama_port,
    );
    fs::write(vdir.join("antie.toml"), &antie_config).expect("Failed to write ANTIE config");

    // Marker file
    fs::write(vdir.join(".validator-root"), "").ok();

    println!("    sphincs pk:    {}...", &sphincs_pk_hex[..16]);
    println!("    ed25519 pk:    {}...", &ed25519_pk_hex[..16]);
    println!("    dilithium pk:  {}... ({} bytes)", &dilithium_pk_hex[..16], dilithium_pk.len());
    println!();

    ManifestEntry {
        name: info.name.clone(),
        validator_id,
        email: info.email.clone(),
        port: info.port,
        sphincs_pk_hex,
        ed25519_pk_hex,
        dilithium_pk_hex,
        genesis: info.genesis,
        carriers: info.carriers.clone(),
    }
}

fn write_manifest(entries: &[ManifestEntry], output_dir: &Path) {
    let manifest = Manifest {
        version: "genesis.v1".into(),
        description: "AXIOM Validators".into(),
        validator_count: entries.len(),
        validators: entries.to_vec(),
    };

    let json = serde_json::to_string_pretty(&manifest).expect("Failed to serialize manifest");
    fs::write(output_dir.join("genesis-manifest.json"), &json)
        .expect("Failed to write manifest");

    println!("  Manifest written: genesis-manifest.json");
}

fn write_gitignore(output_dir: &Path) {
    let content = "# Validator private keys - DO NOT COMMIT\n\
        */config/ed25519.key\n\
        */config/dilithium.key\n\
        */config/sphincs.key\n\
        */data/\n\
        */logs/\n\
        */maildir/\n\
        *.pid\n";
    fs::write(output_dir.join(".gitignore"), content).expect("Failed to write .gitignore");
}

fn print_genesis_rust_code(entries: &[ManifestEntry]) {
    println!("  ── Rust code for genesis.rs (SPHINCS+ PKs) ──");
    println!();
    let genesis_entries: Vec<_> = entries.iter().filter(|e| e.genesis).collect();
    println!("  pub const GENESIS_VALIDATORS: [[u8; 32]; {}] = [", genesis_entries.len());
    for e in &genesis_entries {
        let pk_bytes = hex::decode(&e.sphincs_pk_hex).unwrap();
        let rust_bytes: Vec<String> = pk_bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
        println!("      // {}", e.name);
        println!("      [{}],", rust_bytes.join(", "));
    }
    println!("  ];");
    println!();
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let cli = Cli::parse();

    println!();
    println!("================================================================");
    println!("  AXIOM Validator Setup");
    println!("================================================================");
    println!();

    let output_dir = &cli.output;
    fs::create_dir_all(output_dir).expect("Failed to create output directory");

    let mut entries = Vec::new();

    // Resolve Lambda binary path
    let lambda_binary_path = if let Some(ref path) = cli.lambda_binary {
        path.display().to_string()
    } else {
        // Auto-detect: Lambda binary is sibling of validator-setup in same dir
        let self_path = std::env::current_exe().unwrap_or_default();
        let bin_dir = self_path.parent().unwrap_or(Path::new("."));
        let lambda_path = bin_dir.join("lambda");
        if lambda_path.exists() {
            lambda_path.canonicalize().unwrap_or(lambda_path).display().to_string()
        } else {
            // Fallback: assume it's in PATH
            "lambda".to_string()
        }
    };
    println!("  Lambda binary: {}", lambda_binary_path);
    println!();

    if let Some(batch_path) = &cli.batch {
        // Batch mode
        let content = fs::read_to_string(batch_path)
            .unwrap_or_else(|_| panic!("Failed to read batch file: {:?}", batch_path));
        let batch: BatchConfig =
            toml::from_str(&content).expect("Failed to parse batch TOML");

        let out = batch
            .output
            .map(PathBuf::from)
            .unwrap_or_else(|| output_dir.clone());
        fs::create_dir_all(&out).expect("Failed to create output directory");

        for info in &batch.validators {
            let entry = setup_validator(info, &out, &lambda_binary_path);
            entries.push(entry);
        }

        write_gitignore(&out);
        write_manifest(&entries, &out);
        print_genesis_rust_code(&entries);
    } else if let (Some(name), Some(email)) = (&cli.name, &cli.email) {
        // Single validator mode
        let port = cli.port.unwrap_or(9001);
        let info = ValidatorInfo {
            name: name.clone(),
            email: email.clone(),
            port,
            genesis: cli.genesis,
            carriers: vec![format!("email:{}", email)],
            fatmama_host: default_fatmama_host(),
            fatmama_port: default_fatmama_port(),
        };

        let entry = setup_validator(&info, output_dir, &lambda_binary_path);
        entries.push(entry);
    } else {
        eprintln!("Error: provide --name and --email, or --batch <file.toml>");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  Single:  validator-setup --name my-validator --email me@example.com --port 9001 --output ./validators/");
        eprintln!("  Genesis: validator-setup --name axiom-first-penguin-alpha --email alpha@local --port 9001 --genesis --output genesis-validators/");
        eprintln!("  Batch:   validator-setup --batch genesis-batch.toml --output genesis-validators/");
        std::process::exit(1);
    }

    println!("================================================================");
    println!("  Setup Complete");
    println!("================================================================");
    println!();
    println!("  Structure per validator:");
    println!("    <name>/");
    println!("    +-- config/");
    println!("    |   +-- ed25519.key           (operational, chmod 600)");
    println!("    |   +-- dilithium.key         (quantum-resistant operational, chmod 600)");
    println!("    |   +-- dilithium.pub         (quantum-resistant operational PK)");
    println!("    |   +-- sphincs.key           (VBC identity SK, chmod 600)");
    println!("    |   +-- sphincs.pub           (VBC identity PK)");
    println!("    |   +-- vbc.json               (VBC proof)");
    println!("    |   +-- lambda-config.toml");
    println!("    +-- antie.toml");
    println!("    +-- data/                      (sled databases)");
    println!("    +-- logs/                      (runtime logs)");
    println!("    +-- maildir/inbox|outbox/      (message transport)");
    println!();
}
