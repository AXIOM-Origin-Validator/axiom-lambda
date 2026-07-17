//! Genesis Ceremony Tool
//!
//! The ONE tool that bootstraps AXIOM. Only the CA (you) runs this.
//!
//! Generates ALL keys and credentials for genesis validators:
//!   - 3 Root Authority SPHINCS+ key pairs (CA keeps SK offline forever)
//!   - Per-validator: Ed25519, SPHINCS+, Dilithium key pairs (placed into validator dirs)
//!   - Per-validator: Signed VBC (signed with root authority keys)
//!   - genesis_constants.rs (auto-installed into Core)
//!
//! Post-genesis validators do NOT use this tool. They run validator-setup
//! to generate their own keys, then get k=3 existing validators to sign their VBC.
//!
//! Usage:
//!   cargo run --bin genesis-ceremony -- --config genesis-ceremony.toml
//!
//! Output:
//!   {output_dir}/root-keys/root_{1,2,3}.{key,pub}  — Root authority key pairs
//!   {output_dir}/{validator}/vbc.json               — Signed VBC per validator
//!   {validator_path}/config/{ed25519,sphincs,dilithium}.{key,pub} — Validator keys
//!   Core genesis.rs — auto-installed (with confirmation)

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};

// SPHINCS+ sizes (SLH-DSA-SHA2-128s)
const SPHINCS_PK_SIZE: usize = 32;
const SPHINCS_SK_SIZE: usize = 64;
const SPHINCS_SIG_SIZE: usize = 7856;

// ============================================================================
// Config structs (from TOML)
// ============================================================================

#[derive(Deserialize)]
struct Config {
    ceremony: CeremonyConfig,
    certificate_authority: CAConfig,
    validators: Vec<ValidatorConfig>,
}

#[derive(Deserialize)]
struct CeremonyConfig {
    vbc_version: u8,
    output_dir: String,
    root_keys_dir: Option<String>,
    expires_years: Option<u64>,
    #[serde(default, rename = "validators_base_dir")]
    _validators_base_dir: Option<String>,
    /// Path to axiom-core/core-logic/src/genesis.rs for auto-install
    /// If set, ceremony will write genesis constants directly into Core.
    core_genesis_path: Option<String>,
}

#[derive(Deserialize)]
struct CAConfig {
    name: String,
    pgp_fingerprint: String,
}

#[derive(Deserialize)]
struct ValidatorConfig {
    name: String,
    path: String,
    wallet_email: Option<String>,
    pgp_fingerprint: Option<String>,
    notes: Option<String>,
}

// ============================================================================
// Output VBC (JSON)
// ============================================================================

#[derive(Serialize)]
struct VBCOutput {
    version: u8,
    validator_id_hex: String,
    subject_pubkey_sphincs_hex: String,
    subject_pubkey_dilithium_hex: String,
    subject_pubkey_ed25519_hex: String,
    pgp_fingerprint_hex: String,
    node_name: String,
    issued_at: u64,
    expires_at: u64,
    chain_depth: u8,
    issuer_set: Vec<String>,        // 3 root PK hex strings
    signatures: Vec<String>,        // 3 SPHINCS+ sig hex strings
    name: String,
    notes: String,
    ceremony_ca: String,
    ceremony_ca_pgp: String,
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    let config_path = if args.len() > 2 && args[1] == "--config" {
        &args[2]
    } else if args.len() > 1 {
        &args[1]
    } else {
        eprintln!("Usage: genesis-ceremony --config <path-to-genesis-ceremony.toml>");
        std::process::exit(1);
    };
    
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║           AXIOM Genesis Ceremony Tool                 ║");
    println!("║           VBC v0.9 — SPHINCS+ Root Authority          ║");
    println!("╚════════════════════════════════════════════════════════╝");
    println!();
    
    // Read config
    let config_str = fs::read_to_string(config_path)
        .unwrap_or_else(|e| {
            eprintln!("ERROR: Cannot read config file '{}': {}", config_path, e);
            std::process::exit(1);
        });
    let config: Config = toml::from_str(&config_str)
        .unwrap_or_else(|e| {
            eprintln!("ERROR: Cannot parse config: {}", e);
            std::process::exit(1);
        });
    
    println!("Certificate Authority: {}", config.certificate_authority.name);
    println!("CA PGP:               {}", format_pgp(&config.certificate_authority.pgp_fingerprint));
    println!("Validators:           {}", config.validators.len());
    println!("VBC Version:          v0.{}", config.ceremony.vbc_version);
    println!();
    
    // Create output directories
    let output_dir = PathBuf::from(&config.ceremony.output_dir);
    let root_keys_dir = output_dir.join(
        config.ceremony.root_keys_dir.as_deref().unwrap_or("root-keys")
    );
    fs::create_dir_all(&root_keys_dir).expect("Failed to create root-keys directory");
    
    // Timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time error")
        .as_secs();
    let expires_years = config.ceremony.expires_years.unwrap_or(10);
    let expires_at = now + (expires_years * 365 * 24 * 3600);
    
    println!("Issued at:  {} ({})", now, format_time(now));
    println!("Expires at: {} ({}, +{} years)", expires_at, format_time(expires_at), expires_years);
    println!();
    
    // ========================================
    // Step 1: Generate 3 root authority SPHINCS+ key pairs
    // ========================================
    println!("═══ Step 1: Generating Root Authority Keys ═══");
    
    let mut root_pks: Vec<Vec<u8>> = Vec::new();
    let mut root_sks: Vec<Vec<u8>> = Vec::new();
    
    for i in 1..=3 {
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen()
            .expect("SPHINCS+ keygen failed");
        
        let pk_bytes = pk.into_bytes().to_vec();
        let sk_bytes = sk.into_bytes().to_vec();
        
        assert_eq!(pk_bytes.len(), SPHINCS_PK_SIZE, "SPHINCS+ PK wrong size");
        assert_eq!(sk_bytes.len(), SPHINCS_SK_SIZE, "SPHINCS+ SK wrong size");
        
        // Save keys
        let pk_path = root_keys_dir.join(format!("root_{}.pub", i));
        let sk_path = root_keys_dir.join(format!("root_{}.key", i));
        fs::write(&pk_path, &pk_bytes).expect("Failed to write root PK");
        fs::write(&sk_path, &sk_bytes).expect("Failed to write root SK");
        
        // Set permissions on secret key
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sk_path, fs::Permissions::from_mode(0o600))
                .expect("Failed to set key permissions");
        }
        
        println!("  ROOT_{}: {}", i, hex::encode(&pk_bytes));
        println!("    PK saved: {}", pk_path.display());
        println!("    SK saved: {} (KEEP OFFLINE!)", sk_path.display());
        
        root_pks.push(pk_bytes);
        root_sks.push(sk_bytes);
    }
    println!();
    
    // ========================================
    // Step 2: Generate validator SPHINCS+ keys and sign VBCs
    // ========================================
    // CRITICAL: For genesis validators, the SPHINCS+ key comes from the CA (us),
    // NOT from the validator. This is the same trust model as VBC itself:
    //   - ROOT AUTHORITY SPHINCS+ keys → generated here, CA keeps SK offline
    //   - GENESIS VALIDATOR SPHINCS+ keys → generated here, placed into validator dirs
    //   - VBC → signed here with root authority keys
    // The validator does NOT generate its own SPHINCS+ identity for genesis.
    // Post-genesis validators generate their own via validator-setup,
    // but genesis validators receive theirs from the CA, just like their VBC.
    println!("═══ Step 2: Generating Genesis Validator Keys & Signing VBCs ═══");
    
    let mut genesis_sphincs_pks: Vec<(String, Vec<u8>)> = Vec::new();
    
    for validator in &config.validators {
        println!("\n  --- {} ---", validator.name);
        
        let vdir = PathBuf::from(&validator.path);
        let config_dir = vdir.join("config");
        fs::create_dir_all(&config_dir).ok();
        
        // GENERATE Ed25519 operational key
        // For genesis validators, ALL keys come from the CA.
        // Ed25519 is used for day-to-day witness signing and encryption.
        let ed25519_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ed25519_pk = ed25519_sk.verifying_key();
        let ed25519_pk_bytes = ed25519_pk.as_bytes().to_vec();
        let ed25519_sk_bytes = ed25519_sk.to_bytes().to_vec();
        
        let ed25519_pk_path = config_dir.join("ed25519.pub");
        let ed25519_sk_path = config_dir.join("ed25519.key");
        fs::write(&ed25519_pk_path, &ed25519_pk_bytes).expect("Failed to write Ed25519 PK");
        fs::write(&ed25519_sk_path, &ed25519_sk_bytes).expect("Failed to write Ed25519 SK");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&ed25519_sk_path, fs::Permissions::from_mode(0o600))
                .expect("Failed to set Ed25519 SK permissions");
        }
        println!("  Ed25519 PK:   {} (GENERATED by CA)", hex::encode(&ed25519_pk_bytes[..8]));
        
        // GENERATE SPHINCS+ keypair (VBC identity — primary quantum-resistant)
        let (sphincs_pk_obj, sphincs_sk_obj) = slh_dsa_sha2_128s::try_keygen()
            .expect("SPHINCS+ keygen for genesis validator failed");
        let sphincs_pk = sphincs_pk_obj.into_bytes().to_vec();
        let sphincs_sk = sphincs_sk_obj.into_bytes().to_vec();
        assert_eq!(sphincs_pk.len(), SPHINCS_PK_SIZE, "SPHINCS+ PK wrong size");
        assert_eq!(sphincs_sk.len(), SPHINCS_SK_SIZE, "SPHINCS+ SK wrong size");
        
        let sphincs_pk_path = config_dir.join("sphincs.pub");
        let sphincs_sk_path = config_dir.join("sphincs.key");
        fs::write(&sphincs_pk_path, &sphincs_pk).expect("Failed to write SPHINCS+ PK");
        fs::write(&sphincs_sk_path, &sphincs_sk).expect("Failed to write SPHINCS+ SK");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sphincs_sk_path, fs::Permissions::from_mode(0o600))
                .expect("Failed to set SPHINCS+ SK permissions");
        }
        println!("  SPHINCS+ PK:  {} (GENERATED by CA)", hex::encode(&sphincs_pk[..8]));
        
        // GENERATE Dilithium keypair (quantum backup identity)
        use fips204::ml_dsa_65;
        use fips204::traits::SerDes as DilSerDes;
        let (dilithium_pk_obj, dilithium_sk_obj) = ml_dsa_65::try_keygen()
            .expect("Dilithium keygen for genesis validator failed");
        let dilithium_pk = dilithium_pk_obj.into_bytes().to_vec();
        let dilithium_sk = dilithium_sk_obj.into_bytes().to_vec();
        
        let dilithium_pk_path = config_dir.join("dilithium.pub");
        let dilithium_sk_path = config_dir.join("dilithium.key");
        fs::write(&dilithium_pk_path, &dilithium_pk).expect("Failed to write Dilithium PK");
        fs::write(&dilithium_sk_path, &dilithium_sk).expect("Failed to write Dilithium SK");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dilithium_sk_path, fs::Permissions::from_mode(0o600))
                .expect("Failed to set Dilithium SK permissions");
        }
        println!("  Dilithium PK: {} ({} bytes, GENERATED by CA)", hex::encode(&dilithium_pk[..8]), dilithium_pk.len());
        
        // Compute validator_id = BLAKE3(sphincs_pk) — delegate to Core's function
        let validator_id = axiom_core_logic::compute::compute_validator_id(&sphincs_pk);
        println!("  Validator ID: {}", hex::encode(&validator_id[..8]));
        
        // PGP fingerprint
        let pgp_fp = validator.pgp_fingerprint.as_deref().unwrap_or("");
        let pgp_bytes = hex::decode(pgp_fp).unwrap_or_default();
        
        // Build VBC signing payload — MUST use Core's function to guarantee consistency.
        // Core is the bible. We build a temporary Core VBC struct to compute the payload.
        let core_vbc = axiom_core_logic::types::VBC {
            version: config.ceremony.vbc_version,
            // YPX-021 §7 — genesis certs are baseline-exempt (0 = none;
            // keeps the signing pre-image byte-identical to pre-baseline).
            network_size_baseline: 0,
            baseline_tick: 0,
            validator_id,
            subject_pubkey_sphincs: sphincs_pk.clone(),
            subject_pubkey_dilithium: dilithium_pk.clone(),
            subject_pubkey_ed25519: ed25519_pk_bytes.clone(),
            pgp_fingerprint: pgp_bytes.clone(),
            node_name: validator.name.clone(),
            proof_cap: String::new(),
            issued_at: now,
            expires_at,
            chain_depth: 0,  // root-signed
            issuer_set: root_pks.clone(),
            signatures: vec![],  // not yet signed — payload doesn't include signatures
            max_tx: 0,  // VBCs (Lambda) don't use TX budget — 0 = unlimited
            founding_vbc_hash: [0u8; 32],  // genesis VBC — self-referential, set after signing
        };
        let commitment = axiom_core_logic::compute::compute_vbc_signing_payload(&core_vbc);
        
        println!("  Commitment:   {}", hex::encode(&commitment[..8]));
        
        // Sign with all 3 root keys
        let mut signatures: Vec<Vec<u8>> = Vec::new();
        for (i, sk_bytes) in root_sks.iter().enumerate() {
            let sk_array: [u8; SPHINCS_SK_SIZE] = sk_bytes.as_slice().try_into()
                .expect("Root SK wrong size");
            let sk = slh_dsa_sha2_128s::PrivateKey::try_from_bytes(&sk_array)
                .expect("Failed to parse root SK");
            
            let sig = sk.try_sign(&commitment, b"", false)
                .expect("SPHINCS+ signing failed");
            let sig_bytes = sig.to_vec();
            
            assert_eq!(sig_bytes.len(), SPHINCS_SIG_SIZE, "SPHINCS+ sig wrong size");
            
            // Verify immediately
            let pk_array: [u8; SPHINCS_PK_SIZE] = root_pks[i].as_slice().try_into().unwrap();
            let vk = slh_dsa_sha2_128s::PublicKey::try_from_bytes(&pk_array)
                .expect("Failed to parse root PK for verify");
            let sig_array: &[u8; SPHINCS_SIG_SIZE] = sig_bytes.as_slice().try_into().unwrap();
            assert!(vk.verify(&commitment, sig_array, b""), "Signature verification failed!");
            
            println!("  ROOT_{} sig:   {} ({} bytes) ✓", i + 1, hex::encode(&sig_bytes[..8]), sig_bytes.len());
            signatures.push(sig_bytes);
        }
        
        // Save signed VBC
        let vbc_output_dir = output_dir.join(&validator.name);
        fs::create_dir_all(&vbc_output_dir).expect("Failed to create VBC output dir");
        
        let vbc = VBCOutput {
            version: config.ceremony.vbc_version,
            validator_id_hex: hex::encode(validator_id),
            subject_pubkey_sphincs_hex: hex::encode(&sphincs_pk),
            subject_pubkey_dilithium_hex: hex::encode(&dilithium_pk),
            subject_pubkey_ed25519_hex: hex::encode(&ed25519_pk_bytes),
            pgp_fingerprint_hex: hex::encode(&pgp_bytes),
            node_name: validator.name.clone(),
            issued_at: now,
            expires_at,
            chain_depth: 0,
            issuer_set: root_pks.iter().map(hex::encode).collect(),
            signatures: signatures.iter().map(hex::encode).collect(),
            name: validator.name.clone(),
            notes: validator.notes.clone().unwrap_or_default(),
            ceremony_ca: config.certificate_authority.name.clone(),
            ceremony_ca_pgp: config.certificate_authority.pgp_fingerprint.clone(),
        };
        
        let vbc_json = serde_json::to_string_pretty(&vbc).expect("Failed to serialize VBC");
        let vbc_path = vbc_output_dir.join("vbc.json");
        fs::write(&vbc_path, &vbc_json).expect("Failed to write VBC");
        println!("  VBC saved:    {}", vbc_path.display());
        
        // Also copy to validator's config directory
        let validator_vbc_path = vdir.join("config/vbc.json");
        if vdir.join("config").exists() {
            fs::write(&validator_vbc_path, &vbc_json).ok();
            println!("  VBC copied:   {}", validator_vbc_path.display());
        }

        // Generate genesis wallet_id from wallet_email (e.g. "validator_alpha@axiom/hex10")
        if let Some(ref email) = validator.wallet_email {
            let pk_arr: [u8; 32] = ed25519_pk_bytes.as_slice().try_into().expect("Ed25519 pk must be 32 bytes");
            let wallet_id = axiom_core_logic::wallet_id::generate_wallet_id(email, "00", &pk_arr)
                .unwrap_or_else(|e| panic!("Failed to generate wallet_id for {}: {:?}", email, e));
            let wallet_id_path = config_dir.join("wallet_id.txt");
            fs::write(&wallet_id_path, &wallet_id).expect("Failed to write wallet_id");
            println!("  Wallet ID:    {}", wallet_id);
        }

        genesis_sphincs_pks.push((validator.name.clone(), sphincs_pk));
    }
    
    // ========================================
    // Step 3: Generate genesis constants
    // ========================================
    println!("\n═══ Step 3: Generating genesis constants ═══");
    
    let mut rs = String::new();
    rs.push_str("// ============================================================================\n");
    rs.push_str("// AUTO-GENERATED by genesis-ceremony tool — DO NOT EDIT\n");
    rs.push_str(&format!("// Generated: {}\n", format_time(now)));
    rs.push_str(&format!("// CA: {} (PGP: {})\n", 
        config.certificate_authority.name,
        format_pgp(&config.certificate_authority.pgp_fingerprint)));
    rs.push_str("// ============================================================================\n");
    
    // Genesis validators
    rs.push_str("/// Genesis validators - hardcoded in Core.bin\n");
    rs.push_str("///\n");
    rs.push_str(&format!("/// These are the SPHINCS+ public keys of the {} Genesis validators (First Penguins).\n", genesis_sphincs_pks.len()));
    rs.push_str("/// They define the \"reality anchor\" - the root of trust for all VBCs.\n");
    rs.push_str("/// A VBC chain is valid if and only if all branches terminate at one of these keys.\n");
    rs.push_str("/// Used for backward-compatible overlap detection.\n");
    rs.push_str("/// VBC chain verification uses ROOT_AUTHORITY_PKS as trust anchor.\n");
    rs.push_str(&format!("pub const GENESIS_VALIDATORS: [[u8; 32]; {}] = [\n", genesis_sphincs_pks.len()));
    for (name, pk) in &genesis_sphincs_pks {
        rs.push_str(&format!("    // {}\n", name));
        rs.push_str(&format_bytes_as_rust(pk));
    }
    rs.push_str("];\n\n");
    
    // Root authority PKs
    rs.push_str("/// Root Authority SPHINCS+ public keys — the trust anchor of AXIOM.\n");
    rs.push_str("/// Chain verification stops when it hits one of these.\n");
    rs.push_str(&format!("/// Certificate Authority: {}\n", config.certificate_authority.name));
    rs.push_str(&format!("/// PGP: {}\n", format_pgp(&config.certificate_authority.pgp_fingerprint)));
    rs.push_str("pub const ROOT_AUTHORITY_PKS: [[u8; 32]; 3] = [\n");
    for (i, pk) in root_pks.iter().enumerate() {
        rs.push_str(&format!("    // ROOT_{}\n", i + 1));
        rs.push_str(&format_bytes_as_rust(pk));
    }
    rs.push_str("];\n\n");
    
    // CA PGP fingerprint
    rs.push_str("/// Certificate Authority PGP fingerprint (20 bytes)\n");
    rs.push_str(&format!("/// {}\n", format_pgp(&config.certificate_authority.pgp_fingerprint)));
    let ca_pgp_bytes = hex::decode(&config.certificate_authority.pgp_fingerprint).unwrap_or_default();
    rs.push_str("pub const CA_PGP_FINGERPRINT: [u8; 20] = [\n");
    rs.push_str(&format!("    {}\n", format_bytes_inline(&ca_pgp_bytes)));
    rs.push_str("];\n\n");
    
    // Helper functions — these depend on the constants above
    rs.push_str("/// Check if a public key is a root authority key\n");
    rs.push_str("pub fn is_root_authority(pk: &[u8]) -> bool {\n");
    rs.push_str("    if pk.len() != 32 {\n");
    rs.push_str("        return false;\n");
    rs.push_str("    }\n");
    rs.push_str("    let pk_array: [u8; 32] = pk.try_into().unwrap_or([0; 32]);\n");
    rs.push_str("    // Skip all-zero placeholder keys\n");
    rs.push_str("    if pk_array == [0u8; 32] {\n");
    rs.push_str("        return false;\n");
    rs.push_str("    }\n");
    rs.push_str("    ROOT_AUTHORITY_PKS.iter().any(|r| r == &pk_array)\n");
    rs.push_str("}\n\n");
    
    rs.push_str("/// Check if a public key is a genesis validator\n");
    rs.push_str("pub fn is_genesis_validator(pk: &[u8]) -> bool {\n");
    rs.push_str("    if pk.len() != 32 {\n");
    rs.push_str("        return false;\n");
    rs.push_str("    }\n");
    rs.push_str("    \n");
    rs.push_str("    let pk_array: [u8; 32] = pk.try_into().unwrap_or([0; 32]);\n");
    rs.push_str("    GENESIS_VALIDATORS.iter().any(|g| g == &pk_array)\n");
    rs.push_str("}\n");
    
    // Save to output directory (always, as backup)
    let rs_path = output_dir.join("genesis_constants.rs");
    fs::write(&rs_path, &rs).expect("Failed to write genesis_constants.rs");
    println!("  Saved backup: {}", rs_path.display());
    
    // ========================================
    // Step 4: Auto-install into Core genesis.rs
    // ========================================
    let core_genesis_path = config.ceremony.core_genesis_path.as_ref()
        .map(PathBuf::from);
    
    if let Some(ref genesis_path) = core_genesis_path {
        println!("\n═══ Step 4: Installing into Core genesis.rs ═══");
        println!("  Target: {}", genesis_path.display());
        
        if !genesis_path.exists() {
            eprintln!("  ERROR: genesis.rs not found at '{}'", genesis_path.display());
            eprintln!("  Constants saved to {} — install manually.", rs_path.display());
        } else {
            // Read existing genesis.rs
            let existing = fs::read_to_string(genesis_path)
                .expect("Failed to read existing genesis.rs");
            
            // Find the auto-generated marker
            let marker = "// ============================================================================\n// AUTO-GENERATED by genesis-ceremony tool";
            
            if let Some(marker_pos) = existing.find(marker) {
                // Replace everything from marker to end (but preserve tests)
                let static_part = &existing[..marker_pos];
                
                // Check if there's a #[cfg(test)] section after the auto-generated part
                let after_marker = &existing[marker_pos..];
                let test_section = after_marker.find("#[cfg(test)]")
                    .map(|pos| &after_marker[pos..]);
                
                // Assemble new genesis.rs
                let mut new_genesis = String::new();
                new_genesis.push_str(static_part);
                new_genesis.push_str(&rs);
                if let Some(tests) = test_section {
                    new_genesis.push('\n');
                    new_genesis.push_str(tests);
                }
                
                // Show what we're about to do
                println!();
                println!("  ┌─────────────────────────────────────────────┐");
                println!("  │ About to write {} constants into Core:      │", genesis_sphincs_pks.len());
                println!("  │   {} GENESIS_VALIDATORS", genesis_sphincs_pks.len());
                println!("  │   3 ROOT_AUTHORITY_PKS");
                println!("  │   1 CA_PGP_FINGERPRINT");
                println!("  │   is_root_authority() + is_genesis_validator()");
                println!("  │                                             │");
                println!("  │ Target: {}",  genesis_path.display());
                println!("  │ Static functions preserved: YES             │");
                println!("  │ Tests preserved: {}                     │", if test_section.is_some() { "YES" } else { "N/A" });
                println!("  └─────────────────────────────────────────────┘");
                println!();
                
                print!("  Install into Core? [y/N] ");
                io::stdout().flush().ok();
                
                let mut input = String::new();
                io::stdin().read_line(&mut input).ok();
                
                if input.trim().eq_ignore_ascii_case("y") {
                    // Backup existing
                    let backup_path = genesis_path.with_extension("rs.bak");
                    fs::copy(genesis_path, &backup_path)
                        .expect("Failed to backup genesis.rs");
                    println!("  Backup: {}", backup_path.display());
                    
                    // Write new
                    fs::write(genesis_path, &new_genesis)
                        .expect("Failed to write genesis.rs");
                    println!("  ✓ genesis.rs updated successfully");
                    println!("  ✓ Rebuild Core to activate new keys");
                } else {
                    println!("  Skipped. Constants saved to: {}", rs_path.display());
                }
            } else {
                eprintln!("  WARNING: Could not find auto-generated marker in genesis.rs");
                eprintln!("  This file may have been manually edited.");
                eprintln!("  Constants saved to {} — install manually.", rs_path.display());
            }
        }
    } else {
        println!("\n  NOTE: Set core_genesis_path in ceremony config for auto-install.");
        println!("  Constants saved to: {}", rs_path.display());
    }
    
    // ========================================
    // Summary
    // ========================================
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║           Genesis Ceremony Complete                   ║");
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║  Root keys:      {}/root_{{1,2,3}}.{{key,pub}}", root_keys_dir.display());
    println!("║  Signed VBCs:    {}/*/vbc.json", output_dir.display());
    println!("║  Rust constants: {}", rs_path.display());
    if core_genesis_path.is_some() {
        println!("║  Core genesis:   auto-installed (if confirmed)");
    }
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║  NEXT STEPS:                                         ║");
    println!("║  1. Move root-keys/ to OFFLINE storage                ║");
    println!("║  2. Rebuild Core, Lambda, ANTIE                       ║");
    println!("║  3. Run chaos test to verify VBC chain                ║");
    println!("╚════════════════════════════════════════════════════════╝");
}

// ============================================================================
// Helpers
// ============================================================================

// ============================================================================
// Helpers
// ============================================================================

/// Format PGP fingerprint with spaces
fn format_pgp(hex_str: &str) -> String {
    let chars: Vec<char> = hex_str.to_uppercase().chars().collect();
    let mut result = String::new();
    for (i, ch) in chars.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            result.push(' ');
        }
        if i == 20 {
            result.push(' ');  // Extra space in middle
        }
        result.push(*ch);
    }
    result
}

/// Format timestamp as human readable
fn format_time(epoch: u64) -> String {
    // Simple: just show YYYY-MM-DD
    let days = epoch / 86400;
    let years = 1970 + days / 365;
    let remaining_days = days % 365;
    let month = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;
    format!("{:04}-{:02}-{:02}", years, month.min(12), day.min(31))
}

/// Format bytes as Rust array literal
fn format_bytes_as_rust(bytes: &[u8]) -> String {
    let mut s = String::from("    [\n");
    for chunk in bytes.chunks(8) {
        s.push_str("        ");
        for (i, b) in chunk.iter().enumerate() {
            if i > 0 { s.push_str(", "); }
            s.push_str(&format!("0x{:02X}", b));
        }
        s.push_str(",\n");
    }
    s.push_str("    ],\n");
    s
}

/// Format bytes as inline Rust
fn format_bytes_inline(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ")
}
