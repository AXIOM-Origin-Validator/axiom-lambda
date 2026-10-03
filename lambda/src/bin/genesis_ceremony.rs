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
//!   {output_dir}/{validator}/vbc-bundle.cbor        — Signed VBC per validator (VBCProofBundle CBOR, ValidatorJoin §6b.12)
//!   {validator_path}/config/{ed25519,sphincs,dilithium}.{key,pub} — Validator keys
//!   Core genesis.rs — auto-installed (with confirmation)

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Signer, Verifier};
use serde::Deserialize;

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
    // Genesis re-domaining (the owner, 2026-09-20). Genesis is not the public join
    // path: the OPERATOR creates the stake wallet themselves (a validator never
    // mints its own wallet — feedback_validator_never_creates_wallets) and hands
    // the ceremony its id + Ed25519 key to bake into Core.
    //   wallet_id      = the full stake wallet_id string, e.g.
    //                    "alpha@trustmesh.org/27dbb7d0ba".
    //   stake_key_path = path to the Ed25519 stake PRIVATE key to import
    //                    (raw 32 bytes, as written to config/ed25519.key, or 64-hex).
    // REAL ceremony: BOTH required (missing → error). REHEARSAL (--rehearsal):
    // BOTH absent → the tool mints a fresh key + derives the id on the spot.
    // Exactly one set without the other is a config error. When wallet_id is given
    // it is verified for its key-independent binding (email + salt) to the imported
    // key + wallet_email; the id that BAKES is derived under this network's key and
    // printed (see `genesis_stake_wallet_id` — 2026-09-25 finding).
    wallet_id: Option<String>,
    stake_key_path: Option<String>,
    // `notes` in genesis-ceremony.toml is for humans; the certificate carries no notes (§6b.12 point 6).
}

/// The genesis STAKE wallet id that bakes into Core for one validator, given
/// the operator's imported Ed25519 pk, their `wallet_email`, and (real run)
/// the `wallet_id` they typed into the toml.
///
/// ⚠ FOUND 2026-09-25 on the first temporary re-domaining run. A wallet_id's
/// checksum(6) AND pk_bind(2) are both keyed by `WALLET_IDENTITY_KEY`
/// (`wallet_id::compute_checksum`, `compute_pk_bind` — the MASTER pk is in
/// both preimages); only the trailing salt(2) = `default_salt(pk)` =
/// BLAKE3(pk)[..2] comes from the key alone. The operator creates the stake
/// wallet BEFORE the ceremony, i.e. under the PRE-ceremony key, and the
/// MASTER key this network will use does not exist until the ceremony mints
/// it. So the operator CANNOT know the post-ceremony id, and the old
/// `provided == derived` check could only ever pass by accident of order
/// (the 09-20/21 rehearsals minted keys and derived ids inside the tool).
/// Measured: lockup `alpha@trustmesh.org/df7cfe1a94` (pre-ceremony key) vs
/// the new network's own derivation `alpha@trustmesh.org/d0d3168494` — same
/// pk, same email, only the salt `94` agrees. A baked id the network does
/// not derive means `GENESIS_LOCKUP_WALLET_IDS` (the `E_GENESIS_STAKE_LOCKED`
/// key) names nothing.
///
/// Therefore the provided id is verified for its KEY-INDEPENDENT binding —
/// (i) its email == `wallet_email`, (ii) its salt == `default_salt(pk)`
/// (8 bits of pk binding, the same width as pk_bind) — and the id that bakes
/// is always the one DERIVED under `master_pk` (the compiled, post-bake
/// `WALLET_IDENTITY_KEY` in the real tool). `verify_pk_binding` is NOT used
/// here on purpose: under the new key it refuses every honestly-provided
/// pre-ceremony id.
///
/// Returns `(baked_id, Some(provided))` when the operator's string differs
/// from the baked one (expected on a real run — the caller prints the
/// mapping), `(baked_id, None)` when they agree or nothing was provided.
fn genesis_stake_wallet_id(
    name: &str,
    email: &str,
    master_pk: &[u8; 32],
    pk: &[u8; 32],
    provided: Option<&str>,
) -> Result<(String, Option<String>), String> {
    use axiom_core_logic::wallet_id::{default_salt, extract_email, generate_wallet_id_with_identity_key, parse_wallet_id};
    let salt = default_salt(pk);
    // Derived with the SDK's own salt rule so the id written here is byte-equal
    // to the address the SDK derives from the same key under this network's key.
    let derived = generate_wallet_id_with_identity_key(email, &salt, master_pk, pk)
        .map_err(|e| format!("ERROR [{}]: cannot derive a wallet_id for '{}': {:?}", name, email, e))?;
    let Some(provided) = provided else { return Ok((derived, None)); };
    let (p_email, _checksum, _pk_bind, p_salt) = parse_wallet_id(provided)
        .map_err(|e| format!("ERROR [{}]: provided wallet_id '{}' is malformed: {:?}", name, provided, e))?;
    let want_email = extract_email(&derived).expect("derived id parses");
    if p_email != want_email {
        return Err(format!(
            "ERROR [{}]: provided wallet_id '{}' carries email '{}' but wallet_email is '{}'. Fix the toml wallet_id or wallet_email.",
            name, provided, p_email, want_email));
    }
    if p_salt != salt {
        return Err(format!(
            "ERROR [{}]: provided wallet_id '{}' does NOT bind to the imported key (its salt '{}' ≠ BLAKE3(pk)[..2] = '{}' for stake_key_path's key). Point stake_key_path at the key that created this wallet, or fix the toml wallet_id.",
            name, provided, p_salt, salt));
    }
    if provided == derived { Ok((derived, None)) } else { Ok((derived, Some(provided.to_string()))) }
}

/// Parse an Ed25519 private key from a file's bytes: raw 32 bytes, or a 64-char
/// hex string (whitespace trimmed). Returns None if it is neither.
fn parse_ed25519_sk(raw: &[u8]) -> Option<[u8; 32]> {
    if raw.len() == 32 {
        return raw.try_into().ok();
    }
    let s = std::str::from_utf8(raw).ok()?.trim();
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
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
        eprintln!("Usage: genesis-ceremony --config <path-to-genesis-ceremony.toml> [--rehearsal]");
        std::process::exit(1);
    };
    // Rehearsal lets a validator without wallet_id/stake_key_path mint a fresh key
    // on the spot; a real ceremony REQUIRES both to be provided per validator.
    let rehearsal = args.iter().any(|a| a == "--rehearsal");

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
    // §6c — the ten genesis stake wallet ids, written to genesis_lockup_wallets.txt.
    let mut genesis_stake_wallet_ids: Vec<String> = Vec::new();
    
    for validator in &config.validators {
        println!("\n  --- {} ---", validator.name);
        
        let vdir = PathBuf::from(&validator.path);
        let config_dir = vdir.join("config");
        fs::create_dir_all(&config_dir).ok();

        if validator.wallet_id.is_some() && validator.wallet_email.is_none() {
            eprintln!("ERROR [{}]: wallet_id is set but wallet_email is missing — the id can only be verified against its email.", validator.name);
            std::process::exit(1);
        }

        // Ed25519 = the genesis STAKE wallet key (it is this VBC's subject key AND
        // the key the stake wallet_id derives from, below). Real ceremony: import
        // the operator's pre-created key; rehearsal with nothing provided: mint one.
        let (ed25519_sk_bytes, ed25519_key_imported): (Vec<u8>, bool) =
            match (&validator.wallet_id, &validator.stake_key_path) {
                (Some(_), Some(kp)) => {
                    let raw = fs::read(kp).unwrap_or_else(|e| {
                        eprintln!("ERROR [{}]: cannot read stake_key_path '{}': {}", validator.name, kp, e);
                        std::process::exit(1);
                    });
                    let key = parse_ed25519_sk(&raw).unwrap_or_else(|| {
                        eprintln!("ERROR [{}]: stake_key_path '{}' is not a 32-byte Ed25519 key (raw 32 bytes or 64-hex).", validator.name, kp);
                        std::process::exit(1);
                    });
                    (key.to_vec(), true)
                }
                (None, None) => {
                    if !rehearsal {
                        eprintln!("ERROR [{}]: a REAL genesis ceremony requires `wallet_id` + `stake_key_path` in genesis-ceremony.toml — the operator creates the stake wallet and the ceremony imports it (never mints). Provide both, or run with --rehearsal to mint on the spot.", validator.name);
                        std::process::exit(1);
                    }
                    (ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).to_bytes().to_vec(), false)
                }
                _ => {
                    eprintln!("ERROR [{}]: set BOTH `wallet_id` and `stake_key_path`, or NEITHER (rehearsal mints). One without the other is a config error.", validator.name);
                    std::process::exit(1);
                }
            };
        let ed25519_sk = ed25519_dalek::SigningKey::from_bytes(
            ed25519_sk_bytes.as_slice().try_into().expect("Ed25519 SK must be 32 bytes"));
        let ed25519_pk = ed25519_sk.verifying_key();
        let ed25519_pk_bytes = ed25519_pk.as_bytes().to_vec();

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
        println!("  Ed25519 PK:   {} ({})", hex::encode(&ed25519_pk_bytes[..8]),
                 if ed25519_key_imported { "IMPORTED from stake_key_path" } else { "GENERATED (rehearsal)" });
        
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
            genesis_lineage: [0u8; 32],
            nabla_registration: None,
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
        
        // ValidatorJoin §6b.12 point 6 — the ceremony's certificate output is Core's typed bundle in
        // CBOR (depth 0, no issuer certificates): the one file validators load. The hand-rolled
        // `VBCOutput` JSON copy that stood here is gone; its extra fields (name, notes, CA) are this
        // ceremony's own input config.
        let signed_vbc = axiom_core_logic::types::VBC { signatures: signatures.clone(), ..core_vbc.clone() };
        let bundle = axiom_core_logic::types::VBCProofBundle { target_vbc: signed_vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
        let mut bundle_cbor = Vec::new();
        ciborium::into_writer(&bundle, &mut bundle_cbor).expect("Failed to encode VBC bundle");
        let bundle_path = vbc_output_dir.join("vbc-bundle.cbor");
        fs::write(&bundle_path, &bundle_cbor).expect("Failed to write VBC bundle");
        println!("  VBC saved:    {}", bundle_path.display());

        // Also copy to validator's config directory
        if vdir.join("config").exists() {
            let validator_bundle_path = vdir.join("config/vbc-bundle.cbor");
            fs::write(&validator_bundle_path, &bundle_cbor).ok();
            println!("  VBC copied:   {}", validator_bundle_path.display());
        }

        // §6c — the GENESIS STAKE WALLET id (e.g. "alpha@trustmesh.org/d0d3168494"):
        // the wallet whose key IS this validator's Ed25519 key, opening at the
        // ceremony-minted 1,000,000 AXC (GenesisDistribution §2.3a). Derived
        // with the SDK's own salt rule (`wallet_id::default_salt`) so the id
        // written here is byte-equal to the address the SDK derives from the
        // same key — a fixed "00" salt (until 2026-09-08) produced a second
        // address for one key. Collected into genesis_lockup_wallets.txt below:
        // Core compiles that list in, and it is what makes the wallet a genesis
        // stake wallet everywhere (`genesis::genesis_opening_balance`).
        //
        // The id that bakes is ALWAYS the one derived under the COMPILED
        // WALLET_IDENTITY_KEY — which is why g1-full-ceremony.sh bakes the MASTER
        // key into wallet_id.rs and REBUILDS this tool before running it. A
        // provided (real-run) id is verified for its key-independent binding only;
        // see `genesis_stake_wallet_id` for the 2026-09-25 finding. An earlier
        // version required `provided == derived`, which under the pre-ceremony
        // key baked ids this network never derives.
        if let Some(ref email) = validator.wallet_email {
            let pk_arr: [u8; 32] = ed25519_pk_bytes.as_slice().try_into().expect("Ed25519 pk must be 32 bytes");
            let (wallet_id, operator_id) = genesis_stake_wallet_id(
                &validator.name, email, &axiom_core_logic::wallet_id::WALLET_IDENTITY_KEY, &pk_arr,
                validator.wallet_id.as_deref(),
            ).unwrap_or_else(|msg| { eprintln!("{}", msg); std::process::exit(1); });
            let wallet_id_path = config_dir.join("wallet_id.txt");
            fs::write(&wallet_id_path, &wallet_id).expect("Failed to write wallet_id");
            println!("  Stake wallet: {}", wallet_id);
            if let Some(op) = operator_id {
                // Expected on a real run, not an error: the operator's wallet was
                // created under the PRE-ceremony key; this is the id the network
                // derives for the same key + email. RECORD the baked id.
                println!("  [{}] operator id {} (pre-ceremony key) → baked id {} (this network's key)", validator.name, op, wallet_id);
            }
            // `<wallet_id> <ed25519_pk_hex>` — the KEY column is the identity Core
            // compiles in (GENESIS_STAKE_WALLET_PKS); the id is an address.
            genesis_stake_wallet_ids.push(format!("{} {}", wallet_id, hex::encode(&pk_arr)));
        } else {
            println!("  ⚠ no wallet_email — this validator gets NO genesis stake wallet id (§6c)");
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
    rs.push_str("/// ⚠ These are NOT the VBC trust anchor. VBC chain verification terminates at\n");
    rs.push_str("/// `ROOT_AUTHORITY_PKS` (`vbc.rs::verify_chain_recursive`, `root_check`); this\n");
    rs.push_str("/// table is used for reserved-name enforcement\n");
    rs.push_str("/// (`vbc.rs::enforce_genesis_name_reservation`, which compares\n");
    rs.push_str("/// `subject_pubkey_sphincs`) and for backward-compatible overlap detection.\n");
    rs.push_str("/// An earlier version of this comment called it \"the root of trust for all\n");
    rs.push_str("/// VBCs\" and said chains terminate here — that was wrong.\n");
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
    // §6c — genesis_lockup_wallets.txt: the ten genesis stake wallet ids, ONE per
    // line. Core's build.rs compiles it into GENESIS_LOCKUP_WALLET_IDS, which is
    // both the 3-year lock's key and the membership test behind
    // `genesis::genesis_opening_balance`. Saved with the constants; installed
    // beside genesis.rs (core/logic/genesis_lockup_wallets.txt) on the same
    // confirmation as the constants below.
    let lockup_list = {
        let mut t = String::from("# Genesis STAKE wallets — `<wallet_id> <ed25519_pk_hex>` per line, exactly the genesis validators (§6c).\n");
        t.push_str("# Written by the G1 ceremony (lambda/src/bin/genesis_ceremony.rs) from each\n");
        t.push_str("# validator's wallet_email + Ed25519 key. Core compiles this list in.\n");
        for id in &genesis_stake_wallet_ids { t.push_str(id); t.push('\n'); }
        t
    };
    let lockup_list_path = output_dir.join("genesis_lockup_wallets.txt");
    fs::write(&lockup_list_path, &lockup_list).expect("Failed to write genesis_lockup_wallets.txt");
    println!("  Lockup list:  {} ({} ids)", lockup_list_path.display(), genesis_stake_wallet_ids.len());

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
                    // §6c — the lockup list lives at core/logic/genesis_lockup_wallets.txt,
                    // i.e. two levels up from core/logic/src/genesis.rs.
                    if let Some(core_logic_dir) = genesis_path.parent().and_then(|p| p.parent()) {
                        let list_target = core_logic_dir.join("genesis_lockup_wallets.txt");
                        fs::write(&list_target, &lockup_list)
                            .expect("Failed to write genesis_lockup_wallets.txt");
                        println!("  ✓ {} written ({} genesis stake wallet ids)", list_target.display(), genesis_stake_wallet_ids.len());
                    }
                    println!("  ✓ Rebuild Core to activate new keys");
                } else {
                    println!("  Skipped. Constants saved to: {}", rs_path.display());
                }
            } else {
                // 2026-09-11 (G1 rehearsal 3): this used to be a WARNING followed by exit 0 —
                // a ceremony that did not install its constants reported success. Hard error.
                eprintln!("  ERROR: Could not find the auto-generated marker in genesis.rs — constants NOT installed");
                eprintln!("  This file may have been manually edited.");
                eprintln!("  Constants saved to {} — restore the two-line marker and re-run.", rs_path.display());
                std::process::exit(1);
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
    println!("║  Signed VBCs:    {}/*/vbc-bundle.cbor", output_dir.display());
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

#[cfg(test)]
mod tests {
    use super::genesis_stake_wallet_id;
    use axiom_core_logic::wallet_id::{default_salt, generate_wallet_id_with_identity_key, parse_wallet_id};

    const EMAIL: &str = "alpha@trustmesh.org";
    // PRE-ceremony master key (what the operator's wallet was created under) and
    // the key the ceremony bakes (what the tool is compiled with when it runs).
    const PRE_KEY: [u8; 32] = [0x11; 32];
    const NEW_KEY: [u8; 32] = [0x22; 32];

    fn pk(seed: u8) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()
    }

    /// The 2026-09-25 shape: the operator's id (pre-ceremony key) differs in
    /// checksum + pk_bind, agrees in email + salt → ACCEPTED, and what bakes is
    /// the id derived under the NEW key, with the operator's string reported.
    #[test]
    fn provided_pre_ceremony_id_is_accepted_and_the_derived_id_bakes() {
        let pk = pk(7);
        let salt = default_salt(&pk);
        let operator_id = generate_wallet_id_with_identity_key(EMAIL, &salt, &PRE_KEY, &pk).unwrap();
        let network_id = generate_wallet_id_with_identity_key(EMAIL, &salt, &NEW_KEY, &pk).unwrap();
        assert_ne!(operator_id, network_id, "test premise: the two keys derive different ids");
        // Prove the premise the fix rests on: prefix differs, salt agrees.
        let (_, oc, ob, os) = parse_wallet_id(&operator_id).unwrap();
        let (_, nc, nb, ns) = parse_wallet_id(&network_id).unwrap();
        assert!(oc != nc || ob != nb, "checksum/pk_bind must be key-dependent");
        assert_eq!(os, ns, "salt is key-independent");

        let (baked, reported) = genesis_stake_wallet_id("alpha", EMAIL, &NEW_KEY, &pk, Some(&operator_id)).unwrap();
        assert_eq!(baked, network_id, "the DERIVED id is what bakes");
        assert_eq!(reported.as_deref(), Some(operator_id.as_str()), "the operator's id is reported for the mapping line");
    }

    #[test]
    fn provided_id_equal_to_derived_is_accepted_silently() {
        let pk = pk(8);
        let network_id = generate_wallet_id_with_identity_key(EMAIL, &default_salt(&pk), &NEW_KEY, &pk).unwrap();
        let (baked, reported) = genesis_stake_wallet_id("alpha", EMAIL, &NEW_KEY, &pk, Some(&network_id)).unwrap();
        assert_eq!(baked, network_id);
        assert!(reported.is_none());
    }

    #[test]
    fn no_provided_id_derives_under_the_compiled_key() {
        let pk = pk(9);
        let network_id = generate_wallet_id_with_identity_key(EMAIL, &default_salt(&pk), &NEW_KEY, &pk).unwrap();
        let (baked, reported) = genesis_stake_wallet_id("alpha", EMAIL, &NEW_KEY, &pk, None).unwrap();
        assert_eq!(baked, network_id);
        assert!(reported.is_none());
    }

    /// The id was created from a DIFFERENT Ed25519 key than stake_key_path's:
    /// its salt = BLAKE3(other_pk)[..2] ≠ BLAKE3(pk)[..2] → refused.
    #[test]
    fn wrong_key_is_refused_by_the_salt() {
        let pk = super::tests::pk(10);
        // find a pk whose salt differs (BLAKE3 prefix collides 1/256 of the time)
        let other = (11u8..).map(super::tests::pk).find(|o| default_salt(o) != default_salt(&pk)).unwrap();
        let operator_id = generate_wallet_id_with_identity_key(EMAIL, &default_salt(&other), &PRE_KEY, &other).unwrap();
        let err = genesis_stake_wallet_id("alpha", EMAIL, &NEW_KEY, &pk, Some(&operator_id)).unwrap_err();
        assert!(err.contains("does NOT bind to the imported key"), "{err}");
    }

    #[test]
    fn wrong_email_is_refused() {
        let pk = pk(12);
        let operator_id = generate_wallet_id_with_identity_key("beta@trustmesh.org", &default_salt(&pk), &PRE_KEY, &pk).unwrap();
        let err = genesis_stake_wallet_id("alpha", EMAIL, &NEW_KEY, &pk, Some(&operator_id)).unwrap_err();
        assert!(err.contains("carries email 'beta@trustmesh.org' but wallet_email is 'alpha@trustmesh.org'"), "{err}");
    }

    #[test]
    fn malformed_provided_id_is_refused() {
        let pk = pk(13);
        let err = genesis_stake_wallet_id("alpha", EMAIL, &NEW_KEY, &pk, Some("alpha@trustmesh.org/zz")).unwrap_err();
        assert!(err.contains("is malformed"), "{err}");
    }
}
