//! Lambda configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use crate::error::LambdaError;

/// Lambda configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaConfig {
    /// Network configuration
    pub network: NetworkConfig,

    /// Storage configuration
    pub storage: StorageConfig,

    /// Validator configuration
    pub validator: ValidatorConfig,

    /// Proof configuration (ZKP vs DMAP tiering)
    #[serde(default)]
    pub proof: ProofConfig,

    /// Fee configuration — operator's published fee schedule
    #[serde(default)]
    pub fees: FeeConfig,

    /// Operator identity — public-facing information for clients
    #[serde(default)]
    pub operator: OperatorConfig,

    /// Oracle conversion rate configuration — operators adjust rates without recompiling Core.
    /// Core only enforces the 5 AXC cap; Lambda computes the payout from these rates.
    #[serde(default)]
    pub oracle: OracleConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Admin HTTP port for validator console (optional, disabled by default).
    /// Binds to 127.0.0.1 only. Enable with --admin-port or [admin] port = 7780.
    #[serde(default)]
    pub admin_port: Option<u16>,

    /// Bearer token for admin endpoint authentication (optional).
    /// If set, all admin endpoints except /health require ?token=<value>.
    #[serde(default)]
    pub admin_token: Option<String>,

    /// Minimum number of known peer validators for fee redemption to work.
    /// Fee redemption requires k=3 non-overlapping validators. With exactly 3
    /// validators, all 3 witnessed the original TX — zero eligible for fee
    /// witnessing. Minimum viable network for fees is 6 validators.
    /// This is a warning threshold, not a hard gate — validators still start.
    #[serde(default = "default_min_validators_for_fees")]
    pub min_validators_for_fee_redemption: usize,

    /// Operator soft limit on FACT chain total links (resolved + scarred).
    /// Chains exceeding this are rejected BEFORE AVM execution — saves CPU.
    /// Default: 16 (~1.3MB CBOR, ~25s interpreter). JIT operators may raise.
    /// Core hard limit is 64 (protocol ceiling, not configurable).
    /// Set to 0 to disable (use Core's hard limit only).
    #[serde(default = "default_max_fact_links")]
    pub max_fact_links: usize,

    /// Maximum fee (in atoms) validators can charge on scarred cheques.
    /// Prevents fee laundering: validator charges 100% fee on scarred cheque,
    /// receives clean (unscarred) coins. Cap makes this economically worthless.
    /// Default: 100,000 atoms (0.00001 AXC). Set to 0 to disable cap.
    #[serde(default = "default_scarred_fee_cap")]
    pub scarred_cheque_fee_cap_atoms: u64,

    /// Storage VACUUM interval in seconds. SQLite doesn't reclaim disk from
    /// deleted rows until VACUUM runs. Higher load = more dead pages between
    /// cycles. Default: 1800 (30 min). High-load validators may lower to 300
    /// (5 min). Set to 0 to disable periodic VACUUM (inline cleanup still runs).
    #[serde(default = "default_vacuum_interval")]
    pub vacuum_interval_secs: u64,
}

fn default_min_validators_for_fees() -> usize { 6 }
/// NOT a hardcoded literal — the value is a tuning register in
/// protocol_lambda.toml, baked by build.rs into `tuning_gen::MAX_FACT_LINKS`.
/// Delete that key and this FAILS TO COMPILE (no const is emitted), which is
/// deliberate: the previous `{ 16 }` meant a lambda.toml with no value silently
/// got 16 and nothing reported it. That silently wedged a low-activity wallet
/// on 2026-08-18 — chain legitimately at 23 links while its SEC-07 checkpoint
/// accumulated co-signs, refused by Lambda at 16 under an error naming
/// MAX_FACT_DEPTH, a constant that is not even on the live path.
fn default_max_fact_links() -> usize { crate::tuning_gen::MAX_FACT_LINKS as usize }
fn default_scarred_fee_cap() -> u64 { 100_000 } // 0.00001 AXC
fn default_vacuum_interval() -> u64 { 1800 } // 30 minutes
fn default_vbc_renewal() -> u64 { 86_400 } // 24 hours

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Listen address (e.g., "127.0.0.1:9000" or "unix:/var/run/lambda.sock")
    pub listen: String,

    /// Connection timeout in seconds
    pub timeout_secs: u64,

    /// TLS certificate path (PEM). If set with tls_key_path, enables TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_path: Option<String>,

    /// TLS private key path (PEM). If set with tls_cert_path, enables TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to transaction database (SQLCipher encrypted)
    ///
    /// Replaces the old `state_db` + `receipts_db` pair.
    /// If the old fields are present, `transaction_db` takes precedence.
    pub transaction_db: PathBuf,

    /// Path to management database (SQLCipher encrypted)
    ///
    /// Used by Console governance, DWP/JFP, and freeze orders.
    #[serde(default = "default_management_db")]
    pub management_db: PathBuf,

    /// Maximum validator hints to store (default: 1024)
    #[serde(default = "default_max_hints")]
    pub max_hints: usize,


    // Legacy fields — ignored, kept for backwards compatibility during migration
    #[serde(default, skip_serializing, rename = "state_db")]
    _state_db: Option<PathBuf>,
    #[serde(default, skip_serializing, rename = "receipts_db")]
    _receipts_db: Option<PathBuf>,
}

fn default_max_hints() -> usize {
    1024
}

fn default_management_db() -> PathBuf {
    PathBuf::from("./data/management.db")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Ed25519 operational signing key path (default)
    pub private_key_path: PathBuf,

    /// [DEPRECATED] core-bin is no longer used. Lambda executes via AVM interpreter directly.
    /// The ELF is now named axiom-core.elf. Kept for config file backwards compatibility — silently ignored.
    #[serde(default, skip_serializing, rename = "core_bin_path")]
    pub _core_bin_path: Option<PathBuf>,

    /// Dilithium (ML-DSA-65) operational signing key path
    #[serde(default)]
    pub dilithium_key_path: Option<PathBuf>,

    /// Dilithium public key path
    #[serde(default)]
    pub dilithium_pub_path: Option<PathBuf>,

    /// SPHINCS+ (SLH-DSA-SHA2-128s) VBC identity key path
    #[serde(default)]
    pub sphincs_key_path: Option<PathBuf>,

    /// SPHINCS+ public key path
    #[serde(default)]
    pub sphincs_pub_path: Option<PathBuf>,

    /// VBC JSON path
    #[serde(default)]
    pub vbc_path: Option<PathBuf>,

    /// Minimum required witnesses (k)
    pub min_witnesses: usize,

    /// [DEPRECATED] ZK proofs are always generated. This field is ignored.
    #[serde(default)]
    pub generate_proofs: bool,
}

/// Proof generation configuration — controls ZKP vs DMAP tiering
///
/// # Proof Tiers
/// - `dmap`: DMAP memory attestation (~10-50ms, ~20KB). Default for all validators.
///   Probabilistic detection with ≥13 nines (99.9999999999999%) for security-critical attacks.
/// - `zkp`: Real RISC Zero STARK proof (~200s CPU / ~4s GPU, ~500KB). Mathematical certainty.
///   Only for high-performance validators with GPU proving capability.
///
/// Default: DMAP. ZKP requires zkVM artifacts (axiom-core.elf + image-id) and
/// significant compute resources (GPU recommended). DMAP requires `riscv-interpreter`
/// feature on axiom-dmap-vm and a compiled axiom-core.elf binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofConfig {
    /// Default proof type for standard transactions: "dmap" (default) or "zkp"
    /// ZKP mode requires GPU-class hardware for practical proving times.
    #[serde(default = "default_proof_mode")]
    pub mode: String,

    /// Path to axiom-core.elf (required for DMAP mode)
    #[serde(default)]
    pub avm_elf_path: Option<PathBuf>,

    /// Path to axiom-core image-id.hex (optional, for cross-check)
    #[serde(default)]
    pub avm_image_id_path: Option<PathBuf>,
}

fn default_proof_mode() -> String {
    "dmap".to_string()
}

impl Default for ProofConfig {
    fn default() -> Self {
        ProofConfig {
            mode: "dmap".to_string(),
            avm_elf_path: None,
            avm_image_id_path: None,
        }
    }
}

/// Fee configuration — operator's published fee schedule.
///
/// Clients see these values via VSP (YPX-008) before choosing a validator.
/// Validators compete on fees — lower fees attract more transactions.
///
/// Example TOML:
/// ```toml
/// [fees]
/// rate_bps = 30           # 0.30% per transaction (= MAX_VALIDATOR_FEE_BPS cap; higher is clamped)
/// valid_until = 1735689600  # 2025-01-01 — when this rate expires
/// min_amount = 10000      # minimum fee in atoms (dust floor)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    /// Fee rate in basis points (1 bps = 0.01%). Default: 50 bps = 0.50%.
    #[serde(default = "default_fee_rate")]
    pub rate_bps: u32,

    /// Unix timestamp when this fee schedule expires.
    /// After expiry, clients should re-query VSP for updated fees.
    /// Default: 0 (no expiry — rate valid indefinitely).
    #[serde(default)]
    pub valid_until: u64,

    /// Minimum fee in atoms (dust floor for fees). Default: 10000.
    #[serde(default = "default_min_fee")]
    pub min_amount: u64,
}

fn default_fee_rate() -> u32 { 30 } // 0.30% = MAX_VALIDATOR_FEE_BPS. Was a
// misleading 50 (0.50%): consensus clamps every rate to the 30-bps cap
// (`MAX_VALIDATOR_FEE_BPS`, validation.rs), so 50 charged 30 anyway and only
// misled operators into thinking they earned 0.50%. Audit Area 2 fix.
fn default_min_fee() -> u64 { 10_000 }

impl Default for FeeConfig {
    fn default() -> Self {
        FeeConfig {
            rate_bps: default_fee_rate(),
            valid_until: 0,
            min_amount: default_min_fee(),
        }
    }
}

/// Oracle conversion rate configuration.
///
/// Lambda uses these rates to compute `payout_amount` on oracle cheques.
/// Core only validates: payout_amount <= 5 AXC AND platform is whitelisted.
/// Operators can adjust rates in lambda.toml without recompiling Core.
///
/// Example TOML:
/// ```toml
/// [oracle]
/// enabled = true
///
/// [oracle.conversion_rates]
/// "https://foldingathome.org" = 10000
/// "https://einstein.phys.uwm.edu" = 8000
/// "https://www.zooniverse.org" = 2
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleConfig {
    /// Whether oracle claim processing is enabled on this validator.
    /// Default: false (disabled). Operators must explicitly enable oracle claims
    /// in their config once ZK-TLS verification is implemented.
    #[serde(default)]
    pub enabled: bool,

    /// VBC auto-renewal interval in seconds when oracle is enabled.
    /// Oracle distribution carries higher economic weight — a stale VBC (>24h)
    /// increases stake staleness risk. When enabled > 0, Lambda triggers CL8
    /// VBC renewal on this schedule automatically.
    /// Set to 0 to disable auto-renewal (manual CL8 only).
    /// Default: 86400 (24 hours). Reference: YPX-012 §2.5, YP §25.5.4.
    #[serde(default = "default_vbc_renewal")]
    pub vbc_renewal_interval_secs: u64,

    /// Platform URL → credits per 1 AXC. Lambda computes: payout = credit_delta / rate.
    /// Defaults match Core's initial whitelist rates (backward compatible).
    #[serde(default = "default_conversion_rates")]
    pub conversion_rates: HashMap<String, u64>,
}

fn default_conversion_rates() -> HashMap<String, u64> {
    let mut m = HashMap::new();
    // Compute platforms (same initial rates as Core whitelist)
    m.insert("https://foldingathome.org".into(), 10_000);
    m.insert("https://einstein.phys.uwm.edu".into(), 8_000);
    m.insert("https://boinc.bakerlab.org".into(), 8_000);
    m.insert("https://lhcathome.cern.ch".into(), 8_000);
    m.insert("https://milkyway.cs.rpi.edu".into(), 8_000);
    m.insert("https://universeathome.pl".into(), 8_000);
    m.insert("https://www.worldcommunitygrid.org".into(), 8_000);
    // Human classification platforms
    m.insert("https://www.zooniverse.org".into(), 2);
    m.insert("https://www.inaturalist.org".into(), 20);
    // Mapping and knowledge platforms
    m.insert("https://www.openstreetmap.org".into(), 3);
    m.insert("https://www.wikipedia.org".into(), 5);
    m
}

impl Default for OracleConfig {
    fn default() -> Self {
        OracleConfig {
            enabled: false,
            vbc_renewal_interval_secs: default_vbc_renewal(),
            conversion_rates: default_conversion_rates(),
        }
    }
}

impl OracleConfig {
    /// Compute AXC payout for a given platform and credit delta.
    /// Returns 0 if platform not configured or rate is 0.
    /// Compute the payout for a claim, **in atoms**.
    ///
    /// `conversion_rates` are credits-per-AXC, so `credit_delta / rate` yields
    /// whole AXC; the result is converted to atoms via the denomination lib.
    /// Before the D6 fix (2026-07-28) this returned the raw AXC count, which
    /// Core then compared against an atom cap and credited into an atom balance
    /// — a 10^10 under-payment. Keep the `axc()` conversion here: Core's cap and
    /// the credited balance are both atoms, and this is the only place the rate
    /// is applied.
    pub fn compute_payout(&self, platform_url: &str, credit_delta: u64) -> u64 {
        match self.conversion_rates.get(platform_url) {
            Some(&rate) if rate > 0 => axiom_denomination::axc(credit_delta / rate),
            _ => 0,
        }
    }
}

/// Operator identity — public-facing information for clients.
///
/// This is NOT verified by the protocol. Operators self-report this data.
/// Clients use it for validator selection alongside protocol-verified data
/// (stake from VBC, proof_cap, uptime).
///
/// Example TOML:
/// ```toml
/// [operator]
/// name = "Penguin Validators Ltd"
/// jurisdiction = "SG"       # ISO 3166-1 alpha-2 country code
/// contact = "ops@penguin.example.com"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfig {
    /// Operator name (individual or organization). Default: "Anonymous".
    #[serde(default = "default_operator_name")]
    pub name: String,

    /// Jurisdiction — ISO 3166-1 alpha-2 country code (e.g., "SG", "US", "JP").
    /// "NONE" if the operator chooses not to disclose. Default: "NONE".
    #[serde(default = "default_jurisdiction")]
    pub jurisdiction: String,

    /// Contact information (email, URL, etc.). Optional.
    #[serde(default)]
    pub contact: String,

    /// Supported encryption for cheque email delivery (e.g., "PGP", "GPG", "none").
    /// Receivers with matching suffix in wallet_id (-P, -G) will get encrypted cheques.
    #[serde(default)]
    pub supported_encryption: String,

    /// Encryption public key (PGP/GPG armored key block or base64).
    /// Clients can use this to encrypt messages TO this validator.
    #[serde(default)]
    pub encryption_public_key: String,

    /// Free-text notes (maintenance schedule, announcements, ToS URL, etc.).
    #[serde(default)]
    pub notes: String,
}

fn default_operator_name() -> String { "Anonymous".to_string() }
fn default_jurisdiction() -> String { "NONE".to_string() }

impl Default for OperatorConfig {
    fn default() -> Self {
        OperatorConfig {
            name: default_operator_name(),
            jurisdiction: default_jurisdiction(),
            contact: String::new(),
            supported_encryption: String::new(),
            encryption_public_key: String::new(),
            notes: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
}

impl Default for LambdaConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                listen: "127.0.0.1:9000".to_string(),
                timeout_secs: 30,
                tls_cert_path: None,
                tls_key_path: None,
            },
            storage: StorageConfig {
                transaction_db: PathBuf::from("./data/lambda.db"),
                management_db: PathBuf::from("./data/management.db"),
                max_hints: 1024,
                _state_db: None,
                _receipts_db: None,
            },
            validator: ValidatorConfig {
                private_key_path: PathBuf::from("./config/ed25519.key"),
                _core_bin_path: None,
                dilithium_key_path: Some(PathBuf::from("./config/dilithium.key")),
                dilithium_pub_path: Some(PathBuf::from("./config/dilithium.pub")),
                sphincs_key_path: Some(PathBuf::from("./config/sphincs.key")),
                sphincs_pub_path: Some(PathBuf::from("./config/sphincs.pub")),
                vbc_path: Some(PathBuf::from("./config/vbc-bundle.cbor")), // §6b.12 — the CBOR bundle
                min_witnesses: 3,
                generate_proofs: false,
            },
            proof: ProofConfig::default(),
            oracle: OracleConfig::default(),
            fees: FeeConfig::default(),
            operator: OperatorConfig::default(),
            logging: LoggingConfig {
                level: "info".to_string(),
            },
            admin_port: None,
            admin_token: None,
            min_validators_for_fee_redemption: default_min_validators_for_fees(),
            max_fact_links: default_max_fact_links(),
            scarred_cheque_fee_cap_atoms: default_scarred_fee_cap(),
            vacuum_interval_secs: default_vacuum_interval(),
        }
    }
}

impl LambdaConfig {
    /// Load config from TOML file
    pub fn from_file(path: &str) -> Result<Self, LambdaError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| LambdaError::ConfigError(format!("Failed to read config: {}", e)))?;

        toml::from_str(&content)
            .map_err(|e| LambdaError::ConfigError(format!("Failed to parse config: {}", e)))
    }

    /// Save config to TOML file
    pub fn to_file(&self, path: &str) -> Result<(), LambdaError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| LambdaError::ConfigError(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)
            .map_err(|e| LambdaError::ConfigError(format!("Failed to write config: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod retired_key_tests {
    use super::*;

    /// KI#174 — `seed_hints_path` was removed with the retired `seed-hints.json`
    /// loader. Operator `lambda.toml` files still carry the key and are never
    /// edited for them, so a config with it must keep loading (the key is ignored).
    #[test]
    fn a_config_with_the_retired_seed_hints_path_still_loads() {
        let text = toml::to_string_pretty(&LambdaConfig::default()).unwrap();
        assert!(text.contains("[storage]"));
        let with_key = text.replacen(
            "[storage]\n",
            "[storage]\nseed_hints_path = \"/var/lib/axiom/config/seed-hints.json\"\n",
            1,
        );
        assert!(with_key.contains("seed_hints_path"));
        let parsed: LambdaConfig = toml::from_str(&with_key).expect("retired key must be ignored");
        assert_eq!(parsed.storage.max_hints, LambdaConfig::default().storage.max_hints);
    }
}
