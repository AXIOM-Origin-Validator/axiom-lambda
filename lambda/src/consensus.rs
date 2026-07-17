//! Consensus Engine
//!
//! The heart of Lambda - coordinates k=3 witness consensus.
//!
//! # ARCHITECTURAL RULE: Lambda NEVER verifies cryptographic signatures.
//! Core is the sole cryptographic gatekeeper. Lambda's job:
//!   - S-ABR refill (balance, seq from stored records)
//!   - Build FACT links at witness time (sign with our validator key)
//!   - Manage wallet state (store, lookup, update) — but NOT FACT chains
//!   - Route messages and coordinate consensus
//!
//! # FACT CHAIN OWNERSHIP (YPX-001 §1.6):
//! The FACT chain (money provenance) is CARRIED BY THE CLIENT, not stored
//! by validators. Client passes their chain in WitnessRequest.sender_fact_chain.
//! Validators: verify (Core CL3), sign commitment, build new link at k=3,
//! return updated chain in WitnessResponse.sender_fact_chain.
//! StoredWalletState.fact_chain is DEPRECATED.
//!
//! Lambda does NOT:
//!   - Verify client signatures (Core CL2)
//!   - Verify witness signatures (Core validate_witnesses)
//!   - Verify VBC chains (Core CL2/CL5)
//!   - Verify FACT chains (Core CL5 Step 4b)
//!   - Compute state_ids, hashes, or commitments (Core compute::*)
//!
//! If you need to add verification → put it in Core, not here.
//! See axiom-core/core-logic/src/modes.rs for the full pipeline guide.
//!
//! # Flow (LAMBDA runs Core CL2 — the Gateway runs only CL2_PREFILTER)
//!
//! ```text
//! Gateway receives transaction
//!    │
//! Gateway → Core (CL2_PREFILTER): state-INDEPENDENT early reject
//!    │       (current_state = None — the gateway has no stored state
//!    │        and must never fabricate one; CLAUDE.md §8)
//!    │
//! Gateway → Lambda (pre-filtered transaction)
//!    │
//! 1. Lambda → Core (CL2): THE authoritative gate — S-ABR overlap
//!    decision, CLARA + RECALL attestation verification, state
//!    anchoring (run_cl2 in core_client.rs). Lambda refills from its
//!    own TransactionRecord when Core says overlapped.
//!    │
//! 2. Sign as witness
//!    │
//! 3. If k=3 reached: Core (CL3) produce witness proof — re-verifies
//!    the refill (SABRHashMismatch)
//!    │
//! 4. Return receipt to Gateway
//! ```
//!
//! HISTORY (2026-07-05): the two halves of CL2 used to point at each
//! other — this doc said "Gateway does CL2, NOT Lambda's job" while the
//! Gateway's CL2_PREFILTER doc said "Lambda's own CL2 pass owns the
//! authoritative checks" — and that Lambda CL2 pass was never built.
//! `execute_cl2` (with the recall/CLARA attestation gates) was invoked
//! by NOBODY in production; a drifted overlap-only `validate_sabr`
//! stood in for it. The rewire deleted `validate_sabr` /
//! `is_overlapped_validator` and made Core's CL2 the single authority.
//!
//! # Replay Protection (v2.11.12)
//!
//! Lambda passes the STORED wallet state_id to Core (not the TX's consumed_state_id).
//! After first witness, stored state_id = produced_state_id. Replay TX has
//! consumed_state_id = old_state_id. Core's verify_state_id_valid() catches
//! the mismatch and rejects. This prevents: signature accumulation, DMAP proof
//! compute waste, and V3 scar inconsistency from replays.
//!
//! # Security Model
//!
//! The Gateway pre-filters (CL2_PREFILTER, state-independent).
//! Lambda runs the authoritative Core CL2 against its real stored state,
//! then refills S-ABR values from its own records when Core says
//! overlapped. Core re-verifies the refill at CL3.
//!
//! # S-ABR (Sequential Asymmetric Blind Refill)
//!
//! Prevents double-spend by requiring:
//! - Overlapped validators from prev_receipts
//! - Balance verification against stored state
//!
//! ## Correct Architecture (per Yellow Paper)
//!
//! ```text
//! Client → Gateway: Full payload with claimed_balance (Core-verified), Hash_A
//!                   │
//! Gateway → Core (CL2_PREFILTER): state-independent structure checks
//!                   │
//! Lambda → Core (CL2): the authoritative S-ABR gate
//!                   │
//!                   ├── OVERLAPPED VALIDATOR PATH:
//!                   │   Core STRIPS balance/seq from payload
//!                   │   Core → Lambda: stripped payload
//!                   │   Lambda REFILLS from storage
//!                   │   Lambda → Core: refilled payload
//!                   │   Core computes Hash_B from refilled
//!                   │   Core compares: Hash_A == Hash_B?
//!                   │
//!                   └── NEW VALIDATOR PATH:
//!                       Verify ≥2 overlapped signatures
//!                       Trust declared values (overlapped verified them)
//! ```
//!
//! CORE is the ONLY judge. Lambda just refills.
//! CORE strips, CORE compares, CORE decides.

use crate::core_client::CoreClient;
use crate::error::LambdaError;
use crate::storage::Storage;
use crate::types::*;
use axiom_core_logic::types::{VBCProofBundle, VBC};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// VBC file format v0.9 (JSON from install_genesis.sh, hex-encoded keys)
/// Same format as ANTIE's VBCFile — both load the same vbc.json.
#[derive(Debug, Deserialize)]
struct VBCFile {
    #[serde(default)]
    version: Option<u8>,
    #[serde(default)]
    subject_pubkey_sphincs_hex: String,
    #[serde(default)]
    subject_pubkey_dilithium_hex: String,
    #[serde(default)]
    subject_pubkey_ed25519_hex: String,
    #[serde(default)]
    pgp_fingerprint_hex: Option<String>,
    #[serde(default)]
    issuer_set: Vec<String>,
    #[serde(default)]
    signatures: Vec<String>,
    #[serde(default)]
    issued_at: u64,
    #[serde(default = "default_vbc_expires")]
    expires_at: u64,
    #[serde(default)]
    chain_depth: Option<u8>,
    #[serde(default)]
    founding_vbc_hash: Option<String>,
    #[serde(default)]
    node_name: Option<String>,
}

fn default_vbc_expires() -> u64 { u64::MAX }

/// Minimum witnesses required for consensus (floor — used when required_k is unset)
pub const MIN_WITNESSES: usize = 3;

/// YPX-001 §1.5.1 hardening (2026-07-12): stored scar passcodes expire —
/// consent should be re-confirmed rather than honored from a weeks-old
/// notification (7 days is generous for an offline receiver).
const SCAR_PASSCODE_TTL_SECS: i64 = 7 * 24 * 60 * 60;
/// Wrong-passcode attempts before the entry dies and the gate re-issues a
/// fresh code (re-notifying the receiver). Caps brute-force at 5/900_000
/// per notification cycle, with each cycle visible to the receiver.
const MAX_SCAR_PASSCODE_ATTEMPTS: u32 = 5;

/// Bound for the per-engine request_id → WitnessResponse idempotency cache.
/// A WitnessResponse with a typical cheque + receipt + fact link runs
/// 20-50 KB; 1024 entries ≈ 50 MB worst case. Eviction is FIFO at the
/// front of the deque — the cache only needs to cover the few-second
/// window during which the same request_id can plausibly be re-delivered
/// by the SDK fan-out + §27.5 / S-ABR relay path. Cold restart drops
/// the cache (acceptable — see field doc on ConsensusEngine).
pub const WITNESS_IDEMPOTENCY_CACHE_CAP: usize = 1024;

/// Get effective k from a transaction's required_k field (Core-filled from receiver address).
/// Extract required k from the receiver's wallet_id (YPX-007 tier).
/// This is the SERVER-AUTHORITATIVE source — never trust tx.required_k
/// (client-supplied, can be 0 or forged). Lambda must independently
/// derive k from receiver_wallet_id, same as Core does in validate_transaction.
/// Falls back to MIN_WITNESSES for protocol TXs or unparseable wallet_ids.
fn effective_k(tx: &axiom_core_logic::types::Transaction) -> usize {
    use axiom_core_logic::wallet_id::extract_security_level;
    match extract_security_level(&tx.receiver_wallet_id) {
        Ok((k, _)) => (k as usize).max(MIN_WITNESSES),
        Err(_) => MIN_WITNESSES,
    }
}

/// Result of S-ABR validation
/// 
/// S-ABR doesn't reject directly based on balance - it returns values
/// for Core to use in hash computation. Core compares Hash_A vs Hash_B.
#[derive(Debug, Clone)]
pub enum SABRResult {
    /// Overlapped validator: returns refilled balance/seq from storage
    Refilled {
        balance: u64,
        wallet_seq: u64,
        group_members: Option<Vec<axiom_core_logic::GroupMember>>,
    },
    /// New validator: trusts overlapped validators, uses declared values
    Trusted {
        balance: u64,
        wallet_seq: u64,
        group_members: Option<Vec<axiom_core_logic::GroupMember>>,
    },
}

impl SABRResult {
    /// Get the balance to use for Core's hash computation
    pub fn balance(&self) -> u64 {
        match self {
            SABRResult::Refilled { balance, .. } => *balance,
            SABRResult::Trusted { balance, .. } => *balance,
        }
    }
    
    /// Get the wallet_seq to use for Core's hash computation
    pub fn wallet_seq(&self) -> u64 {
        match self {
            SABRResult::Refilled { wallet_seq, .. } => *wallet_seq,
            SABRResult::Trusted { wallet_seq, .. } => *wallet_seq,
        }
    }
    
    /// Get the group_members from S-ABR (post-deduction from previous TX)
    pub fn group_members(&self) -> Option<&Vec<axiom_core_logic::GroupMember>> {
        match self {
            SABRResult::Refilled { group_members, .. } => group_members.as_ref(),
            SABRResult::Trusted { group_members, .. } => group_members.as_ref(),
        }
    }
}

/// Consensus Engine
pub struct ConsensusEngine {
    /// Core client for CL3 (witness production)
    /// Wrapped in Mutex for interior mutability (production mode needs &mut)
    // RwLock (not Mutex): the DMAP witness production path only needs &self
    // so it can run concurrently under read() while the Lambda mutex machinery
    // is still enforced for the rare ZKP-prover and config-mutation paths via
    // write(). Before this change, all witness production serialized on a
    // single Mutex — 6 soak wallets × ~3 validators each produced 17-27 second
    // queueing delays. Discovered in the 2026-04-13 soak.
    core: RwLock<CoreClient>,
    
    /// Storage for state
    storage: Arc<Storage>,
    
    /// Our validator signing key (Ed25519 — for transaction witness signatures)
    signing_key: SigningKey,
    
    /// Our validator public key (Ed25519)
    public_key: VerifyingKey,
    
    /// Our SPHINCS+ secret key (for VBC signing — identity-grade, ceremonial)
    _sphincs_sk: Vec<u8>,

    /// Our SPHINCS+ public key (from VBC — matches validator_id)
    _sphincs_pk: Vec<u8>,
    
    /// Our Dilithium secret key (for FACT signing — operational quantum-resistant)
    dilithium_sk: Vec<u8>,
    
    /// Our Dilithium public key (from VBC)
    dilithium_pk: Vec<u8>,
    
    /// Our validator unique ID (derived from VBC or public key hash)
    validator_id: [u8; 32],
    
    /// Fee + operator config (for VSP responses to clients)
    fee_config: crate::config::FeeConfig,
    operator_config: crate::config::OperatorConfig,

    /// Oracle conversion rate config (operator-configurable, replaces Core's hardcoded rates)
    oracle_config: crate::config::OracleConfig,

    /// Carrier type (how clients reach us)
    /// e.g., "email" for ANTIE, "swift" for UNCLE, "https" for direct
    /// NOTE: protocol-level scalar baked into WitnessSig. Set via
    /// `set_carrier_info`. For multi-carrier VSP discovery use the
    /// `carriers` Vec below — populated by ANTIE via the
    /// `SetCarriers` IPC at gateway startup.
    carrier_type: String,

    /// Carrier address (our endpoint)
    /// e.g., "validator-alpha@axiom.network"
    carrier_address: String,

    /// Multi-carrier discovery list (YP §27.5.2 — Phase 1, 2026-05-14).
    /// ANTIE pushes this at startup via `SetCarriers` IPC after parsing
    /// `[carriers.*]` from `axiom-antie.toml`. Each entry is a canonical
    /// URI: `tcp:H:P`, `ws:H:P`, `email:<address>`. Default is empty
    /// (operator must configure); `validator_status` emits empty Vec
    /// in that case and Lambda logs a loud warning at set-time.
    ///
    /// `RwLock` because the engine is shared via `Arc<ConsensusEngine>`
    /// post-init — the IPC dispatch (`process_request`) only borrows
    /// `&ConsensusEngine`, so write paths need interior mutability.
    /// Reads (`validator_status`) are vastly more common than writes
    /// (one push at gateway startup) — `RwLock` over `Mutex` matches
    /// that ratio. Mirrors the existing `rate_limits: parking_lot::Mutex`
    /// pattern in this struct.
    carriers: parking_lot::RwLock<Vec<String>>,
    
    /// VBC for this validator — loaded from vbc.json at startup.
    /// Real SPHINCS+ chain with 3 issuers. Lambda refuses to start without it.
    vbc: VBCProofBundle,
    
    // ZKP is always real — no dev mode.
    
    /// Runtime statistics
    pub stats: ValidatorStats,
    
    /// Rate limiter: per-wallet request timestamps (sliding window)
    /// Key = first 16 bytes of client_pk (enough to identify, saves memory)
    /// Value = Vec of recent request timestamps
    /// Uses parking_lot::Mutex (not tokio) since check_rate_limit is synchronous
    rate_limits: parking_lot::Mutex<std::collections::HashMap<[u8; 16], Vec<std::time::Instant>>>,

    /// Max requests per wallet per minute (0 = no limit)
    rate_limit_per_minute: u32,

    /// Operator soft limit on FACT chain total links. 0 = use Core's hard limit.
    max_fact_links: usize,

    /// Proof mode advertised in VSP: "dmap" (default) or "zkp". This is a
    /// SPEED HINT for the SDK picker — it does NOT gate which TXs the
    /// validator will serve. Per [[feedback_no_proof_mode_shortcuts]],
    /// every validator MUST process whatever proof_type the TX requests
    /// (S-ABR continuity requires it). The advertised mode just tells
    /// clients which validators are FAST at zkVM, so they prefer those
    /// for ZKP-tier sends.
    proof_mode: String,

    /// YPX-007: ZKP qualification state — resets on startup, TTL 24h.
    /// Core-enforced: Lambda triggers benchmark, Core verifies STARK + measures time.
    zkp_qualification: parking_lot::Mutex<axiom_core_logic::types::QualificationState>,

    /// Idempotency cache for witness requests, keyed by `request.request_id`.
    /// SDK fan-out (k=3) + §27.5 / S-ABR relay can deliver the same request_id
    /// to the same validator twice — once from the SDK direct, once forwarded
    /// by an overlapped peer. Without dedup each arrival runs a fresh CL2/CL3
    /// and emits a distinct cheque (same protocol fields, different
    /// `created_at` → different Dilithium sig), leaving the receiver with
    /// orphan duplicate cheques after redeem. Mac handoff 2026-06-05.
    ///
    /// Cache is bounded — FIFO eviction at WITNESS_IDEMPOTENCY_CACHE_CAP.
    /// Cold restart drops the cache; a duplicate that lands across a restart
    /// will produce a fresh cheque. Acceptable trade-off — restart is rare,
    /// the SDK guard at WalletState.redeemed_txids catches the post-redeem
    /// residue regardless.
    witness_idempotency_cache: parking_lot::Mutex<
        std::collections::VecDeque<(String, WitnessResponse)>,
    >,

    /// Idempotency cache for REDEEM requests, keyed by `request.request_id` —
    /// the redeem-side mirror of `witness_idempotency_cache` (Mac handoff
    /// 2026-07-06). A duplicate redeem (client-side carrier duplication — the
    /// remote tester's Kiddo double-submits every outbound email) re-runs CL5,
    /// hits the Nabla consume-once, and returns `E_CHEQUE_ALREADY_REDEEMED`;
    /// the wallet then picks the reject, quarantines the cheque, and the sender's
    /// funds are consumed with the receipt orphaned. Replaying the first
    /// RedeemResponse verbatim for the same request_id closes that. Best-effort
    /// (FIFO-bounded, dropped on cold restart) — same trade-off as the witness
    /// cache; the SDK "prefer success over a duplicate's reject" guard covers the
    /// concurrent-arrival race the cache can miss.
    redeem_idempotency_cache: parking_lot::Mutex<
        std::collections::VecDeque<(String, RedeemResponse)>,
    >,

    /// §23.14: Pending audit demand from Core.
    /// Stored after Core generates AuditDemand in PublicOutputs.
    /// Client carries the demand to target validator, returns AuditConfirmation.
    /// Lambda passes confirmation through to Core via PublicInputs.
    pending_audit: parking_lot::Mutex<Option<axiom_core_logic::types::AuditDemand>>,

    /// §23.14: Transaction count since audit demand was issued.
    /// Lambda-level tracking for admin display (AVM enforces the real countdown).
    audit_txs_since_demand: std::sync::atomic::AtomicU64,

    /// §23.14.6: Whether a peer-audit request has been sent (prevents resending).
    /// Reset when audit clears or times out.
    peer_audit_sent: std::sync::atomic::AtomicBool,

    /// YPX-009 §4: Pending Pulse audit request from Core.
    /// When Core emits a PulseAuditRequest, Lambda stores it here.
    /// On next TX, Lambda looks up state_ids from DB, builds raw TxDigests,
    /// and passes PulseAuditResponse to Core for Argon2id→BLAKE3 chain replay.
    pending_pulse_audit: parking_lot::Mutex<Option<axiom_core_logic::types::PulseAuditRequest>>,

    /// Expected Core ID (BLAKE3 hash of axiom-core.elf).
    /// Stored at construction time for DMAP attestation verification.
    /// Used to verify cheque execution proofs came from the canonical Core binary.
    expected_core_id: [u8; 32],

    /// Management DB for DWP/JFP/Console — initialized after construction via init_management()
    management_db: Option<Arc<crate::management_db::ManagementDb>>,
    /// DWP engine (Decoy Witness Protection)
    dwp_engine: Option<crate::dwp_engine::DwpEngine>,
    /// Console engine (YPX-013 — digit migration governance)
    console_engine: Option<crate::console_engine::ConsoleEngine>,

    /// GAP-O3: Oracle binding table — tracks (platform_url, user_id) → axiom_address bindings.
    /// Enforces 24-hour claim interval and prevents binding hijack.
    oracle_bindings: parking_lot::Mutex<axiom_core_logic::oracle::BindingTable>,
    /// GAP-O3: Oracle daily pool state — per-platform daily emission caps.
    oracle_pool: parking_lot::Mutex<axiom_core_logic::oracle::DailyPoolState>,
    /// GAP-O3: Oracle reserve counter — total AXC distributed from 88M reserve.
    oracle_reserve: parking_lot::Mutex<axiom_core_logic::oracle::ReserveCounter>,
}

/// Runtime statistics for a validator
pub struct ValidatorStats {
    /// Total witness requests processed (success + fail)
    pub witness_count: std::sync::atomic::AtomicU64,
    /// Incoming witness requests asking for a DMAP-mode proof. Tagged by
    /// `request.transaction.proof_type == PROOF_TYPE_DMAP` (1), which the
    /// SDK sets from the receiver wallet address's encoded proof type.
    /// Tracked regardless of whether this validator can serve the mode —
    /// counts arrivals, not successes.
    pub witness_dmap_count: std::sync::atomic::AtomicU64,
    /// Incoming witness requests asking for a zkVM-mode proof
    /// (`PROOF_TYPE_ZKP == 0`). Same semantic as `witness_dmap_count` —
    /// counts the arrival, not the validator's ability to fulfil it.
    pub witness_zkvm_count: std::sync::atomic::AtomicU64,
    /// Successful witness responses
    pub witness_success: std::sync::atomic::AtomicU64,
    /// Total redeem requests processed
    pub redeem_count: std::sync::atomic::AtomicU64,
    /// Successful redeem responses
    pub redeem_success: std::sync::atomic::AtomicU64,
    /// Total atoms witnessed (sender side)
    pub atoms_witnessed: std::sync::atomic::AtomicU64,
    /// Total atoms redeemed (receiver side)
    pub atoms_redeemed: std::sync::atomic::AtomicU64,
    /// Total processing time in microseconds (witness)
    pub witness_time_us: std::sync::atomic::AtomicU64,
    /// Total processing time in microseconds (redeem)
    pub redeem_time_us: std::sync::atomic::AtomicU64,
    /// Genesis wallets initialized
    pub genesis_inits: std::sync::atomic::AtomicU64,
    /// Known validator peers (via hint exchange)
    pub hint_count: std::sync::atomic::AtomicU64,
    /// Unix timestamp when VBC was last verified (at startup)
    pub vbc_verified_at: std::sync::atomic::AtomicU64,
    /// Witness failures (total - success)
    pub witness_errors: std::sync::atomic::AtomicU64,
    /// Redeem failures (total - success)
    pub redeem_errors: std::sync::atomic::AtomicU64,
    /// Double-spend attempts detected (consumed_state_id already ACK'd)
    pub double_spend_count: std::sync::atomic::AtomicU64,
    /// Last error message
    pub last_error: parking_lot::Mutex<String>,
    /// Unix timestamp of last successful TX
    pub last_tx_at: std::sync::atomic::AtomicU64,
    /// Unix timestamp when stats were created (process start)
    pub started_at: u64,
    /// Path to write stats file
    pub stats_path: parking_lot::Mutex<Option<std::path::PathBuf>>,
    /// YPX-007: Current proof mode ("dmap" or "zkp")
    pub proof_mode_str: parking_lot::Mutex<String>,
    /// YPX-007: Whether this validator is ZKP-qualified
    pub zkp_qualified: std::sync::atomic::AtomicBool,
    /// Cumulative uptime seconds across all restarts (persisted in stats.json)
    pub cumulative_uptime_secs: std::sync::atomic::AtomicU64,
    /// Cumulative witness count across all restarts
    pub cumulative_witness_count: std::sync::atomic::AtomicU64,
    /// Cumulative redeem count across all restarts
    pub cumulative_redeem_count: std::sync::atomic::AtomicU64,
    /// Number of process restarts (incremented each startup)
    pub restart_count: std::sync::atomic::AtomicU64,
}

impl ValidatorStats {
    fn new() -> Self {
        use std::sync::atomic::AtomicU64;
        let started_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            witness_count: AtomicU64::new(0),
            witness_dmap_count: AtomicU64::new(0),
            witness_zkvm_count: AtomicU64::new(0),
            witness_success: AtomicU64::new(0),
            redeem_count: AtomicU64::new(0),
            redeem_success: AtomicU64::new(0),
            atoms_witnessed: AtomicU64::new(0),
            atoms_redeemed: AtomicU64::new(0),
            witness_time_us: AtomicU64::new(0),
            redeem_time_us: AtomicU64::new(0),
            genesis_inits: AtomicU64::new(0),
            hint_count: AtomicU64::new(0),
            vbc_verified_at: AtomicU64::new(0),
            witness_errors: AtomicU64::new(0),
            redeem_errors: AtomicU64::new(0),
            double_spend_count: AtomicU64::new(0),
            last_error: parking_lot::Mutex::new(String::new()),
            last_tx_at: AtomicU64::new(0),
            started_at,
            stats_path: parking_lot::Mutex::new(None),
            proof_mode_str: parking_lot::Mutex::new("dmap".to_string()),
            cumulative_uptime_secs: AtomicU64::new(0),
            cumulative_witness_count: AtomicU64::new(0),
            cumulative_redeem_count: AtomicU64::new(0),
            restart_count: AtomicU64::new(0),
            zkp_qualified: std::sync::atomic::AtomicBool::new(false),
        }
    }
    
    /// Write stats to JSON file (called periodically or after each TX)
    /// Load cumulative stats from existing stats.json (called once at startup).
    /// Adds previous session's uptime/witness/redeem counts to cumulative totals.
    pub fn load_cumulative(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        let path = self.stats_path.lock();
        let Some(path) = path.as_ref() else { return; };
        let Ok(data) = std::fs::read_to_string(path) else { return; };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) else { return; };

        // Load previous cumulative values (or previous session values if first migration)
        let prev_cum_uptime = v.get("cumulative_uptime_secs").and_then(|v| v.as_u64()).unwrap_or(0);
        let prev_cum_witness = v.get("cumulative_witness_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let prev_cum_redeem = v.get("cumulative_redeem_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let prev_restarts = v.get("restart_count").and_then(|v| v.as_u64()).unwrap_or(0);

        // Add previous session's uptime to cumulative
        let prev_updated = v.get("updated").and_then(|v| v.as_u64()).unwrap_or(0);
        let prev_started = v.get("started_at").and_then(|v| v.as_u64()).unwrap_or(prev_updated);
        let prev_session_uptime = prev_updated.saturating_sub(prev_started);

        // Add previous session's witness/redeem counts
        let prev_witness = v.get("witness").and_then(|w| w.get("total")).and_then(|v| v.as_u64()).unwrap_or(0);
        let prev_redeem = v.get("redeem").and_then(|r| r.get("total")).and_then(|v| v.as_u64()).unwrap_or(0);

        self.cumulative_uptime_secs.store(prev_cum_uptime + prev_session_uptime, Relaxed);
        self.cumulative_witness_count.store(prev_cum_witness + prev_witness, Relaxed);
        self.cumulative_redeem_count.store(prev_cum_redeem + prev_redeem, Relaxed);
        self.restart_count.store(prev_restarts + 1, Relaxed);

        tracing::info!(
            "Loaded cumulative stats: uptime={}h, witnesses={}, redeems={}, restarts={}",
            (prev_cum_uptime + prev_session_uptime) / 3600,
            prev_cum_witness + prev_witness,
            prev_cum_redeem + prev_redeem,
            prev_restarts + 1,
        );
    }

    pub fn write_stats_file(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        let path = self.stats_path.lock();
        let Some(path) = path.as_ref() else {
            return;
        };
        
        let wc = self.witness_count.load(Relaxed);
        let ws = self.witness_success.load(Relaxed);
        let rc = self.redeem_count.load(Relaxed);
        let rs = self.redeem_success.load(Relaxed);
        let aw = self.atoms_witnessed.load(Relaxed);
        let ar = self.atoms_redeemed.load(Relaxed);
        let wt = self.witness_time_us.load(Relaxed);
        let rt = self.redeem_time_us.load(Relaxed);
        let gi = self.genesis_inits.load(Relaxed);
        let hc = self.hint_count.load(Relaxed);
        let vbc_at = self.vbc_verified_at.load(Relaxed);
        let we = self.witness_errors.load(Relaxed);
        let re = self.redeem_errors.load(Relaxed);
        let last_tx = self.last_tx_at.load(Relaxed);
        let last_err = self.last_error.lock().clone();
        
        let avg_witness_ms = if ws > 0 { wt as f64 / ws as f64 / 1000.0 } else { 0.0 };
        let avg_redeem_ms = if rs > 0 { rt as f64 / rs as f64 / 1000.0 } else { 0.0 };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Escape last_error for JSON
        let escaped_err = last_err.replace('\\', "\\\\").replace('"', "\\\"");
        
        let pm = self.proof_mode_str.lock().clone();
        let zq = self.zkp_qualified.load(std::sync::atomic::Ordering::Relaxed);

        // Cumulative stats (persist across restarts)
        let session_uptime = now.saturating_sub(self.started_at);
        let cum_uptime = self.cumulative_uptime_secs.load(Relaxed) + session_uptime;
        let cum_witness = self.cumulative_witness_count.load(Relaxed) + wc;
        let cum_redeem = self.cumulative_redeem_count.load(Relaxed) + rc;
        let restarts = self.restart_count.load(Relaxed);

        let json = format!(
            r#"{{"witness":{{"total":{},"success":{},"errors":{},"atoms":{},"avg_ms":{:.1}}},"redeem":{{"total":{},"success":{},"errors":{},"atoms":{},"avg_ms":{:.1}}},"genesis_inits":{},"hints":{},"vbc_verified_at":{},"last_tx_at":{},"last_error":"{}","proof_mode":"{}","zkp_qualified":{},"started_at":{},"updated":{},"cumulative_uptime_secs":{},"cumulative_witness_count":{},"cumulative_redeem_count":{},"restart_count":{}}}"#,
            wc, ws, we, aw, avg_witness_ms,
            rc, rs, re, ar, avg_redeem_ms,
            gi, hc, vbc_at, last_tx, escaped_err, pm, zq,
            self.started_at, now,
            cum_uptime, cum_witness, cum_redeem, restarts,
        );
        // Atomic write: write to temp then rename
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &json).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
    
    /// Record an error and increment error counter
    pub fn record_error(&self, is_witness: bool, msg: &str) {
        use std::sync::atomic::Ordering::Relaxed;
        if is_witness {
            self.witness_errors.fetch_add(1, Relaxed);
        } else {
            self.redeem_errors.fetch_add(1, Relaxed);
        }
        // Keep last 200 chars
        let truncated = if msg.len() > 200 { &msg[..200] } else { msg };
        *self.last_error.lock() = truncated.to_string();
    }
    
    /// Record successful TX timestamp
    pub fn record_success(&self) {
        self.last_tx_at.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

impl ConsensusEngine {
    /// Load SPHINCS+ secret key.
    /// Tries: explicit config path, then {vbc_dir}/sphincs.key, {vbc_dir}/../config/sphincs.key
    /// Falls back to ephemeral key for dev/test if not found.
    fn load_sphincs_key(vbc_path: &std::path::Path, config_path: Option<&std::path::Path>) -> Vec<u8> {
        let vbc_dir = vbc_path.parent().unwrap_or(std::path::Path::new("."));
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        if let Some(p) = config_path {
            candidates.push(p.to_path_buf());
        }
        candidates.push(vbc_dir.join("sphincs.key"));
        candidates.push(vbc_dir.join("../config/sphincs.key"));
        candidates.push(vbc_dir.join("config/sphincs.key"));
        
        for path in &candidates {
            if let Ok(sk) = std::fs::read(path) {
                if sk.len() == 64 {
                    info!("Loaded SPHINCS+ key from {:?} ({} bytes)", path, sk.len());
                    return sk;
                }
                warn!("SPHINCS+ key at {:?} wrong size: {} bytes (expected 64)", path, sk.len());
            }
        }
        
        warn!("No SPHINCS+ key found — generating ephemeral key for dev/test. NOT FOR PRODUCTION.");
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        let (_, sk) = slh_dsa_sha2_128s::try_keygen()
            .expect("SPHINCS+ keygen failed");
        sk.into_bytes().to_vec()
    }
    
    /// Load Dilithium (ML-DSA-65) secret key.
    /// Tries: explicit config path, then {vbc_dir}/dilithium.key, etc.
    /// Used for FACT signing (operational quantum-resistant, fast).
    ///
    /// Returns (sk, Option<pk>). When loaded from file, pk is None (use VBC's PK).
    /// When ephemeral key is generated for dev/test, pk is Some (MUST use this PK,
    /// not VBC's, since the ephemeral SK won't match VBC's Dilithium PK).
    fn load_dilithium_key(vbc_path: &std::path::Path, config_path: Option<&std::path::Path>) -> (Vec<u8>, Option<Vec<u8>>) {
        let vbc_dir = vbc_path.parent().unwrap_or(std::path::Path::new("."));
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        if let Some(p) = config_path {
            candidates.push(p.to_path_buf());
        }
        candidates.push(vbc_dir.join("dilithium.key"));
        candidates.push(vbc_dir.join("../config/dilithium.key"));
        candidates.push(vbc_dir.join("config/dilithium.key"));
        // g1 ceremony writes the Dilithium SK to keys/dilithium.key (not
        // config/). Without this candidate, load_dilithium_key falls through
        // to ephemeral keygen, the ephemeral PK diverges from the VBC's
        // baked-in subject_pubkey_dilithium, and every FACT signature CL5
        // produces fails verification on the receiver side
        // (verify_fact_link uses validator_pk pulled from VBC, not from
        // the ephemeral key — soak v55 surfaced this exact path).
        candidates.push(vbc_dir.join("../keys/dilithium.key"));
        candidates.push(vbc_dir.join("keys/dilithium.key"));

        for path in &candidates {
            if let Ok(sk) = std::fs::read(path) {
                if sk.len() == 4032 {
                    info!("Loaded Dilithium key from {:?} ({} bytes)", path, sk.len());
                    return (sk, None);
                }
                warn!("Dilithium key at {:?} wrong size: {} bytes (expected 4032)", path, sk.len());
            }
        }

        warn!("No Dilithium key found — generating ephemeral key for dev/test. NOT FOR PRODUCTION. \
               WARNING: ephemeral PK will diverge from VBC subject_pubkey_dilithium and FACT \
               signatures will fail verification on the receiver side.");
        use fips204::ml_dsa_65;
        use fips204::traits::SerDes;
        let (pk, sk) = ml_dsa_65::try_keygen()
            .expect("Dilithium keygen failed");
        (sk.into_bytes().to_vec(), Some(pk.into_bytes().to_vec()))
    }
    
    /// Create new consensus engine.
    ///
    /// Requires a valid VBC file path. Lambda will not start without a real VBC.
    /// Uses AVM interpreter directly (axiom-core.elf) — no core-bin subprocess.
    pub fn new(
        storage: Arc<Storage>,
        signing_key: SigningKey,
        vbc_path: &std::path::Path,
        avm_config: axiom_dmap_vm::AvmConfig,
        sphincs_key_path: Option<&std::path::Path>,
        dilithium_key_path: Option<&std::path::Path>,
    ) -> Result<Self, LambdaError> {
        info!("AVM interpreter: core_id={}", hex::encode(avm_config.core_id));

        let public_key = VerifyingKey::from(&signing_key);

        // Capture expected CoreID before moving avm_config into CoreClient.
        // This is the BLAKE3 hash of the canonical axiom-core.elf binary,
        // used to verify DMAP attestation proofs came from real Core execution.
        let expected_core_id = avm_config.core_id;

        // Load real VBC — fail-stop if missing or invalid
        let vbc = Self::load_vbc_from_file(vbc_path)?;

        // Derive validator_id from VBC's SPHINCS+ public key (not from signing key)
        let validator_id = vbc.target_vbc.validator_id;
        let sphincs_pk = vbc.target_vbc.subject_pubkey_sphincs.clone();
        let carrier_address = format!("validator-{}", hex::encode(&validator_id[..4]));

        let sphincs_sk = Self::load_sphincs_key(vbc_path, sphincs_key_path);
        let (dilithium_sk, ephemeral_dilithium_pk) = Self::load_dilithium_key(vbc_path, dilithium_key_path);
        // Use ephemeral PK if key was generated (dev/test), otherwise VBC's PK
        let dilithium_pk = ephemeral_dilithium_pk
            .unwrap_or_else(|| vbc.target_vbc.subject_pubkey_dilithium.clone());

        let engine = Self {
            core: RwLock::new(CoreClient::new(avm_config)?),
            storage,
            signing_key,
            public_key,
            _sphincs_sk: sphincs_sk,
            _sphincs_pk: sphincs_pk,
            dilithium_sk,
            dilithium_pk,
            validator_id,
            fee_config: crate::config::FeeConfig::default(),
            operator_config: crate::config::OperatorConfig::default(),
            oracle_config: crate::config::OracleConfig::default(),
            carrier_type: "dev".to_string(),
            carrier_address,
            carriers: parking_lot::RwLock::new(Vec::new()),
            vbc,
            rate_limits: parking_lot::Mutex::new(std::collections::HashMap::new()),
            rate_limit_per_minute: 60,
            max_fact_links: 16, // dev default
            stats: ValidatorStats::new(),
            proof_mode: "dmap".to_string(),
            zkp_qualification: parking_lot::Mutex::new(axiom_core_logic::types::QualificationState::default()),
            witness_idempotency_cache: parking_lot::Mutex::new(std::collections::VecDeque::with_capacity(WITNESS_IDEMPOTENCY_CACHE_CAP)),
            redeem_idempotency_cache: parking_lot::Mutex::new(std::collections::VecDeque::with_capacity(WITNESS_IDEMPOTENCY_CACHE_CAP)),
            pending_audit: parking_lot::Mutex::new(None),
            audit_txs_since_demand: std::sync::atomic::AtomicU64::new(0),
            peer_audit_sent: std::sync::atomic::AtomicBool::new(false),
            pending_pulse_audit: parking_lot::Mutex::new(None),
            expected_core_id,
            management_db: None,
            dwp_engine: None,
            console_engine: None,
            oracle_bindings: parking_lot::Mutex::new(axiom_core_logic::oracle::BindingTable::new()),
            oracle_pool: parking_lot::Mutex::new(axiom_core_logic::oracle::DailyPoolState::new("1970-01-01", axiom_core_logic::oracle::TOTAL_RESERVE, 0)),
            oracle_reserve: parking_lot::Mutex::new(axiom_core_logic::oracle::ReserveCounter::new()),
        };
        // Record VBC verification timestamp (verified in load_vbc_from_file)
        engine.stats.vbc_verified_at.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(engine)
    }

    /// Create new consensus engine with explicit carrier info
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_carrier(
        storage: Arc<Storage>,
        signing_key: SigningKey,
        carrier_type: String,
        carrier_address: String,
        vbc_path: &std::path::Path,
        avm_config: axiom_dmap_vm::AvmConfig,
        sphincs_key_path: Option<&std::path::Path>,
        dilithium_key_path: Option<&std::path::Path>,
    ) -> Result<Self, LambdaError> {
        info!("AVM interpreter: core_id={}", hex::encode(avm_config.core_id));

        let public_key = VerifyingKey::from(&signing_key);
        let expected_core_id = avm_config.core_id;

        // Load real VBC — fail-stop if missing or invalid
        let vbc = Self::load_vbc_from_file(vbc_path)?;
        let validator_id = vbc.target_vbc.validator_id;
        let sphincs_pk = vbc.target_vbc.subject_pubkey_sphincs.clone();

        let sphincs_sk = Self::load_sphincs_key(vbc_path, sphincs_key_path);
        let (dilithium_sk, ephemeral_dilithium_pk) = Self::load_dilithium_key(vbc_path, dilithium_key_path);
        // Use ephemeral PK if key was generated (dev/test), otherwise VBC's PK
        let dilithium_pk = ephemeral_dilithium_pk
            .unwrap_or_else(|| vbc.target_vbc.subject_pubkey_dilithium.clone());

        let engine = Self {
            core: RwLock::new(CoreClient::new(avm_config)?),
            storage,
            signing_key,
            public_key,
            _sphincs_sk: sphincs_sk,
            _sphincs_pk: sphincs_pk,
            dilithium_sk,
            dilithium_pk,
            validator_id,
            fee_config: crate::config::FeeConfig::default(),
            operator_config: crate::config::OperatorConfig::default(),
            oracle_config: crate::config::OracleConfig::default(),
            carrier_type,
            carrier_address,
            carriers: parking_lot::RwLock::new(Vec::new()),
            vbc,
            rate_limits: parking_lot::Mutex::new(std::collections::HashMap::new()),
            rate_limit_per_minute: 60,
            max_fact_links: 16,
            stats: ValidatorStats::new(),
            proof_mode: "dmap".to_string(),
            zkp_qualification: parking_lot::Mutex::new(axiom_core_logic::types::QualificationState::default()),
            witness_idempotency_cache: parking_lot::Mutex::new(std::collections::VecDeque::with_capacity(WITNESS_IDEMPOTENCY_CACHE_CAP)),
            redeem_idempotency_cache: parking_lot::Mutex::new(std::collections::VecDeque::with_capacity(WITNESS_IDEMPOTENCY_CACHE_CAP)),
            pending_audit: parking_lot::Mutex::new(None),
            audit_txs_since_demand: std::sync::atomic::AtomicU64::new(0),
            peer_audit_sent: std::sync::atomic::AtomicBool::new(false),
            pending_pulse_audit: parking_lot::Mutex::new(None),
            expected_core_id,
            management_db: None,
            dwp_engine: None,
            console_engine: None,
            oracle_bindings: parking_lot::Mutex::new(axiom_core_logic::oracle::BindingTable::new()),
            oracle_pool: parking_lot::Mutex::new(axiom_core_logic::oracle::DailyPoolState::new("1970-01-01", axiom_core_logic::oracle::TOTAL_RESERVE, 0)),
            oracle_reserve: parking_lot::Mutex::new(axiom_core_logic::oracle::ReserveCounter::new()),
        };
        engine.stats.vbc_verified_at.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(engine)
    }

    // new_production() removed — new() is always production mode.
    // Kept as alias for backwards compatibility during transition.
    pub fn new_production(
        storage: Arc<Storage>,
        signing_key: SigningKey,
        vbc_path: &std::path::Path,
        avm_config: axiom_dmap_vm::AvmConfig,
        sphincs_key_path: Option<&std::path::Path>,
        dilithium_key_path: Option<&std::path::Path>,
    ) -> Result<Self, LambdaError> {
        Self::new(storage, signing_key, vbc_path, avm_config, sphincs_key_path, dilithium_key_path)
    }

    /// Configure proof tiering from ProofConfig.
    ///
    /// Sets the advertised proof mode (dmap or zkp). DMAP is always
    /// available via the AVM interpreter. We ALWAYS attempt to enable
    /// the ZKP prover too, regardless of advertised mode — per
    /// [[feedback_no_proof_mode_shortcuts]], a validator MUST be able
    /// to serve zkVM TXs even when not ZKP-qualified (S-ABR continuity).
    /// If the ZKP prover fails to start, surface the error: the
    /// validator continues running, but a later zkVM TX will fail loud
    /// instead of being silently rejected or downgraded.
    pub async fn configure_proof_tiering(&mut self, proof_config: &crate::config::ProofConfig) {
        self.proof_mode = proof_config.mode.clone();
        info!("Proof tiering: advertised mode={}", self.proof_mode);

        let mut core = self.core.write().await;
        if let Err(e) = core.enable_zkp() {
            error!("ZKP prover failed to enable ({}); zkVM TXs to this validator \
                    will fail at runtime. proof_mode={} is advertised but not \
                    fully backed — fix the prover environment.",
                   e, self.proof_mode);
        }
    }

    /// Run ignition TX sequence (YPX-009 §8.4).
    ///
    /// With `pulse-gate` feature: sends ignition TX through Core → ZKVM → Core,
    /// measuring round-trip time and determining hardware tier. Core stays blocked
    /// until this completes.
    ///
    /// Without `pulse-gate`: Core auto-calibrated at startup, this is a no-op.
    ///
    /// Must be called AFTER `configure_proof_tiering()` (needs ZKVM prover if in ZKP mode).
    pub async fn ignite(&self) -> Result<(), LambdaError> {
        // Set validator_pk on the persistent AVM (needed for Fiat-Shamir audit seed)
        {
            let core = self.core.write().await;
            core.avm().set_validator_pk(self.public_key.as_bytes().to_vec());
        }

        #[cfg(feature = "pulse-gate")]
        {
            info!("YPX-009: Ignition TX — Core blocked until ZKVM round-trip completes");
            let mut core = self.core.write().await;
            core.ignite()?;
        }

        #[cfg(not(feature = "pulse-gate"))]
        {
            // Auto-calibrated at AVM construction — nothing to do
            debug!("YPX-009: pulse-gate disabled, Core auto-calibrated at startup");
        }

        Ok(())
    }

    /// Synchronous version of configure_proof_tiering for use during startup.
    /// See `configure_proof_tiering` for the no-shortcut-mode rationale.
    pub fn configure_proof_tiering_sync(&mut self, proof_config: &crate::config::ProofConfig) {
        self.proof_mode = proof_config.mode.clone();
        info!("Proof tiering: advertised mode={}", self.proof_mode);

        let core = self.core.get_mut();
        if let Err(e) = core.enable_zkp() {
            error!("ZKP prover failed to enable ({}); zkVM TXs to this validator \
                    will fail at runtime. proof_mode={} is advertised but not \
                    fully backed — fix the prover environment.",
                   e, self.proof_mode);
        }
    }

    /// Run ignition TX sequence synchronously (YPX-009 §8.4).
    ///
    /// Same as `ignite()` but callable from non-async context (before engine
    /// is wrapped in Arc). Called from `LambdaServer::new()` during startup.
    pub fn ignite_sync(&mut self) -> Result<(), LambdaError> {
        // Set validator_pk on the persistent AVM
        {
            let core = self.core.get_mut();
            core.avm().set_validator_pk(self.public_key.as_bytes().to_vec());
        }

        #[cfg(feature = "pulse-gate")]
        {
            info!("YPX-009: Ignition TX — Core blocked until ZKVM round-trip completes");
            let core = self.core.get_mut();
            core.ignite()?;
        }

        #[cfg(not(feature = "pulse-gate"))]
        {
            debug!("YPX-009: pulse-gate disabled, Core auto-calibrated at startup");
        }

        Ok(())
    }

    /// Get current proof mode ("zkp" or "dmap")
    pub fn proof_mode(&self) -> &str {
        &self.proof_mode
    }

    /// Set carrier information
    /// Set fee and operator config from Lambda config file.
    /// Called after loading the TOML config.
    pub fn set_fee_and_operator_config(
        &mut self,
        fee_config: crate::config::FeeConfig,
        operator_config: crate::config::OperatorConfig,
    ) {
        self.fee_config = fee_config;
        self.operator_config = operator_config;
    }

    /// Set oracle config from TOML. Operators can adjust conversion rates without recompiling Core.
    /// Whether this validator accepts oracle claims.
    pub fn oracle_enabled(&self) -> bool {
        self.oracle_config.enabled
    }

    pub fn set_oracle_config(&mut self, oracle_config: crate::config::OracleConfig) {
        self.oracle_config = oracle_config;
    }

    pub fn set_carrier_info(&mut self, carrier_type: String, carrier_address: String) {
        self.carrier_type = carrier_type;
        self.carrier_address = carrier_address;
    }

    /// Multi-carrier discovery setter (YP §27.5.2 — Phase 1, 2026-05-14).
    ///
    /// Replaces the entire carrier list. Each entry is a canonical
    /// URI (`tcp:H:P`, `ws:H:P`, `email:<address>`). Empty list is
    /// permitted but logs a loud warning so operators notice the
    /// misconfig — VSP will then emit an empty `carriers` Vec to
    /// downstream peers/clients.
    ///
    /// Takes `&self` (not `&mut self`) because the engine is shared via
    /// `Arc<ConsensusEngine>` post-init and the IPC dispatch
    /// (`process_request`) borrows `&ConsensusEngine`. Interior
    /// mutability via `RwLock` makes this safe.
    pub fn set_carriers(&self, carriers: Vec<String>) {
        if carriers.is_empty() {
            tracing::warn!(
                "[VSP] set_carriers called with EMPTY list — VSP will advertise no \
                 carriers for this validator until [carriers.*] is configured in \
                 axiom-antie.toml. Peers and clients cannot route to us until then."
            );
        } else {
            tracing::info!(
                "[VSP] set_carriers: {} carrier URI(s) registered: {:?}",
                carriers.len(), carriers,
            );
        }
        *self.carriers.write() = carriers.clone();

        // Self-advertise into the local hint table so random emission can
        // surface our own multi-URI carriers to wallets. The wallet then
        // relays via WitnessRequest.validator_hints; receivers UPSERT
        // (storage::add_hint). Authoritative source = each operator's own
        // antie.toml [carriers] advertise list (CLAUDE.md "ANTIE never
        // synthesizes what Lambda verifies" — but ANTIE telling Lambda
        // its own carriers is precisely set_carriers' job).
        if !carriers.is_empty() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let self_hint = axiom_core_logic::types::ValidatorHint {
                validator_id: self.validator_id,
                name: self.vbc.target_vbc.node_name.clone(),
                carriers,
                proof_cap: Some(self.proof_mode.clone()),
                last_seen: Some(now),
                ed25519_pk: Some(ed25519_dalek::VerifyingKey::from(&self.signing_key).to_bytes()),
                encryption_public_key: self.operator_config.encryption_public_key.clone(),
                supported_encryption: self.operator_config.supported_encryption.clone(),
            };
            if let Err(e) = self.storage.add_hint(&self_hint) {
                tracing::warn!("[VSP] self-hint UPSERT failed (non-fatal): {:?}", e);
            }
        }
    }

    /// Read-only snapshot of the current carrier list. Used by VSP
    /// (`validator_status`) and tests.
    pub fn carriers_snapshot(&self) -> Vec<String> {
        self.carriers.read().clone()
    }

    /// Apply operator's `max_fact_links` from lambda.toml. Replaces the
    /// hardcoded 16 baked into `new()` / `new_with_carrier()` — operators
    /// can raise this on JIT validators (Core's hard ceiling is 64).
    /// Set to 0 to disable the depth gate entirely.
    ///
    /// Mirrors into `CoreClient` so it threads the limit into every
    /// `PublicInputs` Core sees. Core does the actual depth check; Lambda
    /// never reads `fact_chain.links` (per `feedback_layer_roles.md`).
    pub fn set_max_fact_links(&mut self, max_fact_links: usize) {
        self.max_fact_links = max_fact_links;
        // RwLock<CoreClient> — tokio's RwLock requires await. set_max_fact_links
        // is only called from sync code at config-load time, so block_on the
        // single write. Alternative would be Mutex / std::sync::RwLock but
        // CoreClient is shared async-wide.
        let max_fact_links_for_core = max_fact_links;
        let core = &self.core;
        // tokio runtime is always present when this is called.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                core.write().await.set_max_fact_links(max_fact_links_for_core);
            })
        });
    }

    /// Fetch our own NablaStakeProof for oracle TX witnessing (YPX-012 §1.2).
    /// Queries Nabla to confirm wallet registration + cross-checks state_id,
    /// then builds proof from local storage (balance, FACT chain scar count).
    /// Both VBC balance AND Nabla registration are required — VBC alone is
    /// insufficient because balance may have moved since VBC issuance.
    pub async fn fetch_own_nabla_stake_proof(&self) -> Option<axiom_core_logic::types::NablaStakeProof> {
        let wallet_pk: [u8; 32] = self.public_key.to_bytes();

        // 1. Query Nabla for our wallet state.
        //
        // TCP CBOR wire (CLAUDE.md §8, Rule 2). Pre-migration this issued a
        // raw `GET /query?wallet_pk=<hex>` over the Nabla HTTP port; Phase
        // 3a-B gated `/query` to `410 Gone`. We now send a length-prefixed
        // CBOR `WireMessage::QueryWalletStateRequest` over the Nabla TCP
        // port and decode the typed `QueryWalletStateResponse` — no JSON,
        // no hex round-trip (the typed struct carries native byte fields).
        //
        // TODO: make nabla_addr configurable via lambda-config.toml (multi-host deployment)
        // TCP port = HTTP port + 1074 (HTTP 6226 → TCP 7300, node alpha).
        let nabla_addr = "127.0.0.1:7300";

        // Build the request envelope and frame it: 4-byte big-endian
        // length prefix, then the CBOR payload (Nabla TCP framing).
        let request = axiom_core_logic::nabla_wire::WireMessage::QueryWalletStateRequest(
            axiom_core_logic::wire_client::QueryWalletStateRequest { wallet_pk },
        );
        let mut cbor_req = Vec::new();
        if let Err(e) = ciborium::ser::into_writer(&request, &mut cbor_req) {
            warn!("Oracle stake proof: CBOR encode QueryWalletStateRequest failed: {}", e);
            return None;
        }
        let mut framed = Vec::with_capacity(4 + cbor_req.len());
        framed.extend_from_slice(&(cbor_req.len() as u32).to_be_bytes());
        framed.extend_from_slice(&cbor_req);

        let resp_cbor: Vec<u8> = match tokio::net::TcpStream::connect(nabla_addr).await {
            Ok(mut stream) => {
                use tokio::io::{AsyncWriteExt, AsyncReadExt};
                if let Err(e) = stream.write_all(&framed).await {
                    warn!("Oracle stake proof: Nabla write failed: {}", e);
                    return None;
                }
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                // Read the 4-byte length prefix.
                let mut len_buf = [0u8; 4];
                match tokio::time::timeout_at(deadline, stream.read_exact(&mut len_buf)).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        warn!("Oracle stake proof: Nabla length-prefix read error: {}", e);
                        return None;
                    }
                    Err(_) => {
                        warn!("Oracle stake proof: Nabla length-prefix read timeout");
                        return None;
                    }
                }
                let resp_len = u32::from_be_bytes(len_buf) as usize;
                // Cap at 64KB to prevent a malicious Nabla from OOM-ing Lambda.
                const MAX_RESPONSE: usize = 65536;
                if resp_len > MAX_RESPONSE {
                    warn!("Oracle stake proof: Nabla response {}B exceeds {}B limit",
                        resp_len, MAX_RESPONSE);
                    return None;
                }
                let mut buf = vec![0u8; resp_len];
                match tokio::time::timeout_at(deadline, stream.read_exact(&mut buf)).await {
                    Ok(Ok(_)) => buf,
                    Ok(Err(e)) => {
                        warn!("Oracle stake proof: Nabla body read error: {}", e);
                        return None;
                    }
                    Err(_) => {
                        warn!("Oracle stake proof: Nabla body read timeout");
                        return None;
                    }
                }
            }
            Err(e) => {
                warn!("Oracle stake proof: cannot connect to Nabla at {}: {}", nabla_addr, e);
                return None;
            }
        };

        // 2. Decode the Nabla response.
        //
        // Nabla's server enum (`axiom_nabla::transport::WireMessage`) is
        // externally tagged: `{"QueryWalletStateResponse": {...}}`. We
        // decode the envelope as a `ciborium::Value`, confirm the variant
        // key, then deserialize the inner value into the shared typed
        // struct from `axiom_core_logic::wire_client` — no mirror struct.
        let envelope: ciborium::value::Value =
            match ciborium::de::from_reader(resp_cbor.as_slice()) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Oracle stake proof: invalid Nabla CBOR response: {}", e);
                    return None;
                }
            };
        let inner = match envelope.as_map().and_then(|m| m.first()) {
            Some((k, v)) if k.as_text() == Some("QueryWalletStateResponse") => v.clone(),
            Some((k, _)) => {
                warn!("Oracle stake proof: unexpected Nabla response variant: {:?}",
                    k.as_text().unwrap_or("<non-text>"));
                return None;
            }
            None => {
                warn!("Oracle stake proof: malformed Nabla response (not a tagged map)");
                return None;
            }
        };
        let nabla_resp: axiom_core_logic::wire_client::QueryWalletStateResponse =
            match inner.deserialized() {
                Ok(r) => r,
                Err(e) => {
                    warn!("Oracle stake proof: cannot decode QueryWalletStateResponse: {}", e);
                    return None;
                }
            };

        if nabla_resp.status != "REGISTERED" {
            warn!("Oracle stake proof: wallet not registered with Nabla");
            return None;
        }

        let nabla_tick = nabla_resp.synced_to_tick;
        let role_str = nabla_resp.role.as_str();

        // `current_state` and `node_id` arrive as native byte fields on
        // the typed response — no hex decoding. Validate the lengths.
        let nabla_state_id: [u8; 32] = match nabla_resp.current_state.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                warn!("Oracle stake proof: invalid Nabla state_id (expected 32 bytes, got {})",
                    nabla_resp.current_state.len());
                return None;
            }
        };
        let nabla_node_pk: [u8; 32] = nabla_resp.node_id;

        // 3. Get our wallet state from storage — balance + scar count
        let wallet_state = match self.storage.get_wallet_state(&wallet_pk, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP) {
            Ok(Some(ws)) => ws,
            _ => {
                warn!("Oracle stake proof: own wallet not found in storage");
                return None;
            }
        };

        // SEC-09 FAIL-CLOSED GATE (load-bearing). This builds the validator's
        // OWN oracle stake proof, which Core's oracle step 3e
        // (validation.rs::validate_transaction) consumes — checking
        // proof.balance and proof.scar_count. scar_count cannot be read here:
        // it lives in the client-held FACT chain (YPX-001 §1.6), not in
        // WalletState, and this path does not have the WitnessRequest in
        // scope. Hardcoding scar_count = 0 is the PERMISSIVE direction — a
        // scarred validator would pass the oracle scar gate. That is only
        // harmless while oracle is disabled. So: refuse to emit a stake proof
        // whenever oracle is enabled, until scar_count is wired to the real
        // chain. This makes "enable oracle" structurally require "wire the
        // real scar count" (and the SEC-09 verification of the Nabla
        // attestation, GAP-O1..O4 in CONSENSUS_CRITICAL.md). See SEC-09.
        if self.oracle_config.enabled {
            warn!("SEC-09: oracle stake proof refused — scar_count not yet wired to the \
                   real FACT chain; oracle witnessing is blocked until that lands");
            return None;
        }

        // 4. Cross-check: Nabla state_id MUST match stored state_id.
        // SEC-09: this was non-fatal ("Nabla may lag a few ticks"), which let
        // a lying/stale local Nabla feed an unverified attested_state_id into
        // the proof. Now fatal — refuse to self-attest against state that does
        // not match our own storage.
        if nabla_state_id != wallet_state.state_id {
            warn!("SEC-09: oracle stake proof refused — Nabla state_id {} != stored state_id {}",
                hex::encode(nabla_state_id), hex::encode(wallet_state.state_id));
            return None;
        }

        // 5. Scar count — placeholder 0 reachable ONLY on the oracle-disabled
        // path above (where this proof is never consumed for a real decision,
        // since oracle TXs are rejected when disabled). Do NOT trust this
        // value once oracle is enabled — the gate above blocks that path.
        let scar_count = 0u32;

        // 6. Build NablaStakeProof
        // Note: Core step 3e for oracle only checks balance + scar_count.
        // The full 7-step Nabla attestation verification is CL8-only.
        // We still populate all fields for forward compatibility.
        let nabla_role = if role_str == "writer" { 1u8 } else { 0u8 };
        // `role_signature` arrives as a native byte field on the typed
        // response (post HTTP→TCP migration) — no hex decode step.
        let nabla_signature = nabla_resp.role_signature.clone();

        info!("Oracle stake proof: balance={}, scar_count={}, nabla_tick={}",
            wallet_state.balance, scar_count, nabla_tick);

        Some(axiom_core_logic::types::NablaStakeProof {
            nabla_node_pk,
            nabla_signature,
            attested_state_id: nabla_state_id,
            nabla_tick,
            nabla_role,
            wallet_pk,
            balance: wallet_state.balance,
            receipt_signatures: vec![], // Oracle step 3e doesn't verify receipts
            receipt_state_id: nabla_state_id,
            scar_count,
        })
    }
    
    /// Sync stats with current storage state (call after construction)
    pub fn sync_stats_from_storage(&self) {
        self.stats.hint_count.store(
            self.storage.hint_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    
    /// Load SPHINCS+ keys for VBC signing
    /// 
    /// Called at startup if sphincs_key_path is configured.
    /// Without this, the validator cannot sign VBCs for new validators.
    /// Approve or reject a VBC signing request (BUSINESS LOGIC ONLY)
    /// 
    /// Lambda makes the business decision: should we sign this new validator's VBC?
    /// Checks signing budget and stake threshold.
    /// Lambda NEVER does cryptography — Core handles all signing.
    /// Approve a VBC signing request from a new validator candidate.
    ///
    /// YP §10: Select MV-set candidates for a new validator.
    ///
    /// Two-phase selection:
    /// 1. Random discovery: shuffle known validators, pick 3, request their hints
    ///    to expand the candidate pool (ensures different pools for different runs)
    /// 2. Deterministic selection: from expanded pool, pick 3 using BLAKE3(candidate_pk)
    ///    as seed (auditable, reproducible given the same pool)
    ///
    /// Returns 3 validator_ids that should be asked to sign the VBC.
    pub fn select_mv_set_candidates(&self, candidate_pk: &[u8; 32]) -> Vec<String> {
        let all_hints = self.storage.get_all_hints().unwrap_or_default();
        if all_hints.len() < 3 {
            // Not enough known validators — return what we have
            return all_hints.iter().map(|h| hex::encode(h.validator_id)).collect();
        }

        // Phase 1: Random shuffle of known validators (ensures different pools per run)
        let mut candidates: Vec<String> = all_hints.iter()
            .map(|h| hex::encode(h.validator_id))
            .collect();

        // Remove self from candidates
        let our_id = hex::encode(self.validator_id());
        candidates.retain(|v| v != &our_id);

        if candidates.len() < 3 {
            return candidates;
        }

        // Phase 2: Deterministic selection using candidate's PK as seed
        let seed = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_MV_SELECT");
            h.update(candidate_pk);
            // Include current timestamp (rounded to hour) for run-to-run variation
            let now_hour = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() / 3600;
            h.update(&now_hour.to_le_bytes());
            *h.finalize().as_bytes()
        };

        // Deterministic shuffle using seed
        for i in 0..candidates.len() {
            let j = (seed[i % 32] as usize + i) % candidates.len();
            candidates.swap(i, j);
        }

        // Take first 3
        candidates.truncate(3);
        candidates
    }

    /// YP §10: Meta-Validator admission. The VBC issuer_set (3 SPHINCS+ PKs)
    /// IS the MV-set — no separate MVIB struct needed. Each approval records an
    /// mvib_binding (subject_validator_id → issuer_validator_id). The candidate
    /// must collect 3 independent approvals (enforced by record_mvib_binding).
    /// MV-set members inherit JFP witness role if this validator becomes absent.
    pub fn approve_vbc_sign_request(
        &self,
        _ed25519_pk_hex: &str,
        proof_cap: &str,
    ) -> Result<VBCSignApproval, LambdaError> {
        let our_chain_depth = self.vbc.target_vbc.chain_depth;

        // Check VBC maturity (30 days, genesis exempt)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if !axiom_core_logic::vbc::is_approval_mature(&self.vbc.target_vbc, now) {
            let remaining = axiom_core_logic::types::VBC_APPROVAL_MATURITY_SECS
                .saturating_sub(now.saturating_sub(self.vbc.target_vbc.issued_at));
            return Ok(VBCSignApproval {
                approved: false,
                reason: Some(format!(
                    "VBC not mature enough to approve new validators ({} seconds remaining)",
                    remaining
                )),
                signs_remaining: self.storage.get_vbc_signs_remaining().unwrap_or(6),
                our_chain_depth,
                accepted_proof_cap: String::new(),
            });
        }

        // Validate proof_cap
        if !proof_cap.is_empty() && proof_cap != "dmap" && proof_cap != "zkvm" {
            return Ok(VBCSignApproval {
                approved: false,
                reason: Some(format!("Invalid proof_cap: {}", proof_cap)),
                signs_remaining: self.storage.get_vbc_signs_remaining().unwrap_or(6),
                our_chain_depth,
                accepted_proof_cap: String::new(),
            });
        }

        // Check signing budget
        let signs_remaining = self.storage.get_vbc_signs_remaining()
            .unwrap_or(6); // Default budget of 6

        if signs_remaining == 0 {
            return Ok(VBCSignApproval {
                approved: false,
                reason: Some("Signing budget exhausted (0 of 6 remaining)".into()),
                signs_remaining: 0,
                our_chain_depth,
                accepted_proof_cap: String::new(),
            });
        }
        // H4 note: If a validator is rejected by some validators, they simply try others
        // from their hint table or discover new ones via VSP. The network has hundreds of
        // validators — a cartel would need near-total control to block all renewal paths.
        // No genesis special authority needed. No forced obligation.

        // Check requester's stake against protocol threshold (White Paper §4.13).
        // 500 AXC minimum stake for validator participation.
        // dev-mode: 0 (allows testing without funded wallets).
        #[cfg(not(feature = "dev-mode"))]
        let min_stake: u64 = 500;
        #[cfg(feature = "dev-mode")]
        let min_stake: u64 = 0;
        if min_stake > 0 {
            // SECURITY FIX #11: Fail on invalid hex — unwrap_or_default silently
            // produces empty bytes, bypassing the stake check entirely.
            let pk_bytes = hex::decode(_ed25519_pk_hex)
                .map_err(|e| LambdaError::InvalidRequest(format!("Invalid Ed25519 PK hex: {}", e)))?;
            let requester_balance = self.storage.get_wallet_state(&pk_bytes, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)?
                .map(|ws| ws.balance)
                .unwrap_or(0);
            if requester_balance < min_stake {
                return Ok(VBCSignApproval {
                    approved: false,
                    reason: Some(format!(
                        "Insufficient stake: {} atoms (need {})", requester_balance, min_stake
                    )),
                    signs_remaining,
                    our_chain_depth,
                    accepted_proof_cap: String::new(),
                });
            }
        }

        let accepted = if proof_cap.is_empty() { "dmap" } else { proof_cap };

        info!("VBC sign request APPROVED ({} signs remaining, our depth {}, proof_cap={})",
              signs_remaining, our_chain_depth, accepted);

        Ok(VBCSignApproval {
            approved: true,
            reason: None,
            signs_remaining,
            our_chain_depth,
            accepted_proof_cap: accepted.to_string(),
        })
    }
    
    /// Record that we signed a VBC (decrements budget + tracks approval)
    /// Called by Gateway AFTER Core produces the signature
    pub fn record_vbc_sign(
        &self,
        validator_id: &str,
        sphincs_pk_hex: &str,
        ed25519_pk_hex: &str,
        proof_cap: &str,
        node_name: &str,
        request_id: &str,
    ) -> Result<u8, LambdaError> {
        let remaining = self.storage.decrement_vbc_signs_remaining()
            .map_err(|e| LambdaError::StorageError(format!("Failed to record VBC sign: {}", e)))?;

        // Track this approval in approved_validators table
        if let Err(e) = self.storage.record_validator_approval(
            validator_id, sphincs_pk_hex, ed25519_pk_hex, proof_cap, node_name, request_id,
        ) {
            warn!("Failed to record validator approval (non-fatal): {}", e);
        }

        // YP §10: Record MVIB binding — we are an issuer for this new validator.
        // The candidate must collect 3 independent approvals to complete their MVIB.
        let our_id = hex::encode(self.validator_id());
        match self.storage.record_mvib_binding(validator_id, &our_id) {
            Ok(count) => info!("MVIB: {} has {}/3 issuers", validator_id, count),
            Err(e) => debug!("MVIB binding note: {}", e), // May already be bound (non-fatal)
        }

        info!("VBC sign recorded for {} ({}). Budget remaining: {}", node_name, validator_id, remaining);
        Ok(remaining)
    }

    /// YP §10: Create and store a signed MVIB binding for this validator.
    ///
    /// Called after this validator's VBC has been fully signed (k=3 approvals collected).
    /// The binding records our admission set (the 3 issuers who signed our VBC) and
    /// signs the commitment with our Ed25519 operational key.
    ///
    /// This binding allows JFP voting responsibility to pass to our meta-validators
    /// (admission set members) if we disappear.
    pub fn create_and_store_mvib_binding(&self) -> Result<(), LambdaError> {
        use axiom_core_logic::mvib::compute_mvib_commitment;
        use axiom_core_logic::types::MvibBinding;
        use ed25519_dalek::Signer;

        let vbc = &self.vbc.target_vbc;

        // Extract admission set: the k=3 issuer validator IDs from our VBC.
        // Each issuer PK is a SPHINCS+ PK; we need the validator_id (BLAKE3 hash).
        if vbc.issuer_set.len() != 3 {
            return Err(LambdaError::InvalidRequest(
                format!("VBC has {} issuers, need exactly 3 for MVIB", vbc.issuer_set.len())
            ));
        }

        let mut admission_set = Vec::with_capacity(3);
        for issuer_pk in &vbc.issuer_set {
            let issuer_id = *blake3::hash(issuer_pk).as_bytes();
            admission_set.push(issuer_id);
        }

        // Current tick
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute commitment and sign
        let commitment = compute_mvib_commitment(&vbc.validator_id, &admission_set, tick);
        let signature = self.signing_key.sign(&commitment);

        let binding = MvibBinding {
            validator_id: vbc.validator_id,
            admission_set,
            binding_tick: tick,
            signature: signature.to_bytes().to_vec(),
        };

        // Verify our own binding (fail-stop)
        let pk = ed25519_dalek::VerifyingKey::from(&self.signing_key);
        axiom_core_logic::mvib::verify_mvib_binding(&binding, pk.as_bytes())
            .map_err(|e| LambdaError::InvalidRequest(format!("MVIB self-verify failed: {}", e)))?;

        // Store
        self.storage.store_mvib_binding(&binding)?;
        info!("MVIB: created and stored signed binding for {} (tick={})",
            hex::encode(vbc.validator_id), tick);

        Ok(())
    }

    /// Set stats file path (call after config is loaded)
    pub fn set_stats_path(&self, path: std::path::PathBuf) {
        info!("Stats path set to: {:?}", path);
        *self.stats.stats_path.lock() = Some(path);
        // Load cumulative stats from previous session (if stats.json exists)
        self.stats.load_cumulative();
    }
    
    /// Load real VBC from vbc.json file.
    /// Same format as ANTIE uses — both load the same file generated by install_genesis.sh.
    /// Fails hard if file is missing, corrupt, or doesn't have 3 issuers/sigs.
    /// "Can crash, must not lie" — a validator without a valid VBC must not start.
    fn load_vbc_from_file(path: &std::path::Path) -> Result<VBCProofBundle, LambdaError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| LambdaError::ConfigError(format!("Failed to read VBC file {:?}: {}", path, e)))?;
        let file_vbc: VBCFile = serde_json::from_str(&content)
            .map_err(|e| LambdaError::ConfigError(format!("Failed to parse VBC file {:?}: {}", path, e)))?;
        
        let sphincs_pk = hex::decode(&file_vbc.subject_pubkey_sphincs_hex)
            .map_err(|e| LambdaError::ConfigError(format!("Invalid SPHINCS+ PK hex in VBC: {}", e)))?;
        if sphincs_pk.is_empty() {
            return Err(LambdaError::ConfigError("VBC has empty SPHINCS+ public key".into()));
        }
        let validator_id = axiom_core_logic::compute::compute_validator_id(&sphincs_pk);
        
        let bundle = VBCProofBundle {
            target_vbc: VBC {
                version: file_vbc.version.unwrap_or(0x09),
                // YPX-021 §7 — ceremony-era validator VBCs carry no baseline.
                network_size_baseline: 0,
                baseline_tick: 0,
                validator_id,
                subject_pubkey_sphincs: sphincs_pk,
                // SECURITY FIX #11: Fail loudly on invalid hex instead of silently producing empty keys.
                // unwrap_or_default() on hex decode would silently accept corrupted VBC data,
                // leading to a validator running with empty/wrong Dilithium public key.
                subject_pubkey_dilithium: hex::decode(&file_vbc.subject_pubkey_dilithium_hex)
                    .map_err(|e| LambdaError::ConfigError(format!("Invalid Dilithium PK hex in VBC: {}", e)))?,
                subject_pubkey_ed25519: hex::decode(&file_vbc.subject_pubkey_ed25519_hex)
                    .map_err(|e| LambdaError::ConfigError(format!("Invalid Ed25519 PK hex in VBC: {}", e)))?,
                pgp_fingerprint: file_vbc.pgp_fingerprint_hex.as_ref()
                    .and_then(|h| hex::decode(h).ok())
                    .unwrap_or_default(),
                node_name: file_vbc.node_name.clone().unwrap_or_default(),
                proof_cap: String::new(),
                issued_at: file_vbc.issued_at,
                expires_at: file_vbc.expires_at,
                chain_depth: file_vbc.chain_depth.unwrap_or(0),
                // AUDIT-FIX v2.11.14: Fail-stop on corrupted VBC hex (was silent drop via filter_map).
                // Silently dropping entries could reduce issuer quorum below k=3.
                issuer_set: file_vbc.issuer_set.iter()
                    .map(|h| hex::decode(h).map_err(|e| LambdaError::InvalidRequest(
                        format!("VBC issuer_set bad hex '{}': {}", h, e))))
                    .collect::<Result<Vec<_>, _>>()?,
                signatures: file_vbc.signatures.iter()
                    .map(|h| hex::decode(h).map_err(|e| LambdaError::InvalidRequest(
                        format!("VBC signature bad hex '{}': {}", h, e))))
                    .collect::<Result<Vec<_>, _>>()?,
                max_tx: 0,
                founding_vbc_hash: file_vbc.founding_vbc_hash.as_ref()
                    .and_then(|h| {
                        let bytes = hex::decode(h).ok()?;
                        let arr: [u8; 32] = bytes.try_into().ok()?;
                        Some(arr)
                    })
                    .unwrap_or([0u8; 32]),
            },
            supporting_vbcs: vec![],
        };
        
        // VBC must have exactly 3 issuers and 3 signatures — protocol requirement
        let n_issuers = bundle.target_vbc.issuer_set.len();
        let n_sigs = bundle.target_vbc.signatures.len();
        #[cfg(not(feature = "dev-mode"))]
        if n_issuers != 3 || n_sigs != 3 {
            return Err(LambdaError::ConfigError(format!(
                "VBC at {:?} has {}/{} issuers/sigs, protocol requires exactly 3/3",
                path, n_issuers, n_sigs
            )));
        }
        #[cfg(feature = "dev-mode")]
        if n_issuers != 3 || n_sigs != 3 {
            warn!("DEV MODE: VBC at {:?} has {}/{} issuers/sigs (production requires 3/3)", path, n_issuers, n_sigs);
        }
        
        info!("Loaded VBC from {:?} (3 issuers, chain_depth={})",
                 path, bundle.target_vbc.chain_depth);
        
        // STARTUP VERIFICATION: Verify our own VBC chains to genesis root keys.
        // If this fails, Core was compiled with different root keys than the ceremony
        // that produced this VBC. This is a fatal configuration error — "can crash, must not lie".
        // In test builds (#[cfg(test)]), skip — test VBCs may not match compiled root keys
        // after ceremony key rotation. Production ALWAYS verifies.
        #[cfg(all(not(test), not(feature = "dev-mode")))]
        {
            if let Err(e) = axiom_core_logic::vbc::verify_vbc_bundle_no_time(&bundle) {
                error!("VBC startup check failed ({}): issuer PKs in vbc.json do not match \
                        ROOT_AUTHORITY_PKS in compiled Core. Ceremony/build mismatch.", e);
                eprintln!();
                eprintln!("  AXIOM Lambda cannot start.");
                eprintln!();
                eprintln!("  Your validator certificate (VBC) does not match this software release.");
                eprintln!("  This node's identity cannot be verified against the network trust root.");
                eprintln!();
                eprintln!("  Please contact your network administrator or re-run the genesis ceremony.");
                eprintln!();
                return Err(LambdaError::ConfigError(
                    "VBC trust chain mismatch — validator certificate does not match this build.".into()
                ));
            }
            info!("VBC chain verification PASSED — issuers match compiled root authority keys");
        }
        #[cfg(test)]
        info!("VBC chain verification SKIPPED (test build)");
        
        Ok(bundle)
    }
    
    /// Get a clone of our VBC bundle (for passing to Core)
    pub fn vbc_bundle(&self) -> VBCProofBundle {
        self.vbc.clone()
    }
    
    /// Get VBC bundle for inclusion in witness signatures.
    /// Always returns Some — Lambda must have a real VBC loaded at startup.
    pub fn vbc_for_signature(&self) -> Option<VBCProofBundle> {
        Some(self.vbc.clone())
    }
    
    /// Get our validator ID
    pub fn validator_id(&self) -> [u8; 32] {
        self.validator_id
    }

    /// Get a reference to storage (for admin API read-only queries)
    pub fn storage(&self) -> &Arc<Storage> {
        &self.storage
    }

    /// Check if fee redemption is available (enough active validators).
    /// Fee redemption requires k=3 non-overlapping validators — minimum 6 in network.
    /// fee_redemption_requires_k3_non_overlapping_validators
    /// minimum_network_size_is_6
    /// with_3_validators_fee_path_is_structurally_impossible
    /// AUDIT-FIX v2.11.13: Uses recent_hint_count (seen within 1h) to exclude stale peers.
    pub fn fee_redemption_available(&self) -> bool {
        const RECENT_PEER_WINDOW_SECS: u64 = 3_600; // 1 hour
        self.storage.recent_hint_count(RECENT_PEER_WINDOW_SECS) >= 6
    }

    /// Log startup warning if peer count is below fee redemption threshold.
    /// Called from server.rs at startup (production path).
    pub fn check_fee_redemption_readiness(&self, min_required: usize) {
        let recent = self.storage.recent_hint_count(3_600);
        let total = self.storage.hint_count();
        if recent < min_required {
            warn!("Fee redemption unavailable: {} recent peers ({} total), need {} minimum. \
                   Fee redemption requires k=3 non-overlapping validators. \
                   Transactions will still process — only fee collection is affected.",
                  recent, total, min_required);
        } else {
            info!("Fee redemption available: {} recent peers (minimum {})", recent, min_required);
        }
    }

    /// Initialize management DB and DWP/JFP/Console engines.
    /// Called after construction (needs &mut self before Arc wrapping).
    pub fn init_management(&mut self, db: Arc<crate::management_db::ManagementDb>) {
        let my_pk = self.public_key.to_bytes();
        self.dwp_engine = Some(crate::dwp_engine::DwpEngine::new_with_storage(
            db.clone(), self.storage.clone(), my_pk,
        ));

        // Initialize Console engine and ensure schema
        let console = crate::console_engine::ConsoleEngine::new(db.clone());
        if let Err(e) = console.ensure_schema() {
            tracing::warn!("Console schema init failed (non-fatal): {}", e);
        }
        self.console_engine = Some(console);

        self.management_db = Some(db);
    }

    /// Get management DB reference (for admin API queries)
    pub fn management_db(&self) -> Option<&Arc<crate::management_db::ManagementDb>> {
        self.management_db.as_ref()
    }

    /// Get DWP engine reference
    pub fn dwp_engine(&self) -> Option<&crate::dwp_engine::DwpEngine> {
        self.dwp_engine.as_ref()
    }

    /// Get Console engine reference
    pub fn console_engine(&self) -> Option<&crate::console_engine::ConsoleEngine> {
        self.console_engine.as_ref()
    }

    /// Build a CL10 Fan-Out message for a Console decision.
    /// Core verifies: originator VBC + Ed25519 signature + TTL + diffusion_id.
    /// Without Core verification, other validators will reject the Fan-Out.
    ///
    /// Content format: proposal_id (UTF-8) || result ("Approved"/"Rejected") || digit_version (u8)
    pub fn build_console_fanout(
        &self,
        proposal_id: &str,
        result: &str,
        digit_version: u8,
    ) -> axiom_core_logic::types::FanOutMessage {
        use ed25519_dalek::Signer;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Content: proposal_id || \0 || result || \0 || digit_version
        let mut content = Vec::new();
        content.extend_from_slice(proposal_id.as_bytes());
        content.push(0);
        content.extend_from_slice(result.as_bytes());
        content.push(0);
        content.push(digit_version);

        let originator_pk: [u8; 32] = self.public_key.to_bytes();

        // Diffusion ID: BLAKE3("AXIOM_FANOUT_ID" || content || originator_pk)
        // Must match CL10 verification in modes.rs
        let diffusion_id = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_FANOUT_ID");
            h.update(&content);
            h.update(&originator_pk);
            *h.finalize().as_bytes()
        };

        let ttl_original: u8 = 5;
        let fanout: u8 = 3;

        // Sign: BLAKE3("AXIOM_FANOUT" || diffusion_id || content_type || content || ttl_original || fanout || timestamp)
        // Must match CL10 verification in modes.rs
        let sign_data = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_FANOUT");
            h.update(&diffusion_id);
            h.update(&axiom_core_logic::types::FANOUT_CONSOLE_RESULT.to_le_bytes());
            h.update(&content);
            h.update(&[ttl_original]);
            h.update(&[fanout]);
            h.update(&now.to_le_bytes());
            *h.finalize().as_bytes()
        };
        let sig = self.signing_key.sign(&sign_data);

        axiom_core_logic::types::FanOutMessage {
            diffusion_id,
            content_type: axiom_core_logic::types::FANOUT_CONSOLE_RESULT,
            content,
            originator_pk,
            originator_sig: sig.to_bytes().to_vec(),
            timestamp: now,
            ttl_original,
            fanout,
            ttl_current: ttl_original,
        }
    }

    /// Handle an incoming Console Fan-Out result (after CL10 verification by Core).
    /// Applies the digit_version update if the result is "Approved".
    /// This is a coordination signal — our Lambda auto-applies it.
    /// Third-party Lambda implementations decide for themselves (YP §21.10.7).
    pub fn handle_console_fanout(&self, content: &[u8]) {
        // Content format: proposal_id \0 result \0 digit_version
        let parts: Vec<&[u8]> = content.splitn(3, |&b| b == 0).collect();
        if parts.len() < 3 { return; }
        let result = String::from_utf8_lossy(parts[1]);
        let dv = parts[2].first().copied().unwrap_or(0);

        if result == "Approved" {
            if let Some(db) = &self.management_db {
                match db.set_digit_version(dv) {
                    Ok(()) => {
                        tracing::info!(
                            "Console Fan-Out received: digit_version updated to {} (auto-applied)",
                            dv
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Console Fan-Out: failed to apply digit_version {}: {}", dv, e);
                    }
                }
            }
        } else {
            tracing::info!("Console Fan-Out received: proposal {} (no action needed)", result);
        }
    }

    /// Query active frozen wallet PKs from management_db freeze_orders.
    /// Returns None if management DB is not initialized (pre-JFP operation).
    /// Lambda passes the result to Core via PublicInputs.frozen_wallets.
    fn get_frozen_wallets(&self) -> Option<Vec<[u8; 32]>> {
        let db = self.management_db.as_ref()?;
        match db.get_active_frozen_wallets() {
            Ok(wallets) if !wallets.is_empty() => Some(wallets),
            _ => None,
        }
    }

    /// §23.14: Get current pending audit demand (for admin API)
    pub fn pending_audit(&self) -> Option<axiom_core_logic::types::AuditDemand> {
        self.pending_audit.lock().clone()
    }

    /// §23.14: Get transaction count since last audit demand (for admin API)
    pub fn audit_txs_since_demand(&self) -> u64 {
        self.audit_txs_since_demand.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// §23.14.6: Get our Ed25519 public key bytes (for admin API is_peer check)
    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    /// Get the bound wallet balance (stake) for VSP response.
    /// Queries own wallet state by validator's Ed25519 PK.
    fn get_bound_wallet_balance(&self) -> u64 {
        self.storage.get_wallet_state(self.public_key.as_bytes(), axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)
            .ok()
            .flatten()
            .map(|ws| ws.balance)
            .unwrap_or(0)
    }

    /// Public accessor for the validator's current stake — same value
    /// the /peers wire publishes as `stake`. Used by the per-validator
    /// dashboard's top bar to render a `STAKE: 1,000,000 AXC` chip
    /// next to the VBC chip.
    pub fn bound_wallet_balance_atoms(&self) -> u64 {
        self.get_bound_wallet_balance()
    }

    /// §23.14.6: Get current peer-audit ban list (for admin API)
    pub fn peer_audit_bans(&self) -> Vec<axiom_core_logic::types::PeerAuditBanEntry> {
        if let Ok(core) = self.core.try_write() {
            core.avm().peer_audit_bans()
        } else {
            Vec::new()
        }
    }

    /// Get random hints for response (used for error responses too)
    /// Per Yellow Paper 27: hints must be included in ALL responses
    pub fn get_hints(&self) -> Vec<ValidatorHint> {
        let validator_id_str = hex::encode(self.validator_id);
        self.storage.get_random_hints(3, &validator_id_str)
            .unwrap_or_default()
    }
    
    /// Check if running in production mode
    pub fn is_production_mode(&self) -> bool {
        true // Always production — no dev mode
    }

    /// §23.14: Process audit demand from Core outputs.
    /// If Core generated a new demand, store it and reset TX counter.
    /// If no demand, increment TX counter (for admin display).
    /// AVM enforces the real countdown — this is Lambda-level tracking only.
    /// §23.14: Resolve audit confirmation for Core.
    ///
    /// Two paths:
    /// - **Self-audit** (target == our PK): Look up trigger_txid in DB,
    ///   send raw stored fields back. Lambda does ZERO crypto — Core hashes and verifies.
    /// - **Peer-audit** (target != our PK): Handled asynchronously via ANTIE email.
    ///   Request sent via pending_peer_audit_outbound(). Response arrives via
    ///   handle_peer_audit_response(). Returns None here — AVM manages countdown.
    ///
    /// Client-provided confirmations take priority (for peer-audit protocol).
    fn resolve_audit_confirmation(
        &self,
        client_confirmation: &Option<axiom_core_logic::types::AuditConfirmation>,
    ) -> Option<axiom_core_logic::types::AuditConfirmation> {
        if client_confirmation.is_some() {
            return client_confirmation.clone();
        }
        let pending = self.pending_audit.lock();
        if let Some(ref demand) = *pending {
            // Check if this is a self-audit (target == our PK)
            let our_pk = self.public_key.as_bytes().to_vec();
            if demand.target_validator_pk == our_pk {
                // Self-audit: look up trigger_txid in DB and send raw data
                debug!("§23.14: Self-audit — looking up trigger_txid={} in DB",
                       hex::encode(&demand.trigger_txid[..8]));

                // Look up trigger_txid in transaction_records (every validator stores these,
                // not just the finalizer). Receipts are only stored by the k=3 finalizer,
                // so using receipts would fail when the audit triggers on V1/V2.
                let tx_record = self.storage.get_transaction_record_by_txid(&demand.trigger_txid)
                    .ok().flatten();

                if let Some(tx_record) = tx_record {
                    // Build confirmation from raw DB data — Lambda does ZERO crypto
                    let state_id = tx_record.produced_state_id;
                    let sender_balance = tx_record.sender_balance;
                    let amount = tx_record.amount;

                    info!("§23.14: Self-audit confirmation built from DB — state_id={}, sender_balance={}, amount={}",
                          hex::encode(&state_id[..8]), sender_balance, amount);

                    Some(axiom_core_logic::types::AuditConfirmation {
                        challenge_nonce: demand.challenge_nonce,
                        target_validator_pk: demand.target_validator_pk.clone(),
                        sender_balance,
                        receiver_balance: 0,
                        state_id,
                        amount,
                    })
                } else {
                    warn!("§23.14: Self-audit — trigger_txid {} not found in transaction_records",
                          hex::encode(&demand.trigger_txid[..8]));
                    None
                }
            } else {
                // Peer-audit: handled asynchronously via ANTIE email.
                // The peer-audit request is sent via handle_peer_audit_outbound()
                // (piggybacked on WitnessResponse). Response arrives later via
                // handle_peer_audit_response(). AVM handles countdown + banning.
                debug!("§23.14.6: Peer-audit demand active for target={} — awaiting ANTIE response",
                       hex::encode(&demand.target_validator_pk[..std::cmp::min(8, demand.target_validator_pk.len())]));
                None // Peer-audit confirmation comes via handle_peer_audit_response(), not here
            }
        } else {
            None
        }
    }

    /// YPX-009 §4: Resolve pending Pulse audit request.
    /// Looks up state_ids from DB, builds raw TxDigests.
    /// Lambda does ZERO crypto — Core replays Argon2id→BLAKE3 chain.
    fn resolve_pulse_audit(&self) -> Option<axiom_core_logic::types::PulseAuditResponse> {
        let request = self.pending_pulse_audit.lock().take()?;

        let mut entries = Vec::with_capacity(request.state_ids.len());
        for (i, state_id) in request.state_ids.iter().enumerate() {
            match self.storage.get_transaction_record(state_id) {
                Ok(Some(record)) => {
                    entries.push(axiom_core_logic::types::TxDigest {
                        tx_number: request.tx_numbers[i],
                        sender_balance: record.sender_balance,
                        receiver_balance: 0,  // not available at sender's validator
                        state_id: record.produced_state_id,
                        amount: record.amount,
                    });
                }
                Ok(None) => {
                    warn!("YPX-009: Pulse audit — state_id={} not found in DB, audit will fail",
                          hex::encode(&state_id[..8]));
                    // Return partial — Core will detect chain mismatch
                    entries.push(axiom_core_logic::types::TxDigest {
                        tx_number: request.tx_numbers[i],
                        sender_balance: 0,
                        receiver_balance: 0,
                        state_id: *state_id,
                        amount: 0,
                    });
                }
                Err(e) => {
                    error!("YPX-009: Pulse audit DB error for state_id={}: {}",
                           hex::encode(&state_id[..8]), e);
                    return None;
                }
            }
        }

        info!("YPX-009: Pulse audit response built — {} entries from DB (epoch={})",
              entries.len(), request.epoch);

        Some(axiom_core_logic::types::PulseAuditResponse {
            entries,
            epoch: request.epoch,
        })
    }

    /// YPX-009 §4: Store Pulse audit request from Core for next TX.
    fn handle_pulse_audit_request(&self, request: Option<axiom_core_logic::types::PulseAuditRequest>) {
        if let Some(req) = request {
            info!("YPX-009: Core emitted PulseAuditRequest — {} entries, epoch={}",
                  req.state_ids.len(), req.epoch);
            *self.pending_pulse_audit.lock() = Some(req);
        }
    }

    fn handle_audit_demand(&self, demand: Option<axiom_core_logic::types::AuditDemand>) {
        if let Some(ref d) = demand {
            info!("§23.14: Core generated audit demand — target={}, nonce={}",
                  hex::encode(&d.target_validator_pk[..std::cmp::min(8, d.target_validator_pk.len())]),
                  hex::encode(&d.challenge_nonce[..8]));
            let mut pending = self.pending_audit.lock();
            // Only set if no pending audit (don't override active countdown — same as AVM)
            if pending.is_none() {
                *pending = Some(d.clone());
                self.audit_txs_since_demand.store(0, std::sync::atomic::Ordering::Relaxed);
            }
        } else {
            // Increment TX counter if we have a pending audit
            let pending = self.pending_audit.lock();
            if pending.is_some() {
                self.audit_txs_since_demand.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// §23.14.6: Get the outbound peer-audit request (for ANTIE to send via email).
    ///
    /// Called after each witness request processing. If there's a pending peer-audit
    /// demand and we haven't sent the request yet, returns an OutboundPeerAudit
    /// containing the request and target email (from validator hints).
    ///
    /// Returns None if: no pending peer-audit, already sent, or target email unknown.
    pub fn pending_peer_audit_outbound(&self) -> Option<crate::types::OutboundPeerAudit> {
        // Check if we already sent
        if self.peer_audit_sent.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }

        // Check if AVM has a pending peer-audit request
        // Use try_lock since we may be called from sync context during response building
        let core = self.core.try_write().ok()?;
        let request = core.avm().pending_peer_audit_request()?;
        drop(core);

        // Resolve target validator's email from hints
        let pending = self.pending_audit.lock();
        if let Some(ref demand) = *pending {
            let target_pk_hex = hex::encode(&demand.target_validator_pk);
            // Search all hints for the target validator
            if let Ok(all_hints) = self.storage.get_all_hints() {
                for hint in &all_hints {
                    if hex::encode(hint.validator_id) == target_pk_hex {
                        // Extract email from carriers (format: "email:user@domain")
                        if let Some(email) = hint.carriers.iter()
                            .find(|c| c.starts_with("email:"))
                            .map(|c| c[6..].to_string())
                        {
                            self.peer_audit_sent.store(true, std::sync::atomic::Ordering::Relaxed);
                            return Some(crate::types::OutboundPeerAudit {
                                request,
                                target_email: email,
                            });
                        }
                    }
                }
            }
            debug!("§23.14.6: Cannot send peer-audit — no email carrier for target {}",
                   &target_pk_hex[..std::cmp::min(16, target_pk_hex.len())]);
        }
        None
    }

    /// §23.14.6: Handle inbound peer audit request from remote validator.
    ///
    /// Remote validator is pinging us: "show me what you stored for txid X".
    /// Lambda looks up the txid in DB, gets raw fields. Core computes hash
    /// independently from those fields, compares against the expected_hash.
    ///
    /// Returns PeerAuditResponse with computed hash (regardless of match/mismatch).
    /// If mismatch: our own Lambda's DB is corrupted → schedule crash in 3 minutes.
    pub async fn handle_peer_audit_request(
        &self,
        request: &axiom_core_logic::types::PeerAuditRequest,
    ) -> Option<axiom_core_logic::types::PeerAuditResponse> {
        info!("§23.14.6: Received peer-audit request — txid={}, from={}",
              hex::encode(&request.txid[..8]),
              hex::encode(&request.requester_pk[..std::cmp::min(8, request.requester_pk.len())]));

        // Lambda looks up txid in DB — pure DB operation, zero crypto
        let receipt = self.storage.get_receipt(&request.txid).ok().flatten();
        let (sender_balance, receiver_balance, state_id, amount) = if let Some(receipt) = &receipt {
            let tx_record = self.storage.get_transaction_record(&receipt.produced_state_id)
                .ok().flatten();
            let sender_balance = tx_record.as_ref().map(|r| r.sender_balance).unwrap_or(0);
            let amount = tx_record.as_ref().map(|r| r.amount).unwrap_or(0);
            (sender_balance, 0u64, receipt.produced_state_id, amount)
        } else {
            warn!("§23.14.6: Peer-audit request for unknown txid={}", hex::encode(&request.txid[..8]));
            return None;
        };

        // Core (the judge) computes hash from raw DB fields and compares
        let (computed_hash, matches) = axiom_core_logic::audit::verify_inbound_peer_audit(
            request,
            sender_balance,
            receiver_balance,
            &state_id,
            amount,
        );

        let response = axiom_core_logic::types::PeerAuditResponse {
            txid: request.txid,
            computed_hash,
            challenge_nonce: request.challenge_nonce,
            responder_pk: self.public_key.as_bytes().to_vec(),
        };

        if !matches {
            // Our own Lambda's DB is corrupted! Core detected it.
            // Wait 3 minutes (give ANTIE time to send response), then exit.
            eprintln!("§23.14.6: FATAL — peer-audit hash mismatch detected on OUR node! \
                       Our Lambda's DB is corrupted for txid={}. \
                       Exiting in {} seconds to allow ANTIE response delivery.",
                      hex::encode(&request.txid[..8]),
                      axiom_core_logic::types::PEER_AUDIT_CRASH_DELAY_SECS);

            let delay = axiom_core_logic::types::PEER_AUDIT_CRASH_DELAY_SECS;
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(delay));
                eprintln!("§23.14.6: Crash delay expired. Self-terminating due to DB corruption.");
                std::process::exit(1);
            });
        } else {
            info!("§23.14.6: Peer-audit verification passed — our DB is honest for txid={}",
                  hex::encode(&request.txid[..8]));
        }

        Some(response)
    }

    /// §23.14.6: Handle inbound peer audit response from remote validator.
    ///
    /// Remote validator responded to our ping. Core compares the hash.
    /// Match → clear pending audit. Mismatch → ban for 24h.
    pub async fn handle_peer_audit_response(
        &self,
        response: &axiom_core_logic::types::PeerAuditResponse,
    ) {
        info!("§23.14.6: Received peer-audit response — txid={}, from={}",
              hex::encode(&response.txid[..8]),
              hex::encode(&response.responder_pk[..std::cmp::min(8, response.responder_pk.len())]));

        let core = self.core.write().await;

        // Get expected hash from AVM's pending peer-audit
        if let Some(expected_hash) = core.avm().pending_peer_audit_hash() {
            // Core is the judge — compare hashes
            if axiom_core_logic::audit::verify_peer_audit_response(&expected_hash, response) {
                // Match! Peer is honest. Clear pending audit.
                info!("§23.14.6: Peer-audit PASSED — validator {} is honest",
                      hex::encode(&response.responder_pk[..std::cmp::min(8, response.responder_pk.len())]));
                core.avm().clear_peer_audit();
                drop(core);
                // Clear Lambda-level tracking
                *self.pending_audit.lock() = None;
                self.peer_audit_sent.store(false, std::sync::atomic::Ordering::Relaxed);
                self.audit_txs_since_demand.store(0, std::sync::atomic::Ordering::Relaxed);
            } else {
                // Mismatch! Ban the remote validator for 24h.
                eprintln!("§23.14.6: Peer-audit FAILED — validator {} returned wrong hash. BANNING for 24h.",
                         hex::encode(&response.responder_pk[..std::cmp::min(8, response.responder_pk.len())]));
                core.avm().ban_validator(
                    response.responder_pk.clone(),
                    axiom_core_logic::types::PeerAuditBanReason::HashMismatch,
                );
                core.avm().clear_peer_audit();
                drop(core);
                // Clear Lambda-level tracking
                *self.pending_audit.lock() = None;
                self.peer_audit_sent.store(false, std::sync::atomic::Ordering::Relaxed);
                self.audit_txs_since_demand.store(0, std::sync::atomic::Ordering::Relaxed);
            }
        } else {
            debug!("§23.14.6: Received peer-audit response but no pending peer-audit — ignoring");
        }
    }

    /// §11.5: Issue a Confidence Index for a wallet after successful TX.
    ///
    /// The CI is signed by this validator's Ed25519 key. Client stores it
    /// and presents it during offline ⟠ Ark trades. The receiver inspects
    /// CI to decide whether to accept (GREEN/YELLOW/RED).
    ///
    /// Core is the law — CI signing message is computed by Core's
    /// compute_ci_signing_message(). Lambda just provides the data and signs.
    fn issue_confidence_index(&self, wallet_pk: &[u8]) -> Option<axiom_core_logic::types::ConfidenceIndex> {
        // Look up wallet stats from storage
        let wallet_state = self.storage.get_wallet_state(wallet_pk, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP).ok().flatten()?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build CI with 5-factor data from wallet state (YPX-010)
        // In production, these factors would come from FACT chain analysis.
        // Lambda provides the best data it has from its DB.
        let mut ci = axiom_core_logic::types::ConfidenceIndex {
            wallet_pk: wallet_pk.to_vec(),
            last_k3_at: now, // This is a k=3 TX right now
            ark_tx_count_since_k3: 0, // Reset on k=3
            k3_balance: wallet_state.balance,
            ark_tx_mean_amount: 0, // No Ark history yet (just loaded)
            ark_validator_count: 1, // At least this validator
            has_fact_scar: false, // Lambda would check FACT chain
            has_any_k3: true, // This IS a k=3 TX
            conflict_count: self.stats.double_spend_count.load(std::sync::atomic::Ordering::Relaxed),
            validator_signature: Vec::new(),
            issuer_validator_pk: self.public_key.as_bytes().to_vec(),
        };

        // Core computes the signing message — Lambda signs it
        let message = axiom_core_logic::ark::compute_ci_signing_message(&ci);

        // Sign with our Ed25519 key
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(&message);
        ci.validator_signature = signature.to_bytes().to_vec();

        Some(ci)
    }

    /// §23.14.6: Resolve a validator's email address from hints.
    /// Looks up the validator_id in the hints table, extracts email from carriers.
    pub fn resolve_validator_email(&self, validator_id_hex: &str) -> Option<String> {
        self.storage.get_all_hints().ok()
            .and_then(|hints: Vec<axiom_core_logic::types::ValidatorHint>| {
                hints.iter()
                    .find(|h| hex::encode(h.validator_id) == validator_id_hex)
                    .and_then(|h| h.carriers.iter()
                        .find(|c: &&String| c.starts_with("email:"))
                        .map(|c| c[6..].to_string()))
            })
    }

    /// §23.14.6: Check if a validator is banned by peer-audit.
    /// Delegates to AVM's ban list (Core is the authority).
    pub async fn is_validator_banned(&self, validator_pk: &[u8]) -> bool {
        let core = self.core.write().await;
        core.avm().is_validator_banned(validator_pk)
    }

    /// Store a witness response in the per-engine idempotency cache,
    /// keyed by `response.request_id`. FIFO eviction once
    /// `WITNESS_IDEMPOTENCY_CACHE_CAP` is exceeded. Safe to call with
    /// an empty `request_id` — the entry is simply not stored.
    /// See `process_witness_request`'s dedup gate for read-side.
    fn remember_witness_response(&self, response: &WitnessResponse) {
        if response.request_id.is_empty() {
            return;
        }
        let mut cache = self.witness_idempotency_cache.lock();
        while cache.len() >= WITNESS_IDEMPOTENCY_CACHE_CAP {
            cache.pop_front();
        }
        cache.push_back((response.request_id.clone(), response.clone()));
    }

    /// Store a redeem response in the per-engine idempotency cache, keyed by
    /// `response.request_id`. Redeem-side mirror of `remember_witness_response`
    /// (Mac handoff 2026-07-06). FIFO eviction at `WITNESS_IDEMPOTENCY_CACHE_CAP`;
    /// empty `request_id` is not stored.
    fn remember_redeem_response(&self, response: &RedeemResponse) {
        if response.request_id.is_empty() {
            return;
        }
        let mut cache = self.redeem_idempotency_cache.lock();
        while cache.len() >= WITNESS_IDEMPOTENCY_CACHE_CAP {
            cache.pop_front();
        }
        cache.push_back((response.request_id.clone(), response.clone()));
    }

    /// Process a witness request
    ///
    /// The Gateway (ANTIE) has run only CL2_PREFILTER (state-independent).
    /// THIS function runs the authoritative Core CL2 (`run_cl2`) against
    /// real stored state — S-ABR overlap decision + CLARA/RECALL
    /// attestation gates — then refills from Lambda's own records when
    /// Core says overlapped.
    pub async fn process_witness_request(
        &self,
        request: WitnessRequest,
    ) -> Result<WitnessResponse, LambdaError> {
        // Sender tier (YPX-010 §10.5): every wallet-state row for this sender is
        // keyed by (pk, k, proof_type) so the k=3 and k=0 tiers of one keypair
        // don't collide. A malformed wallet_id (rejected elsewhere) degrades to
        // Standard — its rows simply won't match a k=0 sender.
        let (sender_k, sender_pt) = axiom_core_logic::wallet_id::extract_security_level(
            &request.transaction.sender_wallet_id,
        )
        .unwrap_or((3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP));

        // Request-id idempotency — replay the prior response verbatim
        // when the same request_id arrives again. SDK fan-out (k=3)
        // and §27.5 / S-ABR relay can both deliver the same request to
        // this validator within a few seconds; without dedup each
        // arrival runs a fresh CL2/CL3 and emits a distinct cheque
        // (same protocol fields, different `created_at` →
        // different Dilithium sig), leaving the receiver with orphan
        // duplicate cheques after redeem.  Mac handoff 2026-06-05.
        if !request.request_id.is_empty() {
            let cache = self.witness_idempotency_cache.lock();
            if let Some((_, resp)) = cache.iter().find(|(k, _)| k == &request.request_id) {
                debug!("[WITNESS-IDEMPOTENT-HIT] request_id={} — replaying cached response",
                       request.request_id);
                return Ok(resp.clone());
            }
        }

        // YPX-002 P6 — simulated ingress latency. Zero-cost when
        // AXIOM_SIM_NET_DELAY_MAX_MS is unset. Placed before any work
        // so the sleep approximates "time for the request to cross
        // the WAN to this validator" rather than "time before we
        // happened to return".
        crate::sim_delay::maybe_sim_delay().await;

        // FACT chain auto-compress at ingress (v2.11.15 fix for
        // E_FACT_CHAIN_TOO_DEEP domination in beta12 soak). Core's
        // verify_fact_chain rejects > MAX_FACT_DEPTH; Lambda's outgoing
        // FACT compression is now handled by Core (returns compressed_fact_chain
        // in PublicOutputs). Lambda no longer compresses at ingress.

        let _t0 = std::time::Instant::now();
        let amount = request.transaction.amount;
        self.stats.witness_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Per-mode arrival counters — increment based on what the
        // requester ASKED for, regardless of whether this validator
        // can serve it. Lets the dashboard surface "incoming zkVM
        // requests on a DMAP-only node" so the operator notices.
        // proof_type encoding: 0 = ZKP/zkVM, 1 = DMAP, 2 = ARK.
        match request.transaction.proof_type {
            0 => { self.stats.witness_zkvm_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
            1 => { self.stats.witness_dmap_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
            _ => { /* unknown proof_type (ARK etc.) — not surfaced separately yet */ }
        }

        // Rate limit check: per-wallet PK, sliding window
        if self.rate_limit_per_minute > 0 {
            self.check_rate_limit(&request.transaction.client_pk)?;
        }

        // FACT chain depth check moved into Core (validation.rs, gated by
        // PublicInputs.max_fact_links — threaded through CoreClient).
        // Lambda MUST NEVER inspect `request.sender_fact_chain.links` — per
        // `feedback_layer_roles.md` only Core decides FACT chain validity.
        // Prior code here read `fc.links.len()` and rejected pre-AVM; that
        // was the layer violation we're closing. Same `is_heal && sender==
        // receiver` exemption is enforced by Core; reject reason on the wire
        // remains `E_FACT_CHAIN_TOO_DEEP`.

        // JFP §7: Frozen wallet enforcement. Query active freeze orders
        // from management_db. Lambda fast-rejects here; Core also checks
        // via PublicInputs.frozen_wallets for defense-in-depth.
        let frozen_wallets = self.get_frozen_wallets();
        if let Some(ref frozen) = frozen_wallets {
            if request.transaction.client_pk.len() == 32 {
                let mut sender_pk = [0u8; 32];
                sender_pk.copy_from_slice(&request.transaction.client_pk);
                if frozen.contains(&sender_pk) {
                    return Err(LambdaError::WalletFrozenJfp);
                }
            }
        }

        // AUDIT-FIX v2.11.13: Explicit oracle rejection — client gets clear signal.
        // Oracle claims are disabled by default (OracleConfig.enabled = false).
        // Returns CoreValidationFailed so the server layer can map to 503.
        //
        // AUDIT-FIX v2.11.14 (Phase 6 external audit): Oracle subsystem has 4 known gaps
        // that are INTENTIONALLY NOT FIXED because Oracle is disabled. These MUST be
        // resolved before enabling Oracle in production:
        //
        // PRE-ACTIVATION CHECKLIST (all must be done before setting enabled=true):
        //
        //   GAP-O1 (Critical): RESOLVED (v2.11.14). Oracle fields (payout_amount,
        //     credit_delta, platform_url) now hashed into cheque commitment in crypto.rs.
        //
        //   GAP-O2 (High): ZK-TLS verification — RESOLVED (v2.11.14).
        //     Real verifier: CBOR-encoded AxiomTlsProof with Notary Ed25519 signature,
        //     server name binding, credit data binding, transcript hash, freshness check.
        //     Remaining: populate TRUSTED_NOTARY_KEYS with production Notary PKs.
        //
        //   GAP-O3 (High): RESOLVED (v2.11.14). process_oracle_claim() wired into
        //     consensus pipeline. Binding/pool/reserve state held in ConsensusEngine.
        //
        //   GAP-O4 (Medium): RESOLVED (v2.11.14). oracle_claim encoded/decoded
        //     as CBOR sub-map at key 16 in tx_to_value/value_to_tx.
        //
        // Current protection: enabled=false gate below rejects ALL oracle claims.
        // This gate is the ONLY defense needed while Oracle is disabled.
        if request.transaction.oracle_claim.is_some() && !self.oracle_config.enabled {
            return Err(LambdaError::CoreValidationFailed(
                "oracle_disabled: Oracle claim processing is not enabled on this validator. \
                 See GAP-O1 through GAP-O4 — oracle subsystem requires pre-activation fixes.".into()
            ));
        }

        // ZK-TLS verification — if proof present, verify before calling Core.
        // AUDIT-FIX v2.11.14: Real verifier (was stub). Checks Notary Ed25519 signature,
        // server name binding, credit total binding, transcript hash, freshness.
        if let Some(ref claim) = request.transaction.oracle_claim {
            if let Some(ref proof_blob) = claim.zktls_proof {
                if let Err(e) = crate::oracle_zktls::verify_zktls_proof(
                    proof_blob,
                    &claim.platform_url,
                    claim.credit_total,
                ) {
                    warn!("Oracle ZK-TLS proof invalid for {}: {}", claim.platform_url, e);
                    return Err(LambdaError::CoreValidationFailed(
                        format!("Oracle ZK-TLS proof invalid: {}", e)
                    ));
                }
                info!("Oracle ZK-TLS proof verified for {}", claim.platform_url);
            }
            // No proof: Living Signature + stake is the trust anchor (GAP-O2 caveat).
        }

        // GAP-O3: Oracle binding/pool/reserve accounting.
        // Enforces 24h claim interval, platform binding immutability, daily pool caps,
        // and reserve exhaustion. Runs BEFORE Core witness production to fail fast.
        if let Some(ref claim) = request.transaction.oracle_claim {
            let oracle_claim = axiom_core_logic::oracle::OracleClaim {
                project_url: claim.platform_url.clone(),
                user_id: claim.user_id,
                username: claim.username.clone(),
                credit_total: claim.credit_total,
                credit_delta: claim.credit_delta,
                proof: claim.zktls_proof.clone().unwrap_or_default(),
                claimer_address: {
                    let mut addr = [0u8; 32];
                    let pk_bytes = &request.transaction.client_pk;
                    let copy_len = pk_bytes.len().min(32);
                    addr[..copy_len].copy_from_slice(&pk_bytes[..copy_len]);
                    addr
                },
                wallet_id: request.transaction.sender_wallet_id.clone(),
                claim_tick: request.transaction.epoch,
            };
            let mut bindings = self.oracle_bindings.lock();
            let mut pool = self.oracle_pool.lock();
            let mut reserve = self.oracle_reserve.lock();
            if let Err(e) = axiom_core_logic::oracle::process_oracle_claim(
                &oracle_claim, &mut bindings, &mut pool, &mut reserve,
            ) {
                warn!("Oracle claim rejected by binding/pool/reserve: {:?}", e);
                return Err(LambdaError::CoreValidationFailed(
                    format!("Oracle claim rejected: {:?}", e)
                ));
            }
            info!("Oracle binding/pool/reserve check passed for {} user_id={}",
                  claim.platform_url, claim.user_id);
        }

        // NOTE: txid is computed by Core, not Lambda. For debug logging,
        // use consumed_state_id prefix as transaction identifier.
        debug!("Processing witness request: consumed_state={} seq={}",
              hex::encode(&request.transaction.consumed_state_id[..8]),
              request.transaction.wallet_seq);
        
        // Process incoming hints (store new, drop known - per Yellow Paper 27.4)
        let new_hints = self.storage.process_incoming_hints(&request.validator_hints)?;
        if new_hints > 0 {
            debug!("Stored {} new validator hints from request", new_hints);
        }
        self.stats.hint_count.store(self.storage.hint_count() as u64, std::sync::atomic::Ordering::Relaxed);

        // ════════════════════════════════════════════════════════════════
        // YPX-007 — Proof-type observability (NOT routing).
        //
        // AXIOM protocol design (per AXIOM Origin, 2026-06-03): a validator MUST
        // process whatever proof_type the TX requests. ZKP-qualified vs
        // not is a VSP advertisement — it lets the SDK *prefer* faster
        // validators, but it must NEVER stop an un-advertised validator
        // from accepting and serving the request. Otherwise, when a TX
        // requires S-ABR overlap with prior witnesses and one of those
        // prior witnesses is not ZKP-qualified, the entire wallet wedges
        // (the next round can't satisfy floor(k/2)+1 overlap because the
        // old witness rejects). "No shortcut, no alternative" — see
        // [[feedback_no_proof_mode_shortcuts]].
        //
        // We still log when a non-qualified validator serves ZKP so the
        // operator can see "this round was slow because we had to do
        // ZKP work without acceleration".
        if request.transaction.required_k > 0 {
            let tx_proof_type = request.transaction.proof_type;
            if tx_proof_type == axiom_core_logic::wallet_id::PROOF_TYPE_ZKP {
                let qual = self.zkp_qualification.lock();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if !qual.is_valid(now) {
                    warn!("ZKP TX accepted on non-ZKP-qualified validator (YPX-007) — \
                           processing will be slow but MUST proceed for S-ABR continuity. \
                           proof_type={}, qualified={}, pk={}",
                          tx_proof_type, qual.zkp_qualified,
                          hex::encode(&request.transaction.client_pk[..8.min(request.transaction.client_pk.len())]));
                }
            }
            // proof_type == PROOF_TYPE_DMAP (1) or PROOF_TYPE_ARK (2) — same path.
        }

        // The Gateway ran only CL2_PREFILTER. The authoritative Core CL2
        // runs BELOW (Step 3, after the YPX-016 cache + early-reject gates).

        // CL1 execution proof — MANDATORY. No exceptions. No fallback.
        // Every client MUST run Core locally and attach a valid DMAP proof.
        // Without CL1, an attacker can submit malformed transactions that
        // waste validator resources, or worse, submit transactions from a
        // modified Core that bypasses validation rules.
        if request.cl1_execution_proof.is_empty() {
            return Err(LambdaError::CoreValidationFailed(
                "CL1: missing execution proof — client must run Core locally".into()
            ));
        }
        {
            let core = self.core.write().await;
            let proof = crate::core_client::ClientProof {
                execution_proof: request.cl1_execution_proof.clone(),
            };
            match core.validate_client_proof(&proof, None) {
                Ok(true) => debug!("CL1: client proof verified"),
                Ok(false) => {
                    return Err(LambdaError::CoreValidationFailed(
                        "CL1: proof validation returned false".into()
                    ));
                }
                Err(e) => {
                    return Err(LambdaError::CoreValidationFailed(format!("CL1: {}", e)));
                }
            }
        }

        // REPLAY-FIX (v2.11.12): Replay protection is enforced by Core.
        // Lambda passes stored state_id (not TX's consumed_state_id) to Core.
        // After first witness: stored state_id = produced_state_id.
        // Replay TX has consumed_state_id = old_state_id → Core rejects (InvalidStateId).
        // This prevents signature accumulation and DMAP proof compute waste.
        
        // Step 2: Get sender's wallet state
        let wallet_state = self.storage.get_wallet_state(&request.transaction.client_pk, sender_k, sender_pt)?;

        // YPX-018 — CLARA: NO storage write here.
        //
        // SECURITY HOTFIX (Phase 5e): the previous version called
        // storage.clara_roll_forward() BEFORE Core CL2 verified the
        // attestation. That mutated wallet state ahead of authentication,
        // creating a state-integrity bug: a forged attestation that fails
        // Core would still corrupt lambda.db.
        //
        // The correct order is:
        //   1. Pass the actual stored state + the clara_attestation to Core.
        //   2. Core CL2 verifies the attestation (signature, NBC trust anchor,
        //      eligibility against the actual stored state).
        //   3. ONLY after Core returns Accept, Lambda commits the roll-forward
        //      via storage.clara_roll_forward() (post-Core, fail-closed).
        //
        // The post-Core commit is wired below near where the witness response
        // is built, after finalize_transaction succeeds.
        //
        // Reference: YPX-018 §2.3, Yellow Paper §17.10.14, §26.17.10.

        // Detect genesis transaction (no prev_receipts)
        let is_genesis_tx = request.prev_receipts.is_empty();
        let _is_genesis_claim = request.transaction.is_genesis_claim();
        
        // ════════════════════════════════════════════════════════════════
        // Double-spend prevention (White Paper §4.11.1):
        //
        // "Did I already witness the consumption of this parent state?"
        //
        // consumed_state_id is marked as consumed ONLY after ACK (fee paid).
        // Before ACK, the TX is PENDING — client can retry freely.
        // After ACK, the state is committed — replay is double-spend.
        //
        // This check catches the overlapped validator case: S-ABR forces
        // k-1 validators from the previous TX to participate in the next.
        // Those validators have the consumed state marked from the ACK.
        // ════════════════════════════════════════════════════════════════
        if !is_genesis_tx
            && self.storage.is_state_consumed(&request.transaction.consumed_state_id)? {
                self.stats.double_spend_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!("DOUBLE-SPEND REJECTED (White Paper §4.11.1): \
                       consumed_state_id={} already ACK'd in prior TX. pk={}",
                      hex::encode(&request.transaction.consumed_state_id[..8]),
                      hex::encode(&request.transaction.client_pk[..8]));
                return Err(LambdaError::InvalidRequest(
                    "E_STATE_CONSUMED: state_id was consumed and ACK'd in a prior transaction".to_string()
                ));
            }
        
        // (YPX-007 routing was moved to the top of process_witness_request,
        // before CL1, so unqualified validators early-reject ZKP TXs.)

        // DEBUG: Log state lookup result
        if let Some(ref state) = wallet_state {
            debug!("Wallet state lookup: pk={} state_id={} balance={} seq={}",
                  hex::encode(&request.transaction.client_pk[..8]),
                  hex::encode(&state.state_id[..8]),
                  state.balance,
                  state.wallet_seq);
        } else {
            debug!("Wallet state lookup: pk={} NOT FOUND (genesis)",
                  hex::encode(&request.transaction.client_pk[..8]));
        }
        debug!("Transaction consumed_state_id: {}", 
              hex::encode(&request.transaction.consumed_state_id[..8]));
        
        // Carry auth_hash from stored wallet state (GAP-A fix: stolen-key protection).
        // auth_hash is set via the dedicated set_auth_hash API (§4.5), not from
        // witness requests. Validators store it independently.
        let stored_auth_hash = self.storage.get_wallet_state(&request.transaction.client_pk, sender_k, sender_pt)
            .ok().flatten().and_then(|ws| ws.auth_hash);

        // REPLAY-FIX (v2.11.12) + YPX-015 fresh validator fix:
        // Overlapped validators use stored state_id (replay protection —
        // stored advances after witness, old consumed mismatches).
        // Fresh validators use TX's consumed_state_id because their stored
        // state is stale (never witnessed this wallet's recent TXs). They
        // trust the overlap validators' proof. Core step 6 still verifies
        // consumed == prev_receipt.produced_state_id.
        // This also self-heals poisoned validators: after serving as fresh,
        // their stored state advances to the current chain.
        //
        // `wire_overlapped` is a pure MEMBERSHIP test on the wire data (is my
        // pk among the prev_receipt witnesses?) used ONLY to pick which
        // state_id view Core sees. It is NOT the overlap decision — Core
        // re-derives the same membership inside CL2 from the same
        // prev_receipts and returns the authoritative `is_overlapped`, which
        // is what drives the S-ABR refill below. The old storage-based
        // detection (`is_overlapped_validator`'s genesis/heal self-knowledge)
        // is GONE: genesis is CL2's empty-prev_receipts first-TX path, and a
        // dead-overlap partial is HAL's job.
        let my_ed25519_pk = self.public_key.as_bytes();
        let wire_overlapped = request.prev_receipts.iter()
            .flat_map(|r| r.witness_sigs.iter())
            .any(|ws| ws.validator_pk == my_ed25519_pk);
        let core_state_id = if wire_overlapped {
            wallet_state
                .as_ref()
                .map(|ws| ws.state_id)
                .unwrap_or(request.transaction.consumed_state_id)
        } else {
            request.transaction.consumed_state_id
        };

        // Log potential replay: stored state_id differs from TX's consumed_state_id.
        // Core will reject this TX (E_SABR_HASH_MISMATCH or InvalidStateId).
        // Operators can monitor these at INFO level to detect replay spam.
        // YPX-016: Witness response cache — partial witness recovery.
        // If state_id mismatches (validator poisoned from partial witness), check if
        // the exact same TX was witnessed before. If so, verify via Core's fact_signature
        // (Dilithium) then return the cached response. Core confirms it previously
        // endorsed this state transition — Lambda cannot forge this.
        if core_state_id != request.transaction.consumed_state_id {
            let tx_hash = *blake3::hash(
                &serde_json::to_vec(&request.transaction).unwrap_or_default()
            ).as_bytes();
            if let Ok(Some(cached_response)) = self.storage.get_witness_cache(
                &request.transaction.client_pk,
                sender_k, sender_pt,
                &tx_hash,
                &request.transaction.consumed_state_id,
                request.transaction.wallet_seq,
            ) {
                // Deserialize the cached response (CBOR — see store sites
                // at lines 2936 / 3295 for matching write encoding). JSON
                // was previously used but coerces every Dilithium pk and
                // signature byte field to integer-array on round-trip,
                // which silently corrupts witness verification on cache
                // hits. CLAUDE.md §13: byte fields don't survive JSON.
                if let Ok(resp) = ciborium::de::from_reader::<WitnessResponse, _>(&cached_response[..]) {
                    // Extract fact_signature and produced_state_id for Core verification
                    let fact_sig = resp.witness_signature.as_ref()
                        .and_then(|ws| ws.fact_signature.as_ref());
                    let produced_sid = resp.produced_state_id.as_ref()
                        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());

                    if let (Some(fact_sig), Some(produced_sid)) = (fact_sig, produced_sid) {
                        // NOTE: compute_txid is a deterministic hash (BLAKE3), not a
                        // validation authority decision. Shared utility between Core and Lambda.
                        let txid = axiom_core_logic::compute::compute_txid(&request.transaction);

                        // Core verification: verify the Dilithium fact_signature proves
                        // Core previously endorsed: consumed → produced for this TX.
                        // Lambda cannot forge this — Dilithium key is Core's.
                        // A2: cache rebind passes sender_anchor=None for now.
                        // Redeem TXs whose commitment was bound to sender_anchor
                        // will miss the cache here and fall through to a fresh
                        // witness production path. That's a perf cost, not a
                        // correctness issue. Stage 3 will extend the cache
                        // schema to carry sender_anchor for redeem TXs.
                        if axiom_core_logic::fact::verify_cached_fact_signature(
                            &self.dilithium_pk,
                            &txid,
                            &request.transaction.consumed_state_id,
                            &produced_sid,
                            request.transaction.amount,
                            None,
                            // Dev-class flag — re-derive from
                            // sender_wallet_id to match what Core CL3
                            // bound at sign time.
                            axiom_core_logic::wallet_id::is_dev_wallet(
                                &request.transaction.sender_wallet_id,
                            ),
                            &[], // send-path cache — send links never inherit (§1.5.1a)
                            // §1.5.4: a burn is a send to BURN_ADDRESS; bind its target
                            // so a burn TX's cached sig matches what Core CL3 signed. A
                            // mismatch here is a cache MISS (falls through to fresh
                            // production), never a wrong accept.
                            if request.transaction.receiver_wallet_id
                                == axiom_core_logic::types::BURN_ADDRESS {
                                request.transaction.burn_target_tx_id.as_ref()
                            } else {
                                None
                            },
                            fact_sig,
                        ).is_ok() {
                            info!("YPX-016: Cache VERIFIED by Core (fact_signature valid) pk={} seq={}",
                                  hex::encode(&request.transaction.client_pk[..8]),
                                  request.transaction.wallet_seq);
                            self.stats.witness_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return Ok(resp);
                        } else {
                            warn!("YPX-016: Cache fact_signature INVALID — tampered or wrong key. Rejecting cache.");
                        }
                    } else {
                        warn!("YPX-016: Cache missing fact_signature or produced_state_id — cannot verify. Rejecting cache.");
                    }
                }
            }
        }

        // YPX-015 §2.2: Early rejection when state_id mismatch is detected
        // AND there are no overlap signatures. If overlap signatures are present,
        // this may be a fresh S-ABR validator — Core needs to verify the overlap
        // chain, so we must NOT short-circuit.
        // Only safe to early-reject when: no overlapped_signatures AND state mismatch.
        // That means this is a replay or completely stale TX with no S-ABR context.
        if core_state_id != request.transaction.consumed_state_id
            && request.overlapped_signatures.is_empty()
        {
            // [DRIFT-DIAG] Downgraded from eprintln to debug! 2026-05-15
            // after the s2r22794 soak showed the class is structural
            // (env-teardown noise + clean-start "no record" condition),
            // not a regression.  Set RUST_LOG=axiom_lambda::consensus=debug
            // to re-enable per-event traces if hunting a fresh
            // hypothesis.
            debug!(
                "[DRIFT-DIAG] EARLY-REJECT pk[..8]={} requested_csid={} stored_csid={} overlap_sigs={} prev_receipts={}",
                hex::encode(&request.transaction.client_pk[..8]),
                hex::encode(&request.transaction.consumed_state_id[..8]),
                hex::encode(&core_state_id[..8]),
                request.overlapped_signatures.len(),
                request.prev_receipts.len(),
            );
            info!("EARLY REJECT: consumed_state_id={} != stored state_id={}, no overlap sigs. pk={}",
                  hex::encode(&request.transaction.consumed_state_id[..8]),
                  hex::encode(&core_state_id[..8]),
                  hex::encode(&request.transaction.client_pk[..8]));
            return Err(LambdaError::CoreError(
                format!("S-ABR state chain mismatch: requested csid={} stored={}",
                    hex::encode(&request.transaction.consumed_state_id[..8]),
                    hex::encode(&core_state_id[..8]))
            ));
        }

        // Identity binding: pass stored wallet_id to Core so it can enforce
        // sender_wallet_id matches the canonical identity for this public key.
        let stored_wallet_id = self.storage.get_wallet_state(&request.transaction.client_pk, sender_k, sender_pt)
            .ok().flatten().and_then(|ws| ws.wallet_id.clone());

        // ════════════════════════════════════════════════════════════════
        // Step 3: Core CL2 — THE authoritative S-ABR + attestation gate.
        //
        // S-ABR's design is don't-trust-Lambda: the wallet carries
        // prev_receipts, CORE decides the overlap from them, Core strips
        // balance/seq for overlapped validators, Lambda ONLY refills from
        // its own TransactionRecord, and Core re-verifies the refill at CL3
        // (SABRHashMismatch). Lambda gets no overlap vote — the old
        // `validate_sabr`/`is_overlapped_validator` stand-ins are DELETED.
        //
        // The CL2 state view is built from DECLARED values: Core's
        // `verify_state_anchored` re-derives the k-signed
        // `prev_receipt.state_hash` from them, so a lying client is
        // rejected before any signature is minted. state_id follows the
        // REPLAY-FIX rule (`core_state_id` above); group_members stays None
        // here — group enforcement is CL3's job via the refilled record
        // (fresh validators lack the record, and Core correctly skips group
        // validation for them).
        //
        // CL2 also verifies, IN CORE, what no Lambda path ever verified
        // before this rewire: the RECALL attestation (Nabla sig + txid
        // binding + over-reclaim equality — forged/attestation-less recalls
        // die HERE, at witness time) and the CLARA attestation (the
        // post-Core roll-forward commit below finally matches its comment).
        // ════════════════════════════════════════════════════════════════
        let cl2_state = Some(WalletState {
            public_key: request.transaction.client_pk.clone(),
            balance: request.claimed_balance_for_sabr,
            wallet_seq: request.transaction.wallet_seq.saturating_sub(1),
            state_id: core_state_id,
            auth_hash: stored_auth_hash.clone(),
            hibernation_until: request.claimed_hibernation_until,
            wallet_id: stored_wallet_id.clone(),
            group_members: None,
        });
        let cl2_outputs = {
            let core = self.core.write().await;
            core.run_cl2(
                &request,
                cl2_state.as_ref(),
                frozen_wallets.clone(),
                Some(self.public_key.as_bytes().to_vec()),
                Some(self.vbc_bundle()),
            )?
        };
        // Core's decision — NOT Lambda's. `wire_overlapped` above only chose
        // the state_id view; this drives the refill and everything after.
        let we_are_overlapped = cl2_outputs.is_overlapped == Some(true);

        // S-ABR refill — Lambda's ONLY S-ABR role.
        //
        // Three cases, matching the deleted validate_sabr's behavior exactly:
        //
        //  1. FIRST TX / GENESIS (`prev_receipts` empty). AXIOM Origin: "Genesis =
        //     CL2's empty-prev_receipts first-tx path." Core CL2 returns
        //     is_overlapped=Some(true) here as "first TX, all validators
        //     proceed" — NOT "I hold a prior record." A genesis CLAIM credits
        //     from the pool and has no prior TransactionRecord by definition,
        //     so `lookup_previous_tx_record` MISSES — that is normal, not an
        //     error, and we use the declared values (Core's genesis path
        //     validated the credit; the balance is bound into the
        //     genesis_state_id). A genesis-FUNDED send (a stored genesis
        //     state exists) refills from the genesis pseudo-record. So: try
        //     the lookup, fall back to declared on miss. This is the ONE place
        //     a lookup miss is not fail-stop, because "no prior record" is the
        //     defining property of a first TX.
        //  2. OVERLAPPED with a real prior TX (`prev_receipts` non-empty, Core
        //     said overlapped). Refill strictly from our record; the client's
        //     claimed_balance_for_sabr is IGNORED. A miss here IS fail-stop —
        //     "can crash, must not lie" (data-loss recovery is HAL's job).
        //  3. FRESH (Core said not overlapped). Declared values, which CL2
        //     just anchored to the k-signed prev_receipt.state_hash.
        // Genesis state_id is per-tier (§10.5) — derive the sender's tier from its
        // wallet_id so the genesis-match check computes the right tier's genesis.
        // A malformed wallet_id (rejected elsewhere) degrades safely to Standard:
        // its genesis simply won't match a k=0 consumed_state_id → lookup misses.
        let (gen_k, gen_pt) = axiom_core_logic::wallet_id::extract_security_level(
            &request.transaction.sender_wallet_id,
        )
        .unwrap_or((3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP));

        let sabr_result = if request.prev_receipts.is_empty() {
            match self.lookup_previous_tx_record(
                &request.transaction.consumed_state_id,
                &request.transaction.client_pk,
                gen_k, gen_pt,
            ) {
                Ok(record) => {
                    debug!(
                        "S-ABR First-TX (Core CL2): genesis pseudo-record refill (balance={}, seq={})",
                        record.balance_after, record.wallet_seq_after + 1
                    );
                    SABRResult::Refilled {
                        balance: record.balance_after,
                        wallet_seq: record.wallet_seq_after + 1,
                        group_members: record.group_members_after.clone(),
                    }
                }
                Err(_) => {
                    // Genesis CLAIM (or any first TX with no stored genesis) —
                    // declared values; Core's genesis-claim path caps + credits.
                    debug!(
                        "S-ABR First-TX (Core CL2): genesis claim, no prior record — declared balance={}",
                        request.claimed_balance_for_sabr
                    );
                    SABRResult::Trusted {
                        balance: request.claimed_balance_for_sabr,
                        wallet_seq: request.transaction.wallet_seq,
                        group_members: None,
                    }
                }
            }
        } else if we_are_overlapped {
            let record = self.lookup_previous_tx_record(
                &request.transaction.consumed_state_id,
                &request.transaction.client_pk,
                gen_k, gen_pt,
            )?;
            debug!(
                "S-ABR Overlapped (Core CL2): refilling from RECORD (balance={}, seq={}, has_gm={}), IGNORING claimed_balance_for_sabr={}",
                record.balance_after,
                record.wallet_seq_after + 1,
                record.group_members_after.is_some(),
                request.claimed_balance_for_sabr
            );
            SABRResult::Refilled {
                balance: record.balance_after,
                wallet_seq: record.wallet_seq_after + 1,
                group_members: record.group_members_after.clone(),
            }
        } else {
            debug!(
                "S-ABR New (Core CL2): overlap verified in Core, using claimed_balance={}",
                request.claimed_balance_for_sabr
            );
            SABRResult::Trusted {
                balance: request.claimed_balance_for_sabr,
                wallet_seq: request.transaction.wallet_seq,
                group_members: None,
            }
        };

        // ================================================================
        // SCAR PASSCODE ENFORCEMENT (YPX-001 §1.5) — overlapped-with-a-real-
        // -prior-TX path only, exactly as before the CL2 rewire (the deleted
        // validate_sabr_overlapped ran it; validate_sabr_new / genesis did
        // NOT). `!prev_receipts.is_empty()` excludes the first-TX / genesis
        // path where Core also returns is_overlapped=Some(true) but there is
        // no prior chain to scar. Lambda business logic (passcode storage +
        // receiver consent), NOT crypto — so it stays in Lambda.
        // YPX-001 §1.6: client carries provenance. Lambda NEVER stores or
        // falls back to a stored FACT chain. The client's chain is
        // authoritative. If the client doesn't send one, there's no chain
        // to check.
        // ================================================================
        let mut scar_consent_voucher_out: Option<crate::types::ScarConsentVoucher> = None;
        if we_are_overlapped && !request.prev_receipts.is_empty() {
            if let Some(ref chain) = request.sender_fact_chain {
                let scar_count = scar_consent_gate_count(
                    chain,
                    &request.transaction,
                    request.clara_attestation.is_some(),
                );
                if scar_count > 0 {
                    let txid = self.compute_txid(&request.transaction);

                    // Under S-ABR EVERY prior witness is "overlapped", but the
                    // passcode is stored only at the validator that generated
                    // it. A round therefore completes via the consent VOUCHER:
                    // the generating validator verifies the passcode (hop 1,
                    // SDK pins it first) and signs a voucher over the txid;
                    // the later hops verify that signature against the
                    // prev-receipt witness set this request already carries
                    // and skip the gate. A bare passcode with neither a local
                    // entry nor a voucher NEVER passes (fabrication-proof).
                    let voucher_ok = request.scar_consent_voucher.as_ref()
                        .map(|v| verify_scar_consent_voucher(v, &txid, &request.prev_receipts))
                        .unwrap_or(false);
                    if voucher_ok {
                        info!(
                            "FACT scar consent voucher verified for txid={} (issuer={}) — gate skipped",
                            hex::encode(&txid[..8]),
                            hex::encode(&request.scar_consent_voucher.as_ref().unwrap().validator_id[..8]),
                        );
                    } else
                    // Check if sender provided a valid passcode (second attempt)
                    if let Some(provided_passcode) = request.transaction.scar_passcode {
                        // ── TTL + attempt cap (2026-07-12 hardening) ──
                        // A stored passcode expires after SCAR_PASSCODE_TTL_SECS
                        // and dies after MAX_SCAR_PASSCODE_ATTEMPTS wrong tries —
                        // either way the entry is DELETED and the gate falls
                        // through to the no-passcode arm below, which issues a
                        // FRESH passcode + re-notifies the receiver. A
                        // brute-forcing sender resets their own progress and
                        // floods the receiver with evidence; the honest late
                        // sender just repeats the consent hand-off.
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64).unwrap_or(0);
                        let expired_or_exhausted = match self.storage.get_scar_passcode_meta(&txid)? {
                            Some((_, created_at, attempts)) =>
                                now_secs.saturating_sub(created_at) > SCAR_PASSCODE_TTL_SECS
                                    || attempts >= MAX_SCAR_PASSCODE_ATTEMPTS,
                            None => false,
                        };
                        if expired_or_exhausted {
                            self.storage.remove_scar_passcode(&txid)?;
                        }
                        match self.storage.get_scar_passcode(&txid)? {
                            Some(stored_passcode) if stored_passcode == provided_passcode => {
                                // Passcode matches — receiver consented. Proceed,
                                // and issue the voucher the SDK carries to the
                                // round's remaining (entry-less) overlapped hops.
                                info!("FACT scar passcode verified for txid={}", hex::encode(&txid[..8]));
                                self.storage.remove_scar_passcode(&txid)?;
                                let payload =
                                    axiom_core_logic::compute::compute_scar_consent_voucher_payload(&txid);
                                scar_consent_voucher_out = Some(crate::types::ScarConsentVoucher {
                                    txid,
                                    validator_id: self.validator_id(),
                                    signature: self.signing_key.sign(&payload).to_bytes().to_vec(),
                                });
                            }
                            Some(_) => {
                                let n = self.storage.bump_scar_passcode_attempts(&txid)?;
                                return Err(LambdaError::InvalidScarPasscode(
                                    format!("Wrong passcode for txid={} (attempt {}/{})",
                                            hex::encode(&txid[..8]), n, MAX_SCAR_PASSCODE_ATTEMPTS)
                                ));
                            }
                            None if expired_or_exhausted => {
                                // Deleted above — fall through semantics: issue a
                                // FRESH pause below is not reachable from this arm
                                // (tx carries a passcode), so reject with the
                                // regeneration hint; the sender retries WITHOUT a
                                // passcode → fresh code + fresh notification.
                                return Err(LambdaError::InvalidScarPasscode(
                                    format!("Passcode for txid={} expired or attempt-capped — \
                                             a fresh send will re-pause and re-notify the receiver",
                                            hex::encode(&txid[..8]))
                                ));
                            }
                            None => {
                                return Err(LambdaError::InvalidScarPasscode(
                                    format!("No pending scar passcode for txid={} at this validator — \
                                             re-initiate through the validator that notified the receiver",
                                            hex::encode(&txid[..8]))
                                ));
                            }
                        }
                    } else {
                        // First attempt — generate passcode and notify receiver
                        let passcode = {
                            use std::time::{SystemTime, UNIX_EPOCH};
                            let seed = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_nanos();
                            let mut h = blake3::Hasher::new();
                            h.update(&(seed as u64).to_le_bytes());
                            h.update(&txid);
                            let hash = h.finalize();
                            let raw = u32::from_le_bytes([hash.as_bytes()[0], hash.as_bytes()[1],
                                                         hash.as_bytes()[2], hash.as_bytes()[3]]);
                            100_000 + (raw % 900_000) // 6-digit: 100000..999999
                        };

                        self.storage.store_scar_passcode(&txid, &request.transaction.client_pk, passcode)?;
                        info!("FACT scar detected: txid={}, {} scars, passcode={}",
                            hex::encode(&txid[..8]), scar_count, passcode);

                        return Err(LambdaError::FactScarDetected {
                            passcode,
                            txid,
                            sender_wallet_id: request.transaction.sender_wallet_id.clone(),
                            receiver_wallet_id: request.transaction.receiver_wallet_id.clone(),
                            amount: request.transaction.amount,
                            scar_count,
                        });
                    }
                }
            }
        }

        debug!("S-ABR result: balance={}, seq={}", sabr_result.balance(), sabr_result.wallet_seq());

        // Create wallet state from S-ABR result for downstream processing
        //
        // CRITICAL FIX (v2.10.17): Always use sabr_result.balance() for the balance.
        //
        // V1/V2 (non-finalize) do NOT update stored WalletState — only V3 (finalize)
        // calls set_wallet_state(). This means V1/V2's stored balance is STALE after
        // the first transaction. Using wallet_state.balance here caused V1/V2 to compute
        // a different produced_state_id than V3, making subsequent S-ABR lookups fail.
        //
        // sabr_result.balance() comes from TransactionRecord, which ALL validators
        // (V1, V2, V3) store consistently during witness. This is the correct source.
        //
        // For group_members: ONLY use S-ABR record (post-deduction from previous TX).
        // DO NOT fall back to stored wallet state — it may be stale from a prior transaction
        // (e.g., genesis group_members summing to 1M while S-ABR balance is 700k post-withdrawal).
        // This is the same fix pattern as v2.10.17's balance fix: S-ABR TransactionRecord is
        // the ONLY authoritative source. Non-overlapped validators that lack a TransactionRecord
        // will have group_members=None, causing Core to skip group validation — which is correct
        // because overlapped validators handle group enforcement via their authoritative records.
        let stored_group_members = sabr_result.group_members().cloned();

        // Always use S-ABR balance — it comes from TransactionRecord,
        // which is consistent across all validators (V1, V2, V3).
        let effective_balance = sabr_result.balance();

        let wallet_state_ref = Some(WalletState {
            public_key: request.transaction.client_pk.clone(),
            balance: effective_balance,
            wallet_seq: sabr_result.wallet_seq().saturating_sub(1),
            state_id: core_state_id,
            auth_hash: stored_auth_hash,
            // YPX-020: use the CLIENT-DECLARED hibernation_until (not stored) so
            // Core's §15 re-derives the prior state_hash with its real value AND
            // the binary gate sees the flag. The declared value is NOT trusted
            // blindly — `verify_state_anchored` rejects unless it re-derives to the
            // k-signed `prev_receipt.state_hash`, so a wrong value (e.g. 0 to dodge
            // the gate) fails the hash. REQUIRED for the overlap-relaxed HAL
            // completion: it reaches FRESH validators that never stored the
            // re-anchor's produced state, so `wallet_state` here is stale (0) and
            // §15 would wrongly reject. Mirrors `claimed_balance_for_sabr`.
            hibernation_until: request.claimed_hibernation_until,
            wallet_id: stored_wallet_id,
            group_members: stored_group_members,
        });

        // [PRODUCED-INPUTS DIAG] — emitted by EVERY validator before
        // Core CL3 runs. `produced_state_id` is BLAKE3 over (pk,
        // new_balance, wallet_seq, consumed_state_id, nonce) at
        // `crypto::compute_produced_state_id`. If two validators in the
        // same k-round print different `bal_in` / `seq_in` /
        // `consumed[..8]`, they will compute different
        // `produced_state_id` and their `fact_signature`s will sign
        // different commitments → finalizer's `build_fact_link` rejects
        // them with `FactInsufficientWitnesses`. Join across the 10
        // penguin lambda.logs by `txid[..8]`. See task #143 +
        // docs/AXIOM_HANDOFF_FactConfRace.md "UPDATE 2026-06-04".
        {
            let vid = hex::encode(&self.validator_id[..4]);
            // Join across validators by `consumed[..8]+amount` — the
            // SDK ships the same (consumed_state_id, amount) to every
            // validator in a k-round, so it's a deterministic group key.
            // `request.commitment_hash` is what the SDK signed for this
            // round; if validators see it, even better — use as primary
            // join key.
            let commitment_short = request.commitment_hash.as_ref()
                .map(|c| hex::encode(&c[..c.len().min(8)]))
                .unwrap_or_else(|| "NO-COMMITMENT".to_string());
            eprintln!(
                "[PRODUCED-INPUTS DIAG] vid={} commit={} pk[..8]={} bal_in={} seq_in={} consumed[..8]={} core_state_id[..8]={} sabr_balance={} sabr_seq={} amount={} is_genesis={}",
                vid,
                commitment_short,
                hex::encode(&request.transaction.client_pk[..request.transaction.client_pk.len().min(8)]),
                effective_balance,
                sabr_result.wallet_seq().saturating_sub(1),
                hex::encode(&request.transaction.consumed_state_id[..8]),
                hex::encode(&core_state_id[..8]),
                sabr_result.balance(),
                sabr_result.wallet_seq(),
                request.transaction.amount,
                request.transaction.is_genesis_claim(),
            );
        }

        debug!("CORE INPUT DEBUG: consumed_state_id={}, balance={}, seq={}",
              hex::encode(&request.transaction.consumed_state_id[..8]),
              sabr_result.balance(),
              sabr_result.wallet_seq().saturating_sub(1));
        
        // Step 4: Sign as witness
        let mut our_sig = self.sign_witness(&request.transaction, request.commitment_hash.as_deref())?;
        
        // Step 5: Collect all signatures
        let mut all_sigs = request.overlapped_signatures.clone();
        all_sigs.push(our_sig.clone());
        
        // Debug: dump fact_signature status of all sigs
        for (i, sig) in all_sigs.iter().enumerate() {
            debug!("all_sigs[{}] vid={} fact_sig={}",
                     i, hex::encode(&sig.validator_id[..4]),
                     if sig.fact_signature.is_some() { "PRESENT" } else { "NONE" });
        }
        
        // Step 6: Check if k reached (variable per YPX-007)
        let prev_receipts = self.collect_prev_receipts(&request).await?;
        let k = effective_k(&request.transaction);

        if all_sigs.len() >= k {
            // We have enough witnesses - produce final receipt via Core (CL3)
            // Use timeout to prevent infinite hang on Core CL3
            let resolved_finalize_audit = self.resolve_audit_confirmation(&request.audit_confirmation);
            let resolved_finalize_pulse = self.resolve_pulse_audit();
            // UMP-safe call: pass the envelope by reference;
            // `finalize_transaction` sources every wire field from it.
            // The only non-envelope args are the resolved audit values
            // (Lambda-side gating applied by `resolve_*`).
            let finalize_future = self.finalize_transaction(
                &request,
                wallet_state_ref.as_ref(),
                all_sigs.clone(),
                resolved_finalize_audit,
                resolved_finalize_pulse,
            );
            // Audit-fix v2.11.15-beta6: bumped from 8s → 30s.
            //
            // The 8s budget pre-fix was a hard cut over the *combined*
            // (queue-wait + compute) cost of `finalize_transaction`. Under
            // soak load with many concurrent witness requests serializing
            // through the single Core mutex (`ConsensusEngine::core`), the
            // queue wait alone could exceed 8s during chaos bursts, causing
            // valid transactions to surface as `CoreError("timed out after
            // 8 seconds")` even though their actual compute completed in
            // <500ms once they reached the head of the queue. That matched
            // the soak failures observed in v2.11.15-beta5 audit pass #2.
            //
            // 30s aligns with the YPX-015 ANTIE backpressure threshold
            // (`queue × avg_witness_ms > 30s` ⇒ E_VALIDATOR_BUSY at the
            // gateway). With both numbers set to 30s the gateway's reject
            // and the consensus engine's hard cut share the same SLO
            // ceiling: any TX that gets past ANTIE has at least the full
            // backpressure budget to complete inside Lambda. The proper
            // structural fix is per-wallet sharding of the Core mutex
            // (audit pass #2 finding 1) — that is in the deferred queue,
            // tracked separately. Until then, this prevents head-of-line
            // blocking from manifesting as protocol errors.
            //
            // The 5s "produce_witness took ..." critical log below is
            // separately bumped to 15s — that one measures pure compute
            // *after* the lock is acquired, where 5s really is a problem
            // worth shouting about, but 15s gives DMAP+CL3 honest cost
            // headroom on busy machines.
            let (receipt, updated_fact_chain, exec_proof_bytes, zkp_nonce, cheque_proof_type,
                 pulse_audit_request, pulse_nonce_challenge, pulse_proof_data, pulse_audit_failed,
                 dmap_input_hash, dmap_output_hash) = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                finalize_future,
            ).await {
                Ok(result) => result?,
                Err(_) => {
                    error!("TIMEOUT: finalize_transaction took >30s — returning error instead of hanging");
                    return Err(LambdaError::CoreError(
                        "finalize_transaction timed out after 30 seconds".to_string()
                    ));
                }
            };

            // YPX-018 Phase 5e — POST-CORE CLARA roll-forward commit (fail-closed).
            //
            // Core CL2 just verified the attestation cryptographically and the
            // eligibility against this validator's stored state. Now Lambda
            // commits the storage update — the only safe order. If the commit
            // fails for any reason, fail the whole witness request: we cannot
            // emit a witness signature for a TX whose state didn't actually
            // advance locally.
            if let Some(ref clara) = request.clara_attestation {
                if clara.wallet_pk.as_slice() == request.transaction.client_pk.as_slice() {
                    let applied = self.storage.clara_roll_forward(
                        &request.transaction.client_pk,
                        sender_k, sender_pt,
                        &clara.healed_from_state_id,
                        &clara.healed_to_state_id,
                        clara.healed_at_seq,
                        clara.healed_balance, // Phase 5f Finding 4
                        &clara.garbage_state_ids,
                    )?;
                    if !applied {
                        // This validator's stored state is not in the garbage
                        // list — it was never poisoned by the partial, or it
                        // already rolled forward from a prior TX. Proceed with
                        // normal witness production. The attestation was for
                        // the poisoned validators; clean validators just skip.
                        debug!(
                            "CLARA: roll-forward not applicable (validator not poisoned) pk={}",
                            hex::encode(&request.transaction.client_pk[..8.min(request.transaction.client_pk.len())]),
                        );
                    }
                    info!(
                        "CLARA: post-Core roll-forward applied pk={} → {}",
                        hex::encode(&request.transaction.client_pk[..8.min(request.transaction.client_pk.len())]),
                        hex::encode(&clara.healed_to_state_id[..8]),
                    );
                }
            }

            // YPX-009 §4: Store Pulse audit request from Core for next TX
            self.handle_pulse_audit_request(pulse_audit_request.clone());

            // YPX-009 §5: Forward PulseProof to Nabla for gossip broadcast.
            // Fire-and-forget: Lambda signs the proof, Nabla gossips it to peers.
            if let Some(ref ppd) = pulse_proof_data {
                let validator_pk = *self.public_key.as_bytes();
                let epoch = ppd.epoch;
                let full_accumulator = ppd.full_accumulator;
                let audit_hash = ppd.audit_hash;
                let entry_count = ppd.entry_count;
                let sample_size = ppd.sample_size;
                let argon2id_per_sec = ppd.argon2id_per_sec;

                // Sign the pulse proof payload (same domain tag as Nabla verification)
                let sign_payload = {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(b"AXIOM_PULSE_PROOF");
                    hasher.update(&validator_pk);
                    hasher.update(&epoch.to_le_bytes());
                    hasher.update(&full_accumulator);
                    hasher.update(&audit_hash);
                    *hasher.finalize().as_bytes()
                };
                use ed25519_dalek::Signer;
                let signature = self.signing_key.sign(&sign_payload).to_bytes().to_vec();

                // Forward to Nabla over the TCP-CBOR `WireMessage` wire
                // (CLAUDE.md §8, Rule 2). Phase 3c gated `POST /pulse-proof`
                // to `410 Gone`; this now frames a length-prefixed CBOR
                // `WireMessage::PulseProofRequest` on the Nabla TCP port
                // (HTTP 6226 + 1074 = 7300, node alpha). Fire-and-forget —
                // the response is logged but not acted on.
                let req = axiom_core_logic::wire_client::PulseProofRequest {
                    validator_pk,
                    epoch,
                    full_accumulator,
                    entry_count,
                    sample_size,
                    audit_hash,
                    argon2id_per_sec,
                    signature,
                };
                let envelope = axiom_core_logic::nabla_wire::WireMessage::PulseProofRequest(req);
                let mut cbor_req = Vec::new();
                match ciborium::ser::into_writer(&envelope, &mut cbor_req) {
                    Ok(()) => {
                        let mut framed = Vec::with_capacity(4 + cbor_req.len());
                        framed.extend_from_slice(&(cbor_req.len() as u32).to_be_bytes());
                        framed.extend_from_slice(&cbor_req);
                        tokio::spawn(async move {
                            use tokio::io::{AsyncWriteExt, AsyncReadExt};
                            // TCP port = HTTP port + 1074 (HTTP 6226 → TCP 7300).
                            let nabla_addr = "127.0.0.1:7300";
                            if let Ok(mut stream) = tokio::net::TcpStream::connect(nabla_addr).await {
                                let _ = stream.write_all(&framed).await;
                                // Drain the length-prefixed response (best
                                // effort — fire-and-forget).
                                let mut len_buf = [0u8; 4];
                                let _ = tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    stream.read_exact(&mut len_buf),
                                ).await;
                                tracing::debug!("YPX-009: PulseProof forwarded to Nabla via TCP (epoch={})", epoch);
                            } else {
                                tracing::warn!("YPX-009: Could not connect to Nabla at {} for PulseProof", nabla_addr);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("YPX-009: CBOR encode PulseProofRequest failed: {}", e);
                    }
                }
            }

            // finalize_transaction patches fact_signature, receipt_signature,
            // execution_proof, and proof_type on witness_sigs inside the
            // receipt, but our_sig (used in the response's witness_signature
            // field) is the original without those fields. Mirror all four
            // from receipt.witness_sigs onto our_sig so the SDK — which
            // collects k=3 from each response's witness_signature, not from
            // the receipt — sees the finalizer's full witness state.
            //
            // execution_proof matters specifically because Core CL4
            // (modes.rs:922) rejects any prev_receipt whose witness_sigs
            // include an empty execution_proof with E_MISSING_EXECUTION_PROOF.
            // The SDK builds last_receipt from accumulated witness_signature
            // entries (send.rs:289), and on the NEXT send that receipt rides
            // as prev_receipt — so a missing execution_proof on the
            // finalizer's witness_signature crashes every post-genesis send.
            //
            // Then refresh all_sigs.last (the clone pushed at line 2533,
            // before finalize ran) so overlapped_signatures and
            // witness_signature carry identical data. Lambda MUST NOT
            // recompute any of these; they all came from the receipt patches.
            {
                let our_pk = self.public_key.as_bytes().to_vec();
                if let Some(receipt_our_sig) = receipt.witness_sigs.iter()
                    .find(|s| s.validator_pk == our_pk)
                {
                    if let Some(ref fact_sig) = receipt_our_sig.fact_signature {
                        our_sig.fact_signature = Some(fact_sig.clone());
                    }
                    if let Some(ref receipt_sig) = receipt_our_sig.receipt_signature {
                        our_sig.receipt_signature = Some(receipt_sig.clone());
                    }
                    if !receipt_our_sig.execution_proof.is_empty() {
                        our_sig.execution_proof = receipt_our_sig.execution_proof.clone();
                        our_sig.proof_type = receipt_our_sig.proof_type;
                    }
                }
                // KI#38 (a): the FINALIZER must ALSO sign the receipt_commitment.
                // The two co-witnesses sign it in the "need more witnesses" else
                // branch (~:3735/:3873), but this finalize path patched only
                // fact/receipt/execution sigs onto our_sig and NEVER the
                // receipt_commitment_sig — so a k=3 SEND shipped only 2 of 3
                // receipt_commitment_sigs. The now-live WI3 `verify_seq_proof`
                // requires 3, so every send seq-advance was rejected mesh-wide →
                // anti-entropy never adopted a send → perpetual reconcile → tick
                // starvation → TARDIS collapse (KI#38). Sign it here: the finalizer
                // is a full k-witness, §15 guarantees it computed the SAME
                // produced_state → the SAME `receipt.receipt_commitment` the
                // co-witnesses signed, so this is the identical strong 3-of-3
                // attestation the gate expects — no weakening, just the missing
                // third signature. Set BEFORE the all_sigs.last copy below so the
                // aggregated set carries it. `receipt.receipt_commitment` is
                // always non-zero here (finalize_transaction hard-errors otherwise).
                our_sig.receipt_commitment_sig =
                    Some(self.sign_receipt_commitment(&receipt.receipt_commitment));
                if let Some(last) = all_sigs.last_mut() {
                    if last.validator_pk == our_sig.validator_pk {
                        *last = our_sig.clone();
                    }
                }
            }
            
            // NOTE: Do NOT mark consumed here. TX is PENDING until ACK.
            // Client can abandon and retry with different TX from same state.
            // Consumed marking happens in ACK handler.
            // Store txid → consumed_state_id so ACK handler can mark consumed.
            // Use receipt.txid (from Core) — Lambda MUST NOT compute txid.
            if !is_genesis_tx {
                self.storage.store_txid_consumed_state(&receipt.txid, &request.transaction.consumed_state_id)?;
            }
            
            // Create ValidatorCheque for delivery to receiver.
            // Skip for protocol TXs (burn/deed/fee) — no real receiver wallet to deliver to.
            let sender_fact_chain = updated_fact_chain;
            let is_protocol_tx = {
                let recv = &request.transaction.receiver_wallet_id;
                recv == axiom_core_logic::types::BURN_ADDRESS
                    || recv == axiom_core_logic::types::DEED_ADDRESS
                    || recv == axiom_core_logic::types::FEE_ADDRESS
            };

            let cheque = if is_protocol_tx {
                None
            } else {
                Some(self.create_validator_cheque(
                    &request.transaction,
                    receipt.txid,
                    &our_sig,
                    receipt.state_hash,
                    receipt.produced_state_id,
                    sender_fact_chain.clone(),
                    &exec_proof_bytes,
                    zkp_nonce,
                    cheque_proof_type,
                    dmap_input_hash,
                    dmap_output_hash,
                    request.nabla_hint.clone(), // YPX-002 §3.2 sticky Nabla
                ))
            };

            // Delivery log: Lambda records intent. encrypted=false because Lambda
            // doesn't know if ANTIE will PGP-encrypt — ANTIE handles that after
            // receiving the cheque via IPC. The encrypted field is a placeholder
            // for future ANTIE→Lambda status callback.
            if cheque.is_some() {
                let recv_email = request.transaction.receiver_wallet_id
                    .split('/').next().unwrap_or("");
                if !recv_email.is_empty() {
                    self.storage.log_cheque_delivery(&receipt.txid, recv_email, false).ok();
                }
            }

            // Detect JFP vote TXs — if this TX is to a DWP group wallet, index the vote
            if request.transaction.receiver_wallet_id.starts_with(crate::dwp_engine::DWP_ADDRESS_PREFIX) {
                if let Some(ref dwp) = self.dwp_engine {
                    // Extract vote hash from reference field (hex-encoded 32 bytes)
                    if request.transaction.reference.len() == 64 {
                        if let Ok(hash_bytes) = hex::decode(&request.transaction.reference) {
                            if hash_bytes.len() == 32 {
                                let mut vote_hash = [0u8; 32];
                                vote_hash.copy_from_slice(&hash_bytes);
                                let mut sender_pk = [0u8; 32];
                                if request.transaction.client_pk.len() == 32 {
                                    sender_pk.copy_from_slice(&request.transaction.client_pk);
                                }
                                // Find the DWP wallet_id for this group wallet address
                                if let Some(db) = self.management_db() {
                                    if let Ok(conn) = db.db() {
                                        // Look up DWP wallet by group wallet address stored in wallet_type
                                        let dwp_wallet_id: Option<Vec<u8>> = conn.query_row(
                                            "SELECT wallet_id FROM dwp_wallets WHERE wallet_type = ?1",
                                            rusqlite::params![&request.transaction.receiver_wallet_id],
                                            |row| row.get(0),
                                        ).ok();
                                        if let Some(wid) = dwp_wallet_id {
                                            if wid.len() == 32 {
                                                let mut wid_arr = [0u8; 32];
                                                wid_arr.copy_from_slice(&wid);
                                                // DWP vote rate limit (protocol_core.toml: MAX_VOTES_PER_CASE_PER_TICK)
                                                let case_addr = &request.transaction.receiver_wallet_id;
                                                let sender_wid = &request.transaction.sender_wallet_id;
                                                let vote_tick = receipt.epoch;
                                                if self.storage.dwp_vote_rate_exceeded(case_addr, sender_wid, vote_tick) {
                                                    warn!("DWP: vote rate limit exceeded for {} on {} tick {}",
                                                        sender_wid, case_addr, vote_tick);
                                                    // Payment TX accepted. Vote silently suppressed.
                                                } else {
                                                    // AUDIT-FIX v2.11.14: Log vote recording failures (was silent drop).
                                                    if let Err(e) = self.storage.dwp_record_vote(case_addr, sender_wid, vote_tick) {
                                                        warn!("DWP vote rate record failed: {} — vote may be re-accepted", e);
                                                    }
                                                    if let Err(e) = dwp.record_vote_tx(
                                                        &wid_arr, &sender_pk, &vote_hash,
                                                        Some(&receipt.txid),
                                                    ) {
                                                        warn!("DWP vote TX record failed: {} — vote counted but not indexed", e);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Detect Console nomination TXs (YPX-013)
            // 1-atom TXs to DWP/CONSOLE/{gen} with nomination hash in reference
            if request.transaction.receiver_wallet_id.starts_with(
                crate::console_engine::CONSOLE_WALLET_PREFIX
            ) {
                tracing::debug!(
                    "Console nomination TX detected: {} → {}",
                    hex::encode(&request.transaction.client_pk),
                    request.transaction.receiver_wallet_id,
                );
                // Lambda logs it — actual nomination processing happens in election flow
            }

            // Generate hints for response (per Yellow Paper 27.5)
            let validator_id_str = hex::encode(self.validator_id);
            let response_hints = self.storage.get_random_hints(3, &validator_id_str)?;

            debug!("finalize_transaction: building response, our_sig.fact_sig={}",
                     our_sig.fact_signature.is_some());

            let response = WitnessResponse {
                request_id: request.request_id,
                success: true,
                witness_signature: Some(our_sig),
                overlapped_signatures: all_sigs,
                rejection: None,
                cheque_for_receiver: cheque,
                receipt: Some(receipt.clone()),
                produced_state_id: Some(receipt.produced_state_id.to_vec()),
                commitment_hash: request.commitment_hash.clone(),
                state_hash: Some(receipt.state_hash.to_vec()),
                // receipt.receipt_commitment is always non-zero at this
                // point because finalize_transaction (consensus.rs:4308)
                // hard-errors if Core didn't return one — so we always
                // expose it on the wire. The unconditional Some(...) is
                // intentional after the strict-mode flip.
                receipt_commitment: Some(receipt.receipt_commitment.to_vec()),
                txid: receipt.txid.to_vec(),
                validator_hints: response_hints,
                sender_fact_chain,
                audit_demand: self.pending_audit.lock().clone(),
                audit_request: pulse_audit_request,
                nonce_challenge: pulse_nonce_challenge,
                pulse_proof: pulse_proof_data,
                audit_failed: pulse_audit_failed,
                outbound_peer_audit: self.pending_peer_audit_outbound(),
                confidence_index: self.issue_confidence_index(&request.transaction.client_pk),
                scar_consent_for_receiver: None,
                scar_consent_voucher: scar_consent_voucher_out.clone(),
            };
            self.stats.witness_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.stats.atoms_witnessed.fetch_add(amount, std::sync::atomic::Ordering::Relaxed);
            self.stats.witness_time_us.fetch_add(_t0.elapsed().as_micros() as u64, std::sync::atomic::Ordering::Relaxed);
            self.stats.record_success();

            // YPX-016: Cache this witness response for partial witness recovery.
            // If the client retries this exact TX later (same hash), we return
            // this cached response without re-executing Core.
            //
            // CBOR (not JSON) — the cached response carries Dilithium pk
            // and signature byte fields. JSON's int-array coercion of
            // [u8; N] / Vec<u8> silently mutates the bytes on round-trip,
            // breaking witness verification when the cache is hit. The
            // tx_hash key (BLAKE3 over JSON of the request) is fine —
            // hashing only needs determinism, not round-trip fidelity.
            {
                let tx_hash = *blake3::hash(
                    &serde_json::to_vec(&request.transaction).unwrap_or_default()
                ).as_bytes();
                let mut serialized = Vec::new();
                if ciborium::ser::into_writer(&response, &mut serialized).is_ok() {
                    let _ = self.storage.set_witness_cache(
                        &request.transaction.client_pk,
                        sender_k, sender_pt,
                        &tx_hash,
                        &request.transaction.consumed_state_id,
                        request.transaction.wallet_seq,
                        &serialized,
                    );
                }
            }

            self.remember_witness_response(&response);
            Ok(response)
        } else {
            // Need more witnesses - but STILL produce our cheque
            // Per Yellow Paper: each sender validator produces a ValidatorCheque
            // Client collects k cheques and bundles them for receiver
            debug!("Collected {}/{} witnesses, producing cheque", all_sigs.len(), k);
            
            // Call Core CL3 to get txid, produced_state_id, state_hash, new_balance, fact_signature.
            // Lambda MUST NOT compute these. Core is the bible.
            //
            // §23.14: Resolve audit confirmation before Core call. If client provided one, use it.
            // Otherwise auto-generate from pending demand (Core only checks nonce match).
            let resolved_audit = self.resolve_audit_confirmation(&request.audit_confirmation);
            let resolved_pulse_audit = self.resolve_pulse_audit();

            // Oracle TXs require NablaStakeProof — fetch from Nabla + local state.
            // Core step 3e rejects oracle claims without proof (OracleInsufficientStake).
            let oracle_stake_proof = if request.transaction.oracle_claim.is_some() {
                self.fetch_own_nabla_stake_proof().await
            } else {
                None
            };

            // UMP-safe call: pass the typed envelope by reference. The
            // remaining args are Lambda-derived (wallet_state from
            // S-ABR result, frozen_wallets from storage, oracle stake
            // proof from Nabla) + Lambda's own crypto material. Adding
            // a new envelope field flows through automatically.
            //
            // `prev_receipts`, `overlapped_signatures`,
            // `group_member_index`, `sender_fact_chain`,
            // `audit_confirmation`, `audit_response`,
            // `clara_attestation` — all envelope-sourced inside
            // `produce_witness{_dmap}`; no longer threaded here.
            let _ = (&prev_receipts, &resolved_audit);
            let proof = {
                let vbc = Some(self.vbc_bundle());
                let mut core = self.core.write().await;
                if self.proof_mode == "dmap" {
                    core.produce_witness_dmap(
                        &request,
                        wallet_state_ref.as_ref(),
                        frozen_wallets.clone(),
                        oracle_stake_proof.clone(),
                        Some(self.public_key.as_bytes().to_vec()),
                        vbc,
                        Some(self.dilithium_sk.clone()),
                        Some(self.dilithium_pk.clone()),
                        Some(self.validator_id),
                        Some(&self.signing_key),
                    )?
                } else {
                    core.produce_witness(
                        &request,
                        wallet_state_ref.as_ref(),
                        frozen_wallets.clone(),
                        oracle_stake_proof,
                        None, // No ZKP nonce on non-k=3 path
                        Some(self.public_key.as_bytes().to_vec()),
                        vbc,
                        Some(self.dilithium_sk.clone()),
                        Some(self.dilithium_pk.clone()),
                        Some(self.validator_id),
                    )?
                }
            };

            // §23.14: Clear pending audit if we sent a confirmation to Core.
            // Core (AVM) clears its own tracking; mirror here for admin/stats.
            if resolved_audit.is_some() {
                let mut pending = self.pending_audit.lock();
                if pending.is_some() {
                    info!("§23.14: Audit confirmation resolved — clearing pending audit");
                    *pending = None;
                    self.audit_txs_since_demand.store(0, std::sync::atomic::Ordering::Relaxed);
                }
            }

            // §23.14: Track audit demand from Core and update TX counter
            self.handle_audit_demand(proof.outputs.audit_demand.clone());

            // YPX-009 §4: Store Pulse audit request from Core for next TX
            self.handle_pulse_audit_request(proof.outputs.audit_request.clone());

            // Extract Core-computed values — Lambda MUST NOT compute these
            let txid = proof.outputs.txid.ok_or_else(|| {
                error!("Core did not provide txid (non-finalize path)");
                LambdaError::CoreError("Core did not provide txid".into())
            })?;
            let state_hash = proof.outputs.new_state_hash.ok_or_else(|| {
                error!("Core did not provide state_hash (non-finalize path)");
                LambdaError::CoreError("Core did not provide state_hash".into())
            })?;
            let produced_state_id = proof.outputs.produced_state_id.ok_or_else(|| {
                error!("Core did not provide produced_state_id (non-finalize path)");
                LambdaError::CoreError("Core did not provide produced_state_id".into())
            })?;
            let new_balance = proof.outputs.new_balance.ok_or_else(|| {
                error!("Core did not provide new_balance (non-finalize path)");
                LambdaError::CoreError("Core did not provide new_balance".into())
            })?;

            // [FACT-SIGN-DIAG] Pinpoint the position-0 fact_signature divergence
            // (CL1 reports verify_fact_link FAIL on witness[0] only; verify
            // recomputes the commitment from the link's stored fields, so a
            // failing W0 means W0's Lambda computed produced_state_id from a
            // different `wallet_state.balance` / `wallet_seq` than W1/W2 did).
            //
            // Print every CL3 witness sign with the EXACT inputs that go into
            // compute_produced_state_id + compute_fact_commitment, plus the
            // resulting outputs. Match across the 3 validator logs by `txid`;
            // the validator whose `produced=` differs is the divergent witness,
            // and `ws_balance=` / `ws_seq=` shows what made it diverge.
            //
            // Eprintln-only — fires on every CL3 in the else branch (W0/W1 in
            // a k=3 fund_genesis; W2 takes finalize_transaction, see its own
            // diag if added there).
            {
                let hex8 = |b: &[u8]| -> String {
                    b.iter().take(8).map(|x| format!("{:02x}", x)).collect()
                };
                let ws_balance = wallet_state_ref.as_ref().map(|s| s.balance).unwrap_or(u64::MAX);
                let ws_seq = wallet_state_ref.as_ref().map(|s| s.wallet_seq).unwrap_or(u64::MAX);
                let ws_state_id = wallet_state_ref.as_ref()
                    .map(|s| hex8(&s.state_id))
                    .unwrap_or_else(|| "NONE".into());
                let fact_sig8 = proof.outputs.fact_signature.as_ref()
                    .map(|s| hex8(s))
                    .unwrap_or_else(|| "NONE".into());
                eprintln!(
                    "[FACT-SIGN-DIAG] val={} txid={} consumed={} produced={} new_balance={} \
                     amount={} is_genesis={} tx_wseq={} ws_balance={} ws_seq={} \
                     ws_state_id={} overlap_sigs={} fact_sig[..8]={}",
                    hex::encode(&self.validator_id[..4]),
                    hex8(&txid),
                    hex8(&request.transaction.consumed_state_id),
                    hex8(&produced_state_id),
                    new_balance,
                    request.transaction.amount,
                    request.transaction.is_genesis_claim(),
                    request.transaction.wallet_seq,
                    ws_balance,
                    ws_seq,
                    ws_state_id,
                    request.overlapped_signatures.len(),
                    fact_sig8,
                );
            }

            // FACT signature from Core — Lambda MUST NOT call sign_fact_commitment
            if let Some(ref fact_sig) = proof.outputs.fact_signature {
                our_sig.fact_signature = Some(fact_sig.clone());
            }
            // SEC-07 travel model: CO-SIGN the STORED provisional checkpoint, if
            // the sender's chain carries one this validator hasn't signed. The
            // co-sign is over the checkpoint bytes already on the chain (identical
            // for everyone — nothing to diverge), after re-verifying the retained
            // covered links against root_hash. The finalizer folds this into the
            // chain's checkpoint via merge_checkpoint_endorsements. None when
            // there's no provisional checkpoint. Core is the signing authority.
            if let Some(ref sender_chain) = request.sender_fact_chain {
                our_sig.checkpoint_sig = axiom_core_logic::compute::cosign_provisional_checkpoint(
                    sender_chain, self.validator_id, &self.dilithium_pk, &self.dilithium_sk,
                ).ok().flatten();
            }
            // Nabla register receipt signature: Ed25519 over
            // wallet_id || consumed_state || produced_state || tick_le.
            // This is what Nabla's /register TCP path verifies (k=3
            // distinct validator sigs over THIS payload). Witness sigs
            // (over commitment_hash) and fact_signatures (Dilithium
            // over FACT commitment) sign different payloads — neither
            // is acceptable to Nabla. Validators sign here directly
            // with their Ed25519 key (same key used for the witness
            // sig above) — no commitment computation, just byte
            // concatenation, so Core involvement isn't required.
            // SEND path: 2026-06-03 receipt_sign_payload refactor — sig
            // covers (wallet_id, consumed_state, tick) only. produced_state
            // and txid both dropped; (wallet_id, consumed_state) is unique
            // per TX because wallet state advances strictly forward.
            our_sig.receipt_signature = self.sign_nabla_receipt(
                &request.transaction.client_pk,
                &request.transaction.consumed_state_id,
            );
            // Receipt commitment signature: Ed25519 over the full receipt
            // commitment (BLAKE3 of all receipt fields). Core computed it;
            // we just sign it. Prevents receipt fabrication.
            //
            // YP §20.8 (post-refactor 2026-06-02): sends carry no fees.
            // verify_my_fee_slot is redeem-only — moved to process_redeem_request.
            if let Some(ref rc) = proof.outputs.receipt_commitment {
                our_sig.receipt_commitment_sig = Some(self.sign_receipt_commitment(rc));
            }
            // Propagate proof_type and execution_proof from Core
            our_sig.proof_type = proof.proof_type;
            our_sig.execution_proof = proof.execution_proof_bytes.clone();

            // Refresh the stale clone of our_sig that was pushed into
            // all_sigs at line 2533 (before Core ran). all_sigs is what the
            // response sets as `overlapped_signatures`, and the SDK's
            // K3Receipt builder reads receipt_signature off whichever sigs
            // it sees first. Without this refresh, overlapped_signatures
            // carries an incomplete copy of our own sig — missing
            // receipt_signature, proof_type, and execution_proof — and any
            // downstream consumer (next validator's overlap, receiver-side
            // verification, or the K3Receipt assembly) sees a sig that
            // looks like it was never patched.
            if let Some(last) = all_sigs.last_mut() {
                if last.validator_pk == our_sig.validator_pk {
                    *last = our_sig.clone();
                }
            }

            // Store THIS transaction's record (for S-ABR overlap lookup)
            // Every validator who witnesses stores a record keyed by produced_state_id
            // Next transaction can lookup by consumed_state_id to find us
            let new_wallet_seq = request.transaction.wallet_seq;
            // new_balance already computed by Core above — Lambda does zero balance math
            
            // Compute post-deduction group_members for this transaction.
            // Core's produced_state_id encodes group_members AFTER the deduction,
            // so the next TX's S-ABR lookup needs these post-deduction values.
            let group_members_after = wallet_state_ref.as_ref()
                .and_then(|ws| ws.group_members.clone())
                .map(|mut members| {
                    if let Some(idx) = request.group_member_index {
                        if idx < members.len() {
                            members[idx].available = members[idx].available
                                .saturating_sub(request.transaction.amount);
                        }
                    }
                    members
                });
            
            let tx_record = TransactionRecord {
                tx_id: txid,
                produced_state_id,
                wallet_pk: request.transaction.client_pk.clone(),
                balance_after: new_balance,
                wallet_seq_after: new_wallet_seq,
                group_members_after: group_members_after.clone(),
                is_genesis_claim: Some(request.transaction.is_genesis_claim()),
                status: WalletStateStatus::Pending,  // PENDING until ACK
                required_k: request.transaction.required_k,
                proof_type: request.transaction.proof_type,
                amount: request.transaction.amount,
                sender_balance: effective_balance,
            };
            // AUDIT-FIX v2.11.14: Store tx record + wallet state atomically in a single
            // SQLite transaction. Prevents partial writes where tx_record is stored but
            // wallet state update fails (leaving stale state until Core rejects on retry).
            {
                // Identity binding: preserve stored wallet_id, or establish from first TX
                let existing_wallet_id = self.storage.get_wallet_state(&request.transaction.client_pk, sender_k, sender_pt)
                    .ok().flatten().and_then(|ws| ws.wallet_id);
                let bound_wallet_id = existing_wallet_id.or_else(|| {
                    let wid = &request.transaction.sender_wallet_id;
                    if wid.is_empty() { None } else { Some(wid.clone()) }
                });
                let sender_state = StoredWalletState {
                    public_key: request.transaction.client_pk.clone(),
                    balance: new_balance,
                    wallet_seq: new_wallet_seq,
                    state_id: produced_state_id,
                    last_tx_id: Some(txid),
                    status: WalletStateStatus::Pending,
                    group_members: group_members_after,
                    auth_hash: stored_auth_hash,
                    // YPX-020: persist the hibernation deadline Core produced
                    // (the SAME value it bound into new_state_hash), so the
                    // next send sees it at the gate + §15 re-derive.
                    hibernation_until: proof.outputs.hibernation_until,
                    wallet_id: bound_wallet_id,
                };
                self.storage.store_tx_record_and_wallet_state(&tx_record, &sender_state, sender_k, sender_pt)?;
                debug!("V1/V2 atomic store: vid={} produced_state_id={} balance={} seq={}",
                      hex::encode(&self.validator_id[..4]),
                      hex::encode(&produced_state_id[..8]), new_balance, new_wallet_seq);
            }
            
            // NOTE: Do NOT mark consumed here — TX is PENDING until ACK.
            // Store txid → consumed_state_id so ACK handler can mark consumed.
            if !is_genesis_tx {
                self.storage.store_txid_consumed_state(&txid, &request.transaction.consumed_state_id)?;
            }

            // YP §20.8 v3.x: validator fees settle at CL5 via fee_breakdown
            // direct-deposit. No per-TX IOU is recorded at witness time
            // (Step 9A2 dropped the legacy fee_records IOU ledger). ACK's
            // "did we witness this?" gate now reads transaction_records.

            // YPX-001 §1.6: client carries provenance. No storage fallback.
            let sender_fact_for_cheque = request.sender_fact_chain.clone();
            
            // GAP-C FIX (Option B): V1/V2 include their execution proof in cheque.
            // Previously empty — now receiver can verify 2+ of k proofs.
            let cheque = self.create_validator_cheque(
                &request.transaction,
                txid,
                &our_sig,
                state_hash,
                produced_state_id,
                sender_fact_for_cheque,
                &proof.execution_proof_bytes,  // GAP-C: include proof from non-finalizing path
                None, // No ZKP nonce on non-k=3 path (DMAP doesn't need one)
                proof.proof_type,
                proof.dmap_input_hash,
                proof.dmap_output_hash,
                request.nabla_hint.clone(), // YPX-002 §3.2 sticky Nabla
            );

            // Delivery log: encrypted=false (Lambda doesn't know PGP status —
            // ANTIE handles encryption after receiving the cheque via IPC).
            let recv_email = request.transaction.receiver_wallet_id
                .split('/').next().unwrap_or("");
            if !recv_email.is_empty() {
                self.storage.log_cheque_delivery(&txid, recv_email, false).ok();
            }

            // Sign Nabla receipt at witness time (V1/V2 path).
            // Every validator signs so the SDK can forward k=3 receipt_signatures
            // to Nabla's TCP register without waiting for the finalizer.
            // 2026-06-03 refactor: sig covers (wallet_id, consumed_state, tick).
            our_sig.receipt_signature = self.sign_nabla_receipt(
                &request.transaction.client_pk,
                &request.transaction.consumed_state_id,
            );
            // YP §20.8 (post-refactor): sends carry no fees; redeem-only.
            if let Some(ref rc) = proof.outputs.receipt_commitment {
                our_sig.receipt_commitment_sig = Some(self.sign_receipt_commitment(rc));
            }

            // Generate hints for response (per Yellow Paper 27.5)
            let validator_id_hex = hex::encode(self.validator_id);
            let response_hints = self.storage.get_random_hints(3, &validator_id_hex)?;

            let response = WitnessResponse {
                request_id: request.request_id,
                success: true,
                witness_signature: Some(our_sig),
                overlapped_signatures: all_sigs,
                rejection: None,
                cheque_for_receiver: Some(cheque),  // Now always produce cheque
                receipt: None,  // No receipt until k=3
                produced_state_id: Some(produced_state_id.to_vec()),
                commitment_hash: request.commitment_hash.clone(),
                state_hash: Some(state_hash.to_vec()),
                receipt_commitment: proof.outputs.receipt_commitment.map(|rc| rc.to_vec()),
                txid: txid.to_vec(),
                validator_hints: response_hints,
                sender_fact_chain: None,  // Only available when k=3 reached
                audit_demand: self.pending_audit.lock().clone(),
                audit_request: proof.outputs.audit_request.clone(),
                nonce_challenge: proof.outputs.nonce_challenge.clone(),
                pulse_proof: proof.outputs.pulse_proof.clone(),
                audit_failed: proof.outputs.audit_failed,
                outbound_peer_audit: self.pending_peer_audit_outbound(),
                confidence_index: self.issue_confidence_index(&request.transaction.client_pk),
                scar_consent_for_receiver: None,
                scar_consent_voucher: scar_consent_voucher_out.clone(),
            };
            self.stats.witness_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.stats.atoms_witnessed.fetch_add(amount, std::sync::atomic::Ordering::Relaxed);
            self.stats.witness_time_us.fetch_add(_t0.elapsed().as_micros() as u64, std::sync::atomic::Ordering::Relaxed);
            self.stats.record_success();

            // YPX-016: Cache witness response (non-k=3 path — this is where
            // partial witnesses happen and caching is most critical).
            //
            // CBOR encoding for the cached value (see read site at line
            // 2469 for matching decode). JSON drops byte-string types on
            // round-trip and silently invalidates Dilithium signatures.
            {
                let tx_hash = *blake3::hash(
                    &serde_json::to_vec(&request.transaction).unwrap_or_default()
                ).as_bytes();
                let mut serialized = Vec::new();
                if ciborium::ser::into_writer(&response, &mut serialized).is_ok() {
                    let _ = self.storage.set_witness_cache(
                        &request.transaction.client_pk,
                        sender_k, sender_pt,
                        &tx_hash,
                        &request.transaction.consumed_state_id,
                        request.transaction.wallet_seq,
                        &serialized,
                    );
                }
            }

            self.remember_witness_response(&response);
            Ok(response)
        }
    }
    
    
    /// Lookup our record of the previous transaction (for overlapped validators)
    /// 
    /// Search by `consumed_state_id` which is the `produced_state_id` of the previous tx.
    /// If we're overlapped but have no record, that's an error - REJECT.
    fn lookup_previous_tx_record(&self, consumed_state_id: &[u8; 32], wallet_pk: &[u8], k: u8, proof_type: u8)
        -> Result<TransactionRecord, LambdaError>
    {
        // Lookup by produced_state_id (which is this tx's consumed_state_id)
        match self.storage.get_transaction_record(consumed_state_id)? {
            Some(record) => {
                // Verify wallet_pk matches (handle TX_ID collision)
                if record.wallet_pk != wallet_pk {
                    return Err(LambdaError::SABRFailed(format!(
                        "TX record wallet mismatch: expected {}, found {}",
                        hex::encode(&wallet_pk[..8]),
                        hex::encode(&record.wallet_pk[..8])
                    )));
                }
                debug!("S-ABR LOOKUP HIT: vid={} found record for csid={} balance={} seq={}",
                       hex::encode(&self.validator_id[..4]),
                       hex::encode(&consumed_state_id[..8]),
                       record.balance_after, record.wallet_seq_after);
                Ok(record)
            }
            None => {
                // Check if this is a genesis transaction (tier-aware, §10.5)
                let genesis_id = self.compute_genesis_state_id(wallet_pk, k, proof_type)?;
                if *consumed_state_id == genesis_id {
                    // Genesis - create a pseudo-record with genesis state
                    if wallet_pk.len() == 32 {
                        let pk_array: [u8; 32] = wallet_pk.try_into().unwrap_or([0u8; 32]);
                        if let Ok(Some(genesis_state)) = self.storage.get_genesis_state(&pk_array, k, proof_type) {
                            return Ok(TransactionRecord {
                                tx_id: [0u8; 32],  // No previous tx for genesis
                                produced_state_id: genesis_id,
                                wallet_pk: wallet_pk.to_vec(),
                                balance_after: genesis_state.balance,
                                wallet_seq_after: 0,
                                group_members_after: genesis_state.group_members.clone(),
                                is_genesis_claim: None,
                                status: WalletStateStatus::Confirmed,
                                required_k: 3,  // Genesis uses default k=3
                                proof_type: 1,  // Genesis uses DMAP
                                amount: 0,  // Genesis has no TX amount
                                sender_balance: genesis_state.balance,  // Genesis balance
                            });
                        }
                    }
                }
                
                // DIAGNOSTIC (debug!, not error!): a lookup miss is an EXPECTED transient
                // — a fresh witness (or a concurrent-fork race) that has no stored state for
                // this wallet yet. The caller handles it (carried proofs / re-route); it is NOT
                // a failure, so it must not log at ERROR (that misleads operators into chasing it).
                debug!("S-ABR LOOKUP MISS: vid={} wanted csid={}",
                       hex::encode(&self.validator_id[..4]),
                       hex::encode(&consumed_state_id[..8]));

                // Also dump wallet state for this pk and capture it for
                // the structured error response (DEBUG-gated detail fields).
                let (stored_sid, stored_seq) = if wallet_pk.len() == 32 {
                    let pk_arr: [u8; 32] = wallet_pk.try_into().unwrap_or([0u8; 32]);
                    if let Ok(Some(ws)) = self.storage.get_wallet_state(&pk_arr, k, proof_type) {
                        debug!("S-ABR LOOKUP MISS: wallet state_id={} balance={} seq={} has_gm={}",
                               hex::encode(&ws.state_id[..8]), ws.balance, ws.wallet_seq,
                               ws.group_members.is_some());
                        (Some(ws.state_id), Some(ws.wallet_seq))
                    } else {
                        debug!("S-ABR LOOKUP MISS: no wallet state for pk={}", hex::encode(&wallet_pk[..8]));
                        (None, None)
                    }
                } else {
                    (None, None)
                };

                // We're supposed to be overlapped but have NO record - REJECT.
                // [DRIFT-DIAG] Downgraded from eprintln to debug! 2026-05-15
                // (paired with the EARLY-REJECT downgrade above).  Re-enable
                // via RUST_LOG=axiom_lambda::consensus=debug when chasing a
                // suspected storage-write-loss regression.
                debug!(
                    "[DRIFT-DIAG] OVERLAPPED-NO-RECORD requested_csid={} stored_sid={} stored_seq={:?}",
                    hex::encode(&consumed_state_id[..8]),
                    stored_sid.as_ref().map(|s| hex::encode(&s[..8])).unwrap_or_else(|| "none".to_string()),
                    stored_seq,
                );
                Err(LambdaError::SabrStateChainMismatch {
                    requested_consumed_state_id: *consumed_state_id,
                    // No wallet_seq on this path — the client's TX isn't in scope
                    // of this helper. 0 is a sentinel; the structured detail
                    // shows validator_wallet_seq so the client can diff.
                    requested_wallet_seq: 0,
                    stored_sid,
                    stored_seq,
                    requested_csid_hex: hex::encode(&consumed_state_id[..8]),
                })
            }
        }
    }
    
    /// Compute genesis state_id for a public key
    /// 
    /// Per Yellow Paper: genesis_state_id = SHA3-256("AXIOM_GENESIS" || pk || balance)
    /// For now, we use the stored balance from genesis state if available,
    /// or compute with standard genesis balance.
    fn compute_genesis_state_id(&self, pk: &[u8], k: u8, proof_type: u8) -> Result<[u8; 32], LambdaError> {
        if pk.len() != 32 {
            return Err(LambdaError::InvalidRequest(
                format!("Genesis state_id requires 32-byte pk, got {}", pk.len())
            ));
        }
        let pk_array: [u8; 32] = pk.try_into()
            .map_err(|_| LambdaError::InvalidRequest("Public key must be 32 bytes".into()))?;

        // Try stored genesis state first (has the correct balance)
        // NOTE: get_genesis_state is still pk-keyed — the wallet_id re-key that
        // lets the k=3 and k=0 tiers of one pk coexist in storage is the rest of
        // step 4 (YPX-010 §10.5). Until then, the COMPUTE path below is tier-aware.
        if let Ok(Some(genesis)) = self.storage.get_genesis_state(&pk_array, k, proof_type) {
            return Ok(genesis.state_id);
        }

        // Compute via Core with standard genesis balance (tier-aware, §10.5)
        Ok(axiom_core_logic::genesis::compute_genesis_state_id(&pk_array, 10000, k, proof_type))
    }
    
    
    /// Calculate required overlap for a given k value
    /// 
    /// | k | Required Overlap |
    /// |---|-----------------|
    /// | 3 | 2               |
    /// | 4 | 3               |
    /// | 5 | 3               |
    fn required_overlap(k: usize) -> usize {
        match k {
            3 => 2,
            4 => 3,
            5 => 3,
            _ => (k + 1).div_ceil(2), // General formula: ceiling((k+1)/2)
        }
    }
    
    // Verify a witness signature is cryptographically valid
    //
    // SECURITY: This prevents a compromised Gateway from injecting fake signatures.
    // We must verify the signature was actually created by the claimed validator.
    // Witness signature verification is handled by Core (CL3 overlap check).
    // Lambda MUST NOT verify Ed25519 signatures directly.

    /// Sign as witness using commitment_hash from Core.
    /// Core is the sole authority for commitment_hash. No fallback.
    /// "Can crash, must not lie."
    /// Sign Nabla's k=3 register receipt payload with this validator's
    /// Ed25519 key. Nabla's `/register` TCP path verifies k of these.
    /// Payload: `wallet_id || consumed_state || produced_state || tick_le`.
    /// Tick is 0 (legacy mode — Nabla falls back to current_tick); a
    /// future commit can thread TARDIS tick through if/when receipts
    /// need staleness pinning.
    fn sign_nabla_receipt(
        &self,
        wallet_id: &[u8],
        consumed_state: &[u8; 32],
    ) -> Option<Vec<u8>> {
        if wallet_id.len() != 32 {
            return None;
        }
        // Matches nabla::crypto::receipt_sign_payload — wallet_id +
        // consumed_state + tick. produced_state and txid are both
        // intentionally NOT in the payload; see that fn's docstring.
        let mut payload = Vec::with_capacity(32 + 32 + 8);
        payload.extend_from_slice(wallet_id);
        payload.extend_from_slice(consumed_state);
        payload.extend_from_slice(&0u64.to_le_bytes());
        let sig = self.signing_key.sign(&payload);
        Some(sig.to_bytes().to_vec())
    }

    /// Sign receipt commitment — Ed25519 over BLAKE3("AXIOM_RECEIPT_v1" || ...).
    /// Core computes the commitment; Lambda signs it with the validator's key.
    /// Core on the next TX recomputes and verifies k signatures match.
    fn sign_receipt_commitment(&self, receipt_commitment: &[u8; 32]) -> Vec<u8> {
        let sig = self.signing_key.sign(receipt_commitment);
        sig.to_bytes().to_vec()
    }

    /// YP §19.6 amendment — fee charged by this validator for a given
    /// transaction amount, in atoms. Honors operator-configured `rate_bps`
    /// but clamps to `MAX_VALIDATOR_FEE_BPS` so an operator setting an
    /// out-of-cap rate cannot push slot verification into permanent fail.
    /// Both SDK (when building fee_breakdown) and Lambda (when verifying its
    /// own slot) MUST use this formula; any divergence breaks slot verify.
    /// Uses u128 to avoid overflow at total-supply scale (see
    /// `validate_fee_breakdown`).
    fn expected_fee_slot_amount(&self, tx_amount: u64) -> u64 {
        let effective_bps = self.fee_config.rate_bps
            .min(axiom_core_logic::types::MAX_VALIDATOR_FEE_BPS);
        let amt_128 = tx_amount as u128;
        let fee_128 = amt_128 * effective_bps as u128 / axiom_core_logic::types::FEE_BPS_DIVISOR as u128;
        fee_128 as u64
    }

    /// YP §19.6 amendment — verify this validator's slot in the proposed
    /// `fee_breakdown` before signing `receipt_commitment`.
    ///
    /// Returns Ok on empty breakdown (no-fee paths — send / heal / genesis /
    /// oracle) or when the slot matches `expected_fee_slot_amount(amount)`.
    /// Returns FeeSlotMismatch / FeeSlotMissing otherwise; the SDK MUST
    /// retry with corrected slots before any further round.
    ///
    /// Cap enforcement (`validate_fee_breakdown`) runs independently at Core
    /// CL3/CL5 + at Nabla `/register`; this method only guarantees consensus
    /// over the slot Lambda i actually authored.
    /// Returns the atoms this validator's slot earned. Zero if fee_breakdown
    /// is empty (heal / genesis-claim / zero-rate). Callers record the
    /// returned amount in the v3.x earnings ledger after CL5 commit.
    fn verify_my_fee_slot(
        &self,
        tx_amount: u64,
        fee_breakdown: &[axiom_core_logic::types::FeeShare],
    ) -> Result<u64, LambdaError> {
        if fee_breakdown.is_empty() {
            return Ok(0);
        }
        let expected = self.expected_fee_slot_amount(tx_amount);
        match fee_breakdown.iter().find(|s| s.validator_id == self.validator_id) {
            Some(slot) if slot.amount == expected => Ok(slot.amount),
            Some(slot) => Err(LambdaError::FeeSlotMismatch {
                expected,
                declared: slot.amount,
                tx_amount,
            }),
            None => Err(LambdaError::FeeSlotMissing { tx_amount }),
        }
    }

    fn sign_witness(&self, _transaction: &Transaction, core_commitment: Option<&[u8]>) -> Result<WitnessSig, LambdaError> {
        let commitment = if let Some(ch) = core_commitment {
            if ch.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(ch);
                arr
            } else {
                error!("Core commitment_hash wrong length ({}), rejecting", ch.len());
                return Err(LambdaError::CoreError(
                    "Core provided invalid commitment_hash length".into()
                ));
            }
        } else {
            error!("No commitment_hash from Core — cannot sign without it");
            return Err(LambdaError::CoreError(
                "Core did not provide commitment_hash".into()
            ));
        };
        
        // Sign with our key
        let signature = self.signing_key.sign(&commitment);
        
        // Generate hints for this witness signature
        let validator_id_str = hex::encode(self.validator_id);
        let hints = self.storage.get_random_hints(3, &validator_id_str)
            .unwrap_or_default();
        
        Ok(WitnessSig {
            validator_id: self.validator_id,
            validator_pk: self.public_key.as_bytes().to_vec(),
            vbc_bundle: self.vbc_for_signature(),
            carrier_type: self.carrier_type.clone(),
            carrier_address: self.carrier_address.clone(),
            signature: signature.to_bytes().to_vec(),
            execution_proof: vec![], // Filled later by finalize_transaction
            proof_type: 0, // Default ZKP; updated if DMAP is used
            availability_attestation: None,
            validator_hints: hints,
            fact_signature: None,  // Filled later when produced_state_id is known
            checkpoint_sig: None,  // SEC-07: filled from Core compressed_fact_chain checkpoint
            receipt_signature: None, // Filled later when produced_state_id is known
            receipt_commitment_sig: None,
            rate_bps: 0,
            slot_amount: 0,
        })
    }

    /// DEPRECATED: Compute commitment hash for signing (fallback only)
    /// 
    /// Core is the sole authority for commitment_hash computation.
    /// Compute transaction ID — delegates to Core
    /// Check rate limit for a wallet PK. Returns Err if limit exceeded.
    /// Uses first 16 bytes of PK as key to save memory.
    /// Sliding window: removes entries older than 60 seconds.
    fn check_rate_limit(&self, client_pk: &[u8]) -> Result<(), LambdaError> {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(60);
        
        // Build key from first 16 bytes of PK
        let mut key = [0u8; 16];
        let copy_len = client_pk.len().min(16);
        key[..copy_len].copy_from_slice(&client_pk[..copy_len]);
        
        let mut limits = self.rate_limits.lock();
        
        // Periodic cleanup: if map grows too large, evict old entries
        if limits.len() > 10_000 {
            limits.retain(|_, timestamps: &mut Vec<std::time::Instant>| {
                timestamps.retain(|t| now.duration_since(*t) < window);
                !timestamps.is_empty()
            });
        }
        
        let timestamps = limits.entry(key).or_default();
        
        // Remove expired entries
        timestamps.retain(|t| now.duration_since(*t) < window);
        
        // Check limit
        if timestamps.len() >= self.rate_limit_per_minute as usize {
            warn!("Rate limit exceeded for wallet {}: {} requests/min",
                hex::encode(&key[..8]), timestamps.len());
            return Err(LambdaError::RateLimitExceeded {
                limit: self.rate_limit_per_minute,
                window_secs: window.as_secs() as u32,
                current_count: timestamps.len() as u32,
            });
        }
        
        // Record this request
        timestamps.push(now);
        Ok(())
    }
    
    // NOTE: compute_txid is a deterministic hash (BLAKE3), not a validation
    // authority decision. Shared utility between Core and Lambda.
    fn compute_txid(&self, transaction: &Transaction) -> [u8; 32] {
        axiom_core_logic::compute::compute_txid(transaction)
    }
    
    // sign_fact_commitment removed — FACT signing moved into Core CL5 (YP §26.17.6.2)
    
    /// Build a FACT link for a witnessed transaction.
    /// Assembles FactWitnesses from k=3 WitnessSigs that carry fact_signatures.
    /// Returns updated FactChain (with new link appended).
    ///
    /// Lambda's role: Lambda is a WITNESS, not a cryptographic authority.
    ///   1. Core computes the FACT commitment (Core is the bible)
    ///   2. Each validator signs the commitment with its own Ed25519 key
    ///   3. Overlapped validator assembles the FactLink from k=3 fact_signatures
    ///
    /// Lambda does NOT perform any hashing or cryptographic operations here.
    /// The only "crypto" Lambda does is signing with its own key — which IS
    /// what a witness does. The commitment it signs was computed by Core.
    ///
    /// In DMAP mode (default): Core computes FACT commitment inside AVM (DMAP-attested).
    /// In ZKP mode (premium): Core computes inside RISC Zero guest; Lambda receives
    /// the commitment from the ZKP receipt. Both modes use the same Core function.
    /// Compress and endorse FACT chain after Core built the new link.
    /// Lambda only handles checkpoint signing (validator's own Dilithium key).
    /// FactLink creation is Core's sole authority — see core/logic/src/fact.rs::build_fact_link.
    fn compress_and_endorse_fact_chain(
        &self,
        mut chain: axiom_core_logic::types::FactChain,
        checkpoint_cosigns: &[axiom_core_logic::types::FactWitness],
        // YPX-021 §8.2 — `receipt.oods_flag.map_or(true, |f| f.healthy)` of
        // the receipt this round just produced. `false` = the wallet's step
        // happened under an eclipsed view → Core refuses ALL checkpoint
        // progress (no wash-out). Flagless receipts pass `true`.
        oods_view_healthy: bool,
    ) -> Result<axiom_core_logic::types::FactChain, LambdaError> {
        // SEC-07 travel-model checkpoint. Lambda does zero compression logic —
        // Core owns it. Two Core calls, in order:
        //
        // 1. merge_checkpoint_endorsements — fold in THIS round's witness co-signs
        //    (WitnessSig.checkpoint_sig). Each co-signs the STORED provisional
        //    checkpoint's commitment (stable bytes, no divergence); dedup by
        //    validator_id, append distinct. With S-ABR overlap this nets ~+1 new
        //    distinct validator per TX.
        // 2. advance_fact_checkpoint — the finalizer's own step: PROPOSE if the
        //    chain just crossed FACT_PROPOSE_TRIGGER (write the proposal, retain
        //    links, 1 sig), or CO-SIGN the existing proposal, then FINALIZE
        //    (delete the covered links) once CHECKPOINT_SIG_THRESHOLD distinct
        //    sigs are present. Never deletes links below the threshold, so the
        //    chain stays fully verifiable while the proposal accumulates.
        // See docs/security_review_20260612/SEC-07_RESOLUTION.md.
        let _ = axiom_core_logic::compute::merge_checkpoint_endorsements(
            &mut chain, checkpoint_cosigns,
        );
        axiom_core_logic::compute::advance_fact_checkpoint(
            &mut chain, self.validator_id, &self.dilithium_pk, &self.dilithium_sk,
            oods_view_healthy,
        ).map_err(|e| LambdaError::CoreError(format!("FACT advance_checkpoint: {:?}", e)))?;

        if let Some(cp) = chain.checkpoint.as_ref() {
            info!(
                "FACT checkpoint: {} distinct sig(s), pending_links={} ({})",
                cp.validator_sigs.len(), cp.pending_links,
                if cp.pending_links == 0 { "finalized" } else { "provisional" },
            );
        }
        Ok(chain)
    }

    // compress_sender_chain_in_place REMOVED (v2.11.16-beta21):
    // FACT compression is now handled by Core inside the AVM. Lambda no longer
    // calls verify_and_compress_fact_chain at the ingress boundary. The scar
    // rule invariant (no compression with scarred links) is enforced by Core.

    /// Compute produced state ID for a transaction
    /// This is the new state ID that will be consumed by the next transaction
    /// 
    /// MUST match Core's computation exactly!
    /// Formula: SHA3-256("AXIOM_STATE" || pk || new_balance || new_seq || consumed_state_id || nonce)
    /// Collect receipts for overlapped validators
    async fn collect_prev_receipts(
        &self,
        request: &WitnessRequest,
    ) -> Result<Vec<Receipt>, LambdaError> {
        // Use prev_receipts from request if provided
        // Client is responsible for including receipts from previous transaction
        if !request.prev_receipts.is_empty() {
            return Ok(request.prev_receipts.clone());
        }
        
        // No prev_receipts - this is either genesis or client forgot to include them
        // Core will validate and reject if needed
        Ok(vec![])
    }
    
    /// Finalize transaction after k=3 reached
    #[allow(clippy::too_many_arguments)]
    /// UMP-safe finalize entry — takes the typed `WitnessRequest` by
    /// reference plus Lambda-derived values. Same shape as
    /// `produce_witness_dmap` / `validate_redeem`. A new field added
    /// to `WitnessRequest` no longer needs to be threaded through here
    /// — it's accessible via the envelope reference.
    async fn finalize_transaction(
        &self,
        envelope: &axiom_core_logic::types::WitnessRequest,
        wallet_state: Option<&WalletState>,
        mut witness_sigs: Vec<WitnessSig>,
        // Audit values Lambda resolved before calling this (NOT raw
        // envelope fields — `resolve_audit_confirmation` /
        // `resolve_pulse_audit` apply Lambda-side gating).
        resolved_audit: Option<axiom_core_logic::types::AuditConfirmation>,
        resolved_pulse: Option<axiom_core_logic::types::PulseAuditResponse>,
    ) -> Result<(Receipt, Option<axiom_core_logic::types::FactChain>, Vec<u8>, Option<[u8; 32]>, u8,
                  Option<axiom_core_logic::types::PulseAuditRequest>, Option<axiom_core_logic::types::NonceChallenge>,
                  Option<axiom_core_logic::types::PulseProofData>, bool, [u8; 32], [u8; 32]), LambdaError> {
        // Returns: (receipt, updated_fact_chain, execution_proof_bytes, zkp_nonce, proof_type,
        //           pulse_audit_request, pulse_nonce_challenge, pulse_proof_data, pulse_audit_failed,
        //           dmap_input_hash, dmap_output_hash)
        info!("Finalizing transaction with {} witnesses (production={}, group_member_index={:?})",
              witness_sigs.len(), self.is_production_mode(), envelope.group_member_index);

        // Log group wallet state if present
        if let Some(ws) = wallet_state {
            if let Some(ref gm) = ws.group_members {
                info!("GROUP WALLET STATE: {} members, balance={}", gm.len(), ws.balance);
                for (i, m) in gm.iter().enumerate() {
                    info!("  GROUP member[{}]: share={}bps, available={}", i, m.share_bps, m.available);
                }
            }
        }

        // Convenience locals — every reference is `envelope.<field>`.
        let transaction = &envelope.transaction;
        // Sender tier (YPX-010 §10.5) for the wallet-state row key.
        let (finalize_k, finalize_pt) = axiom_core_logic::wallet_id::extract_security_level(
            &transaction.sender_wallet_id,
        )
        .unwrap_or((3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP));
        let prev_receipts = envelope.prev_receipts.as_slice();

        // Produce witness proof via Core (CL3)
        // Pass our PK, overlapped sigs, VBC, and sender's FACT chain.
        // Core validates EVERYTHING in one call — one ring to rule them all.
        // Priority: client's chain from request (YPX-001 §1.6 — client is authoritative).
        // Fallback: cached chain from storage (for backwards compat / JSON bloat avoidance).
        let my_pk = self.public_key.as_bytes().to_vec();
        let vbc = Some(self.vbc_bundle());
        // Route proof generation: ZKP (STARK) vs DMAP (memory attestation)
        let use_dmap = self.proof_mode == "dmap";
        // ZKP nonce only needed for STARK proofs (binds into the proof for anti-replay)
        let zkp_nonce: Option<[u8; 32]> = if !use_dmap && self.is_production_mode() {
            Some(rand::random())
        } else {
            None
        };

        // Oracle TXs require NablaStakeProof — fetch from Nabla + local state.
        let oracle_stake_proof = if transaction.oracle_claim.is_some() {
            self.fetch_own_nabla_stake_proof().await
        } else {
            None
        };

        // UMP-safe call: the typed envelope carries every wire field
        // (transaction, prev_receipts, overlapped_signatures,
        // group_member_index, sender_fact_chain, audit_confirmation,
        // audit_response, clara_attestation). `produce_witness{_dmap}`
        // sources them all by reference; `resolved_*` are the
        // Lambda-applied audit values (NOT the raw envelope fields).
        // Pre-Lambda finalize used `audit_confirmation` /
        // `audit_response` as separate args but they were always
        // sourced from `resolve_*` on the envelope at the caller;
        // collapsed here.
        let _ = (&resolved_audit, &resolved_pulse);

        let proof = {
            // Witness-perf fix (beta10, 2026-04-13): DMAP path takes read() so
            // multiple witness requests can run AVM concurrently. ZKP path still
            // needs write() because produce_witness uses &mut self (SubprocessProver).
            // Under the prior Mutex, 6 concurrent soak wallets queued on a single
            // lock with 17-27s tail latencies.
            let start = std::time::Instant::now();

            let frozen = self.get_frozen_wallets();
            let result = if use_dmap {
                debug!("CL3: Using DMAP attestation path (single-pass AVM)");
                let core = self.core.read().await;
                core.produce_witness_dmap(
                    envelope,
                    wallet_state,
                    frozen.clone(),
                    oracle_stake_proof.clone(),
                    Some(my_pk.clone()),
                    vbc,
                    Some(self.dilithium_sk.clone()),
                    Some(self.dilithium_pk.clone()),
                    Some(self.validator_id),
                    Some(&self.signing_key),
                )
            } else {
                let mut core = self.core.write().await;
                core.produce_witness(
                    envelope,
                    wallet_state,
                    frozen,
                    oracle_stake_proof,
                    zkp_nonce,
                    Some(my_pk.clone()),
                    vbc,
                    Some(self.dilithium_sk.clone()),
                    Some(self.dilithium_pk.clone()),
                    Some(self.validator_id),
                )
            };

            let elapsed = start.elapsed();
            debug!("finalize_transaction: produce_witness returned in {:?}: {}",
                     elapsed, if result.is_ok() { "OK" } else { "ERR" });
            // Audit-fix v2.11.15-beta6: bumped from 5s → 15s.
            // 5s was too aggressive for DMAP + CL3 on a busy machine —
            // every soak run produced false-positive critical logs. 15s
            // is the genuine "this is slow enough to investigate" line
            // for pure compute (post-lock-acquire). Queue-wait latency
            // is captured separately by the 30s timeout above.
            if elapsed > std::time::Duration::from_secs(15) {
                error!("CRITICAL: produce_witness took {:?} — potential hang", elapsed);
            }
            result?
        };
        // eprintln!("[TIMING] finalize_transaction: Core lock released, continuing");
        
        // Log Core's overlap determination
        if let Some(overlapped) = proof.outputs.is_overlapped {
            debug!("Core S-ABR: is_overlapped={} for validator {}", 
                  overlapped, self.carrier_address);
        }
        
        // Update our signature to include the execution proof and proof type
        if !proof.execution_proof_bytes.is_empty() {
            let our_pk = self.public_key.as_bytes().to_vec();
            for sig in &mut witness_sigs {
                if sig.validator_pk == our_pk {
                    sig.execution_proof = proof.execution_proof_bytes.clone();
                    sig.proof_type = proof.proof_type;
                    debug!("Added execution proof to witness signature ({} bytes, type={})",
                          sig.execution_proof.len(),
                          if proof.proof_type == 1 { "dmap" } else { "zkp" });
                    break;
                }
            }
        }
        
        // Create receipt
        // Core MUST provide these values. If missing, Lambda rejects — no fallback.
        // "Can crash, must not lie" — a zero state_hash or produced_state_id is a lie.
        let txid = proof.outputs.txid.ok_or_else(|| {
            error!("Core did not provide txid — cannot build receipt");
            LambdaError::CoreError("Core did not provide txid".into())
        })?;
        let state_hash = proof.outputs.new_state_hash.ok_or_else(|| {
            error!("Core did not provide state_hash — cannot build receipt");
            LambdaError::CoreError("Core did not provide state_hash".into())
        })?;
        let produced_state_id = proof.outputs.produced_state_id.ok_or_else(|| {
            error!("Core did not provide produced_state_id — cannot build receipt");
            LambdaError::CoreError("Core did not provide produced_state_id".into())
        })?;
        let new_wallet_seq = proof.outputs.new_wallet_seq.ok_or_else(|| {
            error!("Core did not provide new_wallet_seq — cannot build receipt");
            LambdaError::CoreError("Core did not provide new_wallet_seq".into())
        })?;
        
        // FACT signature — Core signed it internally using Dilithium.
        // Lambda MUST NOT call sign_fact_commitment or sign_dilithium directly.
        // Patch our witness sig with Core's FACT signature.
        if let Some(ref core_fact_sig) = proof.outputs.fact_signature {
            let our_pk = self.public_key.as_bytes().to_vec();
            for sig in &mut witness_sigs {
                if sig.validator_pk == our_pk && sig.fact_signature.is_none() {
                    sig.fact_signature = Some(core_fact_sig.clone());
                    break;
                }
            }
        }

        // SEC-07 travel model: the finalizer's OWN checkpoint co-sign is added
        // directly to the chain's checkpoint by advance_fact_checkpoint (inside
        // compress_and_endorse_fact_chain below) — no need to patch it onto the
        // witness_sig here. The other validators' co-signs arrive via their
        // WitnessSig.checkpoint_sig (set at pre-sign) and are folded in by
        // merge_checkpoint_endorsements.

        // Patch the finalizer's own witness sig with the Nabla receipt
        // signature (Ed25519 over wallet_id || consumed_state || tick).
        // 2026-06-03 refactor — neither produced_state nor txid is in the
        // payload; (wallet_id, consumed_state) alone is unique per TX.
        let receipt_sig_bytes = self.sign_nabla_receipt(
            &transaction.client_pk,
            &transaction.consumed_state_id,
        );
        if let Some(ref rs) = receipt_sig_bytes {
            let our_pk = self.public_key.as_bytes().to_vec();
            for sig in &mut witness_sigs {
                if sig.validator_pk == our_pk && sig.receipt_signature.is_none() {
                    sig.receipt_signature = Some(rs.clone());
                    break;
                }
            }
        }
        // Receipt commitment signature — the finalizer signs Core's receipt_commitment.
        // YP §20.8 (post-refactor): finalizer is on the send path; no fee verify.
        if let Some(ref rc) = proof.outputs.receipt_commitment {
            let rc_sig = self.sign_receipt_commitment(rc);
            let our_pk = self.public_key.as_bytes().to_vec();
            for sig in &mut witness_sigs {
                if sig.validator_pk == our_pk && sig.receipt_commitment_sig.is_none() {
                    sig.receipt_commitment_sig = Some(rc_sig.clone());
                    break;
                }
            }
        }

        // Save witness_sigs for FACT link assembly (Receipt takes ownership below)
        let fact_witness_sigs = witness_sigs.clone();

        // 2026-05-10 — UMP consolidation: build the Receipt via the
        // canonical `axiom_core_logic::receipt::build_send_receipt`
        // instead of an inline struct literal. The SDK calls the same
        // builder; both sides produce byte-identical receipts.
        //
        // We still hard-error if Core didn't provide commitment_hash
        // (security invariant: Lambda MUST NOT compute commitment_hash
        // itself). The receipt_commitment we used to read from
        // proof.outputs is now recomputed inside the builder over the
        // exact same inputs Core CL3 used — so we don't trust the
        // pre-computed value and don't need it.
        let commitment_hash = proof.outputs.commitment_hash.ok_or_else(|| {
            error!("Core did not provide commitment_hash — cannot build receipt");
            LambdaError::CoreError("Core did not provide commitment_hash".into())
        })?;
        let receipt = axiom_core_logic::receipt::build_send_receipt(
            axiom_core_logic::receipt::SendReceiptInputs {
                txid,
                state_hash,
                produced_state_id,
                new_wallet_seq,
                commitment_hash,
                epoch: transaction.epoch,
                witness_sigs,
                required_k: transaction.required_k,
                core_id: transaction.core_id,
                // Source of truth: Core CL3 attested this from
                // tx.sender_wallet_id and bound it into
                // receipt_commitment. Lambda stamps the same value
                // so the receipt's stored field matches what k=3
                // signed over — `verify_receipt_commitment` on the
                // next CL2 recomputes from this field and reaches
                // the same hash.
                is_dev_class: proof.outputs.is_dev_class.unwrap_or(false),
                // YPX-021 §8.2 — same carry-back contract as is_dev_class:
                // stamp exactly what Core CL3 bound into receipt_commitment.
                oods_flag: proof.outputs.oods_flag,
            },
        );
        debug_assert_eq!(
            receipt.receipt_commitment,
            proof.outputs.receipt_commitment.unwrap_or([0u8; 32]),
            "Lambda's receipt_commitment recompute via build_send_receipt \
             should match what Core CL3 returned in proof.outputs — if it \
             doesn't, axiom_core_logic::receipt and core::modes::execute_cl3 \
             have drifted."
        );

        // Store receipt
        self.storage.store_receipt(&receipt)?;
        
        // Store THIS transaction's record (for S-ABR overlap lookup)
        // V3 (k=3 validator) also stores a record, same as V1 and V2
        // Keyed by produced_state_id so next tx can find us
        // Core does ALL balance math — Lambda ONLY stores what Core returned.
        let new_balance = proof.outputs.new_balance.ok_or_else(|| {
            error!("Core did not provide new_balance — cannot store tx record");
            LambdaError::CoreError("Core did not provide new_balance".into())
        })?;
        
        let tx_record = TransactionRecord {
            tx_id: txid,
            produced_state_id,
            wallet_pk: transaction.client_pk.clone(),
            balance_after: new_balance,
            wallet_seq_after: new_wallet_seq,
            group_members_after: wallet_state.and_then(|ws| ws.group_members.clone()).map(|mut members| {
                if let Some(idx) = envelope.group_member_index {
                    if idx < members.len() {
                        members[idx].available = members[idx].available
                            .saturating_sub(transaction.amount);
                    }
                }
                members
            }),
            is_genesis_claim: Some(transaction.is_genesis_claim()),
            status: WalletStateStatus::Pending,  // PENDING until ACK
            required_k: transaction.required_k,
            proof_type: transaction.proof_type,
            amount: transaction.amount,
            sender_balance: wallet_state.map(|ws| ws.balance).unwrap_or(0),
        };
        self.storage.store_transaction_record(&tx_record)?;
        debug!("k={} stored PENDING tx record: vid={} produced_state_id={} balance={} seq={}",
              transaction.required_k,
              hex::encode(&self.validator_id[..4]),
              hex::encode(&produced_state_id[..8]), new_balance, new_wallet_seq);

        // YP §20.8 v3.x: no per-TX fee IOU; ACK gates on transaction_records.

        // ALSO update the sender's WalletState
        // This is critical for redeem to find the correct wallet_seq
        // For group wallets: carry forward group_members, deducting from member's available
        let updated_group_members = if let Some(ws) = wallet_state {
            ws.group_members.as_ref().map(|members| {
                let mut updated = members.clone();
                // If this was a group wallet withdrawal, deduct amount from the member
                if let Some(idx) = envelope.group_member_index {
                    if idx < updated.len() {
                        info!("GROUP DEDUCT: member[{}] available {} → {} (amount={})",
                              idx, updated[idx].available,
                              updated[idx].available.saturating_sub(transaction.amount),
                              transaction.amount);
                        updated[idx].available = updated[idx].available.saturating_sub(transaction.amount);
                    }
                } else {
                    info!("GROUP: no group_member_index, not deducting from any member");
                }
                updated
            })
        } else {
            None
        };
        
        // Build FACT link for this transaction — append to sender's existing chain.
        // sender_fact was already fetched above and verified by Core CL3.
        // Use Core's compressed FACT chain if available. Core is the sole
        // authority for FACT compression (Dilithium checkpoint signing).
        let existing_fact = if let Some(compressed) = proof.outputs.compressed_fact_chain.clone() {
            Some(compressed)
        } else {
            envelope.sender_fact_chain.clone()
        };
        let existing_fact_for_storage = existing_fact.clone();
        // Build receiver contact for scar healing propagation
        // wallet_id format: "email/hex8" — extract email from it
        let receiver_contact = {
            let wid = &transaction.receiver_wallet_id;
            let email = if let Some(slash) = wid.rfind('/') {
                wid[..slash].to_string()
            } else {
                wid.clone() // fallback: use whole wallet_id as email
            };
            Some(axiom_core_logic::types::ReceiverContact {
                wallet_id: wid.clone(),
                email,
            })
        };
        // eprintln!("[TIMING] finalize_transaction: about to call build_fact_link with {} sigs", fact_witness_sigs.len());
        // Build FACT link if we have k=3 valid FACT sigs for THIS transaction.
        // 
        // NON-FATAL: When overlapped_signatures from the previous receipt push
        // all_sigs.len() >= 3 at an early validator (V1), that validator has only
        // 1 valid FACT sig (its own). The other 2+ are stale (for previous TX).
        // In this case, we still produce the receipt but return None for the FACT chain.
        // The later validator (V3) will have accumulated enough current-TX
        // FACT sigs to build the complete link.
        // YPX-018 heal-forward: when is_heal=true, start a fresh FACT chain
        // with just the heal link. The pre-heal chain can't be extended (its
        // tip is at X_prev, the heal consumed X_pending — discontinuity).
        // The heal link has valid Core-signed Dilithium fact_signatures, so
        // Core's verify_fact_chain accepts the 1-link chain with full
        // signature verification. No Core boundary change needed.
        //
        // YPX-022 RECALL (2026-07-06 forward redesign): recall is NO LONGER here.
        // It is a standard forward self-send consuming the wallet's CURRENT tip,
        // so its FACT link extends the existing chain exactly like any send
        // (tip == produced_state_id). The old fresh-chain branch was needed only
        // by the re-anchor (which consumed the pre-send state, off the tip) — that
        // model is gone.
        let heal_existing = if transaction.is_heal() {
            None
        } else {
            existing_fact.as_ref()
        };

        // [CHAIN-EXTEND DIAG] paired with SDK's [CHAIN-RECV DIAG] on the
        // send/redeem extraction path. Match by `txid[..8]` across the
        // Lambda subprocess log and the SDK subprocess log. If
        // `chain_in` differs from `chain_out` by 1, Lambda extended
        // correctly. If they match (no growth), Core's `build_fact_link`
        // returned the unchanged chain and the SDK ends up storing a
        // chain whose tip is the OLD link — every subsequent register's
        // conf then attaches to that wrong tip via
        // `update_fact_chain_confirmation`. Pre-NET-fix this was the
        // residual 20% FactInvalidSignature class
        // (`docs/AXIOM_HANDOFF_FactConfRace.md`).
        eprintln!(
            "[CHAIN-EXTEND DIAG BEFORE] txid={} chain_in={} is_heal={} is_genesis={} produced_state[..8]={}",
            hex::encode(&txid[..8]),
            heal_existing.map(|c| c.links.len()).unwrap_or(0),
            transaction.is_heal(),
            transaction.is_genesis_claim(),
            hex::encode(&produced_state_id[..8]),
        );

        // Diagnostic for the genesis-self-redeem soak failure (v53x):
        // log fact_witness_sigs status BEFORE build_fact_link so we can
        // see whether each WitnessSig actually carries a fact_signature.
        // build_fact_link skips sigs without fact_signature, so missing
        // ones manifest as FactInsufficientWitnesses → updated_fact_chain
        // = None → V3 response carries no chain → wallet has no chain
        // → self-redeem fails E_REDEEM_SENDER_ANCHOR_MISSING.
        let sigs_with_fact: usize = fact_witness_sigs
            .iter()
            .filter(|s| s.fact_signature.is_some())
            .count();
        let is_genesis = transaction.is_genesis_claim();
        info!(
            "build_fact_link inputs: total_sigs={} with_fact_signature={} required_k={} \
             is_genesis={} is_heal={} txid={} existing_chain_links={} compressed_present={}",
            fact_witness_sigs.len(),
            sigs_with_fact,
            proof.outputs.required_k,
            is_genesis,
            transaction.is_heal(),
            hex::encode(&txid[..8]),
            heal_existing.map(|c| c.links.len()).unwrap_or(0),
            proof.outputs.compressed_fact_chain.is_some(),
        );
        if sigs_with_fact < (proof.outputs.required_k as usize) {
            warn!(
                "build_fact_link will fail: only {}/{} sigs have fact_signature \
                 (genesis={} heal={}). Per-sig status:",
                sigs_with_fact, proof.outputs.required_k,
                is_genesis, transaction.is_heal(),
            );
            for (i, sig) in fact_witness_sigs.iter().enumerate() {
                warn!(
                    "  fact_witness_sigs[{}] vid={} fact_sig={} vbc_bundle={}",
                    i,
                    hex::encode(&sig.validator_id[..4]),
                    if sig.fact_signature.is_some() { "PRESENT" } else { "NONE" },
                    if sig.vbc_bundle.is_some() { "PRESENT" } else { "NONE" },
                );
            }
        }

        // Core builds the FactLink — Lambda MUST NOT create FactLinks.
        // Core verifies all Dilithium signatures and assembles the link.
        // Step 1: Core builds and verifies the FactLink (sole cryptographic authority)
        // A2: sender_anchor=None for send / heal / burn (this path).
        // CL5 redeem assembles its FactLink elsewhere via Core; Lambda's
        // build_fact_link path is reached for non-redeem TXs.
        let updated_fact_chain = match axiom_core_logic::fact::build_fact_link(
            &txid,
            &transaction.consumed_state_id,
            &produced_state_id,
            transaction.amount,
            proof.outputs.required_k,  // Core-extracted from receiver_wallet_id, not client-supplied 0
            &fact_witness_sigs,
            receiver_contact,
            transaction.burn_target_tx_id,
            None,  // sender_anchor — only redeem links use it
            // Sticky class lock — derived from the TX's sender_wallet_id.
            // Core's `build_fact_link` also enforces the chain's tip
            // matches; a heal/append onto a mis-classed chain rejects.
            // See `AXIOM_DESIGN_FactChainClassLock.md`.
            axiom_core_logic::wallet_id::is_dev_wallet(&transaction.sender_wallet_id),
            Vec::new(), // §1.5.1a: send/heal/burn links never inherit (redeem-only)
            heal_existing,
            // YPX-022 RECALL: for the recall self-send, hand Core the failed txid + its
            // Nabla attestation so Core attaches the recall_proof to the failed link,
            // resolving its scar. None for every other TX.
            if transaction.is_recall() { transaction.recall_target_tx_id } else { None },
            if transaction.is_recall() { envelope.recall_attestation.clone() } else { None },
        ) {
            Ok(chain) => {
                info!(
                    "build_fact_link OK: {} link(s) (genesis={})",
                    chain.links.len(), is_genesis,
                );
                eprintln!(
                    "[CHAIN-EXTEND DIAG AFTER] txid={} chain_out={} tip_prev[..8]={} tip_new[..8]={}",
                    hex::encode(&txid[..8]),
                    chain.links.len(),
                    chain.links.last().map(|l| hex::encode(&l.previous_state_id[..8])).unwrap_or_else(|| "NONE".into()),
                    chain.links.last().map(|l| hex::encode(&l.new_state_id[..8])).unwrap_or_else(|| "NONE".into()),
                );
                // [LINK-BUILT-DIAG] Lambda-side ground truth: dump each
                // witness's pk[..8] / sig[..8] / blake3(full sig)[..8] for
                // every link in the chain Core just assembled, before any
                // serialization to the response. Pair with the SDK's
                // `[verify_fact_link FAIL]` line (which prints the same
                // fields when the SDK rejects the stored chain) by matching
                // `txid=` across logs. If the bytes match, the wire
                // transport is innocent and the bug is in commitment
                // recomputation. If they differ, byte corruption happened
                // somewhere between here and SDK storage.
                for (li, link) in chain.links.iter().enumerate() {
                    for (wi, w) in link.witnesses.iter().enumerate() {
                        let pk_take = w.validator_pk.len().min(8);
                        let sig_take = w.signature.len().min(8);
                        let pk8 = hex::encode(&w.validator_pk[..pk_take]);
                        let sig8 = hex::encode(&w.signature[..sig_take]);
                        let sig_blake3 = blake3::hash(&w.signature);
                        let sig_blake8 = hex::encode(&sig_blake3.as_bytes()[..8]);
                        eprintln!(
                            "[LINK-BUILT-DIAG] txid={} link={} w={} val={} \
                             pk_len={} sig_len={} pk[..8]={} sig[..8]={} sig_blake3[..8]={}",
                            hex::encode(&txid[..8]),
                            li, wi,
                            hex::encode(&w.validator_id[..4]),
                            w.validator_pk.len(), w.signature.len(),
                            pk8, sig8, sig_blake8,
                        );
                    }
                }
                // Step 2: Lambda compresses + endorses checkpoint (validator's own key)
                // Bug fix: previously returned None on compress/endorse failure,
                // dropping the perfectly valid uncompressed chain Core just built.
                // For genesis (1-link chain), compress_and_endorse occasionally
                // failed at verify_and_compress's checkpoint-signing step, which
                // wiped the V3 response's sender_fact_chain → wallet had no chain
                // → self-redeem failed E_REDEEM_SENDER_ANCHOR_MISSING. Now return
                // the uncompressed chain on Err — matches the warn message's
                // stated intent ("returning uncompressed").
                let chain_for_fallback = chain.clone();
                // SEC-07: collect each witness's checkpoint co-sign of the STORED
                // provisional checkpoint so the finalizer can merge them.
                let checkpoint_endorsements: Vec<axiom_core_logic::types::FactWitness> =
                    fact_witness_sigs.iter()
                        .filter_map(|ws| ws.checkpoint_sig.clone())
                        .collect();
                match self.compress_and_endorse_fact_chain(chain, &checkpoint_endorsements, receipt.oods_flag.map_or(true, |f| f.healthy)) {
                    Ok(compressed) => Some(compressed),
                    Err(e) => {
                        warn!(
                            "FACT compress/endorse failed: {} — returning uncompressed \
                             ({} link(s), genesis={})",
                            e, chain_for_fallback.links.len(), is_genesis,
                        );
                        Some(chain_for_fallback)
                    }
                }
            }
            Err(e) => {
                // NON-FATAL: Early validators (V1, V2) may not have enough
                // current-TX FACT sigs yet. Later validator (V3) will.
                // For genesis V3 this should NOT happen — log loudly so
                // soak surfaces it immediately.
                if is_genesis {
                    error!(
                        "build_fact_link FAILED for GENESIS at finalize: {:?} \
                         (sigs={} with_fact_sig={} required_k={}). \
                         The wallet will redeem with no fact_chain → \
                         E_REDEEM_SENDER_ANCHOR_MISSING downstream.",
                        e, fact_witness_sigs.len(), sigs_with_fact,
                        proof.outputs.required_k,
                    );
                } else {
                    warn!("Core build_fact_link deferred: {:?}", e);
                }
                eprintln!(
                    "[CHAIN-EXTEND DIAG ERR] txid={} err={:?} chain_in={} → returning None",
                    hex::encode(&txid[..8]),
                    e,
                    heal_existing.map(|c| c.links.len()).unwrap_or(0),
                );
                None
            }
        };
        info!(
            "finalize_transaction result: fact_chain={} (is_genesis={}, txid={})",
            if updated_fact_chain.is_some() { "BUILT" } else { "DEFERRED" },
            is_genesis,
            hex::encode(&txid[..8]),
        );
        
        // Identity binding: preserve stored wallet_id, or establish from first TX
        let finalize_wallet_id = self.storage.get_wallet_state(&transaction.client_pk, finalize_k, finalize_pt)
            .ok().flatten().and_then(|ws| ws.wallet_id)
            .or_else(|| {
                let wid = &transaction.sender_wallet_id;
                if wid.is_empty() { None } else { Some(wid.clone()) }
            });
        let sender_state = StoredWalletState {
            public_key: transaction.client_pk.clone(),
            balance: new_balance,
            wallet_seq: new_wallet_seq,
            state_id: produced_state_id,
            last_tx_id: Some(txid),
            status: WalletStateStatus::Pending,
            group_members: updated_group_members,
            // FACT chain cached here for performance (avoids JSON bloat in requests).
            // StoredWalletState.fact_chain removed (YPX-001 §1.6 — client
            // is authoritative). updated_fact_chain / existing_fact_for_storage
            // are no longer persisted here; the client's WitnessRequest
            // carries the chain on every TX.
            auth_hash: wallet_state.and_then(|ws| ws.auth_hash),
            // YPX-020: persist the Core-produced hibernation deadline (same value
            // bound into new_state_hash) so the next send hits the CL2 gate + §15.
            hibernation_until: proof.outputs.hibernation_until,
            wallet_id: finalize_wallet_id,
        };
        self.storage.set_wallet_state(&sender_state, finalize_k, finalize_pt)?;
        
        debug!("Transaction finalized: txid={}", hex::encode(&txid[..8]));
        
        // Save pulse fields from Core outputs before returning
        let pulse_audit_request = proof.outputs.audit_request.clone();
        let pulse_nonce_challenge = proof.outputs.nonce_challenge.clone();
        let pulse_proof_data = proof.outputs.pulse_proof.clone();
        let pulse_audit_failed = proof.outputs.audit_failed;

        // Return updated chain if built, or existing chain if deferred.
        // NEVER return None when sender had a chain — preserve provenance.
        Ok((receipt, updated_fact_chain.or(existing_fact_for_storage), proof.execution_proof_bytes, zkp_nonce, proof.proof_type,
            pulse_audit_request, pulse_nonce_challenge, pulse_proof_data, pulse_audit_failed,
            proof.dmap_input_hash, proof.dmap_output_hash))
    }
    
    /// Create a ValidatorCheque for delivery to receiver
    /// 
    /// Called after witnessing a transaction. This validator's cheque
    /// will be sent to the receiver via ANTIE. Receiver must collect
    /// k such cheques before they can redeem.
    /// 
    /// Each cheque carries the sender's FACT chain (YPX-001 §1.6).
    /// All 3 validators attach the same chain independently (redundant
    /// for survivability). Core verifies it at redeem time.
    #[allow(clippy::too_many_arguments)]
    pub fn create_validator_cheque(
        &self,
        transaction: &Transaction,
        txid: [u8; 32],
        _witness_sig: &WitnessSig,  // Not used - we sign the cheque directly
        state_hash: [u8; 32],
        produced_state_id: [u8; 32],
        sender_fact_chain: Option<axiom_core_logic::types::FactChain>,
        execution_proof_bytes: &[u8],
        zkp_nonce: Option<[u8; 32]>,
        proof_type: u8,
        dmap_input_hash: [u8; 32],
        dmap_output_hash: [u8; 32],
        // YPX-002 §3.2: sender's designated Nabla node, declared in the
        // witness request. Stamped verbatim into ValidatorCheque.nabla_hint
        // for the receiver to use in §4.2 verification. Lambda does not
        // interpret this field and Core does not validate it (the cheque
        // commitment signature does not cover it).
        nabla_hint: Option<axiom_core_logic::types::NablaHint>,
    ) -> ValidatorCheque {
        use ed25519_dalek::Signer;
        
        // YPX-018 Phase 5f bug fix: use the transaction's real sender_wallet_id.
        // Pre-fix this constructed a synthetic placeholder ("sender-<hex>/00000000")
        // which broke CLARA's cheque-level self-send check AND YPX-007
        // verify_pk_binding in nabla::clara::register_clara. Real heal cheques
        // failed Nabla registration even though the protocol logic was correct.
        // The Transaction struct carries sender_wallet_id (CL1 §11.9, set by
        // the client and verified by Core's sender_wallet_id ↔ pk binding rule).
        let sender_wallet_id = transaction.sender_wallet_id.clone();

        // Create cheque structure (without signature)
        let mut cheque = ValidatorCheque {
            txid,
            validator_id: self.validator_id,
            validator_pk: self.public_key.as_bytes().to_vec(),
            signature: vec![], // Will be filled below
            execution_proof: execution_proof_bytes.to_vec(),
            vbc_bundle: self.vbc_for_signature(),
            carrier_type: self.carrier_type.clone(),
            carrier_address: self.carrier_address.clone(),
            sender_wallet_id,
            receiver_wallet_id: transaction.receiver_wallet_id.clone(),
            amount: transaction.amount,
            // Validator signs its own configured rate at cheque-issuance
            // time. Bound into the cheque commitment so the receiver's
            // Core CL5 can compute total_fee deterministically without
            // trusting any client proposal (closes
            // E_RECEIPT_COMMITMENT_MISMATCH — 2026-06-05 PM).
            // Cast u16 -> u32 to match the wire/Core type.
            rate_bps: self.fee_config.rate_bps as u32,
            reference: transaction.reference.clone(),
            epoch: transaction.epoch,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            state_hash,
            produced_state_id,
            sender_fact_chain,
            zkp_nonce,
            proof_type,
            dmap_input_hash,
            dmap_output_hash,
            // YPX-002 §3.2: sender's designated sticky Nabla, stamped at issuance
            // from the witness request. Pass-through only; never validated by Core.
            nabla_hint,
            // YPX-002 §4.6: sender's raw Ed25519 wallet_pk, stamped at issuance from
            // `transaction.client_pk`. The receiver needs this to run the `/query`
            // call in the §4.6 verification routine — Nabla's SMT is keyed on the
            // raw pubkey, and the email-format `sender_wallet_id` above is not a
            // valid Nabla lookup key. Pass-through, unsigned, advisory only.
            // `client_pk` is always 32 bytes on a well-formed Ed25519 transaction;
            // malformed TXs are rejected upstream, so we stamp None only if the
            // TryInto fails defensively rather than propagating a panic into the
            // cheque issuance path.
            sender_wallet_pk: <[u8; 32]>::try_from(transaction.client_pk.as_slice()).ok(),
            oracle_claim: {
                // Oracle claims with oracle_config.enabled=false are rejected at the
                // process_witness_request entry point (line ~1851) before reaching here.
                // This path only executes when oracle is enabled.
                let mut oc = transaction.oracle_claim.clone();
                if let Some(ref mut claim) = oc {
                    claim.payout_amount = self.oracle_config.compute_payout(
                        &claim.platform_url, claim.credit_delta,
                    );
                }
                oc
            },
            // YPX-022 RECALL (forward redesign): stamp the recalled txid on the recall
            // cheque so the receiver's Core CL5 reads it (genesis-guard exemption + the
            // SDK's is_recall_cheque discriminator). Bound into the cheque commitment
            // below (compute_cheque_commitment). None for every non-recall cheque, so a
            // normal cheque's commitment is byte-identical.
            recall_target_tx_id: if transaction.is_recall() {
                transaction.recall_target_tx_id
            } else {
                None
            },
        };

        // Sign the cheque commitment
        let commitment = self.compute_cheque_commitment(&cheque);
        let signature = self.signing_key.sign(&commitment);
        cheque.signature = signature.to_bytes().to_vec();

        cheque
    }
    
    /// Process a redeem request from receiver (NEW 6-VALIDATOR MODEL)
    /// 
    /// Receiver brings k cheques (from sender's validators) to THIS validator.
    /// This validator:
    /// 1. Verifies all k cheques are valid and consistent
    /// 2. Verifies receiver's signature
    /// 3. Signs the receiver's new state
    /// 
    /// Receiver must do this with k validators to get k witness signatures
    /// for their balance increase.
    /// Process a redeem request, with request_id idempotency.
    ///
    /// A duplicate redeem (client-side carrier duplication) that re-runs CL5
    /// hits the Nabla consume-once and returns `E_CHEQUE_ALREADY_REDEEMED`,
    /// which the wallet picks as a reject → cheque quarantined, funds consumed,
    /// receipt orphaned. Replaying the first response for the same request_id
    /// closes that. Mirror of `process_witness_request`'s dedup gate. Mac handoff
    /// 2026-07-06 (redeem side of the 2026-06-05 duplicate-cheque lesson).
    pub async fn process_redeem_request(
        &self,
        request: RedeemRequestEnvelope,
    ) -> Result<RedeemResponse, LambdaError> {
        // Replay the prior response verbatim when the same request_id arrives
        // again (before any re-execution / consume-once).
        if !request.request_id.is_empty() {
            let cache = self.redeem_idempotency_cache.lock();
            if let Some((_, resp)) = cache.iter().find(|(k, _)| k == &request.request_id) {
                // info! (not debug!) — a duplicate redeem is rare and notable: it means a
                // client resubmitted the same request_id, and this replay is what saves the
                // sender from the E_CHEQUE_ALREADY_REDEEMED quarantine. Worth a normal-level log.
                info!("[REDEEM-IDEMPOTENT-HIT] request_id={} — replaying cached response (duplicate redeem absorbed)",
                      request.request_id);
                return Ok(resp.clone());
            }
        }
        let result = self.process_redeem_request_inner(request).await;
        // Cache the first response for this request_id so a later duplicate
        // replays it instead of re-executing into E_CHEQUE_ALREADY_REDEEMED.
        if let Ok(ref response) = result {
            self.remember_redeem_response(response);
        }
        result
    }

    async fn process_redeem_request_inner(
        &self,
        request: RedeemRequestEnvelope,
    ) -> Result<RedeemResponse, LambdaError> {
        // YPX-002 P6 — simulated ingress latency (see process_witness_request).
        crate::sim_delay::maybe_sim_delay().await;

        // FACT chain auto-compress at ingress. The cheque bundle may carry
        // a top-level `fact_chain` (convenience copy) and/or per-cheque
        // FACT compression is now handled by Core (returns compressed_fact_chain
        // in PublicOutputs). Lambda no longer compresses at ingress.

        let _t0 = std::time::Instant::now();
        self.stats.redeem_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!("Processing redeem request: {}", request.request_id);

        let bundle = &request.cheque_bundle;
        
        // Step 1: Verify we have k cheques (k from receiver's address, YPX-007)
        let (redeem_k_raw, redeem_pt) = bundle.cheques.first()
            .and_then(|c| {
                axiom_core_logic::wallet_id::extract_security_level(&c.receiver_wallet_id).ok()
            })
            .unwrap_or((3, 1));  // Default: k=3, DMAP
        let redeem_k = (redeem_k_raw as usize).max(MIN_WITNESSES);
        if !bundle.has_k_cheques(redeem_k) {
            return Ok(RedeemResponse {
                request_id: request.request_id,
                success: false,
                new_balance: None,
                new_state_id: None,
                witness_signature: None,
                commitment_hash: None,
                state_hash: None,
                receipt_commitment: None,
                error_response: Some(
                    crate::error_response::static_error(
                        axiom_errors::error_code::E_INSUFFICIENT_CHEQUES,
                        axiom_errors::ErrorCategory::ProtocolReject,
                        format!("Insufficient cheques: {} < {}", bundle.cheques.len(), redeem_k),
                    )
                    .with_detail(axiom_errors::ErrorDetail::ChequeBundle(
                        axiom_errors::ChequeBundleDetail {
                            distinct_validators: bundle.cheques.len() as u8,
                            k_required: redeem_k as u8,
                            specific_field_mismatch: None,
                        },
                    )),
                ),
                validator_hints: vec![],
                fact_signature: None,
                receiver_fact_chain: None,
            });
        }
        
        // Step 1b: S-ABR overlap enforcement on redeem (2026-04-16).
        //
        // Same rule as sends: a fresh validator (no stored state for this
        // receiver) MUST NOT accept a redeem without sufficient overlap sigs.
        // Without this gate, a fresh validator accepts any replay carrying a
        // stale txid_attestation — the PART:1 gap found in soak testing.
        //
        // Two cases:
        //   OVERLAPPED (we have receiver's state in storage): proceed — we
        //     can verify state_id consistency ourselves.
        //   FRESH (no stored state): require overlap_sigs >= MIN_OVERLAP.
        //     The overlap sigs prove that overlapped validators authorized
        //     this state transition. Same trust model as S-ABR for sends.
        //
        // First-time receivers (never received before) have no stored state
        // on ANY validator → all validators are "fresh" but overlap_sigs = 0
        // is correct (genesis path, no prior state to protect).
        {
            let we_have_receiver_state = self.storage.get_wallet_state(&request.receiver_pk, redeem_k_raw, redeem_pt)
                .ok().flatten()
                .map(|ws| ws.state_id != [0u8; 32])
                .unwrap_or(false);

            if !we_have_receiver_state {
                // We are a FRESH validator for this receiver.
                let overlap_count = request.overlapped_signatures.len();
                // First-time receiver: no state anywhere → overlap_count=0 is fine
                // Returning receiver: must have overlap sigs from prev witness set
                // We can't distinguish these purely from local state (we have
                // nothing stored either way). The distinction comes from
                // whether any OTHER validator has state — but we can't ask.
                // Gate: if client provides overlap sigs, enforce minimum count.
                // If 0 sigs AND cheque receiver has never transacted with us,
                // this is either first-time (legitimate) or a replay routed
                // to avoid overlap (illegitimate). The txid_attestation check
                // downstream (Step 5) is the second line of defense.
                if overlap_count > 0 && overlap_count < Self::required_overlap(overlap_count.max(MIN_WITNESSES)) {
                    return Ok(RedeemResponse {
                        request_id: request.request_id,
                        success: false,
                        new_balance: None,
                        new_state_id: None,
                        witness_signature: None,
                        commitment_hash: None,
                        state_hash: None,
                        receipt_commitment: None,
                        error_response: Some(crate::error_response::static_error(
                            axiom_errors::error_code::E_SABR_INSUFFICIENT_OVERLAP,
                            axiom_errors::ErrorCategory::ProtocolReject,
                            format!("Redeem S-ABR: {} overlap sigs insufficient for fresh validator", overlap_count),
                        )),
                        validator_hints: vec![],
                        fact_signature: None,
                        receiver_fact_chain: None,
                    });
                }
            }
        }

        // Step 2: Verify bundle consistency (all cheques match)
        if !bundle.verify_consistency() {
            return Ok(RedeemResponse {
                request_id: request.request_id,
                success: false,
                new_balance: None,
                new_state_id: None,
                witness_signature: None,
                commitment_hash: None,
                state_hash: None,
                receipt_commitment: None,
                error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_CHEQUE_INCONSISTENT_BUNDLE, axiom_errors::ErrorCategory::RecoverableDrift, "Inconsistent cheque bundle").with_recovery(axiom_errors::RecoveryHint::DedupChequeBundle)),
                validator_hints: vec![],
                fact_signature: None,
                receiver_fact_chain: None,
            });
        }
        
        // Step 3: Verify each cheque's signature
        for cheque in &bundle.cheques {
            if !self.verify_cheque_signature(cheque)? {
                return Ok(RedeemResponse {
                    request_id: request.request_id,
                    success: false,
                    new_balance: None,
                    new_state_id: None,
                    witness_signature: None,
                    commitment_hash: None,
                    state_hash: None,
                    receipt_commitment: None,
                    error_response: Some(crate::error_response::static_error(
                        axiom_errors::error_code::E_INVALID_CHEQUE_SIG,
                        axiom_errors::ErrorCategory::ClientBug,
                        format!(
                            "Invalid cheque signature from validator {}",
                            hex::encode(&cheque.validator_pk[..8])
                        ),
                    )),
                    validator_hints: vec![],
                fact_signature: None,
                receiver_fact_chain: None,
                });
            }
        }
        
        // Step 3b: Verify cheque execution proofs (ZKP or DMAP) in production mode
        //
        // GAP-C FIX: All validators now include execution proofs in cheques.
        // Require at least 2-of-k valid proofs (Option B from security analysis).
        // This eliminates the single-proof-of-execution vulnerability where
        // compromised V1+V2 could rubber-stamp without running Core.
        if self.is_production_mode() {
            let mut verified_proof_count = 0usize;
            for cheque in &bundle.cheques {
                if cheque.execution_proof.is_empty() {
                    continue; // Skip cheques with no execution proof (legacy/pre-GAP-C)
                }

                // H3: DoS prevention — reject oversized proofs
                const MAX_PROOF_SIZE: usize = 10 * 1024 * 1024;
                if cheque.execution_proof.len() > MAX_PROOF_SIZE {
                    return Err(LambdaError::CoreValidationFailed(
                        "Cheque execution proof exceeds size limit".into()
                    ));
                }

                match cheque.proof_type {
                    0 => {
                        // ── ZKP STARK Verification ──
                        let receipt = axiom_zk_vm::ZkvmReceipt::from_bytes(&cheque.execution_proof)
                            .map_err(|e| LambdaError::CoreValidationFailed(
                                format!("Cheque ZKP decode: {}", e)
                            ))?;
                        let verifier = axiom_zk_vm::ZkvmVerifier::production()
                            .map_err(|e| LambdaError::CoreExecutionError(
                                format!("ZkvmVerifier: {}", e)
                            ))?;
                        let outputs = verifier.verify(&receipt)
                            .map_err(|e| LambdaError::CoreValidationFailed(
                                format!("Cheque ZKP invalid: {}", e)
                            ))?;

                        // Layer 1: A valid proof of Reject is still a failure
                        if outputs.result != axiom_core_logic::ValidationResult::Accept {
                            return Err(LambdaError::CoreValidationFailed(
                                "Cheque ZKP: proof valid but logic rejected".into()
                            ));
                        }

                        // Layer 2: ZKP nonce binding — proof must match this cheque's nonce
                        if let Some(ref nonce) = cheque.zkp_nonce {
                            let expected_hash = {
                                let mut h = blake3::Hasher::new();
                                h.update(b"AXIOM_ZKP_NONCE");
                                h.update(nonce);
                                *h.finalize().as_bytes()
                            };
                            match outputs.zkp_nonce_hash {
                                Some(h) if h == expected_hash => {}
                                _ => {
                                    return Err(LambdaError::CoreValidationFailed(
                                        "Cheque ZKP: nonce mismatch — possible replay".into()
                                    ));
                                }
                            }
                        }
                        verified_proof_count += 1;
                    }
                    1 => {
                        // ── DMAP Attestation Verification (proof_type 1) ──
                        // Extracted to `verify_cheque_dmap_attestation` so the exact
                        // redeem-side DMAP gate (incl. the CoreID lineage accept-set) is
                        // unit-testable without a full redeem request.
                        self.verify_cheque_dmap_attestation(cheque)?;
                        verified_proof_count += 1;
                    }
                    unknown => {
                        return Err(LambdaError::CoreValidationFailed(
                            format!("Cheque: unknown proof type {}", unknown)
                        ));
                    }
                }
            }

            // GAP-C: Require at least 2-of-k valid execution proofs.
            // All validators run Core CL3 via produce_witness_dmap and include
            // DMAP attestations in their cheques. This prevents compromised
            // validators from rubber-stamping without running Core.
            let min_proofs = if bundle.cheques.len() >= 3 { 2 } else { 1 };
            if verified_proof_count < min_proofs {
                return Err(LambdaError::CoreValidationFailed(
                    format!("Only {} valid execution proofs — need at least {} for k={} consensus",
                            verified_proof_count, min_proofs, bundle.cheques.len())
                ));
            }
        }

        // Step 3c: Verify cheque's receiver_wallet_id is a valid wallet address
        // The wallet_id checksum uses the protocol-wide WALLET_IDENTITY_KEY, not the receiver's PK.
        // This check validates the address format — the receiver_sig check (Step 4) verifies
        // the receiver actually owns the private key.
        if let Some(cheque_receiver_wid) = bundle.receiver_wallet_id() {
            if axiom_core_logic::wallet_id::validate_wallet_id(cheque_receiver_wid).is_err() {
                return Ok(RedeemResponse {
                    request_id: request.request_id,
                    success: false,
                    new_balance: None,
                    new_state_id: None,
                    witness_signature: None,
                    commitment_hash: None,
                    state_hash: None,
                    receipt_commitment: None,
                    error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_INVALID_WALLET_ID, axiom_errors::ErrorCategory::ClientBug, "Invalid receiver_wallet_id")),
                    validator_hints: vec![],
                    fact_signature: None,
                    receiver_fact_chain: None,
                });
            }
        }

        // Step 4a: REMOVED (2026-05-01).
        //
        // Previously blocked sender from redeeming own cheques. Removed because:
        // 1. Core CL5 already verifies receiver_pk binds to cheque.receiver_wallet_id
        //    — sender PK doesn't match receiver's cheque → CL5 rejects
        // 2. try_mark_cheque_redeemed(txid) prevents same-cheque double-redeem
        // 3. Nabla txid bloom prevents cross-validator replay
        //
        // Step 4a was redundant for normal TXs (three layers already prevent it)
        // and broke genesis claims (§17.11 — legitimate self-sends).
        let txid = bundle.txid().ok_or_else(||
            LambdaError::InvalidRequest("Cheque bundle has no consistent txid".into())
        )?;

        // Step 4b: Verify wallet ownership via CL5 DMAP proof OR wallet_secret checksum.
        // The client proves they own the receiver_wallet_id by providing a DMAP proof
        // that CL5 accepted with their wallet_secret (which produces the correct checksum).
        // The wallet_secret never leaves the client — only the proof travels.
        //
        // H3 FIX: Recompute expected CL5 input_hash from the actual redeem request data,
        // NOT the attestation's self-declared hashes (tautological). Same pattern as
        // GAP-B fix for cheque DMAP proofs (lines 3841-3857).
        // For output_hash: accept attestation's value — CoreID + Merkle proofs + input
        // binding already prove the correct CL5 code ran with the correct inputs.
        // §15: CL5 execution proof — MANDATORY. No exceptions. No fallback.
        // No "if present." No signature-only legacy path. Every redeemer
        // MUST run Core CL5 locally and attach a valid DMAP proof. Without
        // this, a stale or malicious client can submit redeems that Lambda
        // processes by falling back to zero-state — feeding Core different
        // inputs across validators and producing divergent witness sigs.
        // Mirror of the CL1 gate at line 2421. See CLAUDE.md §15.
        if request.cl5_execution_proof.is_empty() {
            return Ok(RedeemResponse {
                request_id: request.request_id,
                success: false,
                new_balance: None,
                new_state_id: None,
                witness_signature: None,
                commitment_hash: None,
                state_hash: None,
                receipt_commitment: None,
                error_response: Some(crate::error_response::static_error(
                    axiom_errors::error_code::E_LAMBDA_CL5_PROOF_MISSING,
                    axiom_errors::ErrorCategory::ClientBug,
                    "CL5: missing execution proof — client must run Core CL5 locally (§15)".to_string(),
                )),
                validator_hints: vec![],
                fact_signature: None,
                receiver_fact_chain: None,
            });
        }
        {
            // Verify DMAP attestation structurally (CoreID + Merkle proofs).
            // CBOR (writer: lambda/src/core_client.rs ~459).
            match ciborium::de::from_reader::<axiom_dmap_vm::dmap::DmapAttestation, _>(&request.cl5_execution_proof[..]) {
                Ok(attestation) => {
                    // H3 FIX: Reconstruct the expected CL5 PublicInputs from the actual
                    // redeem request data. The client builds these inputs the same way
                    // (see webclient/src/avm_bridge.rs:320-382). Lambda recomputes the
                    // input_hash to ensure this proof is bound to THIS exact request,
                    // not a recycled proof from a different redeem.
                    use axiom_core_logic::types::{PublicInputs, Transaction};
                    use axiom_core_logic::CoreLogicMode;

                    // §15: NO `.unwrap_or(0)` fallback. If the client did not
                    // attach `current_state`, the redeem MUST reject — Lambda
                    // computing on zero-state forces Core to see different
                    // inputs than any other validator that does have storage,
                    // which is exactly the divergence vector documented in
                    // AXIOM_HANDOFF_MacClientStaleState.md.
                    let cl5_state = match request.current_state.as_ref() {
                        Some(s) => s,
                        None => {
                            return Ok(RedeemResponse {
                                request_id: request.request_id,
                                success: false,
                                new_balance: None,
                                new_state_id: None,
                                witness_signature: None,
                                commitment_hash: None,
                                state_hash: None,
                                receipt_commitment: None,
                                error_response: Some(crate::error_response::static_error(
                                    axiom_errors::error_code::E_MISSING_WALLET_STATE,
                                    axiom_errors::ErrorCategory::ClientBug,
                                    "CL5: missing current_state — client must supply wallet state, no fallback (§15)".to_string(),
                                )),
                                validator_hints: vec![],
                                fact_signature: None,
                                receiver_fact_chain: None,
                            });
                        }
                    };

                    // Consolidated CL5 attestation-input builder (CLAUDE.md
                    // §12 — 6th mirror-struct instance closed 2026-06-04 PM-3).
                    // Both Lambda's expected_input_hash recompute (here) AND
                    // the SDK's run_cl5 (sdk/client/src/cl5.rs) call this same
                    // function so the BLAKE3(ciborium::into_writer(&inputs))
                    // values are byte-identical by construction. Pre-
                    // consolidation, this site stripped cheque_claim_proof
                    // and txid_attestation to None — but Core CL5 requires
                    // both to accept, so every SDK run_cl5 rejected locally
                    // with ChequeClaimProofMissing and shipped an empty proof.
                    let cl5_inputs = axiom_core_logic::cl5_inputs::build_cl5_attestation_inputs(
                        &request.receiver_pk,
                        bundle,
                        cl5_state.balance,
                        cl5_state.wallet_seq,
                        cl5_state.hibernation_until, // YPX-020 — carry receiver's stored hibernation
                        cl5_state.state_id,
                        request.cheque_claim_proof.clone(),
                        request.txid_attestation.clone(),
                        request.oods_attestation.clone(), // YPX-021 §8.2 — same request-carried value the SDK hashed
                        self.expected_core_id,
                    );

                    // CBOR not JSON — [[feedback_no_json_in_protocol_path]].
                    // MUST stay byte-equivalent to the SDK's hash bytes at
                    // sdk/client/src/cl5.rs:run_cl5. Both use ciborium::into_writer
                    // on the same shared `build_cl5_attestation_inputs`
                    // output.
                    let expected_input_hash = {
                        let mut buf = Vec::new();
                        ciborium::into_writer(&cl5_inputs, &mut buf)
                            .expect("CBOR encode CL5 expected inputs");
                        *blake3::hash(&buf).as_bytes()
                    };

                    // Use recomputed input_hash, NOT the attestation's self-declared one.
                    // For output_hash: CoreID + input binding + Merkle proofs already
                    // prove the correct CL5 code ran with the correct inputs. The output
                    // is deterministic given the inputs, so binding the inputs is sufficient.
                    let verify_input = &expected_input_hash;
                    let verify_output = &attestation.output_hash;

                    // §15: the SDK now produces this attestation (receiver
                    // runs Core CL5 locally and signs with the wallet's
                    // Ed25519 key). The pre-§15 comment "we produced this
                    // ourselves, so our PK is the trusted identity" was
                    // stale — it referred to the validator-side cheque
                    // attestation, not the redeem-side CL5 attestation.
                    // Verify against the receiver's pk, which is what
                    // signed the attestation. CLAUDE.md §15.
                    let receiver_pk_arr: [u8; 32] = {
                        let mut arr = [0u8; 32];
                        let n = request.receiver_pk.len().min(32);
                        arr[..n].copy_from_slice(&request.receiver_pk[..n]);
                        arr
                    };
                    // CoreID-lineage accept-set (mirrors the sender site above): verify against
                    // the blessed CoreID the attestation was built with; a non-accepted CoreID
                    // resolves to self.expected_core_id → WrongCore. §11 (shared resolver).
                    let verify_core_id = axiom_core_logic::version::resolve_dmap_verify_core_id(
                        &attestation.core_id, &self.expected_core_id,
                    );
                    let result = axiom_dmap_vm::dmap::verify_dmap_attestation(
                        &attestation,
                        &verify_core_id,
                        verify_input,
                        verify_output,
                        &receiver_pk_arr,
                    );
                    if result != axiom_dmap_vm::dmap::DmapResult::Valid {
                        return Ok(RedeemResponse {
                            request_id: request.request_id,
                            success: false,
                            new_balance: None,
                            new_state_id: None,
                            witness_signature: None,
                            commitment_hash: None,
                            state_hash: None,
                            receipt_commitment: None,
                            error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_LAMBDA_CL5_PROOF_INVALID, axiom_errors::ErrorCategory::ClientBug, format!("Invalid CL5 wallet ownership proof: {:?}", result))),
                            validator_hints: vec![],
                            fact_signature: None,
                            receiver_fact_chain: None,
                        });
                    }
                    debug!("CL5 wallet ownership DMAP proof verified (H3: input-hash bound)");
                }
                Err(e) => {
                    return Ok(RedeemResponse {
                        request_id: request.request_id,
                        success: false,
                        new_balance: None,
                        new_state_id: None,
                        witness_signature: None,
                        commitment_hash: None,
                        state_hash: None,
                        receipt_commitment: None,
                        error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_LAMBDA_CL5_PROOF_MALFORMED, axiom_errors::ErrorCategory::ClientBug, format!("Malformed CL5 proof: {}", e))),
                        validator_hints: vec![],
                        fact_signature: None,
                        receiver_fact_chain: None,
                    });
                }
            }
        }
        // §15: the "legacy mode (signature-only)" fallback that used to live
        // here has been deleted. CL5 proof is mandatory at the top of this
        // block. CLAUDE.md §15.

        // Step 4c: Verify receiver's signature proves key ownership
        if !self.verify_redeem_signature(&request, &txid)? {
            return Ok(RedeemResponse {
                request_id: request.request_id,
                success: false,
                new_balance: None,
                new_state_id: None,
                witness_signature: None,
                commitment_hash: None,
                state_hash: None,
                receipt_commitment: None,
                error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_INVALID_CLIENT_SIG, axiom_errors::ErrorCategory::ClientBug, "Invalid receiver signature")),
                validator_hints: vec![],
                fact_signature: None,
                receiver_fact_chain: None,
            });
        }
        
        // Step 5: Atomically check-and-mark cheque as redeemed (INV-04 race fix)
        // AUDIT-FIX v2.11.13: Uses try_mark_cheque_redeemed() — single mutex lock
        // for both check and mark. Prevents concurrent double-redeem race condition.
        let my_pk_hex = hex::encode(&self.public_key.as_bytes()[..8]);
        debug!("Validator {} checking if cheque already redeemed: txid={}", my_pk_hex, hex::encode(&txid[..8]));
        if !self.storage.try_mark_cheque_redeemed(&txid)? {
            debug!("Validator {} REJECTING: Cheque {} was already redeemed", my_pk_hex, hex::encode(&txid[..8]));
            return Ok(RedeemResponse {
                request_id: request.request_id,
                success: false,
                new_balance: None,
                new_state_id: None,
                witness_signature: None,
                commitment_hash: None,
                state_hash: None,
                receipt_commitment: None,
                error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_CHEQUE_ALREADY_REDEEMED, axiom_errors::ErrorCategory::ProtocolReject, "Cheque already redeemed")),
                validator_hints: vec![],
                fact_signature: None,
                receiver_fact_chain: None,
            });
        }
        debug!("Validator {} - cheque {} not yet redeemed locally, verifying Nabla attestation", my_pk_hex, hex::encode(&txid[..8]));

        // Step 5a: GLOBAL double-redeem check via client-provided Nabla attestation.
        //
        // Architecture: CLIENT queries Nabla, validator VERIFIES.
        // Lambda MUST NOT talk to Nabla directly (except TARDIS via Core).
        //
        // The client fetches a signed NablaTxidAttestation from Nabla via
        // the TCP-CBOR `WireMessage::QueryTxidRequest` wire and includes it
        // in the redeem request.
        // Lambda verifies the Nabla node's Ed25519 signature and checks
        // the status. If REDEEMED → reject. If missing → reject (required).
        //
        // This closes the cross-validator double-redeem gap: each validator
        // only sees its own redeemed_cheques table (local), but Nabla's
        // txid_index is the GLOBAL truth.
        {
            let attestation = match &request.txid_attestation {
                Some(att) => att,
                None => {
                    self.storage.unmark_cheque_redeemed(&txid).ok();
                    return Ok(RedeemResponse {
                        request_id: request.request_id,
                        success: false,
                        new_balance: None,
                        new_state_id: None,
                        witness_signature: None,
                        commitment_hash: None,
                        state_hash: None,
                        receipt_commitment: None,
                        error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_TXID_ATTESTATION_MISSING, axiom_errors::ErrorCategory::ClientBug, "Txid attestation missing")),
                        validator_hints: vec![],
                        fact_signature: None,
                        receiver_fact_chain: None,
                    });
                }
            };

            // Verify txid matches
            if attestation.txid != txid {
                self.storage.unmark_cheque_redeemed(&txid).ok();
                return Ok(RedeemResponse {
                    request_id: request.request_id,
                    success: false,
                    new_balance: None,
                    new_state_id: None,
                    witness_signature: None,
                    commitment_hash: None,
                    state_hash: None,
                    receipt_commitment: None,
                    error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_ATTESTATION_TXID_MISMATCH, axiom_errors::ErrorCategory::ClientBug, "Attestation txid does not match cheque txid")),
                    validator_hints: vec![],
                    fact_signature: None,
                    receiver_fact_chain: None,
                });
            }

            // Signature + status + trust anchor verification in Core CL5 (RISC-V ELF).
            // NO TIMEOUT-BASED FRESHNESS CHECK.
            //
            // AXIOM is designed for broken/slow networks (SMTP transport). A timeout
            // is fundamentally incompatible — delivery can take minutes or hours.
            // The attestation's nabla_tick is informational (logged), not enforced.
            //
            // Protection against stale attestation replay is provided by LOGIC, not timeouts:
            //   1. Core CL5: signature + status + NBC trust anchor (can't forge)
            //   2. Local: try_mark_cheque_redeemed (same-validator replay)
            //   3. S-ABR: honest validators reject spending without overlap
            //   4. FACT + Nabla ban: double-redeemed money is trapped
            // See docs/AXIOM_REPORT_DoubleRedeem.md — all four layers are
            // independent of timing. An attacker with a cached attestation still
            // can't spend the double-redeemed money through honest validators.
            // Core is authoritative (RISC-V ELF). Lambda only checks freshness (needs clock).
            debug!("Nabla txid attestation present: status={}, tick={} — Core CL5 will verify",
                   attestation.status, attestation.nabla_tick);

            // ════════════════════════════════════════════════════════════
            // Canonical reject-code precedence (YP §17.10.5.x — 2026-05-15)
            //
            // When the txid attestation says REDEEMED, this is a
            // deterministic protocol-level reject.  Emit it BEFORE the
            // receiver_state defense-in-depth check at Step 5b below,
            // so all validators converge on the SAME error code
            // regardless of how far each one's local receiver-state
            // gossip has caught up.
            //
            // Pre-fix behavior: a validator whose receiver_state had
            // already advanced past client_state (gossip ahead of
            // peers) emitted E_LAMBDA_RECEIVER_STATE_DRIFT, while
            // peers still on the prior state emitted
            // E_TXID_ATTESTATION_REDEEMED via Core CL5.  Same outcome
            // (reject), different reason code, hard to triage during
            // incident response.  Observed once in the 2026-05-15
            // 50w1h soak (s2r38036) — see report A−/B+ analysis.
            //
            // Sig verification still happens in Core CL5 (defense in
            // depth); this short-circuit only fires on the cheap
            // status-string match, which a forged attestation can't
            // exploit because forging "REDEEMED" only denies your own
            // redeem — no attack vector.
            //
            // Companion check at Core CL5: core/logic/src/modes.rs
            // line ~1639 (TxidAttestationRedeemed).  Both must stay
            // in sync; if you change one, change both.
            // ════════════════════════════════════════════════════════════
            if attestation.status.as_str() == "REDEEMED" {
                self.storage.unmark_cheque_redeemed(&txid).ok();
                return Ok(RedeemResponse {
                    request_id: request.request_id,
                    success: false,
                    new_balance: None,
                    new_state_id: None,
                    witness_signature: None,
                    commitment_hash: None,
                    state_hash: None,
                    receipt_commitment: None,
                    error_response: Some(crate::error_response::static_error(
                        axiom_errors::error_code::E_TXID_ATTESTATION_REDEEMED,
                        axiom_errors::ErrorCategory::ProtocolReject,
                        "Txid already redeemed (Nabla attestation)",
                    )),
                    validator_hints: vec![],
                    fact_signature: None,
                    receiver_fact_chain: None,
                });
            }
        }

        // Step 5b: Verify receiver's current_state against stored state (INV-04 defense-in-depth)
        // If the validator's stored state is AHEAD of the client's (higher wallet_seq or
        // different state_id with higher seq), the receiver already redeemed elsewhere.
        // If the validator is BEHIND the client (lower wallet_seq or genesis), that's OK —
        // this validator simply wasn't in the previous redeem set. The CAS guard at write
        // time provides the actual concurrency protection.
        if let Some(ref client_state) = request.current_state {
            if let Ok(Some(stored)) = self.storage.get_wallet_state(&request.receiver_pk, redeem_k_raw, redeem_pt) {
                if stored.state_id != client_state.state_id
                    && stored.wallet_seq > client_state.wallet_seq
                {
                    warn!("Redeem rejected: receiver state_id mismatch — validator is AHEAD \
                           (possible double-redeem). stored_seq={} client_seq={}",
                          stored.wallet_seq, client_state.wallet_seq);
                    return Ok(RedeemResponse {
                        request_id: request.request_id,
                        success: false,
                        new_balance: None,
                        new_state_id: None,
                        witness_signature: None,
                        commitment_hash: None,
                        state_hash: None,
                        receipt_commitment: None,
                        error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_LAMBDA_RECEIVER_STATE_DRIFT, axiom_errors::ErrorCategory::RecoverableDrift, "Receiver state has changed").with_recovery(axiom_errors::RecoveryHint::ClaraHealNextSend)),
                        validator_hints: vec![],
                        fact_signature: None,
                        receiver_fact_chain: None,
                    });
                }
            }
        }

        // Step 6: Determine receiver's current state
        // 
        // CRITICAL FOR CONSISTENCY: All validators must compute the same new_state_id.
        // If client provides current_state, use it - this ensures all validators
        // use the same starting balance. The state_id in current_state cryptographically
        // commits to the balance, so clients can't lie.
        //
        // S-ABR verification happens through the standard Core strip/Lambda refill/Core
        // verify mechanism — NOT through explicit balance checks here.
        // The CLIENT must route redeem to validators overlapped with the receiver's
        // last receipt. Those validators have the receiver's state in storage.
        //
        // §15: `request.current_state` is now guaranteed Some by the CL5
        // mandatory-proof + missing-state gate above. The pre-§15 "fall back
        // to local state if client doesn't provide one" branch is gone —
        // first-time receivers must still ship a zero-valued WalletState
        // (state_id=[0u8;32], balance=0, wallet_seq=0) so every validator
        // computes from the same authoritative input. CLAUDE.md §15.
        let client_state = request.current_state.as_ref()
            .expect("§15: current_state guaranteed Some by CL5 gate above");
        debug!("Using client-provided state for receiver: balance={}, seq={}",
              client_state.balance, client_state.wallet_seq);
        // Preserve existing auth_hash from receiver's stored state (if any).
        // Redeem must NOT clear the receiver's stolen-key protection.
        let existing_auth = self.storage.get_wallet_state(&request.receiver_pk, redeem_k_raw, redeem_pt)
            .ok().flatten().and_then(|ws| ws.auth_hash);
        let receiver_state = Some(StoredWalletState {
            public_key: request.receiver_pk.clone(),
            balance: client_state.balance,
            wallet_seq: client_state.wallet_seq,
            state_id: client_state.state_id,
            last_tx_id: None,
            status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: existing_auth, hibernation_until: 0,
            wallet_id: None,
        });

        // Capture receiver's LOCAL pre-redeem state_id for CAS guard at storage time.
        // Used to detect concurrent redeems (state_id changed between read and write).
        // MUST use locally stored state — NOT client-provided state — because this
        // validator may be behind (wasn't in the receiver's previous redeem set).
        // The CAS protects against concurrent writes on THIS validator, so it must
        // compare against what THIS validator currently has in its DB.
        let local_receiver = self.storage.get_wallet_state(&request.receiver_pk, redeem_k_raw, redeem_pt)
            .ok().flatten();
        let pre_redeem_state_id = local_receiver.as_ref()
            .map(|s| s.state_id)
            .unwrap_or([0u8; 32]);

        // Get accurate wallet_seq from TransactionRecord if available
        let latest_seq = if let Some(ref state) = receiver_state {
            if let Ok(Some(record)) = self.storage.get_transaction_record(&state.state_id) {
                record.wallet_seq_after
            } else {
                state.wallet_seq
            }
        } else {
            0
        };
        
        // Step 7: Calculate new balance — receiver-pays NET.
        //
        // The receiver's NET balance is `current + amount - total_fee`,
        // where `total_fee = sum(request.fee_breakdown[i].amount)`.
        // All k witnesses MUST compute the same NET to agree on
        // `produced_state_id` (which feeds the FactCommitment they all
        // Dilithium-sign); the SDK ships its proposed `fee_breakdown`
        // in the redeem request envelope so every witness — and the
        // DMAP recompute path above — sees the same total.
        //
        // total_fee derives from the Dilithium-signed cheques themselves
        // (each carries `rate_bps`). Lambda mirrors what Core CL5 will
        // compute downstream so the receiver's new_balance Lambda stores
        // matches the value Core binds into produced_state_id /
        // state_hash / receipt_commitment. Empty bundle defaults to
        // total_fee=0 (heals + genesis self-redeem path).
        let amount = bundle.amount().ok_or_else(||
            LambdaError::InvalidRequest("Cheque bundle has no consistent amount".into())
        )?;
        let total_fee: u64 = bundle.cheques.iter()
            .map(|c| axiom_core_logic::validation::expected_fee_slot_amount(
                c.amount, c.rate_bps,
            ))
            .sum();
        let receiver_state_id = receiver_state.as_ref().map(|s| s.state_id);
        let current_balance = receiver_state.as_ref().map(|s| s.balance).unwrap_or(0);
        let (new_balance, new_seq) = if let Some(current) = receiver_state {
            // Existing wallet - add cheque amount, subtract receiver-pays fees
            let new_balance = current.balance
                .saturating_add(amount)
                .saturating_sub(total_fee);
            let new_seq = latest_seq; // Use latest seq from TransactionRecord
            (new_balance, new_seq)
        } else {
            // New wallet - first credit is `amount - total_fee`
            let new_balance = amount.saturating_sub(total_fee);
            let new_seq = 0;
            (new_balance, new_seq)
        };
        
        // FACT chain verification happens inside Core CL5 (Step 4b).
        // Core's chain pointer is: bundle.fact_chain → first cheque.sender_fact_chain →
        // Lambda's fallback below (stored as PublicInputs.sender_fact_chain).
        //
        // Lambda resolves the FALLBACK tier only — see `cl5_resolved_fact_chain` after Core runs.
        // Third fallback (Lambda-side StoredWalletState.fact_chain cache)
        // removed per YPX-001 §1.6 — client is authoritative. If neither
        // the cheque bundle nor the receiver's WitnessRequest carries the
        // chain, Core operates without it.
        let sender_fact_chain = bundle.fact_chain.clone()
            .or_else(|| request.receiver_fact_chain.clone());

        // Step 7b: CORE VALIDATION - Core is the cryptographic gatekeeper
        // Core validates: k=3 cheques, consistency, balance math
        // AND MOST IMPORTANTLY: Core computes the new_state_id AND signs FACT!
        let redeem_proof = {
            let core = self.core.write().await;
            // Receiver's existing FACT chain — Core appends the redeem
            // link onto this when our CL5 is the finalizer (k-of-k sigs
            // gathered). The SDK ships it on the redeem request.
            let receiver_fact_chain = request.receiver_fact_chain.clone();
            // Prior validators' FACT WitnessSigs accumulated for this
            // redeem TX. Read from the dedicated `fact_witness_sigs`
            // field (NOT `overlapped_signatures` — the latter is the
            // S-ABR overlap proof on the send path, over a different
            // commitment with a different signature algorithm). Core's
            // CL5 uses these (plus the locally produced sig) to assemble
            // the FactLink when this validator is the finalizer.
            let prior_fact_sigs = request.fact_witness_sigs.clone();
            // UMP-safe call: pass the envelope by reference, let
            // core_client::validate_redeem source every wire field
            // from it directly. The remaining args are Lambda-computed
            // values (balances, chain pointers) + Lambda crypto. A
            // future envelope field added to RedeemRequestEnvelope
            // does NOT need to be threaded through this call site.
            //
            // `prior_fact_sigs` is `request.fact_witness_sigs.clone()`
            // — folded into the envelope reference inside
            // validate_redeem; no longer a separate arg.
            let _ = prior_fact_sigs;
            core.validate_redeem(
                &request,
                current_balance,
                new_seq,
                new_balance,
                sender_fact_chain.clone(),
                receiver_state_id,
                receiver_fact_chain,
                Some(self.dilithium_sk.clone()),
                Some(self.dilithium_pk.clone()),
                Some(self.validator_id),
                Some(self.vbc_bundle()),
            )?
        };

        // Canonical FACT chain pointer for CL5 (must match modes::execute_cl5 Step 4b).
        // `sender_fact_chain` above is ONLY the Lambda → PublicInputs fallback (tier 3).
        // Core prefers bundle.fact_chain, then each cheque's sender_fact_chain, then that fallback.
        // Host mirrors and stored-wallet chain selection must NOT use tier-3 alone.
        let cl5_resolved_fact_chain =
            axiom_core_logic::fact::redeem_fact_chain_ref(bundle, &sender_fact_chain).cloned();

        // Get the state_id that CORE computed (not Lambda!)
        let new_state_id = redeem_proof.new_state_id;

        debug!("Core validated redeem: {} + {} = {}, state_id={}",
               current_balance, amount, new_balance,
               hex::encode(&new_state_id[..8]));

        // DIAG: print exactly what Core CL5 fed to compute_fact_commitment.
        // Core runs in the AVM (no_std) so its own eprintln won't reach
        // Lambda's stderr — recompute on the host with the same inputs
        // CL5 used (modes.rs:1942) and print here so we can directly
        // compare against the SDK's [build_fact_bridge] line. If the
        // commitment hex differs, one of the 5 fields below diverges
        // from what the SDK assembled in build_and_append_fact_bridge.
        {
            let cl5_txid = bundle.txid().unwrap_or([0u8; 32]);
            let cl5_prev = request.current_state.as_ref()
                .map(|s| s.state_id).unwrap_or([0u8; 32]);
            let cl5_anchor = axiom_core_logic::fact::redeem_fact_sender_anchor(bundle, &sender_fact_chain);
            // Re-derive bundle's dev-class for the diag commitment (same
            // logic Core CL5 uses internally).
            let cl5_dev_class = bundle.cheques.first()
                .map(|c| axiom_core_logic::wallet_id::is_dev_wallet(&c.sender_wallet_id))
                .unwrap_or(false);
            // §1.5.1a: the mirror recompute derives the inherited set through
            // the SAME single builder Core used in-guest — one implementation,
            // no drift (CLAUDE.md §12).
            let cl5_chain_ref = axiom_core_logic::fact::redeem_fact_chain_ref(bundle, &sender_fact_chain);
            let cl5_self_redeem = bundle.cheques.first()
                .map(|c| c.sender_wallet_id == c.receiver_wallet_id)
                .unwrap_or(false);
            // Mirrors Core's fail-closed shape (modes.rs::execute_cl5). This site
            // is DIAGNOSTIC — Core's in-guest value is the authority and Core
            // REJECTS a chain-less cross-wallet redeem (RedeemSenderAnchorMissing),
            // so the mirror must not quietly print a "clean" commitment for a
            // shape Core refuses to sign: that would read as agreement.
            let cl5_inherited: Vec<[u8; 32]> = match cl5_chain_ref {
                Some(fc) => axiom_core_logic::fact::compute_inherited_scar_txids(
                    fc, &cl5_txid, cl5_self_redeem,
                ),
                None if cl5_self_redeem => Vec::new(),
                None => {
                    eprintln!(
                        "[Lambda CL5 mirror] no sender FACT chain on a CROSS-WALLET redeem                          (txid={}) — Core CL5 rejects this shape (RedeemSenderAnchorMissing);                          the mirror commitment below is NOT meaningful.",
                        hex::encode(&cl5_txid[..8]),
                    );
                    Vec::new()
                }
            };
            let commitment = axiom_core_logic::fact::compute_fact_commitment(
                &cl5_txid, &cl5_prev, &new_state_id, amount, cl5_anchor.as_ref(), cl5_dev_class,
                &cl5_inherited,
                None, // burn_target_tx_id — this is a redeem mirror, never a burn
            );
            let hex8 = |b: &[u8]| -> String {
                b.iter().take(8).map(|b| format!("{:02x}", b)).collect()
            };
            // Pull the actual fact_signature CL5 produced + the PK we PUBLISHED
            // (vbc.subject_pubkey_dilithium — what the SDK extracts) and the PK
            // we SIGNED with (derivable from self.dilithium_sk via fips204).
            // If signed_pk != published_pk, signatures verify against the wrong
            // key on the receiver side and Dilithium verify fails despite
            // matching commitments (the load_dilithium_key f361b82 fix should
            // have made these equal — this print confirms it).
            let cl5_sig_hex = redeem_proof.outputs.fact_signature.as_ref()
                .map(|s| std::format!("len={} {}", s.len(), hex8(s)))
                .unwrap_or_else(|| "NONE".into());
            let published_pk = &self.vbc.target_vbc.subject_pubkey_dilithium;
            // Re-derive the PK from the loaded SK so we know what the signature
            // actually verifies against. fips204 expects 4032-byte SK input.
            let signed_pk: Vec<u8> = if self.dilithium_sk.len() == 4032 {
                use fips204::ml_dsa_65;
                use fips204::traits::{SerDes, Signer};
                let mut sk_arr = [0u8; 4032];
                sk_arr.copy_from_slice(&self.dilithium_sk);
                match ml_dsa_65::PrivateKey::try_from_bytes(sk_arr) {
                    Ok(sk) => {
                        let pk = sk.get_public_key();
                        pk.into_bytes().to_vec()
                    }
                    Err(_) => Vec::new(),
                }
            } else {
                Vec::new()
            };
            let pk_match = !signed_pk.is_empty()
                && signed_pk.as_slice() == published_pk.as_slice();
            // Full-array hashes so we can prove the SDK sees the SAME bytes
            // (not just same first 8). If pk_hash / sig_hash match between
            // here and SDK's [build_fact_bridge] line, then bytes are truly
            // identical and the bug is in Dilithium verify itself (lib
            // version skew, parameter mismatch). If they differ, we have
            // partial corruption past byte 8.
            let sig_hash_hex = redeem_proof.outputs.fact_signature.as_ref()
                .map(|s| hex8(blake3::hash(s).as_bytes()))
                .unwrap_or_else(|| "NONE".into());
            let signed_pk_hash_hex = if signed_pk.is_empty() {
                "ERR".into()
            } else {
                hex8(blake3::hash(&signed_pk).as_bytes())
            };
            let published_pk_hash_hex = hex8(blake3::hash(published_pk).as_bytes());

            // Crucial check: does the signature CL5 produced verify against
            // OUR computed commitment, in OUR host fips204? If yes, the
            // message ELF's CL5 signed equals our compute_fact_commitment
            // output, and the SDK's local_verify=FAIL means SDK is doing
            // something different. If NO, then the ELF's CL5 signed a
            // DIFFERENT message — host vs ELF compute_fact_commitment
            // disagree (probably because Cargo.lock changed between ELF
            // build and host build, or the ELF was built from older
            // sources).
            let host_verify = match (
                redeem_proof.outputs.fact_signature.as_ref(),
                signed_pk.as_slice(),
            ) {
                (Some(s), pk) if !pk.is_empty() => {
                    axiom_core_logic::verify::verify_dilithium(pk, &commitment, s).is_ok()
                }
                _ => false,
            };
            let host_verify_pub = match redeem_proof.outputs.fact_signature.as_ref() {
                Some(s) => axiom_core_logic::verify::verify_dilithium(
                    published_pk, &commitment, s,
                ).is_ok(),
                None => false,
            };

            eprintln!(
                "[Lambda CL5 mirror] commitment={} tx={} prev={} new={} amount={} \
                 anchor={} sender_chain_links={} \
                 sig=({}) signed_pk[..8]={} published_pk[..8]={} pk_match={} \
                 sig_hash[..8]={} signed_pk_hash[..8]={} published_pk_hash[..8]={} \
                 host_verify_signed={} host_verify_published={}",
                hex8(&commitment), hex8(&cl5_txid), hex8(&cl5_prev),
                hex8(&new_state_id), amount,
                cl5_anchor.as_ref().map(|a| hex8(a)).unwrap_or_else(|| "NONE".into()),
                cl5_resolved_fact_chain.as_ref().map(|fc| fc.links.len()).unwrap_or(0),
                cl5_sig_hex,
                if signed_pk.is_empty() { "ERR".into() } else { hex8(&signed_pk) },
                hex8(published_pk),
                pk_match,
                sig_hash_hex,
                signed_pk_hash_hex,
                published_pk_hash_hex,
                host_verify,
                host_verify_pub,
            );

        }

        // Step 8: Create our witness signature using Core-provided commitment
        let redeem_commitment = redeem_proof.commitment_hash;
        let mut witness_sig = self.sign_redeem_witness(
            &redeem_commitment,
        )?;

        // FACT signature — Core signed it in CL5 (YP §26.17.6.2)
        // Lambda MUST NOT call sign_dilithium directly
        if let Some(ref core_fact_sig) = redeem_proof.outputs.fact_signature {
            witness_sig.fact_signature = Some(core_fact_sig.clone());
        }

        // SEC-07 travel model: co-sign the receiver chain's STORED provisional
        // checkpoint (if any), same as the send path. The finalizer folds the
        // collected co-signs in via merge_checkpoint_endorsements.
        witness_sig.checkpoint_sig = redeem_proof.outputs.receiver_fact_chain.as_ref()
            .and_then(|chain| axiom_core_logic::compute::cosign_provisional_checkpoint(
                chain, self.validator_id, &self.dilithium_pk, &self.dilithium_sk,
            ).ok().flatten());

        // Sign Nabla receipt at redeem witness time.
        // 2026-06-03 refactor: sig covers (wallet_id, consumed_state, tick).
        // Replay protection comes from consumed_state advancing strictly
        // forward per TX.
        witness_sig.receipt_signature = self.sign_nabla_receipt(
            &request.receiver_pk,
            &request.current_state.as_ref().map(|s| s.state_id).unwrap_or([0u8; 32]),
        );
        // Receipt commitment signature for CL5 (redeem).
        //
        // YP §19.6 (2026-06-03 amendment): the fee-slot authority lives
        // in EACH validator's own Core, not in the SDK. This validator
        // computes its slot from its own configured rate, verifies the
        // math via Core's `verify_slot_math`, stamps both `rate_bps` and
        // `slot_amount` into the WitnessSig (signed via the existing
        // receipt_commitment chain), and records the earnings locally.
        // The SDK never proposes a slot; downstream Cores (client CL1,
        // receiver CL5) re-derive and reject any inconsistency.
        let my_rate_bps = self.fee_config.rate_bps
            .min(axiom_core_logic::types::MAX_VALIDATOR_FEE_BPS);
        let my_slot_amount: u64 = ((amount as u128)
            * my_rate_bps as u128
            / axiom_core_logic::types::FEE_BPS_DIVISOR as u128) as u64;
        // Defence-in-depth: ask Core to verify the math we just did.
        // Lambda's own arithmetic and Core's must agree byte-for-byte
        // or Lambda refuses to sign and surfaces the bug loudly.
        axiom_core_logic::validation::verify_slot_math(
            amount, my_rate_bps, my_slot_amount,
        ).map_err(|e| LambdaError::CoreError(
            format!("Lambda's own slot math failed Core verification: {:?}", e)
        ))?;
        witness_sig.rate_bps = my_rate_bps;
        witness_sig.slot_amount = my_slot_amount;
        // YP §20.8 v3.x — record this validator's slot earnings for /fees.
        // Idempotent via INSERT OR IGNORE on txid PK. Dev-class flag
        // sourced from Core's CL5 attestation so the dashboard can
        // surface dev vs public earnings separately
        // (`AXIOM_DESIGN_FactClassIsolation.md`). Dev rows are
        // observability ONLY — the withdrawal-mint cap reads only
        // the WHERE is_dev_class = 0 sum.
        let mut is_dev_class = redeem_proof.outputs.is_dev_class.unwrap_or(false);

        // ── DEFENSIVE PRE-WRITE GATE (2026-06-05 PM-3) ──────────
        //
        // AXIOM Origin's mandate: "before write to validator's fees... verify
        // AGAIN, defensive in depth, the write is NOT from dev account."
        //
        // Even though Core CL5 already attested `is_dev_class` from
        // `cheque.sender_wallet_id`, we cross-check here at the
        // record-write site by re-deriving from the SAME cheque
        // bundle Lambda has in hand. If Core's attestation disagrees
        // with what Lambda independently computes from the bundle,
        // the most defensive interpretation is: a dev-class wallet
        // is involved — UPGRADE to is_dev_class=true rather than
        // silently leak to public earnings.
        //
        // This catches:
        //   - A buggy Core attestation that mis-routes dev fees to
        //     public ledger
        //   - A future refactor that decouples the derivation from
        //     `sender_wallet_id`
        //   - Any path where Core returns is_dev_class=None but the
        //     cheque sender is @axiom.internal
        //
        // Belt-and-braces with Layer 3 (Core attestation), Layer 4
        // (Nabla commitment verify), Layer 4-bis (Nabla pre-write
        // gate), and Layer 5 (withdrawal mint type-isolation).
        let bundle_is_dev = bundle.cheques.iter().any(|c|
            axiom_core_logic::wallet_id::is_dev_wallet(&c.sender_wallet_id)
                || axiom_core_logic::wallet_id::is_dev_wallet(&c.receiver_wallet_id)
        );
        if bundle_is_dev && !is_dev_class {
            error!(
                "[LEAK-DEFENSE] Lambda pre-write gate: Core attested \
                 is_dev_class=false but cheque bundle contains \
                 @axiom.internal wallet(s). Forcing is_dev_class=true \
                 to prevent dev earnings from being recorded as public. \
                 tx_hash={} — investigate Core CL5 attestation path.",
                hex::encode(&txid[..8]),
            );
            is_dev_class = true;
        }

        self.storage.record_validator_earned(&txid, my_slot_amount, is_dev_class)?;
        if let Some(ref rc) = redeem_proof.outputs.receipt_commitment {
            witness_sig.receipt_commitment_sig = Some(self.sign_receipt_commitment(rc));
        }

        let fact_prev_state_id = cl5_resolved_fact_chain.as_ref()
            .and_then(|fc| fc.links.last())
            .map(|link| link.new_state_id)
            .unwrap_or([0u8; 32]);
        debug!("FACT_REDEEM vid={} prev_state={} new_state={} amount={}",
                 hex::encode(&self.validator_id[..4]),
                 hex::encode(&fact_prev_state_id[..8]),
                 hex::encode(&new_state_id[..8]),
                 amount);
        
        // Return Core's assembled receiver chain (set only on the finalizer's
        // CL5 — see CLAUDE.md §12 / modes::execute_cl5). Non-finalizer
        // responses return None and the SDK takes the response that carries
        // a populated chain. Replaces the pre-A2 pattern of returning the
        // sender's chain and letting the SDK assemble the link.
        //
        // Compress + endorse before returning. Core's `build_fact_link`
        // appends the new redeem link uncompressed; without this step the
        // receiver's chain accumulates one link per inbound cheque and
        // hits Lambda's max_fact_links ceiling. The SEND path runs this
        // at consensus.rs:4557 — without the matching call here, a
        // receive-heavy wallet (soak s2r68580 wallet 0: 10 redeems / 4
        // sends) grew to 14 healed links while wallets dominated by sends
        // compressed normally. compress_and_endorse_fact_chain returns
        // the uncompressed chain on Err (existing fallback), so this
        // never drops a valid chain.
        // SEC-07: gather each redeem witness's checkpoint endorsement (this
        // validator's own from `witness_sig`, plus the prior witnesses carried
        // in the redeem request) so a freshly-compressed receiver checkpoint
        // gets its k=3 distinct sigs.
        let redeem_checkpoint_endorsements: Vec<axiom_core_logic::types::FactWitness> =
            request.fact_witness_sigs.iter()
                .chain(core::iter::once(&witness_sig))
                .filter_map(|ws| ws.checkpoint_sig.clone())
                .collect();
        let receiver_fact_chain = match redeem_proof.outputs.receiver_fact_chain.clone() {
            Some(chain) => match self.compress_and_endorse_fact_chain(chain.clone(), &redeem_checkpoint_endorsements, redeem_proof.outputs.oods_flag.map_or(true, |f| f.healthy)) {
                Ok(compressed) => Some(compressed),
                Err(e) => {
                    warn!(
                        "FACT compress/endorse on redeem path failed: {} — \
                         returning uncompressed ({} link(s))",
                        e, chain.links.len(),
                    );
                    Some(chain)
                }
            },
            None => None,
        };
        
        // Preserve existing auth_hash from receiver's stored state
        let receiver_auth = self.storage.get_wallet_state(&request.receiver_pk, redeem_k_raw, redeem_pt)
            .ok().flatten().and_then(|ws| ws.auth_hash);
        let receiver_state = StoredWalletState {
            public_key: request.receiver_pk.clone(),
            balance: new_balance,
            wallet_seq: new_seq,
            state_id: new_state_id,
            last_tx_id: Some(txid),
            status: WalletStateStatus::Pending,
            group_members: None,
            // StoredWalletState.fact_chain removed (YPX-001 §1.6). The
            // SDK reads `receiver_fact_chain` from the finalizer's response
            // directly; no Lambda-side persistence of the chain.
            auth_hash: receiver_auth, hibernation_until: 0,
            wallet_id: None,
        };
        // CAS guard: concurrent redeems to the same wallet can race (wallet_seq
        // doesn't increment on receive). Use conditional update — if state_id changed
        // between our read and write, a concurrent redeem landed first.
        // pre_redeem_state_id was captured from LOCAL storage before computing new state.
        if pre_redeem_state_id != [0u8; 32] {
            // Existing wallet — use CAS
            if !self.storage.update_wallet_state_cas(&receiver_state, &pre_redeem_state_id, redeem_k_raw, redeem_pt)? {
                return Err(LambdaError::InvalidRequest(
                    "Concurrent redeem conflict — receiver state changed. Retry.".into()
                ));
            }
        } else {
            // New wallet (first redeem) — INSERT is safe
            self.storage.set_wallet_state(&receiver_state, redeem_k_raw, redeem_pt)?;
        }
        debug!("Stored receiver wallet state: balance={} seq={} state_id={}",
              new_balance, new_seq, hex::encode(&new_state_id[..8]));
        
        // Step 8b: ALSO store a TransactionRecord for S-ABR lookup
        // When receiver later sends, they'll consume this state_id
        // The lookup needs to find the record that PRODUCED this state_id
        let tx_record = TransactionRecord {
            tx_id: txid,
            produced_state_id: new_state_id,
            wallet_pk: request.receiver_pk.clone(),
            balance_after: new_balance,
            wallet_seq_after: new_seq,
            group_members_after: None,  // Receiver path doesn't track group deductions
            is_genesis_claim: None,
            status: WalletStateStatus::Pending,  // PENDING until receiver ACKs
            required_k: redeem_k_raw,
            proof_type: redeem_pt,
            amount,
            sender_balance: current_balance,  // receiver's pre-redeem balance
        };
        self.storage.store_transaction_record(&tx_record)?;
        debug!("Stored receiver tx record: produced_state_id={} balance={}",
              hex::encode(&new_state_id[..8]), new_balance);

        // [REDEEM-STORE DIAG] — emit by EVERY validator that reaches
        // the receiver-side wallet-state + transaction-record store. The
        // next SEND for this receiver will look up TransactionRecord by
        // its consumed_state_id (= what we store here as new_state_id);
        // if validators store different (state_id → balance) PAIRS,
        // subsequent S-ABR overlap divergences cascade into
        // FactInsufficientWitnesses on the next k-round.
        //
        // Pair with [PRODUCED-INPUTS DIAG] on the NEXT TX via
        // `produced_state_id[..8]` = NEXT tx's `consumed[..8]`.
        // See task #143 / docs/AXIOM_HANDOFF_FactConfRace.md.
        eprintln!(
            "[REDEEM-STORE DIAG] vid={} txid={} receiver_pk[..8]={} current_balance={} amount={} total_fee={} new_balance={} new_seq={} new_state_id[..8]={}",
            hex::encode(&self.validator_id[..4]),
            hex::encode(&txid[..8]),
            hex::encode(&request.receiver_pk[..request.receiver_pk.len().min(8)]),
            current_balance,
            amount,
            total_fee,
            new_balance,
            new_seq,
            hex::encode(&new_state_id[..8]),
        );

        // YP §20.8 v3.x: validator fees settle direct-deposit at CL5 via
        // fee_breakdown (Step 6 Refactor C). No per-TX IOU recorded here.

        // Step 9: Cheque already marked as redeemed in Step 5 (atomic try_mark_cheque_redeemed)
        let _my_pk_hex = hex::encode(&self.public_key.as_bytes()[..8]);
        
        debug!(
            "Cheque witnessed for redemption: {} atoms, new balance: {}",
            amount, new_balance
        );

        // AUDIT-FIX v2.11.13: Mark delivery as ACKed (receiver redeemed)
        self.storage.mark_delivery_acked(&txid).ok();

        // Generate hints for response
        let validator_id_str = hex::encode(self.validator_id);
        let response_hints = self.storage.get_random_hints(3, &validator_id_str)
            .unwrap_or_default();
        
        // Forward Core's per-validator FACT signature into the
        // top-level RedeemResponse field. The SDK collects k of these
        // from k validators to assemble the receiver's redeem
        // FactLink. ANTIE forwards this through to the SDK in
        // ResponsePayload.fact_signature (commit 212c6c5). Previously
        // hardcoded None, leaving the SDK to skip link construction
        // → wallet had only the genesis send link → next send hit
        // E_FACT_CHAIN_BREAK.
        let response_fact_signature = redeem_proof.outputs.fact_signature.clone();
        let response = RedeemResponse {
            request_id: request.request_id,
            success: true,
            new_balance: Some(new_balance),
            new_state_id: Some(new_state_id),
            witness_signature: Some(witness_sig),
            commitment_hash: Some(redeem_commitment.to_vec()),
            // Top-level state_hash + receipt_commitment so the receiver
            // SDK can build its redeem receipt with non-zero values
            // (matches WitnessResponse pattern post-4a81a34). Without
            // these the receiver writes a redeem receipt with
            // state_hash=[0u8;32], and the receiver's next send fails
            // CL2 with E_RECEIPT_COMMITMENT_MISMATCH.
            state_hash: redeem_proof.outputs.new_state_hash.map(|h| h.to_vec()),
            receipt_commitment: redeem_proof.outputs.receipt_commitment.map(|rc| rc.to_vec()),
            error_response: None,
            validator_hints: response_hints,
            fact_signature: response_fact_signature,
            // Return Core's assembled receiver chain (Some on finalizer's
            // response, None elsewhere — see modes::execute_cl5).
            receiver_fact_chain,
        };
        self.stats.redeem_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats.atoms_redeemed.fetch_add(amount, std::sync::atomic::Ordering::Relaxed);
        self.stats.redeem_time_us.fetch_add(_t0.elapsed().as_micros() as u64, std::sync::atomic::Ordering::Relaxed);
        self.stats.record_success();
        Ok(response)
    }
    
    /// Verify one cheque's DMAP execution proof (proof_type 1) — the exact per-cheque
    /// redeem-side gate, extracted from `process_redeem_request_inner` so it is
    /// unit-testable. Returns `Ok(())` when the attestation is structurally valid
    /// against an ACCEPTED CoreID (current ∪ blessed priors, §11); `Err(...)` otherwise,
    /// including `WrongCore` for a non-accepted CoreID.
    ///
    /// SEC-3 + CoreID-lineage accept-set: verify against a TRUSTED CoreID only.
    /// `resolve_dmap_verify_core_id` picks `attestation.core_id` iff it is in the blessed
    /// set (current ∪ non-revoked priors — all baked-in, trusted values), which is
    /// REQUIRED because that CoreID also seeds challenge derivation; a non-accepted CoreID
    /// resolves to `self.expected_core_id` → Step-1 `WrongCore`. We never verify against an
    /// arbitrary sender-supplied CoreID. See docs/AXIOM_DESIGN_CoreUpgradeMigration.md §11.
    /// GAP-B: use the cheque's independently-computed hashes (covered by the validator
    /// signature), falling back to the attestation's only for the zero (legacy) case.
    /// AUDIT-FIX v2.11.14: the cheque's validator_pk is the trusted challenge-seed identity.
    fn verify_cheque_dmap_attestation(&self, cheque: &ValidatorCheque) -> Result<(), LambdaError> {
        // CBOR (writer: lambda/src/core_client.rs ~459).
        let attestation: axiom_dmap_vm::dmap::DmapAttestation =
            ciborium::de::from_reader(&cheque.execution_proof[..])
                .map_err(|e| LambdaError::CoreValidationFailed(
                    format!("Cheque DMAP attestation decode: {}", e)
                ))?;
        let (verify_input_hash, verify_output_hash) = if cheque.dmap_input_hash != [0u8; 32] {
            (&cheque.dmap_input_hash, &cheque.dmap_output_hash)
        } else {
            (&attestation.input_hash, &attestation.output_hash)
        };
        let expected_vpk: [u8; 32] = cheque.validator_pk.clone()
            .try_into().unwrap_or([0u8; 32]);
        let verify_core_id = axiom_core_logic::version::resolve_dmap_verify_core_id(
            &attestation.core_id, &self.expected_core_id,
        );
        match axiom_dmap_vm::dmap::verify_dmap_attestation(
            &attestation,
            &verify_core_id,
            verify_input_hash,
            verify_output_hash,
            &expected_vpk,
        ) {
            axiom_dmap_vm::dmap::DmapResult::Valid => Ok(()),
            other => Err(LambdaError::CoreValidationFailed(
                format!("Cheque DMAP verification failed: {:?}", other)
            )),
        }
    }

    /// Verify a ValidatorCheque's signature
    fn verify_cheque_signature(&self, cheque: &ValidatorCheque) -> Result<bool, LambdaError> {
        // Commitment computed by Core
        let message = self.compute_cheque_commitment(cheque);
        
        // Verify via Core
        match axiom_core_logic::verify::verify_ed25519(&cheque.validator_pk, &message, &cheque.signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Compute commitment hash for cheque signing/verification.
    /// Canonical cheque commitment includes `rate_bps` so receiver-side
    /// Core CL5 can compute `total_fee` deterministically (closes
    /// `E_RECEIPT_COMMITMENT_MISMATCH` class — 2026-06-05 PM).
    fn compute_cheque_commitment(&self, cheque: &ValidatorCheque) -> [u8; 32] {
        axiom_core_logic::compute::compute_cheque_commitment(
            &cheque.txid,
            &cheque.state_hash,
            &cheque.produced_state_id,
            &cheque.receiver_wallet_id,
            cheque.amount,
            cheque.epoch,
            cheque.rate_bps,
            &cheque.dmap_input_hash,
            &cheque.dmap_output_hash,
            cheque.oracle_claim.as_ref(),
            cheque.recall_target_tx_id.as_ref(),
        )
    }

    /// Sign a witness for receiver's redeem (balance increase)
    fn sign_redeem_witness(
        &self,
        commitment: &[u8; 32],
    ) -> Result<WitnessSig, LambdaError> {
        use ed25519_dalek::Signer;
        
        // Sign the Core-provided commitment — Lambda MUST NOT compute commitments
        let signature = self.signing_key.sign(commitment);
        
        // Generate hints for this witness signature
        let validator_id_str = hex::encode(self.validator_id);
        let hints = self.storage.get_random_hints(3, &validator_id_str)
            .unwrap_or_default();
        
        Ok(WitnessSig {
            validator_id: self.validator_id,
            validator_pk: self.public_key.as_bytes().to_vec(),
            vbc_bundle: self.vbc_for_signature(),
            carrier_type: self.carrier_type.clone(),
            carrier_address: self.carrier_address.clone(),
            signature: signature.to_bytes().to_vec(),
            execution_proof: vec![],
            proof_type: 0, // Default ZKP; updated if DMAP is used
            availability_attestation: None,
            validator_hints: hints,
            fact_signature: None,  // Filled by caller from Core CL5 output
            checkpoint_sig: None,  // SEC-07: filled by caller from CL5 receiver-chain checkpoint
            receipt_signature: None, // Filled by caller from Core CL5 output
            receipt_commitment_sig: None,
            rate_bps: 0,
            slot_amount: 0,
        })
    }

    /// Verify receiver's signature on redeem request
    fn verify_redeem_signature(&self, request: &RedeemRequestEnvelope, txid: &[u8; 32]) -> Result<bool, LambdaError> {
        // Commitment computed by Core
        let message = axiom_core_logic::compute::compute_redeem_request_commitment(txid, &request.receiver_pk);
        
        // Verify via Core
        match axiom_core_logic::verify::verify_ed25519(&request.receiver_pk, &message, &request.receiver_sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Compute new state_id for wallet after balance change
    /// Compute new state ID for receiver after redeem
    /// 
    /// MUST use same hash as sender's produced_state_id for consistency.
    /// But for receivers, we don't have consumed_state_id/nonce from a transaction.
    /// Instead we use the txid from the cheque to ensure uniqueness.
    /// 
    /// Formula: SHA3-256("AXIOM_RECV_STATE" || pk || balance || seq || txid)
    /// Query wallet state
    pub fn query_state(&self, public_key: &[u8]) -> Result<Option<StoredWalletState>, LambdaError> {
        self.storage.get_wallet_state(public_key, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)
    }

    /// VSP: Return this validator's public status + 3 known peers.
    /// Free service, no authentication. Per YPX-008.
    pub fn validator_status(&self, request_id: &str) -> ValidatorStatusResponse {
        use std::sync::atomic::Ordering::Relaxed;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        ValidatorStatusResponse {
            request_id: request_id.to_string(),
            validator_name: self.vbc.target_vbc.node_name.clone(),
            validator_id: hex::encode(self.validator_id),
            proof_cap: self.proof_mode.clone(),
            // YP §27.5.2 multi-carrier list. Populated by ANTIE at gateway
            // startup via the `SetCarriers` IPC. Empty if operator hasn't
            // configured any carriers yet (Lambda logs a warn at set_carriers
            // time so the misconfig is visible). Pre-Phase-1 this was
            // hardcoded to `vec![format!("{}:{}", carrier_type, carrier_address)]`
            // which silently shipped "dev:validator-<8 hex>" garbage into
            // every VSP response because set_carrier_info was never called
            // by server.rs.
            carriers: self.carriers_snapshot(),
            core_version: axiom_core_logic::version::CORE_VERSION_TAG.to_string(),
            uptime_secs: now.saturating_sub(self.stats.started_at),
            witness_count: self.stats.witness_count.load(Relaxed),
            redeem_count: self.stats.redeem_count.load(Relaxed),
            zkp_qualified: self.stats.zkp_qualified.load(Relaxed),
            known_validators: self.get_hints(),
            fee_rate_bps: self.fee_config.rate_bps,
            fee_valid_until: self.fee_config.valid_until,
            fee_min_amount: self.fee_config.min_amount,
            jurisdiction: self.operator_config.jurisdiction.clone(),
            operator_name: self.operator_config.name.clone(),
            operator_contact: self.operator_config.contact.clone(),
            supported_encryption: self.operator_config.supported_encryption.clone(),
            encryption_public_key: self.operator_config.encryption_public_key.clone(),
            stake: self.get_bound_wallet_balance(),
            notes: self.operator_config.notes.clone(),
            digit_version: self.management_db.as_ref()
                .and_then(|db| db.get_digit_version().ok())
                .unwrap_or(0),
        }
    }
    
    /// Process ACK request (fee payment + state confirmation)
    /// 
    /// When client receives k=3 witness signatures, they send ACK to each validator:
    /// 1. Verify ACK signature (client authorizes fee payment)
    /// 2. Mark fee as paid
    /// 3. Transition state from PENDING → CONFIRMED
    pub fn process_ack(&self, ack: &AckWithFee, client_pk: &[u8]) -> Result<AckResponse, LambdaError> {
        use axiom_core_logic::verify::verify_ed25519;

        debug!("Processing ACK: txid={}, client={}",
            hex::encode(&ack.txid[..8]),
            hex::encode(&client_pk[..8]),
        );

        // 1. Verify this ACK is for us (our validator_pk)
        let our_pk = self.public_key.as_bytes().to_vec();
        if ack.validator_pk != our_pk {
            return Ok(AckResponse {
                request_id: String::new(), // Filled by caller
                success: false,
                new_status: None,
                error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_LAMBDA_ACK_WRONG_VALIDATOR, axiom_errors::ErrorCategory::ClientBug, "ACK is not for this validator")),
            });
        }

        // 2. Verify the ACK signature — commitment computed by Core
        let message = axiom_core_logic::compute::compute_ack_fee_commitment(
            &ack.txid, &ack.validator_pk,
        );

        if verify_ed25519(client_pk, &message, &ack.sender_sig).is_err() {
            return Ok(AckResponse {
                request_id: String::new(),
                success: false,
                new_status: None,
                error_response: Some(crate::error_response::static_error(axiom_errors::error_code::E_LAMBDA_ACK_INVALID_SIG, axiom_errors::ErrorCategory::ClientBug, "Invalid ACK signature")),
            });
        }

        // 3. Gate on transaction_records — "did we witness this txid?".
        //    The legacy fee_records IOU ledger is gone (YP §20.8 v3.x); the
        //    S-ABR anchor row is the authoritative witness-presence record.
        let tx_record = match self.storage.get_transaction_record_by_txid(&ack.txid)? {
            Some(rec) => rec,
            None => {
                return Ok(AckResponse {
                    request_id: String::new(),
                    success: false,
                    new_status: None,
                    error_response: Some(crate::error_response::static_error(
                        axiom_errors::error_code::E_LAMBDA_ACK_NO_PENDING_FEE,
                        axiom_errors::ErrorCategory::Operational,
                        "ACK references a txid we did not witness",
                    ).with_recovery(axiom_errors::RecoveryHint::WaitAndRetry)),
                });
            }
        };

        // Idempotency: if consumed_state_id is already marked consumed, the
        //   ACK has already been processed for this txid. Return success.
        if let Some(consumed_state_id) = self.storage.get_consumed_state_by_txid(&ack.txid)? {
            if self.storage.is_state_consumed(&consumed_state_id)? {
                return Ok(AckResponse {
                    request_id: String::new(),
                    success: true,
                    new_status: Some("Confirmed".into()),
                    error_response: None,
                });
            }
        }

        // 4. Confirm wallet state (PENDING → CONFIRMED)
        // TODO(ark-k0): confirms the SENDER's state. Standard (k=3) is correct for
        // a charge (sender is the normal wallet); a k=0 settlement (Ark sender)
        // needs the sender tier threaded from ack.txid before Ark settle is exercised.
        self.storage.confirm_wallet_state(client_pk, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)?;

        // 5. Mark consumed_state_id as consumed (White Paper §4.11.1)
        //
        // "Once a validator has witnessed a consumption event, that consumption
        //  is final within its local truth. It does not re-open."
        //
        // This happens at ACK (not witness) because before ACK the TX is
        // PENDING — client can abandon and retry with a different TX.
        // After ACK, the state transition is committed and irreversible.
        //
        // The overlapped validator in the NEXT transaction will check:
        // "Did I already witness the consumption of this parent state?"
        // If yes → reject (double-spend attempt).
        if let Some(consumed_state_id) = self.storage.get_consumed_state_by_txid(&ack.txid)? {
            self.storage.mark_state_consumed(&consumed_state_id)?;
            debug!("ACK committed: consumed_state_id={} now permanently consumed",
                   hex::encode(&consumed_state_id[..8]));
        }

        // 6. Prune S-ABR records superseded by this now-finalized TX. This is
        // the ONLY place transaction_records is pruned — pruning at witness
        // time deleted the wallet's anchor for un-finalized transactions.
        self.storage.prune_superseded_transaction_records(
            &tx_record.wallet_pk, &tx_record.produced_state_id, tx_record.wallet_seq_after,
        )?;

        info!("ACK processed: txid={}", hex::encode(&ack.txid[..8]));

        Ok(AckResponse {
            request_id: String::new(),
            success: true,
            new_status: Some("Confirmed".into()),
            error_response: None,
        })
    }

    /// CL13 / fee ledger Step 9B.3 — chosen-witness handler.
    ///
    /// Called when the operator's Lambda sends a
    /// `WithdrawalMintWitnessRequest` to this validator's gateway
    /// (this validator is one of the operator's `chosen_witnesses`).
    ///
    /// Flow:
    ///   1. Lambda-side `verify_validator_withdrawal` (the cheap 7-step
    ///      chain). Cuts off obvious tamper before paying the AVM cost.
    ///   2. Core CL13 via the AVM — independent re-verification inside
    ///      the consensus ELF. A compromised originating Lambda cannot
    ///      smuggle a bad withdrawal past this gate.
    ///   3. On Accept: sign the canonical mint commitment with this
    ///      validator's Ed25519 key. Operator collects k=3 of these and
    ///      assembles the mint receipt in Step 9B.4.
    ///
    /// This function is intentionally NOT `async` — the cross-Lambda
    /// fan-out happens at the operator's side; the witness handler runs
    /// synchronously on the gateway thread.
    pub async fn process_withdrawal_mint_witness(
        &self,
        req: &axiom_core_logic::types::WithdrawalMintWitnessRequest,
    ) -> axiom_core_logic::types::WithdrawalMintWitnessResponse {
        use ed25519_dalek::Signer;
        use axiom_core_logic::types::WithdrawalMintWitnessResponse;

        let our_pk = self.public_key.as_bytes().to_vec();

        // (1) Lambda-side 7-step verify.
        let pre = crate::validator_withdrawal::verify_validator_withdrawal(&req.withdrawal);
        if pre.status != "VERIFIED" {
            debug!(
                "WithdrawalMintWitness: Lambda-side verify rejected {}",
                pre.status
            );
            return WithdrawalMintWitnessResponse {
                request_id: req.request_id.clone(),
                status: pre.status,
                witness_pk: our_pk,
                witness_sig: None,
                claim_sig: None,
                mint: None,
                error_response: None,
            };
        }

        // (2) Core CL13 via AVM — independent re-verification.
        let outputs = {
            let core = self.core.write().await;
            match core.execute_cl13(&req.withdrawal) {
                Ok(o) => o,
                Err(e) => {
                    return WithdrawalMintWitnessResponse {
                        request_id: req.request_id.clone(),
                        status: format!("REJECTED_CORE_ERROR: {}", e),
                        witness_pk: our_pk,
                        witness_sig: None,
                claim_sig: None,
                        mint: None,
                        error_response: Some(crate::error_response::static_error(
                            axiom_errors::error_code::E_LAMBDA_STORAGE_ERROR,
                            axiom_errors::ErrorCategory::Internal,
                            "Core CL13 execution failed",
                        )),
                    };
                }
            }
        };
        if outputs.result != axiom_core_logic::ValidationResult::Accept {
            let reason = outputs.rejection_reason
                .map(|r| format!("{}", r))
                .unwrap_or_else(|| "unknown".to_string());
            return WithdrawalMintWitnessResponse {
                request_id: req.request_id.clone(),
                status: format!("REJECTED_CORE_CL13: {}", reason),
                witness_pk: our_pk,
                witness_sig: None,
                claim_sig: None,
                mint: None,
                error_response: None,
            };
        }
        let mint = match outputs.validator_withdrawal_mint {
            Some(m) => m,
            None => {
                // Should be unreachable — Core CL13 Accept always
                // populates the field. Surface defensively.
                return WithdrawalMintWitnessResponse {
                    request_id: req.request_id.clone(),
                    status: "REJECTED_CORE_OUTPUT_MISSING".into(),
                    witness_pk: our_pk,
                    witness_sig: None,
                claim_sig: None,
                    mint: None,
                    error_response: Some(crate::error_response::static_error(
                        axiom_errors::error_code::E_LAMBDA_STORAGE_ERROR,
                        axiom_errors::ErrorCategory::Internal,
                        "Core CL13 Accept without mint output",
                    )),
                };
            }
        };

        // (3a) Sign the canonical mint commitment — operator uses k=3
        //      of these for the linked-wallet credit + audit trail.
        let mint_commitment = axiom_core_logic::compute::compute_withdrawal_mint_commitment(
            &mint.validator_id,
            &mint.linked_wallet_id,
            mint.net_amount,
            mint.claimed_through_tick,
        );
        let mint_sig = self.signing_key.sign(&mint_commitment);

        // (3b) Sign the canonical CLAIM payload — operator forwards k=3
        //      of these to Nabla in a `MarkValidatorEarningsClaimedRequest`
        //      so `last_claimed_tick` advances and the same earnings
        //      can't be re-claimed from a fresh Lambda (Step 9B.8).
        let claim_payload = axiom_core_logic::compute::compute_validator_claim_payload(
            &mint.validator_id,
            mint.claimed_through_tick,
        );
        let claim_sig = self.signing_key.sign(&claim_payload);

        info!(
            "WithdrawalMintWitness signed: vid={} net={} → {} (mint+claim)",
            hex::encode(&mint.validator_id[..8]),
            mint.net_amount,
            hex::encode(&mint.linked_wallet_id[..8]),
        );

        WithdrawalMintWitnessResponse {
            request_id: req.request_id.clone(),
            status: "VERIFIED".to_string(),
            witness_pk: our_pk,
            witness_sig: Some(mint_sig.to_bytes().to_vec()),
            claim_sig: Some(claim_sig.to_bytes().to_vec()),
            mint: Some(mint),
            error_response: None,
        }
    }

    /// Get health status
    pub fn health(&self) -> HealthResponse {
        let pending_count = {
            // Can't easily get count from async RwLock synchronously
            // For now return 0
            0
        };
        
        HealthResponse {
            status: "healthy".to_string(),
            core_connected: true,
            pending_transactions: pending_count,
        }
    }
    
    /// Initialize genesis state for a wallet (DEV/TEST MODE ONLY)
    /// 
    /// ⚠️ WARNING: This bypasses real Genesis validator signatures!
    /// 
    /// In production, genesis wallets are created by Genesis validators (G1, G2, G3)
    /// signing initial allocations at network bootstrap (t=0).
    /// 
    /// This method is for TESTING ONLY - it allows creating genesis wallets
    /// without the real Genesis validator signatures.
    /// §4.5 / §30.2: Set auth_hash on a wallet (stolen-key protection).
    ///
    /// The auth_hash is an Ed25519 public key derived from owner_secret (v2.11.13).
    /// Once set, every TX must include owner_proof (Ed25519 signature) proving
    /// knowledge of the secret. Core validates — Lambda just stores the key.
    ///
    /// This is the user-facing API that was missing (G7). Core validation was already
    /// implemented in GAP-A fix (v2.11.3).
    /// Fan-Out dedup: check if diffusion_id is already seen in persistent storage.
    pub fn fanout_is_seen(&self, diffusion_id: &[u8; 32]) -> Result<bool, LambdaError> {
        self.storage.fanout_is_seen(diffusion_id)
    }

    /// Fan-Out dedup: mark diffusion_id as seen (idempotent).
    pub fn fanout_mark_seen(&self, diffusion_id: &[u8; 32]) -> Result<(), LambdaError> {
        self.storage.fanout_mark_seen(diffusion_id)
    }

    /// Fan-Out dedup: prune entries older than max_age_secs.
    pub fn fanout_prune(&self, max_age_secs: u64) -> Result<usize, LambdaError> {
        self.storage.fanout_prune(max_age_secs)
    }

    /// Prune stale per-TX data: old transaction_records, receipts, fee_records, etc.
    /// Keeps only latest per wallet. Called periodically from maintenance loop.
    pub fn storage_prune(&self, max_age_secs: u64) -> Result<usize, LambdaError> {
        self.storage.prune_stale_data(max_age_secs)
    }

    pub fn set_auth_hash(&self, public_key: &[u8], auth_hash: [u8; 32]) -> Result<(), LambdaError> {
        if public_key.len() != 32 {
            return Err(LambdaError::InvalidRequest(
                format!("Public key must be 32 bytes, got {}", public_key.len())
            ));
        }

        // Retrieve existing wallet state — wallet must exist on this validator.
        // Only genesis claim validators (k=3) have the wallet. Fresh validators
        // (other 7) don't have it → set_auth_hash returns OK but is a no-op.
        // Fresh validators don't need auth_hash: they have no stored state, so
        // Core doesn't check auth_hash for them.
        let stored = self.storage.get_wallet_state(public_key, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)?;
        let mut state = match stored {
            Some(s) => s,
            None => {
                // Validator hasn't seen this wallet — no-op. Fresh validators
                // don't check auth_hash (no stored state → auth_hash=None →
                // modes.rs line 786 `if let Some(auth_pk)` skips check).
                info!("§4.5: set_auth_hash skipped — wallet not on this validator pk={}",
                    hex::encode(&public_key[..8]));
                return Ok(());
            }
        };

        // Set auth_hash — once set, every TX requires owner_proof proof
        state.auth_hash = Some(auth_hash);

        // Persist updated state
        self.storage.set_wallet_state(&state, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)?;

        info!("§4.5: auth_hash set for wallet pk={}, hash={}",
              hex::encode(&public_key[..8]), hex::encode(&auth_hash[..8]));

        Ok(())
    }

    ///
    /// Returns error if called in production mode.
    pub fn init_genesis_dev(&self, public_key: &[u8], balance: u64, group_members: Option<Vec<axiom_core_logic::GroupMember>>, auth_hash: Option<[u8; 32]>) -> Result<crate::types::GenesisResult, LambdaError> {
        // Only allow with explicit opt-in (--allow-test-genesis or AXIOM_ALLOW_TEST_GENESIS=1)
        if std::env::var("AXIOM_ALLOW_TEST_GENESIS").unwrap_or_default() != "1" {
            return Err(LambdaError::InvalidRequest(
                "init_genesis_dev not allowed in production mode. Genesis wallets must be created by Genesis validators.".into()
            ));
        }
        
        if public_key.len() != 32 {
            return Err(LambdaError::InvalidRequest(
                format!("Public key must be 32 bytes, got {}", public_key.len())
            ));
        }
        
        let pk_array: [u8; 32] = public_key.try_into().map_err(|_| LambdaError::InvalidRequest("Public key must be 32 bytes".into()))?;
        
        // If group wallet, validate creation rules and distribute initial balance
        let final_group_members = if let Some(members) = group_members {
            // Validate group wallet structure (sum=10000, no dupes, etc.)
            axiom_core_logic::validation::validate_group_wallet_creation(&members)
                .map_err(|e| LambdaError::InvalidRequest(format!("Group wallet validation failed: {}", e)))?;
            
            // Distribute genesis balance to members
            // Use a deterministic hash for genesis distribution
            let mut genesis_hash = [0u8; 32];
            genesis_hash[..8].copy_from_slice(&balance.to_le_bytes());
            genesis_hash[8..16].copy_from_slice(&pk_array[..8]);
            let distributed = axiom_core_logic::validation::distribute_to_group(&members, balance, &genesis_hash)
                .map_err(|e| LambdaError::InvalidRequest(format!("Group distribution failed: {}", e)))?;
            
            debug!("[DEV] Genesis group wallet: {} members, balance={}", distributed.len(), balance);
            for (i, m) in distributed.iter().enumerate() {
                debug!("  member[{}]: share={}bps, available={}", i, m.share_bps, m.available);
            }
            
            Some(distributed)
        } else {
            None
        };
        
        // genesis_state_id = SHA3-256("AXIOM_GENESIS" || pk || balance || k || proof_type)
        // Dev genesis funds the Standard (k=3, DMAP) tier — you fund the normal
        // wallet, then charge the k=0 Ark from it (§10.5).
        let state_id = axiom_core_logic::genesis::compute_genesis_state_id(
            &pk_array,
            balance,
            axiom_core_logic::wallet_id::K_DEFAULT,
            axiom_core_logic::wallet_id::PROOF_TYPE_DMAP,
        );
        
        // Store genesis state: seq=0, balance=X
        // First real TX (seq=1) has no prev_receipts — none exist yet.
        // Core allows this: seq=1, no prev_receipts, no overlap check.
        // Genesis wallet_id starts as None. Identity binding is established on first TX.
        // Genesis lockup is enforced by Core via pk-based check (GENESIS_VALIDATORS),
        // so even if wallet_id is None, genesis validators cannot bypass lockup.
        let state = StoredWalletState {
            public_key: public_key.to_vec(),
            balance,
            wallet_seq: 0,  // Genesis
            state_id,
            last_tx_id: None,
            status: WalletStateStatus::Confirmed,
            group_members: final_group_members,
            auth_hash,
            wallet_id: None,
            hibernation_until: 0,
        };

        self.storage.set_genesis_state(&pk_array, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP, &state)?;
        self.storage.set_wallet_state(&state, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)?;
        
        debug!("[DEV] Genesis: pk={}, balance={}, seq=0, state_id={}", 
            hex::encode(&pk_array[..8]),
            balance,
            hex::encode(&state_id[..8])
        );
        
        self.stats.genesis_inits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        Ok(crate::types::GenesisResult {
            state_id: state_id.to_vec(),
            wallet_seq: 0,
        })
    }
    
    /// Load pre-computed test state directly (DEV/TEST MODE ONLY)
    /// 
    /// ⚠️ WARNING: This bypasses ALL validation!
    /// 
    /// This is for testing only - loads wallet state exactly as provided
    /// without any computation or verification. The state_id, balance,
    /// and wallet_seq are stored as-is.
    /// 
    /// Returns error if called in production mode.
    pub fn load_test_state(
        &self,
        public_key: &[u8],
        state_id: &[u8],
        balance: u64,
        wallet_seq: u64,
    ) -> Result<(), LambdaError> {
        // Only allow with explicit opt-in (--allow-test-genesis or AXIOM_ALLOW_TEST_GENESIS=1)
        if std::env::var("AXIOM_ALLOW_TEST_GENESIS").unwrap_or_default() != "1" {
            return Err(LambdaError::InvalidRequest(
                "load_test_state not allowed in production mode".into()
            ));
        }
        
        if public_key.len() != 32 {
            return Err(LambdaError::InvalidRequest(
                format!("Public key must be 32 bytes, got {}", public_key.len())
            ));
        }
        
        if state_id.len() != 32 {
            return Err(LambdaError::InvalidRequest(
                format!("State ID must be 32 bytes, got {}", state_id.len())
            ));
        }
        
        let pk_array: [u8; 32] = public_key.try_into().map_err(|_| LambdaError::InvalidRequest("Public key must be 32 bytes".into()))?;
        let state_id_array: [u8; 32] = state_id.try_into().map_err(|_| LambdaError::InvalidRequest("State ID must be 32 bytes".into()))?;
        
        // Create wallet state exactly as provided - no computation
        let state = StoredWalletState {
            public_key: public_key.to_vec(),
            balance,
            wallet_seq,
            state_id: state_id_array,
            last_tx_id: None,
            status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: None, hibernation_until: 0,
            wallet_id: None,
        };

        // Store directly
        self.storage.set_wallet_state(&state, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)?;
        
        debug!("[DEV] Test state loaded: pk={}, balance={}, seq={}, state_id={}", 
            hex::encode(&pk_array[..8]),
            balance,
            wallet_seq,
            hex::encode(&state_id_array[..8])
        );
        
        Ok(())
    }

    /// Build a ScarRecoveryProof for a healed scar.
    ///
    /// Called when Nabla confirms a transaction and a validator needs to attest
    /// that the scar on the sender's FACT link has been healed.
    ///
    /// The heal commitment is computed by Core (compute_scar_heal_commitment),
    /// and signed with this validator's Dilithium key.
    pub fn build_scar_recovery_proof(
        &self,
        original_tx_id: &[u8; 32],
        nabla_confirmation: axiom_core_logic::types::NablaConfirmation,
        receiver_wallet_id: String,
    ) -> Result<axiom_core_logic::types::ScarRecoveryProof, LambdaError> {
        use axiom_core_logic::types::{FactWitness, ScarRecoveryProof, PublicInputs, Transaction};
        use axiom_core_logic::CoreLogicMode;

        // GAP-6 FIX: Route scar heal signing through Core (CL9).
        // Lambda MUST NOT call sign_dilithium directly.
        let inputs = PublicInputs {
            recall_attestation: None,
            mode: CoreLogicMode::CL9,
            oods_attestation: None,
            local_core_id: self.expected_core_id,
            withdrawal_inputs: None,
            transaction: Transaction {
                recall_target_tx_id: None,
                consumed_state_id: [0u8; 32],
                client_pk: vec![],
                sender_wallet_id: String::new(),
                wallet_seq: 0,
                receiver_wallet_id: String::new(),
                receiver_address: None,
                amount: 0,
                reference: String::new(),
                nonce: 0,
                epoch: 0,
                client_sig: vec![],
                owner_proof: None,
                scar_passcode: None,
                burn_target_tx_id: None,
                required_k: 0,
                proof_type: 0,
                oracle_claim: None,
                core_version: String::new(),
                core_id: [0u8; 32],
                kind: TxKind::Normal,
            },
            prev_receipts: vec![],
            current_state: None,
            vbc_bundle: None,
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            my_validator_pk: None,
            overlapped_signatures: vec![],
            group_member_index: None,
            sender_fact_chain: None,
            max_fact_links: if self.max_fact_links > 0 { Some(self.max_fact_links as u32) } else { None },
            receiver_fact_chain: None,
            my_dilithium_sk: Some(self.dilithium_sk.clone()),
            my_dilithium_pk: Some(self.dilithium_pk.clone()),
            my_validator_id: Some(self.validator_id),
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            zkp_nonce: None,
            scar_heal_tx_id: Some(*original_tx_id),
            scar_heal_nabla_id: Some(nabla_confirmation.nabla_node_id),
            scar_heal_root_hash: Some(nabla_confirmation.root_hash),
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
        
        };

        let outputs = axiom_core_logic::execute_core(inputs);

        let signature = match outputs.result {
            axiom_core_logic::ValidationResult::Accept => {
                outputs.fact_signature.ok_or_else(||
                    LambdaError::CoreError("CL9: Core did not return scar heal signature".into()))?
            }
            _ => {
                let reason = outputs.rejection_reason
                    .map(|r| format!("{}", r))
                    .unwrap_or_else(|| "unknown".into());
                return Err(LambdaError::CoreError(format!("CL9 rejected: {}", reason)));
            }
        };

        // Build vbc_genesis_anchor from our VBC's issuer set
        let vbc_genesis_anchor: Option<Vec<[u8; 32]>> = {
            let issuer_set = &self.vbc.target_vbc.issuer_set;
            if issuer_set.is_empty() {
                None
            } else {
                Some(issuer_set.iter().map(|pk| {
                    *blake3::hash(pk).as_bytes()
                }).collect())
            }
        };

        let witness = FactWitness {
            validator_id: self.validator_id,
            validator_pk: self.dilithium_pk.clone(),
            signature,
            vbc_genesis_anchor,
        };

        info!("[SCAR_HEAL] Built recovery proof for tx={} receiver={}",
            hex::encode(&original_tx_id[..8]), receiver_wallet_id);

        Ok(ScarRecoveryProof {
            original_tx_id: *original_tx_id,
            nabla_confirmation,
            healing_witnesses: vec![witness],
            receiver_wallet_id,
            fact_link_index: None,
        })
    }

    /// Apply a ScarRecoveryProof to a scarred FACT link.
    ///
    /// Verifies the proof via Core (verify_scar_recovery_proof), then sets
    /// nabla_confirmation on the matching FACT link. Returns downstream
    /// ReceiverContact targets for notification forwarding.
    pub fn apply_scar_recovery(
        &self,
        proof: &axiom_core_logic::types::ScarRecoveryProof,
        wallet_pk: &[u8],
    ) -> Result<Vec<axiom_core_logic::types::ReceiverContact>, LambdaError> {
        // Verify through Core (sole cryptographic authority)
        axiom_core_logic::fact::verify_scar_recovery_proof(proof)
            .map_err(|e| LambdaError::CoreError(format!("Scar recovery proof invalid: {}", e)))?;

        // Wallet state lookup retained for existence check; the
        // downstream-target scan over StoredWalletState.fact_chain was
        // removed when that field was deprecated (YPX-001 §1.6 — client
        // is authoritative). Downstream-receiver notification now needs
        // the client's FACT chain in scope; until that wiring is added,
        // we return an empty target list (scar heal still applies to the
        // sender's chain via the proof itself).
        // TODO(ark-k0): scar recovery is pk-only here; Standard (k=3) suffices for
        // normal wallets. If an Ark (k=0) chain ever scar-recovers via this path,
        // thread the tier from the recovery proof's wallet_id.
        let _state = self.storage.get_wallet_state(wallet_pk, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)?
            .ok_or_else(|| LambdaError::InvalidRequest(
                format!("Wallet not found: {}", hex::encode(&wallet_pk[..8]))
            ))?;

        let downstream_targets = Vec::new();

        info!("[SCAR_HEAL] Applied recovery for tx={}, {} downstream targets",
            hex::encode(&proof.original_tx_id[..8]), downstream_targets.len());

        Ok(downstream_targets)
    }

    // =========================================================================
    // YPX-007: ZKP Qualification
    // =========================================================================

    /// Check if this validator is currently ZKP-qualified.
    pub fn is_zkp_qualified(&self) -> bool {
        let qual = self.zkp_qualification.lock();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        qual.is_valid(now)
    }

    /// Mark this validator as ZKP-qualified after successful benchmark.
    /// Called by the qualification orchestrator after Core verifies the STARK proof
    /// and confirms elapsed time < ZKP_QUAL_THRESHOLD_SECS.
    pub fn set_zkp_qualified(&self) {
        let mut qual = self.zkp_qualification.lock();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        qual.zkp_qualified = true;
        qual.qualified_at = Some(now);
        self.stats.zkp_qualified.store(true, std::sync::atomic::Ordering::Relaxed);
        info!("ZKP qualification granted at t={}", now);
    }

}

/// YPX-001 §1.5.1 scar-consent gate trigger (ACTIVE 2026-07-11 — deferral
/// lifted). Returns the number of gate-relevant scars in the sender's
/// client-carried FACT chain, or 0 when the TX is exempt from the gate.
/// `> 0` ⇒ the overlapped validator pauses the TX pending receiver consent.
///
/// **Trigger definition:** a scar is an UNRESOLVED link — no
/// `nabla_confirmation`, no `burn_proof`, no `recall_proof` — the same
/// resolution rule FACT compression uses (YPX-001 §1.5). NOT the
/// under-witnessed (`witnesses < required_k`) count: under the Quorum Gate
/// (YP §17.1.2) a sub-quorum link can never anchor, so that pre-activation
/// trigger was unreachable — the historical "commented-out" state of this
/// gate.
///
/// **ARK carve-out (YPX-010):** links with `required_k == 0` are Ark
/// provenance — scarred BY DESIGN and disclosed up front; the receiver
/// prices that risk via the Confidence Index, not a passcode. Every
/// connected-mode link carries `required_k >= 3` (Quorum Gate floor), so
/// the filter is exact. Likewise a TX whose sender or receiver wallet_id
/// decodes to the Ark tier (`K_ARK = 0`) skips the gate entirely — the Ark
/// load/flood/recede lifecycle has no passcode dance. Undecodable
/// wallet_ids fall through to gating (fail-closed: consent can't be
/// skipped by mangling a wallet_id).
///
/// **Exemptions** (no external receiver to consent / consent incoherent):
/// - CLARA attestation present (YPX-018): the wallet healed through a
///   witnessed TX_HEAL; the heal link's confirmation legitimately lives on
///   the /clara channel, so its unresolved look is expected.
/// - Burn (`burn_target_tx_id`): burns are the CURE for scars; the target
///   is pinned by Core's `validate_burn_target`.
/// - Recall (YPX-022): self-send recovery whose chain legitimately carries
///   the failed send's scarred link; safety is the CL2 attestation +
///   Nabla consume-once.
/// - Heal / HAL re-anchor: self-sends — sender == receiver.
/// (Genesis claims never reach the gate: the `!prev_receipts.is_empty()`
/// guard at the call site excludes them.)
/// YPX-001 §1.5.1 — verify a scar-consent voucher against the request's own
/// prev-receipt witness set. True iff: the voucher's txid matches this tx,
/// its `validator_id` appears among the prev-receipt witnesses (the same
/// k-signed, §15-anchored set every validator already validates — the
/// sender cannot alter it without breaking those signatures), and the
/// Ed25519 signature over `compute_scar_consent_voucher_payload(txid)`
/// verifies against that witness's recorded public key. Malformed pk/sig
/// fail CLOSED.
pub(crate) fn verify_scar_consent_voucher(
    voucher: &crate::types::ScarConsentVoucher,
    txid: &[u8; 32],
    prev_receipts: &[axiom_core_logic::types::Receipt],
) -> bool {
    if voucher.txid != *txid {
        return false;
    }
    let issuer_pk = prev_receipts.iter()
        .flat_map(|r| r.witness_sigs.iter())
        .find(|ws| ws.validator_id == voucher.validator_id)
        .map(|ws| ws.validator_pk.clone());
    let Some(pk_bytes) = issuer_pk else { return false };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr) else { return false };
    let Ok(sig_arr) = <[u8; 64]>::try_from(voucher.signature.as_slice()) else { return false };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let payload = axiom_core_logic::compute::compute_scar_consent_voucher_payload(txid);
    use ed25519_dalek::Verifier;
    vk.verify(&payload, &sig).is_ok()
}

pub(crate) fn scar_consent_gate_count(
    chain: &axiom_core_logic::types::FactChain,
    tx: &Transaction,
    has_clara_attestation: bool,
) -> usize {
    if has_clara_attestation
        || tx.burn_target_tx_id.is_some()
        || tx.is_recall()
        || tx.is_heal()
        || tx.is_hal_reanchor()
    {
        return 0;
    }
    let is_ark_endpoint = [tx.sender_wallet_id.as_str(), tx.receiver_wallet_id.as_str()]
        .iter()
        .any(|wid| {
            axiom_core_logic::wallet_id::extract_security_level(wid)
                .map(|(k, _)| k == axiom_core_logic::wallet_id::K_ARK)
                .unwrap_or(false)
        });
    if is_ark_endpoint {
        return 0;
    }
    chain.links.iter()
        .filter(|l| {
            // A genuine burn destroys the value (§1.5.4), so a burned link never
            // gates — inherited taint included: there is no tainted value left to
            // warn a downstream receiver about.
            if l.burn_proof.is_some() {
                return false;
            }
            let own_unresolved = l.nabla_confirmation.is_none()
                && l.recall_proof.is_none()
                && l.required_k > 0;
            // YPX-001 §1.5.1a: inherited taint keeps the link gate-relevant
            // no matter how its own transition resolved — every downstream
            // receiver consents in turn until the ORIGIN txid resolves (or the
            // holder burns the tainted value, handled above).
            own_unresolved || l.inherited_unresolved() > 0
        })
        .count()
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod tests {
    use super::*;
    use tempfile::tempdir;
    use rand::rngs::OsRng;
    use blake3::Hasher;
    
    /// Compute commitment_hash for tests only.
    /// In production, ONLY Core computes this. Tests need it to create valid signatures.
    fn test_compute_commitment(transaction: &Transaction) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"AXIOM_WITNESS_V2");
        hasher.update(&transaction.consumed_state_id);
        hasher.update(&transaction.client_pk);
        hasher.update(&transaction.wallet_seq.to_le_bytes());
        hasher.update(transaction.receiver_wallet_id.as_bytes());
        hasher.update(&transaction.amount.to_le_bytes());
        hasher.update(&transaction.nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
    
    /// Create a test engine using a REAL genesis VBC.
    ///
    /// Looks for VBC in these locations (in order):
    /// 1. AXIOM_TEST_VBC env var  
    /// 2. test-fixtures/vbc.json (relative to workspace)
    /// 3. ~/.axiom/axiom-first-penguin-alpha/config/vbc.json
    ///
    /// Tests MUST use real VBCs from the genesis ceremony — no mocks.
    pub fn create_test_engine() -> ConsensusEngine {
        let _dir = tempdir().unwrap();
        let _dir = Box::leak(Box::new(_dir));

        let storage = Arc::new(Storage::open_test().unwrap());
        
        let vbc_path = find_test_vbc();
        
        // Try to find the Ed25519 private key.
        // Genesis ceremony stores it as raw 32 bytes at:
        //   {penguin}/keys/ed25519.key (installed)
        //   {penguin}/config/ed25519.key (pre-install)
        // Or as hex in some setups.
        let vbc_dir = vbc_path.parent().unwrap();
        let sk_candidates = [
            vbc_dir.join("../keys/ed25519.key"),  // penguin/keys/ed25519.key (canonical)
            vbc_dir.join("ed25519.key"),           // config/ed25519.key (pre-install)
            vbc_dir.join("ed25519.sk"),
        ];
        
        let signing_key = 'find_key: {
            for sk_path in &sk_candidates {
                if sk_path.exists() {
                    let sk_bytes = std::fs::read(sk_path)
                        .expect("Failed to read Ed25519 key file");
                    
                    // Try as raw 32 bytes first
                    if sk_bytes.len() == 32 {
                        let mut seed = [0u8; 32];
                        seed.copy_from_slice(&sk_bytes);
                        eprintln!("[TEST] Loaded Ed25519 key from {:?} (raw 32 bytes)", sk_path);
                        break 'find_key SigningKey::from_bytes(&seed);
                    }
                    // Try as 64-byte expanded key (first 32 = seed)
                    if sk_bytes.len() == 64 {
                        let mut seed = [0u8; 32];
                        seed.copy_from_slice(&sk_bytes[..32]);
                        eprintln!("[TEST] Loaded Ed25519 key from {:?} (64 bytes, using first 32)", sk_path);
                        break 'find_key SigningKey::from_bytes(&seed);
                    }
                    // Try as hex string
                    if let Ok(decoded) = hex::decode(String::from_utf8_lossy(&sk_bytes).trim()) {
                        if decoded.len() >= 32 {
                            let mut seed = [0u8; 32];
                            seed.copy_from_slice(&decoded[..32]);
                            eprintln!("[TEST] Loaded Ed25519 key from {:?} (hex)", sk_path);
                            break 'find_key SigningKey::from_bytes(&seed);
                        }
                    }
                    eprintln!("[TEST] Found {:?} but couldn't parse ({} bytes)", sk_path, sk_bytes.len());
                }
            }
            // No key found — use fresh key. VBC chain verification passes,
            // but PK won't match VBC's subject_pubkey_ed25519.
            eprintln!("[TEST] No Ed25519 key found — using fresh key (VBC chain OK, PK mismatch expected)");
            SigningKey::generate(&mut OsRng)
        };
        
        // Build AVM config — for tests, use a minimal ELF (native execution fallback)
        // The AVM interpreter with riscv-interpreter feature will use the real ELF
        // if available, otherwise falls back to native execute_core()
        let avm_config = {
            // Try to find a real core-avm ELF
            let elf_candidates: Vec<Option<std::path::PathBuf>> = vec![
                std::env::var("AXIOM_ZKVM_ELF").ok().map(std::path::PathBuf::from),
                Some(std::path::PathBuf::from("target/riscv32im-unknown-none-elf/release/axiom-core")),
                Some(std::path::PathBuf::from("../target/riscv32im-unknown-none-elf/release/axiom-core")),
            ];
            let elf_path = elf_candidates.into_iter()
                .flatten()
                .find(|p| p.exists());

            if let Some(path) = elf_path {
                eprintln!("[TEST] Loading AVM ELF from {:?}", path);
                axiom_dmap_vm::AvmConfig::from_paths(
                    path.to_str().unwrap(), None
                ).expect("Failed to load AVM ELF")
            } else {
                // Use sentinel ELF — AVM interpreter falls back to native execute_core()
                eprintln!("[TEST] No AVM ELF found — using native execution fallback");
                axiom_dmap_vm::AvmConfig::from_elf(b"AXIOM_CORE_V2".to_vec())
            }
        };
        let mut engine = ConsensusEngine::new(storage, signing_key, &vbc_path, avm_config, None, None).unwrap();
        // Initialize management DB for DWP/JFP tests
        engine.init_management(Arc::new(crate::management_db::ManagementDb::open_test().unwrap()));
        engine
    }

    /// Build a valid DMAP attestation stamped with `core_id`, wrapped in a minimal
    /// ValidatorCheque (only the fields the redeem DMAP gate reads need be meaningful).
    /// Mirrors avm's `make_test_attestation`.
    fn mk_dmap_cheque(core_id: [u8; 32], sk_seed: u8) -> ValidatorCheque {
        use axiom_dmap_vm::dmap::{DmapAttestation, DmapCheckpoint, DmapTrace};
        use ed25519_dalek::{Signer, SigningKey};
        let input_hash = [0xBB; 32];
        let output_hash = [0xCC; 32];
        let sk = SigningKey::from_bytes(&[sk_seed; 32]);
        let vpk: [u8; 32] = sk.verifying_key().to_bytes();
        let checkpoints: Vec<DmapCheckpoint> = (0..50u64)
            .map(|i| DmapCheckpoint {
                instruction_count: (i + 1) * 10_000,
                pc: 0x1000 + (i as u32) * 4,
                memory_root: { let mut h = [0u8; 32]; h[0] = i as u8; h },
                register_hash: [i as u8; 32],
            })
            .collect();
        let trace = DmapTrace::from_checkpoints(checkpoints);
        let mut att =
            DmapAttestation::from_trace(core_id, input_hash, output_hash, &trace, 1_710_000_000, vpk);
        let sig = sk.sign(&att.signing_payload());
        att.set_signature(sig.to_bytes().to_vec());
        let mut execution_proof = Vec::new();
        ciborium::ser::into_writer(&att, &mut execution_proof).unwrap();
        ValidatorCheque {
            recall_target_tx_id: None,
            txid: [0u8; 32],
            validator_id: [1u8; 32],
            validator_pk: vpk.to_vec(),
            signature: vec![0u8; 64],
            execution_proof,
            vbc_bundle: None,
            carrier_type: "test".to_string(),
            carrier_address: "test".to_string(),
            sender_wallet_id: "alice@example.com/87654321".to_string(),
            receiver_wallet_id: "bob@example.com/12345678".to_string(),
            amount: 1_000_000,
            rate_bps: 10,
            reference: "test".to_string(),
            epoch: 1,
            created_at: 12345,
            state_hash: [0x11; 32],
            produced_state_id: [0x22; 32],
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32], // 0 → verify uses the attestation's own hashes (GAP-B legacy)
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        }
    }

    /// End-to-end test of the REAL redeem-side DMAP gate — the extracted
    /// `verify_cheque_dmap_attestation` — through the CoreID lineage accept-set (§11):
    ///   • a cheque stamped with the node's CURRENT CoreID verifies;
    ///   • a cheque stamped with a PRIOR CoreID is `WrongCore` when that CoreID is NOT
    ///     blessed, and VERIFIES when it IS. Build with
    ///     `AXIOM_BLESSED_PRIOR_CORE_IDS=a1a1…a1` (64 hex of 0xA1) to exercise the accept
    ///     branch; the default (unset) build exercises the reject branch.
    /// Complements the avm resolver-composition test and the version.rs units by running
    /// the actual Lambda redeem method against a real, signed attestation.
    #[test]
    fn accept_set_redeem_dmap_gate() {
        let engine = create_test_engine();
        let current = engine.expected_core_id;

        // (1) A cheque minted under the CURRENT CoreID passes the real redeem gate.
        let same = mk_dmap_cheque(current, 0x07);
        assert!(
            engine.verify_cheque_dmap_attestation(&same).is_ok(),
            "a cheque minted under the current CoreID must pass the redeem DMAP gate"
        );

        // (2) A cheque minted under a PRIOR CoreID: accepted iff that CoreID is blessed.
        let prior = [0xA1u8; 32];
        assert_ne!(prior, current, "test setup: prior CoreID must differ from current");
        let cross = mk_dmap_cheque(prior, 0x07);
        let res = engine.verify_cheque_dmap_attestation(&cross);

        if axiom_core_logic::version::is_accepted_core_id(&prior, &current) {
            // Built with AXIOM_BLESSED_PRIOR_CORE_IDS blessing `prior`.
            assert!(
                res.is_ok(),
                "a blessed prior-CoreID cheque must pass the redeem DMAP gate, got {res:?}"
            );
            eprintln!("redeem DMAP gate: BLESSED prior-CoreID cheque ACCEPTED (accept-set active)");
        } else {
            // Default build: prior not blessed → WrongCore.
            let err = format!(
                "{:?}",
                res.expect_err("a non-blessed prior-CoreID cheque must be rejected")
            );
            assert!(
                err.contains("WrongCore"),
                "non-blessed prior-CoreID cheque must fail WrongCore, got: {err}"
            );
            eprintln!("redeem DMAP gate: non-blessed prior-CoreID cheque REJECTED (WrongCore)");
        }
    }

    /// Find a real VBC file for testing.
    fn find_test_vbc() -> std::path::PathBuf {
        // 1. Environment variable
        if let Ok(path) = std::env::var("AXIOM_TEST_VBC") {
            let p = std::path::PathBuf::from(&path);
            if p.exists() { return p; }
            eprintln!("[TEST] AXIOM_TEST_VBC={} not found", path);
        }
        
        // 2. test-fixtures/vbc.json (try several relative paths)
        for candidate in &[
            "test-fixtures/vbc.json",
            "../test-fixtures/vbc.json",
            "../../test-fixtures/vbc.json",
        ] {
            let p = std::path::PathBuf::from(candidate);
            if p.exists() { return p; }
        }
        
        // 3. Installed genesis VBC (try all 10 validators)
        //    Check AXIOM_DATA_DIR first (~/axiom/), then legacy ~/.axiom/
        if let Ok(home) = std::env::var("HOME") {
            let validators = [
                "axiom-first-penguin-alpha",
                "axiom-first-penguin-beta",
                "axiom-first-penguin-gamma",
                "axiom-first-penguin-delta",
                "axiom-first-penguin-epsilon",
                "axiom-first-penguin-zeta",
                "axiom-first-penguin-eta",
                "axiom-first-penguin-theta",
                "axiom-first-penguin-iota",
                "axiom-first-penguin-kappa",
            ];
            let axiom_dir = std::env::var("AXIOM_DATA_DIR")
                .unwrap_or_else(|_| format!("{}/axiom", home));
            for v in &validators {
                // Primary: ~/axiom/{validator}/config/vbc.json
                let installed = std::path::PathBuf::from(&axiom_dir)
                    .join(format!("{}/config/vbc.json", v));
                if installed.exists() { return installed; }
            }
        }
        
        panic!(
            "\n\
             ╔══════════════════════════════════════════════════════════════╗\n\
             ║  TEST VBC NOT FOUND — Lambda tests need a real VBC         ║\n\
             ╠══════════════════════════════════════════════════════════════╣\n\
             ║  Options:                                                   ║\n\
             ║  1. Set AXIOM_TEST_VBC=/path/to/vbc.json                   ║\n\
             ║  2. Copy a genesis VBC to test-fixtures/vbc.json            ║\n\
             ║  3. Run install_genesis.sh to install validators            ║\n\
             ╚══════════════════════════════════════════════════════════════╝"
        );
    }
    
    fn create_test_request() -> WitnessRequest {
        // Generate a valid wallet_id with proper checksum
        let receiver_wallet_id = axiom_core_logic::wallet_id::generate_wallet_id(
            "test@example.com", "45", &[0u8; 32]
        ).unwrap();
        WitnessRequest {
            scar_consent_voucher: None,
            recall_attestation: None,
            oods_attestation: None,
            request_id: "test-123".to_string(),
            transaction: Transaction {
                recall_target_tx_id: None,
                consumed_state_id: [0u8; 32],
                client_pk: vec![0u8; 32],
                sender_wallet_id: String::new(),
                wallet_seq: 1,
                receiver_wallet_id,
                receiver_address: None,
                amount: 100_000,
                reference: "test".into(),
                nonce: 1,
                epoch: 1,
                client_sig: vec![0u8; 64],
                owner_proof: None,
                scar_passcode: None,
                burn_target_tx_id: None,
                required_k: 0,
                proof_type: 0,
                oracle_claim: None,
                core_version: String::new(),
                core_id: [0u8; 32],
                kind: TxKind::Normal,
            },
            overlapped_signatures: vec![],
            group_member_index: None,
            prev_receipts: vec![],
            claimed_balance_for_sabr: 1_000_000,
            claimed_hibernation_until: 0,
            requester_address: "sender@example.com".to_string(),
            offered_fee: 100,
            validator_hints: vec![],
            produced_state_id: None,
            commitment_hash: None,
            sender_fact_chain: None,
            cl1_execution_proof: vec![],
            auth_hash: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            clara_attestation: None,
            nabla_hint: None,
        }
    }

    // ── Phase 1 multi-carrier discovery (YP §27.5.2, 2026-05-14) ───────

    /// Engine with a multi-carrier list emits all entries through VSP
    /// in the order they were registered.
    #[test]
    fn test_set_carriers_emits_through_vsp() {
        let engine = create_test_engine();
        let uris = vec![
            "email:alpha@axiom.network".to_string(),
            "tcp:127.0.0.1:7778".to_string(),
            "ws:127.0.0.1:7779".to_string(),
        ];
        engine.set_carriers(uris.clone());
        let resp = engine.validator_status("vsp-multi");
        assert_eq!(resp.carriers, uris,
            "VSP must emit the carrier list verbatim, in registration order");
    }

    /// Engine without `set_carriers` ever called emits an empty Vec
    /// through VSP — NOT the pre-Phase-1 "dev:validator-<8 hex>"
    /// scalar-derived placeholder.
    #[test]
    fn test_validator_status_empty_carriers_default() {
        let engine = create_test_engine();
        let resp = engine.validator_status("vsp-empty");
        assert!(resp.carriers.is_empty(),
            "VSP must emit empty carriers Vec when set_carriers was never called \
             (was: pre-Phase-1 hardcoded vec![\"dev:validator-...\"]).  Operator \
             config issue surfaces as empty list, not as garbage.");
    }

    /// `set_carriers` replaces the previous list (idempotent re-call wins
    /// the most recent push).
    #[test]
    fn test_set_carriers_replaces_previous() {
        let engine = create_test_engine();
        engine.set_carriers(vec!["email:old@axiom".to_string()]);
        engine.set_carriers(vec![
            "email:new@axiom".to_string(),
            "tcp:127.0.0.1:9000".to_string(),
        ]);
        let resp = engine.validator_status("vsp-replace");
        assert_eq!(resp.carriers.len(), 2);
        assert_eq!(resp.carriers[0], "email:new@axiom");
        assert_eq!(resp.carriers[1], "tcp:127.0.0.1:9000");
    }

    /// `[carriers.fatmama]` (the cluster's INBOUND FATMAMA endpoint
    /// per YP §27.5.2; see docs/AXIOM_DESIGN_FATMAMA.md §0) flows
    /// through end-to-end: ANTIE's
    /// `CarriersConfig { maildir, fatmama }.to_uri_list()` produces
    /// `["email:...", "fatmama:H:P"]` (canonical order — proven in
    /// `antie::carrier::tests::to_uri_list_maildir_plus_fatmama_canonical_order`),
    /// and Lambda's `set_carriers` → VSP path echoes that pair
    /// verbatim. Mirrors the production shape `validator_setup` now
    /// writes into every per-validator antie.toml.
    #[test]
    fn test_set_carriers_emits_fatmama_uri() {
        let engine = create_test_engine();
        let uris = vec![
            "email:alpha@axiom.network".to_string(),
            "fatmama:10.0.0.5:2525".to_string(),
        ];
        engine.set_carriers(uris.clone());
        let resp = engine.validator_status("vsp-fatmama");
        assert_eq!(resp.carriers, uris,
            "VSP must emit fatmama:H:P verbatim in canonical order \
             (email first, then fatmama).  Mac wallet's seed-fallback \
             stub is dropped once this URI surfaces from real VSP.");
    }

    #[test]
    fn test_compute_txid() {
        let engine = create_test_engine();
        let request = create_test_request();

        let txid = engine.compute_txid(&request.transaction);
        assert_eq!(txid.len(), 32);

        // Same transaction should produce same txid
        let txid2 = engine.compute_txid(&request.transaction);
        assert_eq!(txid, txid2);
    }

    /// Mac handoff 2026-06-05 — same request_id must replay the prior
    /// response verbatim (same cheque, same signature, same created_at),
    /// not run a fresh CL2/CL3 and emit a distinct cheque.
    #[test]
    fn witness_idempotency_cache_replays_by_request_id() {
        let engine = create_test_engine();

        // Hand-craft a sentinel response with a recognizable request_id.
        // We test the cache machinery directly — wiring through
        // `process_witness_request` would require a full witness round.
        let stamp = "req-mac-handoff-2026-06-05".to_string();
        let resp = WitnessResponse {
            request_id: stamp.clone(),
            success: true,
            witness_signature: None,
            overlapped_signatures: vec![],
            rejection: None,
            cheque_for_receiver: None,
            receipt: None,
            produced_state_id: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            txid: vec![],
            validator_hints: vec![],
            sender_fact_chain: None,
            audit_demand: None,
            audit_request: None,
            nonce_challenge: None,
            pulse_proof: None,
            audit_failed: false,
            outbound_peer_audit: None,
            confidence_index: None,
            scar_consent_for_receiver: None,
            scar_consent_voucher: None,
        };

        // First time through: cache miss; subsequent lookup hits.
        engine.remember_witness_response(&resp);
        let hit = {
            let cache = engine.witness_idempotency_cache.lock();
            cache.iter().find(|(k, _)| k == &stamp).map(|(_, r)| r.clone())
        };
        assert!(hit.is_some(), "cache must replay request_id={}", stamp);
        assert_eq!(hit.unwrap().request_id, stamp);

        // Empty request_id MUST NOT be cached (collision risk across
        // unrelated requests).
        let mut empty = resp.clone();
        empty.request_id = String::new();
        engine.remember_witness_response(&empty);
        let empty_hit = {
            let cache = engine.witness_idempotency_cache.lock();
            cache.iter().any(|(k, _)| k.is_empty())
        };
        assert!(!empty_hit, "empty request_id must not be stored");
    }

    /// Redeem-side mirror of `witness_idempotency_cache_replays_by_request_id`.
    /// A duplicate redeem (client-side carrier duplication) with the SAME
    /// request_id must replay the first RedeemResponse instead of re-executing
    /// into `E_CHEQUE_ALREADY_REDEEMED`. Mac handoff 2026-07-06.
    #[test]
    fn redeem_idempotency_cache_replays_by_request_id() {
        let engine = create_test_engine();

        let stamp = "req-mac-handoff-2026-07-06-redeem".to_string();
        let resp = RedeemResponse {
            request_id: stamp.clone(),
            success: true,
            new_balance: Some(42),
            new_state_id: None,
            witness_signature: None,
            commitment_hash: None,
            state_hash: None,
            receipt_commitment: None,
            error_response: None,
            validator_hints: vec![],
            fact_signature: None,
            receiver_fact_chain: None,
        };

        // Store the first response; a later duplicate lookup must hit + replay it.
        engine.remember_redeem_response(&resp);
        let hit = {
            let cache = engine.redeem_idempotency_cache.lock();
            cache.iter().find(|(k, _)| k == &stamp).map(|(_, r)| r.clone())
        };
        assert!(hit.is_some(), "redeem cache must replay request_id={}", stamp);
        let hit = hit.unwrap();
        assert_eq!(hit.request_id, stamp);
        assert!(hit.success, "replayed response must carry the first (success) result");
        assert_eq!(hit.new_balance, Some(42));

        // Empty request_id MUST NOT be cached.
        let mut empty = resp.clone();
        empty.request_id = String::new();
        engine.remember_redeem_response(&empty);
        let empty_hit = {
            let cache = engine.redeem_idempotency_cache.lock();
            cache.iter().any(|(k, _)| k.is_empty())
        };
        assert!(!empty_hit, "empty request_id must not be stored");
    }

    #[test]
    fn test_sign_witness() {
        let engine = create_test_engine();
        let request = create_test_request();
        
        // Compute commitment_hash as Core would (sign_witness requires it — "can crash, must not lie")
        let tx = &request.transaction;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_WITNESS_V2");
        hasher.update(&tx.consumed_state_id);
        hasher.update(&tx.client_pk);
        hasher.update(&tx.wallet_seq.to_le_bytes());
        hasher.update(tx.receiver_wallet_id.as_bytes());
        hasher.update(&tx.amount.to_le_bytes());
        hasher.update(&tx.nonce.to_le_bytes());
        let commitment: [u8; 32] = *hasher.finalize().as_bytes();
        
        let sig = engine.sign_witness(&request.transaction, Some(&commitment)).unwrap();
        
        assert!(!sig.validator_pk.is_empty());
        assert!(!sig.signature.is_empty());
    }
    
    #[tokio::test]
    async fn test_process_witness_request() {
        let engine = create_test_engine();
        let mut request = create_test_request();
        
        // For GENESIS transaction (wallet_seq = 0), we don't need prev_receipts
        // Genesis state ID is computed as H("AXIOM_GENESIS" || pk || balance)
        let pk = request.transaction.client_pk.clone();
        let balance = 1_000_000u64;  // Must be >= transaction amount (100_000)

        // Compute genesis state_id using Core's function (SHA3-256, not BLAKE3)
        let pk_array: [u8; 32] = pk.clone().try_into().unwrap();
        let genesis_state_id = axiom_core_logic::genesis::compute_genesis_state_id(&pk_array, balance, 3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP);

        let wallet_state = StoredWalletState {
            public_key: pk.clone(),
            balance,
            wallet_seq: 0,  // Genesis
            state_id: genesis_state_id,
            last_tx_id: None,
            status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: None, hibernation_until: 0,
            wallet_id: None,
        };

        // MUST set genesis state for is_overlapped_validator to return true
        engine.storage.set_genesis_state(&pk_array, 3, 1, &wallet_state).unwrap();

        // Also set wallet state
        engine.storage.set_wallet_state(&wallet_state, 3, 1).unwrap();

        // Update request to be a genesis transaction
        request.transaction.consumed_state_id = genesis_state_id;
        request.transaction.wallet_seq = 1;  // First tx after genesis
        request.claimed_balance_for_sabr = balance;
        request.prev_receipts = vec![];  // Genesis doesn't need prev_receipts

        // Compute produced_state_id using Core's function (SHA3-256 "AXIOM_STATE")
        let new_balance = balance - request.transaction.amount;
        let produced_state_id = axiom_core_logic::compute::compute_produced_state_id(
            &pk_array, new_balance, request.transaction.wallet_seq,
            &genesis_state_id, request.transaction.nonce,
        );
        request.produced_state_id = Some(produced_state_id.to_vec());
        
        // Compute commitment_hash (as Core CL2 would — sign_witness requires it)
        let tx = &request.transaction;
        let mut ch_hasher = blake3::Hasher::new();
        ch_hasher.update(b"AXIOM_WITNESS_V2");
        ch_hasher.update(&tx.consumed_state_id);
        ch_hasher.update(&tx.client_pk);
        ch_hasher.update(&tx.wallet_seq.to_le_bytes());
        ch_hasher.update(tx.receiver_wallet_id.as_bytes());
        ch_hasher.update(&tx.amount.to_le_bytes());
        ch_hasher.update(&tx.nonce.to_le_bytes());
        let commitment_hash: [u8; 32] = *ch_hasher.finalize().as_bytes();
        request.commitment_hash = Some(commitment_hash.to_vec());
        
        let result = engine.process_witness_request(request).await;

        // Core-bin validates the transaction end-to-end. With a test dummy signature
        // (all zeros), Core will reject with E_INVALID_CLIENT_SIG. This is expected —
        // the test verifies the round-trip through AVM (axiom-core.elf) works, not that the
        // dummy transaction is valid.
        match &result {
            Ok(_) => {},  // If somehow it passes, that's fine too
            Err(LambdaError::CoreValidationFailed(msg)) => {
                // Legacy: string-wrapped Core rejection
                eprintln!("[TEST] Core validation (expected, legacy): {}", msg);
            },
            Err(LambdaError::CoreRejected(ve)) => {
                // Phase 2b.3: typed Core rejection
                eprintln!("[TEST] Core validation (expected, typed): {:?}", ve);
            },
            Err(e) => panic!("Unexpected error from process_witness_request: {:?}", e),
        }
    }
    
    // ========================================================================
    // S-ABR Tests
    // ========================================================================
    
    #[test]
    fn test_required_overlap() {
        // k=3 requires 2 overlap
        assert_eq!(ConsensusEngine::required_overlap(3), 2);
        // k=4 requires 3 overlap
        assert_eq!(ConsensusEngine::required_overlap(4), 3);
        // k=5 requires 3 overlap
        assert_eq!(ConsensusEngine::required_overlap(5), 3);
    }
    
    #[test]
    fn test_sabr_overlapped_validator_balance_match() {
        let engine = create_test_engine();
        
        // Set up GENESIS wallet state in storage
        // For genesis, we're automatically "overlapped" if we have the genesis state
        let pk = vec![1u8; 32];
        let balance = 1000u64;
        
        // Compute genesis state_id using Core's function (SHA3-256, not BLAKE3)
        let pk_array: [u8; 32] = pk.clone().try_into().unwrap();
        let genesis_state_id = axiom_core_logic::genesis::compute_genesis_state_id(&pk_array, balance, 3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP);

        // Create wallet state
        let wallet_state = StoredWalletState {
            public_key: pk.clone(),
            balance,
            wallet_seq: 0,  // Genesis starts at 0
            state_id: genesis_state_id,
            last_tx_id: None,
            status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: None, hibernation_until: 0,
            wallet_id: None,
        };
        engine.storage.set_genesis_state(&pk_array, 3, 1, &wallet_state).unwrap();

        // Also store as wallet state
        engine.storage.set_wallet_state(&wallet_state, 3, 1).unwrap();
        
        // The refill path (post-CL2-rewire): Core CL2 decides overlap —
        // the genesis first-TX is CL2's empty-prev_receipts path, which
        // returns is_overlapped=Some(true). Lambda then refills via
        // lookup_previous_tx_record, whose genesis branch serves a
        // pseudo-record from the stored genesis state.
        let record = engine.lookup_previous_tx_record(&genesis_state_id, &pk, 3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)
            .expect("genesis pseudo-record must refill");
        assert_eq!(record.balance_after, balance, "Refilled balance should match storage");
        // process_witness_request builds SABRResult::Refilled with
        // wallet_seq = record.wallet_seq_after + 1.
        assert_eq!(record.wallet_seq_after + 1, 1, "Refilled seq should be 1 for first tx");
    }
    
    #[test]
    fn test_sabr_overlapped_validator_state_id_mismatch() {
        let engine = create_test_engine();

        // Set up wallet state in storage
        let pk = vec![1u8; 32];
        let state_id = [0xAB; 32];
        let wallet_state = StoredWalletState {
            public_key: pk.clone(),
            balance: 1000,
            wallet_seq: 5,
            state_id,
            last_tx_id: None, status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: None, hibernation_until: 0,
            wallet_id: None,
        };
        engine.storage.set_wallet_state(&wallet_state, 3, 1).unwrap();

        // The refill path (post-CL2-rewire): Core CL2 said overlapped, but
        // this validator has NO TransactionRecord whose produced_state_id
        // matches the claimed consumed_state_id (storage has 0xAB, the
        // claim is 0xCC). The refill is fail-stop — "can crash, must not
        // lie" — so lookup_previous_tx_record rejects.
        let result = engine.lookup_previous_tx_record(&[0xCC; 32], &pk, 3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP);
        assert!(result.is_err(), "refill must reject a state_id we have no record for");

        let err = result.unwrap_err();
        assert!(
            matches!(err, LambdaError::SabrStateChainMismatch { .. }),
            "expected SabrStateChainMismatch, got: {:?}",
            err
        );
    }

    // NOTE: "insufficient balance" is NOT checked by Lambda S-ABR
    // Lambda returns refilled values; Core checks balance sufficiency
    // during transaction validation (amount <= balance)
    
    // ========================================================================
    // Cheque Model Tests
    // ========================================================================
    
    #[test]
    fn test_create_validator_cheque() {
        let engine = create_test_engine();
        let request = create_test_request();
        
        // Compute commitment_hash as Core would
        let tx = &request.transaction;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_WITNESS_V2");
        hasher.update(&tx.consumed_state_id);
        hasher.update(&tx.client_pk);
        hasher.update(&tx.wallet_seq.to_le_bytes());
        hasher.update(tx.receiver_wallet_id.as_bytes());
        hasher.update(&tx.amount.to_le_bytes());
        hasher.update(&tx.nonce.to_le_bytes());
        let commitment: [u8; 32] = *hasher.finalize().as_bytes();
        
        let witness_sig = engine.sign_witness(&request.transaction, Some(&commitment)).unwrap();
        let txid = engine.compute_txid(&request.transaction);
        let state_hash = [0x11; 32];
        let produced_state_id = [0x22; 32];
        
        let cheque = engine.create_validator_cheque(
            &request.transaction,
            txid,
            &witness_sig,
            state_hash,
            produced_state_id,
            None,  // No FACT chain in test
            &[],   // No execution proof in test
            None,  // No ZKP nonce in test
            1,     // DMAP proof type
            [0u8; 32], // No DMAP hashes in test
            [0u8; 32],
            None,  // No nabla_hint in test
        );
        
        assert_eq!(cheque.txid, txid);
        assert_eq!(cheque.amount, request.transaction.amount);
        assert_eq!(cheque.receiver_wallet_id, request.transaction.receiver_wallet_id);
        assert!(!cheque.validator_pk.is_empty());
        assert!(!cheque.signature.is_empty());
    }
    
    #[test]
    fn test_cheque_bundle_consistency() {
        // Create consistent cheques (same txid, amount, receiver)
        let txid = [0x12; 32];
        let receiver = "bob@example.com/12345678".to_string();
        let amount = 1000u64;
        let epoch = 1u64;
        
        let cheque1 = ValidatorCheque {
            recall_target_tx_id: None,
            txid,
            validator_id: [1u8; 32],
            validator_pk: vec![1u8; 32],
            signature: vec![0u8; 64],
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".to_string(),
            carrier_address: "test-validator".to_string(),
            sender_wallet_id: "alice@example.com/87654321".to_string(),
            receiver_wallet_id: receiver.clone(),
            amount,
            rate_bps: 10,
            reference: "test".to_string(),
            epoch,
            created_at: 12345,
            state_hash: [0x11; 32],
            produced_state_id: [0x22; 32],
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        };

        let cheque2 = ValidatorCheque {
            recall_target_tx_id: None,
            txid,
            validator_id: [2u8; 32],
            validator_pk: vec![2u8; 32],
            signature: vec![0u8; 64],
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".to_string(),
            carrier_address: "test-validator".to_string(),
            sender_wallet_id: "alice@example.com/87654321".to_string(),
            receiver_wallet_id: receiver.clone(),
            amount,
            rate_bps: 10,
            reference: "test".to_string(),
            epoch,
            created_at: 12346,
            state_hash: [0x11; 32],
            produced_state_id: [0x22; 32],
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        };

        let cheque3 = ValidatorCheque {
            recall_target_tx_id: None,
            txid,
            validator_id: [3u8; 32],
            validator_pk: vec![3u8; 32],
            signature: vec![0u8; 64],
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".to_string(),
            carrier_address: "test-validator".to_string(),
            sender_wallet_id: "alice@example.com/87654321".to_string(),
            receiver_wallet_id: receiver.clone(),
            amount,
            rate_bps: 10,
            reference: "test".to_string(),
            epoch,
            created_at: 12347,
            state_hash: [0x11; 32],
            produced_state_id: [0x22; 32],
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        };

        let bundle = ChequeBundle {
            cheques: vec![cheque1, cheque2, cheque3],
            fact_chain: None,
        };

        // Should be consistent
        assert!(bundle.verify_consistency(), "Bundle should be consistent");
        assert!(bundle.has_k_cheques(3), "Bundle should have 3 cheques");
        assert_eq!(bundle.txid(), Some(txid));
        assert_eq!(bundle.amount(), Some(amount));
        assert_eq!(bundle.receiver_wallet_id(), Some(receiver.as_str()));
    }
    
    #[test]
    fn test_cheque_bundle_inconsistent_amount() {
        let txid = [0x12; 32];
        let receiver = "bob@example.com/12345678".to_string();
        
        let cheque1 = ValidatorCheque {
            recall_target_tx_id: None,
            txid,
            validator_id: [1u8; 32],
            validator_pk: vec![1u8; 32],
            signature: vec![0u8; 64],
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".to_string(),
            carrier_address: "test-validator".to_string(),
            sender_wallet_id: "alice@example.com/87654321".to_string(),
            receiver_wallet_id: receiver.clone(),
            amount: 100_000, // Different amount!
            rate_bps: 10,
            reference: "test".to_string(),
            epoch: 1,
            created_at: 12345,
            state_hash: [0x11; 32],
            produced_state_id: [0x22; 32],
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        };

        let cheque2 = ValidatorCheque {
            recall_target_tx_id: None,
            txid,
            validator_id: [2u8; 32],
            validator_pk: vec![2u8; 32],
            signature: vec![0u8; 64],
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".to_string(),
            carrier_address: "test-validator".to_string(),
            sender_wallet_id: "alice@example.com/87654321".to_string(),
            receiver_wallet_id: receiver.clone(),
            amount: 2000, // Different amount - INCONSISTENT!
            rate_bps: 10,
            reference: "test".to_string(),
            epoch: 1,
            created_at: 12346,
            state_hash: [0x11; 32],
            produced_state_id: [0x22; 32],
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        };

        let bundle = ChequeBundle {
            cheques: vec![cheque1, cheque2],
            fact_chain: None,
        };

        // Should NOT be consistent
        assert!(!bundle.verify_consistency(), "Bundle should be inconsistent due to amount mismatch");
    }
    
    #[test]
    fn test_cheque_bundle_duplicate_validators() {
        let txid = [0x12; 32];
        let receiver = "bob@example.com/12345678".to_string();
        let amount = 1000u64;
        
        // Same validator_pk for all three cheques - SHOULD BE REJECTED
        let cheque1 = ValidatorCheque {
            recall_target_tx_id: None,
            txid,
            validator_id: [1u8; 32],
            validator_pk: vec![1u8; 32], // Same validator
            signature: vec![0u8; 64],
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".to_string(),
            carrier_address: "test-validator".to_string(),
            sender_wallet_id: "alice@example.com/87654321".to_string(),
            receiver_wallet_id: receiver.clone(),
            amount,
            rate_bps: 10,
            reference: "test".to_string(),
            epoch: 1,
            created_at: 12345,
            state_hash: [0x11; 32],
            produced_state_id: [0x22; 32],
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        };

        let cheque2 = ValidatorCheque {
            recall_target_tx_id: None,
            txid,
            validator_id: [1u8; 32],
            validator_pk: vec![1u8; 32], // DUPLICATE - same as cheque1!
            signature: vec![0u8; 64],
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".to_string(),
            carrier_address: "test-validator".to_string(),
            sender_wallet_id: "alice@example.com/87654321".to_string(),
            receiver_wallet_id: receiver.clone(),
            amount,
            rate_bps: 10,
            reference: "test".to_string(),
            epoch: 1,
            created_at: 12346,
            state_hash: [0x11; 32],
            produced_state_id: [0x22; 32],
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        };

        let cheque3 = ValidatorCheque {
            recall_target_tx_id: None,
            txid,
            validator_id: [1u8; 32],
            validator_pk: vec![1u8; 32], // DUPLICATE - same as cheque1!
            signature: vec![0u8; 64],
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".to_string(),
            carrier_address: "test-validator".to_string(),
            sender_wallet_id: "alice@example.com/87654321".to_string(),
            receiver_wallet_id: receiver.clone(),
            amount,
            rate_bps: 10,
            reference: "test".to_string(),
            epoch: 1,
            created_at: 12347,
            state_hash: [0x11; 32],
            produced_state_id: [0x22; 32],
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        };

        let bundle = ChequeBundle {
            cheques: vec![cheque1, cheque2, cheque3],
            fact_chain: None,
        };

        // Should NOT have distinct validators
        assert!(!bundle.has_distinct_validators(), "Bundle should detect duplicate validators");
        // verify_consistency should also fail because it checks distinct validators
        assert!(!bundle.verify_consistency(), "Bundle with duplicate validators should not be consistent");
    }
    
    #[test]
    fn test_cheque_bundle_empty() {
        let bundle = ChequeBundle {
            cheques: vec![],
            fact_chain: None,
        };

        assert!(!bundle.verify_consistency(), "Empty bundle should not be consistent");
        assert!(!bundle.has_k_cheques(3), "Empty bundle should not have k cheques");
        assert_eq!(bundle.txid(), None);
    }

    #[test]
    fn test_scar_heal_commitment_sign_verify() {
        // Test that sign_scar_heal_commitment produces a signature
        // that verify_scar_recovery_proof accepts.
        use axiom_core_logic::types::{FactWitness, ScarRecoveryProof, NablaConfirmation};

        let original_tx_id = [0x42u8; 32];
        let nabla_node_id = [0x11u8; 32];
        let root_hash = [0x22u8; 32];
        let receiver_wallet_id = "receiver@test.local/abc12300".to_string();

        let nabla_confirmation = NablaConfirmation {
            nabla_node_id,
            nabla_signature: vec![0u8; 64],  // Not verified in heal proof
            root_hash,
            synced_to_tick: 100,
            ..Default::default()
        };

        // Generate 3 Dilithium key pairs and sign
        use fips204::ml_dsa_65;
        use fips204::traits::SerDes;
        let mut rng = rand::rngs::OsRng;

        let mut witnesses = Vec::new();
        for i in 0u8..3 {
            let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut rng).expect("keygen");
            let pk_bytes = pk.into_bytes().to_vec();
            let sk_bytes = sk.into_bytes().to_vec();

            let signature = axiom_core_logic::compute::sign_scar_heal_commitment(
                &sk_bytes,
                &original_tx_id,
                &nabla_node_id,
                &root_hash,
            ).expect("sign should succeed");

            let validator_id = {
                let mut id = [0u8; 32];
                id[0] = i;
                id
            };

            witnesses.push(FactWitness {
                validator_id,
                validator_pk: pk_bytes,
                signature,
                vbc_genesis_anchor: None,
            });
        }

        let proof = ScarRecoveryProof {
            original_tx_id,
            nabla_confirmation,
            healing_witnesses: witnesses,
            receiver_wallet_id,
            fact_link_index: None,
        };

        // Verify succeeds
        let result = axiom_core_logic::fact::verify_scar_recovery_proof(&proof);
        assert!(result.is_ok(), "Valid scar recovery proof should verify: {:?}", result.err());
    }

    #[test]
    fn test_scar_heal_proof_bad_signature_rejected() {
        use axiom_core_logic::types::{FactWitness, ScarRecoveryProof, NablaConfirmation};

        let original_tx_id = [0x42u8; 32];
        let nabla_node_id = [0x11u8; 32];
        let root_hash = [0x22u8; 32];

        let nabla_confirmation = NablaConfirmation {
            nabla_node_id,
            nabla_signature: vec![0u8; 64],
            root_hash,
            synced_to_tick: 100,
            ..Default::default()
        };

        use fips204::ml_dsa_65;
        use fips204::traits::SerDes;
        let mut rng = rand::rngs::OsRng;

        let mut witnesses = Vec::new();
        for i in 0u8..3 {
            let (pk, _sk) = ml_dsa_65::try_keygen_with_rng(&mut rng).expect("keygen");
            let pk_bytes = pk.into_bytes().to_vec();

            // Use garbage signature
            let validator_id = { let mut id = [0u8; 32]; id[0] = i; id };
            witnesses.push(FactWitness {
                validator_id,
                validator_pk: pk_bytes,
                signature: vec![0xDE; 3309],  // Wrong signature
                vbc_genesis_anchor: None,
            });
        }

        let proof = ScarRecoveryProof {
            original_tx_id,
            nabla_confirmation,
            healing_witnesses: witnesses,
            receiver_wallet_id: "test@test.local/00000000".to_string(),
            fact_link_index: None,
        };

        let result = axiom_core_logic::fact::verify_scar_recovery_proof(&proof);
        assert!(result.is_err(), "Proof with bad signatures should fail");
    }

    #[test]
    fn test_effective_k_variable() {
        use axiom_core_logic::types::Transaction;
        use axiom_core_logic::wallet_id::generate_wallet_id_full;
        use axiom_core_logic::wallet_id::WALLET_IDENTITY_KEY;

        let pk = [0u8; 32];
        let wid3 = generate_wallet_id_full("test@axiom", "42", &WALLET_IDENTITY_KEY, &pk, 3, 1).unwrap();
        let wid4 = generate_wallet_id_full("test@axiom", "42", &WALLET_IDENTITY_KEY, &pk, 4, 1).unwrap();
        let wid5 = generate_wallet_id_full("test@axiom", "42", &WALLET_IDENTITY_KEY, &pk, 5, 1).unwrap();

        let mut tx = Transaction {
            recall_target_tx_id: None,
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: String::new(),
            wallet_seq: 1,
            receiver_wallet_id: String::new(),
            receiver_address: None,
            amount: 100_000,
            reference: "test".into(),
            nonce: 1,
            epoch: 1,
            client_sig: vec![0u8; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        };

        // Empty receiver_wallet_id → falls back to MIN_WITNESSES=3
        assert_eq!(super::effective_k(&tx), 3);

        // Standard tier (k=3) receiver
        tx.receiver_wallet_id = wid3;
        assert_eq!(super::effective_k(&tx), 3);

        // Secure tier (k=4) receiver
        tx.receiver_wallet_id = wid4;
        assert_eq!(super::effective_k(&tx), 4);

        // AAA tier (k=5) receiver
        tx.receiver_wallet_id = wid5;
        assert_eq!(super::effective_k(&tx), 5);
    }

    #[test]
    fn test_required_overlap_variable_k() {
        // YPX-007: floor(k/2)+1 — strict majority
        assert_eq!(ConsensusEngine::required_overlap(3), 2); // 3/2=1, +1=2
        assert_eq!(ConsensusEngine::required_overlap(4), 3); // 4/2=2, +1=3
        assert_eq!(ConsensusEngine::required_overlap(5), 3); // 5/2=2, +1=3
    }

    #[test]
    fn test_zkp_qualification_state() {
        use axiom_core_logic::types::QualificationState;

        // Default: not qualified
        let qual = QualificationState::default();
        assert!(!qual.zkp_qualified);
        assert!(!qual.is_valid(1000));

        // After qualifying
        let qual = QualificationState {
            zkp_qualified: true,
            qualified_at: Some(1000),
            qual_ttl_secs: 86_400,
        };
        // Valid within TTL
        assert!(qual.is_valid(1000));
        assert!(qual.is_valid(87_399));
        // Expired after TTL
        assert!(!qual.is_valid(87_400));
    }

    #[test]
    fn test_transaction_record_required_k_persisted() {
        let storage = Storage::open_test().unwrap();

        let record = TransactionRecord {
            tx_id: [0xAA; 32],
            produced_state_id: [0xBB; 32],
            wallet_pk: vec![0xCC; 32],
            balance_after: 500,
            wallet_seq_after: 3,
            group_members_after: None,
            is_genesis_claim: None,
            status: WalletStateStatus::Pending,
            required_k: 5,
            proof_type: 0,  // ZKP
            amount: 100,
            sender_balance: 600,
        };
        storage.store_transaction_record(&record).unwrap();

        let loaded = storage.get_transaction_record(&[0xBB; 32]).unwrap().unwrap();
        assert_eq!(loaded.required_k, 5);
        assert_eq!(loaded.proof_type, 0);
    }

    // (removed) test_ypx007_zkp_tx_rejected_when_unqualified — current
    // policy is warn-don't-reject when a non-qualified validator serves
    // a ZKP TX (S-ABR continuity > speed): see
    // process_witness_request line ~2400 + feedback_no_proof_mode_shortcuts.

    #[tokio::test]
    async fn test_ypx007_dmap_tx_always_accepted_by_routing() {
        // YPX-007: DMAP transactions are always accepted regardless of ZKP status.
        // Even on slow machines, DMAP is the default and works everywhere.
        use axiom_core_logic::wallet_id::{PROOF_TYPE_DMAP, generate_wallet_id_full, WALLET_IDENTITY_KEY};

        let engine = create_test_engine();

        // Generate Standard address (k=3, DMAP)
        let dmap_wid = generate_wallet_id_full("alice@test.com", "42", &WALLET_IDENTITY_KEY, &[0u8; 32], 3, 1).unwrap();

        // Build a witness request with DMAP proof type
        let mut request = create_test_request();
        request.transaction.receiver_wallet_id = dmap_wid;
        request.transaction.required_k = 3;
        request.transaction.proof_type = PROOF_TYPE_DMAP;

        // Should NOT be rejected at proof-type routing stage.
        // It will fail later (bad signature etc) but NOT with E_ZKP_NOT_QUALIFIED.
        let result = engine.process_witness_request(request).await;
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(!msg.contains("E_ZKP_NOT_QUALIFIED"),
                "DMAP TX must not be rejected for ZKP qualification, got: {}", msg);
            assert!(!msg.contains("E_ARK_NOT_IMPLEMENTED"),
                "DMAP TX must not be rejected as Ark, got: {}", msg);
        }
        // We don't assert Ok — the TX will fail for other reasons (no VBC, bad sig).
        // The point: it passes the proof-type routing gate.
    }

    #[test]
    fn test_vsp_validator_status() {
        let engine = create_test_engine();
        let resp = engine.validator_status("vsp-test-1");

        assert_eq!(resp.request_id, "vsp-test-1");
        // Validator ID should be 64 hex chars (32 bytes)
        assert_eq!(resp.validator_id.len(), 64);
        // proof_cap defaults to "dmap"
        assert_eq!(resp.proof_cap, "dmap");
        // Core version should contain "Kyoto"
        assert!(resp.core_version.contains("Kyoto"), "core_version={}", resp.core_version);
        // Carriers default to empty Vec post-Phase-1 (2026-05-14). Pre-Phase-1
        // this was hardcoded to vec!["dev:validator-<8 hex>"] from the scalar
        // defaults — but set_carrier_info was never called by server.rs in
        // production, so that garbage shipped into every VSP response.
        // The new contract: operator MUST push carrier URIs via ANTIE's
        // SetCarriers IPC at gateway startup. Tests that exercise the multi-
        // carrier path live in test_set_carriers_emits_through_vsp +
        // test_validator_status_empty_carriers_default +
        // test_set_carriers_replaces_previous.
        assert!(resp.carriers.is_empty(),
            "carriers default to empty Vec until SetCarriers IPC fires");
        // known_validators is 0-3 hints (empty in test since no hints stored)
        assert!(resp.known_validators.len() <= 3);
        // Uptime should be >= 0
        assert!(resp.uptime_secs < 60); // test engine just created
        // Counters start at 0
        assert_eq!(resp.witness_count, 0);
        assert_eq!(resp.redeem_count, 0);
    }

    // ════════════════════════════════════════════════════════════════
    // Fee redemption availability
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_fee_redemption_unavailable_with_few_peers() {
        let engine = create_test_engine();
        // Fresh engine has 0 hints — fee redemption must be unavailable
        assert!(!engine.fee_redemption_available(),
            "Fee redemption must be unavailable with 0 known peers");
    }

    #[test]
    fn test_fee_redemption_warning_with_3_peers() {
        let engine = create_test_engine();
        // This should log a warning but not crash
        engine.check_fee_redemption_readiness(6);
        // Just verifying it doesn't panic — the warning is in the log
        assert!(!engine.fee_redemption_available());
    }

    // ════════════════════════════════════════════════════════════════
    // AUDIT-FIX v2.11.13: Oracle disabled → explicit rejection
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_oracle_config_defaults_to_disabled() {
        let config = crate::config::OracleConfig::default();
        assert!(!config.enabled, "OracleConfig.enabled must default to false");
    }

    #[test]
    fn test_oracle_config_serde_defaults_to_disabled() {
        let config: crate::config::OracleConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.enabled, "Deserialized empty config must have enabled=false");
    }

    #[test]
    fn test_oracle_config_explicit_enable() {
        let config: crate::config::OracleConfig =
            serde_json::from_str(r#"{"enabled": true}"#).unwrap();
        assert!(config.enabled);
    }

    /// AUDIT-FIX v2.11.13: Oracle disabled → explicit rejection.
    /// Submits a real oracle claim through process_witness_request with
    /// oracle_config.enabled=false. Must return oracle_disabled error.
    #[tokio::test]
    async fn test_oracle_disabled_rejects_claim() {
        let engine = create_test_engine();
        let mut request = create_test_request();
        request.transaction.oracle_claim = Some(axiom_core_logic::types::OracleClaimData {
            platform_url: "https://foldingathome.org".into(),
            user_id: 12345,
            username: "testuser_AXM_1234567890abcdef".into(),
            credit_total: 50000,
            credit_delta: 1000,
            payout_amount: 0,
            zktls_proof: None,
        });
        let result = engine.process_witness_request(request).await;
        assert!(result.is_err(), "Oracle claim must be rejected when disabled");
        assert!(result.unwrap_err().to_string().contains("oracle_disabled"));
    }

    /// ZK-TLS verification must run BEFORE Core witness production (YPX-012 §2.7).
    /// If ZK-TLS fails, Core must never see the TX — prevents wasted AVM cycles.
    #[test]
    fn test_oracle_zktls_check_precedes_core_call() {
        let source = include_str!("consensus.rs");
        let zktls_pos = source.find("oracle_zktls::verify_zktls_proof").unwrap();
        let produce_pos = source.find("produce_witness_dmap(").unwrap();
        assert!(zktls_pos < produce_pos,
            "ZK-TLS verification must appear before produce_witness_dmap in consensus.rs");
    }

    /// NablaStakeProof fetch must happen before produce_witness call for oracle TXs.
    #[test]
    fn test_oracle_stake_proof_fetch_precedes_core_call() {
        let source = include_str!("consensus.rs");
        let fetch_pos = source.find("fetch_own_nabla_stake_proof").unwrap();
        let produce_pos = source.find("produce_witness_dmap(").unwrap();
        assert!(fetch_pos < produce_pos,
            "NablaStakeProof fetch must appear before produce_witness_dmap in consensus.rs");
    }

    /// SEC-09: the own-stake-proof builder must (1) fail closed when oracle is
    /// enabled (scar_count is not yet wired to the real chain), and (2) treat a
    /// Nabla-vs-stored state_id mismatch as fatal, not a warning. These guard
    /// against a scarred validator self-attesting oracle eligibility and
    /// against adopting an unverified attested_state_id from a lying Nabla.
    #[test]
    fn test_oracle_stake_proof_fails_closed_and_state_check_fatal() {
        let source = include_str!("consensus.rs");
        let fn_pos = source.find("pub async fn fetch_own_nabla_stake_proof").unwrap();
        let fn_body = &source[fn_pos..];
        // Bound the search to the function body (next `pub ` item).
        let fn_end = fn_body[10..].find("\n    pub ").map(|p| p + 10).unwrap_or(fn_body.len());
        let body = &fn_body[..fn_end];
        assert!(body.contains("if self.oracle_config.enabled"),
            "SEC-09: stake proof must fail closed while oracle is enabled");
        // The old non-fatal posture must be gone.
        assert!(!body.contains("Don't fail hard"),
            "SEC-09: the non-fatal state_id cross-check comment must be removed");
        // The state_id mismatch must now refuse (fatal).
        assert!(body.contains("oracle stake proof refused — Nabla state_id"),
            "SEC-09: state_id mismatch must be a fatal refusal");
    }

    // ════════════════════════════════════════════════════════════════
    // DWP vote rate limit position verification
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_dwp_vote_rate_limit_is_vote_only() {
        // Design verification: DWP rate limit suppresses vote registration only.
        // The payment TX (1 atom to DWP group wallet) is accepted via CL1-CL5.
        // Only dwp.record_vote_tx is skipped when rate limit fires.
        // Verify the rate check fires in the right place:
        let source = include_str!("consensus.rs");
        let rate_check_pos = source.find("dwp_vote_rate_exceeded").unwrap();
        let record_pos = source.find("record_vote_tx").unwrap();
        assert!(rate_check_pos < record_pos,
            "Rate limit check must appear before record_vote_tx in consensus.rs");
    }

    // ========================================================================
    // S-ABR Adversarial Tests
    // ========================================================================

    /// Adversarial: Store a TransactionRecord for wallet A. Then request with
    /// wallet A's consumed_state_id but wallet B's public key. The overlapped
    /// path must NOT return wallet A's balance to wallet B.
    #[test]
    fn test_sabr_overlapped_wrong_wallet_pk_in_record() {
        let engine = create_test_engine();

        // Wallet A: store genesis state + wallet state
        let pk_a = vec![0x11u8; 32];
        let balance_a = 5000u64;
        let pk_a_arr: [u8; 32] = pk_a.clone().try_into().unwrap();
        let genesis_id_a = axiom_core_logic::genesis::compute_genesis_state_id(&pk_a_arr, balance_a, 3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP);

        let wallet_state_a = StoredWalletState {
            public_key: pk_a.clone(),
            balance: balance_a,
            wallet_seq: 0,
            state_id: genesis_id_a,
            last_tx_id: None,
            status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: None, hibernation_until: 0,
            wallet_id: None,
        };
        engine.storage.set_genesis_state(&pk_a_arr, 3, 1, &wallet_state_a).unwrap();
        engine.storage.set_wallet_state(&wallet_state_a, 3, 1).unwrap();

        // Wallet B: different pk, tries to consume wallet A's state.
        // The refill path (post-CL2-rewire): even if Core CL2 classified
        // us overlapped, the refill keys the record lookup on BOTH the
        // consumed_state_id AND the requesting wallet_pk. genesis_id_a
        // resolves through the genesis branch, which recomputes the
        // genesis id from pk_b — mismatch — so wallet B can never refill
        // wallet A's balance.
        let pk_b = vec![0x22u8; 32];
        let result = engine.lookup_previous_tx_record(&genesis_id_a, &pk_b, 3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP);
        assert!(result.is_err(),
            "Must reject: wallet B cannot consume wallet A's state");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                LambdaError::SABRFailed(_) | LambdaError::SabrStateChainMismatch { .. }
            ),
            "expected refill rejection, got: {:?}",
            err
        );
        let msg = err.to_string();
        // The error could be about wallet mismatch or about not finding genesis
        // for pk_b — either way, wallet B must NOT get wallet A's balance.
        eprintln!("[TEST] Correctly rejected cross-wallet state consumption: {}", msg);
    }

    /// Boundary test for required_overlap formula at various k values.
    /// Formula: floor(k/2) + 1 for explicit values, ceil((k+1)/2) for general.
    /// k=3 → 2, k=5 → 3, k=7 → 4.
    #[test]
    fn test_sabr_required_overlap_boundary() {
        // Explicit table values
        assert_eq!(ConsensusEngine::required_overlap(3), 2, "k=3 needs 2");
        assert_eq!(ConsensusEngine::required_overlap(5), 3, "k=5 needs 3");

        // k=7 falls through to general formula: ceil((7+1)/2) = 4
        assert_eq!(ConsensusEngine::required_overlap(7), 4, "k=7 needs 4");

        // Verify strict majority: overlap > k/2 for all tested values
        for k in [3usize, 4, 5, 6, 7, 8, 9, 10] {
            let required = ConsensusEngine::required_overlap(k);
            assert!(required * 2 > k,
                "k={}: required_overlap={} must be strict majority (> k/2={})",
                k, required, k as f64 / 2.0);
            // Also verify it's not MORE than k (impossible to get more overlaps than k)
            assert!(required <= k,
                "k={}: required_overlap={} must not exceed k", k, required);
        }
    }

    /// Adversarial: Overlapped path must return balance from storage, NEVER from
    /// the client's claimed_balance_for_sabr. Store balance=1000, client claims
    /// 9999. Verify returned balance is exactly 1000.
    #[test]
    fn test_sabr_overlapped_balance_never_from_client() {
        let engine = create_test_engine();

        let pk = vec![0x77u8; 32];
        let stored_balance = 1000u64;
        let client_lie = 9999u64;

        let pk_arr: [u8; 32] = pk.clone().try_into().unwrap();
        let genesis_id = axiom_core_logic::genesis::compute_genesis_state_id(&pk_arr, stored_balance, 3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP);

        // Store genesis state with balance=1000
        let wallet_state = StoredWalletState {
            public_key: pk.clone(),
            balance: stored_balance,
            wallet_seq: 0,
            state_id: genesis_id,
            last_tx_id: None,
            status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: None, hibernation_until: 0,
            wallet_id: None,
        };
        engine.storage.set_genesis_state(&pk_arr, 3, 1, &wallet_state).unwrap();
        engine.storage.set_wallet_state(&wallet_state, 3, 1).unwrap();

        // Client LIES: claims 9999 balance. Post-CL2-rewire the refill is
        // lookup_previous_tx_record — a pure storage read keyed on
        // (consumed_state_id, wallet_pk). The client's claimed balance is
        // STRUCTURALLY not an input to it; process_witness_request builds
        // SABRResult::Refilled from the record alone. (The declared value
        // is only used on the Core-says-fresh path, where Core CL2 has
        // already anchored it to the k-signed prev_receipt.state_hash.)
        let record = engine.lookup_previous_tx_record(&genesis_id, &pk, 3, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP)
            .expect("refill from genesis pseudo-record");

        // CRITICAL: balance MUST come from storage, not client
        assert_eq!(record.balance_after, stored_balance,
            "Balance must be {} from storage, not {} from client",
            stored_balance, client_lie);
        assert_ne!(record.balance_after, client_lie,
            "Balance must NEVER be the client's claimed value");
    }

    // ════════════════════════════════════════════════════════════════
    // Oracle adversarial tests — bypass attempts + config hardening
    // ════════════════════════════════════════════════════════════════

    /// Adversarial: attacker submits a TX with oracle_claim = Some(empty fields),
    /// hoping the empty claim slips through the `is_some()` gate when oracle is
    /// disabled. Must still be rejected — the gate checks `is_some()`, not content.
    #[tokio::test]
    async fn test_oracle_disabled_cannot_be_bypassed_via_empty_claim() {
        let engine = create_test_engine();
        let mut request = create_test_request();
        request.transaction.oracle_claim = Some(axiom_core_logic::types::OracleClaimData {
            platform_url: String::new(),
            user_id: 0,
            username: String::new(),
            credit_total: 0,
            credit_delta: 0,
            payout_amount: 0,
            zktls_proof: None,
        });
        // Engine oracle_config.enabled defaults to false
        let result = engine.process_witness_request(request).await;
        assert!(result.is_err(), "Empty oracle claim must be rejected when oracle is disabled");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("oracle_disabled"),
            "Error must mention oracle_disabled, got: {}", err_msg);
    }

    /// Adversarial: attacker submits oracle_claim with zktls_proof = None, hoping
    /// the ZK-TLS check is skipped and the claim reaches Core. Must be rejected
    /// at the oracle_disabled gate before ZK-TLS is even evaluated.
    #[tokio::test]
    async fn test_oracle_disabled_cannot_be_bypassed_via_none_proof() {
        let engine = create_test_engine();
        let mut request = create_test_request();
        request.transaction.oracle_claim = Some(axiom_core_logic::types::OracleClaimData {
            platform_url: "https://foldingathome.org".into(),
            user_id: 99999,
            username: "attacker_AXM_deadbeefcafebabe".into(),
            credit_total: 999_999_999,
            credit_delta: 999_999_999,
            payout_amount: 5_000_000_000_000, // absurdly large
            zktls_proof: None,
        });
        let result = engine.process_witness_request(request).await;
        assert!(result.is_err(), "Oracle claim with None proof must be rejected when disabled");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("oracle_disabled"),
            "Must hit oracle_disabled gate before ZK-TLS, got: {}", err_msg);
    }

    /// Config hardening: deserializing OracleConfig from empty JSON "{}" must
    /// produce enabled=false. This is the production default — a validator that
    /// omits oracle config entirely must NOT accidentally enable oracle claims.
    #[test]
    fn test_oracle_config_default_always_disabled() {
        let config: crate::config::OracleConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.enabled,
            "Empty JSON must deserialize to enabled=false (serde default)");
        // Also verify the Default trait impl agrees
        let default_config = crate::config::OracleConfig::default();
        assert_eq!(config.enabled, default_config.enabled,
            "serde default and Default trait must agree on enabled=false");
    }

    /// Config hardening: explicitly setting {"enabled": false} must remain false
    /// after deserialization. Guards against serde inversion bugs where a
    /// `#[serde(default = "returns_true")]` could silently flip the meaning.
    #[test]
    fn test_oracle_config_explicit_false_stays_false() {
        let config: crate::config::OracleConfig =
            serde_json::from_str(r#"{"enabled": false}"#).unwrap();
        assert!(!config.enabled,
            "Explicit enabled=false must not be inverted by serde");
        // Paranoia: round-trip through serde to catch asymmetric ser/de
        let serialized = serde_json::to_string(&config).unwrap();
        let roundtripped: crate::config::OracleConfig =
            serde_json::from_str(&serialized).unwrap();
        assert!(!roundtripped.enabled,
            "Round-tripped config must preserve enabled=false");
    }


    /// DEED allocation year boundaries: verify 30/70 split during DEED period
    /// and 100/0 (all to validator) after year 10.
    #[test]
    fn test_deed_allocation_year_boundaries() {
        use axiom_core_logic::types::calculate_deed_allocation;

        let fee = 1_000u64; // 1000 atoms

        // Year 0: 10% DEED = 100 atoms
        assert_eq!(calculate_deed_allocation(fee, 0), 100,
            "Year 0: DEED must be 10% = 100");

        // Year 1: still in DEED period = 100 atoms
        assert_eq!(calculate_deed_allocation(fee, 1), 100,
            "Year 1: DEED must be 10% = 100");

        // Year 5: still in DEED period = 100 atoms
        assert_eq!(calculate_deed_allocation(fee, 5), 100,
            "Year 5: DEED must be 10% = 100");

        // Year 9: last year of DEED period = 100 atoms
        assert_eq!(calculate_deed_allocation(fee, 9), 100,
            "Year 9: last DEED year, must be 10% = 100");

        // Year 10: DEED period expired → 0
        assert_eq!(calculate_deed_allocation(fee, 10), 0,
            "Year 10: DEED period expired, allocation must be 0");

        // Year 11: well past DEED period → 0
        assert_eq!(calculate_deed_allocation(fee, 11), 0,
            "Year 11: past DEED period, allocation must be 0");

        // Year 100: far future → 0
        assert_eq!(calculate_deed_allocation(fee, 100), 0,
            "Year 100: far future, allocation must be 0");

        // Verify the split: during DEED period, validator gets fee - deed
        let deed_y0 = calculate_deed_allocation(fee, 0);
        let validator_net_y0 = fee - deed_y0;
        assert_eq!(validator_net_y0, 900,
            "Year 0: validator net must be 900 (fee=1000, deed=100)");

        // After DEED period, validator gets 100% of fee
        let deed_y10 = calculate_deed_allocation(fee, 10);
        let validator_net_y10 = fee - deed_y10;
        assert_eq!(validator_net_y10, 1000,
            "Year 10: validator net must be 1000 (full fee, no DEED)");

        // Edge case: minimum 1 atom DEED for small fees during period
        assert_eq!(calculate_deed_allocation(5, 0), 1,
            "5-atom fee: DEED = 5*10/100 = 0, but minimum = 1 atom");
        assert_eq!(calculate_deed_allocation(9, 0), 1,
            "9-atom fee: DEED = 9*10/100 = 0, but minimum = 1 atom");
        assert_eq!(calculate_deed_allocation(10, 0), 1,
            "10-atom fee: DEED = 10*10/100 = 1 atom (exact)");
        assert_eq!(calculate_deed_allocation(11, 0), 1,
            "11-atom fee: DEED = 11*10/100 = 1 atom (truncated)");

        // Small fees AFTER DEED period: must be 0 regardless
        assert_eq!(calculate_deed_allocation(5, 10), 0,
            "5-atom fee after DEED period: must be 0");
    }

    // ───────────────────────────────────────────────────────────────────
    // YP §19.6 amendment — Lambda per-slot fee verification
    // ───────────────────────────────────────────────────────────────────

    #[test]
    fn expected_fee_slot_amount_honors_rate_bps_up_to_cap() {
        let mut engine = tests::create_test_engine();
        // Operator-configured rate of 20 bps (under the 30-bp cap) — the
        // configured rate is honored verbatim.
        engine.fee_config = crate::config::FeeConfig {
            rate_bps: 20, valid_until: 0, min_amount: 0,
        };
        // 1_000_000 atoms × 20 bps / 10_000 = 2000 atoms.
        assert_eq!(engine.expected_fee_slot_amount(1_000_000), 2000);
    }

    #[test]
    fn expected_fee_slot_amount_clamps_above_cap() {
        let mut engine = tests::create_test_engine();
        // Operator misconfigures at 50 bps — clamp to MAX_VALIDATOR_FEE_BPS=30.
        engine.fee_config = crate::config::FeeConfig {
            rate_bps: 50, valid_until: 0, min_amount: 0,
        };
        // Clamps to 30 bps: 1_000_000 × 30 / 10_000 = 3000 atoms.
        assert_eq!(engine.expected_fee_slot_amount(1_000_000), 3000);
    }

    #[test]
    fn verify_my_fee_slot_empty_breakdown_ok() {
        let engine = tests::create_test_engine();
        // Heal / genesis / oracle / pre-step-7 SDK paths: no slot to verify.
        assert_eq!(engine.verify_my_fee_slot(1_000_000, &[]).unwrap(), 0);
    }

    #[test]
    fn verify_my_fee_slot_matching_slot_ok() {
        let mut engine = tests::create_test_engine();
        engine.fee_config = crate::config::FeeConfig {
            rate_bps: 30, valid_until: 0, min_amount: 0,
        };
        let expected = engine.expected_fee_slot_amount(1_000_000);
        let slot = axiom_core_logic::types::FeeShare {
            validator_id: engine.validator_id,
            amount: expected,
        };
        assert_eq!(engine.verify_my_fee_slot(1_000_000, &[slot]).unwrap(), expected);
    }

    #[test]
    fn verify_my_fee_slot_missing_self_rejects() {
        let engine = tests::create_test_engine();
        // Breakdown with a different validator's slot — we're not in it.
        let slot = axiom_core_logic::types::FeeShare {
            validator_id: [0xEE; 32],   // not our id
            amount: 100,
        };
        match engine.verify_my_fee_slot(1_000_000, &[slot]) {
            Err(LambdaError::FeeSlotMissing { tx_amount }) => assert_eq!(tx_amount, 1_000_000),
            other => panic!("expected FeeSlotMissing, got {:?}", other),
        }
    }

    #[test]
    fn verify_my_fee_slot_wrong_amount_rejects() {
        let mut engine = tests::create_test_engine();
        engine.fee_config = crate::config::FeeConfig {
            rate_bps: 30, valid_until: 0, min_amount: 0,
        };
        let expected = engine.expected_fee_slot_amount(1_000_000);
        let slot = axiom_core_logic::types::FeeShare {
            validator_id: engine.validator_id,
            amount: expected + 1,    // off by one
        };
        match engine.verify_my_fee_slot(1_000_000, &[slot]) {
            Err(LambdaError::FeeSlotMismatch { expected: e, declared, tx_amount }) => {
                assert_eq!(e, expected);
                assert_eq!(declared, expected + 1);
                assert_eq!(tx_amount, 1_000_000);
            },
            other => panic!("expected FeeSlotMismatch, got {:?}", other),
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Step 9B.3 — Withdrawal mint witness handler
    // ─────────────────────────────────────────────────────────────────

    /// Bad withdrawal (forged Nabla signature) is rejected at the
    /// Lambda-side verify chain BEFORE the AVM round-trip — efficient
    /// short-circuit, no signed mint emitted.
    #[tokio::test(flavor = "current_thread")]
    async fn withdrawal_mint_witness_rejects_bad_attestation_signature() {
        use axiom_core_logic::types::WithdrawalMintWitnessRequest;
        use axiom_core_logic::wire_client::{
            EarningsEntry, QueryValidatorEarningsResponse,
            QueryValidatorPoolResponse, ValidatorWithdrawalRequest,
        };

        // Build a withdrawal request with a tampered signature.
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        let (sphincs_pk, _sphincs_sk) = slh_dsa_sha2_128s::try_keygen()
            .expect("sphincs keygen");
        let sphincs_pk_bytes = sphincs_pk.into_bytes().to_vec();
        let validator_id: [u8; 32] = *blake3::hash(&sphincs_pk_bytes).as_bytes();
        let chosen_witnesses = vec![[0x44; 32], [0x55; 32], [0x66; 32]];
        let entries = vec![EarningsEntry {
            tx_hash: [0x01; 32], amount: 30, tick: 5,
            full_fee_breakdown: vec![],
        }];
        let nabla_sk = ed25519_dalek::SigningKey::from_bytes(&[0xAB; 32]);
        let nabla_pk = nabla_sk.verifying_key().to_bytes().to_vec();
        let earnings = QueryValidatorEarningsResponse {
            validator_id, since_tick: 0, until_tick: 100,
            total_amount: 30, net_balance: 27, entries, is_authoritative: true,
            nabla_node_id: [0xCC; 32], nabla_node_pk: nabla_pk,
            nabla_signature: vec![0u8; 64],  // BOGUS sig — won't verify
            nbc_issuer_pk: vec![], nbc_signature: vec![], nbc_commitment: vec![],
        };
        let req = WithdrawalMintWitnessRequest {
            request_id: "test-bad-sig".into(),
            withdrawal: ValidatorWithdrawalRequest {
                validator_id,
                earnings_attestation: earnings,
                pool_linkage: QueryValidatorPoolResponse {
                    validator_id, registered: true,
                    linked_wallet_id: [0xAA; 32],
                    linkage_epoch: 1, registered_at_tick: 50,
                },
                sphincs_pk: sphincs_pk_bytes,
                sphincs_sig: vec![0u8; 7856],  // also bogus
                chosen_witnesses,
            },
        };

        let engine = tests::create_test_engine();
        let resp = engine.process_withdrawal_mint_witness(&req).await;
        assert_eq!(resp.status, "REJECTED_EARNINGS_SIG");
        assert!(resp.witness_sig.is_none(),
            "no signature on a rejection");
        assert!(resp.mint.is_none(),
            "no mint output on a rejection");
    }

    /// Missing withdrawal_inputs (caller bug — should never happen in
    /// practice, but the handler defensively rejects with a clear
    /// status string).
    #[tokio::test(flavor = "current_thread")]
    async fn withdrawal_mint_witness_rejects_zero_validator_id() {
        use axiom_core_logic::types::WithdrawalMintWitnessRequest;
        use axiom_core_logic::wire_client::{
            QueryValidatorEarningsResponse, QueryValidatorPoolResponse,
            ValidatorWithdrawalRequest,
        };

        // SPHINCS+ pk that does NOT hash to validator_id=0.
        let sphincs_pk_bytes = vec![0xDE; 32];
        let req = WithdrawalMintWitnessRequest {
            request_id: "test-id-mismatch".into(),
            withdrawal: ValidatorWithdrawalRequest {
                validator_id: [0; 32],  // doesn't match BLAKE3(sphincs_pk)
                earnings_attestation: QueryValidatorEarningsResponse::default(),
                pool_linkage: QueryValidatorPoolResponse::default(),
                sphincs_pk: sphincs_pk_bytes,
                sphincs_sig: vec![],
                chosen_witnesses: vec![[1; 32], [2; 32], [3; 32]],
            },
        };

        let engine = tests::create_test_engine();
        let resp = engine.process_withdrawal_mint_witness(&req).await;
        assert_eq!(resp.status, "REJECTED_ID_MISMATCH");
        assert!(resp.witness_sig.is_none());
        assert!(resp.mint.is_none());
    }

    // ── YPX-001 §1.5.1 scar-consent gate trigger ─────────────────────────
    // These pin the ACTIVE trigger contract (2026-07-11): unresolved links
    // gate, Ark provenance and self-recovery flows don't. Without the
    // scar_consent_gate_count rework, `scar_gate_fires_on_unresolved_link`
    // FAILS (the old `chain.scar_count()` needed witnesses < required_k,
    // unreachable under the Quorum Gate).

    fn scar_test_link(
        required_k: u8,
        confirmed: bool,
    ) -> axiom_core_logic::types::FactLink {
        axiom_core_logic::types::FactLink {
            tx_id: [0x11; 32],
            previous_state_id: [0x22; 32],
            new_state_id: [0x33; 32],
            amount: 1_000_000,
            burn_target_tx_id: None,
            tick: 7,
            required_k,
            witnesses: vec![],
            nabla_confirmation: if confirmed {
                Some(axiom_core_logic::types::NablaConfirmation {
                    nabla_node_id: [0x44; 32],
                    nabla_signature: vec![0x55; 64],
                    root_hash: [0x66; 32],
                    synced_to_tick: 9,
                    committed_at_tick: 9,
                    nbc_issuer_pk: vec![],
                    nbc_signature: vec![],
                    nbc_commitment: vec![],
                })
            } else {
                None
            },
            receiver_contact: None,
            burn_proof: None,
            recall_proof: None,
            sender_anchor: None,
            is_dev_class: false,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
        }
    }

    fn scar_test_chain(links: Vec<axiom_core_logic::types::FactLink>)
        -> axiom_core_logic::types::FactChain
    {
        axiom_core_logic::types::FactChain { checkpoint: None, links }
    }

    fn scar_test_tx() -> Transaction {
        Transaction {
            consumed_state_id: [0xAA; 32],
            client_pk: vec![0xBB; 32],
            sender_wallet_id: "alice@example.com/a1b2c3d4".to_string(),
            wallet_seq: 3,
            receiver_wallet_id: "bob@example.com/deadbeef".to_string(),
            receiver_address: None,
            amount: 500_000,
            reference: "scar-gate-test".to_string(),
            nonce: 42,
            epoch: 1_700_000_000,
            client_sig: vec![0xCC; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            recall_target_tx_id: None,
            oracle_claim: None,
            required_k: 3,
            proof_type: 0,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        }
    }

    #[test]
    fn scar_gate_fires_on_unresolved_link() {
        // A fully-witnessed link (Quorum Gate) with no Nabla confirmation
        // IS a scar — the exact receiver-consent case. The old
        // `chain.scar_count()` returned 0 here (witnesses check).
        let chain = scar_test_chain(vec![
            scar_test_link(3, true),
            scar_test_link(3, false), // unresolved → gates
        ]);
        assert_eq!(scar_consent_gate_count(&chain, &scar_test_tx(), false), 1);
    }

    #[test]
    fn scar_gate_clean_chain_zero_overhead() {
        let chain = scar_test_chain(vec![
            scar_test_link(3, true),
            scar_test_link(3, true),
        ]);
        assert_eq!(scar_consent_gate_count(&chain, &scar_test_tx(), false), 0);
    }

    #[test]
    fn scar_gate_skips_ark_provenance_links() {
        // required_k = 0 ⇒ Ark provenance — scarred BY DESIGN (YPX-010),
        // priced by the Confidence Index, never the passcode dance.
        let chain = scar_test_chain(vec![
            scar_test_link(0, false),
            scar_test_link(0, false),
        ]);
        assert_eq!(scar_consent_gate_count(&chain, &scar_test_tx(), false), 0);
        // …but a connected-mode scar alongside them still gates.
        let mixed = scar_test_chain(vec![
            scar_test_link(0, false),
            scar_test_link(3, false),
        ]);
        assert_eq!(scar_consent_gate_count(&mixed, &scar_test_tx(), false), 1);
    }

    #[test]
    fn scar_gate_exempts_clara_burn_recall_heal_hal() {
        let chain = scar_test_chain(vec![scar_test_link(3, false)]);

        // CLARA attestation present (YPX-018)
        assert_eq!(scar_consent_gate_count(&chain, &scar_test_tx(), true), 0);

        // Burn — the cure for scars
        let mut burn = scar_test_tx();
        burn.burn_target_tx_id = Some([0x11; 32]);
        assert_eq!(scar_consent_gate_count(&chain, &burn, false), 0);

        // Recall — self-send recovery (YPX-022)
        let mut recall = scar_test_tx();
        recall.kind = TxKind::Recall;
        assert_eq!(scar_consent_gate_count(&chain, &recall, false), 0);

        // Heal / HAL — self-sends, no external receiver
        let mut heal = scar_test_tx();
        heal.kind = TxKind::Heal;
        assert_eq!(scar_consent_gate_count(&chain, &heal, false), 0);
        let mut hal = scar_test_tx();
        hal.kind = TxKind::HalReanchor;
        assert_eq!(scar_consent_gate_count(&chain, &hal, false), 0);
    }

    // ── YPX-001 §1.5.1 consent-voucher verification ──────────────────────
    // The voucher is what lets a verified retry round COMPLETE: only the
    // passcode-generating validator holds the entry, so the round's other
    // overlapped hops accept its signed attestation instead. These pin the
    // verify contract: issuer must be a prev-receipt witness, sig must be
    // Ed25519 over the domain-tagged payload, txid must bind.

    fn voucher_receipt_with_witness(
        validator_id: [u8; 32],
        validator_pk: Vec<u8>,
    ) -> Receipt {
        Receipt {
            txid: [0u8; 32],
            state_hash: [0u8; 32],
            produced_state_id: [0u8; 32],
            new_wallet_seq: 1,
            commitment_hash: [0u8; 32],
            sdid: [0u8; 32],
            lineage_hash: [0u8; 32],
            core_version: String::new(),
            core_id: [0u8; 32],
            witness_sigs: vec![WitnessSig {
                validator_id,
                validator_pk,
                vbc_bundle: None,
                carrier_type: String::new(),
                carrier_address: String::new(),
                signature: vec![],
                execution_proof: vec![],
                proof_type: 0,
                availability_attestation: None,
                validator_hints: vec![],
                fact_signature: None,
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                rate_bps: 0,
                slot_amount: 0,
            }],
            epoch: 0,
            fact_proof: None,
            required_k: 3,
            receipt_commitment: [0u8; 32],
            fee_breakdown: vec![],
            is_dev_class: false,
            oods_flag: None,
        }
    }

    #[test]
    fn scar_consent_voucher_verifies_and_binds() {
        use ed25519_dalek::Signer as _;
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let vid = [0x77u8; 32];
        let txid = [0xAB; 32];
        let payload = axiom_core_logic::compute::compute_scar_consent_voucher_payload(&txid);
        let voucher = crate::types::ScarConsentVoucher {
            txid,
            validator_id: vid,
            signature: sk.sign(&payload).to_bytes().to_vec(),
        };
        let receipts = vec![voucher_receipt_with_witness(vid, pk)];

        // Valid: issuer in the witness set, sig over the right payload.
        assert!(verify_scar_consent_voucher(&voucher, &txid, &receipts));

        // Wrong txid: the voucher must not transfer between transactions.
        assert!(!verify_scar_consent_voucher(&voucher, &[0xCD; 32], &receipts));

        // Issuer not in the prev-receipt witness set: fail closed.
        let stranger = voucher_receipt_with_witness([0x99; 32], sk.verifying_key().to_bytes().to_vec());
        assert!(!verify_scar_consent_voucher(&voucher, &txid, &[stranger]));

        // Forged signature (right issuer id, wrong key): fail closed.
        let forger = SigningKey::from_bytes(&[0x43; 32]);
        let forged = crate::types::ScarConsentVoucher {
            txid,
            validator_id: vid,
            signature: forger.sign(&payload).to_bytes().to_vec(),
        };
        let receipts2 = vec![voucher_receipt_with_witness(vid, sk.verifying_key().to_bytes().to_vec())];
        assert!(!verify_scar_consent_voucher(&forged, &txid, &receipts2));

        // Malformed pk (Dilithium-sized) / malformed sig: fail closed, no panic.
        let bad_pk = voucher_receipt_with_witness(vid, vec![0u8; 1952]);
        assert!(!verify_scar_consent_voucher(&voucher, &txid, &[bad_pk]));
        let short_sig = crate::types::ScarConsentVoucher {
            txid, validator_id: vid, signature: vec![0u8; 10],
        };
        let receipts3 = vec![voucher_receipt_with_witness(vid, sk.verifying_key().to_bytes().to_vec())];
        assert!(!verify_scar_consent_voucher(&short_sig, &txid, &receipts3));
    }

    #[test]
    fn scar_gate_skips_ark_endpoint_tx() {
        // A TX whose endpoint wallet_id decodes to the Ark tier (K_ARK=0)
        // skips the gate — Ark mode is all-scarred by disclosed design.
        let pk = [0x77u8; 32];
        let ids = axiom_core_logic::wallet_id::generate_all_wallet_ids(
            "arkuser@example.com", "", &pk,
        ).expect("generate wallet ids");
        let ark_id = ids.iter()
            .find(|(_, k, pt, _)| *k == axiom_core_logic::wallet_id::K_ARK
                && *pt == axiom_core_logic::wallet_id::PROOF_TYPE_ARK)
            .map(|(id, _, _, _)| id.clone())
            .expect("ark tier wallet_id");

        let chain = scar_test_chain(vec![scar_test_link(3, false)]);
        let mut tx = scar_test_tx();
        tx.receiver_wallet_id = ark_id;
        assert_eq!(scar_consent_gate_count(&chain, &tx, false), 0);

        // Mangled wallet_ids fall through to gating (fail-closed).
        let mut mangled = scar_test_tx();
        mangled.receiver_wallet_id = "not-a-wallet-id".to_string();
        assert_eq!(scar_consent_gate_count(&chain, &mangled, false), 1);
    }
}
