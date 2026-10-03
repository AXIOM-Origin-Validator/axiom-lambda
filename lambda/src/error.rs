//! Lambda error types

use axiom_core_logic::ValidationError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LambdaError {
    /// Core returned a typed ValidationError in `PublicOutputs.rejection_reason`.
    /// Preferred path as of Phase 2b.3 — preserves the discriminant end-to-end
    /// so `From<&LambdaError> for ErrorResponse` can dispatch structurally
    /// via `From<ValidationError>` instead of parsing strings.
    /// Boxed to keep the enum size small (ValidationError is ~240 bytes).
    #[error("Core rejected: {0}")]
    CoreRejected(Box<ValidationError>),

    #[error("Core validation failed: {0}")]
    CoreValidationFailed(String),
    
    #[error("Core execution error: {0}")]
    CoreExecutionError(String),
    /// YPX-009 §7.2 (RULED 2026-09-10): the validator's own Pulse audit
    /// failed on this execution — refused, never signed. `String` = the
    /// execution path (`CL3 finalize`, `CL5 redeem`, …).
    #[error("Pulse audit failed on {0} — this validator refuses to sign (YPX-009 §7.2)")]
    PulseAuditFailed(String),
    /// §5.2.2e part iii — the candidacy proof's work does not reproduce at
    /// this issuer (or exceeds its replay cap).
    #[error("candidacy Pulse refused by the issuer's replay: {0}")]
    CandidacyPulseWork(String),
    /// §5.2.2e part iii — a second provisional request from the same key
    /// inside the issuer's window.
    #[error("candidacy request from key {key_hex} inside the issuer's window — wait {wait_ticks} more ticks")]
    CandidacyPulseRate { key_hex: String, wait_ticks: u64 },
    /// Fable review 2026-10-01 F-3 — a client-carried Nabla OODS attestation
    /// whose tick is more than `ATTESTED_TICK_FUTURE_SKEW_SECS` (300 s,
    /// protocol_lambda.toml) ahead of this validator's wall clock (the TARDIS
    /// forward-only rule, applied at the validator with a wider stated skew).
    /// Raised by `consensus::check_attested_tick_not_future` BEFORE any Core
    /// execution; nothing is witnessed or signed.
    #[error("attested tick {tick} is ahead of this validator's clock ({now_secs}) by more than the forward skew bound (max {bound})")]
    AttestedTickInFuture { tick: u64, now_secs: u64, bound: u64 },
    
    #[error("Insufficient witnesses: got {got}, need {need}")]
    InsufficientWitnesses { got: usize, need: usize },
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),
    
    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
    
    #[error("Invalid wallet_seq: expected {expected}, got {got}")]
    InvalidWalletSeq { expected: u64, got: u64 },
    
    #[error("State ID mismatch")]
    StateIdMismatch,

    /// Phase 2b.11: typed variant for the S-ABR overlapped-validator
    /// lookup-miss case. Carries the client's declared consumed_state_id
    /// and — when available — the validator's currently stored
    /// state_id and wallet_seq for that wallet. DEBUG-gated fields
    /// (stored_sid, stored_seq) are populated when the validator is
    /// the wallet's own validator; they're stripped at untrusted
    /// boundaries (future RequestEnvelope check).
    #[error("S-ABR state chain mismatch: requested csid={requested_csid_hex}")]
    SabrStateChainMismatch {
        requested_consumed_state_id: [u8; 32],
        requested_wallet_seq: u64,
        stored_sid: Option<[u8; 32]>,
        stored_seq: Option<u64>,
        requested_csid_hex: String,
    },
    
    #[error("Transaction already processed: {0}")]
    DuplicateTransaction(String),
    
    #[error("S-ABR validation failed: {0}")]
    SABRFailed(String),

    /// Phase 2b.11: typed variant for the S-ABR "insufficient overlap"
    /// rejection. Carries the three numbers a client needs to
    /// understand what to do (retry with more overlap sigs, or
    /// re-sync). Emitted at consensus.rs:3513.
    #[error("S-ABR insufficient overlap: got {provided}, need {required} (fresh={is_fresh})")]
    SabrInsufficientOverlap {
        provided: u8,
        required: u8,
        is_fresh: bool,
    },
    
    #[error("Consensus timeout")]
    ConsensusTimeout,
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Core error: {0}")]
    CoreError(String),
    
    #[error("Core rejected: {0}")]
    CoreRejection(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Rate limit exceeded: {current_count}/{limit} requests in {window_secs}s window")]
    RateLimitExceeded {
        limit: u32,
        window_secs: u32,
        current_count: u32,
    },

    #[error("Wallet frozen by Judicial Freeze Protocol (JFP)")]
    WalletFrozenJfp,
    
    #[error("FACT scar detected: sender's money is scarred. Passcode required from receiver.")]
    FactScarDetected {
        /// 6-digit passcode for receiver consent
        passcode: u32,
        /// Transaction ID
        txid: [u8; 32],
        /// Sender info (wallet_id, not PK)
        sender_wallet_id: String,
        /// Receiver wallet_id
        receiver_wallet_id: String,
        /// Amount
        amount: u64,
        /// Number of scars in sender's FACT chain
        scar_count: usize,
    },
    
    #[error("Invalid scar passcode: {0}")]
    InvalidScarPasscode(String),

    /// YP §19.6 amendment — per-slot fee verification.
    ///
    /// SDK proposed a `fee_breakdown` slot for this validator whose amount
    /// disagrees with what the validator's local `fee_config.rate_bps` (clamped
    /// to MAX_VALIDATOR_FEE_BPS) would charge for `tx_amount`. The validator
    /// refuses to sign the receipt_commitment — without all k Lambdas agreeing
    /// on identical fee_breakdown bytes, no consensus is possible and the SDK
    /// must retry with corrected slots.
    #[error("Fee slot mismatch: validator expected {expected} atoms, SDK proposed {declared} (tx_amount={tx_amount})")]
    FeeSlotMismatch {
        expected: u64,
        declared: u64,
        tx_amount: u64,
    },

    /// YP §19.6 amendment — proposed breakdown omits this validator entirely.
    /// Same outcome as FeeSlotMismatch (refuse to sign), but distinguished so
    /// the SDK can append rather than amend.
    #[error("Fee slot missing: validator not present in proposed fee_breakdown (tx_amount={tx_amount})")]
    FeeSlotMissing { tx_amount: u64 },
}

impl From<serde_json::Error> for LambdaError {
    fn from(e: serde_json::Error) -> Self {
        LambdaError::SerializationError(e.to_string())
    }
}
