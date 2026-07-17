//! Lambda types
//!
//! All wire/IPC types between Gateway / ANTIE / SDK ↔ Lambda live in
//! `axiom_core_logic::types` (the shared crate). This module re-exports
//! them so existing `axiom_lambda::types::Foo` imports keep working
//! without churn. UMP consolidation, 2026-05-10 — see CLAUDE.md §13.
//!
//! There is no Lambda-local type. If you find yourself adding a struct
//! here, ask: who else needs to deserialize it? If the answer is "ANTIE
//! or SDK", it belongs in `axiom_core_logic::types` (one definition);
//! if "Lambda only" (e.g. internal storage shape), put it next to its
//! consumer (e.g. `lambda/src/storage.rs`), not here.

// Re-export common base types
pub use axiom_core_logic::{
    Transaction, TxKind, Receipt, WalletState, WitnessSig,
    PublicInputs, PublicOutputs, CoreLogicMode,
    ValidationResult, ValidationError,
    ValidatorCheque, ChequeBundle, RedeemRequest,
    AckWithFee, ConfirmationCheque,
    calculate_deed_allocation, calculate_receiver_amount,
    DEFAULT_FEE_PER_VALIDATOR,
    ValidatorHint,
    NablaHint,
};

// Re-export every wire / IPC type — single source of truth in core-logic.
pub use axiom_core_logic::types::{
    // Witness path
    WitnessRequest, WitnessResponse,
    // Redeem path
    RedeemResponse, RedeemRequestEnvelope,
    // Witness response side-channels
    RejectionInfo, OutboundPeerAudit, ScarConsentNotification, ScarConsentVoucher,
    // Query / state
    StateQueryRequest, StateQueryResponse, StoredWalletState, WalletStateStatus,
    // VSP (Validator Status Protocol — YPX-008)
    ValidatorStatusRequest, ValidatorStatusResponse,
    // Health
    HealthRequest, HealthResponse,
    // ACK
    AckRequest, AckResponse,
    // Lambda Gateway IPC envelope (the tagged enum)
    GatewayRequest, GatewayResponse,
    // Genesis (DEV/TEST)
    GenesisResult, InitGenesisRequest, InitGenesisResponse,
    LoadTestStateRequest, LoadTestStateResponse,
    // VBC signing
    VBCSignApproval, VBCSignRequestPayload, VBCSignCommitPayload,
    VBCSignApprovalResponse, VBCSignCommitResponse,
    // Peer-audit IPC
    PeerAuditRequestEnvelope, PeerAuditResponseEnvelope,
    PeerAuditResultPayload, PeerAuditResponseAck,
    // Auth-hash management
    SetAuthHashRequest, SetAuthHashResponse,
    // Fan-out dedup
    FanOutDedupRequest, FanOutDedupResponse,
    FanOutMarkRequest, FanOutMarkResponse,
    // Misc
    ShutdownRequest, ShutdownAck, ErrorEnvelope,
    // Phase 1 multi-carrier discovery (YP §27.5.2)
    SetCarriersRequest, SetCarriersAck,
    // S-ABR transaction record
    TransactionRecord,
};
