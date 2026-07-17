//! AXIOM Lambda - k=3 Consensus Engine
//!
//! Lambda is the consensus logic engine for AXIOM validators.
//! It coordinates transaction witnessing among k=3 validators.
//!
//! # Architecture
//!
//! ```text
//! Gateway ──────► Lambda ──────► Core (CL2/CL3)
//!     ▲              │
//!     │              ▼
//!     └────────── Storage
//! ```
//!
//! # Flow
//!
//! 1. Gateway receives transaction from network
//! 2. Lambda validates via Core (CL2 mode)
//! 3. Lambda coordinates with other validators (k=3)
//! 4. Lambda produces witness proof via Core (CL3 mode)
//! 5. Gateway returns receipt to client
//!
//! # Core Interaction
//!
//! Lambda talks to Core correctly by:
//! - CL2: Validate incoming transaction
//! - CL3: Produce witness proof after consensus

// rusqlite `query_map` closures return nested
// `Iterator<Item = Result<T, rusqlite::Error>>` over `(_, _, _, _, _)`
// tuples whose shape mirrors the row schema. A type alias buys
// readability but doesn't change the shape; allow at crate scope.
#![allow(clippy::type_complexity)]

mod admin;
pub mod config;
/// AUTO-GENERATED tuning registers (from protocol_lambda.toml via build.rs).
pub mod tuning_gen;
pub mod core_client;
pub mod malloc_trim;
pub mod storage;
pub mod management_db;
pub mod consensus;
pub mod types;
pub mod error;
/// `From<LambdaError> for axiom_errors::ErrorResponse` — Phase 2b.1.
/// See `docs/AXIOM_YellowPaper_Errors.md`.
pub mod error_response;
pub mod server;
pub mod rate_limit;
pub mod dwp_engine;
pub mod jfp_engine;
pub mod console_engine;
pub mod oracle_zktls;

/// YP §19.6 + §20.10 — validator-withdrawal verification.
/// Operator-side (per-validator dashboard at :7700-7709) endpoint
/// that verifies a `ValidatorWithdrawalRequest`: SPHINCS+ + Nabla
/// earnings attestation + pool linkage + §20.10 conflict-of-interest.
/// Does NOT actually mint atoms — that requires a new protocol primitive
/// (Step 9+). Returns a structured verification result so the dashboard
/// can display "withdrawal is ready" + the net amount and destination.
pub mod validator_withdrawal;

/// Step 9B.4 — operator-side fan-out: send WithdrawalMintWitnessRequest
/// to each chosen_witness's Lambda gateway over TCP CBOR, collect k=3
/// signatures, verify, assemble the mint receipt.
pub mod withdrawal_mint_orchestrator;

/// YPX-002 P6 — simulated network-delay injection (async).
/// See `sim_delay.rs` for the contract.
pub mod sim_delay;

pub use config::LambdaConfig;
pub use core_client::CoreClient;
pub use storage::Storage;
pub use consensus::ConsensusEngine;
pub use types::*;
pub use error::LambdaError;
