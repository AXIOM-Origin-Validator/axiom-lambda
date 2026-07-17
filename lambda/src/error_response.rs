//! `From<LambdaError> for ErrorResponse` — Lambda-level errors mapped
//! to the structured wire format defined in `AXIOM_YellowPaper_Errors.md`.
//!
//! # Phase 2b.1
//!
//! Lambda wraps `LambdaError` around Core's `ValidationError` (via
//! `CoreValidationFailed(String)` / `CoreRejection(String)`) plus a set
//! of Lambda-level operational errors (storage, consensus, rate limit).
//!
//! This module provides CONVERSION functions. It does NOT yet change
//! any existing Lambda API signature or HTTP response format. Callers
//! that return `Result<_, LambdaError>` keep doing so; the conversion
//! is used at the HTTP response boundary when emitting the new
//! structured error alongside the legacy string field (dual-format
//! grace period per Errors YP §9.1).
//!
//! # Pass-through for Core errors
//!
//! `LambdaError::CoreValidationFailed(String)` and `CoreRejection(String)`
//! historically stringify the inner `ValidationError::Display` output
//! (which is the stable `E_*` code). We parse that string back into a
//! code and synthesize an `ErrorResponse` that mirrors what Core would
//! produce directly. Phase 2b.3 will replace this string-round-trip
//! with a direct `ValidationError → ErrorResponse` pass-through when
//! Core's API signature is updated.

use axiom_errors::{error_code, ErrorCategory, ErrorCode, ErrorResponse, RecoveryHint};

use crate::error::LambdaError;

impl From<&LambdaError> for ErrorResponse {
    fn from(err: &LambdaError) -> Self {
        match err {
            // ── Core typed pass-through (Phase 2b.3) ──────────────────────
            // Preferred path. Core handed Lambda a structured ValidationError
            // in PublicOutputs.rejection_reason, which core/logic/src/error_response.rs
            // classifies structurally (no string parsing). This preserves the
            // discriminant, the YP reference, and the recovery hint end-to-end.
            LambdaError::CoreRejected(boxed) => {
                ErrorResponse::from((**boxed).clone())
            }

            // ── Core string pass-through (legacy) ─────────────────────────
            // The String wrapping CoreValidationFailed / CoreRejection is
            // the `ValidationError::Display` output, which is the stable
            // code. We pass it through as the code AND the message.
            // Kept for sites that still produce a String; Phase 2b.3 is
            // migrating them to CoreRejected one-by-one.
            LambdaError::CoreValidationFailed(s) | LambdaError::CoreRejection(s) => {
                let (code, category, recovery, yp_ref) = classify_core_pass_through(s);
                let mut resp = ErrorResponse::new(
                    ErrorCode::from_static(code),
                    category,
                    s.clone(),
                );
                if let Some(hint) = recovery {
                    resp = resp.with_recovery(hint);
                }
                if let Some(r) = yp_ref {
                    resp = resp.with_yp_reference(r);
                }
                resp
            }
            LambdaError::CoreExecutionError(s) => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_AVM_EXECUTION_ERROR),
                ErrorCategory::Internal,
                format!("Core execution error: {}", s),
            ),
            LambdaError::CoreError(s) => ErrorResponse::new(
                ErrorCode::from_static("E_CORE_UNCLASSIFIED"),
                ErrorCategory::Internal,
                format!("Core error: {}", s),
            ),

            // ── Lambda operational ────────────────────────────────────────
            LambdaError::InsufficientWitnesses { got, need } => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_INSUFFICIENT_WITNESSES),
                ErrorCategory::Operational,
                format!("Insufficient witnesses: got {}, need {}", got, need),
            )
            .with_recovery(RecoveryHint::RetrySameValidator),

            LambdaError::InvalidSignature(msg) => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_INVALID_CLIENT_SIG),
                ErrorCategory::ClientBug,
                format!("Invalid signature: {}", msg),
            ),

            LambdaError::StorageError(msg) => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_STORAGE_ERROR),
                ErrorCategory::Internal,
                format!("Storage error: {}", msg),
            ),

            LambdaError::WalletNotFound(msg) => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_WALLET_NOT_FOUND),
                ErrorCategory::Operational,
                format!("Wallet not found: {}", msg),
            ),

            LambdaError::InsufficientBalance { have, need } => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_INSUFFICIENT_BALANCE),
                ErrorCategory::ProtocolReject,
                format!("Insufficient balance: have {}, need {}", have, need),
            )
            .with_detail(axiom_errors::ErrorDetail::Balance(
                axiom_errors::BalanceDetail {
                    requested_amount: *need,
                    // current_balance is DEBUG-GATED per BalanceDetail's
                    // docstring — only disclosed to the wallet owner.
                    // Phase 1 of RequestEnvelope (future) will gate this
                    // on signed wallet-owner auth. For now Lambda is the
                    // wallet owner's validator, so populating is fine;
                    // the field is stripped at untrusted boundaries.
                    current_balance: Some(*have),
                },
            )),

            LambdaError::InvalidWalletSeq { expected, got } => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_INVALID_WALLET_SEQ),
                ErrorCategory::RecoverableDrift,
                format!("Invalid wallet_seq: expected {}, got {}", expected, got),
            )
            .with_recovery(RecoveryHint::ClaraHealNextSend),

            // LambdaError::StateIdMismatch is the Lambda-level wrap of
            // the Core SABR hash mismatch. Same recovery as Core's variant.
            LambdaError::StateIdMismatch => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_SABR_HASH_MISMATCH),
                ErrorCategory::RecoverableDrift,
                "State ID mismatch — wallet state does not match validator",
            )
            .with_recovery(RecoveryHint::ClaraHealNextSend)
            .with_yp_reference("§17.10.14 CLARA + YPX-018"),

            LambdaError::DuplicateTransaction(msg) => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_DUPLICATE_TRANSACTION),
                ErrorCategory::ProtocolReject,
                format!("Transaction already processed: {}", msg),
            ),

            LambdaError::SABRFailed(msg) => {
                // Try to preserve the inner Core discriminant (§13 Q8 of
                // the Errors YP — Lambda must not stringify Core). For now
                // we inspect the string; Phase 2b.3 will replace this
                // with a direct typed pass-through when Core returns
                // structured errors.
                if msg.contains("Insufficient overlap") {
                    ErrorResponse::new(
                        ErrorCode::from_static(error_code::E_SABR_INSUFFICIENT_OVERLAP),
                        ErrorCategory::RecoverableDrift,
                        msg.clone(),
                    )
                    .with_recovery(RecoveryHint::RetrySameValidator)
                    .with_yp_reference("YPX-016")
                } else if msg.contains("HASH_MISMATCH") {
                    ErrorResponse::new(
                        ErrorCode::from_static(error_code::E_SABR_HASH_MISMATCH),
                        ErrorCategory::RecoverableDrift,
                        msg.clone(),
                    )
                    .with_recovery(RecoveryHint::ClaraHealNextSend)
                } else {
                    ErrorResponse::new(
                        ErrorCode::from_static("E_SABR_UNCLASSIFIED"),
                        ErrorCategory::RecoverableDrift,
                        format!("S-ABR validation failed: {}", msg),
                    )
                }
            }

            LambdaError::SabrStateChainMismatch {
                requested_consumed_state_id,
                requested_wallet_seq,
                stored_sid,
                stored_seq,
                requested_csid_hex,
            } => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_SABR_HASH_MISMATCH),
                ErrorCategory::RecoverableDrift,
                format!(
                    "S-ABR state chain mismatch: requested csid={} stored_sid={} stored_seq={}",
                    requested_csid_hex,
                    stored_sid.as_ref().map(|s| hex::encode(&s[..8])).unwrap_or_else(|| "none".to_string()),
                    stored_seq.map(|s| s.to_string()).unwrap_or_else(|| "none".to_string()),
                ),
            )
            .with_recovery(RecoveryHint::ClaraHealNextSend)
            .with_detail(axiom_errors::ErrorDetail::StateChainMismatch(
                axiom_errors::StateChainMismatchDetail {
                    requested_consumed_state_id: *requested_consumed_state_id,
                    requested_wallet_seq: *requested_wallet_seq,
                    validator_stored_state_id: *stored_sid,
                    validator_wallet_seq: *stored_seq,
                },
            ))
            .with_yp_reference("§17.10.14 CLARA + YPX-018"),

            LambdaError::SabrInsufficientOverlap { provided, required, is_fresh } => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_SABR_INSUFFICIENT_OVERLAP),
                ErrorCategory::RecoverableDrift,
                format!(
                    "S-ABR insufficient overlap: got {}, need {} (fresh={})",
                    provided, required, is_fresh
                ),
            )
            .with_recovery(RecoveryHint::RetrySameValidator)
            .with_detail(axiom_errors::ErrorDetail::SabrInsufficientOverlap(
                axiom_errors::SabrInsufficientOverlapDetail {
                    overlap_sigs_provided: *provided,
                    overlap_sigs_required: *required,
                    is_fresh_validator: *is_fresh,
                },
            ))
            .with_yp_reference("YPX-016"),

            LambdaError::ConsensusTimeout => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_CONSENSUS_TIMEOUT),
                ErrorCategory::Operational,
                "Consensus timeout",
            )
            .with_recovery(RecoveryHint::RetryDifferentValidator),

            LambdaError::ConfigError(msg) => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_CONFIG_ERROR),
                ErrorCategory::Internal,
                format!("Configuration error: {}", msg),
            ),

            LambdaError::InvalidRequest(msg) => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_INVALID_REQUEST),
                ErrorCategory::ClientBug,
                format!("Invalid request: {}", msg),
            ),

            LambdaError::IoError(e) => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_IO_ERROR),
                ErrorCategory::Internal,
                format!("IO error: {}", e),
            ),

            LambdaError::SerializationError(msg) => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_SERIALIZATION_ERROR),
                ErrorCategory::ClientBug,
                format!("Serialization error: {}", msg),
            ),

            LambdaError::RateLimitExceeded { limit, window_secs, current_count } => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_RATE_LIMIT_EXCEEDED),
                ErrorCategory::Operational,
                format!(
                    "Rate limit exceeded: {}/{} requests in {}s window",
                    current_count, limit, window_secs
                ),
            )
            .with_recovery(RecoveryHint::WaitAndRetry)
            .with_retry_after(*window_secs)
            .with_detail(axiom_errors::ErrorDetail::RateLimit(
                axiom_errors::RateLimitDetail {
                    limit: *limit,
                    window_secs: *window_secs,
                    current_count: *current_count,
                },
            ))
            .with_yp_reference("YPX-015"),

            LambdaError::WalletFrozenJfp => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_WALLET_FROZEN_JFP),
                ErrorCategory::ProtocolReject,
                "Wallet frozen by Judicial Freeze Protocol",
            )
            .with_detail(axiom_errors::ErrorDetail::WalletLock(
                axiom_errors::WalletLockDetail {
                    lock_reason: axiom_errors::LockReason::JfpFreeze {
                        // TODO: once get_active_frozen_wallets() returns
                        // (pk, jfp_txid) pairs instead of just pks,
                        // plumb the real txid here. For now a zero
                        // placeholder tells clients "it's a JFP freeze"
                        // without claiming a specific approving JFP.
                        jfp_txid: [0u8; 32],
                    },
                    lock_started_at_tick: 0,
                    lock_expires_at_tick: None,
                    challenge_path: None,
                },
            ))
            .with_yp_reference("§7.8 JFP"),

            // FACT scar consent — per §8 of the Errors YP this SHOULD
            // become a distinct RedeemResponse variant, not an error.
            // Until Phase 2c ships that breaking change, we emit it as
            // a special code so the SDK can recognize and promote it
            // out of the error channel client-side.
            LambdaError::FactScarDetected { .. } => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_SCAR_CONSENT_REQUIRED),
                ErrorCategory::ProtocolReject,
                "FACT scar detected — scar passcode required from receiver",
            )
            .with_yp_reference("§17.9.4 + YPX-018"),

            LambdaError::InvalidScarPasscode(msg) => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_INVALID_SCAR_PASSCODE),
                ErrorCategory::ClientBug,
                format!("Invalid scar passcode: {}", msg),
            ),

            // YP §19.6 amendment — per-slot fee verification. SDK retries
            // with corrected breakdown after either of these.
            LambdaError::FeeSlotMismatch { expected, declared, tx_amount } => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_FEE_SLOT_MISMATCH),
                ErrorCategory::ClientBug,
                format!(
                    "Fee slot mismatch: validator expected {} atoms, SDK proposed {} (tx_amount={})",
                    expected, declared, tx_amount,
                ),
            )
            .with_recovery(RecoveryHint::RetrySameValidator)
            .with_yp_reference("§19.6"),

            LambdaError::FeeSlotMissing { tx_amount } => ErrorResponse::new(
                ErrorCode::from_static(error_code::E_LAMBDA_FEE_SLOT_MISSING),
                ErrorCategory::ClientBug,
                format!(
                    "Fee slot missing: validator not present in proposed fee_breakdown (tx_amount={})",
                    tx_amount,
                ),
            )
            .with_recovery(RecoveryHint::RetrySameValidator)
            .with_yp_reference("§19.6"),
        }
    }
}

impl From<LambdaError> for ErrorResponse {
    fn from(err: LambdaError) -> Self {
        (&err).into()
    }
}

/// Parse the `ValidationError::Display` string that Core returned
/// (wrapped in `CoreValidationFailed` or `CoreRejection`) and map it
/// to the matching `ErrorResponse` fields.
///
/// This is a temporary string-based classifier until Core's API
/// signature is updated in Phase 2b.3 to return `ErrorResponse`
/// directly. Once that lands, this function disappears.
fn classify_core_pass_through(
    s: &str,
) -> (
    &'static str,
    ErrorCategory,
    Option<RecoveryHint>,
    Option<&'static str>,
) {
    // The string emitted by ValidationError::Display is always the
    // E_* code (or a format like "E_FOO: details"). We substring-match
    // on the known codes to recover the classification.
    //
    // Order matters: check more specific codes first.
    if s.contains("E_SABR_HASH_MISMATCH") {
        (
            error_code::E_SABR_HASH_MISMATCH,
            ErrorCategory::RecoverableDrift,
            Some(RecoveryHint::ClaraHealNextSend),
            Some("§17.10.14 CLARA + YPX-018"),
        )
    } else if s.contains("E_SABR_INSUFFICIENT_OVERLAP") {
        (
            error_code::E_SABR_INSUFFICIENT_OVERLAP,
            ErrorCategory::RecoverableDrift,
            Some(RecoveryHint::RetrySameValidator),
            Some("YPX-016"),
        )
    } else if s.contains("E_INCONSISTENT_CHEQUE_BUNDLE") {
        (
            error_code::E_CHEQUE_INCONSISTENT_BUNDLE,
            ErrorCategory::RecoverableDrift,
            Some(RecoveryHint::DedupChequeBundle),
            Some("§17.9.4.0"),
        )
    } else if s.contains("E_INSUFFICIENT_BALANCE") {
        (
            error_code::E_INSUFFICIENT_BALANCE,
            ErrorCategory::ProtocolReject,
            None,
            None,
        )
    } else if s.contains("E_INVALID_CLIENT_SIG") {
        (
            error_code::E_INVALID_CLIENT_SIG,
            ErrorCategory::ClientBug,
            None,
            Some("YPX-007 §39.3"),
        )
    } else if s.contains("E_VBC_EXPIRED") {
        (
            error_code::E_VBC_EXPIRED,
            ErrorCategory::RecoverableDrift,
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        )
    } else if s.contains("E_CHEQUE_ALREADY_REDEEMED") {
        (
            error_code::E_CHEQUE_ALREADY_REDEEMED,
            ErrorCategory::ProtocolReject,
            None,
            None,
        )
    } else if s.contains("E_STATE_ID_CONSUMED") {
        (
            error_code::E_STATE_ID_CONSUMED,
            ErrorCategory::ProtocolReject,
            None,
            None,
        )
    } else if s.contains("E_DUST_AMOUNT") {
        (
            error_code::E_DUST_AMOUNT,
            ErrorCategory::ClientBug,
            None,
            None,
        )
    } else if s.contains("E_AUTH_HASH_REQUIRED") {
        (
            error_code::E_AUTH_HASH_REQUIRED,
            ErrorCategory::ClientBug,
            None,
            Some("YPX-007 §39.3"),
        )
    } else if s.contains("E_GENESIS_STAKE_LOCKED") {
        (
            error_code::E_GENESIS_STAKE_LOCKED,
            ErrorCategory::ProtocolReject,
            None,
            Some("White Paper §2.10.1"),
        )
    } else {
        // Unknown or not-yet-classified Core error. Pass through as
        // a generic unclassified reject; the message preserves the
        // original string for debugging.
        (
            "E_CORE_UNCLASSIFIED",
            ErrorCategory::ProtocolReject,
            None,
            None,
        )
    }
}

// ============================================================================
// Gateway response helpers (Phase 2b.2)
// ============================================================================

/// Build a `GatewayResponse::Error` from a `LambdaError`. The
/// structured `error_response` carries the full failure info
/// (code, category, message, recovery, detail, yp_reference).
/// See `docs/AXIOM_YellowPaper_Errors.md`.
pub fn gateway_error_from_lambda(
    request_id: String,
    err: &LambdaError,
) -> crate::types::GatewayResponse {
    crate::types::GatewayResponse::Error(crate::types::ErrorEnvelope {
        request_id,
        error_response: err.into(),
    })
}

/// Build a `GatewayResponse::Error` from a raw (code, category, message)
/// triple. Used for error sites that don't have a `LambdaError` in hand
/// (CBOR parse failures, static placeholder messages, etc.).
pub fn gateway_error_raw(
    request_id: String,
    code: &'static str,
    category: ErrorCategory,
    message: impl Into<String>,
) -> crate::types::GatewayResponse {
    crate::types::GatewayResponse::Error(crate::types::ErrorEnvelope {
        request_id,
        error_response: static_error(code, category, message),
    })
}

/// Build a structured `ErrorResponse` from a static code + category +
/// message. Used at sites inside `consensus.rs` that emit ad-hoc
/// protocol-string errors (cheque integrity, fee redemption checks,
/// ACK validation) and need a dual-format companion. Pick the code
/// and category that best match the failure; consult
/// `docs/AXIOM_YellowPaper_Errors.md` for the taxonomy.
pub fn static_error(
    code: &'static str,
    category: ErrorCategory,
    message: impl Into<String>,
) -> ErrorResponse {
    ErrorResponse::new(ErrorCode::from_static(code), category, message.into())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_errors::RecoveryHint;

    #[test]
    fn state_id_mismatch_maps_to_resync() {
        let err = LambdaError::StateIdMismatch;
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_SABR_HASH_MISMATCH");
        assert_eq!(resp.category, ErrorCategory::RecoverableDrift);
        assert_eq!(resp.recovery, Some(RecoveryHint::ClaraHealNextSend));
    }

    #[test]
    fn insufficient_witnesses_is_operational() {
        let err = LambdaError::InsufficientWitnesses { got: 2, need: 3 };
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_LAMBDA_INSUFFICIENT_WITNESSES");
        assert_eq!(resp.category, ErrorCategory::Operational);
        assert_eq!(resp.recovery, Some(RecoveryHint::RetrySameValidator));
        assert!(resp.message.contains("got 2"));
        assert!(resp.message.contains("need 3"));
    }

    #[test]
    fn insufficient_balance_preserves_context() {
        let err = LambdaError::InsufficientBalance {
            have: 500_000,
            need: 1_000_000,
        };
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_INSUFFICIENT_BALANCE");
        assert_eq!(resp.category, ErrorCategory::ProtocolReject);
        assert!(resp.message.contains("500000"));
        assert!(resp.message.contains("1000000"));
    }

    /// Phase 2b.8: InsufficientBalance populates a typed BalanceDetail
    /// that carries `requested_amount` and `current_balance` as
    /// structured fields — clients can show proper "you need X more"
    /// UI without parsing the message string.
    #[test]
    fn insufficient_balance_has_typed_detail() {
        let err = LambdaError::InsufficientBalance {
            have: 500_000,
            need: 1_000_000,
        };
        let resp: ErrorResponse = err.into();
        match resp.detail {
            Some(axiom_errors::ErrorDetail::Balance(bd)) => {
                assert_eq!(bd.requested_amount, 1_000_000);
                assert_eq!(bd.current_balance, Some(500_000));
            }
            other => panic!("expected Balance detail, got {:?}", other),
        }
    }

    #[test]
    fn rate_limit_has_retry_after() {
        let err = LambdaError::RateLimitExceeded {
            limit: 60,
            window_secs: 60,
            current_count: 60,
        };
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_LAMBDA_RATE_LIMIT_EXCEEDED");
        assert_eq!(resp.category, ErrorCategory::Operational);
        assert_eq!(resp.retry_after_secs, Some(60));
        assert_eq!(resp.recovery, Some(RecoveryHint::WaitAndRetry));
        match resp.detail {
            Some(axiom_errors::ErrorDetail::RateLimit(rl)) => {
                assert_eq!(rl.limit, 60);
                assert_eq!(rl.window_secs, 60);
                assert_eq!(rl.current_count, 60);
            }
            other => panic!("expected RateLimit detail, got {:?}", other),
        }
    }

    #[test]
    fn core_pass_through_hash_mismatch() {
        let err = LambdaError::CoreValidationFailed(String::from("E_SABR_HASH_MISMATCH"));
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_SABR_HASH_MISMATCH");
        assert_eq!(resp.category, ErrorCategory::RecoverableDrift);
        assert_eq!(resp.recovery, Some(RecoveryHint::ClaraHealNextSend));
    }

    #[test]
    fn core_pass_through_unclassified_falls_back() {
        let err = LambdaError::CoreValidationFailed(String::from("E_SOME_NEW_VARIANT"));
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_CORE_UNCLASSIFIED");
        assert_eq!(resp.category, ErrorCategory::ProtocolReject);
        // The original code string is preserved in the message.
        assert!(resp.message.contains("E_SOME_NEW_VARIANT"));
    }

    #[test]
    fn sabr_failed_insufficient_overlap_is_recognized() {
        let err = LambdaError::SABRFailed(String::from(
            "Insufficient overlap: got 1 signatures but need 2 for k=3",
        ));
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_SABR_INSUFFICIENT_OVERLAP");
        assert_eq!(resp.recovery, Some(RecoveryHint::RetrySameValidator));
    }

    #[test]
    fn scar_detected_maps_to_consent_code() {
        let err = LambdaError::FactScarDetected {
            passcode: 123456,
            txid: [0u8; 32],
            sender_wallet_id: String::from("alice@axiom"),
            receiver_wallet_id: String::from("bob@axiom"),
            amount: 1000,
            scar_count: 1,
        };
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_LAMBDA_SCAR_CONSENT_REQUIRED");
    }

    #[test]
    fn storage_error_is_internal() {
        let err = LambdaError::StorageError(String::from("sqlite busy"));
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.category, ErrorCategory::Internal);
        assert!(resp.message.contains("sqlite busy"));
    }
}
