//! Step 9B.4 — operator-side fan-out for the validator-withdrawal mint.
//!
//! After `validator_withdrawal::verify_validator_withdrawal` returns
//! VERIFIED, the operator's Lambda sends a `WithdrawalMintWitnessRequest`
//! to each of the k=3 `chosen_witnesses` over TCP CBOR (the same wire
//! format their gateway speaks for ANTIE-to-Lambda traffic). Each
//! chosen witness independently re-verifies through Core CL13 and
//! signs the canonical mint commitment with Ed25519 (Step 9B.3).
//!
//! This module:
//!   - sends the request to one address with a deadline,
//!   - fans out across k=3 in parallel,
//!   - verifies every returned signature against the mint commitment,
//!   - filters to the successful witnesses,
//!   - assembles the mint receipt (k=3 sigs + the mint output).
//!
//! Step 9B.5 sends `MarkValidatorEarningsClaimedRequest` to Nabla with
//! the collected sigs after the mint commits.
//!
//! Validator-id → TCP gateway address resolution is deliberately NOT
//! in scope here — the caller (the operator's admin handler in
//! `lambda/src/admin.rs`) is responsible for that lookup. This keeps
//! the fan-out function pure and unit-testable; integration tests
//! drive it with explicit addresses.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use axiom_core_logic::types::{
    GatewayRequest, GatewayResponse,
    WithdrawalMintWitnessRequest, WithdrawalMintWitnessResponse,
    ValidatorWithdrawalMintOutput,
};
use axiom_core_logic::wire_client::ValidatorWithdrawalRequest;

use crate::error::LambdaError;

/// Per-request deadline for talking to one chosen-witness Lambda. The
/// witness round is fully synchronous from the operator's perspective —
/// 30s is generous enough to cover the AVM round-trip + an SPHINCS+
/// verify on a slow validator, short enough to fail fast when a witness
/// is unreachable. Mirrors the gateway's own 30s read timeout
/// (`server.rs:read_timeout`).
const WITNESS_RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// k floor for the chosen-witness set (mirrors the SDK's k=3 protocol
/// floor that Lambda also enforces in `verify_validator_withdrawal`).
const MIN_CHOSEN_WITNESSES: usize = 3;

/// Signature collected from one chosen-witness Lambda.
///
/// Each chosen witness signs TWO payloads in the same round:
///   - `sig` over `compute_withdrawal_mint_commitment(...)` — used by
///     the operator's Lambda for the linked-wallet credit + audit trail.
///   - `claim_sig` over `compute_validator_claim_payload(validator_id,
///     claimed_through_tick)` — collected k=3 into a
///     `MarkValidatorEarningsClaimedRequest` sent to Nabla so
///     `last_claimed_tick` advances (Step 9B.8 cross-Lambda double-claim
///     defense).
#[derive(Debug, Clone)]
pub struct WitnessSignature {
    pub witness_id: [u8; 32],
    pub witness_pk: Vec<u8>,
    pub sig: Vec<u8>,
    pub claim_sig: Vec<u8>,
}

/// Mint receipt assembled from k=3 chosen-witness signatures + the
/// CL13 mint output (all agreed-on, otherwise the assembly fails).
#[derive(Debug, Clone)]
pub struct WithdrawalMintReceipt {
    pub mint: ValidatorWithdrawalMintOutput,
    pub signatures: Vec<WitnessSignature>,
}

/// Errors the operator-side fan-out can return.
#[derive(Debug)]
pub enum OrchestratorError {
    /// Fewer than `MIN_CHOSEN_WITNESSES` addresses supplied.
    NotEnoughWitnesses {
        supplied: usize,
        required: usize,
    },
    /// Fewer than `MIN_CHOSEN_WITNESSES` returned a verified Accept.
    /// Carries diagnostics — which addresses failed and why.
    QuorumNotReached {
        ok_count: usize,
        required: usize,
        failures: Vec<(String, String)>,
    },
    /// Two or more witnesses returned mint outputs that disagree on the
    /// commitment fields. Should be impossible if Core CL13 is
    /// deterministic — keep the check defensively, surface loudly.
    MintMismatch,
}

impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnoughWitnesses { supplied, required } => write!(
                f, "operator supplied {} witness addresses, need at least {}",
                supplied, required,
            ),
            Self::QuorumNotReached { ok_count, required, failures } => {
                write!(f, "{} witnesses accepted, need {} (failures: ", ok_count, required)?;
                for (i, (addr, why)) in failures.iter().enumerate() {
                    if i > 0 { write!(f, "; ")?; }
                    write!(f, "{}={}", addr, why)?;
                }
                write!(f, ")")
            }
            Self::MintMismatch => write!(
                f, "chosen witnesses returned non-identical mint outputs — \
                    Core CL13 nondeterminism (consensus bug)",
            ),
        }
    }
}

impl std::error::Error for OrchestratorError {}

/// Encode a `GatewayRequest` to the framed wire (4-byte BE length + CBOR
/// payload — same format `lambda/src/server.rs::write_framed_response`
/// uses for the reply direction).
fn encode_framed_request(req: &GatewayRequest) -> Result<Vec<u8>, LambdaError> {
    let mut payload = Vec::new();
    ciborium::into_writer(req, &mut payload)
        .map_err(|e| LambdaError::SerializationError(format!("CBOR encode: {e}")))?;
    let len = (payload.len() as u32).to_be_bytes();
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len);
    framed.extend_from_slice(&payload);
    Ok(framed)
}

/// Read a framed `GatewayResponse` off the stream. Mirrors the format
/// written by `server.rs::write_framed_response`. Bounded by the
/// stream's own read-timeout (caller wraps this in `tokio::time::timeout`).
async fn read_framed_response(
    stream: &mut TcpStream,
) -> Result<GatewayResponse, LambdaError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await
        .map_err(|e| LambdaError::SerializationError(format!("read len: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // 10 MB is conservative — withdrawal responses are tiny (<2 KB).
    if len > 10 * 1024 * 1024 {
        return Err(LambdaError::SerializationError(
            format!("response frame too large: {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await
        .map_err(|e| LambdaError::SerializationError(format!("read body: {e}")))?;
    ciborium::from_reader(body.as_slice())
        .map_err(|e| LambdaError::SerializationError(format!("CBOR decode: {e}")))
}

/// Send one `WithdrawalMintWitnessRequest` to one chosen-witness
/// Lambda's TCP gateway and return its response. Bounded by
/// `WITNESS_RPC_TIMEOUT`.
pub async fn send_witness_request(
    address: &str,
    request: &WithdrawalMintWitnessRequest,
) -> Result<WithdrawalMintWitnessResponse, LambdaError> {
    let envelope = GatewayRequest::WithdrawalMintWitness(request.clone());
    let framed = encode_framed_request(&envelope)?;

    let connect = TcpStream::connect(address);
    let mut stream = tokio::time::timeout(WITNESS_RPC_TIMEOUT, connect)
        .await
        .map_err(|_| LambdaError::SerializationError(
            format!("connect timeout to {address}"),
        ))?
        .map_err(|e| LambdaError::SerializationError(
            format!("connect to {address}: {e}"),
        ))?;

    stream.write_all(&framed).await
        .map_err(|e| LambdaError::SerializationError(format!("write {address}: {e}")))?;
    stream.flush().await
        .map_err(|e| LambdaError::SerializationError(format!("flush {address}: {e}")))?;

    let response = tokio::time::timeout(WITNESS_RPC_TIMEOUT, read_framed_response(&mut stream))
        .await
        .map_err(|_| LambdaError::SerializationError(
            format!("read timeout from {address}"),
        ))??;

    match response {
        GatewayResponse::WithdrawalMintWitnessResult(r) => Ok(r),
        other => Err(LambdaError::SerializationError(format!(
            "unexpected response variant from {address}: {:?}",
            std::mem::discriminant(&other),
        ))),
    }
}

/// Verify one witness signature against the canonical mint commitment.
/// Returns the signature wrapped in `WitnessSignature` if it verifies.
fn verify_witness_signature(
    resp: &WithdrawalMintWitnessResponse,
    expected: &ValidatorWithdrawalMintOutput,
) -> Result<WitnessSignature, String> {
    if resp.status != "VERIFIED" {
        return Err(format!("status={}", resp.status));
    }
    let sig = resp.witness_sig.as_ref()
        .ok_or_else(|| "Accept response missing witness_sig".to_string())?;
    let claim_sig = resp.claim_sig.as_ref()
        .ok_or_else(|| "Accept response missing claim_sig".to_string())?;
    let mint = resp.mint.as_ref()
        .ok_or_else(|| "Accept response missing mint".to_string())?;

    // Defensive: even though the response said "VERIFIED", we still
    // assert the mint fields match what we expect. A malicious witness
    // could otherwise sign over a different commitment than the one
    // they claim to verify.
    if mint != expected {
        return Err(format!(
            "mint mismatch: got vid={} amt={} != expected vid={} amt={}",
            hex::encode(&mint.validator_id[..8]),
            mint.net_amount,
            hex::encode(&expected.validator_id[..8]),
            expected.net_amount,
        ));
    }

    let commitment = axiom_core_logic::compute::compute_withdrawal_mint_commitment(
        &mint.validator_id,
        &mint.linked_wallet_id,
        mint.net_amount,
        mint.claimed_through_tick,
    );
    axiom_core_logic::verify::verify_ed25519(&resp.witness_pk, &commitment, sig)
        .map_err(|e| format!("ed25519 verify mint: {:?}", e))?;

    // Verify the claim signature too. Same Ed25519 key, different
    // payload — both must verify before we accept the witness.
    let claim_payload = axiom_core_logic::compute::compute_validator_claim_payload(
        &mint.validator_id,
        mint.claimed_through_tick,
    );
    axiom_core_logic::verify::verify_ed25519(&resp.witness_pk, &claim_payload, claim_sig)
        .map_err(|e| format!("ed25519 verify claim: {:?}", e))?;

    let witness_id: [u8; 32] = *blake3::hash(&resp.witness_pk).as_bytes();
    Ok(WitnessSignature {
        witness_id,
        witness_pk: resp.witness_pk.clone(),
        sig: sig.clone(),
        claim_sig: claim_sig.clone(),
    })
}

/// Compute the expected mint output the operator's Lambda already has
/// (from its own `verify_validator_withdrawal` accept). Used as the
/// reference against which each witness's claimed mint is checked.
fn expected_mint_from_withdrawal(
    withdrawal: &ValidatorWithdrawalRequest,
) -> ValidatorWithdrawalMintOutput {
    let net_amount = withdrawal.earnings_attestation.total_amount * 90 / 100;
    ValidatorWithdrawalMintOutput {
        validator_id: withdrawal.validator_id,
        linked_wallet_id: withdrawal.pool_linkage.linked_wallet_id,
        net_amount,
        claimed_through_tick: withdrawal.earnings_attestation.until_tick,
    }
}

/// Fan out a withdrawal mint round to chosen-witness Lambdas.
///
/// `witness_addrs` MUST have ≥ MIN_CHOSEN_WITNESSES entries. They map
/// 1:1 to `withdrawal.chosen_witnesses` semantically (the caller is
/// responsible for resolving each `validator_id` to its TCP address),
/// but this function does NOT enforce the mapping at the type level —
/// the witnesses' Ed25519 PKs in their replies are what the mint
/// receipt commits to.
///
/// Returns a `WithdrawalMintReceipt` with the k=3+ signatures on
/// success, or an `OrchestratorError` enumerating what failed.
pub async fn collect_witness_signatures(
    request_id: String,
    withdrawal: ValidatorWithdrawalRequest,
    witness_addrs: Vec<String>,
) -> Result<WithdrawalMintReceipt, OrchestratorError> {
    if witness_addrs.len() < MIN_CHOSEN_WITNESSES {
        return Err(OrchestratorError::NotEnoughWitnesses {
            supplied: witness_addrs.len(),
            required: MIN_CHOSEN_WITNESSES,
        });
    }

    let expected = expected_mint_from_withdrawal(&withdrawal);
    let req = WithdrawalMintWitnessRequest {
        request_id: request_id.clone(),
        withdrawal,
    };

    // Fan out in parallel.
    let handles: Vec<_> = witness_addrs.iter().map(|addr| {
        let addr = addr.clone();
        let req = req.clone();
        tokio::spawn(async move {
            let outcome = send_witness_request(&addr, &req).await;
            (addr, outcome)
        })
    }).collect();

    let mut signatures: Vec<WitnessSignature> = Vec::new();
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut collected_mint: Option<ValidatorWithdrawalMintOutput> = None;

    for h in handles {
        let (addr, result) = match h.await {
            Ok(pair) => pair,
            Err(e) => {
                failures.push(("<panicked>".into(), format!("join: {e}")));
                continue;
            }
        };
        match result {
            Err(e) => {
                warn!("withdrawal mint witness {addr}: {e}");
                failures.push((addr, format!("rpc: {e}")));
            }
            Ok(resp) => match verify_witness_signature(&resp, &expected) {
                Err(why) => {
                    debug!("withdrawal mint witness {addr} rejected: {why}");
                    failures.push((addr, why));
                }
                Ok(sig) => {
                    // First successful witness pins the mint output we'll
                    // surface on the receipt; later witnesses must agree.
                    if let Some(existing) = &collected_mint {
                        if existing != resp.mint.as_ref().unwrap() {
                            return Err(OrchestratorError::MintMismatch);
                        }
                    } else {
                        collected_mint = resp.mint.clone();
                    }
                    signatures.push(sig);
                }
            },
        }
    }

    if signatures.len() < MIN_CHOSEN_WITNESSES {
        return Err(OrchestratorError::QuorumNotReached {
            ok_count: signatures.len(),
            required: MIN_CHOSEN_WITNESSES,
            failures,
        });
    }

    Ok(WithdrawalMintReceipt {
        mint: collected_mint.expect("≥3 signatures ⇒ collected_mint populated"),
        signatures,
    })
}

/// Step 9B.8 — outcome of sending the post-mint
/// `MarkValidatorEarningsClaimedRequest` to Nabla.
#[derive(Debug, Clone)]
pub enum MarkClaimedOutcome {
    /// Nabla acknowledged the advance — `last_claimed_tick` is now set
    /// to `claimed_through_tick`. Future earnings queries will exclude
    /// the claimed window, closing the cross-Lambda double-claim path.
    Claimed { stored_last_claimed_tick: u64 },
    /// Nabla rejected. `status` is the verbatim Nabla response status
    /// (`"REJECTED_REPLAY"` / `"REJECTED_SIG"` / `"REJECTED_INTERNAL"`).
    Rejected { status: String, stored_last_claimed_tick: u64 },
    /// Transport-level error (connect / read / decode). Operator can
    /// retry — the mint is already persisted, MarkClaimed is best-effort.
    RpcError { detail: String },
}

/// Build the K3WitnessSig list Nabla expects from the orchestrator's
/// WitnessSignature collection. Maps `witness_pk` (Vec<u8>) → fixed-size
/// `validator_pk: [u8; 32]` and zero-fills the receipt fields (the
/// claim has no fee_breakdown / execution proof to bind).
fn build_lambda_sigs_for_claim(
    sigs: &[WitnessSignature],
) -> Vec<axiom_core_logic::nabla_wire::K3WitnessSig> {
    sigs.iter().filter_map(|s| {
        let pk: [u8; 32] = s.witness_pk.as_slice().try_into().ok()?;
        Some(axiom_core_logic::nabla_wire::K3WitnessSig {
            validator_pk: pk,
            signature: s.claim_sig.clone(),
            execution_proof: vec![],
            proof_type: 0,
            receipt_commitment_sig: vec![],
            // Withdrawal-mint receipts carry no per-validator fee shares —
            // the mint amount comes from the NET ledger, not from a
            // per-slot fee. Both fields stay at default.
            validator_id: [0u8; 32],
            slot_amount: 0,
        })
    }).collect()
}

/// Send a `MarkValidatorEarningsClaimedRequest` to one Nabla TCP
/// endpoint. Uses the same 4-byte BE length prefix + CBOR framing
/// every Nabla wire op uses (see `consensus.rs` oracle stake RPC for
/// the reference path).
///
/// `nabla_addr` is a `host:port` string for the Nabla TCP gateway
/// (e.g. `"127.0.0.1:7300"` for alpha in the dev env). Bounded by a
/// 10s read deadline — claim advancement is a Nabla disk write +
/// gossip emit, not an arbitrary computation.
pub async fn send_mark_validator_claimed(
    nabla_addr: &str,
    validator_id: [u8; 32],
    claimed_through_tick: u64,
    signatures: &[WitnessSignature],
) -> MarkClaimedOutcome {
    use axiom_core_logic::nabla_wire::WireMessage;
    use axiom_core_logic::wire_client::{
        MarkValidatorEarningsClaimedRequest, MarkValidatorEarningsClaimedResponse,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let lambda_signatures = build_lambda_sigs_for_claim(signatures);
    if lambda_signatures.len() < MIN_CHOSEN_WITNESSES {
        return MarkClaimedOutcome::RpcError {
            detail: format!(
                "only {} valid lambda_signatures (need {}); witness_pk \
                must be exactly 32 bytes",
                lambda_signatures.len(), MIN_CHOSEN_WITNESSES,
            ),
        };
    }

    let req = WireMessage::MarkValidatorEarningsClaimedRequest(
        MarkValidatorEarningsClaimedRequest {
            validator_id,
            claimed_through_tick,
            lambda_signatures,
        },
    );
    let mut cbor_req = Vec::new();
    if let Err(e) = ciborium::ser::into_writer(&req, &mut cbor_req) {
        return MarkClaimedOutcome::RpcError {
            detail: format!("CBOR encode: {e}"),
        };
    }
    let mut framed = Vec::with_capacity(4 + cbor_req.len());
    framed.extend_from_slice(&(cbor_req.len() as u32).to_be_bytes());
    framed.extend_from_slice(&cbor_req);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    let mut stream = match tokio::time::timeout_at(
        deadline, TcpStream::connect(nabla_addr),
    ).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return MarkClaimedOutcome::RpcError {
            detail: format!("connect {nabla_addr}: {e}"),
        },
        Err(_) => return MarkClaimedOutcome::RpcError {
            detail: format!("connect timeout {nabla_addr}"),
        },
    };
    if let Err(e) = stream.write_all(&framed).await {
        return MarkClaimedOutcome::RpcError {
            detail: format!("write {nabla_addr}: {e}"),
        };
    }
    if let Err(e) = stream.flush().await {
        return MarkClaimedOutcome::RpcError {
            detail: format!("flush {nabla_addr}: {e}"),
        };
    }

    let mut len_buf = [0u8; 4];
    if let Err(e) = tokio::time::timeout_at(
        deadline, stream.read_exact(&mut len_buf),
    ).await.unwrap_or_else(|_| Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut, "read len timeout",
    ))) {
        return MarkClaimedOutcome::RpcError {
            detail: format!("read len {nabla_addr}: {e}"),
        };
    }
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 65536 {
        return MarkClaimedOutcome::RpcError {
            detail: format!("response too large: {resp_len}"),
        };
    }
    let mut body = vec![0u8; resp_len];
    if let Err(e) = tokio::time::timeout_at(
        deadline, stream.read_exact(&mut body),
    ).await.unwrap_or_else(|_| Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut, "read body timeout",
    ))) {
        return MarkClaimedOutcome::RpcError {
            detail: format!("read body {nabla_addr}: {e}"),
        };
    }
    let envelope: WireMessage = match ciborium::from_reader(body.as_slice()) {
        Ok(v) => v,
        Err(e) => return MarkClaimedOutcome::RpcError {
            detail: format!("decode {nabla_addr}: {e}"),
        },
    };
    let resp: MarkValidatorEarningsClaimedResponse = match envelope {
        WireMessage::MarkValidatorEarningsClaimedResponse(r) => r,
        other => return MarkClaimedOutcome::RpcError {
            detail: format!(
                "unexpected response variant from {nabla_addr}: {:?}",
                std::mem::discriminant(&other),
            ),
        },
    };

    if resp.status == "CLAIMED" {
        MarkClaimedOutcome::Claimed {
            stored_last_claimed_tick: resp.stored_last_claimed_tick,
        }
    } else {
        MarkClaimedOutcome::Rejected {
            status: resp.status,
            stored_last_claimed_tick: resp.stored_last_claimed_tick,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core_logic::wire_client::{
        QueryValidatorEarningsResponse, QueryValidatorPoolResponse,
    };

    fn empty_withdrawal_request() -> ValidatorWithdrawalRequest {
        ValidatorWithdrawalRequest {
            validator_id: [0xAA; 32],
            earnings_attestation: QueryValidatorEarningsResponse {
                total_amount: 100,
                until_tick: 42,
                ..Default::default()
            },
            pool_linkage: QueryValidatorPoolResponse {
                linked_wallet_id: [0xBB; 32],
                ..Default::default()
            },
            sphincs_pk: vec![],
            sphincs_sig: vec![],
            chosen_witnesses: vec![[1; 32], [2; 32], [3; 32]],
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fewer_than_three_addresses_rejected() {
        let result = collect_witness_signatures(
            "test".into(),
            empty_withdrawal_request(),
            vec!["127.0.0.1:1".into(), "127.0.0.1:2".into()],
        ).await;
        match result {
            Err(OrchestratorError::NotEnoughWitnesses { supplied, required }) => {
                assert_eq!(supplied, 2);
                assert_eq!(required, 3);
            }
            other => panic!("expected NotEnoughWitnesses, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn all_unreachable_addresses_report_quorum_failure() {
        // 127.0.0.1:1-3 are reserved/refused — RPCs fail fast (no
        // listener), so we get 0 sigs + 3 connect-failed entries.
        let result = collect_witness_signatures(
            "test".into(),
            empty_withdrawal_request(),
            vec![
                "127.0.0.1:1".into(),
                "127.0.0.1:2".into(),
                "127.0.0.1:3".into(),
            ],
        ).await;
        match result {
            Err(OrchestratorError::QuorumNotReached { ok_count, required, failures }) => {
                assert_eq!(ok_count, 0);
                assert_eq!(required, 3);
                assert_eq!(failures.len(), 3);
                for (_addr, why) in &failures {
                    assert!(why.starts_with("rpc:"), "expected rpc error, got {why}");
                }
            }
            other => panic!("expected QuorumNotReached, got {other:?}"),
        }
    }

    /// Verifies the signature-check is binding: a witness who responds
    /// VERIFIED but whose Ed25519 sig doesn't actually verify is
    /// classified as a failure, not a success.
    #[test]
    fn malformed_signature_classified_as_failure() {
        let expected = ValidatorWithdrawalMintOutput {
            validator_id: [0xAA; 32],
            linked_wallet_id: [0xBB; 32],
            net_amount: 90,
            claimed_through_tick: 42,
        };
        let resp = WithdrawalMintWitnessResponse {
            request_id: "x".into(),
            status: "VERIFIED".into(),
            witness_pk: vec![0u8; 32],   // not the pk that signed
            witness_sig: Some(vec![0u8; 64]),
            claim_sig: Some(vec![0u8; 64]),
            mint: Some(expected.clone()),
            error_response: None,
        };
        let result = verify_witness_signature(&resp, &expected);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("ed25519 verify"), "expected ed25519 error, got {err}");
    }

    /// MarkClaimed against a refused TCP address surfaces a typed
    /// RpcError (best-effort by design — the mint is already
    /// persisted, MarkClaimed is just the cross-Lambda follow-up).
    #[tokio::test(flavor = "current_thread")]
    async fn mark_claimed_refused_address_returns_rpc_error() {
        let sigs: Vec<WitnessSignature> = (0..3).map(|i| WitnessSignature {
            witness_id: [i as u8; 32],
            witness_pk: vec![i as u8; 32],
            sig: vec![],
            claim_sig: vec![],
        }).collect();
        let outcome = send_mark_validator_claimed(
            "127.0.0.1:1",  // reserved port — connection refused fast
            [0xAA; 32],
            42,
            &sigs,
        ).await;
        match outcome {
            MarkClaimedOutcome::RpcError { detail } => {
                assert!(detail.contains("connect"),
                    "expected connect error, got {detail}");
            }
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    /// build_lambda_sigs_for_claim filters out witnesses whose witness_pk
    /// isn't exactly 32 bytes (can't fit into K3WitnessSig.validator_pk).
    /// If fewer than k=3 valid sigs remain, send_mark_validator_claimed
    /// surfaces an RpcError BEFORE opening any TCP socket.
    #[tokio::test(flavor = "current_thread")]
    async fn mark_claimed_rejects_non_32_byte_pks_before_network() {
        // 3 sigs but only 1 has a 32-byte pk — the other two get
        // filtered out by build_lambda_sigs_for_claim. Result: < 3
        // valid sigs → fail fast with no TCP attempt.
        let sigs = vec![
            WitnessSignature {
                witness_id: [1; 32], witness_pk: vec![1; 32], sig: vec![], claim_sig: vec![],
            },
            WitnessSignature {
                witness_id: [2; 32], witness_pk: vec![2; 24],  // wrong length
                sig: vec![], claim_sig: vec![],
            },
            WitnessSignature {
                witness_id: [3; 32], witness_pk: vec![3; 40],  // wrong length
                sig: vec![], claim_sig: vec![],
            },
        ];
        let outcome = send_mark_validator_claimed(
            "127.0.0.1:9999",  // no listener but we never reach it
            [0xAA; 32],
            42,
            &sigs,
        ).await;
        match outcome {
            MarkClaimedOutcome::RpcError { detail } => {
                assert!(detail.contains("witness_pk must be exactly 32 bytes"),
                    "expected pre-network reject, got {detail}");
            }
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    /// Witness signs over a different mint amount than the operator
    /// expects: rejected, not silently accepted with the witness's
    /// version. (Defense against a malicious witness inflating the
    /// mint.)
    #[test]
    fn mint_mismatch_classified_as_failure() {
        let expected = ValidatorWithdrawalMintOutput {
            validator_id: [0xAA; 32],
            linked_wallet_id: [0xBB; 32],
            net_amount: 90,
            claimed_through_tick: 42,
        };
        let tampered = ValidatorWithdrawalMintOutput {
            net_amount: 999_999,  // witness tried to inflate
            ..expected.clone()
        };
        let resp = WithdrawalMintWitnessResponse {
            request_id: "x".into(),
            status: "VERIFIED".into(),
            witness_pk: vec![0u8; 32],
            witness_sig: Some(vec![0u8; 64]),
            claim_sig: Some(vec![0u8; 64]),
            mint: Some(tampered),
            error_response: None,
        };
        let result = verify_witness_signature(&resp, &expected);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("mint mismatch"), "expected mint mismatch, got {err}");
    }
}
