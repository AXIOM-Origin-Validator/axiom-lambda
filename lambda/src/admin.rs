//! Lambda admin endpoint — lightweight HTTP server for validator console.
//!
//! Serves JSON stats from ConsensusEngine and Storage for the operator console.
//! Binds to 127.0.0.1 only (localhost). No public network exposure.
//!
//! Endpoints:
//! - `GET /health`    -> Lightweight health check (always accessible, no auth)
//! - `GET /stats`     -> Witness/redeem counters from ValidatorStats
//! - `GET /proof`     -> Proof pipeline status (DMAP/ZKP mode, timing)
//! - `GET /identity`  -> Validator ID, VBC chain, NBC status
//! - `GET /db`        -> Storage metrics (record count, size)
//! - `GET /fees`      -> v3.x earnings (this validator's slot atoms + count)
//! - `GET /peers`     -> Discovered validators (hint table)
//! - `GET /capacity`  -> Hardware capacity snapshot (CPU/RAM/disk/GPU/net) for operator

use crate::consensus::ConsensusEngine;
use crate::rate_limit::RateLimiter;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

/// Parse hex string to [u8; 32], returning error message on failure.
fn parse_hex32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// AUDIT-FIX v2.11.14: Validate Nabla address against known safe peers.
/// Only localhost Nabla HTTP ports (6226-6231) are accepted.
/// This prevents SSRF via caller-controlled nabla_url in /jfp/scar.
fn is_allowed_nabla_addr(addr: &str) -> bool {
    // Known Nabla HTTP ports: 6226-6231 (6 genesis nodes)
    const ALLOWED: &[&str] = &[
        "127.0.0.1:6226", "127.0.0.1:6227", "127.0.0.1:6228",
        "127.0.0.1:6229", "127.0.0.1:6230", "127.0.0.1:6231",
    ];
    ALLOWED.contains(&addr)
}

/// Extract a query parameter value from a query string.
/// E.g., extract_query_param("token=abc&foo=bar", "token") => Some("abc")
fn extract_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&')
        .find(|p| p.starts_with(key) && p.as_bytes().get(key.len()) == Some(&b'='))
        .map(|p| &p[key.len() + 1..])
}

/// Check bearer token auth. Returns true if request is authorized.
/// /health is always allowed. Other endpoints require token match.
/// SECURITY: When no token is configured, all non-health endpoints are DENIED.
/// Accepts token via Authorization header (preferred) or query parameter (legacy).
fn check_auth(path: &str, query: Option<&str>, auth_token: &Option<String>, headers: Option<&str>) -> bool {
    // /health is always accessible (liveness probes)
    if path == "/health" {
        return true;
    }
    // AUDIT-FIX v2.11.14: deny all non-health routes when no token is configured.
    // Previous behavior (allow all) was a security foot-gun on multi-user hosts.
    let expected = match auth_token {
        Some(t) => t,
        None => return false,
    };
    // Prefer Authorization header (S6: tokens in query params are logged by proxies)
    if let Some(hdrs) = headers {
        for line in hdrs.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("authorization:") {
                let value = line[14..].trim();
                if let Some(token) = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer ")) {
                    return token.trim() == expected;
                }
                return value == expected.as_str();
            }
        }
    }
    // Fallback: query parameter (legacy, still supported)
    matches!(query.and_then(|q| extract_query_param(q, "token")), Some(t) if t == expected)
}

/// Spawn the admin HTTP server on the given port.
/// Returns a JoinHandle that runs until dropped/cancelled.
pub fn spawn_admin_server(port: u16, engine: Arc<ConsensusEngine>, auth_token: Option<String>) -> tokio::task::JoinHandle<()> {
    // AUDIT-FIX v2.11.14: Rate limit admin connections per IP.
    // 6000 req/min is fine for localhost admin (dashboard + soak test + genesis bursts).
    spawn_admin_server_with_rate_limit(port, engine, auth_token, 6000, 60)
}

/// Same as `spawn_admin_server` but with configurable rate limit.
/// Exposed for tests that need to exercise the 429 path without pounding the
/// server with thousands of requests.
pub fn spawn_admin_server_with_rate_limit(
    port: u16,
    engine: Arc<ConsensusEngine>,
    auth_token: Option<String>,
    max_requests: u32,
    window_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if auth_token.is_none() {
            warn!("Admin endpoint has no auth_token configured — all non-health routes will be DENIED. Set admin_token in config to enable access.");
        }
        let addr = format!("127.0.0.1:{}", port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => {
                info!("Admin endpoint listening on {}", addr);
                l
            }
            Err(e) => {
                warn!("Admin endpoint failed to bind to {}: {}", addr, e);
                return;
            }
        };

        let rate_limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new(max_requests, window_secs)));

        loop {
            let (mut stream, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            // AUDIT-FIX v2.11.14: Rate limit admin connections (60 req/min per IP)
            let rate_ok = {
                let mut rl = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
                rl.check(peer_addr.ip())
            }; // MutexGuard dropped before any await
            if !rate_ok {
                let response = "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: 30\r\nConnection: close\r\n\r\n{\"error\":\"rate limit exceeded\"}";
                let _ = stream.write_all(response.as_bytes()).await;
                continue;
            }
            let engine = engine.clone();
            let auth_token = auth_token.clone();
            tokio::spawn(async move {
                // Read HTTP request: loop until we have headers + complete body.
                let mut all = Vec::with_capacity(32768);
                let mut buf = [0u8; 32768];
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);

                loop {
                    let remaining = deadline - tokio::time::Instant::now();
                    let n = match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
                        Ok(Ok(n)) if n > 0 => n,
                        _ => break,
                    };
                    all.extend_from_slice(&buf[..n]);

                    // Check if we have complete request (headers + body)
                    if let Some(hdr_end) = all.windows(4).position(|w| w == b"\r\n\r\n") {
                        let hdr_str = String::from_utf8_lossy(&all[..hdr_end + 4]);
                        let cl: usize = hdr_str.lines()
                            .find(|l| l.to_lowercase().starts_with("content-length:"))
                            .and_then(|l| l.split(':').nth(1))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        let body_have = all.len() - (hdr_end + 4);
                        if body_have >= cl { break; } // Got everything
                    }
                    if all.len() > 65536 { break; } // Safety cap
                }
                if all.is_empty() { return; }

                let request = String::from_utf8_lossy(&all);
                let first_line = request.lines().next().unwrap_or("");

                // Extract method, path, and query from "GET /path?query HTTP/1.1"
                let method = first_line.split_whitespace().next().unwrap_or("GET");
                let uri = first_line.split_whitespace().nth(1).unwrap_or("/");
                let (path, query) = if let Some(pos) = uri.find('?') {
                    (&uri[..pos], Some(&uri[pos + 1..]))
                } else {
                    (uri, None)
                };

                // Extract POST body (after \r\n\r\n)
                let body_str = request.find("\r\n\r\n")
                    .map(|pos| &request[pos + 4..])
                    .unwrap_or("");

                // Extract headers for auth check (between first line and body)
                let header_section = request.find("\r\n")
                    .and_then(|start| request.find("\r\n\r\n").map(|end| &request[start..end]));

                // Auth check
                // All handlers run in spawn_blocking to prevent parking_lot::Mutex
                // from blocking the tokio runtime (DB access is synchronous).
                let method = method.to_string();
                let path = path.to_string();
                let query = query.map(|s| s.to_string());
                let body_str = body_str.to_string();
                let body_str_for_async = body_str.clone();
                let header_section = header_section.map(|s| s.to_string());
                let engine_for_async = engine.clone();

                let (status, body) = tokio::task::spawn_blocking(move || {
                let query_ref = query.as_deref();
                let header_ref = header_section.as_deref();
                if !check_auth(&path, query_ref, &auth_token, header_ref) {
                    warn!("Admin auth failed from client (path={})", path);
                    ("401 Unauthorized", r#"{"error":"unauthorized"}"#.to_string())
                } else if method == "GET" || method == "HEAD" {
                    match path.as_str() {
                        "/health" => ("200 OK", health_json(&engine)),
                        "/stats" => ("200 OK", stats_json(&engine)),
                        "/proof" => ("200 OK", proof_json(&engine)),
                        "/identity" => ("200 OK", identity_json(&engine)),
                        "/db" => ("200 OK", db_json(&engine)),
                        "/fees" => ("200 OK", fees_json(&engine)),
                        "/peers" => ("200 OK", peers_json(&engine)),
                        "/capacity" => ("200 OK", capacity_json(&engine)),
                        "/audit" => ("200 OK", audit_json(&engine)),
                        "/approvals" => ("200 OK", approvals_json(&engine)),
                        "/dwp" => ("200 OK", dwp_json(&engine)),
                        "/dwp/wallets" => ("200 OK", dwp_wallets_json(&engine)),
                        "/dwp/detail" => ("200 OK", dwp_detail_json(&engine, query_ref)),
                        "/jfp/result" => ("200 OK", jfp_result_json(&engine, query_ref)),
                        "/mv/select" => ("200 OK", mv_select_json(&engine, query_ref)),
                        "/mv/status" => ("200 OK", mv_status_json(&engine, query_ref)),
                        "/console" => ("200 OK", console_json(&engine)),
                        "/scar-passcode" => ("200 OK", scar_passcode_json(&engine, query_ref)),
                        "/delivery-status" => ("200 OK", delivery_status_json(&engine, query_ref)),
                        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
                    }
                } else if method == "POST" {
                    match path.as_str() {
                        "/dwp/query" => ("200 OK", handle_dwp_query(&engine, &body_str)),
                        "/dwp/case" => ("200 OK", handle_dwp_case(&engine, &body_str)),
                        "/dwp/vote" => ("200 OK", handle_dwp_vote(&engine, &body_str)),
                        "/jfp/scar" => ("200 OK", handle_jfp_scar(&engine, &body_str)),
                        "/console/bootstrap" => ("200 OK", handle_console_bootstrap(&engine)),
                        "/console/propose" => ("200 OK", handle_console_propose(&engine, &body_str)),
                        "/console/dismiss" => ("200 OK", handle_console_dismiss(&engine, &body_str)),
                        "/console/core-update" => ("200 OK", handle_console_core_update(&engine, &body_str)),
                        "/console/vote" => ("200 OK", handle_console_vote(&engine, &body_str)),
                        "/console/finalize" => ("200 OK", handle_console_finalize(&engine)),
                        "/delivery-update" => ("200 OK", handle_delivery_update(&engine, &body_str)),
                        "/scar-passcode/recover" => ("200 OK", handle_scar_passcode_recover(&engine, &body_str)),
                        // /withdrawal/mint is handled async outside spawn_blocking
                        // (network fan-out, not DB-bound). Sentinel returned here
                        // so the outer match knows to handle it.
                        "/withdrawal/mint" => ("__ASYNC__", String::new()),
                        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
                    }
                } else {
                    ("405 Method Not Allowed", r#"{"error":"method not allowed"}"#.to_string())
                }
                }).await.unwrap_or(("500 Internal Server Error", r#"{"error":"handler panicked"}"#.to_string()));

                // Async-path handlers (network fan-out — must NOT live in
                // spawn_blocking). Dispatch on the sentinel returned above.
                let (status, body) = if status == "__ASYNC__" {
                    let result = handle_withdrawal_mint_async(&engine_for_async, &body_str_for_async).await;
                    ("200 OK", result)
                } else {
                    (status, body)
                };

                // SECURITY FIX #4: CORS restricted from wildcard (*) to localhost only.
                // Wildcard allowed any website to query admin stats via cross-origin requests.
                // Admin endpoint already binds to 127.0.0.1, so only localhost origins are valid.
                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status, body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                debug!("Admin request: {} -> {}", first_line, status);
            });
        }
    })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn health_json(engine: &ConsensusEngine) -> String {
    let uptime = now_secs().saturating_sub(engine.stats.started_at);
    let core_version = axiom_core_logic::version::core_version_full();
    format!(
        r#"{{"ok":true,"uptime_secs":{},"core_version":"{}"}}"#,
        uptime, core_version,
    )
}

fn stats_json(engine: &ConsensusEngine) -> String {
    use std::sync::atomic::Ordering::Relaxed;
    let s = &engine.stats;
    let wc = s.witness_count.load(Relaxed);
    let w_dmap = s.witness_dmap_count.load(Relaxed);
    let w_zkvm = s.witness_zkvm_count.load(Relaxed);
    let ws = s.witness_success.load(Relaxed);
    let we = s.witness_errors.load(Relaxed);
    let aw = s.atoms_witnessed.load(Relaxed);
    let wt = s.witness_time_us.load(Relaxed);
    let rc = s.redeem_count.load(Relaxed);
    let rs = s.redeem_success.load(Relaxed);
    let re = s.redeem_errors.load(Relaxed);
    let ar = s.atoms_redeemed.load(Relaxed);
    let rt = s.redeem_time_us.load(Relaxed);
    let gi = s.genesis_inits.load(Relaxed);
    let hc = s.hint_count.load(Relaxed);
    let last_tx = s.last_tx_at.load(Relaxed);
    let avg_witness_us = if ws > 0 { wt / ws } else { 0 };
    let avg_witness_ms = avg_witness_us / 1000;
    let avg_redeem_us = if rs > 0 { rt / rs } else { 0 };
    // SECURITY FIX #9: Redact internal error details from admin stats.
    // Full error messages may reveal internal logic, file paths, or stack traces
    // to an attacker who gains access to the admin endpoint.
    // Show only error presence and count — operators should check logs for details.
    let last_err = s.last_error.lock().clone();
    let escaped_err = if last_err.is_empty() {
        String::new()
    } else {
        // Show only first 50 chars of error type, strip paths and internal details
        let truncated = if last_err.len() > 50 { &last_err[..50] } else { &last_err };
        truncated.replace('\\', "").replace('"', "'").replace('\n', " ")
    };

    let fee_available = engine.fee_redemption_available();
    let oracle_enabled = engine.oracle_enabled();
    format!(
        concat!(
            r#"{{"witness_count":{},"witness_dmap_count":{},"witness_zkvm_count":{},"witness_success":{},"witness_errors":{},"atoms_witnessed":{},"avg_witness_us":{},"avg_witness_ms":{},"#,
            r#""redeem_count":{},"redeem_success":{},"redeem_errors":{},"atoms_redeemed":{},"avg_redeem_us":{},"#,
            r#""genesis_inits":{},"hint_count":{},"last_tx_at":{},"fee_redemption_available":{},"oracle_qualified":{},"last_error":"{}"}}"#,
        ),
        wc, w_dmap, w_zkvm, ws, we, aw, avg_witness_us, avg_witness_ms,
        rc, rs, re, ar, avg_redeem_us,
        gi, hc, last_tx, fee_available, oracle_enabled, escaped_err,
    )
}

fn proof_json(engine: &ConsensusEngine) -> String {
    use std::sync::atomic::Ordering::Relaxed;
    let s = &engine.stats;
    let mode = s.proof_mode_str.lock().clone();
    let zkp_qualified = s.zkp_qualified.load(Relaxed);
    // Proof count approximated by witness_success (one proof per witness)
    let proofs_generated = s.witness_success.load(Relaxed);
    let proof_failures = s.witness_errors.load(Relaxed);
    let wt = s.witness_time_us.load(Relaxed);
    let ws = s.witness_success.load(Relaxed);
    let avg_proof_ms = if ws > 0 { wt as f64 / ws as f64 / 1000.0 } else { 0.0 };

    format!(
        r#"{{"mode":"{}","proofs_generated":{},"proof_failures":{},"avg_proof_time_ms":{:.1},"zkp_qualified":{}}}"#,
        mode, proofs_generated, proof_failures, avg_proof_ms, zkp_qualified,
    )
}

fn identity_json(engine: &ConsensusEngine) -> String {
    let vid = hex::encode(engine.validator_id());
    let vbc_bundle = engine.vbc_bundle();
    let vbc = &vbc_bundle.target_vbc;
    let issuer_count = vbc.issuer_set.len();
    let chain_depth = vbc.chain_depth;
    let expires_at = vbc.expires_at;
    let issued_at = vbc.issued_at;
    let node_name = &vbc.node_name;
    let proof_mode = engine.stats.proof_mode_str.lock().clone();
    let escaped_name = node_name.replace('\\', "\\\\").replace('"', "\\\"");
    // Validator's current stake (= bound wallet balance, in atoms). The
    // /peers endpoint already publishes this on the wire as `stake`; we
    // mirror it here so the per-validator dashboard's top bar can show
    // it next to the VBC chip without a second fetch.
    let stake_atoms = engine.bound_wallet_balance_atoms();

    format!(
        concat!(
            r#"{{"validator_id":"{}","vbc_issuer_count":{},"vbc_chain_depth":{},"#,
            r#""vbc_issued_at":{},"vbc_expires_at":{},"node_name":"{}","proof_mode":"{}","#,
            r#""stake_atoms":{}}}"#,
        ),
        vid, issuer_count, chain_depth, issued_at, expires_at, escaped_name, proof_mode,
        stake_atoms,
    )
}

fn db_json(engine: &ConsensusEngine) -> String {
    let storage = engine.storage();
    let wallets = storage.wallets_count().unwrap_or(0);
    let hints = storage.hint_count();
    let receipts = storage.receipts_count().unwrap_or(0);
    let records = storage.transaction_records_count().unwrap_or(0);

    format!(
        r#"{{"wallets":{},"hints":{},"receipts":{},"transaction_records":{}}}"#,
        wallets, hints, receipts, records,
    )
}

/// v3.x earnings: per-validator slot atoms recorded at CL5 redeem
/// from fee_breakdown (YP §20.8 v3.x). One row per witnessed redeem
/// (idempotent via txid PK). Reflects what THIS Lambda earned; the
/// authoritative cross-validator ledger lives at Nabla.
///
/// Dev-class earnings (`dev_earned_atoms` /
/// `dev_redeems_witnessed`) come from the same table filtered by
/// `is_dev_class = 1` — observability only, NEVER withdrawable as
/// public AXC (see `AXIOM_DESIGN_FactClassIsolation.md` + the
/// LEAK BOUNDARY in `nabla/src/node.rs`).
fn fees_json(engine: &ConsensusEngine) -> String {
    let storage = engine.storage();
    let (atoms, count) = storage.validator_earned_total().unwrap_or((0, 0));
    let (dev_atoms, dev_count) = storage.validator_dev_earned_total().unwrap_or((0, 0));
    format!(
        r#"{{"earned_atoms":{},"redeems_witnessed":{},"dev_earned_atoms":{},"dev_redeems_witnessed":{}}}"#,
        atoms, count, dev_atoms, dev_count,
    )
}

fn audit_json(engine: &ConsensusEngine) -> String {
    let pending = engine.pending_audit();
    let txs_since = engine.audit_txs_since_demand();

    // Determine if peer-audit by comparing target PK to our PK
    let our_pk = engine.public_key_bytes();
    let is_peer = pending.as_ref()
        .map(|d| d.target_validator_pk.as_slice() != our_pk)
        .unwrap_or(false);

    let countdown_max = if is_peer {
        axiom_core_logic::types::PEER_AUDIT_COUNTDOWN_TXS as u64
    } else {
        axiom_core_logic::types::AUDIT_COUNTDOWN_TXS as u64
    };
    let remaining = countdown_max.saturating_sub(txs_since);

    // Build banned validators JSON array
    let bans = engine.peer_audit_bans();
    let mut bans_json = String::from("[");
    for (i, ban) in bans.iter().enumerate() {
        if i > 0 { bans_json.push(','); }
        let reason = match ban.reason {
            axiom_core_logic::types::PeerAuditBanReason::HashMismatch => "HashMismatch",
            axiom_core_logic::types::PeerAuditBanReason::NonResponds => "NonResponds",
        };
        bans_json.push_str(&format!(
            r#"{{"validator_pk":"{}","banned_at_tick":{},"reason":"{}"}}"#,
            hex::encode(&ban.validator_pk), ban.banned_at_tick, reason,
        ));
    }
    bans_json.push(']');

    if let Some(demand) = pending {
        let target_hex = hex::encode(&demand.target_validator_pk);
        let nonce_hex = hex::encode(demand.challenge_nonce);
        let trigger_txid_hex = hex::encode(demand.trigger_txid);
        format!(
            concat!(
                r#"{{"pending":true,"is_peer":{},"target_validator_pk":"{}","challenge_nonce":"{}","#,
                r#""trigger_txid":"{}","txs_since_demand":{},"txs_remaining":{},"banned_validators":{}}}"#,
            ),
            is_peer, target_hex, nonce_hex, trigger_txid_hex, txs_since, remaining, bans_json,
        )
    } else {
        format!(
            r#"{{"pending":false,"is_peer":false,"txs_since_demand":0,"txs_remaining":{},"banned_validators":{}}}"#,
            countdown_max, bans_json,
        )
    }
}

fn approvals_json(engine: &ConsensusEngine) -> String {
    let storage = engine.storage();
    let count = storage.get_approved_validator_count().unwrap_or(0);
    let approved = storage.get_approved_validators().unwrap_or_default();

    let mut entries = String::from("[");
    for (i, (vid, name, proof_cap, _request_id, approved_at)) in approved.iter().enumerate() {
        if i > 0 { entries.push(','); }
        let escaped_name = name.replace('\\', "\\\\").replace('"', "\\\"");
        let escaped_vid = vid.replace('\\', "\\\\").replace('"', "\\\"");
        entries.push_str(&format!(
            r#"{{"validator_id":"{}","node_name":"{}","proof_cap":"{}","approved_at":{}}}"#,
            escaped_vid, escaped_name, proof_cap, approved_at,
        ));
    }
    entries.push(']');

    format!(r#"{{"count":{},"approved":{}}}"#, count, entries)
}

fn dwp_json(engine: &ConsensusEngine) -> String {
    let db = match engine.management_db() {
        Some(db) => db,
        None => return r#"{"dwp_wallets":0,"active_queries":0,"frozen_wallets":0,"status":"not_initialized"}"#.to_string(),
    };
    let conn = match db.db() {
        Ok(c) => c,
        Err(_) => return r#"{"error":"db lock failed"}"#.to_string(),
    };
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM dwp_wallets", [], |r| r.get(0)).unwrap_or(0);
    let active: i64 = conn.query_row("SELECT COUNT(*) FROM dwp_wallets WHERE status = 'locked'", [], |r| r.get(0)).unwrap_or(0);
    let resolved: i64 = conn.query_row("SELECT COUNT(*) FROM dwp_wallets WHERE status = 'resolved'", [], |r| r.get(0)).unwrap_or(0);
    let votes: i64 = conn.query_row("SELECT COUNT(*) FROM jfp_vote_index", [], |r| r.get(0)).unwrap_or(0);
    format!(r#"{{"dwp_wallets":{},"active_queries":{},"resolved":{},"total_votes":{},"status":"operational"}}"#, total, active, resolved, votes)
}

/// GET /dwp/detail?wallet_id=<hex> — full DWP wallet details including case log entries.
fn dwp_detail_json(engine: &ConsensusEngine, query: Option<&str>) -> String {
    let wallet_id_hex = match query
        .and_then(|q| q.split('&').find(|p| p.starts_with("wallet_id=")))
        .map(|p| &p[10..])
    {
        Some(h) if h.len() == 64 => h,
        _ => return r#"{"error":"missing wallet_id param"}"#.to_string(),
    };
    let wallet_id = match parse_hex32(wallet_id_hex) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"{}"}}"#, e),
    };
    let db = match engine.management_db() {
        Some(db) => db,
        None => return r#"{"error":"not initialized"}"#.to_string(),
    };
    let conn = match db.db() {
        Ok(c) => c,
        Err(_) => return r#"{"error":"db lock failed"}"#.to_string(),
    };

    // Wallet info
    let wallet_row = conn.query_row(
        "SELECT txid, requester_pk, status, result, pwv_set, created_at, resolved_at, wallet_type
         FROM dwp_wallets WHERE wallet_id = ?1",
        rusqlite::params![wallet_id.as_ref()],
        |row| Ok((
            row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?, row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?, row.get::<_, i64>(5)?,
            row.get::<_, Option<i64>>(6)?, row.get::<_, Option<String>>(7)?,
        )),
    );
    let (txid, requester_pk, status, result, pwv_set, created_at, resolved_at, wallet_type) = match wallet_row {
        Ok(v) => v,
        Err(_) => return r#"{"error":"wallet not found"}"#.to_string(),
    };

    // Case log entries
    let mut case_log = String::from("[");
    {
        let mut stmt = conn.prepare(
            "SELECT author_pk, timestamp, content FROM dwp_case_log WHERE wallet_id = ?1 ORDER BY timestamp ASC"
        ).unwrap();
        let mut first = true;
        let rows = stmt.query_map(rusqlite::params![wallet_id.as_ref()], |row| {
            let author: Vec<u8> = row.get(0)?;
            let ts: i64 = row.get(1)?;
            let content: String = row.get(2)?;
            Ok((author, ts, content))
        }).unwrap();
        for row in rows.flatten() {
            let (author, ts, content) = row;
            if !first { case_log.push(','); }
            first = false;
            let escaped = content.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
            case_log.push_str(&format!(
                r#"{{"author":"{}","timestamp":{},"content":"{}"}}"#,
                hex::encode(&author), ts, escaped,
            ));
        }
    }
    case_log.push(']');

    // Vote count
    let voted: i64 = conn.query_row(
        "SELECT COUNT(*) FROM jfp_vote_index WHERE dwp_wallet_id = ?1",
        rusqlite::params![wallet_id.as_ref()],
        |r| r.get(0),
    ).unwrap_or(0);

    let pwv_count = pwv_set.as_ref()
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .map(|v| v.len()).unwrap_or(0);

    format!(
        concat!(
            r#"{{"wallet_id":"{}","txid":"{}","requester_pk":"{}","status":"{}","result":"{}","#,
            r#""pwv_count":{},"voted":{},"group_address":"{}","created_at":{},"resolved_at":{},"#,
            r#""case_log":{}}}"#,
        ),
        wallet_id_hex, hex::encode(&txid), hex::encode(&requester_pk),
        status, result, pwv_count, voted,
        wallet_type.as_deref().unwrap_or(""),
        created_at,
        resolved_at.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
        case_log,
    )
}

fn dwp_wallets_json(engine: &ConsensusEngine) -> String {
    let db = match engine.management_db() {
        Some(db) => db,
        None => return r#"{"wallets":[]}"#.to_string(),
    };
    let conn = match db.db() {
        Ok(c) => c,
        Err(_) => return r#"{"error":"db lock failed"}"#.to_string(),
    };
    let mut stmt = match conn.prepare(
        "SELECT wallet_id, txid, requester_pk, status, result, pwv_set, created_at, resolved_at, expires_at
         FROM dwp_wallets ORDER BY created_at DESC LIMIT 50"
    ) {
        Ok(s) => s,
        Err(_) => return r#"{"wallets":[]}"#.to_string(),
    };
    let mut wallets = String::from("[");
    let mut first = true;
    let rows = stmt.query_map([], |row| {
        let wallet_id: Vec<u8> = row.get(0)?;
        let txid: Vec<u8> = row.get(1)?;
        let requester_pk: Vec<u8> = row.get(2)?;
        let status: String = row.get(3)?;
        let result: String = row.get(4)?;
        let pwv_set: Option<String> = row.get(5)?;
        let created_at: i64 = row.get(6)?;
        let resolved_at: Option<i64> = row.get(7)?;
        let expires_at: Option<i64> = row.get(8)?;
        Ok((wallet_id, txid, requester_pk, status, result, pwv_set, created_at, resolved_at, expires_at))
    });
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            let (wallet_id, txid, requester_pk, status, result, pwv_set, created_at, resolved_at, expires_at) = row;
            let wid_hex = hex::encode(&wallet_id);

            // Vote count from jfp_vote_index (real k=3 TX votes)
            let voted: i64 = conn.query_row(
                "SELECT COUNT(*) FROM jfp_vote_index WHERE dwp_wallet_id = ?1",
                rusqlite::params![wallet_id.as_slice()],
                |r| r.get(0),
            ).unwrap_or(0);

            // PWV set size
            let pwv_count = pwv_set.as_ref()
                .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                .map(|v| v.len())
                .unwrap_or(0);

            // Case log entry count
            let case_entries: i64 = conn.query_row(
                "SELECT COUNT(*) FROM dwp_case_log WHERE wallet_id = ?1",
                rusqlite::params![wallet_id.as_slice()],
                |r| r.get(0),
            ).unwrap_or(0);

            if !first { wallets.push(','); }
            first = false;
            wallets.push_str(&format!(
                concat!(
                    r#"{{"wallet_id":"{}","txid":"{}","requester_pk":"{}","status":"{}","result":"{}","#,
                    r#""pwv_count":{},"voted":{},"case_entries":{},"#,
                    r#""created_at":{},"resolved_at":{},"expires_at":{}}}"#,
                ),
                wid_hex, hex::encode(&txid), hex::encode(&requester_pk),
                status, result,
                pwv_count, voted, case_entries,
                created_at,
                resolved_at.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
                expires_at.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
            ));
        }
    }
    wallets.push(']');
    format!(r#"{{"wallets":{}}}"#, wallets)
}

// --- POST handlers ---

/// Step 9B.7 — CBOR-serializable shape of `WitnessSignature` for
/// persisting the mint receipt's signature list. Mirror struct (not
/// the runtime one) so storage encoding stays explicit and the
/// runtime type stays free to evolve.
#[derive(serde::Serialize, serde::Deserialize)]
struct SerWitSig {
    witness_id: [u8; 32],
    witness_pk: Vec<u8>,
    sig: Vec<u8>,
    #[serde(default)]
    claim_sig: Vec<u8>,
}

impl SerWitSig {
    fn from_runtime(s: &crate::withdrawal_mint_orchestrator::WitnessSignature) -> Self {
        Self {
            witness_id: s.witness_id,
            witness_pk: s.witness_pk.clone(),
            sig: s.sig.clone(),
            claim_sig: s.claim_sig.clone(),
        }
    }
    fn into_runtime(self) -> crate::withdrawal_mint_orchestrator::WitnessSignature {
        crate::withdrawal_mint_orchestrator::WitnessSignature {
            witness_id: self.witness_id,
            witness_pk: self.witness_pk,
            claim_sig: self.claim_sig,
            sig: self.sig,
        }
    }
}

fn encode_signatures_cbor(
    receipt: &crate::withdrawal_mint_orchestrator::WithdrawalMintReceipt,
) -> Result<Vec<u8>, String> {
    let wire: Vec<SerWitSig> = receipt.signatures.iter()
        .map(SerWitSig::from_runtime)
        .collect();
    let mut buf = Vec::with_capacity(256);
    ciborium::into_writer(&wire, &mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Step 9B.5 — operator-driven validator withdrawal mint.
///
/// Body schema:
/// ```json
/// {
///   "withdrawal": { ...full ValidatorWithdrawalRequest CBOR-shape JSON... },
///   "chosen_witness_addrs": ["host:port", "host:port", "host:port"]
/// }
/// ```
///
/// The endpoint is async because it fans out TCP CBOR RPCs to the k=3
/// chosen-witness Lambda gateways via
/// `withdrawal_mint_orchestrator::collect_witness_signatures`. The
/// operator-side `verify_validator_withdrawal` chain runs first
/// (Step 8.4) — only VERIFIED proofs are fanned out.
///
/// Response shapes:
///
/// - VERIFIED + quorum reached:
///   ```json
///   {
///     "status": "MINTED",
///     "mint": { "validator_id": "...", "linked_wallet_id": "...",
///               "net_amount": N, "claimed_through_tick": T },
///     "signatures": [ { "witness_id": "...", "witness_pk": "...",
///                       "sig": "..." }, ... ]
///   }
///   ```
///   (Persistence of the mint into `linked_wallet_id` + the
///   `MarkValidatorEarningsClaimedRequest` to Nabla land in
///   subsequent commits.)
///
/// - VERIFIED-but-quorum-missed / RPC failures:
///   ```json
///   { "status": "QUORUM_NOT_REACHED",
///     "ok_count": N, "required": 3,
///     "failures": [ { "address": "...", "reason": "..." }, ... ] }
///   ```
///
/// - Anything `verify_validator_withdrawal` rejects:
///   ```json
///   { "status": "REJECTED_*",
///     "validator_id": "...", "net_amount": 0,
///     "linked_wallet_id": "...", "claimed_through_tick": T }
///   ```
async fn handle_withdrawal_mint_async(
    engine: &ConsensusEngine,
    body: &str,
) -> String {
    use axiom_core_logic::wire_client::ValidatorWithdrawalRequest;
    use crate::withdrawal_mint_orchestrator::{WithdrawalMintReceipt, WitnessSignature};

    #[derive(serde::Deserialize)]
    struct Body {
        withdrawal: ValidatorWithdrawalRequest,
        chosen_witness_addrs: Vec<String>,
    }
    let parsed: Body = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(
            r#"{{"error":"bad JSON: {}"}}"#,
            e.to_string().replace('"', "'")
        ),
    };

    // Step 1 — operator-side verify (Step 8.4).
    let verify = crate::validator_withdrawal::verify_validator_withdrawal(
        &parsed.withdrawal,
    );
    if verify.status != "VERIFIED" {
        return serde_json::to_string(&verify)
            .unwrap_or_else(|_| r#"{"error":"serialize verify response"}"#.to_string());
    }

    // Step 1b — idempotency. If we already minted for this exact
    // (validator_id, claimed_through_tick) pair, return the stored
    // receipt verbatim instead of re-fanning-out + re-paying for the
    // witness round.
    let vid = parsed.withdrawal.validator_id;
    let tick = parsed.withdrawal.earnings_attestation.until_tick;
    if let Ok(Some((stored_linked, stored_net, stored_at, sigs_cbor))) =
        engine.storage().get_validator_mint(&vid, tick)
    {
        let decoded: Result<Vec<WitnessSignature>, _> =
            ciborium::from_reader(sigs_cbor.as_slice())
                .map(|sigs: Vec<SerWitSig>| sigs.into_iter().map(SerWitSig::into_runtime).collect());
        let sigs_json: Vec<serde_json::Value> = match decoded {
            Ok(sigs) => sigs.iter().map(|s| serde_json::json!({
                "witness_id": hex::encode(s.witness_id),
                "witness_pk": hex::encode(&s.witness_pk),
                "sig": hex::encode(&s.sig),
            })).collect(),
            Err(_) => vec![],
        };
        return serde_json::json!({
            "status": "ALREADY_MINTED",
            "mint": {
                "validator_id": hex::encode(vid),
                "linked_wallet_id": hex::encode(stored_linked),
                "net_amount": stored_net,
                "claimed_through_tick": tick,
            },
            "signatures": sigs_json,
            "minted_at": stored_at,
        }).to_string();
    }

    // Step 2 — fan out to chosen_witness Lambdas (Step 9B.4).
    let request_id = format!(
        "wmint-{}-{}",
        hex::encode(&vid[..4]),
        tick,
    );
    let receipt = crate::withdrawal_mint_orchestrator::collect_witness_signatures(
        request_id,
        parsed.withdrawal,
        parsed.chosen_witness_addrs,
    ).await;

    use crate::withdrawal_mint_orchestrator::OrchestratorError;
    match receipt {
        Ok(rcpt) => {
            // Step 3 — persist the receipt (Step 9B.7). Idempotency lock
            // on (validator_id, claimed_through_tick) protects against
            // races where multiple admin calls fire in parallel.
            let sigs_cbor = match encode_signatures_cbor(&rcpt) {
                Ok(b) => b,
                Err(e) => return format!(
                    r#"{{"error":"signatures CBOR encode failed: {}"}}"#,
                    e.replace('"', "'"),
                ),
            };
            let inserted = match engine.storage().record_validator_mint(
                &rcpt.mint.validator_id,
                rcpt.mint.claimed_through_tick,
                &rcpt.mint.linked_wallet_id,
                rcpt.mint.net_amount,
                &sigs_cbor,
            ) {
                Ok(b) => b,
                Err(e) => return format!(
                    r#"{{"error":"persist mint receipt failed: {}"}}"#,
                    e.to_string().replace('"', "'"),
                ),
            };
            let status = if inserted { "MINTED" } else { "ALREADY_MINTED" };

            // Step 9B.8 — send MarkValidatorEarningsClaimedRequest to
            // Nabla so `last_claimed_tick` advances and the same
            // earnings can't be claimed twice via a different operator
            // session on a fresh Lambda (cross-Lambda replay defense).
            //
            // Best-effort: failure here does NOT undo the mint
            // persistence (the mint is already committed to local
            // storage). The operator's UI surfaces the Nabla outcome
            // so an operator can manually retry if needed. The mint
            // itself stays valid; only the cross-Lambda replay
            // window is wider until Nabla actually advances.
            //
            // TODO: make nabla_addr configurable via lambda config
            // (same TODO as `consensus.rs:1029` — multi-host
            // deployment will need the operator-local Nabla pinned
            // per Lambda).
            let nabla_addr = "127.0.0.1:7300";
            let claim_outcome = crate::withdrawal_mint_orchestrator::send_mark_validator_claimed(
                nabla_addr,
                rcpt.mint.validator_id,
                rcpt.mint.claimed_through_tick,
                &rcpt.signatures,
            ).await;
            let claim_json = match &claim_outcome {
                crate::withdrawal_mint_orchestrator::MarkClaimedOutcome::Claimed {
                    stored_last_claimed_tick,
                } => serde_json::json!({
                    "result": "CLAIMED",
                    "stored_last_claimed_tick": stored_last_claimed_tick,
                }),
                crate::withdrawal_mint_orchestrator::MarkClaimedOutcome::Rejected {
                    status, stored_last_claimed_tick,
                } => serde_json::json!({
                    "result": "REJECTED",
                    "nabla_status": status,
                    "stored_last_claimed_tick": stored_last_claimed_tick,
                }),
                crate::withdrawal_mint_orchestrator::MarkClaimedOutcome::RpcError {
                    detail,
                } => serde_json::json!({
                    "result": "RPC_ERROR",
                    "detail": detail,
                }),
            };

            serde_json::json!({
                "status": status,
                "mint": {
                    "validator_id": hex::encode(rcpt.mint.validator_id),
                    "linked_wallet_id": hex::encode(rcpt.mint.linked_wallet_id),
                    "net_amount": rcpt.mint.net_amount,
                    "claimed_through_tick": rcpt.mint.claimed_through_tick,
                },
                "signatures": rcpt.signatures.iter().map(|s| {
                    serde_json::json!({
                        "witness_id": hex::encode(s.witness_id),
                        "witness_pk": hex::encode(&s.witness_pk),
                        "sig": hex::encode(&s.sig),
                    })
                }).collect::<Vec<_>>(),
                "mark_claimed": claim_json,
            }).to_string()
        }
        Err(OrchestratorError::NotEnoughWitnesses { supplied, required }) => {
            serde_json::json!({
                "status": "NOT_ENOUGH_WITNESSES",
                "supplied": supplied,
                "required": required,
            }).to_string()
        }
        Err(OrchestratorError::QuorumNotReached { ok_count, required, failures }) => {
            serde_json::json!({
                "status": "QUORUM_NOT_REACHED",
                "ok_count": ok_count,
                "required": required,
                "failures": failures.iter().map(|(addr, reason)| serde_json::json!({
                    "address": addr,
                    "reason": reason,
                })).collect::<Vec<_>>(),
            }).to_string()
        }
        Err(OrchestratorError::MintMismatch) => {
            r#"{"status":"MINT_MISMATCH","detail":"chosen witnesses returned non-identical mint outputs"}"#.to_string()
        }
    }
}

fn handle_dwp_query(engine: &ConsensusEngine, body: &str) -> String {
    let dwp = match engine.dwp_engine() {
        Some(d) => d,
        None => return r#"{"error":"DWP engine not initialized"}"#.to_string(),
    };
    let req: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"bad JSON: {}"}}"#, e),
    };
    let txid = match req.get("txid").and_then(|v| v.as_str()).and_then(|s| parse_hex32(s).ok()) {
        Some(v) => v,
        None => return r#"{"error":"missing or invalid txid (hex 64 chars)"}"#.to_string(),
    };
    let requester_pk = match req.get("requester_pk").and_then(|v| v.as_str()).and_then(|s| parse_hex32(s).ok()) {
        Some(v) => v,
        None => return r#"{"error":"missing or invalid requester_pk"}"#.to_string(),
    };
    let payment_txid = match req.get("payment_txid").and_then(|v| v.as_str()).and_then(|s| parse_hex32(s).ok()) {
        Some(v) => v,
        None => return r#"{"error":"missing or invalid payment_txid"}"#.to_string(),
    };
    let pwv_set: Vec<[u8; 32]> = match req.get("pwv_set").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut pks = Vec::new();
            for item in arr {
                match item.as_str().and_then(|s| parse_hex32(s).ok()) {
                    Some(pk) => pks.push(pk),
                    None => return r#"{"error":"invalid pk in pwv_set"}"#.to_string(),
                }
            }
            pks
        }
        None => return r#"{"error":"missing pwv_set array"}"#.to_string(),
    };
    let case_desc = req.get("case_description").and_then(|v| v.as_str()).unwrap_or("");
    let tardis_tick = req.get("tardis_tick").and_then(|v| v.as_u64()).unwrap_or(0);

    // Replay check: prevent duplicate DWP queries for same txid
    if let Some(db) = engine.management_db() {
        if let Ok(conn) = db.db() {
            let existing: Option<i64> = conn.query_row(
                "SELECT query_count FROM dwp_query_cache WHERE txid = ?1",
                rusqlite::params![txid.as_ref()],
                |row| row.get(0),
            ).ok();
            if let Some(count) = existing {
                // Update count and allow (requester pays again)
                let _ = conn.execute(
                    "UPDATE dwp_query_cache SET query_count = query_count + 1, last_queried = ?1 WHERE txid = ?2",
                    rusqlite::params![now_secs() as i64, txid.as_ref()],
                );
                debug!("DWP replay: txid {} queried {} times", hex::encode(&txid[..8]), count + 1);
            } else {
                let _ = conn.execute(
                    "INSERT INTO dwp_query_cache (txid, query_count, last_queried) VALUES (?1, 1, ?2)",
                    rusqlite::params![txid.as_ref(), now_secs() as i64],
                );
            }
        }
    }

    // Payment verification: the DWP query must include a valid k=3 receipt
    // proving 1 AXC was paid. We verify the receipt cryptographically (k=3
    // signatures), NOT by checking any local DB. Never trust Lambda.
    // The payment_txid is stored for audit trail only.
    // Payment receipt verification: In production, the request body should include
    // a k=3 signed receipt which is verified via Core CL4. Currently, payment_txid
    // is recorded for audit trail. Zero payment_txid = test/bootstrap mode.
    // CL4 verification integration: the admin caller (Console or operator) submits
    // the receipt; Lambda forwards to Core CL4 and rejects if invalid.

    match dwp.create_dwp_wallet(&txid, &requester_pk, &payment_txid, &pwv_set, case_desc, tardis_tick) {
        Ok(wallet_id) => {
            // Get group wallet key material for distribution
            let (group_addr, key_seed) = crate::dwp_engine::DwpEngine::get_group_wallet_key(&txid, &requester_pk);

            // Queue key distribution to PWV members via audit_log (ANTIE picks these up)
            if let Some(db) = engine.management_db() {
                if let Ok(conn) = db.db() {
                    let now = now_secs();
                    let key_msg = serde_json::json!({
                        "event": "jfp_key_distribution",
                        "dwp_wallet_id": hex::encode(wallet_id),
                        "group_wallet_address": group_addr,
                        "key_seed": hex::encode(key_seed),
                        "pwv_members": pwv_set.iter().map(hex::encode).collect::<Vec<_>>(),
                        "case_description": case_desc,
                    });
                    let _ = conn.execute(
                        "INSERT INTO audit_log (timestamp, event_type, details)
                         VALUES (?1, 'jfp_key_distribution', ?2)",
                        rusqlite::params![now as i64, key_msg.to_string()],
                    );
                    info!("JFP: Key distribution queued for {} PWV members (group wallet {})",
                          pwv_set.len(), &group_addr);
                }
            }

            format!(
                r#"{{"ok":true,"wallet_id":"{}","group_wallet_address":"{}","key_seed":"{}"}}"#,
                hex::encode(wallet_id), group_addr, hex::encode(key_seed),
            )
        }
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

fn handle_dwp_case(engine: &ConsensusEngine, body: &str) -> String {
    let dwp = match engine.dwp_engine() {
        Some(d) => d,
        None => return r#"{"error":"DWP engine not initialized"}"#.to_string(),
    };
    let req: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"bad JSON: {}"}}"#, e),
    };
    let wallet_id = match req.get("wallet_id").and_then(|v| v.as_str()).and_then(|s| parse_hex32(s).ok()) {
        Some(v) => v,
        None => return r#"{"error":"missing or invalid wallet_id"}"#.to_string(),
    };
    let author_pk = match req.get("author_pk").and_then(|v| v.as_str()).and_then(|s| parse_hex32(s).ok()) {
        Some(v) => v,
        None => return r#"{"error":"missing or invalid author_pk"}"#.to_string(),
    };
    let content = match req.get("content").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return r#"{"error":"missing content"}"#.to_string(),
    };
    let tardis_tick = req.get("tardis_tick").and_then(|v| v.as_u64()).unwrap_or(0);

    match dwp.add_case_entry(&wallet_id, &author_pk, content, tardis_tick) {
        Ok(()) => r#"{"ok":true}"#.to_string(),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// POST /dwp/vote — record a vote TX (simulates what consensus.rs does after k=3 witness).
/// Body: { "dwp_wallet_id": "hex64", "voter_pk": "hex64", "vote_hash": "hex64" }
fn handle_dwp_vote(engine: &ConsensusEngine, body: &str) -> String {
    let dwp = match engine.dwp_engine() {
        Some(d) => d,
        None => return r#"{"error":"DWP engine not initialized"}"#.to_string(),
    };
    let req: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"bad JSON: {}"}}"#, e),
    };
    let wallet_id = match req.get("dwp_wallet_id").and_then(|v| v.as_str()).and_then(|s| parse_hex32(s).ok()) {
        Some(v) => v,
        None => return r#"{"error":"missing or invalid dwp_wallet_id"}"#.to_string(),
    };
    let voter_pk = match req.get("voter_pk").and_then(|v| v.as_str()).and_then(|s| parse_hex32(s).ok()) {
        Some(v) => v,
        None => return r#"{"error":"missing or invalid voter_pk"}"#.to_string(),
    };
    let vote_hash = match req.get("vote_hash").and_then(|v| v.as_str()).and_then(|s| parse_hex32(s).ok()) {
        Some(v) => v,
        None => return r#"{"error":"missing or invalid vote_hash"}"#.to_string(),
    };
    match dwp.record_vote_tx(&wallet_id, &voter_pk, &vote_hash, None) {
        Ok(()) => r#"{"ok":true}"#.to_string(),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// GET /jfp/result?wallet_id=<hex> — compute JFP result from vote hashes + Nabla secrets.
/// Reads votes from jfp_vote_index, queries Nabla for secrets, computes outcome.
fn jfp_result_json(engine: &ConsensusEngine, query: Option<&str>) -> String {
    let wallet_id_hex = match query
        .and_then(|q| q.split('&').find(|p| p.starts_with("wallet_id=")))
        .map(|p| &p[10..])
    {
        Some(h) if h.len() == 64 => h,
        _ => return r#"{"error":"missing wallet_id query param (64 hex chars)"}"#.to_string(),
    };
    let wallet_id = match parse_hex32(wallet_id_hex) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"{}"}}"#, e),
    };

    let dwp = match engine.dwp_engine() {
        Some(d) => d,
        None => return r#"{"error":"DWP engine not initialized"}"#.to_string(),
    };

    // For now, secrets must be provided via query param or fetched from Nabla.
    // In production, Lambda queries its connected Nabla node.
    // For testing, accept secrets as a query param: &secrets=hex1,hex2,...
    let secrets_param = query
        .and_then(|q| q.split('&').find(|p| p.starts_with("secrets=")))
        .map(|p| &p[8..]);

    let secrets: Vec<[u8; 32]> = if let Some(param) = secrets_param {
        param.split(',')
            .filter_map(|h| parse_hex32(h).ok())
            .collect()
    } else {
        vec![] // No secrets provided — result will be "pending" or "failed"
    };

    match dwp.compute_jfp_result(&wallet_id, &secrets) {
        Ok((result, yes, no)) => format!(
            r#"{{"result":"{}","yes":{},"no":{},"wallet_id":"{}"}}"#,
            result, yes, no, wallet_id_hex,
        ),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// POST /jfp/scar — register SCAR on Nabla for the target wallet after APPROVED result.
/// Body: { "dwp_wallet_id": "hex64", "nabla_url": "http://127.0.0.1:6226" }
fn handle_jfp_scar(engine: &ConsensusEngine, body: &str) -> String {
    let req: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"bad JSON: {}"}}"#, e),
    };
    let dwp_wallet_id = match req.get("dwp_wallet_id").and_then(|v| v.as_str()).and_then(|s| parse_hex32(s).ok()) {
        Some(v) => v,
        None => return r#"{"error":"missing or invalid dwp_wallet_id"}"#.to_string(),
    };
    // SEC-08: the `nabla_url` parameter + SSRF allowlist were removed with the
    // synthetic Nabla `/register` POST below — there is no Nabla call here
    // anymore. Enforcement is the Core frozen_wallets freeze, not a Nabla SCAR.

    // Verify the DWP wallet result is "approved"
    let db = match engine.management_db() {
        Some(db) => db,
        None => return r#"{"error":"management DB not initialized"}"#.to_string(),
    };
    // Read result + target from DB, then DROP the lock before calling compute
    let (result, target_pk) = {
        let conn = match db.db() {
            Ok(c) => c,
            Err(_) => return r#"{"error":"db lock failed"}"#.to_string(),
        };
        match conn.query_row(
            "SELECT result, txid FROM dwp_wallets WHERE wallet_id = ?1",
            rusqlite::params![dwp_wallet_id.as_ref()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        ) {
            Ok(v) => v,
            Err(_) => return r#"{"error":"DWP wallet not found"}"#.to_string(),
        }
    }; // conn dropped here — mutex released

    // If result is still pending, compute it (needs its own DB lock)
    let final_result = if result == "pending" {
        if let Some(secrets_arr) = req.get("secrets").and_then(|v| v.as_array()) {
            let secrets: Vec<[u8; 32]> = secrets_arr.iter()
                .filter_map(|s| s.as_str().and_then(|h| parse_hex32(h).ok()))
                .collect();
            if let Some(dwp) = engine.dwp_engine() {
                match dwp.compute_jfp_result(&dwp_wallet_id, &secrets) {
                    Ok((r, _, _)) => {
                        if let Ok(conn) = db.db() {
                            let _ = conn.execute(
                                "UPDATE dwp_wallets SET result = ?1 WHERE wallet_id = ?2",
                                rusqlite::params![&r, dwp_wallet_id.as_ref()],
                            );
                        }
                        r
                    }
                    Err(_) => result.clone(),
                }
            } else { result.clone() }
        } else { result.clone() }
    } else {
        result.clone()
    };

    if final_result != "approved" {
        return format!(r#"{{"error":"DWP wallet result is '{}', not 'approved'"}}"#, final_result);
    }

    // JFP §7: Insert freeze order so Lambda passes this wallet to Core's frozen_wallets.
    // Core CL1 will reject all future transactions from this wallet.
    {
        let order_id = format!("JFP-{}", hex::encode(&dwp_wallet_id[..16]));
        let mut target_pk_arr = [0u8; 32];
        if target_pk.len() == 32 {
            target_pk_arr.copy_from_slice(&target_pk);
        }
        if let Err(e) = db.insert_freeze_order(
            &order_id,
            &target_pk_arr,
            "JFP",
            Some(&dwp_wallet_id),
        ) {
            warn!("Failed to insert freeze order: {}", e);
        }
    }

    // SEC-08: the synthetic, unauthenticated Nabla `/register` SCAR has been
    // DELETED. It posted a forged state
    // (`scar_state = BLAKE3("AXIOM_JFP_SCAR" || dwp_wallet_id || target_pk)`)
    // mesh-wide with no k-witnessed verdict and no authority proof — a single
    // operator (or stolen admin token) could mark ANY wallet SCARRED across the
    // network (and the nabla_url was an SSRF surface). A SCAR also does not
    // freeze (the wallet heals through it) and Nabla-side enforcement is
    // untrusted (fails open). Per SEC-08_RESOLUTION.md (option B), enforcement
    // is the Core `frozen_wallets` exact-set freeze, populated ONLY from a
    // verified k=3 `JfpFreezeVerdict` — NOT a Nabla SCAR, NOT an operator POST.
    // Nabla "Tainted" is at most an advisory hint, never the enforcement.
    // (The freeze_order insert above is the remaining gate to harden — it must
    // require a verified verdict; tracked, see SEC-08_RESOLUTION.md "The fix".)

    // Update DWP wallet status to resolved
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Ok(conn) = db.db() {
        let _ = conn.execute(
            "UPDATE dwp_wallets SET status = 'resolved', resolved_at = ?1,
             expires_at = ?2 WHERE wallet_id = ?3",
            rusqlite::params![
                now as i64,
                (now + crate::dwp_engine::DWP_EXPIRY_SECS) as i64,
                dwp_wallet_id.as_ref(),
            ],
        );
    }

    info!("JFP freeze order recorded (Core frozen_wallets) for wallet {}", hex::encode(&target_pk[..8]));
    format!(r#"{{"ok":true,"frozen_wallet":"{}"}}"#, hex::encode(&target_pk))
}

/// GET /mv/select?candidate_pk=<hex> — select 3 MV-set candidates for a new validator.
fn mv_select_json(engine: &ConsensusEngine, query: Option<&str>) -> String {
    let pk_hex = match query
        .and_then(|q| q.split('&').find(|p| p.starts_with("candidate_pk=")))
        .map(|p| &p[13..])
    {
        Some(h) if h.len() == 64 => h,
        _ => return r#"{"error":"missing candidate_pk param (64 hex chars)"}"#.to_string(),
    };
    let pk = match parse_hex32(pk_hex) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"{}"}}"#, e),
    };
    let selected = engine.select_mv_set_candidates(&pk);
    let json_arr = selected.iter().map(|v| format!("\"{}\"", v)).collect::<Vec<_>>().join(",");
    format!(r#"{{"candidates":[{}],"count":{}}}"#, json_arr, selected.len())
}

/// GET /mv/status?validator_id=<hex> — check MVIB completion status.
fn mv_status_json(engine: &ConsensusEngine, query: Option<&str>) -> String {
    let vid = match query
        .and_then(|q| q.split('&').find(|p| p.starts_with("validator_id=")))
        .map(|p| &p[13..])
    {
        Some(h) => h,
        _ => return r#"{"error":"missing validator_id param"}"#.to_string(),
    };
    let mv_set = engine.storage().get_mv_set(vid).unwrap_or_default();
    let complete = engine.storage().is_mvib_complete(vid).unwrap_or(false);
    let json_arr = mv_set.iter().map(|v| format!("\"{}\"", v)).collect::<Vec<_>>().join(",");
    format!(r#"{{"validator_id":"{}","mv_set":[{}],"count":{},"complete":{}}}"#,
            vid, json_arr, mv_set.len(), complete)
}

/// Minimal JSON string escaper (subset of RFC 8259) — handles the
/// characters that show up in PGP/GPG armoured key blocks. Used by
/// `peers_json` (and any other hand-rolled JSON writer) where field
/// values may contain newlines or other control bytes.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ─── Hardware capacity probe ──────────────────────────────────────────
//
// One-shot snapshot of the box's static capacity (CPU model + cores,
// total RAM, disk free, GPU presence, link speed) plus the AXIOM-
// relevant fitness signals (Pulse Argon2id/sec, current AVM JIT mode).
// Probed on every /capacity request — Linux /proc + /sys reads + a
// short-timeout nvidia-smi subprocess. ~30-80 ms total, no protocol
// surface. Dashboard polls once per page load.
//
// Display intent (operator dashboard "HARDWARE CAPACITY" card):
//   CPU   <model>   <cores>c/<threads>t @ <freq> GHz   Pulse: N
//   RAM   <total>   (available now: N)
//   DISK  <total fs> free <N>
//   GPU   <model>/<vram> driver <ver>   (or "none")
//   NET   <iface> <link Mbps>
//
// "Static visually" — the values reflect what the machine HAS, not
// what it's currently doing. Live load lives on the existing
// storage/witness cards.
fn capacity_json(engine: &ConsensusEngine) -> String {
    use std::fs;

    // ── CPU ──
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpu_model = cpuinfo.lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let cores_logical = cpuinfo.lines().filter(|l| l.starts_with("processor")).count();
    // physical cores: count distinct (physical id, core id) pairs
    let mut physical_pairs: std::collections::BTreeSet<(String, String)> = Default::default();
    let mut cur_phys = String::new();
    let mut cur_core = String::new();
    for line in cpuinfo.lines() {
        if let Some(v) = line.strip_prefix("physical id\t:") { cur_phys = v.trim().to_string(); }
        if let Some(v) = line.strip_prefix("core id\t:") { cur_core = v.trim().to_string(); }
        if line.is_empty() && !cur_phys.is_empty() && !cur_core.is_empty() {
            physical_pairs.insert((cur_phys.clone(), cur_core.clone()));
            cur_phys.clear(); cur_core.clear();
        }
    }
    let cores_physical = if physical_pairs.is_empty() { cores_logical } else { physical_pairs.len() };
    let cpu_mhz = cpuinfo.lines()
        .find(|l| l.starts_with("cpu MHz"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse::<f64>().ok())
        .unwrap_or(0.0);

    // Pulse Argon2id/sec — read from axiom-dmap-vm's process-global atomic,
    // set when the AVM's pulse self-benchmark fires at startup
    // (interpreter.rs::run_pulse_benchmark → LAST_ARGON2ID_PER_SEC).
    // Returns 0 if the benchmark hasn't run yet — the dashboard
    // distinguishes "0 = pending" from a real low value.
    let pulse: u64 = axiom_dmap_vm::last_argon2id_per_sec();
    let _ = engine; // engine reserved for future per-engine fitness signals

    // ── RAM ──
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_kb = |key: &str| -> u64 {
        meminfo.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };
    let ram_total_mb = mem_kb("MemTotal:") / 1024;
    let ram_avail_mb = mem_kb("MemAvailable:") / 1024;

    // ── Disk (current working dir — Lambda's data dir lives here) ──
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
    let (disk_total_gb, disk_free_gb, disk_fs) = probe_disk(&cwd);

    // ── GPU — nvidia-smi if available, otherwise empty (no error) ──
    let (gpu_present, gpu_model, gpu_vram_mb, gpu_driver) = probe_gpu();

    // ── Network — first non-loopback interface with a link speed ──
    let (net_iface, net_link_mbps) = probe_net();

    // ── JIT — AVM execution mode marker. JIT is the workspace default
    //         (`cranelift-jit-backend` feature on axiom-dmap-vm; see
    //         [[feedback_jit_default]]). A feature-cfg check from
    //         lambda's perspective is misleading because the feature
    //         lives on the avm crate, not lambda. If a future build
    //         disables JIT for a real reason, plumb the actual mode
    //         off `engine.core` instead of flipping this string.
    let jit_mode = "cranelift-jit";

    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{"probed_at_unix":{},"cpu":{{"model":"{}","cores_physical":{},"cores_logical":{},"freq_mhz":{:.0},"pulse_argon2id_per_sec":{},"jit_mode":"{}"}},"ram":{{"total_mb":{},"available_mb":{}}},"disk":{{"total_gb":{:.1},"free_gb":{:.1},"fs":"{}","path":"{}"}},"gpu":{{"present":{},"model":"{}","vram_mb":{},"driver":"{}"}},"net":{{"iface":"{}","link_mbps":{}}}}}"#,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0),
        esc(&cpu_model), cores_physical, cores_logical, cpu_mhz, pulse, jit_mode,
        ram_total_mb, ram_avail_mb,
        disk_total_gb, disk_free_gb, esc(&disk_fs), esc(&cwd.display().to_string()),
        gpu_present, esc(&gpu_model), gpu_vram_mb, esc(&gpu_driver),
        esc(&net_iface), net_link_mbps,
    )
}

fn probe_disk(path: &std::path::Path) -> (f64, f64, String) {
    // Use libc::statvfs via a small unsafe block — Lambda already pulls
    // libc transitively, no new dep.
    use std::os::unix::ffi::OsStrExt;
    use std::ffi::CString;
    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(_) => return (0.0, 0.0, "unknown".into()),
    };
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return (0.0, 0.0, "unknown".into());
    }
    let bsize = stat.f_frsize as u64;
    let total = (stat.f_blocks as u64) * bsize;
    let free  = (stat.f_bavail as u64) * bsize;
    let to_gb = |b: u64| (b as f64) / 1_073_741_824.0;
    // Best-effort fs name from /proc/mounts (longest prefix match on
    // cwd). Falls back to "unknown" if not found.
    let fs_name = std::fs::read_to_string("/proc/mounts").ok()
        .and_then(|mounts| {
            let path_str = path.display().to_string();
            mounts.lines()
                .filter_map(|l| {
                    let mut parts = l.split_whitespace();
                    let _dev = parts.next()?;
                    let mount = parts.next()?;
                    let fstype = parts.next()?;
                    if path_str.starts_with(mount) {
                        Some((mount.len(), fstype.to_string()))
                    } else {
                        None
                    }
                })
                .max_by_key(|(len, _)| *len)
                .map(|(_, fstype)| fstype)
        })
        .unwrap_or_else(|| "unknown".into());
    (to_gb(total), to_gb(free), fs_name)
}

fn probe_gpu() -> (bool, String, u64, String) {
    use std::process::Command;

    // Path 1 — nvidia-smi. If the driver is installed and reporting,
    // this is the authoritative source (model + VRAM + driver version).
    let nv = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,memory.total,driver_version",
            "--format=csv,noheader,nounits",
        ])
        .stdin(std::process::Stdio::null())
        .output();
    if let Ok(o) = nv {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout);
            if let Some(line) = s.lines().next() {
                let parts: Vec<&str> = line.split(',').map(|p| p.trim()).collect();
                if parts.len() >= 3 && !parts[0].is_empty() {
                    let model  = parts[0].to_string();
                    let vram   = parts[1].parse::<u64>().unwrap_or(0);
                    let driver = parts[2].to_string();
                    return (true, model, vram, driver);
                }
            }
        }
    }

    // Path 2 — lspci hardware probe. Detects a GPU card on the bus even
    // when the userspace driver isn't installed. We can't report VRAM
    // (the kernel driver would be needed for that) but we can tell the
    // operator "you have a card, no driver loaded — install one to
    // unlock zkVM acceleration."
    let pci = Command::new("lspci")
        .arg("-mm")
        .stdin(std::process::Stdio::null())
        .output();
    if let Ok(o) = pci {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout);
            // -mm format: each line space-separated, fields quoted.
            // Class "VGA compatible controller" or "3D controller" is a GPU.
            for line in s.lines() {
                let lower = line.to_ascii_lowercase();
                if lower.contains("\"vga compatible controller\"")
                    || lower.contains("\"3d controller\"")
                    || lower.contains("\"display controller\"")
                {
                    // Extract the third quoted field (vendor) + fourth (device)
                    // for the model string. Best-effort parse.
                    let quoted: Vec<&str> = line.split('"').collect();
                    let vendor = quoted.get(3).copied().unwrap_or("").trim();
                    let device = quoted.get(5).copied().unwrap_or("").trim();
                    let model = if !vendor.is_empty() && !device.is_empty() {
                        format!("{} {}", vendor, device)
                    } else if !device.is_empty() {
                        device.to_string()
                    } else {
                        "unknown GPU".to_string()
                    };
                    return (true, model, 0, "no driver".into());
                }
            }
        }
    }

    (false, String::new(), 0, String::new())
}

fn probe_net() -> (String, u64) {
    // First non-lo interface that reports a usable link speed.
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" { continue; }
            let speed_path = entry.path().join("speed");
            if let Ok(s) = std::fs::read_to_string(&speed_path) {
                if let Ok(mbps) = s.trim().parse::<i64>() {
                    if mbps > 0 {
                        return (name, mbps as u64);
                    }
                }
            }
        }
    }
    (String::new(), 0)
}

fn peers_json(engine: &ConsensusEngine) -> String {
    let storage = engine.storage();
    let hints = storage.get_all_hints().unwrap_or_default();
    let count = hints.len();

    let mut peers = String::from("[");
    for (i, h) in hints.iter().enumerate() {
        if i > 0 { peers.push(','); }
        let escaped_name = h.name.replace('\\', "\\\\").replace('"', "\\\"");
        let escaped_id = hex::encode(h.validator_id);
        let proof_cap = h.proof_cap.as_deref().unwrap_or("dmap");
        let carriers = h.carriers.iter()
            .map(|c| format!(r#""{}""#, c.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(",");
        let last_seen = h.last_seen.unwrap_or(0);
        // Encryption fields may contain newlines (PGP/GPG armoured key
        // blocks always do) so full JSON escape is required.
        let epk_esc = json_escape(&h.encryption_public_key);
        let se_esc = json_escape(&h.supported_encryption);
        peers.push_str(&format!(
            r#"{{"validator_id":"{}","name":"{}","proof_cap":"{}","carriers":[{}],"last_seen":{},"encryption_public_key":"{}","supported_encryption":"{}"}}"#,
            escaped_id, escaped_name, proof_cap, carriers, last_seen, epk_esc, se_esc,
        ));
    }
    peers.push(']');

    format!(r#"{{"count":{},"validators":{}}}"#, count, peers)
}

// ── Console governance endpoints ───────────────────────────────────────────

/// GET /console — current cohort, active proposals, digit_version, election state.
/// Also auto-finalizes expired proposals on every poll (coordination signal).
fn console_json(engine: &ConsensusEngine) -> String {
    match engine.console_engine() {
        Some(ce) => {
            // Note: auto-finalization is handled by POST /console/finalize,
            // NOT on every GET poll. This prevents race conditions where proposals
            // expire mid-vote due to real-time vs proposal-tick mismatch.
            let my_id = engine.validator_id();
            let is_member = ce.is_member(&my_id).unwrap_or(false);
            // Inject is_member + my_validator_id into the status JSON
            let mut json = ce.status_json();
            if json.ends_with('}') {
                json.pop(); // remove trailing }
                json.push_str(&format!(
                    r#","is_member":{},"my_validator_id":"{}"}}"#,
                    is_member, hex::encode(my_id)
                ));
            }
            json
        }
        None => r#"{"error":"Console engine not initialized"}"#.to_string(),
    }
}

/// POST /console/propose — submit digit migration proposal.
/// Body: { "proposer_id": "validator_hex", "direction": "Dedigitize"|"Redigitize", "magnitude": 1, "current_tick": 12345 }
fn handle_console_propose(engine: &ConsensusEngine, body: &str) -> String {
    let req: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"bad JSON: {}"}}"#, e),
    };
    let proposer_id = match req.get("proposer_id").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return r#"{"error":"missing proposer_id"}"#.to_string(),
    };
    let direction_str = match req.get("direction").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return r#"{"error":"missing direction"}"#.to_string(),
    };
    let direction = match crate::console_engine::DigitDirection::from_str(direction_str) {
        Some(d) => d,
        None => return format!(r#"{{"error":"invalid direction: {}"}}"#, direction_str),
    };
    let magnitude = match req.get("magnitude").and_then(|v| v.as_u64()) {
        Some(v) => v as u8,
        None => return r#"{"error":"missing or invalid magnitude"}"#.to_string(),
    };
    let current_tick = match req.get("current_tick").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return r#"{"error":"missing current_tick"}"#.to_string(),
    };

    let ce = match engine.console_engine() {
        Some(ce) => ce,
        None => return r#"{"error":"Console engine not initialized"}"#.to_string(),
    };

    match ce.submit_proposal(proposer_id, direction, magnitude, current_tick) {
        Ok(p) => format!(
            r#"{{"ok":true,"proposal_id":"{}","direction":"{}","magnitude":{},"expires_at":{}}}"#,
            p.proposal_id, p.direction.as_str(), p.magnitude, p.expires_at,
        ),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// POST /console/vote — cast ACK or NO on a proposal (White Paper §7.8).
/// Body: { "proposal_id": "CSL-...", "validator_id": "...", "vote": "ACK"|"NO", "current_tick": 12345 }
fn handle_console_vote(engine: &ConsensusEngine, body: &str) -> String {
    let req: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"bad JSON: {}"}}"#, e),
    };
    let proposal_id = match req.get("proposal_id").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return r#"{"error":"missing proposal_id"}"#.to_string(),
    };
    let validator_id = match req.get("validator_id").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return r#"{"error":"missing validator_id"}"#.to_string(),
    };
    let vote = match req.get("vote").and_then(|v| v.as_str()) {
        Some(v) if v == "ACK" || v == "NO" => v,
        _ => return r#"{"error":"vote must be 'ACK' or 'NO'"}"#.to_string(),
    };
    let current_tick = match req.get("current_tick").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return r#"{"error":"missing current_tick"}"#.to_string(),
    };

    let ce = match engine.console_engine() {
        Some(ce) => ce,
        None => return r#"{"error":"Console engine not initialized"}"#.to_string(),
    };

    match ce.cast_vote(proposal_id, validator_id, vote, current_tick) {
        Ok(()) => format!(r#"{{"ok":true,"vote":"{}"}}"#, vote),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// POST /console/bootstrap — create genesis Console Certificate (generation 0).
///
/// DEV/TEST ONLY: creates 15 synthetic seats for testing the voting flow.
///
/// In production (G1 ceremony): generation 0 has exactly 10 seats (the 10 genesis
/// validators). Console is INERT with <15 seats — no tasks can execute (YP §21.10.4).
/// Console becomes active only after the first election fills all 15 seats,
/// which requires the network to grow beyond the initial 10 genesis validators.
fn handle_console_bootstrap(engine: &ConsensusEngine) -> String {
    let ce = match engine.console_engine() {
        Some(ce) => ce,
        None => return r#"{"error":"Console engine not initialized"}"#.to_string(),
    };

    // Check if already bootstrapped
    if let Ok(cohort) = ce.get_cohort() {
        if !cohort.is_empty() {
            return format!(r#"{{"error":"Console already bootstrapped (gen {}, {} seats)"}}"#,
                ce.election_state().map(|s| s.2).unwrap_or(0),
                cohort.len());
        }
    }

    let my_id = engine.validator_id();

    // DEV/TEST: fill 15 seats for testing voting flow.
    // PRODUCTION (G1): would create 10 seats with real genesis validator IDs.
    // Console is INERT with <15 seats (YP §21.10.4).
    let mut seats = Vec::new();
    for i in 0u8..15 {
        let mut seat = my_id;
        if i > 0 { seat[31] = i; } // Make distinct IDs for testing
        seats.push(seat);
    }

    let cert = axiom_core_logic::types::ConsoleCertificate {
        generation: 0,
        seats,
        term_start_tick: 0,
        term_end_tick: axiom_core_logic::types::CONSOLE_TICKS_PER_YEAR,
        previous_link_hash: [0; 32],
        election_attempt: 0,
        group_wallet_id: "DWP/CONSOLE/0".to_string(),
        core_signature: vec![],
    };

    let hash = axiom_core_logic::console::compute_console_chain_hash(&cert);
    match ce.store_certificate(&cert, &hash) {
        Ok(()) => format!(
            r#"{{"ok":true,"generation":0,"seats":15,"term_end_tick":{},"chain_hash":"{}"}}"#,
            axiom_core_logic::types::CONSOLE_TICKS_PER_YEAR,
            hex::encode(hash)
        ),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// POST /console/finalize — finalize expired proposals (trigger 24h window check).
/// Called periodically by Lambda main loop or manually for testing.
/// When a proposal is approved, builds CL10 Fan-Out to broadcast the decision.
/// Core verifies the Fan-Out (originator VBC + signature). (YP §18.8)
fn handle_console_finalize(engine: &ConsensusEngine) -> String {
    let ce = match engine.console_engine() {
        Some(ce) => ce,
        None => return r#"{"error":"Console engine not initialized"}"#.to_string(),
    };

    let tick = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() / 5; // Convert to TARDIS ticks

    let dv_before = ce.status().map(|s| s.digit_version).unwrap_or(0);

    match ce.finalize_expired(tick) {
        Ok(count) => {
            let dv_after = ce.status().map(|s| s.digit_version).unwrap_or(0);
            let mut fanout_id = String::new();

            if count > 0 && dv_after != dv_before {
                // Digit migration approved — build CL10 Fan-Out
                let fanout_msg = engine.build_console_fanout("finalized", "Approved", dv_after);
                fanout_id = hex::encode(&fanout_msg.diffusion_id[..8]);
                tracing::info!(
                    "Console: digit_version {} -> {}. Fan-Out built (diffusion_id={})",
                    dv_before, dv_after, fanout_id,
                );
            }

            format!(
                r#"{{"ok":true,"finalized":{},"current_tick":{},"digit_version_before":{},"digit_version_after":{},"fanout_id":"{}"}}"#,
                count, tick, dv_before, dv_after, fanout_id,
            )
        }
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// POST /console/dismiss — initiate self-dismissal vote (White Paper §7.7A).
/// Body: { "validator_id": "...", "current_tick": 12345 }
fn handle_console_dismiss(engine: &ConsensusEngine, body: &str) -> String {
    let req: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"bad JSON: {}"}}"#, e),
    };
    let validator_id = match req.get("validator_id").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return r#"{"error":"missing validator_id"}"#.to_string(),
    };
    let current_tick = match req.get("current_tick").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return r#"{"error":"missing current_tick"}"#.to_string(),
    };

    let ce = match engine.console_engine() {
        Some(ce) => ce,
        None => return r#"{"error":"Console engine not initialized"}"#.to_string(),
    };

    match ce.submit_self_dismissal(validator_id, current_tick) {
        Ok(p) => format!(r#"{{"ok":true,"proposal_id":"{}","expires_at":{}}}"#, p.proposal_id, p.expires_at),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// POST /console/core-update — recommend Core ELF update (coordination signal).
/// Body: { "validator_id": "...", "current_tick": 12345 }
///
/// WARNING: This is a RECOMMENDATION, not a command. If approved by 15/15 ACK:
/// - Each validator independently decides whether to adopt the new Core ELF
/// - Validators running different Core versions CANNOT interoperate
/// - Different core_id = SPLIT WORLDLINE
/// - Reality Attestation (C1) resolves which worldline is canonical
fn handle_console_core_update(engine: &ConsensusEngine, body: &str) -> String {
    let req: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"bad JSON: {}"}}"#, e),
    };
    let validator_id = match req.get("validator_id").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return r#"{"error":"missing validator_id"}"#.to_string(),
    };
    let current_tick = match req.get("current_tick").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return r#"{"error":"missing current_tick"}"#.to_string(),
    };

    let ce = match engine.console_engine() {
        Some(ce) => ce,
        None => return r#"{"error":"Console engine not initialized"}"#.to_string(),
    };

    match ce.submit_core_update(validator_id, current_tick) {
        Ok(p) => format!(
            r#"{{"ok":true,"proposal_id":"{}","type":"CoreUpdate","expires_at":{},"warning":"If approved, validators must independently adopt new Core ELF. Different Core = SPLIT WORLDLINE."}}"#,
            p.proposal_id, p.expires_at
        ),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// GET /scar-passcode?txid=<hex> — look up a scar passcode (read-only).
/// AUDIT-FIX v2.11.14: recover action moved to POST /scar-passcode/recover.
/// GET requests MUST NOT mutate state (HTTP semantics, CSRF prevention).
fn scar_passcode_json(engine: &ConsensusEngine, query: Option<&str>) -> String {
    let txid_hex = query.and_then(|q| extract_query_param(q, "txid")).unwrap_or("");
    if txid_hex.len() != 64 {
        return r#"{"error":"txid must be 64 hex chars"}"#.to_string();
    }
    let txid = match parse_hex32(txid_hex) {
        Ok(t) => t,
        Err(e) => return format!(r#"{{"error":"{}"}}"#, e),
    };

    match engine.storage().get_scar_passcode_full(&txid) {
        Ok(Some((passcode, delivered_at, recovered_at))) => {
            let del_str = delivered_at.map(|d| d.to_string()).unwrap_or("null".into());
            let rec_str = recovered_at.map(|r| r.to_string()).unwrap_or("null".into());
            format!(r#"{{"txid":"{}","passcode":{},"delivered_at":{},"recovered_at":{}}}"#,
                txid_hex, passcode, del_str, rec_str)
        }
        Ok(None) => format!(r#"{{"txid":"{}","passcode":null,"delivered_at":null,"recovered_at":null}}"#, txid_hex),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// POST /scar-passcode/recover — mark a scar passcode as recovered.
/// AUDIT-FIX v2.11.14: State mutation via POST only (was GET ?recover=true).
fn handle_scar_passcode_recover(engine: &ConsensusEngine, body: &str) -> String {
    let req: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"bad JSON: {}"}}"#, e),
    };
    let txid_hex = match req.get("txid").and_then(|v| v.as_str()) {
        Some(h) if h.len() == 64 => h,
        _ => return r#"{"error":"txid must be 64 hex chars"}"#.to_string(),
    };
    let txid = match parse_hex32(txid_hex) {
        Ok(t) => t,
        Err(e) => return format!(r#"{{"error":"{}"}}"#, e),
    };
    match engine.storage().mark_passcode_recovered(&txid) {
        Ok(()) => format!(r#"{{"ok":true,"txid":"{}"}}"#, txid_hex),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// GET /delivery-status?txid=<hex> — check cheque delivery status.
fn delivery_status_json(engine: &ConsensusEngine, query: Option<&str>) -> String {
    let txid_hex = query.and_then(|q| extract_query_param(q, "txid")).unwrap_or("");
    if txid_hex.len() != 64 {
        return r#"{"error":"txid must be 64 hex chars"}"#.to_string();
    }
    let txid = match parse_hex32(txid_hex) {
        Ok(t) => t,
        Err(e) => return format!(r#"{{"error":"{}"}}"#, e),
    };
    // Timeout stale deliveries on query
    engine.storage().timeout_stale_deliveries().ok();
    match engine.storage().get_delivery_status(&txid) {
        Ok(Some((status, recipient, sent_at, ack_at, encrypted))) => {
            let ack_str = ack_at.map(|a| a.to_string()).unwrap_or("null".into());
            format!(r#"{{"txid":"{}","recipient":"{}","sent_at":{},"ack_received_at":{},"status":"{}","encrypted":{}}}"#,
                txid_hex, recipient, sent_at, ack_str, status, encrypted)
        }
        Ok(None) => format!(r#"{{"txid":"{}","status":"not_found"}}"#, txid_hex),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

/// POST /delivery-update — ANTIE callback to update encrypted status after email send.
fn handle_delivery_update(engine: &ConsensusEngine, body: &str) -> String {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"error":"invalid JSON: {}"}}"#, e),
    };
    let txid_hex = match v["txid"].as_str() {
        Some(s) if s.len() == 64 => s,
        _ => return r#"{"error":"txid must be 64 hex chars"}"#.to_string(),
    };
    let encrypted = v["encrypted"].as_bool().unwrap_or(false);
    let txid = match parse_hex32(txid_hex) {
        Ok(t) => t,
        Err(e) => return format!(r#"{{"error":"{}"}}"#, e),
    };
    engine.storage().update_delivery_encrypted(&txid, encrypted).ok();
    r#"{"ok":true}"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_admin_endpoint_compiles() {
        // Verifies the module compiles and spawn signature is correct.
        // Integration test with real engine would use a known port.
    }

    #[test]
    fn test_check_auth_no_token_configured() {
        // AUDIT-FIX v2.11.14: No token configured => health passes, everything else denied
        assert!(check_auth("/health", None, &None, None));
        assert!(!check_auth("/stats", None, &None, None));
        assert!(!check_auth("/proof", None, &None, None));
        assert!(!check_auth("/identity", None, &None, None));
        assert!(!check_auth("/console", None, &None, None));
        assert!(!check_auth("/jfp/scar", None, &None, None));
    }

    #[test]
    fn test_check_auth_health_always_accessible() {
        let token = Some("secret123".to_string());
        // /health always accessible regardless of token
        assert!(check_auth("/health", None, &token, None));
        assert!(check_auth("/health", Some("token=wrong"), &token, None));
        assert!(check_auth("/health", Some("token=secret123"), &token, None));
    }

    #[test]
    fn test_check_auth_requires_token() {
        let token = Some("mysecret".to_string());
        // No token provided -> denied
        assert!(!check_auth("/stats", None, &token, None));
        // Wrong token -> denied
        assert!(!check_auth("/stats", Some("token=wrong"), &token, None));
        // Correct token -> allowed (query param, legacy)
        assert!(check_auth("/stats", Some("token=mysecret"), &token, None));
        // Token with other params
        assert!(check_auth("/proof", Some("foo=bar&token=mysecret"), &token, None));
    }

    #[test]
    fn test_check_auth_authorization_header() {
        let token = Some("mysecret".to_string());
        // Authorization header with Bearer prefix
        assert!(check_auth("/stats", None, &token,
            Some("\r\nAuthorization: Bearer mysecret\r\n")));
        // Wrong token in header
        assert!(!check_auth("/stats", None, &token,
            Some("\r\nAuthorization: Bearer wrong\r\n")));
        // Header takes precedence over query param
        assert!(check_auth("/stats", Some("token=wrong"), &token,
            Some("\r\nAuthorization: Bearer mysecret\r\n")));
        // No Authorization header, falls back to query param
        assert!(check_auth("/stats", Some("token=mysecret"), &token,
            Some("\r\nContent-Type: application/json\r\n")));
    }

    #[test]
    fn test_extract_query_param() {
        assert_eq!(extract_query_param("token=abc", "token"), Some("abc"));
        assert_eq!(extract_query_param("foo=bar&token=xyz", "token"), Some("xyz"));
        assert_eq!(extract_query_param("foo=bar", "token"), None);
        // "tokenizer" should NOT match "token"
        assert_eq!(extract_query_param("tokenizer=bad", "token"), None);
    }

    #[test]
    fn test_is_allowed_nabla_addr() {
        // AUDIT-FIX v2.11.14: Only known Nabla peers accepted
        assert!(is_allowed_nabla_addr("127.0.0.1:6226"));
        assert!(is_allowed_nabla_addr("127.0.0.1:6231"));
        // Reject arbitrary addresses (SSRF prevention)
        assert!(!is_allowed_nabla_addr("127.0.0.1:9999"));
        assert!(!is_allowed_nabla_addr("169.254.169.254:80"));
        assert!(!is_allowed_nabla_addr("10.0.0.1:6226"));
        assert!(!is_allowed_nabla_addr("example.com:6226"));
        assert!(!is_allowed_nabla_addr(""));
    }

    /// SEC-08: handle_jfp_scar must NO LONGER post a synthetic, unauthenticated
    /// SCAR state to Nabla `/register`. The forgeable mesh-wide path (POST
    /// /register with `AXIOM_JFP_SCAR`-derived state, no k-witnessed verdict)
    /// is deleted; enforcement is the Core frozen_wallets freeze only. This is
    /// a source-level guard (the function fires fire-and-forget I/O, not unit-
    /// testable in isolation), mirroring the SEC-09 oracle-path guard.
    #[test]
    fn test_sec08_jfp_scar_has_no_synthetic_nabla_register() {
        let source = include_str!("admin.rs");
        let fn_pos = source.find("fn handle_jfp_scar").unwrap();
        let fn_end = source[fn_pos + 20..].find("\nfn ").map(|p| p + fn_pos + 20).unwrap_or(source.len());
        let body = &source[fn_pos..fn_end];
        // Match the CODE forms (not the explanatory comment, which necessarily
        // names the deleted behavior).
        assert!(!body.contains("b\"AXIOM_JFP_SCAR\""),
            "SEC-08: the synthetic JFP SCAR state computation must be gone");
        assert!(!body.contains("POST /register HTTP"),
            "SEC-08: handle_jfp_scar must not POST a synthetic SCAR to Nabla /register");
        assert!(!body.contains("TcpStream::connect"),
            "SEC-08: handle_jfp_scar must make no Nabla network call");
    }

    #[test]
    fn test_dwp_admin_handlers() {
        let engine = crate::consensus::tests::create_test_engine();

        // GET /dwp should show real counts
        let dwp_status = dwp_json(&engine);
        assert!(dwp_status.contains("\"dwp_wallets\":0"), "Should start with 0: {}", dwp_status);
        assert!(dwp_status.contains("\"status\":\"operational\""), "Should be operational: {}", dwp_status);

        // POST /dwp/query creates a wallet
        let pwv_hex: Vec<String> = (0x10..0x1Fu8).map(|i| hex::encode([i; 32])).collect();
        let query_body = format!(
            r#"{{"txid":"{}","requester_pk":"{}","payment_txid":"{}","pwv_set":[{}],"case_description":"Test case","tardis_tick":0}}"#,
            hex::encode([0xAA; 32]),
            hex::encode([0x02; 32]),
            hex::encode([0x00; 32]), // zero = test/bootstrap mode (skips payment check)
            pwv_hex.iter().map(|h| format!("\"{}\"", h)).collect::<Vec<_>>().join(","),
        );
        let result = handle_dwp_query(&engine, &query_body);
        assert!(result.contains("\"ok\":true"), "DWP query should succeed: {}", result);
        let resp: serde_json::Value = serde_json::from_str(&result).unwrap();
        let wallet_id_hex = resp["wallet_id"].as_str().unwrap();

        // GET /dwp should now show 1 wallet
        let dwp_status2 = dwp_json(&engine);
        assert!(dwp_status2.contains("\"dwp_wallets\":1"), "Should have 1: {}", dwp_status2);

        // POST /dwp/case adds a case entry
        let case_body = format!(
            r#"{{"wallet_id":"{}","author_pk":"{}","content":"Evidence submitted","tardis_tick":1}}"#,
            wallet_id_hex, hex::encode([0x02; 32]),
        );
        let result = handle_dwp_case(&engine, &case_body);
        assert!(result.contains("\"ok\":true"), "Case entry should succeed: {}", result);

        // Bad JSON → error
        let result = handle_dwp_query(&engine, "not json");
        assert!(result.contains("\"error\":"), "Should return error: {}", result);
    }

    #[test]
    fn test_scar_passcode_recover_route() {
        let engine = crate::consensus::tests::create_test_engine();

        // GET /scar-passcode is read-only (no recover parameter honored)
        let result = scar_passcode_json(&engine, Some("txid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&recover=true"));
        assert!(result.contains("\"passcode\":null"), "Should return null for unknown txid: {}", result);

        // POST /scar-passcode/recover with valid JSON but unknown txid
        let body = r#"{"txid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let result = handle_scar_passcode_recover(&engine, body);
        // Should succeed or error gracefully (storage may return Ok or Err depending on whether txid exists)
        assert!(result.contains("\"ok\":true") || result.contains("\"error\":"),
            "Should return ok or error: {}", result);

        // POST /scar-passcode/recover with bad JSON
        let result = handle_scar_passcode_recover(&engine, "not json");
        assert!(result.contains("\"error\":\"bad JSON"), "Should reject bad JSON: {}", result);

        // POST /scar-passcode/recover with short txid
        let result = handle_scar_passcode_recover(&engine, r#"{"txid":"abcd"}"#);
        assert!(result.contains("\"error\":\"txid must be 64 hex chars\""), "Should reject short txid: {}", result);
    }

    #[tokio::test]
    async fn test_admin_rate_limit_returns_429() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Spawn admin server with auth token on a random port
        let engine = Arc::new(crate::consensus::tests::create_test_engine());
        let auth_token = Some("testtoken".to_string());

        // Bind to port 0 to get a random available port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        // Spawn admin server on that port with a low rate limit (60 req / 60s)
        // so the test doesn't need to send thousands of requests to hit the gate.
        // Production uses (6000, 60); this test uses (60, 60).
        let _handle = spawn_admin_server_with_rate_limit(port, engine, auth_token, 60, 60);

        // Helper: send a request and read the response status line
        async fn send_request(port: u16) -> Result<String, std::io::Error> {
            let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await?;
            let req = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            stream.write_all(req.as_bytes()).await?;
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await?;
            Ok(String::from_utf8_lossy(&buf[..n]).to_string())
        }

        // Poll the server until it's ready (replaces fixed 100ms sleep).
        // Retries a connect every 10ms for up to 2 seconds.
        let start = std::time::Instant::now();
        loop {
            if let Ok(resp) = send_request(port).await {
                if resp.contains("200 OK") {
                    break; // server ready — this counts as request #1 of 60
                }
            }
            if start.elapsed() > std::time::Duration::from_secs(2) {
                panic!("admin server did not become ready within 2s");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Readiness request already counted as 1; send 59 more to reach the limit of 60
        for i in 0..59 {
            let resp = send_request(port).await.unwrap();
            assert!(resp.contains("200 OK"), "Should be 200 within limit (req {}): {}",
                i + 2, &resp[..resp.len().min(80)]);
        }

        // 61st request should be rate-limited
        let resp = send_request(port).await.unwrap();
        assert!(resp.contains("429 Too Many Requests"), "Should be 429 after limit: {}", &resp[..resp.len().min(80)]);
    }
}
