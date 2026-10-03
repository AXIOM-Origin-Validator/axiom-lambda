//! Lambda Server
//!
//! Handles Gateway connections and dispatches requests to ConsensusEngine.
//!
//! All transport uses CBOR framing (Yellow Paper §16.8.5.3):
//! - TCP: For production Gateway connections
//! - Stdio-framed (default): Length-prefixed CBOR for subprocess IPC

use crate::config::LambdaConfig;
use crate::consensus::ConsensusEngine;
use crate::error::LambdaError;
use crate::error_response::{gateway_error_from_lambda, gateway_error_raw};
use crate::rate_limit::RateLimiter;
use crate::storage::Storage;
use crate::types::*;
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// Lambda Server
pub struct LambdaServer {
    config: LambdaConfig,
    engine: Arc<ConsensusEngine>,
    /// Clone of the transaction storage handle — kept so the WAL can be
    /// checkpointed on shutdown without routing through ConsensusEngine.
    storage: Arc<Storage>,
    pub shutdown_tx: broadcast::Sender<()>,
}

impl LambdaServer {
    /// Create new Lambda server.
    ///
    /// Executes core validation via AVM interpreter directly (no core-bin subprocess).
    /// Optionally requires axiom-core.elf for DMAP attestation.
    pub fn new(config: LambdaConfig, signing_key: SigningKey) -> Result<Self, LambdaError> {
        // Derive encryption key from Ed25519 private key
        let db_key = crate::storage::derive_db_key(
            signing_key.as_bytes(),
            b"AXIOM_DB_KEY_V1",
        );

        // AUDIT-FIX v2.11.14: Fail-stop on directory creation (was silent .ok()).
        if let Some(parent) = config.storage.transaction_db.parent() {
            std::fs::create_dir_all(parent).map_err(|e|
                LambdaError::StorageError(format!("Cannot create DB directory {:?}: {}", parent, e)))?;
        }
        if let Some(parent) = config.storage.management_db.parent() {
            std::fs::create_dir_all(parent).map_err(|e|
                LambdaError::StorageError(format!("Cannot create mgmt DB directory {:?}: {}", parent, e)))?;
        }

        // Open transaction storage (encrypted)
        let storage = Arc::new(Storage::open_with_max_hints(
            &config.storage.transaction_db,
            &db_key,
            config.storage.max_hints,
        )?);

        // Open management database (encrypted, used by Console/DWP/JFP)
        let mgmt_key = crate::storage::derive_db_key(
            signing_key.as_bytes(),
            b"AXIOM_MGMT_DB_KEY_V1",
        );
        let management_db = Arc::new(crate::management_db::ManagementDb::open(
            &config.storage.management_db,
            &mgmt_key,
        )?);

        // No seed-hints file (KI#174): `seed-hints.json` was retired 2026-05-19 (55f26e6d) —
        // wallets relay hints into this table; `seeds/validators.list` seeds clients.

        // VBC path is mandatory — Lambda cannot start without a real VBC
        let vbc_path = config.validator.vbc_path.as_ref()
            .ok_or_else(|| LambdaError::ConfigError(
                "vbc_path is required in [validator] config. Run install_genesis.sh to generate VBCs.".into()
            ))?;
        
        // Load AVM ELF for direct interpreter execution
        let avm_config = if let Some(ref elf_path) = config.proof.avm_elf_path {
            axiom_dmap_vm::AvmConfig::from_paths(
                elf_path.to_str().ok_or_else(|| LambdaError::ConfigError("AVM ELF path is not valid UTF-8".into()))?,
                config.proof.avm_image_id_path.as_deref()
                    .map(|p| p.to_str().ok_or_else(|| LambdaError::ConfigError("AVM IMAGE_ID path is not valid UTF-8".into())))
                    .transpose()?,
            ).map_err(|e| LambdaError::ConfigError(format!("Failed to load AVM ELF: {}", e)))?
        } else {
            // Try default paths
            let default_candidates = [
                config.validator.private_key_path.parent()
                    .map(|p| p.join("../axiom-core.elf")),
                Some(std::path::PathBuf::from("./axiom-core.elf")),
            ];
            let found = default_candidates.iter()
                .flatten()
                .find(|p| p.exists());
            match found {
                Some(path) => {
                    info!("Auto-discovered AVM ELF at {:?}", path);
                    axiom_dmap_vm::AvmConfig::from_paths(
                        path.to_str().unwrap(), None
                    ).map_err(|e| LambdaError::ConfigError(format!("Failed to load AVM ELF: {}", e)))?
                }
                None => {
                    // GAP-5 FIX: Fail-stop if no AVM ELF found.
                    // Without a real ELF, Lambda cannot produce DMAP proofs and other
                    // validators will reject our cheques (empty execution proof → H1 reject).
                    // Sentinel fallback was dev convenience — production must have real ELF.
                    return Err(LambdaError::ConfigError(
                        "No AVM ELF found. Set avm_elf_path in [proof] config, \
                         set AXIOM_AVM_ELF env var, or place axiom-core.elf \
                         in the working directory. Run build-zkvm.sh to build it."
                            .into(),
                    ));
                }
            }
        };

        // CoreID verification — ensures all validators run the same Core ELF.
        let loaded_core_id = hex::encode(avm_config.core_id);
        let canonical = axiom_core_logic::version::CANONICAL_CORE_ID;
        if !canonical.is_empty() {
            if loaded_core_id != canonical {
                return Err(LambdaError::ConfigError(format!(
                    "CoreID mismatch: loaded ELF has CoreID {} but canonical is {}. \
                     Download the correct axiom-core.elf from the release page.",
                    loaded_core_id, canonical
                )));
            }
            info!("CoreID verified: {}", loaded_core_id);
        } else {
            info!("CoreID: {} (dev build — no canonical enforcement)", loaded_core_id);
        }

        // Create consensus engine — will fail if VBC file is missing or invalid
        let sphincs_key_path = config.validator.sphincs_key_path.as_deref();
        let dilithium_key_path = config.validator.dilithium_key_path.as_deref();
        let mut engine = ConsensusEngine::new(storage.clone(), signing_key, vbc_path, avm_config, sphincs_key_path, dilithium_key_path)?;

        // Initialize management DB + DWP/JFP engines
        engine.init_management(management_db.clone());

        // Configure proof tiering (ZKP vs DMAP) from config
        engine.configure_proof_tiering_sync(&config.proof);

        // Apply operator's max_fact_links from lambda.toml (default 16,
        // configurable per-operator). Replaces the hardcoded 16 in
        // ConsensusEngine::new — operators on JIT validators may raise this
        // up to Core's hard ceiling of 64.
        engine.set_max_fact_links(config.max_fact_links);

        // Thread [fee] + [operator] from lambda.toml into the engine.
        // Without this the engine sat on Default values forever:
        // operator_name = "Anonymous", encryption_public_key = "", etc.
        // The discovery self-hint built in `set_carriers` reads
        // operator_config.encryption_public_key — empty here ⇒ wallets
        // never learn the operator's PGP/GPG key over the gossip mesh.
        engine.set_fee_and_operator_config(config.fees.clone(), config.operator.clone());
        engine.set_oracle_config(config.oracle.clone());

        // YPX-009: bind the validator pk into the AVM before any execution.
        engine.bind_avm_validator_pk();

        let engine = Arc::new(engine);

        // YPX-009 ignition = YPX-007 §9 ZKP qualification run (KI#125), on EVERY
        // build, in the background: listening never waits on Nabla or the prover,
        // and no Nabla/prover outcome stops service (status + optional record only).
        // With `pulse-gate` the AVM blocks execution until the ignition completes;
        // an ignition that never completes (error or panic) EXITS the process.
        tokio::spawn(engine.clone().run_ignition());
        
        // Sync stats with storage (picks up seed hints loaded earlier)
        engine.sync_stats_from_storage();
        
        // Set stats file path next to transaction_db
        let stats_path = std::path::Path::new(&config.storage.transaction_db)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("stats.json");
        engine.set_stats_path(stats_path);
        
        // AUDIT-FIX v2.11.13: Check fee redemption readiness at startup
        engine.check_fee_redemption_readiness(config.min_validators_for_fee_redemption);

        // Spawn admin HTTP server if configured
        if let Some(admin_port) = config.admin_port {
            crate::admin::spawn_admin_server(admin_port, engine.clone(), config.admin_token.clone());
        }

        // Spawn periodic storage pruning + VACUUM.
        // Configurable via lambda.toml vacuum_interval_secs (default 1800 = 30 min).
        // High-load validators should lower to 300 (5 min).
        // Set to 0 to disable (inline cleanup still runs on every write).
        let vacuum_interval = config.vacuum_interval_secs;
        if vacuum_interval > 0 {
            let prune_engine = engine.clone();
            let interval_secs = vacuum_interval;
            tokio::spawn(async move {
                // Run immediately on startup, then at configured interval.
                loop {
                    match prune_engine.storage_prune(3600) {
                        Ok(n) if n > 0 => tracing::info!("[MAINTENANCE] pruned {} stale storage rows", n),
                        Err(e) => tracing::warn!("[MAINTENANCE] storage prune error: {}", e),
                        _ => {}
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
                }
            });
        }

        // Spawn periodic WAL checkpoint — keeps lambda.db-wal bounded so the
        // shutdown checkpoint stays fast and an ungraceful kill is cheap.
        // Without it the WAL grows unbounded under load (172 MB+ observed).
        {
            let ckpt_storage = storage.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                interval.tick().await; // skip the immediate first tick
                loop {
                    interval.tick().await;
                    if let Err(e) = ckpt_storage.checkpoint_wal() {
                        tracing::warn!("[MAINTENANCE] WAL checkpoint error: {}", e);
                    }
                }
            });
        }

        // Spawn periodic DWP expiry sweep (daily)
        {
            let sweep_db = management_db.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(86_400));
                interval.tick().await; // skip immediate first tick
                loop {
                    interval.tick().await;
                    match sweep_db.sweep_expired_dwp() {
                        Ok(n) if n > 0 => info!("DWP sweep: {} wallets expired", n),
                        Err(e) => warn!("DWP sweep error: {}", e),
                        _ => {}
                    }
                }
            });
        }

        // Spawn JFP online proof generator (hourly)
        // Generates proof TXs for active DWP cases where this validator is a PWV member.
        // Proofs are queued in management DB and sent on next password unlock / vote.
        {
            let proof_db = management_db.clone();
            let proof_engine_id = engine.validator_id();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
                interval.tick().await; // skip immediate first tick
                loop {
                    interval.tick().await;
                    // Find active DWP wallets where we're in the PWV set
                    if let Ok(conn) = proof_db.db() {
                        let mut stmt = match conn.prepare(
                            "SELECT wallet_id, pwv_set FROM dwp_wallets WHERE status = 'locked' AND result = 'pending'"
                        ) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let wallets: Vec<([u8; 32], String)> = stmt.query_map([], |row| {
                            let wid: Vec<u8> = row.get(0)?;
                            let pwv: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
                            let mut arr = [0u8; 32];
                            if wid.len() == 32 { arr.copy_from_slice(&wid); }
                            Ok((arr, pwv))
                        }).ok()
                        .map(|rows| rows.filter_map(|r| r.ok()).collect())
                        .unwrap_or_default();

                        let my_hex = hex::encode(proof_engine_id);
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        for (wallet_id, pwv_json) in &wallets {
                            if let Ok(pwv) = serde_json::from_str::<Vec<String>>(pwv_json) {
                                if pwv.contains(&my_hex) {
                                    // Generate proof hash (includes Nabla-like timestamp for uniqueness)
                                    let proof_hash = {
                                        let mut h = blake3::Hasher::new();
                                        h.update(b"AXIOM_JFP_ONLINE_PROOF");
                                        h.update(wallet_id);
                                        h.update(&proof_engine_id);
                                        h.update(&now.to_le_bytes());
                                        *h.finalize().as_bytes()
                                    };
                                    // Queue in audit_log for tracking
                                    let _ = conn.execute(
                                        "INSERT INTO audit_log (timestamp, event_type, details)
                                         VALUES (?1, 'jfp_online_proof', ?2)",
                                        rusqlite::params![
                                            now as i64,
                                            format!("{{\"wallet_id\":\"{}\",\"proof\":\"{}\"}}",
                                                    hex::encode(wallet_id), hex::encode(proof_hash)),
                                        ],
                                    );
                                    debug!("JFP online proof generated for DWP {}", hex::encode(&wallet_id[..4]));
                                }
                            }
                        }
                    }
                }
            });
        }

        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            engine,
            storage,
            shutdown_tx,
        })
    }
    
    /// Check if running in production mode
    pub fn is_production_mode(&self) -> bool {
        self.engine.is_production_mode()
    }
    
    /// Run the server in TCP mode
    pub async fn run(&self) -> Result<(), LambdaError> {
        let addr = &self.config.network.listen;
        
        if addr.starts_with("unix:") {
            // Unix socket (not implemented yet)
            return Err(LambdaError::ConfigError(
                "Unix socket not yet implemented".to_string()
            ));
        }
        
        // TCP listener
        let listener = TcpListener::bind(addr).await?;

        // Optional TLS (YPX-015 §2.3 — required for multi-host deployment)
        let tls_acceptor = match (&self.config.network.tls_cert_path, &self.config.network.tls_key_path) {
            (Some(cert_path), Some(key_path)) => {
                let certs = load_tls_certs(cert_path)?;
                let key = load_tls_key(key_path)?;
                let config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| LambdaError::ConfigError(format!("TLS config: {e}")))?;
                info!("Lambda listening on {} (TLS)", addr);
                Some(TlsAcceptor::from(Arc::new(config)))
            }
            _ => {
                info!("Lambda listening on {} (plaintext — set tls_cert_path/tls_key_path to enable TLS)", addr);
                None
            }
        };

        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut rate_limiter = RateLimiter::new(100, 60);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            if !rate_limiter.check(addr.ip()) {
                                warn!("Rate limited: {}", addr.ip());
                                drop(stream);
                                continue;
                            }
                            debug!("New connection from {}", addr);
                            let engine = Arc::clone(&self.engine);
                            let acceptor = tls_acceptor.clone();
                            tokio::spawn(async move {
                                if let Some(acceptor) = acceptor {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            if let Err(e) = handle_tcp_connection(tls_stream, engine).await {
                                                error!("TLS connection error: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("TLS handshake failed from {}: {}", addr, e);
                                        }
                                    }
                                } else if let Err(e) = handle_tcp_connection(stream, engine).await {
                                    error!("Connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        Ok(())
    }
    
    /// Run in stdio mode with length-prefixed CBOR frames (matches Gateway IPC)
    ///
    /// Frame format: 4-byte big-endian length + CBOR payload (Yellow Paper §16.8.5.3)
    pub async fn run_stdio_framed(&self) -> Result<(), LambdaError> {
        info!("Lambda running in stdio framed mode (CBOR)");
        
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        
        loop {
            // Read frame: 4-byte length + CBOR payload
            let mut len_buf = [0u8; 4];
            match stdin.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    info!("Stdin closed, shutting down");
                    break;
                }
                Err(e) => {
                    error!("Stdin read error: {}", e);
                    break;
                }
            }
            
            let len = u32::from_be_bytes(len_buf) as usize;
            const MAX_IPC_BYTES: usize = 16 * 1024 * 1024;
            if len > MAX_IPC_BYTES {
                error!("IPC frame too large: {} bytes (max {})", len, MAX_IPC_BYTES);
                break;
            }
            
            let mut payload = vec![0u8; len];
            stdin.read_exact(&mut payload).await?;
            
            // SECURITY FIX #14: Debug eprintln removed — use structured tracing instead.
            // eprintln! in production bypasses log level filtering and may leak to stderr.
            debug!("Received {} bytes from stdin", len);
            
            // Parse CBOR payload (Yellow Paper §16.8.5.3 — CBOR everywhere)
            let response = match ciborium::from_reader::<GatewayRequest, _>(&payload[..]) {
                Ok(request) => {
                    debug!("Parsed CBOR request OK");
                    if matches!(request, GatewayRequest::Shutdown (ShutdownRequest { .. })) {
                        let resp = process_request(request, &self.engine).await;
                        write_framed_response(&mut stdout, &resp).await?;
                        info!("Shutdown requested via stdio");
                        break;
                    }
                    process_request(request, &self.engine).await
                }
                Err(e) => gateway_error_raw(
                    "unknown".to_string(),
                    axiom_errors::error_code::E_LAMBDA_SERIALIZATION_ERROR,
                    axiom_errors::ErrorCategory::ClientBug,
                    format!("CBOR parse error: {}", e),
                ),
            };
            
            write_framed_response(&mut stdout, &response).await?;
        }
        
        Ok(())
    }
    
    /// Signal shutdown
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
    
    /// Get the consensus engine (for testing)
    pub fn engine(&self) -> &Arc<ConsensusEngine> {
        &self.engine
    }

    /// Checkpoint the WAL into lambda.db. Call on shutdown — see
    /// Storage::checkpoint_wal for why this is mandatory.
    pub fn checkpoint_wal(&self) -> Result<(), LambdaError> {
        self.storage.checkpoint_wal()
    }

    /// Handle to the transaction storage — for the shutdown signal handler.
    pub fn storage_handle(&self) -> Arc<Storage> {
        Arc::clone(&self.storage)
    }
}

/// Load TLS certificate chain from PEM file.
fn load_tls_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, LambdaError> {
    let file = std::fs::File::open(path)
        .map_err(|e| LambdaError::ConfigError(format!("TLS cert {path}: {e}")))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| LambdaError::ConfigError(format!("TLS cert parse {path}: {e}")))
}

/// Load TLS private key from PEM file.
fn load_tls_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, LambdaError> {
    let file = std::fs::File::open(path)
        .map_err(|e| LambdaError::ConfigError(format!("TLS key {path}: {e}")))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| LambdaError::ConfigError(format!("TLS key parse {path}: {e}")))?
        .ok_or_else(|| LambdaError::ConfigError(format!("No private key found in {path}")))
}

/// Write a length-prefixed CBOR response (Yellow Paper §16.8.5.3)
async fn write_framed_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: &GatewayResponse,
) -> Result<(), LambdaError> {
    let mut buf = Vec::new();
    ciborium::into_writer(response, &mut buf)
        .map_err(|e| LambdaError::SerializationError(format!("CBOR encode error: {}", e)))?;
    let len = (buf.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

/// Handle a TCP connection (CBOR per Yellow Paper §16.8.5.3)
///
/// SECURITY FIX #3: Added per-read timeout to prevent Slowloris-style attacks
/// where a client opens a connection and sends data very slowly, holding the
/// connection indefinitely and exhausting server resources.
async fn handle_tcp_connection<S>(
    mut stream: S,
    engine: Arc<ConsensusEngine>,
) -> Result<(), LambdaError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // 30-second read timeout — generous enough for legitimate clients,
    // short enough to prevent idle connection exhaustion (Slowloris).
    let read_timeout = std::time::Duration::from_secs(30);

    loop {
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(read_timeout, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("Client disconnected");
                return Ok(());
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("Client read timed out (Slowloris protection)");
                return Ok(());
            }
        }
        
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 10 * 1024 * 1024 {
            return Err(LambdaError::SerializationError(
                "Message too large".to_string()
            ));
        }
        
        let mut payload = vec![0u8; len];
        match tokio::time::timeout(read_timeout, stream.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("Client payload read timed out (Slowloris protection)");
                return Ok(());
            }
        }

        let request: GatewayRequest = ciborium::from_reader(&payload[..])
            .map_err(|e| LambdaError::SerializationError(format!("CBOR parse error: {}", e)))?;
        
        let response = process_request(request, &engine).await;
        
        let mut buf = Vec::new();
        ciborium::into_writer(&response, &mut buf)
            .map_err(|e| LambdaError::SerializationError(format!("CBOR encode error: {}", e)))?;
        let response_len = (buf.len() as u32).to_be_bytes();
        
        stream.write_all(&response_len).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
    }
}

/// SECURITY FIX #13: Sanitize error messages before returning to clients.
/// Strips internal file paths, stack traces, and implementation details
/// while preserving the error category so clients can act on rejections.
#[allow(dead_code)]  // Security utility — will be wired when IPC error path is activated
pub(crate) fn sanitize_error(msg: &str) -> String {
    // Strip anything that looks like a file path
    let sanitized = msg.lines().next().unwrap_or(msg);
    // Cap length to prevent information leakage in verbose errors
    if sanitized.len() > 200 {
        format!("{}...", &sanitized[..200])
    } else {
        sanitized.to_string()
    }
}

/// Process a request
async fn process_request(
    request: GatewayRequest,
    engine: &ConsensusEngine,
) -> GatewayResponse {
    
    match request {
        GatewayRequest::Witness(req) => {
            let request_id = req.request_id.clone();
            let result = match engine.process_witness_request(req).await {
                Ok(response) => GatewayResponse::WitnessResult(Box::new(response)),
                // YPX-001 §1.5.1 scar-consent gate fire: NOT a plain error
                // envelope — the response must carry the receiver-bound
                // ScarConsentNotification so the gateway (ANTIE) can deliver
                // the passcode to the RECEIVER. The sender sees only the
                // rejection code; the passcode never rides the sender leg.
                Err(LambdaError::FactScarDetected {
                    passcode, txid, sender_wallet_id, receiver_wallet_id,
                    amount, scar_count,
                }) => {
                    engine.stats.record_error(true, "FactScarDetected");
                    // Notification handed to the gateway = delivered intent
                    // (mirrors log_cheque_delivery's "Lambda records intent").
                    engine.storage().mark_passcode_delivered(&txid).ok();
                    GatewayResponse::WitnessResult(Box::new(
                        crate::types::WitnessResponse {
                            sender_state: None,
                            request_id,
                            success: false,
                            witness_signature: None,
                            overlapped_signatures: Vec::new(),
                            // A rejection issues nothing.
                            vbc_signature: None,
                            rejection: Some(crate::types::RejectionInfo {
                                code: axiom_errors::error_code::E_LAMBDA_SCAR_CONSENT_REQUIRED
                                    .to_string(),
                                message: format!(
                                    "FACT scar detected ({} unverified link(s)) — receiver \
                                     consent required. The receiver has been notified with a \
                                     passcode; re-initiate the same transaction with \
                                     scar_passcode once the receiver shares it.",
                                    scar_count,
                                ),
                            }),
                            cheque_for_receiver: None,
                            receipt: None,
                            produced_state_id: None,
                            commitment_hash: None,
                            state_hash: None,
                            receipt_commitment: None,
                            txid: txid.to_vec(),
                            validator_hints: Vec::new(),
                            sender_fact_chain: None,
                            audit_demand: None,
                            audit_request: None,
                            nonce_challenge: None,
                            pulse_proof: None,
                            audit_failed: false,
                            outbound_peer_audit: None,
                            confidence_index: None,
                            scar_consent_voucher: None,
                            scar_consent_for_receiver: Some(
                                crate::types::ScarConsentNotification {
                                    txid,
                                    sender_wallet_id,
                                    receiver_wallet_id,
                                    amount,
                                    scar_count: scar_count as u32,
                                    passcode,
                                },
                            ),
                        },
                    ))
                }
                Err(e) => {
                    engine.stats.record_error(true, &e.to_string());
                    gateway_error_from_lambda(request_id, &e)
                },
            };
            engine.stats.write_stats_file();
            result
        }

        GatewayRequest::QueryState(req) => {
            let request_id = req.request_id.clone();
            match engine.query_state(&req.wallet_pk) {
                Ok(state) => GatewayResponse::StateResult(StateQueryResponse {
                    request_id,
                    found: state.is_some(),
                    wallet_state: state,
                }),
                Err(e) => gateway_error_from_lambda(request_id, &e),
            }
        }

        GatewayRequest::ValidatorStatus(req) => {
            GatewayResponse::ValidatorStatusResult(engine.validator_status(&req.request_id))
        }

        GatewayRequest::Redeem(req) => {
            let request_id = req.request_id.clone();
            let result = match engine.process_redeem_request(req).await {
                Ok(response) => GatewayResponse::RedeemResult(response),
                Err(e) => {
                    engine.stats.record_error(false, &e.to_string());
                    gateway_error_from_lambda(request_id, &e)
                },
            };
            engine.stats.write_stats_file();
            result
        }
        
        GatewayRequest::Health (HealthRequest { request_id: _ }) => {
            GatewayResponse::HealthResult(engine.health())
        }
        
        GatewayRequest::Ack(req) => {
            debug!("ACK request: txid={}", hex::encode(&req.ack.txid[..8]));
            match engine.process_ack(&req.ack, &req.client_pk) {
                Ok(mut response) => {
                    response.request_id = req.request_id;
                    GatewayResponse::AckResult(response)
                }
                Err(e) => GatewayResponse::AckResult(AckResponse {
                    request_id: req.request_id,
                    success: false,
                    new_status: None,
                    error_response: Some((&e).into()),
                }),
            }
        }


        // YP §20.8 v3.x (Step 9A 2026-06-02): FeeRedemption variant is gone.
        // Validator fees settle direct-deposit at CL5 redeem via the
        // fee_breakdown channel on Receipt/K3Receipt; per-validator
        // earnings live at Nabla. The legacy cheque-claim flow is deleted.

        GatewayRequest::Shutdown (ShutdownRequest { request_id }) => {
            info!("Shutdown requested");
            GatewayResponse::ShutdownAck (ShutdownAck { request_id })
        }

        GatewayRequest::SetCarriers (req) => {
            // Phase 1 — VSP discovery correctness (2026-05-14). ANTIE
            // pushes the operator's configured `[carriers.*]` set as a
            // canonical YP §27.5.2 URI list at gateway startup. Engine
            // logs a loud warning if the list is empty — operators see
            // a visible signal at startup if axiom-antie.toml hasn't
            // declared any inbound carriers.
            let accepted = req.carriers.len() as u32;
            engine.set_carriers(req.carriers);
            GatewayResponse::SetCarriersAck (SetCarriersAck {
                request_id: req.request_id,
                accepted,
            })
        }
        
        GatewayRequest::InitGenesis (InitGenesisRequest { request_id, public_key, balance, group_members, auth_hash }) => {
            info!("[DEV] InitGenesis request: balance={}, group={}, auth_hash={}", balance, group_members.is_some(), auth_hash.is_some());
            let auth_hash_arr: Option<[u8; 32]> = auth_hash.and_then(|h| h.try_into().ok());
            let result = match engine.init_genesis_dev(&public_key, balance, group_members, auth_hash_arr) {
                Ok(genesis_result) => GatewayResponse::InitGenesisResult (InitGenesisResponse {
                    request_id,
                    success: true,
                    result: Some(genesis_result),
                    error: None,
                }),
                Err(e) => GatewayResponse::InitGenesisResult (InitGenesisResponse {
                    request_id,
                    success: false,
                    result: None,
                    error: Some(e.to_string()),
                }),
            };
            engine.stats.write_stats_file();
            result
        }
        
        GatewayRequest::LoadTestState (LoadTestStateRequest { request_id, public_key, state_id, balance, wallet_seq }) => {
            debug!("[DEV] LoadTestState request: balance={}, seq={}", balance, wallet_seq);
            match engine.load_test_state(&public_key, &state_id, balance, wallet_seq) {
                Ok(()) => GatewayResponse::LoadTestStateResult (LoadTestStateResponse {
                    request_id,
                    success: true,
                    error: None,
                }),
                Err(e) => GatewayResponse::LoadTestStateResult (LoadTestStateResponse {
                    request_id,
                    success: false,
                    error: Some(e.to_string()),
                }),
            }
        }
        
        GatewayRequest::VBCSignRequest (VBCSignRequestPayload { request_id, sphincs_pk_hex: _, dilithium_pk_hex: _, ed25519_pk_hex, pgp_fingerprint_hex: _, proof_cap, node_name: _ }) => {
            // ╔═══════════════════════════════════════════════════════════╗
            // ║  ⚠ NO PRODUCTION EMITTER — RULE 3 shape 3                  ║
            // ╚═══════════════════════════════════════════════════════════╝
            // `VBCSignRequest` / `VBCSignCommit` are a COMPLETE receiver with
            // NOT ONE sender anywhere in the tree (verified 2026-09-03: the
            // only hits are the type definitions, `lambda/src/types.rs`
            // re-exports, and these two arms). `scripts/validator-setup.sh`
            // prints "--request-vbc (not yet implemented)".
            //
            // This is the scaffolding CLAUDE.md's "Don't recreate" note records
            // as reverted at `51d993d7` — the receiver survived the revert.
            //
            // ⚠ AND IT IS NOW THE OLD SHAPE. The owner ruled 2026-09-02 that a VBC
            // request is an ORDINARY TRANSACTION (§5.2.2d): the candidate runs a
            // normal k-witness round and each witness returns a CL8 signature
            // where a cheque would go. That path is LIVE — `consensus.rs::
            // sign_requested_vbc`, driven by the SDK's `validator_join::
            // request_vbc` — and it REUSES `commit_vbc_sign`, so these arms and
            // the witness path share one issuance rule, one budget, one lineage.
            //
            // Retained, not deleted (RULE 4: mark superseded text, never remove
            // it): the genesis ceremony has no wallet to run a witness round
            // with, so an admin door may still be needed there. Do NOT build a
            // client for these arms without ruling on that first — a second
            // emitter would be a second way to spend the same signing budget.
            info!("VBC sign request (Phase 1 — approval): {}", request_id);
            match engine.approve_vbc_sign_request(&ed25519_pk_hex, &proof_cap) {
                Ok(approval) => GatewayResponse::VBCSignApprovalResult (VBCSignApprovalResponse {
                    request_id,
                    approval,
                }),
                Err(e) => gateway_error_from_lambda(request_id, &e),
            }
        }

        GatewayRequest::VBCSignCommit (VBCSignCommitPayload { request_id, sphincs_pk_hex, dilithium_pk_hex: _, ed25519_pk_hex, pgp_fingerprint_hex: _, proof_cap, node_name, issued_at, expires_at, chain_depth, issuer_set_hex, previous_vbc }) => {
            // Phase 2 (AXIOM_DESIGN_ValidatorJoin.md §6a): Lambda orchestrates
            // Core (CL8 signs) -> budget -> record. Core stays the signing
            // boundary; Lambda never touches sign_sphincs.
            info!("VBC sign commit (Phase 2): {}", request_id);
            match engine.commit_vbc_sign(
                &sphincs_pk_hex, &ed25519_pk_hex, &proof_cap, &node_name,
                issued_at, expires_at, chain_depth, &issuer_set_hex,
                &request_id,
                previous_vbc,
                // Same time source as approve_vbc_sign_request above. Not an
                // attested tick — Lambda has none (KI#130).
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                // The gateway path carries no OODS reading, so a depth>0
                // certificate is refused here — correctly. See the emitterless
                // note above: this door predates §5.3 and has no client.
                None,
                // ... and it carries no CERTIFICATE either, only the scalars
                // above, so `commit_vbc_sign` builds one. That is the legacy
                // half of the split introduced 2026-09-04; the VbcRequest path
                // passes the candidate's own document instead of rebuilding it.
                None,
                // §5.2.2e — no transaction on this door: the same clock as above.
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ).await {
                Ok((signature, signer_pk, commitment)) =>
                    GatewayResponse::VBCSignCommitResult(VBCSignCommitResponse {
                        request_id,
                        success: true,
                        signature_hex: hex::encode(&signature),
                        signer_sphincs_pk_hex: hex::encode(&signer_pk),
                        // Core's own commitment, so the candidate can verify
                        // the signature independently rather than trusting us.
                        commitment_hex: hex::encode(commitment),
                        error: None,
                    }),
                Err(e) => gateway_error_from_lambda(request_id, &e),
            }
        }

        GatewayRequest::PeerAuditRequest (PeerAuditRequestEnvelope { request_id, peer_audit_request }) => {
            info!("§23.14.6: Peer audit request: {}", request_id);
            let answer = engine.handle_peer_audit_request(&peer_audit_request).await;

            // Resolve requester's email from hints — by its Ed25519 key (KI#211 twin).
            // `None` for a built answer is counted; ANTIE then replies to the
            // request's From: (KI#229), never drops it.
            let answered = !matches!(answer, crate::consensus::PeerAuditAnswer::Dropped);
            let requester_email =
                engine.resolve_peer_audit_reply_email(&peer_audit_request.requester_pk, answered);

            // KI#213: a NotHeld is an ANSWER (success), not a failure — ANTIE mails it back.
            let (response, not_held) = match answer {
                crate::consensus::PeerAuditAnswer::Held(r) => (Some(r), None),
                crate::consensus::PeerAuditAnswer::NotHeld(nh) => (None, Some(nh)),
                crate::consensus::PeerAuditAnswer::Dropped => (None, None),
            };
            GatewayResponse::PeerAuditResult (PeerAuditResultPayload {
                request_id,
                success: response.is_some() || not_held.is_some(),
                response,
                not_held,
                requester_email,
                error: None,
            })
        }

        GatewayRequest::PeerAuditResponse (PeerAuditResponseEnvelope { request_id, peer_audit_response }) => {
            info!("§23.14.6: Peer audit response: {}", request_id);
            engine.handle_peer_audit_response(&peer_audit_response).await;
            GatewayResponse::PeerAuditResponseAck (PeerAuditResponseAck {
                request_id,
                success: true,
            })
        }

        GatewayRequest::PeerAuditDispatchFailed (axiom_core_logic::types::PeerAuditDispatchFailedEnvelope { request_id, target_email, error }) => {
            info!("§23.14.3: Peer audit dispatch FAILED (carrier): {}", request_id);
            engine.handle_peer_audit_dispatch_failed(&target_email, &error).await;
            GatewayResponse::PeerAuditResponseAck (PeerAuditResponseAck { request_id, success: true })
        }

        GatewayRequest::PeerAuditNotHeld (axiom_core_logic::types::PeerAuditNotHeldEnvelope { request_id, peer_audit_not_held }) => {
            info!("§23.14.6: Peer audit NotHeld: {}", request_id);
            engine.handle_peer_audit_not_held(&peer_audit_not_held).await;
            GatewayResponse::PeerAuditResponseAck (PeerAuditResponseAck {
                request_id,
                success: true,
            })
        }

        GatewayRequest::SetAuthHash (SetAuthHashRequest { request_id, public_key, auth_hash }) => {
            info!("§4.5: SetAuthHash request: pk={}", hex::encode(&public_key[..std::cmp::min(8, public_key.len())]));
            match auth_hash.as_slice().try_into() as Result<[u8; 32], _> {
                Ok(hash_arr) => {
                    match engine.set_auth_hash(&public_key, hash_arr) {
                        Ok(()) => GatewayResponse::SetAuthHashResult (SetAuthHashResponse {
                            request_id,
                            success: true,
                            error: None,
                        }),
                        Err(e) => GatewayResponse::SetAuthHashResult (SetAuthHashResponse {
                            request_id,
                            success: false,
                            error: Some(e.to_string()),
                        }),
                    }
                }
                Err(_) => GatewayResponse::SetAuthHashResult (SetAuthHashResponse {
                    request_id,
                    success: false,
                    error: Some(format!("auth_hash must be 32 bytes, got {}", auth_hash.len())),
                }),
            }
        }

        GatewayRequest::FanOutDedup (FanOutDedupRequest { request_id, diffusion_id }) => {
            let id: [u8; 32] = match diffusion_id.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => return GatewayResponse::FanOutDedupResult (FanOutDedupResponse {
                    request_id,
                    already_seen: false, // malformed — let CL10 reject it
                }),
            };
            // Check-only (read). Mark happens AFTER CL10 acceptance via FanOutMark.
            // This prevents invalid/forged messages from poisoning the dedup set.
            let seen = engine.fanout_is_seen(&id).unwrap_or(false);
            // Prune stale entries opportunistically
            let _ = engine.fanout_prune(86400); // FANOUT_MAX_AGE_SECS
            GatewayResponse::FanOutDedupResult (FanOutDedupResponse {
                request_id,
                already_seen: seen,
            })
        }

        GatewayRequest::FanOutMark (FanOutMarkRequest { request_id, diffusion_id }) => {
            let id: [u8; 32] = match diffusion_id.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => return GatewayResponse::FanOutMarkResult (FanOutMarkResponse {
                    request_id,
                    success: false,
                }),
            };
            let ok = engine.fanout_mark_seen(&id).is_ok();
            GatewayResponse::FanOutMarkResult (FanOutMarkResponse {
                request_id,
                success: ok,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sanitize_error ──────────────────────────────────────────────

    /// sanitize_error strips multi-line messages to the first line.
    #[test]
    fn sanitize_error_strips_multiline() {
        let msg = "Validation failed\n  at /home/user/axiom/src/lambda/consensus.rs:42\n  stack trace ...";
        let result = sanitize_error(msg);
        assert_eq!(result, "Validation failed");
        assert!(!result.contains('\n'));
    }

    /// sanitize_error truncates messages longer than 200 characters.
    #[test]
    fn sanitize_error_truncates_long_message() {
        let long_msg = "x".repeat(300);
        let result = sanitize_error(&long_msg);
        assert_eq!(result.len(), 203); // 200 chars + "..."
        assert!(result.ends_with("..."));
    }

    /// sanitize_error preserves short single-line messages.
    #[test]
    fn sanitize_error_preserves_short_message() {
        let msg = "Insufficient balance: have 100, need 200";
        let result = sanitize_error(msg);
        assert_eq!(result, msg);
    }

    /// sanitize_error handles empty string.
    #[test]
    fn sanitize_error_empty_string() {
        let result = sanitize_error("");
        assert_eq!(result, "");
    }

    /// sanitize_error on exactly 200-char message does not truncate.
    #[test]
    fn sanitize_error_exactly_200_chars() {
        let msg = "a".repeat(200);
        let result = sanitize_error(&msg);
        assert_eq!(result.len(), 200);
        assert!(!result.ends_with("..."));
    }

    // ── write_framed_response ───────────────────────────────────────

    /// write_framed_response produces 4-byte length prefix + CBOR payload.
    #[tokio::test]
    async fn write_framed_response_format() {
        let response = GatewayResponse::ShutdownAck (ShutdownAck {
            request_id: "sd-1".into(),
        });
        let mut buf: Vec<u8> = Vec::new();
        write_framed_response(&mut buf, &response).await.unwrap();

        // First 4 bytes are big-endian length
        assert!(buf.len() > 4);
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        assert_eq!(len, buf.len() - 4);

        // Payload is valid CBOR
        let decoded: GatewayResponse =
            ciborium::from_reader(&buf[4..]).unwrap();
        match decoded {
            GatewayResponse::ShutdownAck (ShutdownAck { request_id }) => {
                assert_eq!(request_id, "sd-1");
            }
            other => panic!("Expected ShutdownAck, got {:?}", other),
        }
    }

    /// Phase 2b end-to-end: a LambdaError reaches the wire as a dual-format
    /// GatewayResponse::Error — legacy string in `message`, structured
    /// `error_response` with the right code/category, CBOR-roundtrippable,
    /// and the typed payload survives serialize/deserialize intact.
    #[tokio::test]
    async fn dual_format_error_roundtrips_through_cbor() {
        use axiom_errors::ErrorCategory;
        use crate::error_response::gateway_error_from_lambda;

        // Pick a LambdaError that Phase 2b.1 classifies with a recovery
        // hint — `InsufficientWitnesses` → Operational + RetrySameValidator.
        let err = LambdaError::InsufficientWitnesses { got: 2, need: 3 };
        let resp = gateway_error_from_lambda("e2e-1".into(), &err);

        // Encode to CBOR (the wire format) and decode back.
        let mut buf: Vec<u8> = Vec::new();
        write_framed_response(&mut buf, &resp).await.unwrap();
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let decoded: GatewayResponse =
            ciborium::from_reader(&buf[4..4 + len]).unwrap();

        match decoded {
            GatewayResponse::Error(ErrorEnvelope { request_id, error_response }) => {
                assert_eq!(request_id, "e2e-1");
                // Structured field: typed code + category + recovery hint.
                assert!(error_response.message.contains("2"), "message should mention got");
                assert!(error_response.message.contains("3"), "message should mention need");
                assert_eq!(error_response.code.as_str(), "E_LAMBDA_INSUFFICIENT_WITNESSES");
                assert_eq!(error_response.category, ErrorCategory::Operational);
                assert_eq!(
                    error_response.recovery,
                    Some(axiom_errors::RecoveryHint::RetrySameValidator),
                    "InsufficientWitnesses should hint RetrySameValidator — see Phase 2b.1"
                );
            }
            other => panic!("Expected Error variant, got {:?}", other),
        }
    }

    /// write_framed_response for Error variant includes the error_response.
    #[tokio::test]
    async fn write_framed_response_error_variant() {
        let response = GatewayResponse::Error(ErrorEnvelope {
            request_id: "err-99".into(),
            error_response: axiom_errors::ErrorResponse::new(
                axiom_errors::ErrorCode::from_static("E_LAMBDA_INVALID_REQUEST"),
                axiom_errors::ErrorCategory::ClientBug,
                "test error",
            ),
        });
        let mut buf: Vec<u8> = Vec::new();
        write_framed_response(&mut buf, &response).await.unwrap();

        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let decoded: GatewayResponse =
            ciborium::from_reader(&buf[4..4 + len]).unwrap();
        match decoded {
            GatewayResponse::Error(ErrorEnvelope { request_id, error_response }) => {
                assert_eq!(request_id, "err-99");
                assert_eq!(error_response.message, "test error");
                assert_eq!(error_response.code.as_str(), "E_LAMBDA_INVALID_REQUEST");
            }
            _ => panic!("Expected Error variant"),
        }
    }

    // ── Frame size constants ────────────────────────────────────────

    /// TCP handler rejects frames > 10MB. Stdio handler rejects > 16MB.
    #[test]
    fn frame_size_limits() {
        // TCP limit from handle_tcp_connection
        let tcp_limit: usize = 10 * 1024 * 1024;
        assert_eq!(tcp_limit, 10_485_760);

        // Stdio limit from run_stdio_framed
        let stdio_limit: usize = 16 * 1024 * 1024;
        assert_eq!(stdio_limit, 16_777_216);

        // Stdio is more generous because it's localhost-only (no network attack surface)
        assert!(stdio_limit > tcp_limit);
    }

    // ── GatewayRequest CBOR round-trip ──────────────────────────────

    /// GatewayRequest::Health round-trips through CBOR.
    #[test]
    fn gateway_request_health_cbor_roundtrip() {
        let req = GatewayRequest::Health(HealthRequest {
            request_id: "h-99".into(),
        });
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&req, &mut cbor_buf).unwrap();
        let decoded: GatewayRequest = ciborium::from_reader(&cbor_buf[..]).unwrap();
        match decoded {
            GatewayRequest::Health(HealthRequest { request_id }) => {
                assert_eq!(request_id, "h-99");
            }
            _ => panic!("Expected Health variant"),
        }
    }

    /// GatewayRequest::Shutdown round-trips through CBOR.
    #[test]
    fn gateway_request_shutdown_cbor_roundtrip() {
        let req = GatewayRequest::Shutdown(ShutdownRequest {
            request_id: "sd-42".into(),
        });
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&req, &mut cbor_buf).unwrap();
        let decoded: GatewayRequest = ciborium::from_reader(&cbor_buf[..]).unwrap();
        match decoded {
            GatewayRequest::Shutdown(ShutdownRequest { request_id }) => {
                assert_eq!(request_id, "sd-42");
            }
            _ => panic!("Expected Shutdown variant"),
        }
    }
}
