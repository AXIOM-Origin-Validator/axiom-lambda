//! AXIOM Lambda - k=3 Consensus Engine
//!
//! Lambda is the consensus logic engine for AXIOM validators.
//!
//! # Usage
//!
//! ```bash
//! # Default: stdio-framed mode (CBOR, for subprocess/development)
//! lambda --config config.toml
//!
//! # Socket mode (for distributed deployment)
//! lambda --config config.toml --listen 127.0.0.1:9000
//!
//! # Production mode (real RISC Zero ZKP)
//! lambda --config config.toml --production
//! ```
//!
//! # Communication Modes
//!
//! - **stdio-framed (default)**: Length-prefixed CBOR frames on stdin/stdout
//!   (Yellow Paper §16.8.5.3). Best for subprocess mode where Gateway spawns Lambda.
//!
//! - **socket (--listen)**: TCP server with CBOR framing for distributed deployment
//!   where Gateway and Lambda run on different machines.
//!
//! # Production Mode
//!
//! Production mode generates real RISC Zero ZK proofs for CL3 witness production.
//! Requires zkVM artifacts to be built and placed at:
//! - ~/.axiom/zkvm/axiom-core.elf (RISC-V ELF binary)
//! - ~/.axiom/zkvm/image-id.hex (32-byte program digest)
//!
//! To build zkVM artifacts:
//! ```bash
//! # Install RISC Zero toolchain
//! curl -L https://risczero.com/install | bash
//! rzup install
//!
//! # Build the guest
//! cd axiom-core
//! ./build-zkvm.sh
//! ```

use axiom_lambda::LambdaConfig;
use axiom_lambda::server::LambdaServer;
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::PathBuf;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "lambda")]
#[command(about = "AXIOM Lambda - k=3 Consensus Engine")]
struct Args {
    /// Config file path
    #[arg(short, long)]
    config: Option<PathBuf>,
    
    /// Listen address for TCP/socket mode (e.g., 127.0.0.1:9000)
    /// By default, Lambda uses stdio-framed mode.
    /// Use this flag to enable socket mode for distributed deployment.
    #[arg(long)]
    listen: Option<String>,
    
    /// Transaction database path (SQLCipher encrypted)
    #[arg(long)]
    transaction_db: Option<PathBuf>,

    /// Management database path (SQLCipher encrypted)
    #[arg(long)]
    management_db: Option<PathBuf>,
    
    /// Private key file path
    #[arg(long)]
    private_key: Option<PathBuf>,
    
    /// Generate new private key
    #[arg(long)]
    generate_key: bool,
    
    /// [DEPRECATED] Production mode is now always enabled.
    /// This flag is accepted for backwards compatibility but has no effect.
    #[arg(long, hide = true)]
    production: bool,
    
    /// Maximum validator hints to store (default: 1024)
    #[arg(long)]
    max_hints: Option<usize>,

    /// Admin HTTP port for validator console (e.g., 7780).
    /// Binds to 127.0.0.1 only. Disabled by default.
    #[arg(long)]
    admin_port: Option<u16>,

    /// Bearer token for admin endpoint authentication.
    /// If set, all admin endpoints except /health require ?token=<value>.
    #[arg(long)]
    admin_token: Option<String>,
    
    /// Allow init_genesis_dev and load_test_state requests (E2E testing only).
    /// WARNING: Never use in production — bypasses real Genesis validator signatures.
    #[arg(long)]
    allow_test_genesis: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Decorative boot charm. TTY-gated, no-op under systemd/journald.
    // Lives in axiom-denomination so every native binary that links
    // the AXC/L$/atom conversion lib also gets the canary — see
    // denomination/src/lib.rs. Purely for luck; zero functional effect.
    axiom_denomination::print_if_tty("lambda");

    // ── FIRST: verify this environment has 64-bit unix time (§31.3) ──
    // If this fails, Lambda refuses to start. Core is the sole authority
    // for platform safety — since Lambda executes core-logic directly
    // via AVM (no core-bin subprocess), the check must run here.
    axiom_core_logic::verify_time_safety();

    // KI#23 mitigation — periodic glibc malloc_trim + SIGUSR1 handler.
    // See axiom_lambda::malloc_trim for the why. Combined with the
    // MALLOC_ARENA_MAX=2 env var that axiom-env.py sets on spawn.
    axiom_lambda::malloc_trim::spawn_periodic();
    let _ = axiom_lambda::malloc_trim::install_sigusr1_handler();

    let args = Args::parse();

    // Set env var for test genesis if flag is passed
    if args.allow_test_genesis {
        std::env::set_var("AXIOM_ALLOW_TEST_GENESIS", "1");
        eprintln!("[WARN] --allow-test-genesis enabled. DO NOT use in production.");
    }
    
    // log → tracing bridge: tracing-subscriber 0.3 with the default
    // `tracing-log` feature calls `LogTracer::init()` automatically
    // inside `.init()` below. An explicit LogTracer::init() here would
    // double-install the global log dispatcher and panic .init() with
    // SetLoggerError. Rely on the auto-install.

    // Initialize logging (skip for stdio mode to keep output clean)
    // Socket mode can use logging since it's separate from data channel
    let use_stdio = args.listen.is_none();
    // Default filter — applied when RUST_LOG isn't set. Always silences
    // Cranelift's JIT internals (CLIF IR dumps, regalloc traces) which
    // generated ~90MB per validator per minute under normal traffic
    // before this was tightened (Linux soak finding 2026-05-11). The
    // JIT crates remain useful at WARN+ for compile failures, but
    // their info/debug-level chatter is operational noise we don't
    // want filling lambda.log during long soaks.
    let default_filter = if use_stdio {
        "warn,cranelift=off,cranelift_codegen=off,cranelift_jit=off,cranelift_frontend=off,cranelift_module=off,regalloc2=off,wasmtime=off,wasmtime_jit=off"
    } else {
        // Non-stdio mode honours --log-level for axiom_lambda itself,
        // but still silences the JIT crates.
        // (EnvFilter::new accepts a directive string with comma-
        // separated target=level pairs.)
        // Caller can override via RUST_LOG to bring them back.
        Box::leak(format!(
            "{},cranelift=off,cranelift_codegen=off,cranelift_jit=off,cranelift_frontend=off,cranelift_module=off,regalloc2=off,wasmtime=off,wasmtime_jit=off",
            args.log_level,
        ).into_boxed_str())
    };
    if !use_stdio {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(default_filter));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .init();

        info!("AXIOM Lambda v{}", env!("CARGO_PKG_VERSION"));
    } else {
        // Minimal logging for stdio mode (to stderr — the subprocess
        // path used by ANTIE; lands in lambda.log via the AXIOM_LAMBDA_LOG
        // redirect set up in antie/src/lambda_client.rs).
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(default_filter));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }
    
    // Load or create config
    let mut config = if let Some(config_path) = &args.config {
        LambdaConfig::from_file(config_path.to_str()
            .ok_or_else(|| anyhow::anyhow!("Config path contains invalid UTF-8"))?)?
    } else {
        LambdaConfig::default()
    };
    
    // Override with command line args
    if let Some(ref listen) = args.listen {
        config.network.listen = listen.clone();
    }
    if let Some(transaction_db) = args.transaction_db {
        config.storage.transaction_db = transaction_db;
    }
    if let Some(management_db) = args.management_db {
        config.storage.management_db = management_db;
    }
    if let Some(private_key) = args.private_key {
        config.validator.private_key_path = private_key;
    }
    if let Some(max_hints) = args.max_hints {
        config.storage.max_hints = max_hints;
    }
    if let Some(admin_port) = args.admin_port {
        config.admin_port = Some(admin_port);
    }
    if let Some(admin_token) = args.admin_token {
        config.admin_token = Some(admin_token);
    }
    
    // Create storage directories
    if let Some(parent) = config.storage.transaction_db.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = config.storage.management_db.parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    // Load or generate signing key
    let signing_key = if args.generate_key {
        let key = SigningKey::generate(&mut OsRng);
        info!("Generated new signing key");
        
        // Optionally save it
        if let Some(parent) = config.validator.private_key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&config.validator.private_key_path, key.to_bytes())?;
        // S4: Restrict private key file to owner-only (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &config.validator.private_key_path,
                std::fs::Permissions::from_mode(0o600),
            )?;
        }
        info!("Saved key to {:?}", config.validator.private_key_path);
        
        key
    } else if config.validator.private_key_path.exists() {
        let bytes = std::fs::read(&config.validator.private_key_path)?;
        if bytes.len() != 32 {
            error!("Invalid private key file (expected 32 bytes)");
            return Err("Invalid private key".into());
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        SigningKey::from_bytes(&key_bytes)
    } else {
        // Generate ephemeral key for development
        info!("No private key found, generating ephemeral key");
        SigningKey::generate(&mut OsRng)
    };
    
    let public_key = ed25519_dalek::VerifyingKey::from(&signing_key);
    // Only log if NOT using stdio (socket mode can log freely)
    if !use_stdio {
        info!("Validator public key: {}", hex::encode(public_key.as_bytes()));
    }
    
    // Create server — always production mode (real ZKP, no dev fallback)
    info!("Starting Lambda (real RISC Zero ZKP)");
    let server = match LambdaServer::new(config, signing_key) {
        Ok(s) => s,
        Err(e) => {
            // Fail-stop: zkVM artifacts MUST be available. No fallback.
            eprintln!("[FATAL] Lambda startup failed: {}", e);
            eprintln!("zkVM artifacts required. To set up:");
            eprintln!("  1. Install RISC Zero: curl -L https://risczero.com/install | bash && rzup install");
            eprintln!("  2. Build zkvm-guest: cd axiom-core && ./build-zkvm.sh");
            eprintln!("  3. Artifacts should be in ~/.axiom/zkvm/");
            std::process::exit(1);
        }
    };
    
    // Graceful-shutdown signal handler (SIGINT + SIGTERM). On either signal,
    // checkpoint the WAL into lambda.db before exiting — without it the
    // un-checkpointed WAL is dropped on connection close and the validator
    // silently reverts to a stale state on restart.
    {
        let sig_storage = server.storage_handle();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                match signal(SignalKind::terminate()) {
                    Ok(mut sigterm) => {
                        tokio::select! {
                            _ = tokio::signal::ctrl_c() => info!("SIGINT received, shutting down"),
                            _ = sigterm.recv() => info!("SIGTERM received, shutting down"),
                        }
                    }
                    Err(e) => {
                        error!("SIGTERM handler install failed ({}); SIGINT only", e);
                        tokio::signal::ctrl_c().await.ok();
                        info!("SIGINT received, shutting down");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.ok();
                info!("Ctrl+C received, shutting down");
            }
            match sig_storage.checkpoint_wal() {
                Ok(()) => info!("WAL checkpointed on shutdown signal"),
                Err(e) => error!("WAL checkpoint on signal FAILED: {} — data-loss risk", e),
            }
            std::process::exit(0);
        });
    }

    // Run in appropriate mode
    // DEFAULT: stdio-framed (for subprocess/development)
    // OPTIONAL: --listen for socket mode (distributed deployment)
    let run_result = if let Some(ref addr) = args.listen {
        info!("Mode: socket (listening on {})", addr);
        server.run().await
    } else {
        info!("Mode: stdio-framed (default)");
        server.run_stdio_framed().await
    };

    // The run loop also exits on stdin EOF — how the env stops Lambda (it
    // kills Lambda's ANTIE parent, which delivers no signal here). So this
    // path, not only the signal handler, must checkpoint the WAL.
    match server.checkpoint_wal() {
        Ok(()) => info!("WAL checkpointed on shutdown"),
        Err(e) => error!("WAL checkpoint on shutdown FAILED: {} — data-loss risk", e),
    }

    info!("Lambda shutdown complete");
    run_result?;
    Ok(())
}
