//! KI#23 mitigation — periodic `malloc_trim(0)` + SIGUSR1 handler.
//! See `antie/src/malloc_trim.rs` for the full rationale; this is the
//! same shape duplicated into Lambda. Distinct env-var name so
//! operators can tune the two independently.

use tracing::{debug, info};

const DEFAULT_INTERVAL_SECS: u64 = 60;

#[cfg(target_os = "linux")]
pub fn trim() -> i32 {
    unsafe { libc::malloc_trim(0) }
}

#[cfg(not(target_os = "linux"))]
pub fn trim() -> i32 {
    0
}

pub fn spawn_periodic() -> Option<tokio::task::JoinHandle<()>> {
    let secs = std::env::var("LAMBDA_MALLOC_TRIM_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    if secs == 0 {
        info!("malloc_trim: periodic task disabled (interval=0)");
        return None;
    }
    info!("malloc_trim: periodic task every {secs}s");
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs));
        tick.tick().await;
        loop {
            tick.tick().await;
            let released = trim();
            debug!("malloc_trim: periodic call returned {released}");
        }
    }))
}

#[cfg(target_os = "linux")]
pub fn install_sigusr1_handler() -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut stream = signal(SignalKind::user_defined1())?;
    tokio::spawn(async move {
        loop {
            stream.recv().await;
            let released = trim();
            info!("malloc_trim: SIGUSR1 triggered, returned {released}");
        }
    });
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn install_sigusr1_handler() -> std::io::Result<()> {
    Ok(())
}
