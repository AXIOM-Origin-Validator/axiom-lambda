//! YPX-002 P6 — simulated network-delay injection for local soak runs.
//!
//! Async sibling of `axiom_nabla::sim_delay`. Same env var
//! (`AXIOM_SIM_NET_DELAY_MAX_MS`), same contract: zero-cost when unset
//! or `0`, otherwise sleeps a uniform-random `[0, max]` ms at ingress
//! points so a single-machine dev env approximates cross-WAN latency.
//!
//! Uses `tokio::time::sleep` instead of `std::thread::sleep` because
//! Lambda's request handlers (`process_witness_request`,
//! `process_redeem_request`) run on the shared Tokio executor. A
//! blocking sleep would park a worker thread and starve every other
//! request on that worker until it woke. `tokio::time::sleep` yields
//! to the executor so other tasks continue while the simulated
//! latency is waiting.
//!
//! Call sites (inserted at the top of each async entry so every
//! request pays its own simulated latency):
//!   - `ConsensusEngine::process_witness_request`
//!   - `ConsensusEngine::process_redeem_request`
//!
//! The sample is drawn inside the async function rather than outside
//! because Rust async blocks capture their local state — hoisting
//! the sleep into the caller would just move the blocker around.

use std::sync::OnceLock;
use std::time::Duration;

static MAX_MS: OnceLock<u64> = OnceLock::new();

fn max_ms() -> u64 {
    *MAX_MS.get_or_init(|| {
        std::env::var("AXIOM_SIM_NET_DELAY_MAX_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    })
}

/// Async simulated ingress delay. Yields the Tokio executor while
/// waiting so other requests on the same worker are not blocked.
pub async fn maybe_sim_delay() {
    let max = max_ms();
    if max == 0 {
        return;
    }
    use rand::Rng;
    let ms = rand::thread_rng().gen_range(0..=max);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_by_default_is_zero_cost() {
        let t0 = std::time::Instant::now();
        for _ in 0..10_000 {
            maybe_sim_delay().await;
        }
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "disabled sim_delay should be ~free: took {:?}", elapsed,
        );
    }
}
