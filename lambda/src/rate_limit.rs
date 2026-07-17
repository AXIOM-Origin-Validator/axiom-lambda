//! Per-IP sliding-window rate limiter for Lambda TCP connections.
//!
//! The implementation lives in the shared `axiom-rate-limit` crate so
//! Lambda and ANTIE share one source instead of byte-identical copies.
//! Re-exported here so `crate::rate_limit::RateLimiter` keeps resolving.

pub use axiom_rate_limit::RateLimiter;
