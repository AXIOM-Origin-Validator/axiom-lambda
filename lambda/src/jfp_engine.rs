//! JFP Engine — Judicial Freeze Protocol (§7-9)
//!
//! REDESIGNED (2026-03-23): JFP voting uses standard k=3 wallet TXs + Nabla
//! secrets instead of custom voting infrastructure. See Yellow Paper §8.4.
//!
//! # Architecture
//!
//! JFP functions live on `DwpEngine` because DWP and JFP share the same
//! ManagementDb and are part of the same lifecycle (DWP query → JFP vote → SCAR).
//! This module re-exports and documents the JFP-specific functions.
//!
//! # JFP Functions (implemented in dwp_engine.rs)
//!
//! - `DwpEngine::record_vote_tx()` — Record a k=3 witnessed vote TX (PWV verified)
//! - `DwpEngine::compute_jfp_result()` — Match vote hashes against Nabla secrets
//!   → APPROVED (unanimity) / REJECTED (any NO) / FAILED (missing secrets)
//! - `DwpEngine::compute_random_votes()` — Deterministic RANDOM for offline voters
//!   (BLAKE3 entropy from voting_end_tick, unpredictable before deadline)
//! - `DwpEngine::get_group_wallet_key()` — Derive group wallet keypair for distribution
//!
//! # Admin API Endpoints (implemented in admin.rs)
//!
//! - `POST /dwp/vote` — Record vote TX (voter_pk + vote_hash, PWV verified)
//! - `GET /jfp/result?wallet_id=&secrets=` — Compute result from hashes + secrets
//! - `POST /jfp/scar` — Register SCAR on Nabla after APPROVED result
//! - `GET /dwp/detail?wallet_id=` — Full wallet info + case log for voting decision
//!
//! # Nabla Operations (implemented in nabla_node.rs)
//!
//! TCP-CBOR `WireMessage` wire (Phase 3c migration — the legacy
//! `POST /jfp-secret` / `GET /jfp-secrets` HTTP endpoints are gated
//! `410 Gone`):
//!
//! - `WireMessage::JfpSecretRequest` — Register unnamed vote secret
//!   (gossip-propagated)
//! - `WireMessage::JfpSecretsRequest` — Query secrets for result
//!   computation
//!
//! # Consensus Integration (consensus.rs)
//!
//! Vote TXs to `DWP/` addresses are auto-detected after k=3 witness.
//! Lambda extracts vote_hash from reference field and calls `record_vote_tx()`.
//!
//! # Vote Flow
//!
//! 1. DWP wallet created (1 AXC group wallet, PWV set determined)
//! 2. Group wallet key distributed to PWV members via ANTIE email
//! 3. Each PWV member sends 1-atom TX to DWP/ address with BLAKE3(vote||secret)
//! 4. Each PWV member registers secret on Nabla
//!    (`WireMessage::JfpSecretRequest` over TCP, unnamed)
//! 5. After all votes: match secrets against hashes (any validator, deterministic)
//! 6. If APPROVED: register SCAR on Nabla → target wallet SCARRED in FACT
//!
//! # Three Outcomes
//!
//! - APPROVED: all k×5 votes YES (unanimity) → SCAR registered
//! - REJECTED: any vote NO → no action
//! - FAILED: silence (online but no vote) or missing secret → no consensus
//!
//! # Why Not a Separate Engine
//!
//! The old design (pre-2026-03-23) had a separate JfpEngine with custom
//! jfp_votes table, admin voting endpoints, and cross-validator sync.
//! This was removed because it duplicated functionality already provided
//! by k=3 wallet TXs + Nabla gossip. See YP §8.4.1 for full rationale.
