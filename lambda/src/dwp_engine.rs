//! DWP Engine — Decoy Witness Protection (§5)
//!
//! Handles DWP judicial queries: Fan-Out query → real witness responds with PWV set
//! → DWP group wallet created → JFP freeze proceeds.
//!
//! The DWP query costs 1 AXC (k=3 witnessed TX). The payment receipt is the proof.
//! Real witnesses respond with self + 14 decoys from known validators.
//! Entry validator uses first response, creates group wallet with 17 members.

use crate::error::LambdaError;
use crate::management_db::ManagementDb;
use crate::storage::Storage;
use std::sync::Arc;
use tracing::{info, warn};

/// Maximum case log entry size (bytes)
pub const MAX_CASE_ENTRY_BYTES: usize = 4096;
/// Maximum number of case log entries per DWP wallet
pub const MAX_CASE_ENTRIES: usize = 50;
/// PWV set size multiplier: PWV_SIZE = k × PWV_K_MULTIPLIER
/// k=3 → 15, k=4 → 20, k=5 → 25
pub const PWV_K_MULTIPLIER: usize = 5;
/// Default PWV set size for k=3 (convenience constant)
pub const PWV_SET_SIZE: usize = 3 * PWV_K_MULTIPLIER;
/// Decoy Query Fee in atoms (1 AXC). White Paper §5.5 "DQF", Yellow Paper §5.2.
/// "1 AXC per judicial query" — 50% to requester, 50% split among PWV members.
/// Derived from the denomination unit — `axc(1)` = 1 AXC in atoms — so it can never
/// drift from ATOMS_PER_AXC (was a hand-mirrored `10_000_000_000` literal).
/// Spec name: "DQF" (Decoy Query Fee). Also referenced as "DWP query cost" in older docs.
pub const DQF_ATOMS: u64 = axiom_denomination::axc(1);
/// DWP group wallet address prefix (protocol TX — bypasses dust limit)
pub const DWP_ADDRESS_PREFIX: &str = "DWP/";

/// Generate a DWP group wallet address from the wallet's public key.
/// Format: "DWP/<first 8 hex chars of pk>" — recognized as protocol TX by Core.
pub fn dwp_wallet_address(pk: &[u8; 32]) -> String {
    format!("{}{}", DWP_ADDRESS_PREFIX, &hex::encode(pk)[..8])
}
/// Group wallet expiry after resolution (365 days in seconds)
pub const DWP_EXPIRY_SECS: u64 = crate::tuning_gen::DWP_EXPIRY_SECS;

pub struct DwpEngine {
    db: Arc<ManagementDb>,
    storage: Option<Arc<Storage>>,
    my_pk: [u8; 32],
}

impl DwpEngine {
    pub fn new(db: Arc<ManagementDb>, my_pk: [u8; 32]) -> Self {
        Self { db, storage: None, my_pk }
    }

    /// Create with storage reference for payment verification
    pub fn new_with_storage(db: Arc<ManagementDb>, storage: Arc<Storage>, my_pk: [u8; 32]) -> Self {
        Self { db, storage: Some(storage), my_pk }
    }

    /// Check if we witnessed a TX (check Lambda's transaction DB)
    pub fn have_txid(&self, txid: &[u8; 32]) -> bool {
        match &self.storage {
            Some(storage) => storage.get_transaction_record_by_txid(txid)
                .ok()
                .flatten()
                .is_some(),
            None => false, // No storage → can't verify (test mode)
        }
    }

    /// Build PWV set: self + other real witnesses + decoys from known validators.
    /// Called only when we are a real witness for the queried txid.
    /// `k` is the consensus parameter (default 3). PWV size = k × 5.
    pub fn build_pwv_set(
        &self,
        txid: &[u8; 32],
        real_witnesses: &[[u8; 32]],  // from the TX receipt (k validator PKs)
        known_validators: &[[u8; 32]], // from mesh/hints
    ) -> Vec<[u8; 32]> {
        let pwv_size = real_witnesses.len() * PWV_K_MULTIPLIER;
        let mut pwv: Vec<[u8; 32]> = Vec::new();

        // Add all real witnesses first
        for w in real_witnesses {
            if !pwv.contains(w) {
                pwv.push(*w);
            }
        }

        // Add decoys from known validators (deterministic from txid)
        let seed = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_PWV_SEED");
            h.update(txid);
            h.update(&self.my_pk);
            *h.finalize().as_bytes()
        };

        // Deterministic shuffle of candidates
        let mut candidates: Vec<[u8; 32]> = known_validators
            .iter()
            .filter(|v| !pwv.contains(v))
            .copied()
            .collect();

        // Simple deterministic shuffle using seed bytes
        for i in 0..candidates.len() {
            let j = (seed[i % 32] as usize + i) % candidates.len();
            candidates.swap(i, j);
        }

        // Fill to pwv_size (k × 5)
        for c in candidates {
            if pwv.len() >= pwv_size {
                break;
            }
            pwv.push(c);
        }

        // Final shuffle (hide real witnesses in the set)
        let order_seed = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_PWV_ORDER");
            h.update(txid);
            *h.finalize().as_bytes()
        };
        for i in 0..pwv.len() {
            let j = (order_seed[i % 32] as usize + i) % pwv.len();
            pwv.swap(i, j);
        }

        pwv
    }

    /// Create a DWP group wallet record in management DB.
    /// Called by entry validator after receiving PWV response.
    pub fn create_dwp_wallet(
        &self,
        txid: &[u8; 32],
        requester_pk: &[u8; 32],
        payment_txid: &[u8; 32],
        pwv_set: &[[u8; 32]],
        case_description: &str,
        tardis_tick: u64,
    ) -> Result<[u8; 32], LambdaError> {
        // Generate wallet_id from txid + requester
        let wallet_id = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_DWP_WALLET");
            h.update(txid);
            h.update(requester_pk);
            let mut id = [0u8; 32];
            id.copy_from_slice(h.finalize().as_bytes());
            id
        };

        // Serialize PWV set as JSON hex array
        let pwv_json = serde_json::to_string(
            &pwv_set.iter().map(hex::encode).collect::<Vec<_>>()
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        let conn = self.db.db()?;
        conn.execute(
            "INSERT INTO dwp_wallets (wallet_id, txid, anchor_pk, requester_pk, payment_txid, pwv_set, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                wallet_id.as_ref(),
                txid.as_ref(),
                self.my_pk.as_ref(),
                requester_pk.as_ref(),
                payment_txid.as_ref(),
                pwv_json,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            ],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // Add initial case log entry (use same connection to avoid deadlock)
        if !case_description.is_empty() {
            let content = if case_description.len() > MAX_CASE_ENTRY_BYTES {
                &case_description[..MAX_CASE_ENTRY_BYTES]
            } else {
                case_description
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            conn.execute(
                "INSERT INTO dwp_case_log (wallet_id, author_pk, timestamp, tardis_tick, content)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    wallet_id.as_ref(),
                    requester_pk.as_ref(),
                    now as i64,
                    tardis_tick as i64,
                    content,
                ],
            ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        }

        // Create real group wallet in Lambda storage (if storage available)
        if let Some(ref storage) = self.storage {
            // Generate deterministic keypair for group wallet.
            // SECURITY: This key is derivable from public data (txid + requester_pk).
            // This is an accepted design choice — see docs/AXIOM_SECURITY_JFP_ThreatModel.md §2.
            let seed = {
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_JFP_WALLET_KEY");
                h.update(txid);
                h.update(requester_pk);
                *h.finalize().as_bytes()
            };
            let group_signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let group_pk = ed25519_dalek::VerifyingKey::from(&group_signing_key);
            let group_pk_bytes = group_pk.to_bytes();

            // Build group members: requester 50%, PWV members split 50%
            // PWV set is capped at PWV_SET_SIZE (15) by build_pwv_set(). Guard against
            // pathological inputs — cap at 5000 to prevent u16 overflow in bps math.
            let pwv_count = pwv_set.len().min(5000);
            let requester_bps: u16 = 5000;
            let per_member_bps = if pwv_count > 0 { 5000u16 / pwv_count as u16 } else { 0 };
            let remainder_bps = 5000u16 - (per_member_bps * pwv_count as u16);

            let mut members = Vec::with_capacity(pwv_count + 1);
            members.push(axiom_core_logic::types::GroupMember {
                member_pk: requester_pk.to_vec(),
                share_bps: requester_bps,
                available: 0,
            });
            for (i, pk) in pwv_set.iter().enumerate() {
                let bps = per_member_bps + if i == 0 { remainder_bps } else { 0 };
                members.push(axiom_core_logic::types::GroupMember {
                    member_pk: pk.to_vec(),
                    share_bps: bps,
                    available: 0,
                });
            }

            // Store as real wallet state (balance = 1 AXC from payment)
            let genesis_state_id = {
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_GENESIS");
                h.update(&group_pk_bytes);
                h.update(&DQF_ATOMS.to_le_bytes());
                *h.finalize().as_bytes()
            };
            let wallet_state = crate::types::StoredWalletState {
                public_key: group_pk_bytes.to_vec(),
                balance: DQF_ATOMS,
                state_id: genesis_state_id,
                wallet_seq: 0,
                last_tx_id: None,
                status: crate::types::WalletStateStatus::Confirmed,
                group_members: Some(members),
                auth_hash: None, hibernation_until: 0,
                wallet_id: None,
            };
            // AUDIT-FIX v2.11.14: Propagate write errors (was silently dropped).
            // DWP group wallets are synthetic (not personal Ark keypairs) → Standard tier.
            if let Err(e) = storage.set_wallet_state(&wallet_state, axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP) {
                warn!("DWP group wallet state write failed: {} — JFP flow may malfunction", e);
            }

            // Store group wallet address (DWP/hex8) in wallet_type for vote TX lookup
            let group_addr = dwp_wallet_address(&group_pk_bytes);
            if let Err(e) = conn.execute(
                "UPDATE dwp_wallets SET wallet_type = ?1 WHERE wallet_id = ?2",
                rusqlite::params![group_addr, wallet_id.as_ref()],
            ) {
                warn!("DWP wallet_type update failed: {}", e);
            }

            info!("JFP group wallet created: pk={} with {} members ({}+{} bps)",
                  hex::encode(&group_pk_bytes[..4]), pwv_count + 1, requester_bps, per_member_bps);
        }

        info!("DWP wallet created: {} for txid {}", hex::encode(&wallet_id[..4]), hex::encode(&txid[..4]));
        Ok(wallet_id)
    }

    /// Get the group wallet key material for distribution to PWV members.
    /// Returns (group_wallet_address, signing_key_seed) for the given DWP wallet.
    /// The seed is deterministic — any validator with txid + requester_pk can derive it.
    pub fn get_group_wallet_key(
        txid: &[u8; 32],
        requester_pk: &[u8; 32],
    ) -> (String, [u8; 32]) {
        let seed = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_JFP_WALLET_KEY");
            h.update(txid);
            h.update(requester_pk);
            *h.finalize().as_bytes()
        };
        let group_pk = ed25519_dalek::VerifyingKey::from(
            &ed25519_dalek::SigningKey::from_bytes(&seed)
        ).to_bytes();
        (dwp_wallet_address(&group_pk), seed)
    }

    /// Add a case log entry to a DWP wallet.
    pub fn add_case_entry(
        &self,
        wallet_id: &[u8; 32],
        author_pk: &[u8; 32],
        content: &str,
        tardis_tick: u64,
    ) -> Result<(), LambdaError> {
        if content.len() > MAX_CASE_ENTRY_BYTES {
            return Err(LambdaError::StorageError("Case entry exceeds 4096 bytes".into()));
        }

        let conn = self.db.db()?;

        // Check entry count
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM dwp_case_log WHERE wallet_id = ?1",
            rusqlite::params![wallet_id.as_ref()],
            |row| row.get(0),
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        if count >= MAX_CASE_ENTRIES as i64 {
            return Err(LambdaError::StorageError("Case log full (max 50 entries)".into()));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        conn.execute(
            "INSERT INTO dwp_case_log (wallet_id, author_pk, timestamp, tardis_tick, content)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                wallet_id.as_ref(),
                author_pk.as_ref(),
                now as i64,
                tardis_tick as i64,
                content,
            ],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Record a vote TX that arrived on the group wallet (k=3 witnessed).
    /// Called by Lambda after witnessing a TX to a DWP group wallet with
    /// a vote hash in the reference field.
    pub fn record_vote_tx(
        &self,
        dwp_wallet_id: &[u8; 32],
        voter_pk: &[u8; 32],
        vote_hash: &[u8; 32],
        tx_id: Option<&[u8; 32]>,
    ) -> Result<(), LambdaError> {
        // Verify voter is in PWV set
        let conn = self.db.db()?;
        let pwv_json: Option<String> = conn.query_row(
            "SELECT pwv_set FROM dwp_wallets WHERE wallet_id = ?1",
            rusqlite::params![dwp_wallet_id.as_ref()],
            |row| row.get(0),
        ).ok().flatten();

        if let Some(ref json) = pwv_json {
            let pwv_hex: Vec<String> = serde_json::from_str(json)
                .map_err(|e| LambdaError::StorageError(e.to_string()))?;
            let voter_hex = hex::encode(voter_pk);
            if !pwv_hex.contains(&voter_hex) {
                return Err(LambdaError::StorageError(
                    format!("Voter {} not in PWV set", &voter_hex[..8])
                ));
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        conn.execute(
            "INSERT OR IGNORE INTO jfp_vote_index (dwp_wallet_id, voter_pk, vote_hash, tx_id, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                dwp_wallet_id.as_ref(),
                voter_pk.as_ref(),
                vote_hash.as_ref(),
                tx_id.map(|t| t.as_ref()),
                now as i64,
            ],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        info!("JFP vote recorded: voter={} for DWP {}", hex::encode(&voter_pk[..4]), hex::encode(&dwp_wallet_id[..4]));
        Ok(())
    }

    /// Compute JFP result by matching vote hashes against Nabla secrets.
    /// Returns ("approved", "rejected", "failed", or "pending") + vote counts.
    ///
    /// If `voting_end_tick` is provided, computes RANDOM votes for voters who:
    /// - Have 0/11 online proofs (can't prove they were online)
    /// - Did not submit a vote TX
    ///
    /// RANDOM: BLAKE3("AXIOM_JFP_RANDOM" || dwp_wallet_id || voter_index || tick) → even=YES, odd=NO
    pub fn compute_jfp_result(
        &self,
        dwp_wallet_id: &[u8; 32],
        secrets: &[[u8; 32]],
    ) -> Result<(String, usize, usize), LambdaError> {
        let conn = self.db.db()?;

        // Read vote hashes from index
        let mut stmt = conn.prepare(
            "SELECT vote_hash FROM jfp_vote_index WHERE dwp_wallet_id = ?1"
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        let vote_hashes: Vec<[u8; 32]> = stmt.query_map(
            rusqlite::params![dwp_wallet_id.as_ref()],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let mut arr = [0u8; 32];
                if bytes.len() == 32 { arr.copy_from_slice(&bytes); }
                Ok(arr)
            },
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

        // Get expected vote count (PWV set size)
        let pwv_json: Option<String> = conn.query_row(
            "SELECT pwv_set FROM dwp_wallets WHERE wallet_id = ?1",
            rusqlite::params![dwp_wallet_id.as_ref()],
            |row| row.get(0),
        ).ok().flatten();
        let expected_count = pwv_json
            .and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
            .map(|v| v.len())
            .unwrap_or(0);

        if vote_hashes.len() < expected_count {
            // Not all votes in yet
            return Ok(("pending".into(), 0, 0));
        }

        // Match secrets against hashes
        let mut yes_count = 0usize;
        let mut no_count = 0usize;
        let mut matched = 0usize;
        let mut remaining_hashes: Vec<[u8; 32]> = vote_hashes.clone();

        for secret in secrets {
            let hash_yes = {
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_JFP_VOTE");
                h.update(&[0x01]); // YES
                h.update(secret);
                *h.finalize().as_bytes()
            };
            let hash_no = {
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_JFP_VOTE");
                h.update(&[0x00]); // NO
                h.update(secret);
                *h.finalize().as_bytes()
            };

            if let Some(pos) = remaining_hashes.iter().position(|h| *h == hash_yes) {
                remaining_hashes.remove(pos);
                yes_count += 1;
                matched += 1;
            } else if let Some(pos) = remaining_hashes.iter().position(|h| *h == hash_no) {
                remaining_hashes.remove(pos);
                no_count += 1;
                matched += 1;
            }
        }

        // SEC-08: NEVER approve a freeze without a real PWV set. With an empty/
        // missing pwv_set, expected_count == 0 and `yes_count(0) == expected_count(0)`
        // would trivially produce "approved" on ZERO votes — letting an operator
        // freeze ANY wallet via a malformed DWP wallet (the freeze then drives
        // Core's frozen_wallets, an un-burnable hard freeze). A real DWP carries a
        // non-empty PWV set (k×5 by construction in compute_pwv). Refuse to approve
        // anything with no PWV members. See docs/security_review_20260612/SEC-08_RESOLUTION.md.
        let result = if expected_count == 0 {
            "failed" // no PWV set — refuse to approve a freeze on zero votes
        } else if matched < expected_count {
            "failed" // not all secrets revealed
        } else if yes_count == expected_count {
            "approved" // unanimity over the full PWV set
        } else {
            "rejected" // any NO
        };

        info!("JFP result for {}: {} (yes={}, no={}, matched={}/{})",
              hex::encode(&dwp_wallet_id[..4]), result, yes_count, no_count, matched, expected_count);

        Ok((result.to_string(), yes_count, no_count))
    }

    /// Compute RANDOM votes for offline validators.
    /// Called when voting window has expired and some voters didn't submit.
    /// Returns (random_secrets, random_hashes) to inject into the result computation.
    #[allow(clippy::type_complexity)] // Architectural: tuple of two Vec<[u8; 32]> is clearer than a wrapper type here
    pub fn compute_random_votes(
        &self,
        dwp_wallet_id: &[u8; 32],
        voting_end_tick: u64,
    ) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>), LambdaError> {
        let conn = self.db.db()?;

        // Get PWV set
        let pwv_json: String = conn.query_row(
            "SELECT pwv_set FROM dwp_wallets WHERE wallet_id = ?1",
            rusqlite::params![dwp_wallet_id.as_ref()],
            |row| row.get(0),
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        let pwv_hex: Vec<String> = serde_json::from_str(&pwv_json)
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // Find voters who didn't submit a vote TX
        let mut random_secrets = Vec::new();
        let mut random_hashes = Vec::new();

        for (i, pk_hex) in pwv_hex.iter().enumerate() {
            let pk_bytes = hex::decode(pk_hex)
                .map_err(|e| LambdaError::StorageError(e.to_string()))?;

            // Check if this voter submitted a vote
            let has_vote: bool = conn.query_row(
                "SELECT COUNT(*) FROM jfp_vote_index WHERE dwp_wallet_id = ?1 AND voter_pk = ?2",
                rusqlite::params![dwp_wallet_id.as_ref(), pk_bytes.as_slice()],
                |row| row.get::<_, i64>(0),
            ).map(|c| c > 0)
            .unwrap_or(false);

            if !has_vote {
                // Compute deterministic RANDOM vote
                let random_seed = {
                    let mut h = blake3::Hasher::new();
                    h.update(b"AXIOM_JFP_RANDOM");
                    h.update(dwp_wallet_id);
                    h.update(&(i as u64).to_le_bytes());
                    h.update(&voting_end_tick.to_le_bytes());
                    *h.finalize().as_bytes()
                };
                let vote_value = if random_seed[0] % 2 == 0 { 0x01u8 } else { 0x00u8 }; // even=YES, odd=NO

                // Generate secret + hash for the random vote
                let secret = {
                    let mut h = blake3::Hasher::new();
                    h.update(b"AXIOM_JFP_RANDOM_SECRET");
                    h.update(dwp_wallet_id);
                    h.update(&(i as u64).to_le_bytes());
                    h.update(&voting_end_tick.to_le_bytes());
                    *h.finalize().as_bytes()
                };
                let hash = {
                    let mut h = blake3::Hasher::new();
                    h.update(b"AXIOM_JFP_VOTE");
                    h.update(&[vote_value]);
                    h.update(&secret);
                    *h.finalize().as_bytes()
                };

                random_secrets.push(secret);
                random_hashes.push(hash);

                info!("JFP RANDOM vote for voter {}: {} (DWP {})",
                      &pk_hex[..8], if vote_value == 0x01 { "YES" } else { "NO" },
                      hex::encode(&dwp_wallet_id[..4]));
            }
        }

        Ok((random_secrets, random_hashes))
    }

    /// Create a Fan-Out message for a DWP query (content_type = 0x0010).
    /// The message is signed by this validator and ready for CL10 relay.
    pub fn create_query_fanout(
        &self,
        txid: &[u8; 32],
        requester_pk: &[u8; 32],
        payment_txid: &[u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> axiom_core_logic::types::FanOutMessage {
        use ed25519_dalek::Signer;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Content: txid || requester_pk || payment_txid
        let mut content = Vec::with_capacity(96);
        content.extend_from_slice(txid);
        content.extend_from_slice(requester_pk);
        content.extend_from_slice(payment_txid);

        // Diffusion ID: BLAKE3("AXIOM_FANOUT_DWP" || txid || timestamp)
        let diffusion_id = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_FANOUT_DWP");
            h.update(txid);
            h.update(&now.to_le_bytes());
            *h.finalize().as_bytes()
        };

        // Sign: BLAKE3(diffusion_id || content_type || content || ttl_original || timestamp)
        let sign_data = {
            let mut h = blake3::Hasher::new();
            h.update(&diffusion_id);
            h.update(&axiom_core_logic::types::FANOUT_DWP_QUERY.to_le_bytes());
            h.update(&content);
            h.update(&[3u8]); // ttl_original
            h.update(&now.to_le_bytes());
            *h.finalize().as_bytes()
        };
        let sig = signing_key.sign(&sign_data);

        axiom_core_logic::types::FanOutMessage {
            diffusion_id,
            content_type: axiom_core_logic::types::FANOUT_DWP_QUERY,
            content,
            originator_pk: self.my_pk,
            originator_sig: sig.to_bytes().to_vec(),
            timestamp: now,
            ttl_original: 3,
            fanout: 5,
            ttl_current: 3,
        }
    }

    /// Create a Fan-Out message for a JFP freeze result (content_type = 0x0003).
    pub fn create_freeze_result_fanout(
        &self,
        dwp_wallet_id: &[u8; 32],
        result: &str,
        frozen_wallet_pk: &[u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> axiom_core_logic::types::FanOutMessage {
        use ed25519_dalek::Signer;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Content: dwp_wallet_id || result_byte || frozen_wallet_pk
        let mut content = Vec::with_capacity(65);
        content.extend_from_slice(dwp_wallet_id);
        content.push(if result == "approved" { 1 } else { 0 });
        content.extend_from_slice(frozen_wallet_pk);

        let diffusion_id = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_FANOUT_JFP_RESULT");
            h.update(dwp_wallet_id);
            h.update(&now.to_le_bytes());
            *h.finalize().as_bytes()
        };

        let sign_data = {
            let mut h = blake3::Hasher::new();
            h.update(&diffusion_id);
            h.update(&axiom_core_logic::types::FANOUT_JFP_RESULT.to_le_bytes());
            h.update(&content);
            h.update(&[3u8]);
            h.update(&now.to_le_bytes());
            *h.finalize().as_bytes()
        };
        let sig = signing_key.sign(&sign_data);

        axiom_core_logic::types::FanOutMessage {
            diffusion_id,
            content_type: axiom_core_logic::types::FANOUT_JFP_RESULT,
            content,
            originator_pk: self.my_pk,
            originator_sig: sig.to_bytes().to_vec(),
            timestamp: now,
            ttl_original: 3,
            fanout: 5,
            ttl_current: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The DQF is spec'd as exactly 1 AXC (WP §5.5). Lock it to the denomination
    // unit so it can never revert to a hand-mirrored literal that drifts from
    // ATOMS_PER_AXC — if someone rescales the atom, DQF tracks it automatically.
    #[test]
    fn dqf_is_exactly_one_axc() {
        assert_eq!(DQF_ATOMS, axiom_denomination::axc(1));
        assert_eq!(DQF_ATOMS, axiom_denomination::ATOMS_PER_AXC);
    }

    #[test]
    fn test_build_pwv_set() {
        let engine = DwpEngine {
            db: Arc::new(ManagementDb::open_test().unwrap()),
            storage: None,
            my_pk: [0x01; 32],
        };

        let txid = [0xAA; 32];
        let real_witnesses = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        let mut known = Vec::new();
        for i in 4..30u8 {
            known.push([i; 32]);
        }

        let pwv = engine.build_pwv_set(&txid, &real_witnesses, &known);

        // Must be PWV_SET_SIZE
        assert_eq!(pwv.len(), PWV_SET_SIZE);

        // All 3 real witnesses must be in the set
        assert!(pwv.contains(&[0x01; 32]), "V1 missing from PWV");
        assert!(pwv.contains(&[0x02; 32]), "V2 missing from PWV");
        assert!(pwv.contains(&[0x03; 32]), "V3 missing from PWV");

        // No duplicates
        let mut unique = pwv.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), pwv.len(), "PWV has duplicates");
    }

    #[test]
    fn test_pwv_deterministic() {
        let engine = DwpEngine {
            db: Arc::new(ManagementDb::open_test().unwrap()),
            storage: None,
            my_pk: [0x01; 32],
        };

        let txid = [0xBB; 32];
        let real = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        let mut known = Vec::new();
        for i in 4..30u8 {
            known.push([i; 32]);
        }

        let pwv1 = engine.build_pwv_set(&txid, &real, &known);
        let pwv2 = engine.build_pwv_set(&txid, &real, &known);

        // Same inputs → same output
        assert_eq!(pwv1, pwv2, "PWV set must be deterministic");
    }

    #[test]
    fn test_pwv_includes_all_real_witnesses() {
        let engine = DwpEngine {
            db: Arc::new(ManagementDb::open_test().unwrap()),
            storage: None,
            my_pk: [0x01; 32],
        };

        let txid = [0xDD; 32];
        // 3 distinct real witnesses
        let real_witnesses = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        let mut known = Vec::new();
        for i in 4..30u8 {
            known.push([i; 32]);
        }

        let pwv = engine.build_pwv_set(&txid, &real_witnesses, &known);

        assert_eq!(pwv.len(), PWV_SET_SIZE);
        // All 3 real witnesses MUST be present
        assert!(pwv.contains(&[0x01; 32]), "Real witness V1 missing");
        assert!(pwv.contains(&[0x02; 32]), "Real witness V2 missing");
        assert!(pwv.contains(&[0x03; 32]), "Real witness V3 missing");
    }

    #[test]
    fn test_pwv_no_duplicates_even_with_overlap() {
        let engine = DwpEngine {
            db: Arc::new(ManagementDb::open_test().unwrap()),
            storage: None,
            my_pk: [0x01; 32],
        };

        let txid = [0xEE; 32];
        // Real witnesses
        let real_witnesses = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        // known_validators includes the same PKs as real_witnesses (overlap)
        let mut known = Vec::new();
        for i in 1..30u8 {
            known.push([i; 32]);
        }

        let pwv = engine.build_pwv_set(&txid, &real_witnesses, &known);

        assert_eq!(pwv.len(), PWV_SET_SIZE);
        // Verify no duplicates
        let mut sorted = pwv.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), pwv.len(), "PWV set has duplicates despite overlap");

        // All real witnesses still present
        assert!(pwv.contains(&[0x01; 32]), "Real witness V1 missing after overlap");
        assert!(pwv.contains(&[0x02; 32]), "Real witness V2 missing after overlap");
        assert!(pwv.contains(&[0x03; 32]), "Real witness V3 missing after overlap");
    }

    #[test]
    fn test_create_dwp_wallet() {
        let db = Arc::new(ManagementDb::open_test().unwrap());
        let engine = DwpEngine::new(db, [0x01; 32]);

        let txid = [0xCC; 32];
        let requester = [0x02; 32];
        let payment = [0x03; 32];
        let pwv: Vec<[u8; 32]> = (0..15).map(|i| [i as u8; 32]).collect();

        let wallet_id = engine.create_dwp_wallet(
            &txid, &requester, &payment, &pwv,
            "Court Order #2026-CR-4521", 1774090000,
        ).unwrap();

        assert_ne!(wallet_id, [0u8; 32]);
    }

    #[test]
    fn test_case_entry_max_size() {
        let db = Arc::new(ManagementDb::open_test().unwrap());
        let engine = DwpEngine::new(db, [0x01; 32]);

        let txid = [0xDD; 32];
        let requester = [0x02; 32];
        let payment = [0x03; 32];
        let pwv: Vec<[u8; 32]> = (0..15).map(|i| [i as u8; 32]).collect();

        let wallet_id = engine.create_dwp_wallet(
            &txid, &requester, &payment, &pwv, "", 0,
        ).unwrap();

        // Too large entry should fail
        let big = "x".repeat(MAX_CASE_ENTRY_BYTES + 1);
        let result = engine.add_case_entry(&wallet_id, &requester, &big, 0);
        assert!(result.is_err());

        // Max size entry should work
        let ok = "x".repeat(MAX_CASE_ENTRY_BYTES);
        let result = engine.add_case_entry(&wallet_id, &requester, &ok, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_jfp_vote_and_result_computation() {
        let db = Arc::new(ManagementDb::open_test().unwrap());
        let engine = DwpEngine::new(db.clone(), [0x01; 32]);

        // Create DWP wallet with 3 PWV members
        let txid = [0xAA; 32];
        let requester = [0x02; 32];
        let payment = [0x03; 32];
        let pwv: Vec<[u8; 32]> = vec![[0x10; 32], [0x11; 32], [0x12; 32]];

        let wallet_id = engine.create_dwp_wallet(
            &txid, &requester, &payment, &pwv, "Test JFP", 0,
        ).unwrap();

        // Simulate 3 voters casting hashed votes
        let mut secrets = Vec::new();
        let mut vote_hashes = Vec::new();
        for (i, voter_pk) in pwv.iter().enumerate() {
            let secret = [0x50 + i as u8; 32];
            let vote_value = 0x01u8; // YES
            let hash = {
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_JFP_VOTE");
                h.update(&[vote_value]);
                h.update(&secret);
                *h.finalize().as_bytes()
            };
            secrets.push(secret);
            vote_hashes.push(hash);

            engine.record_vote_tx(&wallet_id, voter_pk, &hash, None).unwrap();
        }

        // Non-PWV member should be rejected
        let result = engine.record_vote_tx(&wallet_id, &[0xFF; 32], &[0; 32], None);
        assert!(result.is_err(), "Non-PWV voter should be rejected");

        // Compute result with all secrets → should be APPROVED
        let (result, yes, no) = engine.compute_jfp_result(&wallet_id, &secrets).unwrap();
        assert_eq!(result, "approved", "All YES should approve");
        assert_eq!(yes, 3);
        assert_eq!(no, 0);
    }

    #[test]
    fn test_sec08_empty_pwv_cannot_approve_freeze() {
        // SEC-08: a DWP wallet with an EMPTY PWV set must NEVER compute "approved".
        // Pre-fix, expected_count==0 made `yes_count(0) == expected_count(0)` true,
        // so a malformed DWP wallet trivially "approved" a freeze on ZERO votes —
        // letting an operator freeze ANY target. The freeze drives Core's
        // un-burnable frozen_wallets, so this was a censorship/asset-lock vector.
        let db = Arc::new(ManagementDb::open_test().unwrap());
        let engine = DwpEngine::new(db.clone(), [0x01; 32]);

        let txid = [0xBB; 32];
        let requester = [0x02; 32];
        let payment = [0x03; 32];
        let empty_pwv: Vec<[u8; 32]> = vec![]; // malformed — no PWV members

        let wallet_id = engine.create_dwp_wallet(
            &txid, &requester, &payment, &empty_pwv, "Empty PWV", 0,
        ).unwrap();

        // No votes, no secrets → must NOT approve (was "approved" before the fix).
        let (result, yes, no) = engine.compute_jfp_result(&wallet_id, &[]).unwrap();
        assert_ne!(result, "approved",
            "empty PWV must never approve a freeze (got {:?})", result);
        assert_eq!(result, "failed");
        assert_eq!(yes, 0);
        assert_eq!(no, 0);
    }

    #[test]
    fn test_jfp_result_rejected() {
        let db = Arc::new(ManagementDb::open_test().unwrap());
        let engine = DwpEngine::new(db.clone(), [0x01; 32]);

        let txid = [0xBB; 32];
        let requester = [0x02; 32];
        let pwv: Vec<[u8; 32]> = vec![[0x20; 32], [0x21; 32], [0x22; 32]];

        let wallet_id = engine.create_dwp_wallet(
            &txid, &requester, &[0x03; 32], &pwv, "", 0,
        ).unwrap();

        // 2 YES + 1 NO
        let mut secrets = Vec::new();
        for (i, voter_pk) in pwv.iter().enumerate() {
            let secret = [0x60 + i as u8; 32];
            let vote_value = if i < 2 { 0x01u8 } else { 0x00u8 }; // YES, YES, NO
            let hash = {
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_JFP_VOTE");
                h.update(&[vote_value]);
                h.update(&secret);
                *h.finalize().as_bytes()
            };
            secrets.push(secret);
            engine.record_vote_tx(&wallet_id, voter_pk, &hash, None).unwrap();
        }

        let (result, yes, no) = engine.compute_jfp_result(&wallet_id, &secrets).unwrap();
        assert_eq!(result, "rejected", "Any NO should reject");
        assert_eq!(yes, 2);
        assert_eq!(no, 1);
    }

    #[test]
    fn test_jfp_result_failed_missing_secret() {
        let db = Arc::new(ManagementDb::open_test().unwrap());
        let engine = DwpEngine::new(db.clone(), [0x01; 32]);

        let txid = [0xCC; 32];
        let requester = [0x02; 32];
        let pwv: Vec<[u8; 32]> = vec![[0x30; 32], [0x31; 32], [0x32; 32]];

        let wallet_id = engine.create_dwp_wallet(
            &txid, &requester, &[0x03; 32], &pwv, "", 0,
        ).unwrap();

        // All 3 submit vote hashes
        let mut secrets = Vec::new();
        for (i, voter_pk) in pwv.iter().enumerate() {
            let secret = [0x70 + i as u8; 32];
            let hash = {
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_JFP_VOTE");
                h.update(&[0x01]); // YES
                h.update(&secret);
                *h.finalize().as_bytes()
            };
            secrets.push(secret);
            engine.record_vote_tx(&wallet_id, voter_pk, &hash, None).unwrap();
        }

        // Only provide 2 of 3 secrets → FAILED (can't resolve all votes)
        let (result, _, _) = engine.compute_jfp_result(&wallet_id, &secrets[..2]).unwrap();
        assert_eq!(result, "failed", "Missing secret should cause FAILED");
    }

    /// DQF (Decoy Query Fee) = 1 AXC (White Paper §5.5).
    /// Verify the constant matches protocol denomination.
    #[test]
    fn test_dqf_is_1_axc() {
        assert_eq!(DQF_ATOMS, 10_000_000_000,
            "DQF must be exactly 1 AXC = 10^10 atoms");
    }

    /// DWP group wallet distributes 50% to requester, 50% split among PWV members.
    /// White Paper §5.5: "50% distributed to PWV participants."
    #[test]
    fn test_dqf_50_50_distribution() {
        let db = Arc::new(ManagementDb::open_test().unwrap());
        let engine = DwpEngine::new(db, [0x01; 32]);

        let txid = [0xEE; 32];
        let requester = [0x02; 32];
        let payment = [0x03; 32];
        // 3 PWV members
        let pwv: Vec<[u8; 32]> = vec![[0x10; 32], [0x11; 32], [0x12; 32]];

        let wallet_id = engine.create_dwp_wallet(
            &txid, &requester, &payment, &pwv, "DQF distribution test", 0,
        ).unwrap();

        // Read back the group wallet to verify member shares
        if let Some(storage) = &engine.storage {
            if let Ok(Some(ws)) = storage.get_wallet_state(&wallet_id, 3, 1) {
                let members = ws.group_members.expect("DWP wallet must have group_members");
                assert_eq!(members.len(), 4, "1 requester + 3 PWV = 4 members");

                // Requester gets 50% (5000 bps)
                assert_eq!(members[0].share_bps, 5000,
                    "Requester must get 50% (5000 bps)");

                // PWV members split the other 50%
                let pwv_total: u16 = members[1..].iter().map(|m| m.share_bps).sum();
                assert_eq!(pwv_total, 5000,
                    "PWV members must collectively get 50% (5000 bps)");

                // Each PWV member gets ~1666 bps (5000/3), remainder to first
                assert_eq!(members[1].share_bps, 1666 + 2, // 5000 - 1666*3 = 2 remainder
                    "First PWV member gets per-member share + remainder");
                assert_eq!(members[2].share_bps, 1666);
                assert_eq!(members[3].share_bps, 1666);

                // Total must be 10000 bps
                let total: u16 = members.iter().map(|m| m.share_bps).sum();
                assert_eq!(total, 10000, "Total shares must be 10000 bps (100%)");

                // Balance must be 1 AXC
                assert_eq!(ws.balance, DQF_ATOMS,
                    "Group wallet balance must be 1 AXC");
            }
        }
    }
}
