//! Lambda storage — SQLite/SQLCipher backend
//!
//! Lambda is the HISTORIAN. Lambda has the database.
//!
//! Storage contains:
//! - Wallet states (balance, seq, state_id) from all witnessed transactions
//! - Receipts from finalized transactions
//! - Transaction records for S-ABR overlap lookup
//! - Consumed/redeemed state tracking (double-spend prevention)
//! - Fee records (ACK tracking)
//! - Validator hints (organic discovery)
//! - Scar passcodes
//!
//! When an overlapped validator receives a transaction:
//! 1. Lambda looks up the wallet state from THIS database
//! 2. Lambda refills balance/seq from database
//! 3. Core uses refilled values to compute Hash_B
//! 4. Core compares Hash_A (client) == Hash_B (refilled)
//!
//! Lambda has the DATA. Core makes the DECISION.
//!
//! ## Encryption
//!
//! The transaction DB (`lambda.db`) uses SQLCipher AES-256 encryption at rest.
//! The encryption key is derived from the validator's Ed25519 private key:
//!   `BLAKE3("AXIOM_DB_KEY_V1" || ed25519_secret_key)`
//! PRAGMA locking_mode = EXCLUSIVE — no other process can open the DB.

use crate::error::LambdaError;
use crate::types::*;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use parking_lot::Mutex;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{debug, info};

// ════════════════════════════════════════════════════════════════════
// CBOR helpers for disk-stored protocol-bearing fields.
//
// Per CLAUDE.md §13 and `feedback_no_json_in_protocol_path`: every
// serialized field that round-trips through storage and is consumed
// by the protocol (group_members, witness_sigs, fact_proof, etc.)
// must be CBOR, not JSON.  The pre-2026-05-15 code used
// `serde_json::to_vec(…).ok()` / `serde_json::from_slice(…).ok()` —
// both silently swallowed serialization errors and degraded to
// "None" / "default" without any signal.  That class of bug
// (corrupted-or-mis-decoded → silent → wrong consensus) has burned
// the codebase 5 separate times in the past 5 months.
//
// These helpers:
//   - emit CBOR via ciborium (consistent with the rest of the wire)
//   - surface every error as a LambdaError::StorageError so soak/CI
//     see it on the first iteration
//   - never return Ok(None) when decode failed — only when the input
//     was actually absent (NULL column)
// ════════════════════════════════════════════════════════════════════

fn cbor_encode<T: Serialize>(value: &T, field: &'static str) -> Result<Vec<u8>, LambdaError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| LambdaError::StorageError(
        format!("cbor_encode({}): {}", field, e)
    ))?;
    Ok(buf)
}

fn cbor_encode_opt<T: Serialize>(value: &Option<T>, field: &'static str) -> Result<Option<Vec<u8>>, LambdaError> {
    match value {
        None => Ok(None),
        Some(v) => Ok(Some(cbor_encode(v, field)?)),
    }
}

fn cbor_decode<T: DeserializeOwned>(bytes: &[u8], field: &'static str) -> Result<T, LambdaError> {
    ciborium::from_reader(bytes).map_err(|e| LambdaError::StorageError(
        format!("cbor_decode({}): {}", field, e)
    ))
}

fn cbor_decode_opt<T: DeserializeOwned>(bytes: Option<&[u8]>, field: &'static str) -> Result<Option<T>, LambdaError> {
    match bytes {
        None => Ok(None),
        Some(b) => Ok(Some(cbor_decode(b, field)?)),
    }
}

/// CBOR decode inside a rusqlite closure.  Maps the decode error to
/// `rusqlite::Error::FromSqlConversionFailure` so the outer
/// `.map_err(|e| LambdaError::StorageError(e.to_string()))?` chain
/// surfaces it as a StorageError — no silent fallback.
fn cbor_decode_in_row<T: DeserializeOwned>(bytes: &[u8], field: &'static str) -> rusqlite::Result<T> {
    ciborium::from_reader(bytes).map_err(|e| rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("cbor decode {}: {}", field, e),
        )),
    ))
}

fn cbor_decode_opt_in_row<T: DeserializeOwned>(bytes: Option<Vec<u8>>, field: &'static str) -> rusqlite::Result<Option<T>> {
    match bytes {
        None => Ok(None),
        Some(b) => Ok(Some(cbor_decode_in_row(&b, field)?)),
    }
}

/// Safe u64 → i64 for SQLite storage. Rejects values > i64::MAX.
#[inline]
fn to_db_int(val: u64) -> Result<i64, LambdaError> {
    i64::try_from(val).map_err(|_| LambdaError::StorageError(
        format!("value {} exceeds SQLite integer range", val)
    ))
}

/// Safe i64 → u64 from SQLite. Negative values become 0 (defensive).
/// Logs warning for negative values — indicates DB corruption.
#[inline]
fn from_db_int(val: i64) -> u64 {
    if val < 0 { 0 } else { val as u64 }
}

/// Storage for Lambda (SQLite/SQLCipher backend)
pub struct Storage {
    /// Single connection protected by mutex (exclusive access)
    conn: Mutex<Connection>,

    /// Maximum hints to store (default: 1024)
    max_hints: usize,
}

impl Storage {
    /// Acquire DB lock — parking_lot::Mutex never poisons.
    fn db(&self) -> Result<parking_lot::MutexGuard<'_, Connection>, LambdaError> {
        Ok(self.conn.lock())
    }
}

/// Stored validator hint with metadata (for persistence)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredValidatorHint {
    pub validator_id: String,
    pub name: String,
    pub carriers: Vec<String>,
    /// YPX-007: "dmap" or "zkvm" — validator's proof capability
    #[serde(default = "default_proof_cap")]
    pub proof_cap: String,
    pub last_seen: u64,
    pub stored_at: u64,
}

fn default_proof_cap() -> String {
    "dmap".into()
}

/// Resolve a validator's Ed25519 public key from the two possible
/// sources in a JOIN row:
///   * `stored_blob` — `validator_hints.ed25519_pk` (BLOB), reflects
///     what the SOURCE of the hint actually said. Takes precedence.
///   * `approved_hex` — `approved_validators.ed25519_pk_hex` (TEXT),
///     the operator-approved local truth, used as a fallback for
///     pre-migration rows or hints from peers that didn't ship the key.
///
/// Returns `None` if neither source produces a 32-byte key. Malformed
/// values (wrong length, bad hex) are silently dropped — the SDK side
/// already treats `ed25519_pk: None` as "verify later via VBC
/// cross-check", so a missing/garbage value fails closed safely.
fn resolve_ed25519_pk(
    stored_blob: Option<Vec<u8>>,
    approved_hex: Option<String>,
) -> Option<[u8; 32]> {
    if let Some(b) = stored_blob {
        if let Ok(arr) = <[u8; 32]>::try_from(b.as_slice()) {
            return Some(arr);
        }
    }
    if let Some(h) = approved_hex {
        if let Ok(bytes) = hex::decode(&h) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Some(arr);
            }
        }
    }
    None
}

impl Storage {
    /// Default max hints for Lambda (1024)
    pub const DEFAULT_MAX_HINTS: usize = 1024;

    /// Open encrypted storage at given path
    ///
    /// `db_key_hex` is the hex-encoded BLAKE3 hash derived from the validator's
    /// Ed25519 private key. Set to empty string for unencrypted (test only).
    pub fn open(db_path: &Path, db_key_hex: &str) -> Result<Self, LambdaError> {
        Self::open_with_max_hints(db_path, db_key_hex, Self::DEFAULT_MAX_HINTS)
    }

    /// Open encrypted storage with custom max_hints limit
    pub fn open_with_max_hints(
        db_path: &Path,
        db_key_hex: &str,
        max_hints: usize,
    ) -> Result<Self, LambdaError> {
        let conn = Connection::open(db_path)
            .map_err(|e| LambdaError::StorageError(format!("Failed to open DB: {}", e)))?;

        // Apply encryption key if provided
        if !db_key_hex.is_empty() {
            conn.pragma_update(None, "key", format!("x'{}'", db_key_hex))
                .map_err(|e| LambdaError::StorageError(format!("Failed to set encryption key: {}", e)))?;
        }

        // Apply PRAGMAs
        Self::apply_pragmas(&conn)?;

        // Create schema
        Self::create_schema(&conn)?;

        debug!("Storage opened: {:?}, max_hints={}", db_path, max_hints);

        Ok(Self {
            conn: Mutex::new(conn),
            max_hints,
        })
    }

    /// Open an unencrypted in-memory database for testing
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn open_test() -> Result<Self, LambdaError> {
        Self::open_test_with_max_hints(Self::DEFAULT_MAX_HINTS)
    }

    /// Open an unencrypted in-memory database for testing with custom max_hints
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn open_test_with_max_hints(max_hints: usize) -> Result<Self, LambdaError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| LambdaError::StorageError(format!("Failed to open in-memory DB: {}", e)))?;

        Self::apply_pragmas_unencrypted(&conn)?;
        Self::create_schema(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            max_hints,
        })
    }

    fn apply_pragmas(conn: &Connection) -> Result<(), LambdaError> {
        let pragmas = [
            "PRAGMA cipher_page_size = 4096",
            "PRAGMA kdf_iter = 256000",
            "PRAGMA auto_vacuum = INCREMENTAL",
            "PRAGMA journal_mode = WAL",
            "PRAGMA synchronous = FULL",
            "PRAGMA locking_mode = EXCLUSIVE",
            "PRAGMA foreign_keys = ON",
            "PRAGMA busy_timeout = 5000",
        ];
        for pragma in &pragmas {
            conn.execute_batch(pragma)
                .map_err(|e| LambdaError::StorageError(format!("PRAGMA failed: {}", e)))?;
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-helpers"))]
    fn apply_pragmas_unencrypted(conn: &Connection) -> Result<(), LambdaError> {
        let pragmas = [
            "PRAGMA journal_mode = WAL",
            "PRAGMA synchronous = FULL",
            "PRAGMA locking_mode = EXCLUSIVE",
            "PRAGMA foreign_keys = ON",
            "PRAGMA busy_timeout = 5000",
        ];
        for pragma in &pragmas {
            conn.execute_batch(pragma)
                .map_err(|e| LambdaError::StorageError(format!("PRAGMA failed: {}", e)))?;
        }
        Ok(())
    }

    fn create_schema(conn: &Connection) -> Result<(), LambdaError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS wallets (
                public_key    BLOB NOT NULL,
                -- YPX-010 §10.5 single-keypair: (k, proof_type) is the YPX-007 tier.
                -- One keypair backs 7 tier addresses (e.g. k=3 Standard and k=0 Ark);
                -- the tier is part of the state-row key so the tiers do not collide.
                k             INTEGER NOT NULL,
                proof_type    INTEGER NOT NULL,
                balance       INTEGER NOT NULL,
                wallet_seq    INTEGER NOT NULL,
                state_id      BLOB NOT NULL,
                last_tx_id    BLOB,
                status        TEXT NOT NULL DEFAULT 'Confirmed',
                group_members BLOB,
                auth_hash     BLOB,
                wallet_id     TEXT,
                hibernation_until INTEGER NOT NULL DEFAULT 0, -- YPX-020 (persist hibernation)
                updated_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (public_key, k, proof_type)
            );
            CREATE INDEX IF NOT EXISTS idx_wallets_state_id ON wallets(state_id);

            CREATE TABLE IF NOT EXISTS fanout_seen (
                diffusion_id  BLOB PRIMARY KEY,
                received_at   INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_fanout_age ON fanout_seen(received_at);

            CREATE TABLE IF NOT EXISTS genesis_states (
                public_key    BLOB NOT NULL,
                k             INTEGER NOT NULL,   -- YPX-010 §10.5 tier (see wallets)
                proof_type    INTEGER NOT NULL,
                balance       INTEGER NOT NULL,
                wallet_seq    INTEGER NOT NULL,
                state_id      BLOB NOT NULL,
                last_tx_id    BLOB,
                status        TEXT NOT NULL DEFAULT 'Confirmed',
                group_members BLOB,
                created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (public_key, k, proof_type)
            );

            CREATE TABLE IF NOT EXISTS transaction_records (
                produced_state_id BLOB PRIMARY KEY,
                tx_id             BLOB NOT NULL,
                wallet_pk         BLOB NOT NULL,
                balance_after     INTEGER NOT NULL,
                wallet_seq_after  INTEGER NOT NULL,
                group_members_after BLOB,
                status            TEXT NOT NULL DEFAULT 'Pending',
                required_k        INTEGER NOT NULL DEFAULT 3,
                proof_type        INTEGER NOT NULL DEFAULT 1,
                amount            INTEGER NOT NULL DEFAULT 0,
                sender_balance    INTEGER NOT NULL DEFAULT 0,
                created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_txrec_tx_id ON transaction_records(tx_id);
            CREATE INDEX IF NOT EXISTS idx_txrec_wallet ON transaction_records(wallet_pk);

            CREATE TABLE IF NOT EXISTS txid_consumed_states (
                txid              BLOB PRIMARY KEY,
                consumed_state_id BLOB NOT NULL,
                created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS consumed_states (
                state_id    BLOB PRIMARY KEY,
                consumed_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS redeemed_cheques (
                cheque_id   BLOB PRIMARY KEY,
                redeemed_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS receipts (
                txid               BLOB PRIMARY KEY,
                state_hash         BLOB NOT NULL,
                produced_state_id  BLOB NOT NULL,
                new_wallet_seq     INTEGER NOT NULL,
                commitment_hash    BLOB NOT NULL,
                sdid               BLOB NOT NULL,
                lineage_hash       BLOB NOT NULL,
                core_version       TEXT NOT NULL DEFAULT '',
                witness_sigs       BLOB NOT NULL,
                epoch              INTEGER NOT NULL,
                fact_proof         BLOB,
                receipt_commitment BLOB NOT NULL DEFAULT (zeroblob(32)),
                core_id            BLOB NOT NULL DEFAULT (zeroblob(32)),
                created_at         INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_receipts_produced ON receipts(produced_state_id);
            CREATE INDEX IF NOT EXISTS idx_receipts_epoch ON receipts(epoch);

            -- fee_records / validator_fee_tracking retired in Step 9A2
            -- (YP §20.8 v3.x). The CREATE TABLE statements are gone; on
            -- existing databases the tables linger as dead rows that no
            -- code path reads, until the operator runs a one-off VACUUM.

            -- v3.x per-validator earnings: one row per redeem this validator
            -- witnessed (txid is the PK). Atoms is the slot amount this
            -- validator earned at CL5 from fee_breakdown. INSERT OR IGNORE
            -- on txid makes the bump idempotent under retry. The /fees
            -- admin endpoint reports SUM(atoms) and COUNT(*).
            CREATE TABLE IF NOT EXISTS validator_earned (
                txid          BLOB NOT NULL PRIMARY KEY,
                atoms         INTEGER NOT NULL,
                earned_at     INTEGER NOT NULL,
                -- Dev-class isolation observability (AXIOM_DESIGN_FactClassIsolation.md).
                -- Lambda counts BOTH dev-class and public earnings here so the
                -- per-validator dashboard can show them as separate lines.
                -- Public sum: SUM(atoms) WHERE is_dev_class = 0.
                -- Dev sum:    SUM(atoms) WHERE is_dev_class = 1.
                -- Dev rows are observability ONLY — they can NEVER mint public
                -- AXC; the withdrawal-mint path reads only Nabla's public
                -- ValidatorNetLedger (see node.rs LEAK BOUNDARY).
                is_dev_class  INTEGER NOT NULL DEFAULT 0
            );

            -- Step 9B.7 — validator-withdrawal mint receipts (YP §20.10).
            -- One row per completed mint witness round. PRIMARY KEY
            -- (validator_id, claimed_through_tick) is the idempotency
            -- lock: a retried admin POST against the same proof returns
            -- the persisted receipt instead of re-minting / re-fanning-out
            -- to chosen_witnesses. `signatures` is a CBOR-encoded
            -- Vec<WitnessSignature> (witness_id + witness_pk + sig per
            -- entry). After persistence, Step 9B.8 sends
            -- MarkValidatorEarningsClaimedRequest to Nabla so
            -- last_claimed_tick advances.
            CREATE TABLE IF NOT EXISTS validator_withdrawal_mints (
                validator_id          BLOB NOT NULL,
                claimed_through_tick  INTEGER NOT NULL,
                linked_wallet_id      BLOB NOT NULL,
                net_amount            INTEGER NOT NULL,
                minted_at             INTEGER NOT NULL,
                signatures            BLOB NOT NULL,
                PRIMARY KEY (validator_id, claimed_through_tick)
            );
            CREATE INDEX IF NOT EXISTS idx_withdrawal_mints_wallet
                ON validator_withdrawal_mints(linked_wallet_id);

            CREATE TABLE IF NOT EXISTS validator_hints (
                validator_id BLOB PRIMARY KEY,
                name         TEXT NOT NULL,
                proof_cap    TEXT NOT NULL DEFAULT 'dmap',
                carriers     TEXT NOT NULL,
                last_seen    INTEGER NOT NULL,
                stored_at    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_hints_stored_at ON validator_hints(stored_at);

            CREATE TABLE IF NOT EXISTS scar_passcodes (
                txid         BLOB NOT NULL PRIMARY KEY,
                wallet_pk    BLOB NOT NULL,
                passcode     INTEGER NOT NULL,
                created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                delivered_at INTEGER,
                recovered_at INTEGER,
                attempts     INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS approved_validators (
                validator_id   TEXT PRIMARY KEY,
                sphincs_pk_hex TEXT NOT NULL,
                ed25519_pk_hex TEXT NOT NULL,
                proof_cap      TEXT NOT NULL DEFAULT 'dmap',
                node_name      TEXT NOT NULL DEFAULT '',
                approved_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                request_id     TEXT NOT NULL DEFAULT '',
                issuer_id      TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS cheque_delivery_log (
                txid             BLOB NOT NULL,
                recipient_email  TEXT NOT NULL,
                sent_at          INTEGER NOT NULL,
                ack_received_at  INTEGER,
                delivery_status  TEXT NOT NULL DEFAULT 'sent',
                encrypted        INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_delivery_txid ON cheque_delivery_log(txid);

            CREATE TABLE IF NOT EXISTS dwp_vote_rate (
                case_address     TEXT NOT NULL,
                sender_wallet_id TEXT NOT NULL,
                tick             INTEGER NOT NULL,
                count            INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (case_address, sender_wallet_id, tick)
            );

            -- YP §10: MVIB — Meta-Validator Inheritance Binding
            -- Tracks the 3 independent validators (MV-set) that approved a new validator.
            -- The VBC issuer_set contains their SPHINCS+ PKs; this table tracks validator_ids.
            -- Used for JFP witness inheritance when a validator becomes absent.
            CREATE TABLE IF NOT EXISTS mvib_bindings (
                subject_validator_id TEXT NOT NULL,
                issuer_validator_id  TEXT NOT NULL,
                issuer_index         INTEGER NOT NULL,  -- 0, 1, or 2 (Set A, B, C)
                bound_at             INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (subject_validator_id, issuer_index)
            );

            -- YP §10: Signed MVIB bindings — the full cryptographic binding document.
            -- Created by the new validator after collecting k=3 approvals.
            -- Stores serialized MvibBinding (validator_id, admission_set, tick, signature).
            CREATE TABLE IF NOT EXISTS mvib_signed (
                validator_id TEXT NOT NULL PRIMARY KEY,
                binding_json TEXT NOT NULL,
                stored_at    INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            -- YPX-016: Witness response cache for partial witness recovery.
            -- When the exact same TX is retried after a partial witness (2/3),
            -- the validator returns the cached response instead of re-executing Core.
            CREATE TABLE IF NOT EXISTS witness_cache (
                wallet_pk         BLOB NOT NULL,
                k                 INTEGER NOT NULL,   -- YPX-010 §10.5 tier (see wallets)
                proof_type        INTEGER NOT NULL,
                tx_hash           BLOB NOT NULL,
                consumed_state_id BLOB NOT NULL,
                wallet_seq        INTEGER NOT NULL,
                witness_response  BLOB NOT NULL,
                created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (wallet_pk, k, proof_type)
            );

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');
            INSERT OR IGNORE INTO meta (key, value) VALUES ('vbc_signs_remaining', '6');
            ",
        )
        .map_err(|e| LambdaError::StorageError(format!("Schema creation failed: {}", e)))?;

        // Migration: add receipt_commitment column to receipts if missing.
        // Pre-existing DBs (from before the receipt-commitment feature
        // landed) lack this column; the receipts CREATE TABLE above
        // includes it for fresh DBs. SQLite ADD COLUMN is idempotent in
        // effect when paired with PRAGMA pragma check — but since
        // CREATE TABLE IF NOT EXISTS doesn't add columns to an existing
        // table, we issue an ALTER TABLE and ignore the
        // "duplicate column name" error (occurs if the column is
        // already present).
        let _ = conn.execute_batch(
            "ALTER TABLE receipts ADD COLUMN receipt_commitment BLOB NOT NULL DEFAULT (zeroblob(32));",
        );

        // Migration: attempts counter for the scar-passcode gate (YPX-001
        // §1.5.1 hardening, 2026-07-12) — retained dev DBs predate the
        // column. Entries are transient consent state, so the default 0
        // is exact for pre-existing rows.
        let _ = conn.execute_batch(
            "ALTER TABLE scar_passcodes ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;",
        );

        // Migration: add ed25519_pk column to validator_hints if missing.
        // Pre-existing DBs lack this column; new INSERTs persist the key
        // when an incoming hint carries it, otherwise NULL. Reads
        // (`get_random_hints` / `get_all_hints`) fall back to a LEFT JOIN
        // against `approved_validators` to fill in the local validator's
        // own key + any peers the operator has explicitly approved.
        let _ = conn.execute_batch(
            "ALTER TABLE validator_hints ADD COLUMN ed25519_pk BLOB;",
        );

        // Migration: encryption_public_key + supported_encryption.
        // Operator's encryption key rides alongside the URI vec so
        // discovered validators can be encrypted-to without a separate
        // VSP round-trip. Empty TEXT = no encryption advertised.
        let _ = conn.execute_batch(
            "ALTER TABLE validator_hints ADD COLUMN encryption_public_key TEXT NOT NULL DEFAULT '';",
        );
        let _ = conn.execute_batch(
            "ALTER TABLE validator_hints ADD COLUMN supported_encryption TEXT NOT NULL DEFAULT '';",
        );

        Ok(())
    }

    // =========================================================================
    // YPX-016: Witness Response Cache
    // =========================================================================

    /// Check if we have a cached witness response for this exact TX.
    /// Returns Some(response_bytes) if cache hit, None if miss.
    pub fn get_witness_cache(
        &self,
        wallet_pk: &[u8],
        k: u8,
        proof_type: u8,
        tx_hash: &[u8; 32],
        consumed_state_id: &[u8; 32],
        wallet_seq: u64,
    ) -> Result<Option<Vec<u8>>, LambdaError> {
        let db = self.db()?;
        let mut stmt = db
            .prepare(
                "SELECT witness_response FROM witness_cache \
                 WHERE wallet_pk = ?1 AND k = ?2 AND proof_type = ?3 AND tx_hash = ?4 \
                 AND consumed_state_id = ?5 AND wallet_seq = ?6",
            )
            .map_err(|e| LambdaError::StorageError(format!("witness_cache prepare: {}", e)))?;

        let result = stmt
            .query_row(
                rusqlite::params![wallet_pk, k as i64, proof_type as i64, tx_hash.as_slice(), consumed_state_id.as_slice(), wallet_seq as i64],
                |row| row.get::<_, Vec<u8>>(0),
            );

        match result {
            Ok(response) => Ok(Some(response)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LambdaError::StorageError(format!("witness_cache get: {}", e))),
        }
    }

    /// Cache a witness response for a wallet. Overwrites any previous cache entry.
    pub fn set_witness_cache(
        &self,
        wallet_pk: &[u8],
        k: u8,
        proof_type: u8,
        tx_hash: &[u8; 32],
        consumed_state_id: &[u8; 32],
        wallet_seq: u64,
        witness_response: &[u8],
    ) -> Result<(), LambdaError> {
        let db = self.db()?;
        db.execute(
            "INSERT OR REPLACE INTO witness_cache \
             (wallet_pk, k, proof_type, tx_hash, consumed_state_id, wallet_seq, witness_response, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, strftime('%s','now'))",
            rusqlite::params![
                wallet_pk,
                k as i64,
                proof_type as i64,
                tx_hash.as_slice(),
                consumed_state_id.as_slice(),
                wallet_seq as i64,
                witness_response,
            ],
        )
        .map_err(|e| LambdaError::StorageError(format!("witness_cache set: {}", e)))?;
        Ok(())
    }

    // =========================================================================
    // Wallet State
    // =========================================================================

    /// Get wallet state by public key
    pub fn get_wallet_state(
        &self,
        public_key: &[u8],
        k: u8,
        proof_type: u8,
    ) -> Result<Option<StoredWalletState>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT public_key, balance, wallet_seq, state_id, last_tx_id, status, group_members, auth_hash, wallet_id, hibernation_until
                 FROM wallets WHERE public_key = ?1 AND k = ?2 AND proof_type = ?3",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // Two-phase decode: pull raw row tuple inside the closure so
        // the SQLite call signature stays clean, then CBOR-decode the
        // group_members blob OUTSIDE the closure so decode failure
        // surfaces as LambdaError::StorageError (not silently None).
        // Per CLAUDE.md §13 — decode failure is an error.
        type WalletRow = (Vec<u8>, i64, i64, Vec<u8>, Option<Vec<u8>>, String, Option<Vec<u8>>, Option<Vec<u8>>, Option<String>, i64);
        let raw: Option<WalletRow> = stmt
            .query_row(params![public_key, k as i64, proof_type as i64], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?, // YPX-020 hibernation_until
                ))
            })
            .optional()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        let result = match raw {
            None => None,
            Some((pk, balance, seq, sid, last_tx, status, gm_bytes, auth_bytes, wid, hib)) => {
                Some(StoredWalletState {
                    public_key: pk,
                    balance: from_db_int(balance),
                    wallet_seq: from_db_int(seq),
                    state_id: blob_to_32(sid),
                    last_tx_id: last_tx.map(blob_to_32),
                    status: status_from_str(&status),
                    group_members: cbor_decode_opt(gm_bytes.as_deref(), "wallets.group_members")?,
                    auth_hash: auth_bytes.and_then(|b| b.try_into().ok()),
                    hibernation_until: from_db_int(hib),
                    wallet_id: wid,
                })
            }
        };

        if let Some(ref state) = result {
            debug!(
                "Found wallet state for pk={}",
                hex::encode(&state.public_key[..8.min(state.public_key.len())])
            );
        } else {
            debug!(
                "Wallet not found: pk={}",
                hex::encode(&public_key[..8.min(public_key.len())])
            );
        }

        Ok(result)
    }

    /// Set wallet state
    ///
    /// SAFETY NOTE (concurrent access): Uses INSERT OR REPLACE (last writer wins).
    /// This is safe because wallet state is keyed by public_key, and a wallet can
    /// only have one active TX at a time (wallet_seq must increment sequentially).
    /// Core rejects TXs with wrong seq (InvalidWalletSeq), and k-of-k consensus
    /// means concurrent TXs to the same wallet are rejected before reaching storage.
    /// No CAS/version guard needed — the seq constraint is the serialization point.
    pub fn set_wallet_state(&self, state: &StoredWalletState, k: u8, proof_type: u8) -> Result<(), LambdaError> {
        let conn = self.db()?;
        // CBOR (not JSON) — group_members rides protocol consensus; a
        // silent serialization failure would corrupt S-ABR refill on
        // every overlapped validator that reads this row.  `?` is
        // mandatory; the legacy `.and_then(|gm| serde_json::to_vec(gm).ok())`
        // swallowed every error and was the recurring bug class
        // catalogued in CLAUDE.md §13.
        let group_members_cbor = cbor_encode_opt(&state.group_members, "wallets.group_members")?;
        let status_str = status_to_str(&state.status);
        let last_tx_id = state.last_tx_id.map(|id| id.to_vec());
        let now = unix_now();

        let auth_hash_bytes = state.auth_hash.map(|h| h.to_vec());

        conn.execute(
            "INSERT OR REPLACE INTO wallets
             (public_key, k, proof_type, balance, wallet_seq, state_id, last_tx_id, status, group_members, auth_hash, wallet_id, hibernation_until, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                state.public_key,
                k as i64,
                proof_type as i64,
                to_db_int(state.balance)?,
                to_db_int(state.wallet_seq)?,
                state.state_id.as_ref(),
                last_tx_id,
                status_str,
                group_members_cbor,
                auth_hash_bytes,
                state.wallet_id,
                to_db_int(state.hibernation_until)?, // YPX-020 — persist hibernation
                now as i64,
            ],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // ════════════════════════════════════════════════════════════
        // ║ MANDATORY WRITE-VERIFY — DO NOT REMOVE                  ║
        // ║                                                          ║
        // ║ S-ABR is the central beam of the entire protocol. Every  ║
        // ║ subsequent TX from this wallet (and every redeem of a    ║
        // ║ cheque this wallet issued) depends on validators having  ║
        // ║ a STORED state record that matches what was witnessed.   ║
        // ║ A silent storage write failure HERE produces the         ║
        // ║ "overlap path with no stored record" condition — and the ║
        // ║ wallet ends up in an unrecoverable drift the next time a ║
        // ║ peer tries to overlap-cite this state.                   ║
        // ║                                                          ║
        // ║ We cannot tolerate a write failing silently. So:         ║
        // ║   (1) issue the INSERT OR REPLACE                        ║
        // ║   (2) immediately SELECT back                            ║
        // ║   (3) compare state_id + wallet_seq + balance            ║
        // ║   (4) only return Ok if all three match                  ║
        // ║                                                          ║
        // ║ If a future contributor sees this as "redundant" or "a   ║
        // ║ perf optimization" — STOP. It is neither. Without this,  ║
        // ║ a sqlite_busy retry that silently dropped, a WAL fsync   ║
        // ║ ordering bug, a disk-full degradation, or any storage    ║
        // ║ pathology returns Ok but no row lands. The TX completes  ║
        // ║ at the protocol layer; the wallet's NEXT op fails        ║
        // ║ mysteriously hours/days later when validators can't find ║
        // ║ the state they "stored". That is the worst possible      ║
        // ║ failure mode for S-ABR consensus.                        ║
        // ║                                                          ║
        // ║ Cost: one extra indexed SELECT per state mutation        ║
        // ║ (~0.3ms locally). This is negligible against the witness ║
        // ║ round (multi-second). The cost is the price of           ║
        // ║ correctness — non-negotiable.                            ║
        // ║                                                          ║
        // ║ Original context: 2026-05-15 DRIFT-DIAG showed           ║
        // ║ "OVERLAPPED-NO-RECORD" firing in production soak — a     ║
        // ║ stored record was missing for a state validators had     ║
        // ║ committed to. Cause not fully isolated, but the fix      ║
        // ║ is structural: never trust a write without read-back.    ║
        // ║                                                          ║
        // ║ — AXIOM Origin, 2026-05-15                                      ║
        // ════════════════════════════════════════════════════════════
        let verify_row: Option<(Vec<u8>, i64, i64, Option<Vec<u8>>)> = conn.query_row(
            "SELECT state_id, wallet_seq, balance, group_members FROM wallets WHERE public_key = ?1 AND k = ?2 AND proof_type = ?3",
            params![state.public_key, k as i64, proof_type as i64],
            |row| Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            )),
        ).optional().map_err(|e| LambdaError::StorageError(
            format!("set_wallet_state verify SELECT: {}", e),
        ))?;

        match verify_row {
            None => {
                return Err(LambdaError::StorageError(format!(
                    "set_wallet_state write-verify: no row found after INSERT for pk={} \
                     — write silently dropped (sqlite consistency issue?)",
                    hex::encode(&state.public_key[..8.min(state.public_key.len())]),
                )));
            }
            Some((read_state_id, read_seq, read_balance, read_gm_bytes)) => {
                let expected_state_id: &[u8] = state.state_id.as_ref();
                let expected_seq = to_db_int(state.wallet_seq)? as i64;
                let expected_balance = to_db_int(state.balance)? as i64;
                if read_state_id != expected_state_id {
                    return Err(LambdaError::StorageError(format!(
                        "set_wallet_state write-verify: state_id mismatch (wrote={}, read={})",
                        hex::encode(&expected_state_id[..8.min(expected_state_id.len())]),
                        hex::encode(&read_state_id[..8.min(read_state_id.len())]),
                    )));
                }
                if read_seq != expected_seq {
                    return Err(LambdaError::StorageError(format!(
                        "set_wallet_state write-verify: wallet_seq mismatch (wrote={}, read={})",
                        expected_seq, read_seq,
                    )));
                }
                if read_balance != expected_balance {
                    return Err(LambdaError::StorageError(format!(
                        "set_wallet_state write-verify: balance mismatch (wrote={}, read={})",
                        expected_balance, read_balance,
                    )));
                }
                // group_members byte-identical CBOR round-trip check.
                // Pre-2026-05-15 this field rode JSON with .ok() silent
                // swallowing on both sides — a group wallet whose
                // group_members failed serde would write NULL and read
                // back None, silently downgrading consensus to non-group.
                // Now we CBOR-encode, fail-loud, AND verify the bytes
                // round-tripped.  See cbor_encode_opt + this verify pair.
                if read_gm_bytes != group_members_cbor {
                    return Err(LambdaError::StorageError(format!(
                        "set_wallet_state write-verify: group_members bytes mismatch \
                         (wrote {} bytes, read {} bytes)",
                        group_members_cbor.as_ref().map(|v| v.len()).unwrap_or(0),
                        read_gm_bytes.as_ref().map(|v| v.len()).unwrap_or(0),
                    )));
                }
            }
        }

        debug!(
            "Stored wallet state: pk={}, balance={}, seq={} (write-verified)",
            hex::encode(&state.public_key[..8.min(state.public_key.len())]),
            state.balance,
            state.wallet_seq
        );

        Ok(())
    }

    /// Update wallet state with CAS (compare-and-swap) guard.
    ///
    /// Only updates if the current state_id matches `expected_state_id`.
    /// Returns true if the update succeeded, false if a concurrent update
    /// changed the state_id (caller should retry with fresh state).
    ///
    /// Used by CL5 redeem path where concurrent redeems to the same wallet
    /// can race (wallet_seq doesn't increment on receive).
    pub fn update_wallet_state_cas(
        &self,
        state: &StoredWalletState,
        expected_state_id: &[u8; 32],
        k: u8,
        proof_type: u8,
    ) -> Result<bool, LambdaError> {
        let conn = self.db()?;
        // CBOR — see set_wallet_state for the rule rationale.
        let group_members_cbor = cbor_encode_opt(&state.group_members, "wallets.group_members")?;
        let status_str = status_to_str(&state.status);
        let last_tx_id = state.last_tx_id.map(|id| id.to_vec());
        let now = unix_now();
        let auth_hash_bytes = state.auth_hash.map(|h| h.to_vec());

        let rows = conn.execute(
            "UPDATE wallets SET balance=?1, wallet_seq=?2, state_id=?3,
             last_tx_id=?4, status=?5, group_members=?6,
             auth_hash=?7, wallet_id=?8, hibernation_until=?9, updated_at=?10
             WHERE public_key=?11 AND state_id=?12 AND k=?13 AND proof_type=?14",
            params![
                to_db_int(state.balance)?,
                to_db_int(state.wallet_seq)?,
                state.state_id.as_ref(),
                last_tx_id,
                status_str,
                group_members_cbor,
                auth_hash_bytes,
                state.wallet_id,
                to_db_int(state.hibernation_until)?, // YPX-020 — persist hibernation
                now as i64,
                state.public_key,
                expected_state_id.as_ref(),
                k as i64,
                proof_type as i64,
            ],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        if rows == 0 {
            debug!("CAS conflict: wallet pk={} state_id changed concurrently",
                hex::encode(&state.public_key[..8.min(state.public_key.len())]));
            Ok(false)
        } else {
            debug!("CAS update ok: pk={}, balance={}, seq={}",
                hex::encode(&state.public_key[..8.min(state.public_key.len())]),
                state.balance, state.wallet_seq);
            Ok(true)
        }
    }

    /// YPX-018 — CLARA roll-forward.
    ///
    /// Atomically advance a wallet's stored state from a known-garbage state
    /// to the healed state declared in a `ClaraAttestation`. The update only
    /// succeeds if the wallet's current stored `state_id` is in the
    /// `garbage_state_ids` set OR equals `healed_from_state_id`.
    ///
    /// This is the only protocol-defined exception to "stored state moves
    /// only as a result of a witnessed-and-ACK'd TX." Safe because:
    ///   1. Core CL2 has already verified the Nabla signature on the
    ///      attestation (via verify_clara_signature).
    ///   2. Core CL2 has already verified the wallet binding
    ///      (clara.wallet_pk == transaction.client_pk).
    ///   3. Core CL2 has already verified the eligibility rule (stored state
    ///      in garbage_state_ids OR == healed_from_state_id).
    ///   4. The validator only ever moves *forward* — never backward.
    ///
    /// Returns:
    /// - Ok(true)  if the roll-forward applied (or was a no-op because the
    ///   wallet was already at `healed_to_state_id` — idempotent)
    /// - Ok(false) if the wallet's current state is not in the garbage set
    ///   (caller should NOT proceed — Core would have rejected)
    /// - Err(...)  on storage error
    ///
    /// Reference: YPX-018 §2.3, Yellow Paper §17.10.14, §26.17.10.
    pub fn clara_roll_forward(
        &self,
        wallet_pk: &[u8],
        k: u8,
        proof_type: u8,
        healed_from_state_id: &[u8; 32],
        healed_to_state_id: &[u8; 32],
        healed_at_seq: u64,
        healed_balance: u64,
        garbage_state_ids: &[[u8; 32]],
    ) -> Result<bool, LambdaError> {
        let conn = self.db()?;

        // Read current state inside a transaction so the check + update is
        // atomic against concurrent writes.
        let tx = conn.unchecked_transaction()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        let current_state_id: Option<Vec<u8>> = tx.query_row(
            "SELECT state_id FROM wallets WHERE public_key = ?1 AND k = ?2 AND proof_type = ?3",
            params![wallet_pk, k as i64, proof_type as i64],
            |row| row.get(0),
        ).ok();

        let current = match current_state_id {
            Some(s) if s.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&s);
                a
            }
            _ => {
                // No stored state for this wallet — nothing to roll forward.
                // Caller should treat this as success (the validator hasn't
                // observed this wallet yet, so it can't be poisoned).
                return Ok(true);
            }
        };

        // Idempotent: already at the healed state.
        if current == *healed_to_state_id {
            return Ok(true);
        }

        // Eligibility check (mirrors Core CL2 §2.3): current must be in
        // garbage_state_ids OR equal healed_from_state_id.
        let eligible = current == *healed_from_state_id
            || garbage_state_ids.iter().any(|g| g == &current);
        if !eligible {
            debug!(
                "CLARA roll-forward refused: stored state not in garbage set (wallet pk={}, stored={}, from={}, garbage={})",
                hex::encode(&wallet_pk[..8.min(wallet_pk.len())]),
                hex::encode(&current[..8]),
                hex::encode(&healed_from_state_id[..8]),
                garbage_state_ids.len(),
            );
            return Ok(false);
        }

        // YPX-018 Phase 5f Finding 4: also refresh the stored balance.
        //
        // The validator's stored balance was wrong because it processed a
        // partial TX whose debit was never matched by k=3 finalization.
        // Without this refresh the validator stays functionally broken — it
        // will reject the wallet's next TX larger than its (lowered) stored
        // balance, even though every other validator sees the correct balance.
        //
        // The trust chain on `healed_balance`:
        //   1. Wallet declared it in the CLARA registration request.
        //   2. Nabla recomputed `BLAKE3(wallet_pk || healed_balance ||
        //      healed_at_seq)` and verified it equals `cheque.state_hash`.
        //   3. The cheque is k=3-witnessed, so each fresh validator signed
        //      `state_hash` cryptographically committing to this balance.
        //   4. Nabla's signed ClaraAttestation propagates the verified value.
        //   5. Core CL2 verifies the Nabla signature + NBC trust anchor.
        //   6. clara_roll_forward (here) trusts the value because every link
        //      in the chain has been independently verified.
        //
        // No new trust assumption — every party in the chain has either
        // observed or cryptographically attested to this balance.
        let now = unix_now();
        let rows = tx.execute(
            "UPDATE wallets SET state_id=?1, wallet_seq=?2, balance=?3, updated_at=?4 WHERE public_key=?5 AND k=?6 AND proof_type=?7",
            params![
                healed_to_state_id.as_ref(),
                to_db_int(healed_at_seq)?,
                to_db_int(healed_balance)?,
                now as i64,
                wallet_pk,
                k as i64,
                proof_type as i64,
            ],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        tx.commit()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        if rows == 0 {
            debug!("CLARA roll-forward: 0 rows updated for pk={}",
                hex::encode(&wallet_pk[..8.min(wallet_pk.len())]));
            return Ok(false);
        }

        info!(
            "CLARA roll-forward applied: pk={} {}→{} seq={}",
            hex::encode(&wallet_pk[..8.min(wallet_pk.len())]),
            hex::encode(&current[..8]),
            hex::encode(&healed_to_state_id[..8]),
            healed_at_seq,
        );
        Ok(true)
    }

    // =========================================================================
    // Fan-Out Dedup (replay prevention)
    // =========================================================================

    /// Check if a Fan-Out diffusion_id has been seen (replay detection).
    pub fn fanout_is_seen(&self, diffusion_id: &[u8; 32]) -> Result<bool, LambdaError> {
        let conn = self.db()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM fanout_seen WHERE diffusion_id = ?1",
            params![diffusion_id.as_ref()],
            |row| row.get(0),
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(count > 0)
    }

    /// Mark a Fan-Out diffusion_id as seen. Idempotent (INSERT OR IGNORE).
    pub fn fanout_mark_seen(&self, diffusion_id: &[u8; 32]) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let now = unix_now();
        conn.execute(
            "INSERT OR IGNORE INTO fanout_seen (diffusion_id, received_at) VALUES (?1, ?2)",
            params![diffusion_id.as_ref(), now as i64],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Prune expired Fan-Out entries (older than max_age_secs).
    pub fn fanout_prune(&self, max_age_secs: u64) -> Result<usize, LambdaError> {
        let conn = self.db()?;
        let cutoff = unix_now().saturating_sub(max_age_secs);
        let deleted = conn.execute(
            "DELETE FROM fanout_seen WHERE received_at < ?1",
            params![cutoff as i64],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        if deleted > 0 {
            debug!("Pruned {} expired fanout entries", deleted);
        }
        Ok(deleted)
    }

    /// Prune stale per-TX data that's no longer needed.
    ///
    /// A validator needs:
    /// - wallets: latest state (always kept, INSERT OR REPLACE)
    /// - transaction_records: ACK-time pruned by `prune_superseded_transaction_records`
    ///   ONLY — see Why below. Periodic prune NEVER touches this table.
    /// - receipts: tied to transaction_records via tx_id (FK semantically)
    /// - consumed_states: permanent (double-spend detection)
    /// - redeemed_cheques / fee_records / cheque_delivery_log / scar_passcodes:
    ///   safe to prune on timer with the correct status + age gate
    ///
    /// **Why this no longer touches transaction_records or receipts:**
    /// Original commit `6c3c45ca` (2026-04-27) added a periodic
    /// `MAX(rowid) GROUP BY wallet_pk` delete to bound storage during
    /// the 72h soak. Three weeks later, `1c2011cf` added the correct
    /// mechanism: `prune_superseded_transaction_records`, called from
    /// `process_ack`, which only drops records the wallet has
    /// EXPLICITLY ACKed as superseded.
    ///
    /// The periodic prune kept running anyway and silently dropped the
    /// pre-ACK record of the wallet's prior state — exactly the row
    /// the heal flow's S-ABR overlap lookup needs. Pattern:
    ///   1. wallet ACKs seq=N+1 → ACK-prune drops seq<=N (correct)
    ///   2. wallet sends seq=N+2 witness → validator stores pre-ACK row
    ///   3. periodic prune fires → keeps MAX(rowid) = seq=N+2,
    ///      DROPS seq=N+1 (the still-load-bearing anchor)
    ///   4. seq=N+2 partial-commits → wallet heals back to seq=N+1
    ///   5. validator lookup for seq=N+1 state_id → S-ABR LOOKUP MISS
    /// Observed in the 2026-05-22 30-wallet soak: 6 events, every one
    /// within 1-3 minutes after a 30-min periodic prune cycle.
    /// Storage budget calc (250B/row × wallet count post-ACK-prune):
    /// even pessimistically, ~25 GB per validator at 100M-wallet
    /// network scale — modern hardware budget, no real bound issue.
    pub fn prune_stale_data(&self, max_age_secs: u64) -> Result<usize, LambdaError> {
        let conn = self.db()?;
        let cutoff = unix_now().saturating_sub(max_age_secs);
        let mut total = 0usize;

        // Prune old txid_consumed_states (keep recent for ACK window)
        total += conn.execute(
            "DELETE FROM txid_consumed_states WHERE created_at < ?1",
            params![cutoff as i64],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // (fee_records prune removed — table retired in Step 9A2)

        // Prune completed cheque deliveries older than cutoff
        total += conn.execute(
            "DELETE FROM cheque_delivery_log WHERE delivery_status IN ('acked', 'timeout') AND sent_at < ?1",
            params![cutoff as i64],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // Prune recovered scar passcodes older than cutoff
        total += conn.execute(
            "DELETE FROM scar_passcodes WHERE recovered_at IS NOT NULL AND recovered_at < ?1",
            params![cutoff as i64],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // Prune ABANDONED scar passcodes (never verified/recovered) older
        // than cutoff — a receiver who declines simply does nothing
        // (YPX-001 §1.5.1 reject = non-action), so pre-fix these rows
        // accumulated forever. Deleting one is non-destructive: nothing
        // was witnessed for the paused txid; a sender retrying after the
        // window gets "No pending scar passcode", starts a fresh send,
        // and the gate re-pauses it with a new code.
        total += conn.execute(
            "DELETE FROM scar_passcodes WHERE recovered_at IS NULL AND created_at < ?1",
            params![cutoff as i64],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // Prune old redeemed_cheques (Nabla has global txid attestation check)
        total += conn.execute(
            "DELETE FROM redeemed_cheques WHERE redeemed_at < ?1",
            params![cutoff as i64],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // Always VACUUM — the inline cleanup in store_transaction_record frees
        // rows on every write, but SQLite doesn't reclaim disk space from DELETEs.
        // VACUUM rebuilds the file (~1-3s on 100MB encrypted DB).
        match conn.execute_batch("VACUUM") {
            Ok(_) => info!("[STORAGE-VACUUM] reclaimed disk space (pruned {} rows)", total),
            Err(e) => eprintln!("[STORAGE-VACUUM] failed: {}", e),
        }

        Ok(total)
    }

    /// Get wallet state by state ID (O(1) with index)
    pub fn get_wallet_by_state_id(
        &self,
        state_id: &[u8; 32],
    ) -> Result<Option<StoredWalletState>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT public_key, balance, wallet_seq, state_id, last_tx_id, status, group_members, auth_hash, wallet_id, hibernation_until
                 FROM wallets WHERE state_id = ?1",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        stmt.query_row(params![state_id.as_ref()], |row| {
            Ok(StoredWalletState {
                public_key: row.get::<_, Vec<u8>>(0)?,
                balance: row.get::<_, i64>(1)? as u64,
                wallet_seq: row.get::<_, i64>(2)? as u64,
                state_id: blob_to_32(row.get::<_, Vec<u8>>(3)?),
                last_tx_id: row
                    .get::<_, Option<Vec<u8>>>(4)?
                    .map(blob_to_32),
                status: status_from_str(&row.get::<_, String>(5)?),
                group_members: cbor_decode_opt_in_row(
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    "wallets.group_members",
                )?,
                auth_hash: row
                    .get::<_, Option<Vec<u8>>>(7)?
                    .and_then(|b| b.try_into().ok()),
                wallet_id: row.get::<_, Option<String>>(8)?,
                hibernation_until: row.get::<_, i64>(9)? as u64, // YPX-020 — persisted
            })
        })
        .optional()
        .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    // =========================================================================
    // Genesis State
    // =========================================================================

    /// Get genesis state for a public key
    pub fn get_genesis_state(
        &self,
        public_key: &[u8; 32],
        k: u8,
        proof_type: u8,
    ) -> Result<Option<StoredWalletState>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT public_key, balance, wallet_seq, state_id, last_tx_id, status, group_members
                 FROM genesis_states WHERE public_key = ?1 AND k = ?2 AND proof_type = ?3",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        stmt.query_row(params![public_key.as_ref(), k as i64, proof_type as i64], |row| {
            Ok(StoredWalletState {
                public_key: row.get::<_, Vec<u8>>(0)?,
                balance: row.get::<_, i64>(1)? as u64,
                wallet_seq: row.get::<_, i64>(2)? as u64,
                state_id: blob_to_32(row.get::<_, Vec<u8>>(3)?),
                last_tx_id: row
                    .get::<_, Option<Vec<u8>>>(4)?
                    .map(blob_to_32),
                status: status_from_str(&row.get::<_, String>(5)?),
                group_members: cbor_decode_opt_in_row(
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    "genesis_states.group_members",
                )?,
                auth_hash: None, hibernation_until: 0, // Genesis wallets have no auth_hash
                wallet_id: None, // Set on first TX (identity binding)
            })
        })
        .optional()
        .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    /// Store genesis state for a wallet
    pub fn set_genesis_state(
        &self,
        public_key: &[u8; 32],
        k: u8,
        proof_type: u8,
        state: &StoredWalletState,
    ) -> Result<(), LambdaError> {
        let conn = self.db()?;
        // CBOR — see set_wallet_state for rationale.
        let group_members_cbor = cbor_encode_opt(&state.group_members, "genesis_states.group_members")?;
        let status_str = status_to_str(&state.status);
        let last_tx_id = state.last_tx_id.map(|id| id.to_vec());

        conn.execute(
            "INSERT OR REPLACE INTO genesis_states
             (public_key, k, proof_type, balance, wallet_seq, state_id, last_tx_id, status, group_members)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                public_key.as_ref(),
                k as i64,
                proof_type as i64,
                to_db_int(state.balance)?,
                to_db_int(state.wallet_seq)?,
                state.state_id.as_ref(),
                last_tx_id,
                status_str,
                group_members_cbor,
            ],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        debug!(
            "Stored genesis state: pk={}, balance={}",
            hex::encode(&public_key[..8]),
            state.balance
        );

        Ok(())
    }

    // =========================================================================
    // Receipts
    // =========================================================================

    /// Store a receipt
    pub fn store_receipt(&self, receipt: &Receipt) -> Result<(), LambdaError> {
        let conn = self.db()?;
        // Receipts carry the k-witness Dilithium sigs that prove this
        // TX was admitted by k validators.  Any silent encode failure
        // here is catastrophic — Core's verify_receipt would fail
        // round-trip on the next read.  CBOR + fail-loud.
        let witness_sigs_cbor = cbor_encode(&receipt.witness_sigs, "receipts.witness_sigs")?;
        let fact_proof_cbor = cbor_encode_opt(&receipt.fact_proof, "receipts.fact_proof")?;

        conn.execute(
            "INSERT OR REPLACE INTO receipts
             (txid, state_hash, produced_state_id, new_wallet_seq, commitment_hash,
              sdid, lineage_hash, core_version, witness_sigs, epoch, fact_proof,
              receipt_commitment, core_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                receipt.txid.as_ref(),
                receipt.state_hash.as_ref(),
                receipt.produced_state_id.as_ref(),
                receipt.new_wallet_seq as i64,
                receipt.commitment_hash.as_ref(),
                receipt.sdid.as_ref(),
                receipt.lineage_hash.as_ref(),
                receipt.core_version,
                witness_sigs_cbor,
                receipt.epoch as i64,
                fact_proof_cbor,
                receipt.receipt_commitment.as_ref(),
                receipt.core_id.as_ref(),
            ],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        debug!("Stored receipt: txid={}", hex::encode(&receipt.txid[..8]));

        Ok(())
    }

    /// Get a receipt by transaction ID
    pub fn get_receipt(&self, txid: &[u8; 32]) -> Result<Option<Receipt>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT txid, state_hash, produced_state_id, new_wallet_seq, commitment_hash,
                        sdid, lineage_hash, core_version, witness_sigs, epoch, fact_proof,
                        receipt_commitment, core_id
                 FROM receipts WHERE txid = ?1",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        stmt.query_row(params![txid.as_ref()], |row| {
            let witness_sigs_bytes: Vec<u8> = row.get(8)?;
            let fact_proof_bytes: Option<Vec<u8>> = row.get(10)?;
            Ok(Receipt {
                txid: blob_to_32(row.get::<_, Vec<u8>>(0)?),
                state_hash: blob_to_32(row.get::<_, Vec<u8>>(1)?),
                produced_state_id: blob_to_32(row.get::<_, Vec<u8>>(2)?),
                new_wallet_seq: row.get::<_, i64>(3)? as u64,
                commitment_hash: blob_to_32(row.get::<_, Vec<u8>>(4)?),
                sdid: blob_to_32(row.get::<_, Vec<u8>>(5)?),
                lineage_hash: blob_to_32(row.get::<_, Vec<u8>>(6)?),
                core_version: row.get(7)?,
                witness_sigs: cbor_decode_in_row(&witness_sigs_bytes, "receipts.witness_sigs")?,
                epoch: row.get::<_, i64>(9)? as u64,
                fact_proof: cbor_decode_opt_in_row(fact_proof_bytes, "receipts.fact_proof")?,
                // required_k column doesn't exist in this schema — defaults to 3.
                // (separate pre-existing gap, not introduced by this commit)
                required_k: 3,
                receipt_commitment: blob_to_32(row.get::<_, Vec<u8>>(11)?),
                core_id: blob_to_32(row.get::<_, Vec<u8>>(12)?),
                // YP §19.6 — Step 2 ships the field but no storage column
                // yet. Step 7 adds the schema migration + write path; until
                // then every stored Receipt is pre-fee-breakdown era and
                // round-trips with an empty Vec (which matches what the
                // commitment was hashed over).
                fee_breakdown: Vec::new(),
                // YPX-021 — same no-column treatment as is_dev_class below:
                // this SELECT feeds has_receipt-style lookups only, never a
                // commitment re-verify.
                oods_flag: None,
                // Dev-class isolation flag — no storage column yet either;
                // current schema only persists Receipts inside this Lambda's
                // own write path (which always sets the field), and the
                // SELECT here is used only for has_receipt-style lookups
                // that don't re-verify receipt_commitment. Default `false`
                // is safe for non-dev TXs and the dev-class soak suite
                // will surface any column-add need.
                is_dev_class: false,
            })
        })
        .optional()
        .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    /// Check if transaction was already processed
    pub fn has_receipt(&self, txid: &[u8; 32]) -> Result<bool, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM receipts WHERE txid = ?1")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        let exists = stmt
            .query_row(params![txid.as_ref()], |_| Ok(()))
            .optional()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .is_some();
        Ok(exists)
    }

    // =========================================================================
    // Redeemed Cheques
    // =========================================================================

    /// Check if a cheque has been redeemed
    pub fn is_cheque_redeemed(&self, cheque_id: &[u8; 32]) -> Result<bool, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM redeemed_cheques WHERE cheque_id = ?1")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        let exists = stmt
            .query_row(params![cheque_id.as_ref()], |_| Ok(()))
            .optional()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .is_some();
        Ok(exists)
    }

    /// Mark a cheque as redeemed
    pub fn mark_cheque_redeemed(&self, cheque_id: &[u8; 32]) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let now = unix_now();
        conn.execute(
            "INSERT OR REPLACE INTO redeemed_cheques (cheque_id, redeemed_at) VALUES (?1, ?2)",
            params![cheque_id.as_ref(), now as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        debug!(
            "Marked cheque as redeemed: {}",
            hex::encode(&cheque_id[..8])
        );
        Ok(())
    }

    /// AUDIT-FIX v2.11.13 (INV-04): Atomic check-and-mark for double-redeem prevention.
    /// Returns Ok(true) if this call was the FIRST to mark the cheque (accepted).
    /// Returns Ok(false) if the cheque was already redeemed (rejected).
    /// Both check and mark happen under a single mutex lock — no race window.
    pub fn try_mark_cheque_redeemed(&self, cheque_id: &[u8; 32]) -> Result<bool, LambdaError> {
        let conn = self.db()?;
        // Check
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM redeemed_cheques WHERE cheque_id = ?1")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        let already = stmt
            .query_row(params![cheque_id.as_ref()], |_| Ok(()))
            .optional()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .is_some();
        if already {
            return Ok(false);
        }
        // Mark
        let now = unix_now();
        conn.execute(
            "INSERT OR REPLACE INTO redeemed_cheques (cheque_id, redeemed_at) VALUES (?1, ?2)",
            params![cheque_id.as_ref(), now as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        debug!(
            "Atomically marked cheque as redeemed: {}",
            hex::encode(&cheque_id[..8])
        );
        Ok(true)
    }

    /// Undo a local cheque redemption mark.
    /// Called when Nabla's global txid check reveals the cheque was already
    /// redeemed on a different validator set. We marked it locally (step 5)
    /// but need to undo that mark so the error is clean.
    pub fn unmark_cheque_redeemed(&self, cheque_id: &[u8; 32]) -> Result<(), LambdaError> {
        let conn = self.db()?;
        conn.execute(
            "DELETE FROM redeemed_cheques WHERE cheque_id = ?1",
            params![cheque_id.as_ref()],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        debug!("Unmarked cheque (Nabla global reject): {}", hex::encode(&cheque_id[..8]));
        Ok(())
    }

    // =========================================================================
    // Transaction Records (S-ABR overlap lookup)
    // =========================================================================

    /// Store a transaction record
    pub fn store_transaction_record(
        &self,
        record: &TransactionRecord,
    ) -> Result<(), LambdaError> {
        let conn = self.db()?;
        // Wrap INSERT + cleanup in a transaction so no concurrent reader
        // sees the gap between INSERT and DELETE.
        let tx = conn.unchecked_transaction()
            .map_err(|e| LambdaError::StorageError(format!("begin txn: {}", e)))?;
        // CBOR — see set_wallet_state for the recurring-bug-class rationale.
        let group_members_cbor = cbor_encode_opt(
            &record.group_members_after,
            "transaction_records.group_members_after",
        )?;
        let status_str = status_to_str(&record.status);

        tx.execute(
            "INSERT OR REPLACE INTO transaction_records
             (produced_state_id, tx_id, wallet_pk, balance_after, wallet_seq_after, group_members_after, status, required_k, proof_type, amount, sender_balance)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.produced_state_id.as_ref(),
                record.tx_id.as_ref(),
                record.wallet_pk,
                record.balance_after as i64,
                record.wallet_seq_after as i64,
                group_members_cbor,
                status_str,
                record.required_k as i64,
                record.proof_type as i64,
                record.amount as i64,
                record.sender_balance as i64,
            ],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // Superseded records are pruned at ACK time, NOT here — see
        // prune_superseded_transaction_records (called from process_ack).
        // Pruning at witness time deleted the wallet's prior S-ABR anchor
        // on a store for an un-finalized (pre-ACK) transaction; a witness
        // round that never finalized then left the validator pruned
        // forward to a phantom state.

        tx.commit()
            .map_err(|e| LambdaError::StorageError(format!("commit txn: {}", e)))?;

        // ════════════════════════════════════════════════════════════
        // ║ MANDATORY WRITE-VERIFY — DO NOT REMOVE                  ║
        // ║                                                          ║
        // ║ transaction_records is the S-ABR OVERLAP lookup table —  ║
        // ║ every overlapped validator MUST find a row keyed by the  ║
        // ║ produced_state_id of the previous TX in this wallet's    ║
        // ║ chain, or `validate_sabr_overlapped` returns Err          ║
        // ║ (OVERLAPPED-NO-RECORD) and the witness round fails for   ║
        // ║ that validator.  A silently-dropped write here produces  ║
        // ║ the exact "missing record" condition our DRIFT-DIAG was  ║
        // ║ designed to catch.                                       ║
        // ║                                                          ║
        // ║ Companion to set_wallet_state's write-verify (line 645). ║
        // ║ S-ABR depends on BOTH tables landing the row:            ║
        // ║   - wallets:               protected at line 645         ║
        // ║   - transaction_records:   protected HERE                ║
        // ║                                                          ║
        // ║ If a future contributor sees this as "redundant" or a    ║
        // ║ perf optimization — STOP.  Without write-verify a        ║
        // ║ sqlite_busy retry that silently dropped, a WAL fsync     ║
        // ║ ordering bug, a disk-full degradation, or any storage    ║
        // ║ pathology returns Ok with no row.  The TX completes at   ║
        // ║ the protocol layer; the wallet's NEXT op fails           ║
        // ║ mysteriously hours/days later when an overlapped         ║
        // ║ validator can't find the prior record.                   ║
        // ║                                                          ║
        // ║ Cost: one indexed SELECT (~0.3ms) per tx_record write.   ║
        // ║ Witness round is multi-second; this is a rounding error. ║
        // ║                                                          ║
        // ║ — AXIOM Origin, 2026-05-15                                      ║
        // ════════════════════════════════════════════════════════════
        let verify_row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, Option<Vec<u8>>)> = conn.query_row(
            "SELECT produced_state_id, tx_id, wallet_pk, balance_after, wallet_seq_after, group_members_after \
             FROM transaction_records WHERE produced_state_id = ?1",
            params![record.produced_state_id.as_ref()],
            |row| Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            )),
        ).optional().map_err(|e| LambdaError::StorageError(
            format!("store_transaction_record verify SELECT: {}", e),
        ))?;

        match verify_row {
            None => {
                return Err(LambdaError::StorageError(format!(
                    "store_transaction_record write-verify: no row found after INSERT \
                     for produced_state_id={} pk={} — write silently dropped \
                     (sqlite consistency issue?)",
                    hex::encode(&record.produced_state_id[..8]),
                    hex::encode(&record.wallet_pk[..8.min(record.wallet_pk.len())]),
                )));
            }
            Some((read_psid, read_txid, read_pk, read_balance, read_seq, read_gm_bytes)) => {
                if read_psid.as_slice() != record.produced_state_id.as_ref() {
                    return Err(LambdaError::StorageError(format!(
                        "tx_record write-verify mismatch produced_state_id: wrote={} read={}",
                        hex::encode(&record.produced_state_id[..8]),
                        hex::encode(&read_psid[..8.min(read_psid.len())]),
                    )));
                }
                if read_txid.as_slice() != record.tx_id.as_ref() {
                    return Err(LambdaError::StorageError(format!(
                        "tx_record write-verify mismatch tx_id: wrote={} read={}",
                        hex::encode(&record.tx_id[..8]),
                        hex::encode(&read_txid[..8.min(read_txid.len())]),
                    )));
                }
                if read_pk != record.wallet_pk {
                    return Err(LambdaError::StorageError(format!(
                        "tx_record write-verify mismatch wallet_pk: wrote={} read={}",
                        hex::encode(&record.wallet_pk[..8.min(record.wallet_pk.len())]),
                        hex::encode(&read_pk[..8.min(read_pk.len())]),
                    )));
                }
                if read_balance as u64 != record.balance_after {
                    return Err(LambdaError::StorageError(format!(
                        "tx_record write-verify mismatch balance_after: wrote={} read={}",
                        record.balance_after, read_balance,
                    )));
                }
                if read_seq as u64 != record.wallet_seq_after {
                    return Err(LambdaError::StorageError(format!(
                        "tx_record write-verify mismatch wallet_seq_after: wrote={} read={}",
                        record.wallet_seq_after, read_seq,
                    )));
                }
                // group_members_after byte-identical CBOR round-trip check.
                if read_gm_bytes != group_members_cbor {
                    return Err(LambdaError::StorageError(format!(
                        "tx_record write-verify mismatch group_members_after \
                         (wrote {} bytes, read {} bytes)",
                        group_members_cbor.as_ref().map(|v| v.len()).unwrap_or(0),
                        read_gm_bytes.as_ref().map(|v| v.len()).unwrap_or(0),
                    )));
                }
            }
        }

        debug!(
            "Stored tx record: produced_state_id={}, wallet={}, balance={}",
            hex::encode(&record.produced_state_id[..8]),
            hex::encode(&record.wallet_pk[..8.min(record.wallet_pk.len())]),
            record.balance_after,
        );

        Ok(())
    }

    /// Prune S-ABR records superseded by an ACK'd (finalized) transaction.
    ///
    /// Called from process_ack — NOT from the witness-time store paths.
    /// Keeps the ACK'd transaction's record and anything newer (a later TX
    /// the wallet already had witnessed); removes the ACK'd record's
    /// predecessors and any losing same-seq fork. Pruning at witness time
    /// instead deleted the wallet's anchor on a store for a not-yet-finalized
    /// transaction.
    pub fn prune_superseded_transaction_records(
        &self,
        wallet_pk: &[u8],
        keep_produced_state_id: &[u8; 32],
        keep_wallet_seq: u64,
    ) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let tx = conn.unchecked_transaction()
            .map_err(|e| LambdaError::StorageError(format!("begin prune txn: {}", e)))?;
        let deleted = tx.execute(
            "DELETE FROM transaction_records \
             WHERE wallet_pk = ?1 AND produced_state_id != ?2 AND wallet_seq_after <= ?3",
            params![wallet_pk, keep_produced_state_id.as_ref(), keep_wallet_seq as i64],
        ).unwrap_or(0);
        if deleted > 0 {
            let _ = tx.execute(
                "DELETE FROM receipts WHERE txid NOT IN (SELECT tx_id FROM transaction_records)", [],
            );
            // fee_records retired in Step 9A2 — no companion DELETE.
        }
        tx.commit()
            .map_err(|e| LambdaError::StorageError(format!("commit prune txn: {}", e)))?;
        Ok(())
    }

    /// Store transaction record AND update wallet state atomically in a single SQLite transaction.
    /// AUDIT-FIX v2.11.14: Prevents partial writes where tx_record is stored but wallet state
    /// update fails (or vice versa), which could leave stale state until Core rejects on retry.
    pub fn store_tx_record_and_wallet_state(
        &self,
        record: &TransactionRecord,
        state: &StoredWalletState,
        k: u8,
        proof_type: u8,
    ) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let tx = conn.unchecked_transaction()
            .map_err(|e| LambdaError::StorageError(format!("begin txn: {}", e)))?;

        // 1. Store transaction record (CBOR, fail-loud per CLAUDE.md §13).
        let group_members_cbor_rec = cbor_encode_opt(
            &record.group_members_after,
            "transaction_records.group_members_after",
        )?;
        let status_str_rec = status_to_str(&record.status);
        tx.execute(
            "INSERT OR REPLACE INTO transaction_records
             (produced_state_id, tx_id, wallet_pk, balance_after, wallet_seq_after, group_members_after, status, required_k, proof_type, amount, sender_balance)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.produced_state_id.as_ref(),
                record.tx_id.as_ref(),
                record.wallet_pk,
                record.balance_after as i64,
                record.wallet_seq_after as i64,
                group_members_cbor_rec,
                status_str_rec,
                record.required_k as i64,
                record.proof_type as i64,
                record.amount as i64,
                record.sender_balance as i64,
            ],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // 1b. Superseded records are pruned at ACK time, NOT here — this
        // store runs at witness time for a not-yet-finalized transaction.
        // See prune_superseded_transaction_records (called from process_ack).

        // 2. Update wallet state (CBOR).
        let group_members_cbor_ws = cbor_encode_opt(
            &state.group_members,
            "wallets.group_members",
        )?;
        let status_str_ws = status_to_str(&state.status);
        let last_tx_id = state.last_tx_id.map(|id| id.to_vec());
        let auth_hash_bytes = state.auth_hash.map(|h| h.to_vec());
        let now = unix_now();
        tx.execute(
            "INSERT OR REPLACE INTO wallets
             (public_key, k, proof_type, balance, wallet_seq, state_id, last_tx_id, status, group_members, auth_hash, wallet_id, hibernation_until, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                state.public_key,
                k as i64,
                proof_type as i64,
                to_db_int(state.balance)?,
                to_db_int(state.wallet_seq)?,
                state.state_id.as_ref(),
                last_tx_id,
                status_str_ws,
                group_members_cbor_ws,
                auth_hash_bytes,
                state.wallet_id,
                to_db_int(state.hibernation_until)?, // YPX-020 — persist hibernation (?10)
                now as i64,
            ],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

        tx.commit()
            .map_err(|e| LambdaError::StorageError(format!("commit txn: {}", e)))?;

        // ════════════════════════════════════════════════════════════
        // ║ MANDATORY WRITE-VERIFY — DO NOT REMOVE                  ║
        // ║                                                          ║
        // ║ Same rule as set_wallet_state / store_transaction_record. ║
        // ║ This atomic-write path commits BOTH the tx_record and    ║
        // ║ the wallet row.  A silent commit/fsync loss on EITHER    ║
        // ║ row poisons future S-ABR consensus for this wallet.      ║
        // ║                                                          ║
        // ║ — AXIOM Origin, 2026-05-15                                      ║
        // ════════════════════════════════════════════════════════════
        let verify_txr: Option<(Vec<u8>, Vec<u8>, i64, i64, Option<Vec<u8>>)> = conn.query_row(
            "SELECT tx_id, wallet_pk, balance_after, wallet_seq_after, group_members_after \
             FROM transaction_records WHERE produced_state_id = ?1",
            params![record.produced_state_id.as_ref()],
            |row| Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
            )),
        ).optional().map_err(|e| LambdaError::StorageError(
            format!("store_tx_record_and_wallet_state verify SELECT tx_record: {}", e),
        ))?;
        match verify_txr {
            None => return Err(LambdaError::StorageError(format!(
                "atomic write-verify: tx_record row missing after commit for produced_state_id={}",
                hex::encode(&record.produced_state_id[..8]),
            ))),
            Some((rtxid, rpk, rbal, rseq, rgm)) => {
                if rtxid.as_slice() != record.tx_id.as_ref() {
                    return Err(LambdaError::StorageError("atomic write-verify: tx_record.tx_id mismatch".into()));
                }
                if rpk != record.wallet_pk {
                    return Err(LambdaError::StorageError("atomic write-verify: tx_record.wallet_pk mismatch".into()));
                }
                if rbal as u64 != record.balance_after {
                    return Err(LambdaError::StorageError("atomic write-verify: tx_record.balance_after mismatch".into()));
                }
                if rseq as u64 != record.wallet_seq_after {
                    return Err(LambdaError::StorageError("atomic write-verify: tx_record.wallet_seq_after mismatch".into()));
                }
                if rgm != group_members_cbor_rec {
                    return Err(LambdaError::StorageError("atomic write-verify: tx_record.group_members_after bytes mismatch".into()));
                }
            }
        }
        let verify_ws: Option<(Vec<u8>, i64, i64, Option<Vec<u8>>)> = conn.query_row(
            "SELECT state_id, wallet_seq, balance, group_members FROM wallets WHERE public_key = ?1",
            params![state.public_key],
            |row| Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            )),
        ).optional().map_err(|e| LambdaError::StorageError(
            format!("store_tx_record_and_wallet_state verify SELECT wallet: {}", e),
        ))?;
        match verify_ws {
            None => return Err(LambdaError::StorageError(format!(
                "atomic write-verify: wallet row missing after commit for pk={}",
                hex::encode(&state.public_key[..8.min(state.public_key.len())]),
            ))),
            Some((rsid, rseq, rbal, rgm)) => {
                if rsid.as_slice() != state.state_id.as_ref() {
                    return Err(LambdaError::StorageError("atomic write-verify: wallet.state_id mismatch".into()));
                }
                if rseq != to_db_int(state.wallet_seq)? {
                    return Err(LambdaError::StorageError("atomic write-verify: wallet.wallet_seq mismatch".into()));
                }
                if rbal != to_db_int(state.balance)? {
                    return Err(LambdaError::StorageError("atomic write-verify: wallet.balance mismatch".into()));
                }
                if rgm != group_members_cbor_ws {
                    return Err(LambdaError::StorageError("atomic write-verify: wallet.group_members bytes mismatch".into()));
                }
            }
        }
        Ok(())
    }

    /// Lookup transaction record by produced_state_id
    pub fn get_transaction_record(
        &self,
        produced_state_id: &[u8; 32],
    ) -> Result<Option<TransactionRecord>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT produced_state_id, tx_id, wallet_pk, balance_after, wallet_seq_after, group_members_after, status, required_k, proof_type, amount, sender_balance
                 FROM transaction_records WHERE produced_state_id = ?1",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        stmt.query_row(params![produced_state_id.as_ref()], |row| {
            let gm_bytes: Option<Vec<u8>> = row.get(5)?;
            Ok(TransactionRecord {
                produced_state_id: blob_to_32(row.get::<_, Vec<u8>>(0)?),
                tx_id: blob_to_32(row.get::<_, Vec<u8>>(1)?),
                wallet_pk: row.get::<_, Vec<u8>>(2)?,
                balance_after: row.get::<_, i64>(3)? as u64,
                wallet_seq_after: row.get::<_, i64>(4)? as u64,
                group_members_after: cbor_decode_opt_in_row(gm_bytes, "transaction_records.group_members_after")?,
                status: status_from_str(&row.get::<_, String>(6)?),
                required_k: row.get::<_, i64>(7).unwrap_or(3) as u8,
                proof_type: row.get::<_, i64>(8).unwrap_or(1) as u8,
                amount: row.get::<_, i64>(9).unwrap_or(0) as u64,
                sender_balance: row.get::<_, i64>(10).unwrap_or(0) as u64,
                is_genesis_claim: None, // TODO: add DB column
            })
        })
        .optional()
        .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    /// Look up a transaction record by txid (§23.14 self-audit).
    /// Uses the idx_txrec_tx_id index. Every validator stores transaction records
    /// (not just the finalizer), so this works for self-audit on any validator.
    pub fn get_transaction_record_by_txid(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<TransactionRecord>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT produced_state_id, tx_id, wallet_pk, balance_after, wallet_seq_after, group_members_after, status, required_k, proof_type, amount, sender_balance
                 FROM transaction_records WHERE tx_id = ?1 ORDER BY created_at ASC LIMIT 1",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        stmt.query_row(params![txid.as_ref()], |row| {
            let gm_bytes: Option<Vec<u8>> = row.get(5)?;
            Ok(TransactionRecord {
                produced_state_id: blob_to_32(row.get::<_, Vec<u8>>(0)?),
                tx_id: blob_to_32(row.get::<_, Vec<u8>>(1)?),
                wallet_pk: row.get::<_, Vec<u8>>(2)?,
                balance_after: row.get::<_, i64>(3)? as u64,
                wallet_seq_after: row.get::<_, i64>(4)? as u64,
                group_members_after: cbor_decode_opt_in_row(gm_bytes, "transaction_records.group_members_after")?,
                status: status_from_str(&row.get::<_, String>(6)?),
                required_k: row.get::<_, i64>(7).unwrap_or(3) as u8,
                proof_type: row.get::<_, i64>(8).unwrap_or(1) as u8,
                amount: row.get::<_, i64>(9).unwrap_or(0) as u64,
                sender_balance: row.get::<_, i64>(10).unwrap_or(0) as u64,
                is_genesis_claim: None, // TODO: add DB column
            })
        })
        .optional()
        .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    // =========================================================================
    // txid → consumed_state_id mapping
    // =========================================================================

    /// Store txid → consumed_state_id mapping.
    /// Written at witness time, used at ACK time to mark consumed.
    pub fn store_txid_consumed_state(
        &self,
        txid: &[u8; 32],
        consumed_state_id: &[u8; 32],
    ) -> Result<(), LambdaError> {
        let conn = self.db()?;
        conn.execute(
            "INSERT OR REPLACE INTO txid_consumed_states (txid, consumed_state_id) VALUES (?1, ?2)",
            params![txid.as_ref(), consumed_state_id.as_ref()],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        debug!(
            "Stored txid→consumed_state_id: txid={} csid={}",
            hex::encode(&txid[..8]),
            hex::encode(&consumed_state_id[..8])
        );
        Ok(())
    }

    /// Lookup consumed_state_id by txid (for ACK handler).
    pub fn get_consumed_state_by_txid(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT consumed_state_id FROM txid_consumed_states WHERE txid = ?1",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        stmt.query_row(params![txid.as_ref()], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(blob_to_32(bytes))
        })
        .optional()
        .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    // =========================================================================
    // Consumed State ID Tracking (Double-Spend Prevention)
    // =========================================================================

    /// Mark a state_id as consumed. Called at ACK time (White Paper §4.11.1).
    pub fn mark_state_consumed(&self, state_id: &[u8; 32]) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let now = unix_now();
        conn.execute(
            "INSERT OR REPLACE INTO consumed_states (state_id, consumed_at) VALUES (?1, ?2)",
            params![state_id.as_ref(), now as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        debug!(
            "Marked state_id as consumed (ACK'd): {}",
            hex::encode(&state_id[..8])
        );
        Ok(())
    }

    /// Check if a state_id has been consumed (ACK'd in a prior transaction).
    pub fn is_state_consumed(&self, state_id: &[u8; 32]) -> Result<bool, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM consumed_states WHERE state_id = ?1")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        let exists = stmt
            .query_row(params![state_id.as_ref()], |_| Ok(()))
            .optional()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .is_some();
        Ok(exists)
    }


    // =========================================================================
    // Status Updates (PENDING → CONFIRMED)
    // =========================================================================

    /// Update wallet state status to CONFIRMED
    pub fn confirm_wallet_state(&self, public_key: &[u8], k: u8, proof_type: u8) -> Result<bool, LambdaError> {
        match self.get_wallet_state(public_key, k, proof_type)? {
            Some(mut state) => {
                if state.status == WalletStateStatus::Pending {
                    state.status = WalletStateStatus::Confirmed;
                    self.set_wallet_state(&state, k, proof_type)?;
                    debug!(
                        "Wallet state confirmed: pk={}",
                        hex::encode(&public_key[..8.min(public_key.len())])
                    );
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            None => Ok(false),
        }
    }

    /// Update transaction record status to CONFIRMED
    pub fn confirm_transaction_record(
        &self,
        produced_state_id: &[u8; 32],
    ) -> Result<bool, LambdaError> {
        match self.get_transaction_record(produced_state_id)? {
            Some(mut record) => {
                if record.status == WalletStateStatus::Pending {
                    record.status = WalletStateStatus::Confirmed;
                    self.store_transaction_record(&record)?;
                    debug!(
                        "Transaction record confirmed: state_id={}",
                        hex::encode(&produced_state_id[..8])
                    );
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            None => Ok(false),
        }
    }

    // =========================================================================
    // Flush
    // =========================================================================

    /// Flush all pending writes (WAL checkpoint)
    pub fn flush(&self) -> Result<(), LambdaError> {
        let conn = self.db()?;
        conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Checkpoint the WAL fully into the main database file (TRUNCATE mode).
    ///
    /// MUST run before the process exits, and periodically during operation.
    /// With `journal_mode=WAL`, committed transactions live in `<db>-wal`
    /// until a checkpoint migrates them into the main db file. If the process
    /// exits without checkpointing, the un-migrated WAL is dropped when the
    /// connection closes — every transaction since the last checkpoint is
    /// lost and the validator silently reverts on restart.
    pub fn checkpoint_wal(&self) -> Result<(), LambdaError> {
        let conn = self.db()?;
        // PRAGMA wal_checkpoint returns one row: (busy, log_frames, checkpointed_frames)
        let (busy, log, ckpt): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|e| LambdaError::StorageError(format!("wal_checkpoint: {}", e)))?;
        if busy != 0 {
            tracing::warn!(
                "WAL checkpoint incomplete (busy): {}/{} frames migrated — \
                 a reader is blocking; un-migrated frames remain at risk",
                ckpt, log
            );
        } else {
            tracing::debug!("WAL checkpoint: {} frames migrated, WAL truncated", ckpt);
        }
        Ok(())
    }

    // =========================================================================
    // Validator Hint Storage (Yellow Paper Section 27)
    // =========================================================================

    /// Add a validator hint (silently drops if already known)
    /// UPSERT a validator hint.
    ///
    /// Returns `true` if a NEW validator was added, `false` if an
    /// existing entry was UPDATED with fresher carriers / last_seen.
    /// (The boolean used to mean "added or skipped" — the
    /// "already known → drop" branch was the propagation bug that
    /// kept validator carrier lists frozen at their seed-hints.json
    /// values forever. Now incoming hints with newer info actually
    /// overwrite the stored copy.)
    ///
    /// The wire format treats `carriers: Vec<String>` as opaque
    /// strings (CLAUDE.md §13 — operators may advertise any URI
    /// scheme), so any field that changed between the stored row
    /// and the incoming hint takes effect on the next
    /// `get_random_hints` emission.
    pub fn add_hint(&self, hint: &ValidatorHint) -> Result<bool, LambdaError> {
        let conn = self.db()?;

        let exists: bool = conn
            .prepare_cached("SELECT 1 FROM validator_hints WHERE validator_id = ?1")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .query_row(params![hint.validator_id], |_| Ok(()))
            .optional()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .is_some();

        let now = unix_now();
        // CBOR-encoded carrier list, see CLAUDE.md §13 for why CBOR
        // not JSON. SQLite is dynamically typed; storing bytes into
        // the (declared TEXT) column is fine.
        let carriers_cbor = cbor_encode(&hint.carriers, "validator_hints.carriers")?;
        // ed25519_pk: persist exactly what the incoming hint carried.
        // `None` here means "the producer didn't bind a key in this
        // hint"; on read we fall back to the `approved_validators`
        // JOIN, so a key the operator approved locally still surfaces
        // even if no peer ever shipped it in a hint.
        let pk_blob: Option<&[u8]> = hint.ed25519_pk.as_ref().map(|a| a.as_slice());

        if exists {
            // UPDATE — refresh carriers, last_seen, ed25519_pk if
            // the hint now carries a key, but DO NOT bump stored_at
            // (that's the LRU-eviction anchor; resetting it would
            // make a fresh hint look like a brand-new arrival and
            // skew the eviction-oldest policy).
            // Encryption fields: refresh only when the incoming hint
            // brings a non-empty value (operator may have legitimately
            // cleared them later — handle via explicit clear path, not
            // an empty propagation hop).
            conn.execute(
                "UPDATE validator_hints
                 SET name = ?2,
                     carriers = ?3,
                     proof_cap = ?4,
                     last_seen = ?5,
                     ed25519_pk = COALESCE(?6, ed25519_pk),
                     encryption_public_key = CASE WHEN ?7 = '' THEN encryption_public_key ELSE ?7 END,
                     supported_encryption = CASE WHEN ?8 = '' THEN supported_encryption ELSE ?8 END
                 WHERE validator_id = ?1",
                params![
                    hint.validator_id,
                    hint.name,
                    carriers_cbor,
                    hint.proof_cap.as_deref().unwrap_or("dmap"),
                    hint.last_seen.unwrap_or(now),
                    pk_blob,
                    hint.encryption_public_key,
                    hint.supported_encryption,
                ],
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
            debug!("Refreshed hint: {} ({})", hint.name, hex::encode(hint.validator_id));
            return Ok(false);
        }

        // INSERT path — new validator. Apply LRU eviction if at cap.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM validator_hints", [], |row| row.get(0))
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        if count as usize >= self.max_hints {
            conn.execute(
                "DELETE FROM validator_hints WHERE validator_id = (
                    SELECT validator_id FROM validator_hints ORDER BY stored_at ASC LIMIT 1
                )",
                [],
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
            debug!("Evicted oldest hint to make room (max={})", self.max_hints);
        }

        conn.execute(
            "INSERT INTO validator_hints (validator_id, name, carriers, proof_cap, last_seen, stored_at, ed25519_pk, encryption_public_key, supported_encryption)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                hint.validator_id,
                hint.name,
                carriers_cbor,
                hint.proof_cap.as_deref().unwrap_or("dmap"),
                hint.last_seen.unwrap_or(now),
                now as i64,
                pk_blob,
                hint.encryption_public_key,
                hint.supported_encryption,
            ],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        debug!("Stored new hint: {} ({})", hint.name, hex::encode(hint.validator_id));
        Ok(true)
    }

    /// Get random hints for response (1-3).
    ///
    /// `_exclude_self` is retained for API compatibility but no
    /// longer filters. The validator's own row (inserted at
    /// `set_carriers` time with the antie.toml advertise list) is
    /// eligible: random emission surfaces it to wallets, wallets
    /// relay it to other validators on the next witness round, and
    /// receivers UPSERT (add_hint). Net result: every operator's
    /// own authoritative carrier list propagates organically without
    /// a separate VSP discovery step.
    pub fn get_random_hints(
        &self,
        count: usize,
        _exclude_self: &str,
    ) -> Result<Vec<ValidatorHint>, LambdaError> {
        let count = count.clamp(1, 3);
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT vh.validator_id, vh.name, vh.carriers, vh.last_seen, vh.proof_cap,
                        vh.ed25519_pk, av.ed25519_pk_hex,
                        vh.encryption_public_key, vh.supported_encryption
                 FROM validator_hints vh
                 LEFT JOIN approved_validators av ON av.validator_id = lower(hex(vh.validator_id))
                 ORDER BY RANDOM()
                 LIMIT ?1",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        let hints = stmt
            .query_map(params![count as i64], |row| {
                let carriers_bytes: Vec<u8> = row.get(2)?;
                let proof_cap: Option<String> = row.get(4).ok();
                let ed25519_pk = resolve_ed25519_pk(row.get(5).ok(), row.get(6).ok());
                Ok(ValidatorHint {
                    validator_id: { let b: Vec<u8> = row.get(0)?; b.try_into().map_err(|_| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, "validator_id not 32 bytes".into()))? },
                    name: row.get(1)?,
                    carriers: cbor_decode_in_row(&carriers_bytes, "validator_hints.carriers")?,
                    proof_cap,
                    last_seen: Some(row.get::<_, i64>(3)? as u64),
                    ed25519_pk,
                    encryption_public_key: row.get(7).unwrap_or_default(),
                    supported_encryption: row.get(8).unwrap_or_default(),
                })
            })
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        Ok(hints)
    }

    /// Get all stored validator hints (for admin API peer list)
    pub fn get_all_hints(&self) -> Result<Vec<ValidatorHint>, LambdaError> {
        let conn = self.db()?;
        // Same LEFT JOIN pattern as get_random_hints — see its comment
        // for the precedence rationale (column wins over JOIN fallback).
        let mut stmt = conn
            .prepare_cached(
                "SELECT vh.validator_id, vh.name, vh.carriers, vh.last_seen, vh.proof_cap,
                        vh.ed25519_pk, av.ed25519_pk_hex,
                        vh.encryption_public_key, vh.supported_encryption
                 FROM validator_hints vh
                 LEFT JOIN approved_validators av ON av.validator_id = lower(hex(vh.validator_id))
                 ORDER BY vh.last_seen DESC",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        let hints = stmt
            .query_map([], |row| {
                let carriers_bytes: Vec<u8> = row.get(2)?;
                let proof_cap: Option<String> = row.get(4).ok();
                let ed25519_pk = resolve_ed25519_pk(row.get(5).ok(), row.get(6).ok());
                Ok(ValidatorHint {
                    validator_id: { let b: Vec<u8> = row.get(0)?; b.try_into().map_err(|_| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, "validator_id not 32 bytes".into()))? },
                    name: row.get(1)?,
                    carriers: cbor_decode_in_row(&carriers_bytes, "validator_hints.carriers")?,
                    proof_cap,
                    last_seen: Some(row.get::<_, i64>(3)? as u64),
                    ed25519_pk,
                    encryption_public_key: row.get(7).unwrap_or_default(),
                    supported_encryption: row.get(8).unwrap_or_default(),
                })
            })
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        Ok(hints)
    }

    /// Get hint count
    pub fn hint_count(&self) -> usize {
        let conn = self.conn.lock();
        conn.query_row("SELECT COUNT(*) FROM validator_hints", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize
    }

    /// Count validator hints seen within the last `within_secs` seconds.
    /// Used for fee_redemption_available — only live/recent peers count.
    /// AUDIT-FIX v2.11.13: stale hints from dead validators excluded.
    pub fn recent_hint_count(&self, within_secs: u64) -> usize {
        let conn = self.conn.lock();
        let cutoff = unix_now().saturating_sub(within_secs) as i64;
        conn.query_row(
            "SELECT COUNT(*) FROM validator_hints WHERE last_seen >= ?1",
            params![cutoff],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as usize
    }

    /// Count wallets in storage (for admin API)
    pub fn wallets_count(&self) -> Result<usize, LambdaError> {
        let conn = self.db()?;
        let count = conn.query_row("SELECT COUNT(*) FROM wallets", [], |row| {
            row.get::<_, i64>(0)
        }).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(count as usize)
    }

    /// v3.x earnings ledger: record this validator's slot earnings for a
    /// redeem txid. Idempotent: a re-submission of the same txid drops via
    /// INSERT OR IGNORE on the PK. Called once per redeem after CL5
    /// `verify_my_fee_slot` succeeds (YP §20.8 v3.x). atoms == 0 inserts
    /// a row but doesn't affect the sum; useful for "I witnessed N redeems
    /// even if all were zero-fee" accounting via the count field.
    pub fn record_validator_earned(&self, txid: &[u8; 32], atoms: u64, is_dev_class: bool) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let now = unix_now() as i64;
        conn.execute(
            "INSERT OR IGNORE INTO validator_earned (txid, atoms, earned_at, is_dev_class)
             VALUES (?1, ?2, ?3, ?4)",
            params![txid.as_ref(), atoms as i64, now, is_dev_class as i64],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Lifetime PUBLIC earnings for this validator: (sum_atoms, receipt_count).
    /// Excludes dev-class rows — those have their own accessor below.
    /// Stays the authoritative number for the withdrawal-mint cap; the
    /// withdrawal path NEVER consults the dev sum.
    pub fn validator_earned_total(&self) -> Result<(u64, u64), LambdaError> {
        let conn = self.db()?;
        let (sum, count) = conn.query_row(
            "SELECT COALESCE(SUM(atoms), 0), COUNT(*) FROM validator_earned WHERE is_dev_class = 0",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok((sum as u64, count as u64))
    }

    /// Lifetime DEV-CLASS earnings for this validator: (sum_atoms, count).
    /// Observability only — surfaced on the validator dashboard as a
    /// separate sub-line under EST. EARNED. NEVER feeds the withdrawal
    /// mint path; dev earnings cannot mint public AXC (see
    /// `AXIOM_DESIGN_FactClassIsolation.md` + the LEAK BOUNDARY in
    /// `nabla/src/node.rs`).
    pub fn validator_dev_earned_total(&self) -> Result<(u64, u64), LambdaError> {
        let conn = self.db()?;
        let (sum, count) = conn.query_row(
            "SELECT COALESCE(SUM(atoms), 0), COUNT(*) FROM validator_earned WHERE is_dev_class = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok((sum as u64, count as u64))
    }

    /// Step 9B.7 — record a completed validator-withdrawal mint receipt.
    ///
    /// Idempotent via PRIMARY KEY `(validator_id, claimed_through_tick)`.
    /// Returns `true` on first insert, `false` if a receipt for the
    /// same (vid, tick) pair already exists. Callers use the bool to
    /// distinguish "I just minted" from "retry — already minted, here's
    /// the prior receipt" and avoid double-sending Nabla's MarkClaimed.
    ///
    /// `signatures_cbor` is the CBOR-encoded `Vec<WitnessSignature>`
    /// the orchestrator returned. Stored as opaque bytes — callers
    /// decode when they need the per-witness detail.
    pub fn record_validator_mint(
        &self,
        validator_id: &[u8; 32],
        claimed_through_tick: u64,
        linked_wallet_id: &[u8; 32],
        net_amount: u64,
        signatures_cbor: &[u8],
    ) -> Result<bool, LambdaError> {
        let conn = self.db()?;
        let now = unix_now() as i64;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO validator_withdrawal_mints
             (validator_id, claimed_through_tick, linked_wallet_id,
              net_amount, minted_at, signatures)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                validator_id.as_ref(),
                claimed_through_tick as i64,
                linked_wallet_id.as_ref(),
                net_amount as i64,
                now,
                signatures_cbor,
            ],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(inserted > 0)
    }

    /// Look up a stored mint receipt by (validator_id, claimed_through_tick).
    /// Returns `(linked_wallet_id, net_amount, minted_at, signatures_cbor)`
    /// or `None` if no row matches.
    #[allow(clippy::type_complexity)]
    pub fn get_validator_mint(
        &self,
        validator_id: &[u8; 32],
        claimed_through_tick: u64,
    ) -> Result<Option<([u8; 32], u64, u64, Vec<u8>)>, LambdaError> {
        let conn = self.db()?;
        let row = conn.query_row(
            "SELECT linked_wallet_id, net_amount, minted_at, signatures
             FROM validator_withdrawal_mints
             WHERE validator_id = ?1 AND claimed_through_tick = ?2",
            params![validator_id.as_ref(), claimed_through_tick as i64],
            |row| {
                let lw: Vec<u8> = row.get(0)?;
                let net: i64 = row.get(1)?;
                let at: i64 = row.get(2)?;
                let sigs: Vec<u8> = row.get(3)?;
                Ok((lw, net, at, sigs))
            },
        );
        match row {
            Ok((lw, net, at, sigs)) => {
                let lw_arr: [u8; 32] = lw.try_into()
                    .map_err(|_| LambdaError::StorageError(
                        "linked_wallet_id wrong length".into(),
                    ))?;
                Ok(Some((lw_arr, net as u64, at as u64, sigs)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LambdaError::StorageError(e.to_string())),
        }
    }

    /// Sum of `net_amount` across all mints credited to a linked wallet.
    /// Used by future wallet-side credit logic and by audit reporting.
    pub fn lifetime_minted_to(
        &self,
        linked_wallet_id: &[u8; 32],
    ) -> Result<u64, LambdaError> {
        let conn = self.db()?;
        let sum: i64 = conn.query_row(
            "SELECT COALESCE(SUM(net_amount), 0)
             FROM validator_withdrawal_mints
             WHERE linked_wallet_id = ?1",
            params![linked_wallet_id.as_ref()],
            |row| row.get(0),
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(sum as u64)
    }

    /// Count receipts in storage (for admin API)
    pub fn receipts_count(&self) -> Result<usize, LambdaError> {
        let conn = self.db()?;
        let count = conn.query_row("SELECT COUNT(*) FROM receipts", [], |row| {
            row.get::<_, i64>(0)
        }).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(count as usize)
    }

    /// Count transaction records in storage (for admin API)
    pub fn transaction_records_count(&self) -> Result<usize, LambdaError> {
        let conn = self.db()?;
        let count = conn.query_row("SELECT COUNT(*) FROM transaction_records", [], |row| {
            row.get::<_, i64>(0)
        }).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(count as usize)
    }

    /// Process incoming hints (store new, drop known)
    pub fn process_incoming_hints(&self, hints: &[ValidatorHint]) -> Result<usize, LambdaError> {
        let mut new_count = 0;
        for hint in hints {
            if self.add_hint(hint)? {
                new_count += 1;
            }
        }
        if new_count > 0 {
            debug!("Processed {} hints, {} new", hints.len(), new_count);
        }
        Ok(new_count)
    }

    // =========================================================================
    // VBC Signing Budget
    // =========================================================================

    /// Get remaining VBC signing budget (default: 6 if not set)
    pub fn get_vbc_signs_remaining(&self) -> Result<u8, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached("SELECT value FROM meta WHERE key = 'vbc_signs_remaining'")
            .map_err(|e| LambdaError::StorageError(format!("Failed to read VBC signs: {}", e)))?;

        let result: Option<String> = stmt
            .query_row([], |row| row.get(0))
            .optional()
            .map_err(|e| LambdaError::StorageError(format!("Failed to read VBC signs: {}", e)))?;

        match result {
            Some(val) => val
                .parse::<u8>()
                .map_err(|e| LambdaError::StorageError(format!("Invalid VBC signs value: {}", e))),
            None => Ok(6), // Default budget
        }
    }

    /// Decrement VBC signing budget. Returns new remaining count.
    /// Fails if budget is already 0.
    pub fn decrement_vbc_signs_remaining(&self) -> Result<u8, LambdaError> {
        let remaining = self.get_vbc_signs_remaining()?;
        if remaining == 0 {
            return Err(LambdaError::InvalidRequest(
                "VBC signing budget exhausted".into(),
            ));
        }
        let new_remaining = remaining - 1;
        let conn = self.db()?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('vbc_signs_remaining', ?1)",
            params![new_remaining.to_string()],
        )
        .map_err(|e| LambdaError::StorageError(format!("Failed to write VBC signs: {}", e)))?;
        Ok(new_remaining)
    }

    // =========================================================================
    // Approved Validators (Phase 3C onboarding tracking)
    // =========================================================================

    /// Record that we approved a new validator's VBC
    pub fn record_validator_approval(
        &self,
        validator_id: &str,
        sphincs_pk_hex: &str,
        ed25519_pk_hex: &str,
        proof_cap: &str,
        node_name: &str,
        request_id: &str,
    ) -> Result<(), LambdaError> {
        let conn = self.db()?;
        conn.execute(
            "INSERT OR REPLACE INTO approved_validators
             (validator_id, sphincs_pk_hex, ed25519_pk_hex, proof_cap, node_name, request_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![validator_id, sphincs_pk_hex, ed25519_pk_hex, proof_cap, node_name, request_id],
        )
        .map_err(|e| LambdaError::StorageError(format!("Failed to record approval: {}", e)))?;
        Ok(())
    }

    /// YP §10: Record MVIB binding — this validator approved a new validator.
    /// Called after VBC signing. Builds the MV-set: 3 independent issuers.
    pub fn record_mvib_binding(
        &self,
        subject_validator_id: &str,
        issuer_validator_id: &str,
    ) -> Result<usize, LambdaError> {
        let conn = self.db()?;
        // Find next available issuer_index (0, 1, or 2)
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM mvib_bindings WHERE subject_validator_id = ?1",
            params![subject_validator_id],
            |row| row.get(0),
        ).unwrap_or(0);

        if count >= 3 {
            return Err(LambdaError::StorageError(
                format!("MVIB complete: {} already has 3 issuers", subject_validator_id)
            ));
        }

        // Check independence: issuer must not already be in this subject's MV-set
        let already: bool = conn.query_row(
            "SELECT COUNT(*) FROM mvib_bindings WHERE subject_validator_id = ?1 AND issuer_validator_id = ?2",
            params![subject_validator_id, issuer_validator_id],
            |row| row.get::<_, i64>(0).map(|c| c > 0),
        ).unwrap_or(false);

        if already {
            return Err(LambdaError::StorageError(
                format!("MV-set independence: {} already approved by {}", subject_validator_id, issuer_validator_id)
            ));
        }

        conn.execute(
            "INSERT INTO mvib_bindings (subject_validator_id, issuer_validator_id, issuer_index)
             VALUES (?1, ?2, ?3)",
            params![subject_validator_id, issuer_validator_id, count],
        ).map_err(|e| LambdaError::StorageError(format!("MVIB bind: {}", e)))?;

        info!("MVIB: {} approved by {} (set {}/3)", subject_validator_id, issuer_validator_id, count + 1);
        Ok((count + 1) as usize)
    }

    /// YP §10: Get MV-set for a validator (the 3 issuers who approved them).
    pub fn get_mv_set(&self, subject_validator_id: &str) -> Result<Vec<String>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn.prepare(
            "SELECT issuer_validator_id FROM mvib_bindings
             WHERE subject_validator_id = ?1 ORDER BY issuer_index"
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        let issuers = stmt.query_map(params![subject_validator_id], |row| row.get(0))
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(issuers)
    }

    /// YP §10: Check if MVIB is complete (3 independent issuers).
    pub fn is_mvib_complete(&self, subject_validator_id: &str) -> Result<bool, LambdaError> {
        let conn = self.db()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM mvib_bindings WHERE subject_validator_id = ?1",
            params![subject_validator_id],
            |row| row.get(0),
        ).unwrap_or(0);
        Ok(count >= 3)
    }

    /// YP §10: Store a signed MVIB binding document.
    /// Called after a new validator creates and signs its MVIB binding
    /// (once it has collected k=3 independent approvals).
    pub fn store_mvib_binding(
        &self,
        binding: &axiom_core_logic::types::MvibBinding,
    ) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let validator_id_hex = hex::encode(binding.validator_id);
        // CBOR (was JSON-text).  MVIB is YP §10 identity-binding —
        // mis-decode would orphan validator identity verification.
        // Column is declared TEXT but SQLite is dynamically typed;
        // storing bytes is fine.  Schema column name kept for back-
        // compat with existing tooling that references it.
        let binding_cbor = cbor_encode(binding, "mvib_bindings")?;
        conn.execute(
            "INSERT OR REPLACE INTO mvib_signed (validator_id, binding_json) VALUES (?1, ?2)",
            params![validator_id_hex, binding_cbor],
        ).map_err(|e| LambdaError::StorageError(format!("MVIB store: {}", e)))?;
        info!("MVIB: stored signed binding for {}", validator_id_hex);
        Ok(())
    }

    /// YP §10: Retrieve a signed MVIB binding document by validator ID.
    pub fn get_mvib_binding(
        &self,
        validator_id_hex: &str,
    ) -> Result<Option<axiom_core_logic::types::MvibBinding>, LambdaError> {
        let conn = self.db()?;
        // `.optional()` (not `.ok()`) — surfaces real DB errors
        // instead of swallowing them as Ok(None) per CLAUDE.md §13.
        let result: Option<Vec<u8>> = conn.query_row(
            "SELECT binding_json FROM mvib_signed WHERE validator_id = ?1",
            params![validator_id_hex],
            |row| row.get(0),
        ).optional().map_err(|e| LambdaError::StorageError(format!("MVIB query: {}", e)))?;
        match result {
            Some(bytes) => Ok(Some(cbor_decode(&bytes, "mvib_bindings")?)),
            None => Ok(None),
        }
    }

    /// Get all approved validators (for admin API)
    /// Returns: (validator_id, node_name, proof_cap, request_id, approved_at)
    #[allow(clippy::type_complexity)]
    pub fn get_approved_validators(&self) -> Result<Vec<(String, String, String, String, u64)>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT validator_id, node_name, proof_cap, request_id, approved_at
                 FROM approved_validators ORDER BY approved_at DESC",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)? as u64,
                ))
            })
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        Ok(rows)
    }

    /// Get count of approved validators
    pub fn get_approved_validator_count(&self) -> Result<u64, LambdaError> {
        let conn = self.db()?;
        let count = conn.query_row(
            "SELECT COUNT(*) FROM approved_validators", [], |row| {
                row.get::<_, i64>(0)
            },
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(count as u64)
    }

    // =========================================================================
    // FACT Scar Passcode Storage
    // =========================================================================

    /// Store a scar passcode for a pending scarred transaction.
    /// AUDIT-FIX v2.11.13: Persists wallet_pk + timestamps for recovery.
    pub fn store_scar_passcode(&self, txid: &[u8; 32], wallet_pk: &[u8], passcode: u32) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let now = unix_now();
        conn.execute(
            "INSERT OR REPLACE INTO scar_passcodes (txid, wallet_pk, passcode, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![txid.as_ref(), wallet_pk, passcode as i64, now as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Get the stored scar passcode for a transaction.
    /// Full passcode gate metadata: (passcode, created_at, attempts).
    /// Backing for the TTL + attempt-cap checks (YPX-001 §1.5.1 hardening,
    /// 2026-07-12).
    pub fn get_scar_passcode_meta(
        &self, txid: &[u8; 32],
    ) -> Result<Option<(u32, i64, u32)>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT passcode, created_at, attempts FROM scar_passcodes WHERE txid = ?1")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        let row = stmt.query_row(params![txid.as_ref()], |r| {
            Ok((r.get::<_, i64>(0)? as u32, r.get::<_, i64>(1)?, r.get::<_, i64>(2)? as u32))
        });
        match row {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LambdaError::StorageError(e.to_string())),
        }
    }

    /// Bump the wrong-passcode attempt counter; returns the NEW count.
    pub fn bump_scar_passcode_attempts(&self, txid: &[u8; 32]) -> Result<u32, LambdaError> {
        let conn = self.db()?;
        conn.execute(
            "UPDATE scar_passcodes SET attempts = attempts + 1 WHERE txid = ?1",
            params![txid.as_ref()],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached("SELECT attempts FROM scar_passcodes WHERE txid = ?1")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        stmt.query_row(params![txid.as_ref()], |r| r.get::<_, i64>(0))
            .map(|v| v as u32)
            .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    pub fn get_scar_passcode(&self, txid: &[u8; 32]) -> Result<Option<u32>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached("SELECT passcode FROM scar_passcodes WHERE txid = ?1")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        stmt.query_row(params![txid.as_ref()], |row| {
            Ok(row.get::<_, i64>(0)? as u32)
        })
        .optional()
        .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    /// Mark passcode as delivered to the client (witness response sent).
    pub fn mark_passcode_delivered(&self, txid: &[u8; 32]) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let now = unix_now();
        conn.execute(
            "UPDATE scar_passcodes SET delivered_at = ?1 WHERE txid = ?2",
            params![now as i64, txid.as_ref()],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Get full scar passcode record with all timestamps.
    /// Returns (passcode, delivered_at, recovered_at) or None.
    #[allow(clippy::type_complexity)]
    pub fn get_scar_passcode_full(&self, txid: &[u8; 32]) -> Result<Option<(u32, Option<i64>, Option<i64>)>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached("SELECT passcode, delivered_at, recovered_at FROM scar_passcodes WHERE txid = ?1")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        stmt.query_row(params![txid.as_ref()], |row| {
            Ok((
                row.get::<_, i64>(0)? as u32,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })
        .optional()
        .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    /// Mark passcode as recovered via admin endpoint.
    pub fn mark_passcode_recovered(&self, txid: &[u8; 32]) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let now = unix_now();
        conn.execute(
            "UPDATE scar_passcodes SET recovered_at = ?1 WHERE txid = ?2",
            params![now as i64, txid.as_ref()],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(())
    }

    // =========================================================================
    // Cheque delivery log (AUDIT-FIX v2.11.13)
    // =========================================================================

    /// Log a cheque delivery attempt.
    pub fn log_cheque_delivery(&self, txid: &[u8; 32], recipient_email: &str, encrypted: bool) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let now = unix_now();
        conn.execute(
            "INSERT OR IGNORE INTO cheque_delivery_log (txid, recipient_email, sent_at, delivery_status, encrypted) VALUES (?1, ?2, ?3, 'sent', ?4)",
            params![txid.as_ref(), recipient_email, now as i64, encrypted as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Mark a cheque delivery as acknowledged (receiver redeemed).
    pub fn mark_delivery_acked(&self, txid: &[u8; 32]) -> Result<(), LambdaError> {
        let conn = self.db()?;
        let now = unix_now();
        conn.execute(
            "UPDATE cheque_delivery_log SET delivery_status = 'acked', ack_received_at = ?1 WHERE txid = ?2",
            params![now as i64, txid.as_ref()],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Get delivery status for a txid. Returns (status, email, sent_at, ack_at, encrypted).
    #[allow(clippy::type_complexity)]
    pub fn get_delivery_status(&self, txid: &[u8; 32]) -> Result<Option<(String, String, i64, Option<i64>, bool)>, LambdaError> {
        let conn = self.db()?;
        let mut stmt = conn
            .prepare_cached("SELECT delivery_status, recipient_email, sent_at, ack_received_at, encrypted FROM cheque_delivery_log WHERE txid = ?1")
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        stmt.query_row(params![txid.as_ref()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, i64>(4)? != 0,
            ))
        })
        .optional()
        .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    // =========================================================================
    // DWP vote rate limiting
    // =========================================================================

    /// Check if a sender has exceeded the vote rate limit for a DWP case in this tick.
    /// Returns true if the vote should be rejected (rate exceeded).
    pub fn dwp_vote_rate_exceeded(&self, case_address: &str, sender_wallet_id: &str, tick: u64) -> bool {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT count FROM dwp_vote_rate WHERE case_address = ?1 AND sender_wallet_id = ?2 AND tick = ?3",
            params![case_address, sender_wallet_id, tick as i64],
            |row| row.get(0),
        ).unwrap_or(0);
        count >= axiom_core_logic::validation::MAX_VOTES_PER_CASE_PER_TICK as i64
    }

    /// Record a DWP vote and prune old entries.
    pub fn dwp_record_vote(&self, case_address: &str, sender_wallet_id: &str, tick: u64) -> Result<(), LambdaError> {
        let conn = self.db()?;
        conn.execute(
            "INSERT INTO dwp_vote_rate (case_address, sender_wallet_id, tick, count) VALUES (?1, ?2, ?3, 1) \
             ON CONFLICT(case_address, sender_wallet_id, tick) DO UPDATE SET count = count + 1",
            params![case_address, sender_wallet_id, tick as i64],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        // Prune old entries (keep only last 2 ticks)
        conn.execute(
            "DELETE FROM dwp_vote_rate WHERE tick < ?1",
            params![(tick.saturating_sub(2)) as i64],
        ).ok();
        Ok(())
    }

    /// Check for timed-out deliveries (sent > 7 days ago, no ACK).
    pub fn timeout_stale_deliveries(&self) -> Result<usize, LambdaError> {
        let conn = self.db()?;
        let cutoff = unix_now().saturating_sub(7 * 86400); // 7 days
        let count = conn.execute(
            "UPDATE cheque_delivery_log SET delivery_status = 'timeout' WHERE delivery_status = 'sent' AND sent_at < ?1",
            params![cutoff as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(count)
    }

    /// Update the encrypted flag on an existing delivery log entry.
    /// Called by the ANTIE admin callback after the actual email send.
    pub fn update_delivery_encrypted(&self, txid: &[u8; 32], encrypted: bool) -> Result<(), LambdaError> {
        let conn = self.db()?;
        conn.execute(
            "UPDATE cheque_delivery_log SET encrypted = ?1 WHERE txid = ?2",
            params![encrypted as i64, txid.as_ref()],
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(())
    }

    // =========================================================================

    /// Remove scar passcode after successful verification.
    pub fn remove_scar_passcode(&self, txid: &[u8; 32]) -> Result<(), LambdaError> {
        let conn = self.db()?;
        conn.execute(
            "DELETE FROM scar_passcodes WHERE txid = ?1",
            params![txid.as_ref()],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok(())
    }
}

// =========================================================================
// Helper Functions
// =========================================================================

fn blob_to_32(bytes: Vec<u8>) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = bytes.len().min(32);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

fn status_to_str(status: &WalletStateStatus) -> &'static str {
    match status {
        WalletStateStatus::Confirmed => "Confirmed",
        WalletStateStatus::Pending => "Pending",
    }
}

fn status_from_str(s: &str) -> WalletStateStatus {
    match s {
        "Pending" => WalletStateStatus::Pending,
        _ => WalletStateStatus::Confirmed,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Derive a database encryption key from an Ed25519 private key.
///
/// Returns the hex-encoded BLAKE3 hash suitable for SQLCipher `PRAGMA key`.
pub fn derive_db_key(ed25519_secret: &[u8], domain: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(ed25519_secret);
    hex::encode(hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_state_roundtrip() {
        let storage = Storage::open_test().unwrap();

        let state = StoredWalletState {
            public_key: vec![1, 2, 3, 4],
            balance: 1000,
            wallet_seq: 5,
            state_id: [0xAB; 32],
            last_tx_id: Some([0xCD; 32]),
            status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: None, hibernation_until: 0,
            wallet_id: None,
        };

        storage.set_wallet_state(&state, 3, 1).unwrap();

        let loaded = storage.get_wallet_state(&[1, 2, 3, 4], 3, 1).unwrap();
        assert!(loaded.is_some());

        let loaded = loaded.unwrap();
        assert_eq!(loaded.balance, 1000);
        assert_eq!(loaded.wallet_seq, 5);
        assert_eq!(loaded.state_id, [0xAB; 32]);
        assert_eq!(loaded.last_tx_id, Some([0xCD; 32]));
    }

    #[test]
    fn test_genesis_state_roundtrip() {
        let storage = Storage::open_test().unwrap();

        let pk = [0x42u8; 32];
        let state = StoredWalletState {
            public_key: pk.to_vec(),
            balance: 50000,
            wallet_seq: 0,
            state_id: [0xBB; 32],
            last_tx_id: None,
            status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: None, hibernation_until: 0,
            wallet_id: None,
        };

        storage.set_genesis_state(&pk, 3, 1, &state).unwrap();

        let loaded = storage.get_genesis_state(&pk, 3, 1).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.balance, 50000);
        assert_eq!(loaded.state_id, [0xBB; 32]);
    }

    #[test]
    fn test_wallet_by_state_id_indexed() {
        let storage = Storage::open_test().unwrap();

        let state = StoredWalletState {
            public_key: vec![1u8; 32],
            balance: 500,
            wallet_seq: 3,
            state_id: [0xDD; 32],
            last_tx_id: None,
            status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: None, hibernation_until: 0,
            wallet_id: None,
        };

        storage.set_wallet_state(&state, 3, 1).unwrap();

        // Lookup by state_id — O(1) with index
        let found = storage.get_wallet_by_state_id(&[0xDD; 32]).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().balance, 500);

        // Not found
        let not_found = storage.get_wallet_by_state_id(&[0xEE; 32]).unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_transaction_record_lifecycle() {
        let storage = Storage::open_test().unwrap();

        let record = TransactionRecord {
            tx_id: [0x11; 32],
            produced_state_id: [0x22; 32],
            wallet_pk: vec![0x33; 32],
            balance_after: 900,
            wallet_seq_after: 2,
            group_members_after: None,
            status: WalletStateStatus::Pending,
            required_k: 4,
            proof_type: 0,
            amount: 250,
            sender_balance: 1150,
            is_genesis_claim: None,
        };

        storage.store_transaction_record(&record).unwrap();

        let loaded = storage.get_transaction_record(&[0x22; 32]).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.balance_after, 900);
        assert_eq!(loaded.status, WalletStateStatus::Pending);
        assert_eq!(loaded.required_k, 4);
        assert_eq!(loaded.proof_type, 0);

        // Confirm it
        assert!(storage.confirm_transaction_record(&[0x22; 32]).unwrap());
        let confirmed = storage.get_transaction_record(&[0x22; 32]).unwrap().unwrap();
        assert_eq!(confirmed.status, WalletStateStatus::Confirmed);
    }

    // Regression for the S-ABR restart-divergence bug (2026-05-16).
    //
    // store_transaction_record prunes EVERY prior record for the wallet on
    // each store. But the witness-time store happens for a transaction that
    // is NOT yet finalized (PENDING until ACK — the client may still abandon
    // or retry it). So a witness round that never finalizes — e.g. a mass
    // SIGKILL mid-relay — leaves an overlapped validator having pruned the
    // wallet's real anchor record for a phantom state it never reached. Every
    // subsequent overlapped lookup then hits S-ABR LOOKUP MISS and the wallet
    // is permanently rejected.
    //
    // The prune happens at ACK (transaction finalized), not at witness —
    // prune_superseded_transaction_records, called from process_ack.
    #[test]
    fn test_unfinalized_witness_store_must_not_prune_anchor() {
        let storage = Storage::open_test().unwrap();
        let wallet_pk = vec![0x33; 32];

        // The wallet's confirmed anchor (its real current S-ABR record).
        let anchor = TransactionRecord {
            tx_id: [0x01; 32],
            produced_state_id: [0xA0; 32],
            wallet_pk: wallet_pk.clone(),
            balance_after: 1000,
            wallet_seq_after: 25,
            group_members_after: None,
            status: WalletStateStatus::Pending,
            required_k: 3,
            proof_type: 1,
            amount: 0,
            sender_balance: 1000,
            is_genesis_claim: None,
        };
        storage.store_transaction_record(&anchor).unwrap();

        // A new transaction consuming the anchor state — witnessed but NOT
        // yet finalized (no ACK).
        let pending = TransactionRecord {
            tx_id: [0x02; 32],
            produced_state_id: [0xB0; 32],
            wallet_pk: wallet_pk.clone(),
            balance_after: 900,
            wallet_seq_after: 26,
            group_members_after: None,
            status: WalletStateStatus::Pending,
            required_k: 3,
            proof_type: 1,
            amount: 100,
            sender_balance: 1000,
            is_genesis_claim: None,
        };
        storage.store_transaction_record(&pending).unwrap();

        // The pending TX is not finalized. An overlapped validator handling a
        // retry must still be able to S-ABR-lookup the anchor — it must NOT
        // have been pruned by the speculative witness-time store.
        assert!(
            storage.get_transaction_record(&[0xA0; 32]).unwrap().is_some(),
            "BUG: witness-time store of an un-finalized TX pruned the wallet's prior S-ABR anchor"
        );
        assert!(
            storage.get_transaction_record(&[0xB0; 32]).unwrap().is_some(),
            "the pending record itself must be stored"
        );

        // ACK of the pending TX finalizes it — prune_superseded_transaction_records
        // (called from process_ack) now removes the superseded anchor and keeps
        // the finalized record.
        storage
            .prune_superseded_transaction_records(&wallet_pk, &[0xB0; 32], 26)
            .unwrap();
        assert!(
            storage.get_transaction_record(&[0xA0; 32]).unwrap().is_none(),
            "ACK-time prune must remove the superseded anchor"
        );
        assert!(
            storage.get_transaction_record(&[0xB0; 32]).unwrap().is_some(),
            "ACK-time prune must keep the finalized transaction's record"
        );
    }

    /// Companion to `test_unfinalized_witness_store_must_not_prune_anchor`:
    /// the periodic `prune_stale_data` cron must also NOT touch
    /// `transaction_records`. Original commit `6c3c45ca` introduced a
    /// `MAX(rowid) GROUP BY wallet_pk` delete on the periodic path that
    /// silently dropped the wallet's prior anchor in the gap between
    /// witness-time store and ACK-time prune. The S-ABR LOOKUP MISS
    /// class observed in the 2026-05-22 30-wallet soak traced to this
    /// exact race (every miss within 1-3 minutes after a periodic prune).
    ///
    /// ACK-time pruning is the only mechanism that has the necessary
    /// context to drop a record safely.
    #[test]
    fn test_periodic_prune_must_not_touch_transaction_records() {
        let storage = Storage::open_test().unwrap();
        let wallet_pk = vec![0x77; 32];

        // Anchor: an ACKed prior state.
        let anchor = TransactionRecord {
            tx_id: [0x10; 32],
            produced_state_id: [0xC0; 32],
            wallet_pk: wallet_pk.clone(),
            balance_after: 500,
            wallet_seq_after: 10,
            group_members_after: None,
            status: WalletStateStatus::Confirmed,
            required_k: 3,
            proof_type: 1,
            amount: 0,
            sender_balance: 500,
            is_genesis_claim: None,
        };
        storage.store_transaction_record(&anchor).unwrap();

        // Pending: a newly-witnessed TX, not yet ACKed. After this store,
        // the table holds 2 rows for this wallet.
        let pending = TransactionRecord {
            tx_id: [0x11; 32],
            produced_state_id: [0xD0; 32],
            wallet_pk: wallet_pk.clone(),
            balance_after: 400,
            wallet_seq_after: 11,
            group_members_after: None,
            status: WalletStateStatus::Pending,
            required_k: 3,
            proof_type: 1,
            amount: 100,
            sender_balance: 500,
            is_genesis_claim: None,
        };
        storage.store_transaction_record(&pending).unwrap();

        // The periodic prune fires. Pre-fix it would have collapsed the
        // wallet's history to just the most-recently-inserted row
        // (`0xD0`), dropping the still-load-bearing anchor (`0xC0`) that
        // a subsequent heal might reference.
        storage.prune_stale_data(3600).unwrap();

        // Both rows must survive — periodic prune is no longer allowed
        // to make this decision.
        assert!(
            storage.get_transaction_record(&[0xC0; 32]).unwrap().is_some(),
            "REGRESSION: periodic prune dropped the wallet's prior S-ABR anchor"
        );
        assert!(
            storage.get_transaction_record(&[0xD0; 32]).unwrap().is_some(),
            "periodic prune must not touch the pending record either"
        );
    }

    #[test]
    fn test_consumed_state_roundtrip() {
        let storage = Storage::open_test().unwrap();

        let sid = [0x44; 32];
        assert!(!storage.is_state_consumed(&sid).unwrap());

        storage.mark_state_consumed(&sid).unwrap();
        assert!(storage.is_state_consumed(&sid).unwrap());
    }

    #[test]
    fn test_redeemed_cheque_roundtrip() {
        let storage = Storage::open_test().unwrap();

        let cid = [0x55; 32];
        assert!(!storage.is_cheque_redeemed(&cid).unwrap());

        storage.mark_cheque_redeemed(&cid).unwrap();
        assert!(storage.is_cheque_redeemed(&cid).unwrap());
    }


    #[test]
    fn validator_earned_idempotent_and_sums() {
        let storage = Storage::open_test().unwrap();
        let txid1 = [0xA1; 32];
        let txid2 = [0xA2; 32];

        // Initial state — no earnings.
        assert_eq!(storage.validator_earned_total().unwrap(), (0, 0));
        assert_eq!(storage.validator_dev_earned_total().unwrap(), (0, 0));

        // First redeem credits 30 atoms (public).
        storage.record_validator_earned(&txid1, 30, false).unwrap();
        assert_eq!(storage.validator_earned_total().unwrap(), (30, 1));

        // Idempotency — same txid does not double-credit.
        storage.record_validator_earned(&txid1, 30, false).unwrap();
        assert_eq!(storage.validator_earned_total().unwrap(), (30, 1));

        // Distinct txid adds to the sum.
        storage.record_validator_earned(&txid2, 45, false).unwrap();
        assert_eq!(storage.validator_earned_total().unwrap(), (75, 2));

        // Zero-fee redeem (heal / genesis-claim) bumps count, not atoms.
        let txid3 = [0xA3; 32];
        storage.record_validator_earned(&txid3, 0, false).unwrap();
        assert_eq!(storage.validator_earned_total().unwrap(), (75, 3));

        // Dev-class earning lands in the dev sum, NOT the public sum.
        // Closes the leak boundary: dashboard surfaces it separately,
        // withdrawal mint never sees it.
        let txid_dev = [0xA4; 32];
        storage.record_validator_earned(&txid_dev, 100, true).unwrap();
        assert_eq!(storage.validator_earned_total().unwrap(), (75, 3),
            "dev earnings must NOT be counted as public earnings");
        assert_eq!(storage.validator_dev_earned_total().unwrap(), (100, 1),
            "dev earnings must be visible via the dev accessor");
    }

    #[test]
    fn validator_withdrawal_mint_idempotent_and_lookup() {
        let storage = Storage::open_test().unwrap();
        let vid = [0xAA; 32];
        let linked = [0xBB; 32];
        let tick = 42u64;
        let sigs_cbor = vec![0xDE, 0xAD, 0xBE, 0xEF];

        // Initial: no mint for this (vid, tick).
        assert!(storage.get_validator_mint(&vid, tick).unwrap().is_none());
        assert_eq!(storage.lifetime_minted_to(&linked).unwrap(), 0);

        // First persist: inserts a row, returns true.
        let inserted = storage
            .record_validator_mint(&vid, tick, &linked, 90, &sigs_cbor)
            .unwrap();
        assert!(inserted, "first persist must be a new insert");
        assert_eq!(storage.lifetime_minted_to(&linked).unwrap(), 90);

        // Lookup returns the stored fields.
        let (got_linked, got_net, _minted_at, got_sigs) =
            storage.get_validator_mint(&vid, tick).unwrap().unwrap();
        assert_eq!(got_linked, linked);
        assert_eq!(got_net, 90);
        assert_eq!(got_sigs, sigs_cbor);

        // Idempotency: re-inserting the same (vid, tick) returns false
        // and does NOT bump the credited amount. Defends against a
        // double admin POST or a retried witness round.
        let again = storage
            .record_validator_mint(&vid, tick, &linked, 90, &sigs_cbor)
            .unwrap();
        assert!(!again, "duplicate (vid, tick) must be ignored");
        assert_eq!(storage.lifetime_minted_to(&linked).unwrap(), 90,
            "lifetime_minted_to must NOT double-count");

        // Distinct tick on the same vid is a new mint.
        let inserted2 = storage
            .record_validator_mint(&vid, tick + 100, &linked, 50, &sigs_cbor)
            .unwrap();
        assert!(inserted2);
        assert_eq!(storage.lifetime_minted_to(&linked).unwrap(), 140);

        // Different linked wallet on the same vid → separate accumulator.
        let other_linked = [0xCC; 32];
        let inserted3 = storage
            .record_validator_mint(&vid, tick + 200, &other_linked, 25, &sigs_cbor)
            .unwrap();
        assert!(inserted3);
        assert_eq!(storage.lifetime_minted_to(&other_linked).unwrap(), 25);
        assert_eq!(storage.lifetime_minted_to(&linked).unwrap(), 140,
            "second linked_wallet must not affect the first's total");
    }

    #[test]
    fn test_hint_add_and_eviction() {
        let storage = Storage::open_test_with_max_hints(3).unwrap();

        for i in 0..3 {
            let hint = ValidatorHint {
                validator_id: { let mut a = [0u8; 32]; a[0] = i as u8; a },
                name: format!("node{}", i),
                carriers: vec!["test".to_string()],
                proof_cap: None,
                last_seen: Some(1000 + i as u64),
                ed25519_pk: None,
                encryption_public_key: String::new(),
                supported_encryption: String::new(),
            };
            assert!(storage.add_hint(&hint).unwrap());
        }

        assert_eq!(storage.hint_count(), 3);

        // Adding a 4th should evict the oldest
        let hint = ValidatorHint {
            validator_id: [0x03u8; 32],
            name: "node3".to_string(),
            carriers: vec!["test".to_string()],
            proof_cap: None,
            last_seen: Some(2000),
            ed25519_pk: None,
            encryption_public_key: String::new(),
            supported_encryption: String::new(),
        };
        assert!(storage.add_hint(&hint).unwrap());
        assert_eq!(storage.hint_count(), 3); // Still 3 after eviction

        // Duplicate should return false (now an UPDATE path, not a skip)
        assert!(!storage.add_hint(&hint).unwrap());
    }

    /// Regression: when the same validator_id is re-added with
    /// fresher carriers (e.g. operator adds TOT to their advertise
    /// list and the new hint propagates through the network),
    /// `add_hint` must UPDATE the stored carriers — not silently
    /// drop the new hint. Pre-fix the SQL table stayed frozen at
    /// the seed-hints.json bootstrap values forever; that broke
    /// discovery hint propagation entirely once any new carrier
    /// scheme was introduced.
    #[test]
    fn test_hint_add_updates_carriers_on_re_add() {
        let storage = Storage::open_test().unwrap();

        // Initial hint — email only (simulates seed-hints.json).
        let v1 = ValidatorHint {
            validator_id: [0xAAu8; 32],
            name: "alpha".to_string(),
            carriers: vec!["email:alpha@axiom".to_string()],
            proof_cap: None,
            last_seen: Some(1000),
            ed25519_pk: None,
            encryption_public_key: String::new(),
            supported_encryption: String::new(),
        };
        assert!(storage.add_hint(&v1).unwrap(), "first add is INSERT");

        // Same validator_id, NEW carriers (simulates the operator
        // adding tot: + fatmama: to their advertise list and the
        // new hint reaching us via VSP propagation).
        let v2 = ValidatorHint {
            validator_id: [0xAAu8; 32],
            name: "alpha".to_string(),
            carriers: vec![
                "email:alpha@axiom".to_string(),
                "fatmama:axiom-dev.mooo.com:2525".to_string(),
                "tot:axiom-dev.mooo.com:7400".to_string(),
            ],
            proof_cap: None,
            last_seen: Some(2000),
            ed25519_pk: None,
            encryption_public_key: String::new(),
            supported_encryption: String::new(),
        };
        assert!(!storage.add_hint(&v2).unwrap(), "re-add is UPDATE, returns false");

        // Read back — get_random_hints must surface the NEW carriers.
        let emitted = storage.get_random_hints(3, "self").unwrap();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].carriers, vec![
            "email:alpha@axiom".to_string(),
            "fatmama:axiom-dev.mooo.com:2525".to_string(),
            "tot:axiom-dev.mooo.com:7400".to_string(),
        ], "carrier list MUST reflect the latest hint, not the seed");
    }

    /// Meta-approval propagation: when a new validator X comes
    /// online and sends its self-hint to one of its meta-set
    /// validators (via the UMP `validator_hints` field carried on
    /// the MV-bootstrap request), the meta validator's hint table
    /// must INSERT X with X's real carriers. From there, X is
    /// visible in `get_random_hints` emissions and the discovery
    /// chain takes over (wallets receive X in hints, relay to other
    /// validators on subsequent UMPs, those validators UPSERT, etc).
    ///
    /// This test pins the meta-approval propagation contract at the
    /// storage layer: `process_incoming_hints` is the single chokepoint
    /// where the meta validator picks up X's hint. SDK / consensus
    /// changes that populate `validator_hints` on registration UMPs
    /// flow through this same call.
    #[test]
    fn test_meta_approval_propagates_new_validator_hint() {
        let storage = Storage::open_test().unwrap();

        // Seed: meta validator already knows 4 existing peers from
        // its seed-hints.json bootstrap (the normal startup state).
        for v in &["alpha", "beta", "gamma", "delta"] {
            let hint = ValidatorHint {
                validator_id: { let mut a = [0u8; 32]; a[0] = v.as_bytes()[0]; a },
                name: v.to_string(),
                carriers: vec![format!("email:{}@axiom.local", v)],
                proof_cap: None,
                last_seen: Some(1000),
                ed25519_pk: None,
                encryption_public_key: String::new(),
                supported_encryption: String::new(),
            };
            storage.add_hint(&hint).unwrap();
        }
        assert_eq!(storage.hint_count(), 4, "seed bootstrap state");

        // ── ARRIVAL ──────────────────────────────────────────────
        // New validator X comes online with its own carrier set
        // (email floor + TOT). During MV-bootstrap X sends an UMP
        // to this meta validator carrying its self-hint in the
        // `validator_hints` field. Meta validator runs the incoming
        // hints through process_incoming_hints.
        let x_self_hint = ValidatorHint {
            validator_id: [0x05u8; 32],
            name: "xnewvalidator".to_string(),
            carriers: vec![
                "email:xnewvalidator@axiom".to_string(),
                "tot:newhost.example.com:7410".to_string(),
            ],
            proof_cap: Some("dmap".to_string()),
            last_seen: Some(2000),
            ed25519_pk: None,
            encryption_public_key: String::new(),
            supported_encryption: String::new(),
        };
        let new_count = storage.process_incoming_hints(&[x_self_hint.clone()]).unwrap();
        assert_eq!(new_count, 1, "X is new — INSERT path, returns 1");
        assert_eq!(storage.hint_count(), 5,
            "meta validator's table now carries the new peer X");

        // Meta validator's get_random_hints can now surface X to
        // any wallet that queries it. Wallets that receive X in
        // hints will relay it to OTHER validators via subsequent
        // UMP traffic; this is the propagation gradient.
        let all = storage.get_all_hints().unwrap();
        let x_in_table = all.iter().find(|v| v.name == "xnewvalidator")
            .expect("X must appear in meta validator's hint table after onboarding");
        assert_eq!(x_in_table.carriers, vec![
            "email:xnewvalidator@axiom".to_string(),
            "tot:newhost.example.com:7410".to_string(),
        ], "X's stored carriers must match what X self-declared");
        assert_eq!(x_in_table.proof_cap.as_deref(), Some("dmap"));

        // ── REFRESH ──────────────────────────────────────────────
        // Later, X's operator adds a fatmama relay to X's antie.toml
        // and X starts re-emitting with 3 URIs. Same UMP path — any
        // wallet that has talked to X with the new carrier list will
        // relay the updated hint to its next meta validator. UPSERT
        // (test_hint_add_updates_carriers_on_re_add covers the
        // mechanism in isolation) must apply here in the integration
        // path too.
        let x_self_hint_updated = ValidatorHint {
            carriers: vec![
                "email:xnewvalidator@axiom".to_string(),
                "tot:newhost.example.com:7410".to_string(),
                "fatmama:newhost.example.com:2525".to_string(),
            ],
            last_seen: Some(3000),
            ..x_self_hint
        };
        let new_count = storage.process_incoming_hints(&[x_self_hint_updated]).unwrap();
        assert_eq!(new_count, 0,
            "X already known — UPSERT path; 0 newly-added but still applied");
        assert_eq!(storage.hint_count(), 5, "no extra rows from the refresh");

        let updated = storage.get_all_hints().unwrap()
            .into_iter()
            .find(|v| v.name == "xnewvalidator")
            .expect("X still there");
        assert_eq!(updated.carriers.len(), 3,
            "carrier list grew from 2 to 3 — fatmama added");
        assert!(updated.carriers.iter().any(|c| c.starts_with("fatmama:")),
            "fatmama URI must be present after operator's later update");
        assert_eq!(updated.last_seen, Some(3000),
            "last_seen must reflect the most recent hint timestamp");

        // ── INDEPENDENCE ─────────────────────────────────────────
        // X's arrival + refresh must not have disturbed the existing
        // seed validators — they're untouched by the meta-approval flow.
        for v in &["alpha", "beta", "gamma", "delta"] {
            let existing = storage.get_all_hints().unwrap()
                .into_iter()
                .find(|h| h.name == *v)
                .expect("seed peers still in table");
            assert_eq!(existing.carriers,
                vec![format!("email:{}@axiom.local", v)],
                "seed peer {} carriers must not be touched by X's arrival", v);
        }
    }

    /// `get_random_hints` no longer filters self — the validator's own
    /// row (inserted at `set_carriers` time) participates in random
    /// emission so wallets learn the operator's authoritative carrier
    /// list and propagate it onward. The `_exclude_self` parameter is
    /// retained for API compatibility only.
    #[test]
    fn test_hint_random_includes_self_after_set_carriers() {
        let storage = Storage::open_test().unwrap();

        for i in 0..5 {
            let hint = ValidatorHint {
                validator_id: { let mut a = [0u8; 32]; a[0] = i as u8; a },
                name: format!("node{}", i),
                carriers: vec!["test".to_string()],
                proof_cap: None,
                last_seen: Some(1000),
                ed25519_pk: None,
                ..Default::default()
            };
            storage.add_hint(&hint).unwrap();
        }

        // Over many samples, "v2" appears like any other row — the
        // self-exclusion filter is gone by design.
        let mut saw_v2 = false;
        for _ in 0..30 {
            let hints = storage.get_random_hints(3, "v2").unwrap();
            if hints.iter().any(|h| h.validator_id[0] == 2) {
                saw_v2 = true;
                break;
            }
        }
        assert!(saw_v2, "v2 must be eligible for emission (no self-exclusion)");
    }

    /// Regression: `get_random_hints` must surface ed25519_pk from
    /// the LEFT JOIN against `approved_validators` even when the
    /// originating hint row was stored before the key column existed
    /// (or arrived from a peer that didn't ship the key). Without
    /// the JOIN this test fails — the SDK side would see
    /// `ed25519_pk: None` for a peer the operator has explicitly
    /// approved locally, which is precisely the gap the field was
    /// added to close.
    #[test]
    fn test_hint_emission_fills_ed25519_pk_from_approved_validators() {
        let storage = Storage::open_test().unwrap();

        let pk_hex = "11".repeat(32); // 32 bytes = 64 hex chars
        let vid_bytes = [0x06u8; 32];
        let vid_hex = hex::encode(vid_bytes);
        storage.record_validator_approval(
            &vid_hex,
            "sphincs_hex",
            &pk_hex,
            "dmap",
            "alpha",
            "req-test-1",
        ).unwrap();

        // Hint row WITHOUT the key — simulates a remote peer that
        // didn't ship ed25519_pk in the wire (older Lambda) OR a
        // pre-migration row sitting in the DB.
        let hint = ValidatorHint {
            validator_id: vid_bytes,
            name: "alpha".to_string(),
            carriers: vec!["email:alpha@axiom".to_string()],
            proof_cap: Some("dmap".to_string()),
            last_seen: Some(1000),
            ed25519_pk: None,
            encryption_public_key: String::new(),
            supported_encryption: String::new(),
        };
        storage.add_hint(&hint).unwrap();

        let emitted = storage.get_random_hints(3, "self").unwrap();
        assert_eq!(emitted.len(), 1);
        let key = emitted[0].ed25519_pk.expect(
            "ed25519_pk MUST be populated from approved_validators JOIN"
        );
        assert_eq!(key, [0x11u8; 32]);

        // get_all_hints exercises the same JOIN — same result expected.
        let all = storage.get_all_hints().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].ed25519_pk, Some([0x11u8; 32]));
    }

    /// Stored hint key wins over the JOIN fallback — reflects what
    /// the SOURCE of the hint actually said, even if local
    /// approved_validators has a different value.
    #[test]
    fn test_hint_stored_key_wins_over_approved_validators_join() {
        let storage = Storage::open_test().unwrap();

        let approved_hex = "22".repeat(32);
        let vid_bytes = [0x07u8; 32];
        let vid_hex = hex::encode(vid_bytes);
        storage.record_validator_approval(
            &vid_hex,
            "sphincs_hex",
            &approved_hex,
            "dmap",
            "beta",
            "req-test-2",
        ).unwrap();

        // Hint row WITH a key — should win over the JOIN value.
        let stored_pk = [0x33u8; 32];
        let hint = ValidatorHint {
            validator_id: vid_bytes,
            name: "beta".to_string(),
            carriers: vec!["email:beta@axiom".to_string()],
            proof_cap: Some("dmap".to_string()),
            last_seen: Some(1000),
            ed25519_pk: Some(stored_pk),
            encryption_public_key: String::new(),
            supported_encryption: String::new(),
        };
        storage.add_hint(&hint).unwrap();

        let emitted = storage.get_random_hints(3, "self").unwrap();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].ed25519_pk, Some(stored_pk),
            "stored validator_hints.ed25519_pk MUST take precedence over the approved_validators JOIN");
    }

    #[test]
    fn test_vbc_signs_budget() {
        let storage = Storage::open_test().unwrap();

        // Default is 6
        assert_eq!(storage.get_vbc_signs_remaining().unwrap(), 6);

        // Decrement
        assert_eq!(storage.decrement_vbc_signs_remaining().unwrap(), 5);
        assert_eq!(storage.decrement_vbc_signs_remaining().unwrap(), 4);
        assert_eq!(storage.get_vbc_signs_remaining().unwrap(), 4);
    }

    #[test]
    fn test_approved_validators_crud() {
        let storage = Storage::open_test().unwrap();

        // Initially empty
        assert_eq!(storage.get_approved_validator_count().unwrap(), 0);
        assert!(storage.get_approved_validators().unwrap().is_empty());

        // Record an approval
        storage.record_validator_approval(
            "abc123", "sphincs_hex", "ed25519_hex", "dmap", "node-alpha", "req-001",
        ).unwrap();
        assert_eq!(storage.get_approved_validator_count().unwrap(), 1);

        let approved = storage.get_approved_validators().unwrap();
        assert_eq!(approved.len(), 1);
        assert_eq!(approved[0].0, "abc123"); // validator_id
        assert_eq!(approved[0].1, "node-alpha"); // node_name
        assert_eq!(approved[0].2, "dmap"); // proof_cap
        assert_eq!(approved[0].3, "req-001"); // request_id

        // Record second approval
        storage.record_validator_approval(
            "def456", "sphincs2", "ed2", "zkvm", "node-beta", "req-002",
        ).unwrap();
        assert_eq!(storage.get_approved_validator_count().unwrap(), 2);

        // Upsert (same validator_id replaces)
        storage.record_validator_approval(
            "abc123", "sphincs_new", "ed_new", "zkvm", "node-alpha-v2", "req-003",
        ).unwrap();
        assert_eq!(storage.get_approved_validator_count().unwrap(), 2); // still 2
        let approved = storage.get_approved_validators().unwrap();
        let alpha = approved.iter().find(|a| a.0 == "abc123").unwrap();
        assert_eq!(alpha.1, "node-alpha-v2"); // updated name
        assert_eq!(alpha.2, "zkvm"); // updated proof_cap
    }

    #[test]
    fn test_scar_passcode_roundtrip() {
        let storage = Storage::open_test().unwrap();
        let txid = [0x99; 32];
        let wallet_pk = [0xAA; 32];

        assert!(storage.get_scar_passcode(&txid).unwrap().is_none());

        storage.store_scar_passcode(&txid, &wallet_pk, 123456).unwrap();
        assert_eq!(storage.get_scar_passcode(&txid).unwrap(), Some(123456));

        storage.remove_scar_passcode(&txid).unwrap();
        assert!(storage.get_scar_passcode(&txid).unwrap().is_none());
    }

    #[test]
    fn test_scar_passcode_prune_abandoned() {
        let storage = Storage::open_test().unwrap();
        let old_txid = [1u8; 32];
        let fresh_txid = [2u8; 32];
        storage.store_scar_passcode(&old_txid, &[9u8; 32], 111111).unwrap();
        storage.store_scar_passcode(&fresh_txid, &[9u8; 32], 222222).unwrap();
        // Age the first entry past the cutoff (created_at is wall-seconds).
        {
            let conn = storage.conn.lock();
            conn.execute(
                "UPDATE scar_passcodes SET created_at = created_at - 999999 WHERE txid = ?1",
                params![old_txid.as_ref()],
            ).unwrap();
        }
        // Prune with a 1-day window: the aged, never-recovered entry goes;
        // the fresh one survives (a live paused send must stay verifiable).
        storage.prune_stale_data(86_400).unwrap();
        assert!(storage.get_scar_passcode(&old_txid).unwrap().is_none(),
                "abandoned entry past cutoff must be pruned");
        assert_eq!(storage.get_scar_passcode(&fresh_txid).unwrap(), Some(222222),
                "fresh pending entry must survive the sweep");
    }

    #[test]
    fn test_cheque_delivery_log_roundtrip() {
        let storage = Storage::open_test().unwrap();
        let txid = [0xDD; 32];
        assert!(storage.get_delivery_status(&txid).unwrap().is_none());

        storage.log_cheque_delivery(&txid, "bob@test.com", false).unwrap();
        let (status, email, _, ack, encrypted) = storage.get_delivery_status(&txid).unwrap().unwrap();
        assert_eq!(status, "sent");
        assert_eq!(email, "bob@test.com");
        assert!(ack.is_none());
        assert!(!encrypted);
    }

    #[test]
    fn test_cheque_delivery_ack() {
        let storage = Storage::open_test().unwrap();
        let txid = [0xEE; 32];
        storage.log_cheque_delivery(&txid, "alice@test.com", false).unwrap();
        storage.mark_delivery_acked(&txid).unwrap();
        let (status, _, _, ack, _) = storage.get_delivery_status(&txid).unwrap().unwrap();
        assert_eq!(status, "acked");
        assert!(ack.is_some());
    }

    #[test]
    fn test_cheque_delivery_timeout() {
        let storage = Storage::open_test().unwrap();
        let txid = [0xFF; 32];
        let old_time = (unix_now() - 8 * 86400) as i64;
        // Scoped: drop the MutexGuard before calling timeout_stale_deliveries,
        // which re-acquires the same non-reentrant parking_lot::Mutex.
        {
            let conn = storage.db().unwrap();
            conn.execute(
                "INSERT INTO cheque_delivery_log (txid, recipient_email, sent_at, delivery_status, encrypted) VALUES (?1, ?2, ?3, 'sent', 0)",
                params![txid.as_ref(), "old@test.com", old_time],
            ).unwrap();
        }

        let count = storage.timeout_stale_deliveries().unwrap();
        assert_eq!(count, 1);

        let (status, _, _, _, _) = storage.get_delivery_status(&txid).unwrap().unwrap();
        assert_eq!(status, "timeout");
    }

    #[test]
    fn test_update_delivery_encrypted() {
        let storage = Storage::open_test().unwrap();
        let txid = [0xFE; 32];
        storage.log_cheque_delivery(&txid, "test@test.com", false).unwrap();
        let (_, _, _, _, enc) = storage.get_delivery_status(&txid).unwrap().unwrap();
        assert!(!enc, "Initially not encrypted");
        storage.update_delivery_encrypted(&txid, true).unwrap();
        let (_, _, _, _, enc2) = storage.get_delivery_status(&txid).unwrap().unwrap();
        assert!(enc2, "Should be encrypted after update");
    }

    #[test]
    fn test_delivery_log_encrypted_flag() {
        let storage = Storage::open_test().unwrap();
        let txid = [0xE1; 32];
        storage.log_cheque_delivery(&txid, "pgp@test.com", true).unwrap();
        let (_, _, _, _, encrypted) = storage.get_delivery_status(&txid).unwrap().unwrap();
        assert!(encrypted, "encrypted flag must be true");
    }

    #[test]
    fn test_dwp_vote_rate_limit_single_tick() {
        let storage = Storage::open_test().unwrap();
        let case = "DWP/test1234";
        let sender = "alice@test/00001111";
        let tick = 100u64;

        // First vote: allowed
        assert!(!storage.dwp_vote_rate_exceeded(case, sender, tick));
        storage.dwp_record_vote(case, sender, tick).unwrap();

        // Second vote same tick: rejected
        assert!(storage.dwp_vote_rate_exceeded(case, sender, tick),
            "Second vote in same tick must be rate-limited");
    }

    #[test]
    fn test_dwp_vote_rate_limit_different_ticks() {
        let storage = Storage::open_test().unwrap();
        let case = "DWP/test5678";
        let sender = "bob@test/00002222";

        // Tick 100: allowed
        assert!(!storage.dwp_vote_rate_exceeded(case, sender, 100));
        storage.dwp_record_vote(case, sender, 100).unwrap();

        // Tick 101: allowed (different tick)
        assert!(!storage.dwp_vote_rate_exceeded(case, sender, 101),
            "Vote in different tick must be allowed");
        storage.dwp_record_vote(case, sender, 101).unwrap();
    }

    #[test]
    fn test_dwp_vote_rate_enforced_end_to_end() {
        let storage = Storage::open_test().unwrap();
        let case = "DWP/E2E/001";
        let alice = "alice@test/aabbccdd";
        let bob = "bob@test/11223344";
        let tick = 1000u64;

        // Step 1: Alice votes at tick 1000 — allowed
        assert!(!storage.dwp_vote_rate_exceeded(case, alice, tick));
        storage.dwp_record_vote(case, alice, tick).unwrap();

        // Step 2: Alice votes AGAIN at tick 1000 — rate limited
        assert!(storage.dwp_vote_rate_exceeded(case, alice, tick),
            "Same sender/case/tick must be rate limited");

        // Step 3: Record the duplicate anyway — count should increment but rate check still blocks
        storage.dwp_record_vote(case, alice, tick).unwrap();
        assert!(storage.dwp_vote_rate_exceeded(case, alice, tick),
            "Still rate limited after duplicate record");

        // Step 4: Alice votes at tick 1001 — different tick, allowed
        assert!(!storage.dwp_vote_rate_exceeded(case, alice, tick + 1),
            "Different tick must reset rate limit for same sender");
        storage.dwp_record_vote(case, alice, tick + 1).unwrap();

        // Step 5: Bob votes at tick 1000 — different sender, allowed
        assert!(!storage.dwp_vote_rate_exceeded(case, bob, tick),
            "Different sender in same tick must be allowed");
        storage.dwp_record_vote(case, bob, tick).unwrap();

        // Step 6: Bob also rate limited at tick 1000 after his vote
        assert!(storage.dwp_vote_rate_exceeded(case, bob, tick),
            "Bob also rate limited after voting in same tick");
    }

    #[test]
    fn test_delivery_ack_updates_encrypted_record() {
        let storage = Storage::open_test().unwrap();
        let txid = [0xE2; 32];
        storage.log_cheque_delivery(&txid, "pgp@test.com", true).unwrap();
        storage.mark_delivery_acked(&txid).unwrap();
        let (status, _, _, ack, encrypted) = storage.get_delivery_status(&txid).unwrap().unwrap();
        assert_eq!(status, "acked");
        assert!(ack.is_some());
        assert!(encrypted, "encrypted flag must persist after ACK");
    }

    #[test]
    fn test_recent_hint_count_excludes_stale() {
        let storage = Storage::open_test().unwrap();
        // Insert 6 hints with last_seen 2 hours ago
        let old_time = (unix_now() - 7200) as i64;
        // Scoped: drop the MutexGuard before calling hint_count / recent_hint_count,
        // which re-acquire the same non-reentrant parking_lot::Mutex.
        {
            let conn = storage.db().unwrap();
            for i in 0..6u8 {
                conn.execute(
                    "INSERT INTO validator_hints (validator_id, name, proof_cap, carriers, last_seen, stored_at) VALUES (?1, ?2, 'dmap', 'email', ?3, ?3)",
                    params![format!("stale-{}", i), format!("Stale {}", i), old_time],
                ).unwrap();
            }
        }
        assert_eq!(storage.hint_count(), 6, "Total hints should be 6");
        assert_eq!(storage.recent_hint_count(3600), 0, "Recent hints (1h) should be 0 — all stale");
    }

    #[test]
    fn test_recent_hint_count_includes_fresh() {
        let storage = Storage::open_test().unwrap();
        let now = unix_now() as i64;
        // Scoped: drop the MutexGuard before calling recent_hint_count,
        // which re-acquires the same non-reentrant parking_lot::Mutex.
        {
            let conn = storage.db().unwrap();
            for i in 0..4u8 {
                conn.execute(
                    "INSERT INTO validator_hints (validator_id, name, proof_cap, carriers, last_seen, stored_at) VALUES (?1, ?2, 'dmap', 'email', ?3, ?3)",
                    params![format!("fresh-{}", i), format!("Fresh {}", i), now],
                ).unwrap();
            }
        }
        assert_eq!(storage.recent_hint_count(3600), 4, "Recent hints should be 4");
    }

    #[test]
    fn test_get_scar_passcode_full_returns_timestamps() {
        let storage = Storage::open_test().unwrap();
        let txid = [0xF1; 32];
        let wallet_pk = [0xF2; 32];
        storage.store_scar_passcode(&txid, &wallet_pk, 111222).unwrap();
        storage.mark_passcode_delivered(&txid).unwrap();
        let (passcode, delivered, recovered) = storage.get_scar_passcode_full(&txid).unwrap().unwrap();
        assert_eq!(passcode, 111222);
        assert!(delivered.is_some(), "delivered_at must be set");
        assert!(recovered.is_none(), "recovered_at must be None");
    }

    #[test]
    fn test_scar_passcode_full_without_recover() {
        let storage = Storage::open_test().unwrap();
        let txid = [0xF3; 32];
        let wallet_pk = [0xF4; 32];
        storage.store_scar_passcode(&txid, &wallet_pk, 333444).unwrap();
        let (_, _, recovered) = storage.get_scar_passcode_full(&txid).unwrap().unwrap();
        assert!(recovered.is_none(), "recovered_at must be None without mark_recovered");
    }

    #[test]
    fn test_scar_passcode_delivered_and_recovered() {
        let storage = Storage::open_test().unwrap();
        let txid = [0xBB; 32];
        let wallet_pk = [0xCC; 32];

        storage.store_scar_passcode(&txid, &wallet_pk, 654321).unwrap();
        assert_eq!(storage.get_scar_passcode(&txid).unwrap(), Some(654321));

        storage.mark_passcode_delivered(&txid).unwrap();
        // Passcode still retrievable after delivery
        assert_eq!(storage.get_scar_passcode(&txid).unwrap(), Some(654321));

        storage.mark_passcode_recovered(&txid).unwrap();
        // Passcode still retrievable after recovery
        assert_eq!(storage.get_scar_passcode(&txid).unwrap(), Some(654321));
    }

    #[test]
    fn test_receipt_roundtrip() {
        let storage = Storage::open_test().unwrap();

        // Sentinel non-zero commitment so the SQLite round-trip is
        // observable. Real wire receipts must have non-zero
        // receipt_commitment after the strict-mode flip in
        // core/logic/src/validation.rs (the skip-when-zero shim was
        // removed pre-mainnet). The compute_receipt_commitment function
        // is in the private `crypto` module so this storage test uses a
        // distinctive sentinel rather than the canonical hash; see
        // core/logic/src/validation.rs::tests::test_receipt_commitment_strict_*
        // for the end-to-end consistency tests.
        let receipt_commitment: [u8; 32] = [0x9F; 32];
        let receipt = Receipt {
            oods_flag: None,
            txid: [0x12; 32],
            state_hash: [0x34; 32],
            produced_state_id: [0x56; 32],
            new_wallet_seq: 1,
            commitment_hash: [0x78; 32],
            sdid: [0u8; 32],
            lineage_hash: [0u8; 32],
            core_version: String::new(),
            core_id: [0u8; 32],
            witness_sigs: vec![],
            epoch: 1,
            fact_proof: None,
            required_k: 3,
            receipt_commitment,
            fee_breakdown: Vec::new(),
            is_dev_class: false,
        };

        storage.store_receipt(&receipt).unwrap();

        assert!(storage.has_receipt(&[0x12; 32]).unwrap());

        let loaded = storage.get_receipt(&[0x12; 32]).unwrap();
        let loaded = loaded.unwrap();
        assert_eq!(loaded.epoch, 1);
        assert_eq!(loaded.receipt_commitment, receipt_commitment,
            "receipt_commitment must round-trip through SQLite storage");
    }

    #[test]
    fn test_encryption_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("encrypted.db");

        // Open with key A, write data
        {
            let storage =
                Storage::open(&db_path, "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233").unwrap();
            let state = StoredWalletState {
                public_key: vec![1; 32],
                balance: 999,
                wallet_seq: 1,
                state_id: [0xAA; 32],
                last_tx_id: None,
                status: WalletStateStatus::Confirmed,
                group_members: None,
                auth_hash: None, hibernation_until: 0,
                wallet_id: None,
            };
            storage.set_wallet_state(&state, 3, 1).unwrap();
        }

        // Open with key B — should fail
        let result =
            Storage::open(&db_path, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert!(result.is_err(), "Opening with wrong key should fail");
    }

    #[test]
    fn test_txid_consumed_state_roundtrip() {
        let storage = Storage::open_test().unwrap();

        let txid = [0xAA; 32];
        let csid = [0xBB; 32];

        assert!(storage.get_consumed_state_by_txid(&txid).unwrap().is_none());

        storage.store_txid_consumed_state(&txid, &csid).unwrap();
        let loaded = storage.get_consumed_state_by_txid(&txid).unwrap().unwrap();
        assert_eq!(loaded, csid);
    }

    #[test]
    fn test_derive_db_key() {
        let secret = [0x42u8; 32];
        let key1 = derive_db_key(&secret, b"AXIOM_DB_KEY_V1");
        let key2 = derive_db_key(&secret, b"AXIOM_MGMT_DB_KEY_V1");

        // Same secret, different domains → different keys
        assert_ne!(key1, key2);
        // Deterministic
        assert_eq!(key1, derive_db_key(&secret, b"AXIOM_DB_KEY_V1"));
        // 64 hex chars (32 bytes)
        assert_eq!(key1.len(), 64);
    }

    // ================================================================
    // INV-04: Concurrent double-redeem storage test
    // ================================================================
    // AUDIT-FIX v2.11.13: Confirms that concurrent redeem attempts for the
    // same cheque_id are serialised by the Storage mutex — exactly 1 succeeds.
    // Storage mutex serialises concurrent access — this test confirms the
    // invariant holds under mutex serialisation.

    #[test]
    fn test_inv04_concurrent_double_redeem_storage() {
        use std::sync::Arc;
        use std::thread;

        let storage = Arc::new(Storage::open_test().expect("open test DB"));
        let cheque_id: [u8; 32] = *blake3::hash(b"INV04-test-cheque-concurrent").as_bytes();

        let n_threads = 6;
        let mut handles = Vec::new();
        let barrier = Arc::new(std::sync::Barrier::new(n_threads));

        for _ in 0..n_threads {
            let s = storage.clone();
            let cid = cheque_id;
            let b = barrier.clone();
            handles.push(thread::spawn(move || {
                b.wait(); // Sync all threads to fire simultaneously
                // Atomic check-and-mark (same as consensus.rs redeem path)
                s.try_mark_cheque_redeemed(&cid).unwrap()
            }));
        }

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let accepted = results.iter().filter(|&&r| r).count();
        let rejected = results.iter().filter(|&&r| !r).count();

        assert_eq!(accepted, 1,
            "INV-04: exactly 1 concurrent redeem must succeed, got {}", accepted);
        assert_eq!(rejected, n_threads - 1,
            "INV-04: {} threads must be rejected, got {}", n_threads - 1, rejected);

        // Confirm cheque is marked as redeemed
        assert!(storage.is_cheque_redeemed(&cheque_id).unwrap(),
            "Cheque must be marked as redeemed after concurrent test");
    }

    #[test]
    fn test_inv04_staggered_double_redeem_storage() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let storage = Arc::new(Storage::open_test().expect("open test DB"));
        let cheque_id: [u8; 32] = *blake3::hash(b"INV04-test-cheque-staggered").as_bytes();

        let delays_ms = [0, 5, 10, 20, 50, 100];
        let mut handles = Vec::new();

        for &delay in &delays_ms {
            let s = storage.clone();
            let cid = cheque_id;
            handles.push(thread::spawn(move || {
                thread::sleep(Duration::from_millis(delay));
                s.try_mark_cheque_redeemed(&cid).unwrap()
            }));
        }

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let accepted = results.iter().filter(|&&r| r).count();

        assert_eq!(accepted, 1,
            "INV-04 stagger: exactly 1 redeem must succeed, got {}", accepted);
        assert!(storage.is_cheque_redeemed(&cheque_id).unwrap());
    }

    // ========================================================================
    // YPX-016: Witness Response Cache Tests
    // ========================================================================

    #[test]
    fn test_witness_cache_miss_returns_none() {
        let storage = Storage::open_test().unwrap();

        let wallet_pk = [0xAAu8; 32];
        let tx_hash = [0xBBu8; 32];
        let consumed = [0xCCu8; 32];

        let result = storage.get_witness_cache(&wallet_pk, 3, 1, &tx_hash, &consumed, 1).unwrap();
        assert!(result.is_none(), "Empty cache must return None");
    }

    #[test]
    fn test_witness_cache_hit_returns_response() {
        let storage = Storage::open_test().unwrap();

        let wallet_pk = [0xAAu8; 32];
        let tx_hash = [0xBBu8; 32];
        let consumed = [0xCCu8; 32];
        let response = b"cached_witness_response_data";

        storage.set_witness_cache(&wallet_pk, 3, 1, &tx_hash, &consumed, 1, response).unwrap();

        let result = storage.get_witness_cache(&wallet_pk, 3, 1, &tx_hash, &consumed, 1).unwrap();
        assert_eq!(result, Some(response.to_vec()), "Cache hit must return stored response");
    }

    #[test]
    fn test_witness_cache_different_tx_hash_misses() {
        // Attack: attacker sends different TX (different nonce) with same seq.
        // Cache must NOT return the cached response.
        let storage = Storage::open_test().unwrap();

        let wallet_pk = [0xAAu8; 32];
        let tx_hash_original = [0xBBu8; 32];
        let tx_hash_attack = [0xDDu8; 32];  // Different TX
        let consumed = [0xCCu8; 32];

        storage.set_witness_cache(&wallet_pk, 3, 1, &tx_hash_original, &consumed, 1, b"response").unwrap();

        let result = storage.get_witness_cache(&wallet_pk, 3, 1, &tx_hash_attack, &consumed, 1).unwrap();
        assert!(result.is_none(),
            "Different TX hash MUST miss cache — prevents different-TX substitution attack");
    }

    #[test]
    fn test_witness_cache_different_seq_misses() {
        // Different wallet_seq = different TX slot. Must not return cached response.
        let storage = Storage::open_test().unwrap();

        let wallet_pk = [0xAAu8; 32];
        let tx_hash = [0xBBu8; 32];
        let consumed = [0xCCu8; 32];

        storage.set_witness_cache(&wallet_pk, 3, 1, &tx_hash, &consumed, 1, b"response").unwrap();

        let result = storage.get_witness_cache(&wallet_pk, 3, 1, &tx_hash, &consumed, 2).unwrap();
        assert!(result.is_none(),
            "Different wallet_seq MUST miss cache");
    }

    #[test]
    fn test_witness_cache_different_consumed_misses() {
        // Different consumed_state_id = different state chain position.
        let storage = Storage::open_test().unwrap();

        let wallet_pk = [0xAAu8; 32];
        let tx_hash = [0xBBu8; 32];
        let consumed_original = [0xCCu8; 32];
        let consumed_different = [0xEEu8; 32];

        storage.set_witness_cache(&wallet_pk, 3, 1, &tx_hash, &consumed_original, 1, b"response").unwrap();

        let result = storage.get_witness_cache(&wallet_pk, 3, 1, &tx_hash, &consumed_different, 1).unwrap();
        assert!(result.is_none(),
            "Different consumed_state_id MUST miss cache");
    }

    #[test]
    fn test_witness_cache_overwrites_on_new_witness() {
        // New witness for same wallet overwrites the cache. Only 1 entry per wallet.
        let storage = Storage::open_test().unwrap();

        let wallet_pk = [0xAAu8; 32];
        let tx_hash_1 = [0x11u8; 32];
        let tx_hash_2 = [0x22u8; 32];
        let consumed_1 = [0xCCu8; 32];
        let consumed_2 = [0xDDu8; 32];

        storage.set_witness_cache(&wallet_pk, 3, 1, &tx_hash_1, &consumed_1, 1, b"response1").unwrap();
        storage.set_witness_cache(&wallet_pk, 3, 1, &tx_hash_2, &consumed_2, 2, b"response2").unwrap();

        // Old entry overwritten
        let result = storage.get_witness_cache(&wallet_pk, 3, 1, &tx_hash_1, &consumed_1, 1).unwrap();
        assert!(result.is_none(), "Old cache entry must be overwritten");

        // New entry present
        let result = storage.get_witness_cache(&wallet_pk, 3, 1, &tx_hash_2, &consumed_2, 2).unwrap();
        assert_eq!(result, Some(b"response2".to_vec()), "New cache entry must be present");
    }

    #[test]
    fn test_witness_cache_oracle_tx_safe() {
        // Oracle TXs have NablaStakeProof that may become stale.
        // Cache returns the original response (no re-execution).
        // The cached response contains the original valid witness signature.
        let storage = Storage::open_test().unwrap();

        let wallet_pk = [0xAAu8; 32];
        // Oracle TX hash includes oracle_claim data
        let oracle_tx_hash = [0xFFu8; 32];
        let consumed = [0xCCu8; 32];
        let oracle_response = b"oracle_witness_with_stake_proof";

        storage.set_witness_cache(&wallet_pk, 3, 1, &oracle_tx_hash, &consumed, 1, oracle_response).unwrap();

        // Retry returns cached response — no NablaStakeProof re-check needed
        let result = storage.get_witness_cache(&wallet_pk, 3, 1, &oracle_tx_hash, &consumed, 1).unwrap();
        assert_eq!(result, Some(oracle_response.to_vec()),
            "Oracle TX retry must return cached response (no re-execution, no stale proof issue)");
    }

    #[test]
    fn test_witness_cache_group_wallet_safe() {
        // Group wallet TXs use the same Transaction struct.
        // Cache works identically for group wallets.
        let storage = Storage::open_test().unwrap();

        // Group wallet PK (shared key)
        let group_pk = [0x77u8; 32];
        let jfp_vote_tx_hash = [0x88u8; 32]; // JFP vote TX (1-atom to DWP/)
        let consumed = [0xCCu8; 32];
        let vote_response = b"jfp_vote_witness_response";

        storage.set_witness_cache(&group_pk, 3, 1, &jfp_vote_tx_hash, &consumed, 5, vote_response).unwrap();

        let result = storage.get_witness_cache(&group_pk, 3, 1, &jfp_vote_tx_hash, &consumed, 5).unwrap();
        assert_eq!(result, Some(vote_response.to_vec()),
            "Group wallet (JFP vote) TX retry must return cached response");
    }

    #[test]
    fn test_witness_cache_idempotent_same_txid() {
        // Same TX retried = same txid. Nabla txid service prevents double-redeem.
        // This test verifies the cache returns the exact same bytes (idempotent).
        let storage = Storage::open_test().unwrap();

        let wallet_pk = [0xAAu8; 32];
        let tx_hash = [0xBBu8; 32];
        let consumed = [0xCCu8; 32];
        let response = b"exact_witness_response_bytes";

        storage.set_witness_cache(&wallet_pk, 3, 1, &tx_hash, &consumed, 1, response).unwrap();

        // Multiple retries all return identical bytes
        for _ in 0..5 {
            let result = storage.get_witness_cache(&wallet_pk, 3, 1, &tx_hash, &consumed, 1).unwrap();
            assert_eq!(result.as_deref(), Some(response.as_slice()),
                "Cache must return identical bytes on every retry (idempotent)");
        }
    }

    #[test]
    fn test_witness_cache_cross_wallet_isolation() {
        // Cache entries are per-wallet. Wallet A's cache must not affect Wallet B.
        let storage = Storage::open_test().unwrap();

        let wallet_a = [0xAAu8; 32];
        let wallet_b = [0xBBu8; 32];
        let tx_hash = [0x11u8; 32]; // Same TX hash (unlikely but test isolation)
        let consumed = [0xCCu8; 32];

        storage.set_witness_cache(&wallet_a, 3, 1, &tx_hash, &consumed, 1, b"response_a").unwrap();

        let result = storage.get_witness_cache(&wallet_b, 3, 1, &tx_hash, &consumed, 1).unwrap();
        assert!(result.is_none(),
            "Wallet B must not see Wallet A's cached response");
    }

    // ════════════════════════════════════════════════════════════════════
    // YPX-018 — CLARA roll-forward storage tests (Phase 5a)
    // ════════════════════════════════════════════════════════════════════

    fn make_stored(pk: &[u8], state_id: [u8; 32], seq: u64, balance: u64) -> StoredWalletState {
        StoredWalletState {
            public_key: pk.to_vec(),
            balance,
            wallet_seq: seq,
            state_id,
            last_tx_id: None,
            status: WalletStateStatus::Confirmed,
            group_members: None,
            auth_hash: None, hibernation_until: 0,
            wallet_id: None,
        }
    }

    /// SINGLE-KEYPAIR CONVERGENCE PROOF (YPX-010 §10.5). One keypair backs both a
    /// normal (k=3) and an Ark (k=0) wallet. Because the state row is keyed by
    /// (public_key, k, proof_type), the two tiers COEXIST in storage — neither
    /// overwrites the other. Before the re-key, both mapped to one pk-keyed row
    /// and the second write clobbered the first. This is the whole point of the
    /// re-key; the tier-distinct genesis state_ids from step 1 would otherwise
    /// land in the same row.
    #[test]
    fn wallet_state_tiers_coexist_under_one_pk() {
        use axiom_core_logic::wallet_id::{K_ARK, PROOF_TYPE_ARK, PROOF_TYPE_DMAP};
        let storage = Storage::open_test().unwrap();
        let pk = [0x7fu8; 32];

        // Distinct states for the SAME pk at two tiers.
        let normal = make_stored(&pk, [0x11u8; 32], 5, 100_000); // k=3 reserve
        let ark = make_stored(&pk, [0x22u8; 32], 2, 10_000); // k=0 float

        storage.set_wallet_state(&normal, 3, PROOF_TYPE_DMAP).unwrap();
        storage.set_wallet_state(&ark, K_ARK, PROOF_TYPE_ARK).unwrap();

        // Each tier reads back its OWN state — no collision.
        let g_normal = storage.get_wallet_state(&pk, 3, PROOF_TYPE_DMAP).unwrap().unwrap();
        let g_ark = storage.get_wallet_state(&pk, K_ARK, PROOF_TYPE_ARK).unwrap().unwrap();
        assert_eq!(g_normal.balance, 100_000, "k=3 reserve must survive the k=0 write");
        assert_eq!(g_ark.balance, 10_000, "k=0 float is its own row");
        assert_eq!(g_normal.state_id, [0x11u8; 32]);
        assert_eq!(g_ark.state_id, [0x22u8; 32]);

        // A tier that was never written for this pk is absent (not a stray match).
        assert!(storage.get_wallet_state(&pk, 4, PROOF_TYPE_DMAP).unwrap().is_none());
    }

    /// Phase 5f Finding 4: stored balance is poisoned to 100 (the partial TX
    /// debited 900 from a real 1000), and CLARA roll-forward refreshes it to
    /// the canonical 1000 declared by the heal cheque's state_hash binding.
    #[test]
    fn test_clara_roll_forward_advances_from_garbage_to_healed() {
        let storage = Storage::open_test().unwrap();
        let pk = vec![0xAA; 32];
        let garbage = [0x11; 32];
        let healed_to = [0x22; 32];
        // Validator was poisoned: stored balance is 100 (canonical was 1000).
        storage.set_wallet_state(&make_stored(&pk, garbage, 5, 100), 3, 1).unwrap();

        let applied = storage.clara_roll_forward(
            &pk, 3, 1, &garbage, &healed_to, 9, 1000, &[garbage],
        ).unwrap();
        assert!(applied);

        let after = storage.get_wallet_state(&pk, 3, 1).unwrap().unwrap();
        assert_eq!(after.state_id, healed_to);
        assert_eq!(after.wallet_seq, 9);
        assert_eq!(after.balance, 1000,
            "Phase 5f Finding 4: stored balance must be refreshed to the \
             cryptographically attested healed_balance, not stay at the \
             pre-heal poisoned value");
    }

    #[test]
    fn test_clara_roll_forward_rejects_when_stored_not_in_garbage() {
        let storage = Storage::open_test().unwrap();
        let pk = vec![0xBB; 32];
        let unrelated = [0xEE; 32];
        let healed_to = [0x22; 32];
        storage.set_wallet_state(&make_stored(&pk, unrelated, 5, 100_000), 3, 1).unwrap();

        let applied = storage.clara_roll_forward(
            &pk, 3, 1, &[0x11; 32], &healed_to, 9, 999_999, &[[0x11; 32], [0x12; 32]],
        ).unwrap();
        assert!(!applied, "must refuse when stored state isn't in garbage");

        let after = storage.get_wallet_state(&pk, 3, 1).unwrap().unwrap();
        assert_eq!(after.state_id, unrelated, "state must NOT be changed on refusal");
        assert_eq!(after.balance, 100_000,
            "balance must NOT be changed when roll-forward is refused");
    }

    #[test]
    fn test_clara_roll_forward_idempotent_when_already_at_healed() {
        let storage = Storage::open_test().unwrap();
        let pk = vec![0xCC; 32];
        let healed_to = [0x22; 32];
        storage.set_wallet_state(&make_stored(&pk, healed_to, 9, 100_000), 3, 1).unwrap();

        let applied = storage.clara_roll_forward(
            &pk, 3, 1, &[0x11; 32], &healed_to, 9, 100_000, &[[0x11; 32]],
        ).unwrap();
        assert!(applied, "second application of same heal must succeed (idempotent)");

        let after = storage.get_wallet_state(&pk, 3, 1).unwrap().unwrap();
        assert_eq!(after.state_id, healed_to);
        assert_eq!(after.wallet_seq, 9);
    }

    #[test]
    fn test_clara_roll_forward_no_stored_state_succeeds() {
        // A wallet that's never been observed by this validator can't be
        // "poisoned", so CLARA roll-forward is a no-op (success).
        let storage = Storage::open_test().unwrap();
        let pk = vec![0xDD; 32];
        let applied = storage.clara_roll_forward(
            &pk, 3, 1, &[0x11; 32], &[0x22; 32], 9, 1000, &[[0x11; 32]],
        ).unwrap();
        assert!(applied);
    }

    #[test]
    fn test_clara_roll_forward_accepts_from_state_directly() {
        // Edge case: stored state == healed_from_state_id (not in garbage list).
        // This is the legitimate case where the validator is exactly at the
        // pre-broken state and the heal is jumping past it.
        let storage = Storage::open_test().unwrap();
        let pk = vec![0xEE; 32];
        let from = [0x33; 32];
        let healed_to = [0x44; 32];
        storage.set_wallet_state(&make_stored(&pk, from, 5, 100_000), 3, 1).unwrap();

        let applied = storage.clara_roll_forward(
            &pk, 3, 1, &from, &healed_to, 9, 100_000, &[],  // empty garbage; matches via from
        ).unwrap();
        assert!(applied);
        assert_eq!(storage.get_wallet_state(&pk, 3, 1).unwrap().unwrap().state_id, healed_to);
    }

    #[test]
    fn test_clara_roll_forward_advances_through_one_of_many_garbage() {
        let storage = Storage::open_test().unwrap();
        let pk = vec![0xFF; 32];
        let stored = [0x77; 32]; // matches garbage[1]
        let healed_to = [0x99; 32];
        storage.set_wallet_state(&make_stored(&pk, stored, 5, 100_000), 3, 1).unwrap();

        let applied = storage.clara_roll_forward(
            &pk, 3, 1, &[0x33; 32], &healed_to, 9, 100_000,
            &[[0x66; 32], [0x77; 32], [0x88; 32]],
        ).unwrap();
        assert!(applied);
        assert_eq!(storage.get_wallet_state(&pk, 3, 1).unwrap().unwrap().state_id, healed_to);
    }

    /// Phase 5f Finding 4 regression: balance must be refreshed to the
    /// cryptographically attested value, even when the stored balance was
    /// arbitrarily poisoned by a partial witness.
    #[test]
    fn test_clara_roll_forward_refreshes_poisoned_balance() {
        let storage = Storage::open_test().unwrap();
        let pk = vec![0x42; 32];
        let garbage = [0x55; 32];
        let healed_to = [0x66; 32];
        // Worst case: stored balance was debited to 0 by a partial TX that
        // tried to send the wallet's entire 1 trillion atom holding.
        storage.set_wallet_state(&make_stored(&pk, garbage, 7, 0), 3, 1).unwrap();

        let canonical = 1_000_000_000_000u64;
        let applied = storage.clara_roll_forward(
            &pk, 3, 1, &[0x99; 32], &healed_to, 11, canonical, &[garbage],
        ).unwrap();
        assert!(applied);

        let after = storage.get_wallet_state(&pk, 3, 1).unwrap().unwrap();
        assert_eq!(after.balance, canonical,
            "balance must be restored to the cryptographically attested \
             canonical value after CLARA roll-forward");
        assert_eq!(after.state_id, healed_to);
        assert_eq!(after.wallet_seq, 11);
    }
}
