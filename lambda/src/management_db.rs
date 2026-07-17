//! Management database — JFP freeze orders, DWP wallets, MVIB bindings, Console governance.
//!
//! Separate from the transaction DB (`lambda.db`).
//! Uses NORMAL locking so Console and admin API can read concurrently.
//! Active subsystems: freeze_orders (JFP), dwp_wallets (DWP), mvib_bindings (MVIB),
//! digit_version (L$ governance), audit_log.

use crate::error::LambdaError;
use rusqlite::Connection;
use std::path::Path;
use parking_lot::Mutex;
use tracing::debug;

/// Management database — JFP, DWP, MVIB, Console governance.
pub struct ManagementDb {
    conn: Mutex<Connection>,
}

impl ManagementDb {
    /// Open (or create) the management database with encryption
    pub fn open(db_path: &Path, db_key_hex: &str) -> Result<Self, LambdaError> {
        let conn = Connection::open(db_path)
            .map_err(|e| LambdaError::StorageError(format!("Failed to open management DB: {}", e)))?;

        if !db_key_hex.is_empty() {
            conn.pragma_update(None, "key", format!("x'{}'", db_key_hex))
                .map_err(|e| LambdaError::StorageError(format!("Failed to set management DB key: {}", e)))?;
        }

        // Normal locking — allows future console reads
        let pragmas = [
            "PRAGMA journal_mode = WAL",
            "PRAGMA synchronous = FULL",
            "PRAGMA locking_mode = NORMAL",
            "PRAGMA foreign_keys = ON",
            "PRAGMA busy_timeout = 5000",
        ];
        for pragma in &pragmas {
            conn.execute_batch(pragma)
                .map_err(|e| LambdaError::StorageError(format!("Management DB PRAGMA failed: {}", e)))?;
        }

        Self::create_schema(&conn)?;

        debug!("Management DB opened: {:?}", db_path);

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an unencrypted in-memory database for testing
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn open_test() -> Result<Self, LambdaError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| LambdaError::StorageError(format!("Failed to open in-memory management DB: {}", e)))?;

        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000")
            .map_err(|e| LambdaError::StorageError(format!("Management DB PRAGMA failed: {}", e)))?;

        Self::create_schema(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn create_schema(conn: &Connection) -> Result<(), LambdaError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');

            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                details    TEXT NOT NULL,
                wallet_pk  BLOB
            );
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_wallet ON audit_log(wallet_pk);

            CREATE TABLE IF NOT EXISTS freeze_orders (
                order_id      TEXT PRIMARY KEY,
                wallet_pk     BLOB NOT NULL,
                authority     TEXT NOT NULL,
                issued_at     INTEGER NOT NULL,
                expires_at    INTEGER,
                status        TEXT NOT NULL DEFAULT 'Active',
                evidence_hash BLOB,
                created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_freeze_wallet ON freeze_orders(wallet_pk);

            -- DWP group wallets (JFP lifecycle tracking)
            CREATE TABLE IF NOT EXISTS dwp_wallets (
                wallet_id     BLOB PRIMARY KEY,
                status        TEXT NOT NULL DEFAULT 'locked',  -- locked, resolved, expired
                wallet_type   TEXT NOT NULL DEFAULT 'DWP',
                txid          BLOB NOT NULL,                   -- TX being investigated
                anchor_pk     BLOB NOT NULL,                   -- entry validator (liaison)
                requester_pk  BLOB NOT NULL,                   -- who paid
                payment_txid  BLOB,                            -- k=3 TX receipt of 1 AXC payment
                amount        INTEGER NOT NULL DEFAULT 100000000, -- 1 AXC in atoms
                pwv_set       TEXT,                            -- JSON array of 15 validator_id hex strings
                result        TEXT DEFAULT 'pending',          -- pending, approved, rejected, expired
                result_hash   BLOB,                            -- BLAKE3(votes || result || order_id)
                created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                resolved_at   INTEGER,
                expires_at    INTEGER                          -- resolved_at + 365 days
            );

            -- DWP case log entries
            CREATE TABLE IF NOT EXISTS dwp_case_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_id     BLOB NOT NULL,
                author_pk     BLOB NOT NULL,
                timestamp     INTEGER NOT NULL,
                tardis_tick   INTEGER NOT NULL DEFAULT 0,
                content       TEXT NOT NULL,                   -- max 4096 bytes enforced in code
                FOREIGN KEY (wallet_id) REFERENCES dwp_wallets(wallet_id)
            );
            CREATE INDEX IF NOT EXISTS idx_case_log_wallet ON dwp_case_log(wallet_id);

            -- JFP vote index (tracks which votes arrived as k=3 TXs)
            -- This is NOT a separate voting mechanism — it indexes real TXs
            -- on the group wallet for result computation. See YP §8.4.
            CREATE TABLE IF NOT EXISTS jfp_vote_index (
                dwp_wallet_id BLOB NOT NULL,
                voter_pk      BLOB NOT NULL,               -- sender of the vote TX
                vote_hash     BLOB NOT NULL,                -- BLAKE3 hash from TX reference
                tx_id         BLOB,                         -- txid of the witnessed vote TX
                timestamp     INTEGER NOT NULL,
                FOREIGN KEY (dwp_wallet_id) REFERENCES dwp_wallets(wallet_id),
                UNIQUE(dwp_wallet_id, voter_pk)
            );

            -- DWP query replay cache (prevent same txid queried cheaply)
            CREATE TABLE IF NOT EXISTS dwp_query_cache (
                txid          BLOB PRIMARY KEY,
                query_count   INTEGER NOT NULL DEFAULT 1,
                last_queried  INTEGER NOT NULL,
                dwp_wallet_id BLOB                             -- most recent DWP wallet for this txid
            );
            ",
        )
        .map_err(|e| LambdaError::StorageError(format!("Management schema creation failed: {}", e)))?;

        Ok(())
    }

    /// Get a reference to the database connection (locked).
    pub fn db(&self) -> Result<parking_lot::MutexGuard<'_, Connection>, LambdaError> {
        Ok(self.conn.lock())
    }

    /// Sweep expired DWP wallets — move unclaimed shares to pool.
    /// Called periodically by Lambda main loop.
    pub fn sweep_expired_dwp(&self) -> Result<u64, LambdaError> {
        let conn = self.conn.lock();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Find resolved wallets past expiry
        let count = conn.execute(
            "UPDATE dwp_wallets SET status = 'expired'
             WHERE status = 'resolved' AND expires_at IS NOT NULL AND expires_at < ?1",
            rusqlite::params![now as i64],
        ).map_err(|e| LambdaError::StorageError(format!("sweep_expired_dwp: {}", e)))?;

        if count > 0 {
            debug!("DWP sweep: {} wallets expired", count);
        }

        Ok(count as u64)
    }

    /// Get schema version
    pub fn schema_version(&self) -> Result<String, LambdaError> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))
    }

    /// Get current L$ digit_version (White Paper §J.14-J.18).
    /// digit_version=0: 1 AXC = 1 L$ (default).
    /// digit_version=N: 1 AXC = 10^N L$ (decimal shift for readability).
    /// Console-managed, presentation-only — does NOT affect protocol.
    pub fn get_digit_version(&self) -> Result<u8, LambdaError> {
        let conn = self.conn.lock();
        match conn.query_row(
            "SELECT value FROM meta WHERE key = 'digit_version'",
            [],
            |row| row.get::<_, String>(0),
        ) {
            Ok(v) => Ok(v.parse().unwrap_or(0)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(LambdaError::StorageError(e.to_string())),
        }
    }

    /// Set L$ digit_version. Called by Console governance only.
    /// Max ±2 digits per proposal, max 2 proposals/year, 3-month cooldown.
    pub fn set_digit_version(&self, version: u8) -> Result<(), LambdaError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('digit_version', ?1)",
            rusqlite::params![version.to_string()],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        debug!("L$ digit_version set to {}", version);
        Ok(())
    }

    /// JFP freeze duration (SEC-08). A judicial freeze auto-expires; it is NOT
    /// permanent (BANNED wallets are separately permanent — YP §..21602). Each
    /// freeze order carries `expires_at = issued_at + JFP_FREEZE_DURATION`, and
    /// `get_active_frozen_wallets` deterministically drops it once it passes —
    /// auto-unfreeze, no coordination. This also bounds the censorship residual:
    /// a false/malicious freeze self-lifts at expiry.
    ///
    /// NOTE: per SEC-08_RESOLUTION.md this 1-year figure is NOT yet in the
    /// Yellow Paper (the 365-day figure there is unclaimed-DWP-payment → pool, a
    /// different clock). The constant is defined here as the protocol value;
    /// the YP must state it. (1 year = 365 days.)
    pub const JFP_FREEZE_DURATION_SECS: u64 = crate::tuning_gen::JFP_FREEZE_DURATION_SECS;

    /// Insert a freeze order for a wallet (JFP §7 enforcement).
    /// Called by handle_jfp_scar after an APPROVED JFP result.
    /// The wallet_pk is the sender of the original investigated TX.
    pub fn insert_freeze_order(
        &self,
        order_id: &str,
        wallet_pk: &[u8; 32],
        authority: &str,
        evidence_hash: Option<&[u8; 32]>,
    ) -> Result<(), LambdaError> {
        let conn = self.conn.lock();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // SEC-08: set expires_at so the freeze auto-lifts. get_active_frozen_wallets
        // filters `expires_at IS NULL OR expires_at > now`, so this entry drops
        // deterministically at expiry on every validator with no coordination.
        let expires_at = now + Self::JFP_FREEZE_DURATION_SECS;
        conn.execute(
            "INSERT OR IGNORE INTO freeze_orders (order_id, wallet_pk, authority, issued_at, status, evidence_hash, expires_at)
             VALUES (?1, ?2, ?3, ?4, 'Active', ?5, ?6)",
            rusqlite::params![
                order_id,
                wallet_pk.as_ref(),
                authority,
                now as i64,
                evidence_hash.map(|h| h.as_ref()),
                expires_at as i64,
            ],
        ).map_err(|e| LambdaError::StorageError(format!("insert_freeze_order: {}", e)))?;
        debug!("Freeze order inserted: {} for wallet {} (expires_at {})", order_id, hex::encode(&wallet_pk[..8]), expires_at);
        Ok(())
    }

    /// Get all active frozen wallet PKs.
    /// Returns the set of wallet public keys that have an active freeze order.
    /// Lambda passes these to Core via PublicInputs.frozen_wallets for CL1 enforcement.
    pub fn get_active_frozen_wallets(&self) -> Result<Vec<[u8; 32]>, LambdaError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT wallet_pk FROM freeze_orders
             WHERE status = 'Active'
               AND (expires_at IS NULL OR expires_at > ?1)"
        ).map_err(|e| LambdaError::StorageError(format!("get_active_frozen_wallets: {}", e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let wallets: Vec<[u8; 32]> = stmt.query_map(
            rusqlite::params![now as i64],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let mut arr = [0u8; 32];
                if bytes.len() == 32 {
                    arr.copy_from_slice(&bytes);
                }
                Ok(arr)
            },
        ).map_err(|e| LambdaError::StorageError(format!("get_active_frozen_wallets: {}", e)))?
        .filter_map(|r| r.ok())
        .collect();

        Ok(wallets)
    }

    /// Revoke a freeze order (set status to 'Revoked').
    pub fn revoke_freeze_order(&self, order_id: &str) -> Result<bool, LambdaError> {
        let conn = self.conn.lock();
        let count = conn.execute(
            "UPDATE freeze_orders SET status = 'Revoked' WHERE order_id = ?1 AND status = 'Active'",
            rusqlite::params![order_id],
        ).map_err(|e| LambdaError::StorageError(format!("revoke_freeze_order: {}", e)))?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_management_db_open() {
        let db = ManagementDb::open_test().unwrap();
        assert_eq!(db.schema_version().unwrap(), "1");
    }

    #[test]
    fn test_sweep_expired_dwp() {
        let db = ManagementDb::open_test().unwrap();
        let conn = db.conn.lock();

        // Insert a resolved wallet that has already expired
        conn.execute(
            "INSERT INTO dwp_wallets (wallet_id, txid, anchor_pk, requester_pk, amount, status, result, resolved_at, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'resolved', 'approved', ?6, ?7, ?8)",
            rusqlite::params![
                [0xAA_u8; 32].as_ref(), [0xBB_u8; 32].as_ref(),
                [0x01_u8; 32].as_ref(), [0x02_u8; 32].as_ref(),
                100000000_i64, 1000_i64, 1001_i64, 999_i64,
            ],
        ).unwrap();

        // Insert a resolved wallet that has NOT expired yet (far future)
        conn.execute(
            "INSERT INTO dwp_wallets (wallet_id, txid, anchor_pk, requester_pk, amount, status, result, resolved_at, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'resolved', 'rejected', ?6, ?7, ?8)",
            rusqlite::params![
                [0xCC_u8; 32].as_ref(), [0xDD_u8; 32].as_ref(),
                [0x01_u8; 32].as_ref(), [0x02_u8; 32].as_ref(),
                100000000_i64, 1000_i64, 9999999999_i64, 999_i64,
            ],
        ).unwrap();
        drop(conn);

        let swept = db.sweep_expired_dwp().unwrap();
        assert_eq!(swept, 1, "Should sweep exactly 1 expired wallet");

        // Verify the expired one changed status
        let conn = db.conn.lock();
        let status: String = conn.query_row(
            "SELECT status FROM dwp_wallets WHERE wallet_id = ?1",
            rusqlite::params![[0xAA_u8; 32].as_ref()],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(status, "expired");

        // The non-expired one should still be resolved
        let status2: String = conn.query_row(
            "SELECT status FROM dwp_wallets WHERE wallet_id = ?1",
            rusqlite::params![[0xCC_u8; 32].as_ref()],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(status2, "resolved");
    }

    #[test]
    fn test_digit_version_default_zero() {
        let db = ManagementDb::open_test().unwrap();
        assert_eq!(db.get_digit_version().unwrap(), 0);
    }

    #[test]
    fn test_digit_version_set_and_get() {
        let db = ManagementDb::open_test().unwrap();
        db.set_digit_version(3).unwrap();
        assert_eq!(db.get_digit_version().unwrap(), 3);
        // Update
        db.set_digit_version(5).unwrap();
        assert_eq!(db.get_digit_version().unwrap(), 5);
    }

    #[test]
    fn test_management_db_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("management.db");
        let key = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";

        let db = ManagementDb::open(&db_path, key).unwrap();
        assert_eq!(db.schema_version().unwrap(), "1");
    }

    #[test]
    fn test_freeze_order_insert_and_query() {
        let db = ManagementDb::open_test().unwrap();

        // No frozen wallets initially
        let frozen = db.get_active_frozen_wallets().unwrap();
        assert!(frozen.is_empty(), "Should start with no frozen wallets");

        // Insert a freeze order
        let wallet_pk = [0xAA_u8; 32];
        let evidence = [0xBB_u8; 32];
        db.insert_freeze_order("JFP-001", &wallet_pk, "JFP", Some(&evidence)).unwrap();

        // Should now have 1 frozen wallet
        let frozen = db.get_active_frozen_wallets().unwrap();
        assert_eq!(frozen.len(), 1, "Should have 1 frozen wallet");
        assert_eq!(frozen[0], wallet_pk, "Frozen wallet PK should match");

        // Insert another freeze order for a different wallet
        let wallet_pk2 = [0xCC_u8; 32];
        db.insert_freeze_order("JFP-002", &wallet_pk2, "JFP", None).unwrap();

        let frozen = db.get_active_frozen_wallets().unwrap();
        assert_eq!(frozen.len(), 2, "Should have 2 frozen wallets");

        // Duplicate insert (same order_id) should be ignored
        db.insert_freeze_order("JFP-001", &wallet_pk, "JFP", None).unwrap();
        let frozen = db.get_active_frozen_wallets().unwrap();
        assert_eq!(frozen.len(), 2, "Duplicate should not create extra entry");
    }

    #[test]
    fn test_freeze_order_revoke() {
        let db = ManagementDb::open_test().unwrap();

        let wallet_pk = [0xDD_u8; 32];
        db.insert_freeze_order("JFP-R01", &wallet_pk, "JFP", None).unwrap();

        // Wallet should be frozen
        let frozen = db.get_active_frozen_wallets().unwrap();
        assert_eq!(frozen.len(), 1);

        // Revoke the order
        let revoked = db.revoke_freeze_order("JFP-R01").unwrap();
        assert!(revoked, "Should successfully revoke active order");

        // Wallet should no longer be frozen
        let frozen = db.get_active_frozen_wallets().unwrap();
        assert!(frozen.is_empty(), "Revoked wallet should not appear as frozen");

        // Revoking again should return false (already revoked)
        let revoked = db.revoke_freeze_order("JFP-R01").unwrap();
        assert!(!revoked, "Already revoked order should return false");
    }
}
