//! YPX-013: Console Engine — Core-signed governance chain with group wallet.
//!
//! The Console is the only authority for L$ digit_version migration.
//! All operations pass through a Console group wallet (DWP/CONSOLE/{gen}),
//! reusing JFP's 1-atom TX voting pattern.
//!
//! Consensus model: absence of sustained objection (NOT majority vote).
//! Election model: 3 random selectors from current Console each pick 5.
//!
//! # Key design — ONE-WAY TICKET:
//! After MAX_ELECTION_ATTEMPTS failed elections, Lambda stops sending
//! Fan-Out messages. No more elections. Console is permanently dissolved.
//! Only a new Core ELF can reinstate it. This is by design.
//!
//! Rules:
//! - 15 validators form the Console (scale custodians)
//! - 1-year term (6,311,520 ticks at 5s/tick)
//! - Max 2 digit migration proposals per year, 3-month cooldown
//! - Proposals carry a voting window (30 days); if no sustained objection → Approved
//! - Max ±2 digit magnitude per proposal
//! - Compensation: 1 AXC per full service year per member (conditional on full term)
//! - 3 failed elections → permanent dissolution

use crate::error::LambdaError;
use crate::management_db::ManagementDb;
use std::sync::Arc;
use tracing::{debug, info, warn, error};

// Re-export Core constants
pub use axiom_core_logic::types::{
    CONSOLE_SIZE, CONSOLE_TICKS_PER_YEAR,
    CONSOLE_MAX_ELECTION_ATTEMPTS,
    CONSOLE_ELECTION_WINDOW_TICKS, CONSOLE_ELECTION_RETRY_TICKS,
    CONSOLE_SELECTOR_COUNT, CONSOLE_PICKS_PER_SELECTOR,
    CONSOLE_CHAIN_DEPTH,
    ConsoleCertificate, SelectorPick,
};

// ── Console-specific constants (Lambda layer) ────────────────────────────────

/// Cooldown between digit migration proposals: 3 months at 5s/tick.
pub const CONSOLE_COOLDOWN_TICKS: u64 = crate::tuning_gen::CONSOLE_COOLDOWN_TICKS;

/// Maximum proposals per calendar year (White Paper G.2).
pub const CONSOLE_MAX_PROPOSALS_PER_YEAR: usize = 2;

/// Deliberation window: 24 hours at 5s/tick = 17,280 ticks (White Paper §7.8).
/// "Set to 24 hours to ensure operators across all time zones have opportunity to respond."
pub const CONSOLE_VOTING_WINDOW_TICKS: u64 = crate::tuning_gen::CONSOLE_VOTING_WINDOW_TICKS;

/// Maximum digit magnitude shift per proposal (White Paper §7.7: ±2 decimal places).
pub const CONSOLE_MAX_MAGNITUDE: u8 = 2;

/// Liveness check interval: 3 months at 5s/tick = 1,555,200 ticks (YP §21.12.3).
/// Console members MUST respond to a heartbeat within this window.
/// Failure by ANY member = entire Console dissolved. No partial continuation.
pub const CONSOLE_LIVENESS_INTERVAL_TICKS: u64 = crate::tuning_gen::CONSOLE_LIVENESS_INTERVAL_TICKS;

/// Liveness response window: 72 hours at 5s/tick = 51,840 ticks.
/// After a liveness check is broadcast, members have 72h to respond.
pub const CONSOLE_LIVENESS_RESPONSE_TICKS: u64 = crate::tuning_gen::CONSOLE_LIVENESS_RESPONSE_TICKS;

/// Console group wallet address prefix.
pub const CONSOLE_WALLET_PREFIX: &str = "DWP/CONSOLE/";

// ── Types ──────────────────────────────────────────────────────────────────────

/// Direction of digit migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigitDirection {
    /// Increase digit_version (1 AXC = more L$).
    Dedigitize,
    /// Decrease digit_version (1 AXC = fewer L$).
    Redigitize,
}

impl DigitDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            DigitDirection::Dedigitize => "Dedigitize",
            DigitDirection::Redigitize => "Redigitize",
        }
    }

    #[allow(clippy::should_implement_trait)] // Returns Option, not Result — intentionally differs from FromStr
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Dedigitize" => Some(DigitDirection::Dedigitize),
            "Redigitize" => Some(DigitDirection::Redigitize),
            _ => None,
        }
    }
}

/// Status of a Console proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalStatus {
    /// 24h deliberation window open, collecting votes.
    Active,
    /// Unanimous ACK — digit_version updated.
    Approved,
    /// Explicit NO received — action fails, Console continues.
    Rejected,
    /// Deliberation expired with missing votes — see retry_count.
    MissingVotes,
    /// Retry after first missing-votes failure (automatic second 24h window).
    Retry,
    /// Dissolved — second missing-votes failure dissolved the Console.
    Dissolved,
}

impl ProposalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProposalStatus::Active => "Active",
            ProposalStatus::Approved => "Approved",
            ProposalStatus::Rejected => "Rejected",
            ProposalStatus::MissingVotes => "MissingVotes",
            ProposalStatus::Retry => "Retry",
            ProposalStatus::Dissolved => "Dissolved",
        }
    }

    #[allow(clippy::should_implement_trait)] // Returns Option, not Result — intentionally differs from FromStr
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Active" => Some(ProposalStatus::Active),
            "Approved" => Some(ProposalStatus::Approved),
            "Rejected" => Some(ProposalStatus::Rejected),
            "MissingVotes" => Some(ProposalStatus::MissingVotes),
            "Retry" => Some(ProposalStatus::Retry),
            "Dissolved" => Some(ProposalStatus::Dissolved),
            _ => None,
        }
    }
}

/// Type of Console action (White Paper §7.6, §7.7, §7.7A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalType {
    /// Digit migration: De-Digit or Re-Digit (§7.7).
    DigitMigration,
    /// Self-dismissal vote (§7.7A). Any member can initiate. Dissolves Console if unanimous.
    SelfDismissal,
    /// Core update recommendation. A coordination signal advising all validators
    /// to upgrade to a new Core ELF. This is NOT enforceable — each validator
    /// independently decides whether to adopt the new ELF.
    ///
    /// CRITICAL WARNING: Different Core ELFs have different core_id (BLAKE3 of the binary).
    /// Validators running different Core versions CANNOT interoperate — they produce
    /// different commitments, different state hashes, different proofs.
    /// Adopting a new Core ELF creates a SPLIT WORLDLINE:
    ///   - Validators on the old ELF form one worldline
    ///   - Validators on the new ELF form another
    ///   - Reality Attestation (C1) resolves which is canonical
    ///
    /// The Console recommends; validators decide; the protocol resolves.
    CoreUpdateRecommendation,
}

impl ProposalType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProposalType::DigitMigration => "DigitMigration",
            ProposalType::SelfDismissal => "SelfDismissal",
            ProposalType::CoreUpdateRecommendation => "CoreUpdate",
        }
    }
    #[allow(clippy::should_implement_trait)] // Returns Option, not Result — intentionally differs from FromStr
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "DigitMigration" => Some(ProposalType::DigitMigration),
            "SelfDismissal" => Some(ProposalType::SelfDismissal),
            "CoreUpdate" | "CoreUpdateRecommendation" => Some(ProposalType::CoreUpdateRecommendation),
            _ => None,
        }
    }
}

/// A Console proposal (digit migration, self-dismissal, or Core update recommendation).
#[derive(Debug, Clone)]
pub struct ConsoleProposal {
    pub proposal_id: String,
    pub proposal_type: ProposalType,
    pub proposer_validator_id: String,
    /// Only for DigitMigration.
    pub direction: DigitDirection,
    /// Only for DigitMigration (±2 max).
    pub magnitude: u8,
    pub proposed_at: u64,
    pub expires_at: u64,
    pub status: ProposalStatus,
    /// How many times this proposal has been retried after missing votes (max 1).
    pub retry_count: u8,
    /// Number of ACK votes received.
    pub ack_count: u16,
    /// Number of NO votes received.
    pub no_count: u16,
}

/// Election state — tracks the current election lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElectionPhase {
    /// No election in progress — Console is active.
    Idle,
    /// Nomination window open — collecting self-nominations via group wallet TXs.
    Nominating,
    /// Selectors chosen — waiting for picks.
    AwaitingPicks,
    /// Election resolved — pending CL11 Core signing.
    PendingCoreSign,
    /// Console permanently dissolved — awaiting reformation via new nominations.
    /// Three-election dissolution — see docs/CONSOLE_GOVERNANCE_CONSTRAINTS.md
    /// Dissolution is the recovery mechanism. After dissolution, reformation
    /// begins automatically via the nomination process.
    Dissolved,
    /// Reformation in progress — first nomination received after dissolution.
    /// Fresh Console will start at generation=1 with no dissolved history.
    Reforming,
}

/// Full Console status.
#[derive(Debug)]
pub struct ConsoleStatus {
    pub generation: u32,
    pub cohort: Vec<String>,
    pub active_proposals: Vec<ConsoleProposal>,
    pub digit_version: u8,
    pub election_phase: ElectionPhase,
    pub failed_attempts: u8,
    pub term_end_tick: u64,
}

// ── Engine ─────────────────────────────────────────────────────────────────────

/// Console governance engine.
///
/// Manages the Console group wallet, election lifecycle, and digit migration.
/// All operations pass through the Console group wallet as 1-atom TXs.
pub struct ConsoleEngine {
    db: Arc<ManagementDb>,
}

impl ConsoleEngine {
    pub fn new(db: Arc<ManagementDb>) -> Self {
        Self { db }
    }

    /// Ensure Console schema tables exist. Called once at startup. Idempotent.
    pub fn ensure_schema(&self) -> Result<(), LambdaError> {
        let conn = self.db.db()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS console_chain (
                generation       INTEGER PRIMARY KEY,
                seats            BLOB NOT NULL,
                term_start_tick  INTEGER NOT NULL,
                term_end_tick    INTEGER NOT NULL,
                prev_link_hash   BLOB NOT NULL,
                election_attempt INTEGER NOT NULL DEFAULT 0,
                group_wallet_id  TEXT NOT NULL,
                core_signature   BLOB NOT NULL DEFAULT X'',
                chain_hash       BLOB NOT NULL DEFAULT X''
            );

            CREATE TABLE IF NOT EXISTS console_election (
                id               INTEGER PRIMARY KEY CHECK (id = 1),
                phase            TEXT NOT NULL DEFAULT 'Idle',
                failed_attempts  INTEGER NOT NULL DEFAULT 0,
                current_gen      INTEGER NOT NULL DEFAULT 0,
                nomination_deadline INTEGER NOT NULL DEFAULT 0
            );

            INSERT OR IGNORE INTO console_election (id, phase, failed_attempts, current_gen, nomination_deadline)
                VALUES (1, 'Idle', 0, 0, 0);

            CREATE TABLE IF NOT EXISTS console_proposals (
                proposal_id    TEXT PRIMARY KEY,
                proposal_type  TEXT NOT NULL DEFAULT 'DigitMigration',
                proposer_id    TEXT NOT NULL,
                direction      TEXT NOT NULL DEFAULT '',
                magnitude      INTEGER NOT NULL DEFAULT 0,
                proposed_at    INTEGER NOT NULL,
                expires_at     INTEGER NOT NULL,
                status         TEXT NOT NULL DEFAULT 'Active',
                retry_count    INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS console_votes (
                proposal_id  TEXT NOT NULL,
                validator_id TEXT NOT NULL,
                vote         TEXT NOT NULL,
                voted_at     INTEGER NOT NULL,
                PRIMARY KEY (proposal_id, validator_id)
            );

            CREATE TABLE IF NOT EXISTS console_liveness (
                check_id        INTEGER PRIMARY KEY AUTOINCREMENT,
                initiated_at    INTEGER NOT NULL,
                deadline        INTEGER NOT NULL,
                status          TEXT NOT NULL DEFAULT 'Pending'
            );

            CREATE TABLE IF NOT EXISTS console_heartbeats (
                check_id        INTEGER NOT NULL,
                validator_id    TEXT NOT NULL,
                responded_at    INTEGER NOT NULL,
                PRIMARY KEY (check_id, validator_id)
            );
            ",
        )
        .map_err(|e| LambdaError::StorageError(format!("Console schema: {}", e)))?;
        debug!("Console schema ensured");
        Ok(())
    }

    // ── Election lifecycle ────────────────────────────────────────────────

    /// Get the current election phase and failed attempt count.
    pub fn election_state(&self) -> Result<(ElectionPhase, u8, u32), LambdaError> {
        let conn = self.db.db()?;
        let (phase_str, attempts, gen): (String, i64, i64) = conn
            .query_row(
                "SELECT phase, failed_attempts, current_gen FROM console_election WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        let phase = match phase_str.as_str() {
            "Idle" => ElectionPhase::Idle,
            "Nominating" => ElectionPhase::Nominating,
            "AwaitingPicks" => ElectionPhase::AwaitingPicks,
            "PendingCoreSign" => ElectionPhase::PendingCoreSign,
            "Dissolved" => ElectionPhase::Dissolved,
            "Reforming" => ElectionPhase::Reforming,
            _ => ElectionPhase::Idle,
        };

        Ok((phase, attempts as u8, gen as u32))
    }

    /// Check if an election should be triggered based on current tick.
    /// Returns true if term has expired and we're in Idle phase.
    pub fn should_trigger_election(&self, current_tick: u64) -> Result<bool, LambdaError> {
        let (phase, attempts, gen) = self.election_state()?;

        // Dissolved — reformation allowed via start_nomination.
        // Liveness threshold: full seat participation required.
        // This is intentional — Console health checks are infrequent (monthly)
        // and a Console that cannot muster full participation signals a governance
        // problem that should surface. Repeated liveness failures increment the
        // election failure counter toward dissolution, which is the correct
        // recovery path. See docs/CONSOLE_GOVERNANCE_CONSTRAINTS.md
        if phase == ElectionPhase::Dissolved || phase == ElectionPhase::Reforming {
            return Ok(true); // Allow reformation
        }

        // Already in an election
        if phase != ElectionPhase::Idle {
            return Ok(false);
        }

        // Check if current Console term has expired
        let conn = self.db.db()?;
        let term_end: Option<i64> = conn
            .query_row(
                "SELECT term_end_tick FROM console_chain WHERE generation = ?1",
                rusqlite::params![gen as i64],
                |row| row.get(0),
            )
            .ok();

        match term_end {
            Some(end) if current_tick >= end as u64 => Ok(true),
            _ => {
                // Also trigger if no Console exists yet and we have 15+ validators
                if gen == 0 {
                    // Check if genesis cert exists
                    let count: i64 = conn
                        .query_row("SELECT COUNT(*) FROM console_chain", [], |row| row.get(0))
                        .unwrap_or(0);
                    // If no chain yet, need to bootstrap at genesis
                    Ok(count == 0 && attempts < CONSOLE_MAX_ELECTION_ATTEMPTS)
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Start the nomination phase for a new election.
    /// Sends CL10 Fan-Out to announce election.
    pub fn start_nomination(&self, current_tick: u64) -> Result<(), LambdaError> {
        let (phase, mut attempts, gen) = self.election_state()?;

        // Three-election dissolution — see docs/CONSOLE_GOVERNANCE_CONSTRAINTS.md
        // After dissolution, reformation begins automatically via the nomination process.
        if phase == ElectionPhase::Dissolved {
            info!("Console reformation: first nomination after dissolution. Resetting to generation=1.");
            let conn = self.db.db()?;
            conn.execute(
                "UPDATE console_election SET phase = 'Reforming', failed_attempts = 0, current_gen = 1",
                [],
            ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
            attempts = 0; // Reset local copy — DB was just reset to 0
        }

        if attempts >= CONSOLE_MAX_ELECTION_ATTEMPTS {
            // Console dies by silence. No more Fan-Out. No more elections.
            self.dissolve()?;
            error!(
                "Console PERMANENTLY DISSOLVED after {} failed election attempts. \
                 Only a new Core ELF can reinstate Console.",
                attempts
            );
            return Err(LambdaError::InvalidRequest(
                "Console dissolved after max failed attempts".to_string()
            ));
        }

        let deadline = current_tick + CONSOLE_ELECTION_WINDOW_TICKS;

        let conn = self.db.db()?;
        conn.execute(
            "UPDATE console_election SET phase = 'Nominating', nomination_deadline = ?1 WHERE id = 1",
            rusqlite::params![deadline as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        info!(
            "Console election started: generation {} → {}, attempt {}/{}, deadline tick {}",
            gen, gen + 1, attempts + 1, CONSOLE_MAX_ELECTION_ATTEMPTS, deadline
        );

        Ok(())
    }

    /// Record a failed election attempt.
    /// If this was the last attempt, Console is permanently dissolved.
    pub fn record_election_failure(&self) -> Result<(), LambdaError> {
        let (_, attempts, _) = self.election_state()?;
        let new_attempts = attempts + 1;

        let conn = self.db.db()?;
        if new_attempts >= CONSOLE_MAX_ELECTION_ATTEMPTS {
            // ONE-WAY TICKET: Console permanently dissolved.
            conn.execute(
                "UPDATE console_election SET phase = 'Dissolved', failed_attempts = ?1 WHERE id = 1",
                rusqlite::params![new_attempts as i64],
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

            error!(
                "Console PERMANENTLY DISSOLVED after {} failed election attempts. \
                 No restart mechanism exists in this Core version. \
                 Only a new Core ELF (new worldline) can reinstate Console.",
                new_attempts
            );
        } else {
            conn.execute(
                "UPDATE console_election SET phase = 'Idle', failed_attempts = ?1 WHERE id = 1",
                rusqlite::params![new_attempts as i64],
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

            warn!(
                "Console election failed (attempt {}/{}). \
                 Retry after {} ticks (~1 month). \
                 If all {} attempts fail, Console is PERMANENTLY dissolved.",
                new_attempts, CONSOLE_MAX_ELECTION_ATTEMPTS,
                CONSOLE_ELECTION_RETRY_TICKS, CONSOLE_MAX_ELECTION_ATTEMPTS
            );
        }

        Ok(())
    }

    /// Store a new Console Certificate after CL11 Core signing.
    pub fn store_certificate(&self, cert: &ConsoleCertificate, chain_hash: &[u8; 32]) -> Result<(), LambdaError> {
        let seats_blob: Vec<u8> = cert.seats.iter().flat_map(|s| s.iter()).copied().collect();

        let conn = self.db.db()?;
        conn.execute(
            "INSERT OR REPLACE INTO console_chain \
             (generation, seats, term_start_tick, term_end_tick, prev_link_hash, \
              election_attempt, group_wallet_id, core_signature, chain_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                cert.generation as i64,
                seats_blob,
                cert.term_start_tick as i64,
                cert.term_end_tick as i64,
                cert.previous_link_hash.to_vec(),
                cert.election_attempt as i64,
                cert.group_wallet_id,
                cert.core_signature,
                chain_hash.to_vec(),
            ],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // Update election state: reset to Idle, reset attempts, advance generation
        conn.execute(
            "UPDATE console_election SET phase = 'Idle', failed_attempts = 0, current_gen = ?1 WHERE id = 1",
            rusqlite::params![cert.generation as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        info!(
            "Console generation {} stored. Term: tick {} → {}. Wallet: {}",
            cert.generation, cert.term_start_tick, cert.term_end_tick, cert.group_wallet_id
        );

        Ok(())
    }

    /// Mark Console as permanently dissolved.
    /// Mark Console as permanently dissolved.
    /// Remaining AXC in the Console group wallet returns to oracle reserve pool
    /// (same pattern as JFP unused funds — no locked/lost money).
    fn dissolve(&self) -> Result<(), LambdaError> {
        let conn = self.db.db()?;
        conn.execute(
            "UPDATE console_election SET phase = 'Dissolved' WHERE id = 1",
            [],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // NOTE: The actual return-to-pool TX is triggered by Lambda's main loop
        // when it detects Dissolved state — sends remaining Console wallet balance
        // back to the oracle reserve pool address as a regular TX.
        // This follows the same pattern as JFP group wallet cleanup.

        Ok(())
    }

    // ── Cohort queries ────────────────────────────────────────────────────

    /// Get the current Console cohort (validator IDs from latest certificate).
    pub fn get_cohort(&self) -> Result<Vec<[u8; 32]>, LambdaError> {
        let (_, _, gen) = self.election_state()?;
        self.get_cohort_for_gen(gen)
    }

    fn get_cohort_for_gen(&self, generation: u32) -> Result<Vec<[u8; 32]>, LambdaError> {
        let conn = self.db.db()?;
        let seats_blob: Vec<u8> = conn
            .query_row(
                "SELECT seats FROM console_chain WHERE generation = ?1",
                rusqlite::params![generation as i64],
                |row| row.get(0),
            )
            .map_err(|e| LambdaError::StorageError(format!("Console gen {} not found: {}", generation, e)))?;

        if !seats_blob.len().is_multiple_of(32) {
            return Err(LambdaError::StorageError("Invalid seats blob length".to_string()));
        }

        let seats: Vec<[u8; 32]> = seats_blob
            .chunks_exact(32)
            .map(|chunk| {
                let mut id = [0u8; 32];
                id.copy_from_slice(chunk);
                id
            })
            .collect();

        Ok(seats)
    }

    /// Check if a validator is in the current Console.
    pub fn is_member(&self, validator_id: &[u8; 32]) -> Result<bool, LambdaError> {
        let cohort = self.get_cohort()?;
        Ok(cohort.contains(validator_id))
    }

    /// Get the Console group wallet address for the current generation.
    pub fn group_wallet_id(&self) -> Result<String, LambdaError> {
        let (_, _, gen) = self.election_state()?;
        Ok(format!("{}{}", CONSOLE_WALLET_PREFIX, gen))
    }

    // ── Proposal management (White Paper §7.6-§7.8) ────────────────────

    /// Submit a digit migration proposal (White Paper §7.7).
    /// Only Console members. Max 2/year. 3-month cooldown. ±2 digits max.
    pub fn submit_proposal(
        &self,
        proposer_id: &str,
        direction: DigitDirection,
        magnitude: u8,
        current_tick: u64,
    ) -> Result<ConsoleProposal, LambdaError> {
        self.submit_proposal_inner(
            ProposalType::DigitMigration, proposer_id,
            direction, magnitude, current_tick,
        )
    }

    /// Submit a self-dismissal vote (White Paper §7.7A).
    /// Any Console member can initiate. Unanimous → Console dissolved + new election.
    /// Max 1 self-dismissal per member per term.
    pub fn submit_self_dismissal(
        &self,
        proposer_id: &str,
        current_tick: u64,
    ) -> Result<ConsoleProposal, LambdaError> {
        self.submit_proposal_inner(
            ProposalType::SelfDismissal, proposer_id,
            DigitDirection::Dedigitize, 0, current_tick, // direction/magnitude unused
        )
    }

    /// Submit a Core update recommendation (coordination signal).
    ///
    /// CRITICAL: This is a RECOMMENDATION, not a command. Each validator independently
    /// decides whether to adopt the new Core ELF. Validators running different Core
    /// versions will split into separate worldlines — they cannot interoperate because
    /// core_id (BLAKE3 of the ELF binary) changes, producing different commitments,
    /// state hashes, and proofs.
    ///
    /// The Console recommends. Validators decide. Reality Attestation (C1) resolves.
    pub fn submit_core_update(
        &self,
        proposer_id: &str,
        current_tick: u64,
    ) -> Result<ConsoleProposal, LambdaError> {
        self.submit_proposal_inner(
            ProposalType::CoreUpdateRecommendation, proposer_id,
            DigitDirection::Dedigitize, 0, current_tick, // direction/magnitude unused
        )
    }

    fn submit_proposal_inner(
        &self,
        proposal_type: ProposalType,
        proposer_id: &str,
        direction: DigitDirection,
        magnitude: u8,
        current_tick: u64,
    ) -> Result<ConsoleProposal, LambdaError> {
        // AUDIT-FIX v2.11.14 (Phase 7, Finding 1): Verify proposer is current cohort member.
        // validator_id must be valid 64-char hex (32 bytes). Non-hex or wrong length = reject.
        let proposer_bytes = hex::decode(proposer_id).map_err(|_|
            LambdaError::InvalidRequest(format!("Invalid proposer_id hex: {}", proposer_id)))?;
        if proposer_bytes.len() != 32 {
            return Err(LambdaError::InvalidRequest(format!(
                "proposer_id must be 32 bytes (64 hex chars), got {}", proposer_bytes.len()
            )));
        }
        let mut proposer_id_arr = [0u8; 32];
        proposer_id_arr.copy_from_slice(&proposer_bytes);
        match self.get_cohort() {
            Ok(cohort) if !cohort.contains(&proposer_id_arr) => {
                return Err(LambdaError::InvalidRequest(format!(
                    "Proposer {} is not a current Console member", proposer_id
                )));
            }
            Err(_) => {
                // No cohort yet (Console inert) — allow bootstrap proposals
            }
            _ => {} // Member confirmed
        }

        if proposal_type == ProposalType::DigitMigration {
            if magnitude == 0 || magnitude > CONSOLE_MAX_MAGNITUDE {
                return Err(LambdaError::InvalidRequest(format!(
                    "Magnitude must be 1..={}, got {}", CONSOLE_MAX_MAGNITUDE, magnitude
                )));
            }

            // Cooldown check (3 months between digit migration proposals)
            let conn = self.db.db()?;
            let last_proposed: Option<i64> = conn
                .query_row(
                    "SELECT MAX(proposed_at) FROM console_proposals WHERE proposal_type = 'DigitMigration' AND status NOT IN ('MissingVotes','Dissolved')",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| LambdaError::StorageError(e.to_string()))?;

            if let Some(last) = last_proposed {
                let elapsed = current_tick.saturating_sub(last as u64);
                if elapsed < CONSOLE_COOLDOWN_TICKS {
                    return Err(LambdaError::InvalidRequest(format!(
                        "Cooldown: {} ticks since last proposal, need {}", elapsed, CONSOLE_COOLDOWN_TICKS
                    )));
                }
            }

            // Max 2 digit migration proposals per year
            let year_start = current_tick.saturating_sub(CONSOLE_TICKS_PER_YEAR);
            let year_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM console_proposals WHERE proposal_type = 'DigitMigration' AND proposed_at >= ?1",
                    rusqlite::params![year_start as i64],
                    |row| row.get(0),
                )
                .map_err(|e| LambdaError::StorageError(e.to_string()))?;

            if year_count as usize >= CONSOLE_MAX_PROPOSALS_PER_YEAR {
                return Err(LambdaError::InvalidRequest(format!(
                    "Max {} digit migration proposals per year exceeded", CONSOLE_MAX_PROPOSALS_PER_YEAR
                )));
            }
        }

        let proposal_id = format!(
            "CSL-{}-{}",
            current_tick,
            &blake3::hash(format!("{}{}{}", proposer_id, proposal_type.as_str(), current_tick).as_bytes())
                .to_hex()[..8]
        );
        let expires_at = current_tick + CONSOLE_VOTING_WINDOW_TICKS; // 24 hours

        let conn = self.db.db()?;
        conn.execute(
            "INSERT INTO console_proposals (proposal_id, proposal_type, proposer_id, direction, magnitude, proposed_at, expires_at, status, retry_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'Active', 0)",
            rusqlite::params![
                proposal_id,
                proposal_type.as_str(),
                proposer_id,
                if proposal_type == ProposalType::DigitMigration { direction.as_str() } else { "" },
                magnitude as i64,
                current_tick as i64,
                expires_at as i64,
            ],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        // Proposer auto-votes ACK (White Paper §7.7A: "initiating member automatically records a YES")
        conn.execute(
            "INSERT OR IGNORE INTO console_votes (proposal_id, validator_id, vote, voted_at)
             VALUES (?1, ?2, 'ACK', ?3)",
            rusqlite::params![proposal_id, proposer_id, current_tick as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        info!("Console {} submitted: {} by {}", proposal_type.as_str(), proposal_id, proposer_id);

        Ok(ConsoleProposal {
            proposal_id,
            proposal_type,
            proposer_validator_id: proposer_id.to_string(),
            direction,
            magnitude,
            proposed_at: current_tick,
            expires_at,
            status: ProposalStatus::Active,
            retry_count: 0,
            ack_count: 1, // proposer auto-ACK
            no_count: 0,
        })
    }

    /// Cast a vote on an active proposal. vote = "ACK" or "NO".
    /// White Paper §7.8: Unanimous ACK required. Any NO → rejected.
    pub fn cast_vote(
        &self,
        proposal_id: &str,
        validator_id: &str,
        vote: &str,
        current_tick: u64,
    ) -> Result<(), LambdaError> {
        if vote != "ACK" && vote != "NO" {
            return Err(LambdaError::InvalidRequest(
                "Vote must be 'ACK' or 'NO'".to_string()
            ));
        }

        // AUDIT-FIX v2.11.14 (Phase 7, Finding 1): Verify voter is current cohort member.
        // validator_id must be valid 64-char hex (32 bytes). Non-hex or wrong length = reject.
        let voter_bytes = hex::decode(validator_id).map_err(|_|
            LambdaError::InvalidRequest(format!("Invalid voter_id hex: {}", validator_id)))?;
        if voter_bytes.len() != 32 {
            return Err(LambdaError::InvalidRequest(format!(
                "voter_id must be 32 bytes (64 hex chars), got {}", voter_bytes.len()
            )));
        }
        let mut voter_id_arr = [0u8; 32];
        voter_id_arr.copy_from_slice(&voter_bytes);
        match self.get_cohort() {
            Ok(cohort) if !cohort.contains(&voter_id_arr) => {
                return Err(LambdaError::InvalidRequest(format!(
                    "Voter {} is not a current Console member", validator_id
                )));
            }
            Err(_) => {} // No cohort (inert) — allow
            _ => {} // Member confirmed
        }

        let conn = self.db.db()?;
        let status: String = conn
            .query_row(
                "SELECT status FROM console_proposals WHERE proposal_id = ?1",
                rusqlite::params![proposal_id],
                |row| row.get(0),
            )
            .map_err(|e| LambdaError::StorageError(format!("Proposal not found: {}", e)))?;

        if status != "Active" && status != "Retry" {
            return Err(LambdaError::InvalidRequest(format!(
                "Proposal {} is not Active/Retry (status={})", proposal_id, status
            )));
        }

        conn.execute(
            "INSERT OR REPLACE INTO console_votes (proposal_id, validator_id, vote, voted_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![proposal_id, validator_id, vote, current_tick as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        info!("Console vote: {} voted {} on {}", validator_id, vote, proposal_id);
        Ok(())
    }

    /// Get vote counts for a proposal.
    fn vote_counts(&self, proposal_id: &str) -> Result<(i64, i64, i64), LambdaError> {
        let conn = self.db.db()?;
        let acks: i64 = conn.query_row(
            "SELECT COUNT(*) FROM console_votes WHERE proposal_id = ?1 AND vote = 'ACK'",
            rusqlite::params![proposal_id], |row| row.get(0),
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        let nos: i64 = conn.query_row(
            "SELECT COUNT(*) FROM console_votes WHERE proposal_id = ?1 AND vote = 'NO'",
            rusqlite::params![proposal_id], |row| row.get(0),
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM console_votes WHERE proposal_id = ?1",
            rusqlite::params![proposal_id], |row| row.get(0),
        ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
        Ok((acks, nos, total))
    }

    /// Finalize all proposals whose 24h deliberation window has expired.
    ///
    /// White Paper §7.8 resolution:
    /// 1. Unanimous ACK (15/15) → action executes
    /// 2. Any NO → action fails, Console continues
    /// 3. Missing votes (1st) → automatic retry with same 24h window
    /// 4. Missing votes (2nd) → entire Console dissolved
    pub fn finalize_expired(&self, current_tick: u64) -> Result<usize, LambdaError> {
        let conn = self.db.db()?;
        let mut stmt = conn
            .prepare(
                "SELECT proposal_id, proposal_type, direction, magnitude, retry_count
                 FROM console_proposals WHERE status IN ('Active','Retry') AND expires_at <= ?1",
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        let expired: Vec<(String, String, String, i64, i64)> = stmt
            .query_map(rusqlite::params![current_tick as i64], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
            })
            .map_err(|e| LambdaError::StorageError(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);
        drop(conn);

        let cohort_size = self.get_cohort().map(|c| c.len()).unwrap_or(0) as i64;
        let mut finalized = 0;

        for (proposal_id, type_str, direction_str, magnitude, retry_count) in &expired {
            let (acks, nos, total) = self.vote_counts(proposal_id)?;

            if nos > 0 {
                // Any NO → Rejected. Console continues. (§7.8 case 2)
                let conn = self.db.db()?;
                conn.execute(
                    "UPDATE console_proposals SET status = 'Rejected' WHERE proposal_id = ?1",
                    rusqlite::params![proposal_id],
                ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
                warn!("Console proposal {} REJECTED ({} NO votes)", proposal_id, nos);

            } else if acks >= cohort_size && cohort_size > 0 {
                // Unanimous ACK → Execute action. (§7.8 case 1)
                let ptype = ProposalType::from_str(type_str).unwrap_or(ProposalType::DigitMigration);

                match ptype {
                    ProposalType::DigitMigration => {
                        let direction = DigitDirection::from_str(direction_str)
                            .ok_or_else(|| LambdaError::StorageError(format!("bad direction: {}", direction_str)))?;
                        let mag = *magnitude as u8;
                        let current_dv = self.db.get_digit_version()?;
                        let new_dv = match direction {
                            DigitDirection::Dedigitize => current_dv.saturating_add(mag),
                            DigitDirection::Redigitize => current_dv.saturating_sub(mag),
                        };
                        self.db.set_digit_version(new_dv)?;
                        info!("Console DIGIT MIGRATION APPROVED — digit_version {} → {}", current_dv, new_dv);
                    }
                    ProposalType::SelfDismissal => {
                        // Dissolve cohort and trigger new election
                        info!("Console SELF-DISMISSAL APPROVED — cohort dissolved, new election triggered");
                        // Note: actual dissolution/re-election handled by Lambda main loop
                    }
                    ProposalType::CoreUpdateRecommendation => {
                        // COORDINATION SIGNAL ONLY — no automatic action.
                        // Each validator independently decides whether to adopt the new Core ELF.
                        // Different Core versions = different core_id = SPLIT WORLDLINE.
                        // Validators on old ELF and new ELF cannot interoperate.
                        // Reality Attestation (C1) resolves which worldline is canonical.
                        warn!(
                            "Console CORE UPDATE RECOMMENDATION APPROVED — \
                             This is a coordination signal. Each validator must independently \
                             decide whether to adopt the new Core ELF. \
                             WARNING: Different Core = different core_id = SPLIT WORLDLINE. \
                             Validators on different Core versions cannot interoperate."
                        );
                    }
                }

                let conn = self.db.db()?;
                conn.execute(
                    "UPDATE console_proposals SET status = 'Approved' WHERE proposal_id = ?1",
                    rusqlite::params![proposal_id],
                ).map_err(|e| LambdaError::StorageError(e.to_string()))?;

            } else {
                // Missing votes — some members didn't vote within 24h
                if *retry_count == 0 {
                    // First miss → automatic retry (§7.8 case 3)
                    let new_expires = current_tick + CONSOLE_VOTING_WINDOW_TICKS;
                    let conn = self.db.db()?;
                    conn.execute(
                        "UPDATE console_proposals SET status = 'Retry', retry_count = 1, expires_at = ?1 WHERE proposal_id = ?2",
                        rusqlite::params![new_expires as i64, proposal_id],
                    ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
                    // Clear votes for retry — fresh 24h window
                    conn.execute(
                        "DELETE FROM console_votes WHERE proposal_id = ?1",
                        rusqlite::params![proposal_id],
                    ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
                    warn!("Console proposal {} — missing votes ({}/{}). Automatic retry (24h). \
                           Second miss = Console DISSOLVED.",
                        proposal_id, total, cohort_size);
                } else {
                    // Second miss → Console dissolved (§7.8 case 4)
                    let conn = self.db.db()?;
                    conn.execute(
                        "UPDATE console_proposals SET status = 'Dissolved' WHERE proposal_id = ?1",
                        rusqlite::params![proposal_id],
                    ).map_err(|e| LambdaError::StorageError(e.to_string()))?;
                    error!("Console proposal {} — second missing-votes failure. \
                            ENTIRE CONSOLE COHORT DISSOLVED. New election triggered.",
                        proposal_id);
                    // Lambda main loop detects Dissolved status and triggers re-election
                }
            }
            finalized += 1;
        }

        Ok(finalized)
    }

    // ── Liveness checks (YP §21.12.3) ──────────────────────────────────────

    /// Check if a liveness check should be initiated (every 3 months).
    /// Returns true if no pending check exists and enough time has passed.
    pub fn should_check_liveness(&self, current_tick: u64) -> Result<bool, LambdaError> {
        let (phase, _, _) = self.election_state()?;
        if phase != ElectionPhase::Idle { return Ok(false); }

        let cohort = self.get_cohort()?;
        if cohort.len() < CONSOLE_SIZE { return Ok(false); } // inert

        let conn = self.db.db()?;
        let last_check: Option<i64> = conn
            .query_row(
                "SELECT MAX(initiated_at) FROM console_liveness WHERE status IN ('Pending','Complete')",
                [], |row| row.get(0),
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        match last_check {
            Some(last) => Ok(current_tick.saturating_sub(last as u64) >= CONSOLE_LIVENESS_INTERVAL_TICKS),
            None => Ok(true), // No check ever done
        }
    }

    /// Initiate a liveness check. Broadcasts a heartbeat request via CL10 Fan-Out.
    /// Each Console member must respond within CONSOLE_LIVENESS_RESPONSE_TICKS (72h).
    pub fn initiate_liveness_check(&self, current_tick: u64) -> Result<i64, LambdaError> {
        let deadline = current_tick + CONSOLE_LIVENESS_RESPONSE_TICKS;
        let conn = self.db.db()?;
        conn.execute(
            "INSERT INTO console_liveness (initiated_at, deadline, status) VALUES (?1, ?2, 'Pending')",
            rusqlite::params![current_tick as i64, deadline as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;

        let check_id = conn.last_insert_rowid();
        info!(
            "Console liveness check #{} initiated at tick {}. Deadline: tick {} (72h). \
             ALL 15 members must respond or Console is DISSOLVED.",
            check_id, current_tick, deadline
        );
        Ok(check_id)
    }

    /// Record a heartbeat response from a Console member.
    /// AUDIT-FIX v2.11.14 (Phase 7, Finding 3): Verify responder is current cohort member.
    /// validator_id must be valid 64-char hex (32 bytes). Non-hex or wrong length = reject.
    pub fn record_heartbeat(&self, check_id: i64, validator_id: &str, current_tick: u64) -> Result<(), LambdaError> {
        let responder_bytes = hex::decode(validator_id).map_err(|_|
            LambdaError::InvalidRequest(format!("Invalid heartbeat validator_id hex: {}", validator_id)))?;
        if responder_bytes.len() != 32 {
            return Err(LambdaError::InvalidRequest(format!(
                "heartbeat validator_id must be 32 bytes, got {}", responder_bytes.len()
            )));
        }
        let mut responder_id = [0u8; 32];
        responder_id.copy_from_slice(&responder_bytes);
        if let Ok(cohort) = self.get_cohort() {
            if !cohort.contains(&responder_id) {
                return Err(LambdaError::InvalidRequest(format!(
                    "Heartbeat from {} rejected — not a current Console member", validator_id
                )));
            }
        }
        let conn = self.db.db()?;
        conn.execute(
            "INSERT OR IGNORE INTO console_heartbeats (check_id, validator_id, responded_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![check_id, validator_id, current_tick as i64],
        )
        .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        debug!("Console heartbeat: {} responded to check #{}", validator_id, check_id);
        Ok(())
    }

    /// Check if a pending liveness check has expired.
    /// If all 15 responded → Complete. If deadline passed with missing → DISSOLVE.
    pub fn check_liveness_result(&self, current_tick: u64) -> Result<Option<String>, LambdaError> {
        let conn = self.db.db()?;
        let pending: Option<(i64, i64)> = conn
            .query_row(
                "SELECT check_id, deadline FROM console_liveness WHERE status = 'Pending' ORDER BY check_id DESC LIMIT 1",
                [], |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        let (check_id, deadline) = match pending {
            Some(p) => p,
            None => return Ok(None),
        };

        let responses: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT validator_id) FROM console_heartbeats WHERE check_id = ?1",
                rusqlite::params![check_id], |row| row.get(0),
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
        drop(conn);

        let cohort_size = self.get_cohort()?.len() as i64;

        if responses >= cohort_size && cohort_size >= CONSOLE_SIZE as i64 {
            // All responded — liveness confirmed
            let conn = self.db.db()?;
            conn.execute(
                "UPDATE console_liveness SET status = 'Complete' WHERE check_id = ?1",
                rusqlite::params![check_id],
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;
            info!("Console liveness check #{}: ALL {}/{} members responded. Console healthy.",
                check_id, responses, cohort_size);
            return Ok(Some("Complete".to_string()));
        }

        if current_tick >= deadline as u64 {
            // Deadline passed with missing responses — DISSOLVE
            let conn = self.db.db()?;
            conn.execute(
                "UPDATE console_liveness SET status = 'Failed' WHERE check_id = ?1",
                rusqlite::params![check_id],
            )
            .map_err(|e| LambdaError::StorageError(e.to_string()))?;

            error!(
                "Console liveness check #{} FAILED: only {}/{} members responded within 72h. \
                 ENTIRE CONSOLE DISSOLVED. Silence is not permitted. (YP §21.12.3)",
                check_id, responses, cohort_size
            );
            // Dissolution handled by Lambda main loop detecting Failed status
            return Ok(Some("Failed".to_string()));
        }

        Ok(None) // Still pending
    }

    // ── Status queries ─────────────────────────────────────────────────────

    pub fn active_proposals(&self) -> Result<Vec<ConsoleProposal>, LambdaError> {
        // Collect raw proposal data first, then DROP the connection before calling vote_counts.
        // parking_lot::Mutex is NOT re-entrant — holding conn while calling vote_counts() deadlocks.
        #[allow(clippy::type_complexity)]
        let raw: Vec<(String, String, String, String, i64, i64, i64, String, i64)>;
        {
            let conn = self.db.db()?;
            let mut stmt = conn
                .prepare(
                    "SELECT proposal_id, proposal_type, proposer_id, direction, magnitude, proposed_at, expires_at, status, retry_count
                     FROM console_proposals WHERE status IN ('Active','Retry')",
                )
                .map_err(|e| LambdaError::StorageError(e.to_string()))?;

            raw = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                })
                .map_err(|e| LambdaError::StorageError(e.to_string()))?
                .filter_map(|r| r.ok())
                .collect();
        } // conn + stmt dropped here — safe to call vote_counts now

        let proposals = raw.into_iter()
            .map(|(id, type_str, proposer, dir_str, mag, proposed, expires, status_str, retry)| {
                let (acks, nos, _) = self.vote_counts(&id).unwrap_or((0, 0, 0));
                ConsoleProposal {
                    proposal_id: id,
                    proposal_type: ProposalType::from_str(&type_str).unwrap_or(ProposalType::DigitMigration),
                    proposer_validator_id: proposer,
                    direction: DigitDirection::from_str(&dir_str).unwrap_or(DigitDirection::Dedigitize),
                    magnitude: mag as u8,
                    proposed_at: proposed as u64,
                    expires_at: expires as u64,
                    status: ProposalStatus::from_str(&status_str).unwrap_or(ProposalStatus::Active),
                    retry_count: retry as u8,
                    ack_count: acks as u16,
                    no_count: nos as u16,
                }
            })
            .collect();

        Ok(proposals)
    }

    pub fn status(&self) -> Result<ConsoleStatus, LambdaError> {
        let (phase, attempts, gen) = self.election_state()?;
        let cohort = self.get_cohort().unwrap_or_default();
        let active_proposals = self.active_proposals()?;
        let digit_version = self.db.get_digit_version()?;

        let conn = self.db.db()?;
        let term_end: u64 = conn
            .query_row(
                "SELECT term_end_tick FROM console_chain WHERE generation = ?1",
                rusqlite::params![gen as i64],
                |row| row.get::<_, i64>(0).map(|v| v as u64),
            )
            .unwrap_or(0);

        let cohort_hex: Vec<String> = cohort.iter().map(hex::encode).collect();

        Ok(ConsoleStatus {
            generation: gen,
            cohort: cohort_hex,
            active_proposals,
            digit_version,
            election_phase: phase,
            failed_attempts: attempts,
            term_end_tick: term_end,
        })
    }

    pub fn status_json(&self) -> String {
        match self.status() {
            Ok(s) => {
                let members_json: Vec<String> = s.cohort.iter()
                    .map(|m| format!(r#""{}""#, m))
                    .collect();
                let proposals_json: Vec<String> = s.active_proposals.iter()
                    .map(|p| format!(
                        r#"{{"id":"{}","type":"{}","proposer":"{}","direction":"{}","magnitude":{},"proposed_at":{},"expires_at":{},"status":"{}","retry":{},"acks":{},"nos":{}}}"#,
                        p.proposal_id, p.proposal_type.as_str(), p.proposer_validator_id,
                        p.direction.as_str(), p.magnitude, p.proposed_at, p.expires_at,
                        p.status.as_str(), p.retry_count, p.ack_count, p.no_count,
                    ))
                    .collect();
                let phase_str = match s.election_phase {
                    ElectionPhase::Idle => "Idle",
                    ElectionPhase::Nominating => "Nominating",
                    ElectionPhase::AwaitingPicks => "AwaitingPicks",
                    ElectionPhase::PendingCoreSign => "PendingCoreSign",
                    ElectionPhase::Dissolved => "Dissolved",
                    ElectionPhase::Reforming => "Reforming",
                };
                format!(
                    r#"{{"generation":{},"cohort":[{}],"cohort_size":{},"active_proposals":[{}],"digit_version":{},"election_phase":"{}","failed_attempts":{},"term_end_tick":{}}}"#,
                    s.generation,
                    members_json.join(","),
                    s.cohort.len(),
                    proposals_json.join(","),
                    s.digit_version,
                    phase_str,
                    s.failed_attempts,
                    s.term_end_tick,
                )
            }
            Err(e) => format!(r#"{{"error":"{}"}}"#, e),
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> ConsoleEngine {
        let db = Arc::new(ManagementDb::open_test().unwrap());
        let engine = ConsoleEngine::new(db);
        engine.ensure_schema().unwrap();
        engine
    }

    /// Convert seat index (0..14) to the hex string ID used in genesis cert.
    /// Matches the pattern in store_genesis_cert: id[0] = i, rest zeros.
    fn member_hex(i: u8) -> String {
        let mut id = [0u8; 32];
        id[0] = i;
        hex::encode(id)
    }

    fn store_genesis_cert(engine: &ConsoleEngine) {
        let seats: Vec<[u8; 32]> = (0..15).map(|i| {
            let mut id = [0u8; 32];
            id[0] = i;
            id
        }).collect();

        let cert = ConsoleCertificate {
            generation: 0,
            seats,
            term_start_tick: 0,
            term_end_tick: CONSOLE_TICKS_PER_YEAR,
            previous_link_hash: [0; 32],
            election_attempt: 0,
            group_wallet_id: "DWP/CONSOLE/0".to_string(),
            core_signature: vec![],
        };

        let hash = axiom_core_logic::console::compute_console_chain_hash(&cert);
        engine.store_certificate(&cert, &hash).unwrap();
    }

    #[test]
    fn test_schema_creation() {
        let _engine = setup();
        // No panic = success
    }

    #[test]
    fn test_election_state_default() {
        let engine = setup();
        let (phase, attempts, gen) = engine.election_state().unwrap();
        assert_eq!(phase, ElectionPhase::Idle);
        assert_eq!(attempts, 0);
        assert_eq!(gen, 0);
    }

    #[test]
    fn test_store_and_retrieve_certificate() {
        let engine = setup();
        store_genesis_cert(&engine);

        let cohort = engine.get_cohort().unwrap();
        assert_eq!(cohort.len(), 15);
        assert_eq!(cohort[0][0], 0);
        assert_eq!(cohort[14][0], 14);

        let (_, _, gen) = engine.election_state().unwrap();
        assert_eq!(gen, 0);
    }

    #[test]
    fn test_is_member() {
        let engine = setup();
        store_genesis_cert(&engine);

        let mut id0 = [0u8; 32];
        id0[0] = 0;
        assert!(engine.is_member(&id0).unwrap());

        let mut id99 = [0u8; 32];
        id99[0] = 99;
        assert!(!engine.is_member(&id99).unwrap());
    }

    #[test]
    fn test_start_nomination() {
        let engine = setup();
        store_genesis_cert(&engine);

        // Term hasn't expired yet at tick 100
        assert!(!engine.should_trigger_election(100).unwrap());

        // Term expired at TICKS_PER_YEAR
        assert!(engine.should_trigger_election(CONSOLE_TICKS_PER_YEAR).unwrap());

        engine.start_nomination(CONSOLE_TICKS_PER_YEAR).unwrap();
        let (phase, _, _) = engine.election_state().unwrap();
        assert_eq!(phase, ElectionPhase::Nominating);
    }

    #[test]
    fn test_election_failure_and_dissolution() {
        let engine = setup();
        store_genesis_cert(&engine);

        // Fail 3 times → dissolved
        engine.record_election_failure().unwrap();
        let (phase, attempts, _) = engine.election_state().unwrap();
        assert_eq!(phase, ElectionPhase::Idle);
        assert_eq!(attempts, 1);

        engine.record_election_failure().unwrap();
        let (phase, attempts, _) = engine.election_state().unwrap();
        assert_eq!(phase, ElectionPhase::Idle);
        assert_eq!(attempts, 2);

        engine.record_election_failure().unwrap();
        let (phase, attempts, _) = engine.election_state().unwrap();
        assert_eq!(phase, ElectionPhase::Dissolved);
        assert_eq!(attempts, 3);

        // After dissolution, nomination ALLOWED (reformation path)
        // See docs/CONSOLE_GOVERNANCE_CONSTRAINTS.md — dissolution is recovery, not terminal.
        let result = engine.start_nomination(CONSOLE_TICKS_PER_YEAR * 2);
        assert!(result.is_ok(), "Nomination must be allowed after dissolution (reformation)");

        // Phase should transition to Reforming
        let (phase, attempts, gen) = engine.election_state().unwrap();
        assert!(phase == ElectionPhase::Reforming || phase == ElectionPhase::Nominating,
            "Phase should be Reforming or Nominating after post-dissolution nomination, got {:?}", phase);
        assert_eq!(attempts, 0, "Failed attempts reset to 0 after dissolution");
        assert_eq!(gen, 1, "Generation reset to 1 after dissolution");
    }

    #[test]
    fn test_proposal_submission() {
        let engine = setup();
        store_genesis_cert(&engine);

        let proposal = engine.submit_proposal(
            &member_hex(0), DigitDirection::Dedigitize, 1, 10_000_000,
        ).unwrap();

        assert_eq!(proposal.direction, DigitDirection::Dedigitize);
        assert_eq!(proposal.magnitude, 1);
        assert_eq!(proposal.status, ProposalStatus::Active);
        assert_eq!(proposal.ack_count, 1, "proposer auto-ACKs");
        assert_eq!(proposal.proposal_type, ProposalType::DigitMigration);
    }

    #[test]
    fn test_no_vote_rejects_proposal() {
        let engine = setup();
        store_genesis_cert(&engine);

        let proposal = engine.submit_proposal(
            &member_hex(0), DigitDirection::Dedigitize, 1, 10_000_000,
        ).unwrap();

        // member 1 votes NO — any NO rejects (White Paper §7.8)
        engine.cast_vote(&proposal.proposal_id, &member_hex(1), "NO", 10_000_100).unwrap();

        let finalized = engine.finalize_expired(proposal.expires_at + 1).unwrap();
        assert_eq!(finalized, 1);

        let dv = engine.db.get_digit_version().unwrap();
        assert_eq!(dv, 0, "digit_version should not change on rejected proposal");
    }

    #[test]
    fn test_unanimous_ack_approves() {
        let engine = setup();
        store_genesis_cert(&engine);

        let proposal = engine.submit_proposal(
            &member_hex(0), DigitDirection::Dedigitize, 2, 10_000_000,
        ).unwrap();

        // All 15 must ACK (proposer auto-ACKed as member 0)
        for i in 1..15u64 {
            engine.cast_vote(&proposal.proposal_id, &member_hex(i as u8), "ACK", 10_000_000 + i).unwrap();
        }

        let finalized = engine.finalize_expired(proposal.expires_at + 1).unwrap();
        assert_eq!(finalized, 1);

        let dv = engine.db.get_digit_version().unwrap();
        assert_eq!(dv, 2, "digit_version should be 2 after unanimous dedigitize");
    }

    #[test]
    fn test_missing_votes_triggers_retry() {
        let engine = setup();
        store_genesis_cert(&engine);

        let proposal = engine.submit_proposal(
            &member_hex(0), DigitDirection::Dedigitize, 1, 10_000_000,
        ).unwrap();

        // Only proposer ACK (1 out of 15) — missing votes
        // Finalize — should trigger retry (first miss)
        let finalized = engine.finalize_expired(proposal.expires_at + 1).unwrap();
        assert_eq!(finalized, 1);

        // Check retry_count directly from DB
        let conn = engine.db.db().unwrap();
        let (status, retry): (String, i64) = conn.query_row(
            "SELECT status, retry_count FROM console_proposals WHERE proposal_id = ?1",
            rusqlite::params![proposal.proposal_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(status, "Retry");
        assert_eq!(retry, 1);
    }

    #[test]
    fn test_self_dismissal() {
        let engine = setup();
        store_genesis_cert(&engine);

        let proposal = engine.submit_self_dismissal(&member_hex(0), 10_000_000).unwrap();
        assert_eq!(proposal.proposal_type, ProposalType::SelfDismissal);
        assert_eq!(proposal.ack_count, 1, "proposer auto-ACKs dismissal");
    }

    #[test]
    fn test_cooldown_enforced() {
        let engine = setup();
        store_genesis_cert(&engine);

        engine.submit_proposal(&member_hex(0), DigitDirection::Dedigitize, 1, 10_000_000).unwrap();

        let result = engine.submit_proposal(&member_hex(1), DigitDirection::Redigitize, 1, 10_001_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cooldown"));
    }

    #[test]
    fn test_group_wallet_id() {
        let engine = setup();
        store_genesis_cert(&engine);

        let wallet = engine.group_wallet_id().unwrap();
        assert_eq!(wallet, "DWP/CONSOLE/0");
    }

    #[test]
    fn test_status_json() {
        let engine = setup();
        store_genesis_cert(&engine);

        let json = engine.status_json();
        assert!(json.contains("\"generation\":0"));
        assert!(json.contains("\"cohort_size\":15"));
        assert!(json.contains("\"election_phase\":\"Idle\""));
        assert!(json.contains("\"failed_attempts\":0"));
    }

    // ── Phase 7 audit-fix regression tests ──────────────────────────────────

    #[test]
    fn test_non_hex_proposer_rejected() {
        let engine = setup();
        store_genesis_cert(&engine);

        let result = engine.submit_proposal(
            "not_hex", DigitDirection::Dedigitize, 1, 10_000_000,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid") || err.contains("hex"),
            "Expected InvalidRequest for non-hex proposer, got: {}", err);
    }

    #[test]
    fn test_short_hex_voter_rejected() {
        let engine = setup();
        store_genesis_cert(&engine);

        // Submit a valid proposal first
        let proposal = engine.submit_proposal(
            &member_hex(0), DigitDirection::Dedigitize, 1, 10_000_000,
        ).unwrap();

        // "abcd" is valid hex but only 2 bytes, not 32
        let result = engine.cast_vote(&proposal.proposal_id, "abcd", "ACK", 10_000_100);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("32 bytes") || err.contains("64 hex"),
            "Expected rejection for short hex voter, got: {}", err);
    }

    #[test]
    fn test_non_member_vote_rejected() {
        let engine = setup();
        store_genesis_cert(&engine);

        let proposal = engine.submit_proposal(
            &member_hex(0), DigitDirection::Dedigitize, 1, 10_000_000,
        ).unwrap();

        // Valid 32-byte hex that is NOT in the cohort (byte 0 = 0xFF, not 0..14)
        let mut non_member = [0u8; 32];
        non_member[0] = 0xFF;
        let non_member_hex = hex::encode(non_member);

        let result = engine.cast_vote(&proposal.proposal_id, &non_member_hex, "ACK", 10_000_100);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not a current Console member"),
            "Expected 'not a current Console member', got: {}", err);
    }

    #[test]
    fn test_non_member_heartbeat_rejected() {
        let engine = setup();
        store_genesis_cert(&engine);

        let check_id = engine.initiate_liveness_check(10_000_000).unwrap();

        // Valid 32-byte hex that is NOT in the cohort
        let mut non_member = [0u8; 32];
        non_member[0] = 0xFF;
        let non_member_hex = hex::encode(non_member);

        let result = engine.record_heartbeat(check_id, &non_member_hex, 10_000_100);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not a current Console member"),
            "Expected 'not a current Console member', got: {}", err);
    }
}
