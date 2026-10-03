//! Core Client — Lambda's interface to Core via AVM interpreter
//!
//! Lambda executes core-logic through the AVM interpreter directly.
//! Single execution path: AVM runs the RISC-V ELF, validates the transaction,
//! and collects DMAP checkpoints — all in one pass.
//!
//! Core (axiom-core.elf): All validation, crypto, balance math, FACT signing.
//! Lambda (this): Builds PublicInputs, runs AVM, wraps output with proof.

use crate::error::LambdaError;
use axiom_core_logic::{PublicInputs, PublicOutputs, CoreLogicMode, ValidationResult, VBCProofBundle};
use axiom_core_logic::types::*;
use axiom_zk_vm::{SubprocessProver, ZkvmReceipt};
use axiom_dmap_vm::{AvmInterpreter, AvmConfig};
use axiom_dmap_vm::dmap::{DmapAttestation, ProofType};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Proof from CL3 witness production.
/// YPX-009 — everything the AVM emits about the audit, captured at the ONE
/// place every execution passes (the `execute_avm*` wrappers), so no Lambda
/// path can drop it. Until 2026-09-08 only the witness/finalize path read
/// `outputs.audit_request`; a request emitted on a CL5 redeem (the smoke's
/// first accepted execution) was discarded, the AVM's `pending_request`
/// stayed set, and `should_trigger` was false forever — the audit never ran.
#[derive(Default)]
pub struct PulseSink {
    pending_request: parking_lot::Mutex<Option<axiom_core_logic::types::PulseAuditRequest>>,
    proofs: parking_lot::Mutex<Vec<axiom_core_logic::types::PulseProofData>>,
    /// Executions REFUSED because Core reported `audit_failed` (YPX-009 §7.2,
    /// RULED 2026-09-10). A counter, not a log line: "0 refusals" and "the
    /// check never ran" must not read the same (RULE 3 shape 2). On `/pulse`.
    audit_failures: std::sync::atomic::AtomicU64,
}

impl PulseSink {
    /// Record what an execution emitted. `label` names the path for the log.
    pub fn absorb(&self, outputs: &PublicOutputs, label: &str) {
        if let Some(req) = outputs.audit_request.as_ref() {
            let mut slot = self.pending_request.lock();
            if slot.is_some() {
                warn!("YPX-009: audit request captured from {label} while one was still unanswered — replacing");
            }
            info!("YPX-009: audit request captured from {label} execution — {} entries, epoch={}",
                  req.state_ids.len(), req.epoch);
            *slot = Some(req.clone());
        }
        if let Some(ppd) = outputs.pulse_proof.as_ref() {
            info!("YPX-009: Pulse proof produced by {label} execution — epoch={} entries={} sample={} argon2id/s={}",
                  ppd.epoch, ppd.entry_count, ppd.sample_size, ppd.argon2id_per_sec);
            self.proofs.lock().push(ppd.clone());
        }
        if outputs.audit_failed {
            self.audit_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            warn!("YPX-009 §7.2: Pulse audit FAILED on {label} execution — Core's chain and Lambda's DB disagree; REFUSING to sign it (E_LAMBDA_PULSE_AUDIT_FAILED)");
        }
    }
    /// Executions refused for a failed self-audit since start.
    pub fn audit_failures(&self) -> u64 {
        self.audit_failures.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn take_request(&self) -> Option<axiom_core_logic::types::PulseAuditRequest> {
        self.pending_request.lock().take()
    }
    pub fn take_proofs(&self) -> Vec<axiom_core_logic::types::PulseProofData> {
        std::mem::take(&mut *self.proofs.lock())
    }
}

/// YPX-009 §7.2 — RULED 2026-09-10 (the owner: "if pulse fail, reject"). Until
/// then `audit_failed` was a `warn!` and nothing else: a validator whose own
/// audit chain disagreed with its DB kept signing. Now the execution that
/// carried the failed audit is REFUSED, at the ONE place every Core execution
/// passes (the `execute_avm*` wrappers), so no path can sign past it. Pure
/// function so the refusal can be driven by a test (RULE 6 §2/§3).
pub(crate) fn refuse_if_audit_failed(outputs: &PublicOutputs, label: &str) -> Result<(), LambdaError> {
    if outputs.audit_failed {
        Err(LambdaError::PulseAuditFailed(label.to_string()))
    } else {
        Ok(())
    }
}

pub struct WitnessProof {
    pub outputs: PublicOutputs,
    pub zkp_receipt: Option<ZkvmReceipt>,
    pub execution_proof_bytes: Vec<u8>,
    /// Proof type: 0=ZKP (STARK), 1=DMAP (memory attestation)
    pub proof_type: u8,
    /// DMAP input hash (independently computed from PublicInputs at proof time)
    pub dmap_input_hash: [u8; 32],
    /// DMAP output hash (independently computed from PublicOutputs at proof time)
    pub dmap_output_hash: [u8; 32],
}

/// Proof from CL5 redeem validation.
pub struct RedeemProof {
    pub new_state_id: [u8; 32],
    pub commitment_hash: [u8; 32],
    pub outputs: PublicOutputs,
}

/// Client-submitted CL1 proof for fast-path validation.
pub struct ClientProof {
    /// CL1 ZKP execution proof bytes (empty = no proof submitted)
    pub execution_proof: Vec<u8>,
}

/// Post-verification checks on ZKP outputs.
///
/// After the STARK proof is cryptographically verified, check:
/// - Layer 2: `outputs.result == Accept` (valid proof of Reject is still a failure)
/// - Layer 3: ZKP nonce binding matches expected (anti-replay)
// Takes ZkpCheckpointOutputs, not PublicOutputs (2026-09-02): the zkVM guest
// commits a checkpoint, and the three fields this reads — result,
// rejection_reason, zkp_nonce_hash — are all on it. The previous PublicOutputs
// signature matched a journal type no guest produces.
fn check_proof_outputs(
    outputs: &axiom_core_logic::ZkpCheckpointOutputs,
    expected_zkp_nonce: Option<&[u8; 32]>,
) -> Result<(), LambdaError> {
    // Layer 2: Logic result check — a valid proof of Reject is still a failure
    match outputs.result {
        ValidationResult::Accept => {}
        _ => {
            return Err(LambdaError::CoreValidationFailed(
                format!("CL1 ZKP: proof valid but logic rejected: {:?}", outputs.rejection_reason)
            ));
        }
    }

    // Layer 3: ZKP nonce anti-replay binding
    if let Some(expected_nonce) = expected_zkp_nonce {
        let expected_hash = {
            axiom_core_logic::compute::zkp_nonce_hash(expected_nonce)
        };
        match outputs.zkp_nonce_hash {
            Some(h) if h == expected_hash => {}
            _ => {
                return Err(LambdaError::CoreValidationFailed(
                    "CL1 ZKP: nonce binding mismatch — possible replay".into()
                ));
            }
        }
    }

    Ok(())
}

/// Core Client for Lambda — executes core-logic via AVM interpreter.
///
/// Single execution path: the AVM interpreter runs axiom-core.elf (RISC-V),
/// producing both validation outputs AND DMAP checkpoints in one pass.
/// No subprocess, no IPC — direct in-process execution.
///
/// The AVM interpreter is **persistent** across TX executions. This is required
/// for YPX-009 Silicon Pulse: the audit buffer, wallet cache, and ignition state
/// must survive across transactions. Lambda holds `Arc<AvmInterpreter>` — it can
/// call execute() but cannot access internal audit state.
///
/// ZKP mode still available via SubprocessProver for high-performance validators.
pub struct CoreClient {
    /// AVM config (ELF bytes + core_id)
    pub(crate) avm_config: AvmConfig,
    /// Persistent AVM interpreter — holds audit buffer, wallet cache, ignition state.
    /// Arc because AvmInterpreter uses interior mutability (Mutex) for thread safety.
    avm: Arc<AvmInterpreter>,
    /// YPX-009 capture point shared with the ConsensusEngine.
    pulse: Arc<PulseSink>,
    /// ZKP subprocess prover (only used in ZKP mode, lazily initialized)
    prover: Option<SubprocessProver>,
    program_digest: [u8; 32],
    /// Operator's `max_fact_links` (mirrors lambda.toml). Threaded into every
    /// `PublicInputs` we construct so Core — not Lambda — does the depth check.
    /// `0` = no operator limit (Core's hard `MAX_TOTAL_LINKS` still applies).
    /// Lambda MUST NEVER inspect `fact_chain.links` directly; per
    /// `feedback_layer_roles.md` only Core decides FACT chain validity.
    /// Set via `set_max_fact_links` by ConsensusEngine at config-load time.
    max_fact_links: usize,
}

impl CoreClient {
    /// Create a CoreClient with a persistent AVM interpreter (DMAP mode — default).
    ///
    /// The AVM interpreter persists across all TX executions, maintaining:
    /// - YPX-009 audit buffer and wallet cache (invisible to Lambda)
    /// - Ignition state (pulse-gate feature)
    /// - §23.14 pending audit countdown
    ///
    /// ZKP prover is not spawned — call `enable_zkp()` to add it.
    pub fn new(avm_config: AvmConfig) -> Result<Self, LambdaError> {
        info!("CoreClient: AVM interpreter ready, core_id={}", hex::encode(avm_config.core_id));
        let avm = Arc::new(AvmInterpreter::new(
            avm_config.elf_bytes.clone(),
            [0u8; 32],
        ));
        Ok(Self { avm_config, avm, pulse: Arc::new(PulseSink::default()), prover: None, program_digest: [0u8; 32], max_fact_links: 0 })
    }

    /// Apply operator's `max_fact_links` from lambda.toml. ConsensusEngine
    /// calls this after constructing the CoreClient. Value is threaded into
    /// every `PublicInputs` Core sees; Core decides whether to reject.
    /// `0` = no operator limit.
    pub fn set_max_fact_links(&mut self, max_fact_links: usize) {
        self.max_fact_links = max_fact_links;
    }

    /// Get a reference to the persistent AVM interpreter.
    /// Used by ConsensusEngine for ignition and validator_pk setup.
    pub fn avm(&self) -> &Arc<AvmInterpreter> {
        &self.avm
    }

    /// Enable ZKP mode by spawning the SubprocessProver.
    ///
    /// Only needed for validators running in ZKP mode (STARK proofs).
    pub fn enable_zkp(&mut self) -> Result<(), LambdaError> {
        let prover = SubprocessProver::spawn(None)
            .map_err(|e| LambdaError::CoreExecutionError(format!("SubprocessProver: {}", e)))?;
        self.program_digest = prover.program_digest();
        info!("CoreClient: ZKP prover ready, digest={}", hex::encode(self.program_digest));
        self.prover = Some(prover);
        Ok(())
    }

    pub fn program_digest(&self) -> [u8; 32] {
        self.program_digest
    }

    /// The YPX-009 capture point (shared `Arc`), for the ConsensusEngine.
    pub fn pulse_sink(&self) -> Arc<PulseSink> {
        self.pulse.clone()
    }

    /// Execute core validation via persistent AVM interpreter.
    ///
    /// Returns PublicOutputs from the AVM execution.
    /// Uses the persistent AVM — audit buffer and wallet cache carry across TXs.
    fn execute_avm(&self, inputs: PublicInputs) -> Result<PublicOutputs, LambdaError> {
        let result = self.avm.execute(inputs)
            .map_err(|e| LambdaError::CoreExecutionError(format!("AVM: {}", e)))?;
        self.pulse.absorb(&result, "unrecorded");
        refuse_if_audit_failed(&result, "unrecorded")?;
        Ok(result)
    }

    /// CL5 redeem — RECORDED by `process_redeem_request_inner`, so it joins
    /// the YPX-009 audit chain (`execute_audited`).
    fn execute_avm_cl5_with_capture(&self, inputs: PublicInputs) -> Result<PublicOutputs, LambdaError> {
        let input_bytes = serde_json::to_vec(&inputs).unwrap_or_default();
        let result = self.avm.execute_audited(inputs)
            .map_err(|e| LambdaError::CoreExecutionError(format!("AVM: {}", e)));
        if let Ok(ref o) = result {
            self.pulse.absorb(o, "CL5 redeem");
        }
        let result = match result {
            Ok(o) => refuse_if_audit_failed(&o, "CL5 redeem").map(|_| o),
            Err(e) => Err(e),
        };
        if result.is_err() {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            let path = format!("/tmp/cl5_panic_{}.json", ts);
            eprintln!("[CL5-PANIC] Dumping {} bytes to {}", input_bytes.len(), &path);
            let _ = std::fs::write(&path, &input_bytes);
        }
        result
    }

    /// Execute core validation via persistent AVM interpreter with DMAP trace collection.
    ///
    /// Single-pass: validates AND collects DMAP checkpoints simultaneously.
    /// Uses the persistent AVM — audit buffer and wallet cache carry across TXs.
    /// `audited` = this is the FINALIZING CL3 whose result `finalize_transaction`
    /// records; a non-final witness hop passes false and stays out of the chain.
    fn execute_avm_with_dmap(&self, inputs: PublicInputs, audited: bool) -> Result<axiom_dmap_vm::AvmExecutionResult, LambdaError> {
        let result = if audited { self.avm.execute_with_dmap_audited(inputs) } else { self.avm.execute_with_dmap(inputs) }
            .map_err(|e| LambdaError::CoreExecutionError(format!("AVM DMAP: {}", e)))?;
        let label = if audited { "CL3 finalize" } else { "CL3 hop" };
        self.pulse.absorb(&result.outputs, label);
        refuse_if_audit_failed(&result.outputs, label)?;
        Ok(result)
    }

    // ========================================================================
    // CL2: Validator Core In — THE authoritative S-ABR + attestation gate
    // ========================================================================

    /// Run Core CL2 on an incoming witness request.
    ///
    /// CL2 is "Validator Core In": Core verifies the transaction against the
    /// supplied state view, verifies the CLARA attestation (Ed25519 + NBC
    /// trust anchor + eligibility `view == healed_to`, KI#260 — no rewrite), verifies the
    /// RECALL attestation (Nabla sig + txid binding + over-reclaim equality —
    /// a bare `kind=Recall` without it is REJECTED), and decides the S-ABR
    /// overlap from `prev_receipts` alone. Lambda gets NO overlap vote: it
    /// reads `outputs.is_overlapped` and only REFILLS balance/seq from its
    /// own `TransactionRecord` when Core says overlapped — Core then
    /// re-verifies the refill at CL3 (SABRHashMismatch).
    ///
    /// The `recall_attestation` is threaded from the envelope — this call is
    /// the fix for the None-drop that left `execute_cl2`'s attestation gate
    /// unreachable (see docs/decision record: CL2 was invoked by nobody).
    ///
    /// `current_state` is Lambda's CL2 state view: DECLARED values
    /// (`claimed_balance_for_sabr`, `wallet_seq-1`, `claimed_hibernation_until`)
    /// which Core anchors to the k-signed `prev_receipt.state_hash`
    /// (`verify_state_anchored`), with `state_id` following the REPLAY-FIX
    /// rule (stored for overlapped, consumed for fresh). Built by
    /// `process_witness_request` — see the construction comment there.
    ///
    /// UMP-safe: envelope fields are pulled from the typed `WitnessRequest`
    /// directly, same shape as `produce_witness{_dmap}`.
    pub fn run_cl2(
        &self,
        envelope: &axiom_core_logic::types::WitnessRequest,
        current_state: Option<&WalletState>,
        frozen_wallets: Option<Vec<[u8; 32]>>,
        my_validator_pk: Option<Vec<u8>>,
        vbc_bundle: Option<VBCProofBundle>,
        // YP §26.17.6.5 B4 — Lambda-assembled certificate set for the chain.
        fact_certificates: Vec<VBCProofBundle>,
    ) -> Result<PublicOutputs, LambdaError> {
        debug!("CL2: authoritative S-ABR + attestation gate (recall_att={}, clara_att={})",
               envelope.recall_attestation.is_some(), envelope.clara_attestation.is_some());

        let inputs = PublicInputs {
            zkq_request: None,
            fact_certificates,
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
            receiver_witness: None,
            receiver_signing_key: None,
            mode: CoreLogicMode::CL2,
            local_core_id: self.avm_config.core_id,
            // ── Envelope-sourced fields ───────────────────────────
            transaction: envelope.transaction.clone(),
            prev_receipts: envelope.prev_receipts.clone(),
            overlapped_signatures: envelope.overlapped_signatures.clone(),
            group_member_index: envelope.group_member_index.map(|i| i as u32),
            sender_fact_chain: envelope.sender_fact_chain.clone(),
            audit_confirmation: envelope.audit_confirmation.clone(),
            audit_response: envelope.audit_response.clone(),
            clara_attestation: envelope.clara_attestation.clone(),
            oods_attestation: envelope.oods_attestation.clone(),
            // YPX-022: the RECALL attestation rides the envelope INTO Core —
            // never dropped to None on this path (that drop was the bug that
            // made the CL2 attestation gate dead code).
            recall_attestation: envelope.recall_attestation.clone(),
            // §10.0 FOB fee-claim: SAME rule — the claim attestation must ride
            // the envelope into Core or the CL2 fee-claim gate is dead code.
            fob_claim_attestation: envelope.fob_claim_attestation.clone(),
            // §5.2.2b: SAME RULE, and it was broken here — the claimant's
            // provisional certificate must ride the envelope into Core or the
            // admission gate is dead code. Every Core-input site in this file
            // hardcoded `None`, so no real claim could EVER satisfy the gate;
            // it refused correctly and unsatisfiably (2026-09-04).
            claimant_vbc: envelope.claimant_vbc.clone(),
            // ── Lambda-derived values ─────────────────────────────
            current_state: current_state.cloned(),
            frozen_wallets,
            // ── Lambda's own crypto material ──────────────────────
            // No signing keys: CL2 verifies, it never signs. Depth
            // enforcement in verify_fact_chain keys on my_dilithium_sk
            // being present, so CL2 (like CL2_PREFILTER) leaves the
            // anti-abuse depth ceiling to the finalizer's CL3.
            vbc_bundle,
            my_validator_pk,
            my_dilithium_sk: None,
            my_dilithium_pk: None,
            my_validator_id: None,
            nabla_stake_proof: None,
            zkp_nonce: None,
            max_fact_links: if self.max_fact_links > 0 { Some(self.max_fact_links as u32) } else { None },
            // ── Modes not applicable to CL2 ───────────────────────
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            receiver_fact_chain: None,
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            nonce_response: None,
            wallet_secret: None,
            fanout_message: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None,
            txid_attestation: None,
            cheque_claim_proof: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
        };

        let outputs = self.execute_avm(inputs)?;

        match outputs.result {
            ValidationResult::Accept => Ok(outputs),
            ValidationResult::Fatal => {
                let reason = outputs.rejection_reason
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                eprintln!("[FATAL] Core CL2: {}", reason);
                std::process::exit(78);
            }
            ValidationResult::Reject => {
                // Typed pass-through when Core gives the structured error.
                match outputs.rejection_reason {
                    Some(ve) => Err(LambdaError::CoreRejected(Box::new(ve))),
                    None => Err(LambdaError::CoreValidationFailed("CL2: Unknown".to_string())),
                }
            }
        }
    }

    // ========================================================================
    // CL3: Produce witness proof (ZKP mode — STARK proof)
    // ========================================================================

    /// UMP-safe witness CL3 entry (ZKP path). Same shape as
    /// `produce_witness_dmap`: takes the typed `WitnessRequest` by
    /// reference. The only ZKP-specific extra is `zkp_nonce`, which
    /// is Lambda-derived (not an envelope field).
    pub fn produce_witness(
        &mut self,
        envelope: &axiom_core_logic::types::WitnessRequest,
        // Lambda-derived inputs (NOT envelope fields).
        wallet_state: Option<&WalletState>,
        frozen_wallets: Option<Vec<[u8; 32]>>,
        nabla_stake_proof: Option<axiom_core_logic::types::NablaStakeProof>,
        zkp_nonce: Option<[u8; 32]>,
        // Lambda's own crypto material.
        my_validator_pk: Option<Vec<u8>>,
        vbc_bundle: Option<VBCProofBundle>,
        my_dilithium_sk: Option<Vec<u8>>,
        my_dilithium_pk: Option<Vec<u8>>,
        my_validator_id: Option<[u8; 32]>,
        // KI#50: needed to SIGN the DMAP attestation this path now always
        // produces. DMAP is the base service; the STARK is additional.
        my_signing_key: Option<&ed25519_dalek::SigningKey>,
        // YPX-009: true only from `finalize_transaction` (the recorded execution).
        audited: bool,
        // YPX-009 §4.4: LAMBDA's answer to Core's pending audit (built from its
        // DB by `resolve_pulse_audit`). Until 2026-09-08 this was read from the
        // CLIENT's envelope — always empty — so Core never received an answer,
        // `pending_request` stayed set, and the audit stalled after one request.
        pulse_audit_response: Option<axiom_core_logic::types::PulseAuditResponse>,
        // YP §26.17.6.5 B4 — Lambda-assembled certificate set for the chain.
        fact_certificates: Vec<VBCProofBundle>,
    ) -> Result<WitnessProof, LambdaError> {
        debug!("CL3: Producing witness proof (DMAP base + additional STARK)");

        let inputs = PublicInputs {
            zkq_request: None,
            fact_certificates,
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
            receiver_witness: None,
            receiver_signing_key: None,
            recall_attestation: None,
            // §4.2a — the finalize (CL3) computes the RECEIPT's state hash; an
            // emission claim's produced state carries `attestation.epoch`, so
            // CL3 must see the same attestation CL2 did (live gate #3,
            // 2026-09-14: the receipt anchored epoch 0, the wallet expected the
            // attested epoch, and the SDK refused its own commit).
            fob_claim_attestation: envelope.fob_claim_attestation.clone(),
            // §5.2.2b rides into CL3 as well: unlike the RECALL/FOB gates
            // (which live in `modes.rs::execute_cl2`), the admission gate is in
            // `validate_transaction`, so the finalize pass re-applies it.
            claimant_vbc: envelope.claimant_vbc.clone(),
            mode: CoreLogicMode::CL3,
            local_core_id: self.avm_config.core_id,
            // ── Envelope-sourced fields ───────────────────────────
            transaction: envelope.transaction.clone(),
            prev_receipts: envelope.prev_receipts.clone(),
            overlapped_signatures: envelope.overlapped_signatures.clone(),
            group_member_index: envelope.group_member_index.map(|i| i as u32),
            sender_fact_chain: envelope.sender_fact_chain.clone(),
            audit_confirmation: envelope.audit_confirmation.clone(),
            audit_response: pulse_audit_response.clone().or_else(|| envelope.audit_response.clone()),
            clara_attestation: envelope.clara_attestation.clone(),
            // YPX-021 §8.2 — client-fetched Nabla OODS reading, forwarded
            // VERBATIM (the YPX-020 lesson: dropping a UMP-carried field
            // here silently breaks the protocol downstream).
            oods_attestation: envelope.oods_attestation.clone(),
            // ── Lambda-derived values ─────────────────────────────
            current_state: wallet_state.cloned(),
            frozen_wallets,
            nabla_stake_proof,
            zkp_nonce,
            // ── Lambda's own crypto material ──────────────────────
            vbc_bundle,
            my_validator_pk,
            my_dilithium_sk,
            my_dilithium_pk,
            my_validator_id,
            max_fact_links: if self.max_fact_links > 0 { Some(self.max_fact_links as u32) } else { None },
            // ── Modes not applicable to CL3 / ZKP witness ─────────
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            receiver_fact_chain: None,
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            nonce_response: None,
            wallet_secret: None,
            fanout_message: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None,
            txid_attestation: None,
            cheque_claim_proof: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
        };

        // KI#50 — DMAP IS THE BASE SERVICE. This path used `execute_avm`, which
        // collects no trace, and then hardcoded the dmap hashes to zero: a
        // validator serving ZKP emitted NO DMAP attestation at all and could not
        // honour the fail-closed rule. Capture the trace exactly as the DMAP path
        // does, so every witness carries a DMAP attestation whatever else it also
        // carries.
        let input_bytes_for_hash = {
            let mut buf = Vec::new();
            ciborium::into_writer(&inputs, &mut buf).expect("CBOR encode inputs");
            buf
        };
        let input_hash = *blake3::hash(&input_bytes_for_hash).as_bytes();
        let avm_result = self.execute_avm_with_dmap(inputs.clone(), audited)?;
        let outputs = avm_result.outputs.clone();

        match outputs.result {
            ValidationResult::Accept => {
                // Generate real STARK proof via subprocess prover.
                debug!("CL3: Generating real ZKP via subprocess prover");

                // Strip signing keys and large bundles for zkVM — PQC signing
                // (Dilithium/SPHINCS+) is 100-1000x slower inside RISC-V emulation.
                // The STARK proof covers validation logic only; signatures and
                // VBC verification are produced natively.
                let mut zkvm_inputs = inputs;
                zkvm_inputs.my_dilithium_sk = None;
                zkvm_inputs.my_dilithium_pk = None;
                zkvm_inputs.issuer_sphincs_sk = None;
                zkvm_inputs.vbc_bundle = None;
                zkvm_inputs.fact_witness_sigs = vec![];
                zkvm_inputs.cl1_execution_proof = None;
                // KI#155: the KI#145 certificate set (~165 KB on a FACT send) is
                // decoded in-circuit and never read by the checkpoint — 58
                // segments for nothing. `prove_checkpoint` strips it too.
                zkvm_inputs.fact_certificates = vec![];

                // Prove via subprocess (prover-worker) — completely isolated
                // from Tokio's runtime, no Rayon deadlock possible.
                // NEVER SUBSTITUTE (AXIOM Origin, 2026-08-01). A client that asked
                // for ZKP gets ZKP. On weaker hardware that is merely SLOWER —
                // warn and proceed. Silently returning a DMAP-only witness when a
                // STARK was requested is fail-open: the caller believes it holds a
                // proof it does not have. If the prover is genuinely unavailable
                // this is a HARD ERROR.
                let prover = self.prover.as_mut()
                    .ok_or_else(|| LambdaError::CoreExecutionError(
                        "ZKP requested but the prover is unavailable. NOT falling back to \
                         DMAP-only — a requested STARK is never optional. Fix the prover \
                         environment (core/build-zkvm.sh) or route this request to a node \
                         that can serve it.".into()
                    ))?;
                let (zkp_checkpoint, receipt) = prover.prove(zkvm_inputs, Some(outputs.clone()))
                    .map_err(|e| LambdaError::CoreExecutionError(format!("zkVM prove: {}", e)))?;

                if zkp_checkpoint.produced_state_id != outputs.produced_state_id {
                    return Err(LambdaError::CoreExecutionError(
                        "zkVM/AVM state_id mismatch — determinism failure".into()
                    ));
                }

                debug!("CL3: STARK generated ({} bytes)", receipt.to_bytes().len());

                // The DMAP attestation is the BASE service — built through the
                // SAME shared builder the DMAP path uses, so it inherits the
                // fail-closed rule. `proof_type` stays Dmap; a non-empty
                // `zkp_receipt` is what signals the additional ZKP tier
                // (AXIOM Origin's ruling, 2026-08-01).
                let output_hash = {
                    let mut buf = Vec::new();
                    ciborium::into_writer(&outputs, &mut buf).expect("CBOR encode outputs");
                    *blake3::hash(&buf).as_bytes()
                };
                let execution_proof_bytes = self.build_dmap_execution_proof(
                    &avm_result,
                    input_hash,
                    output_hash,
                    self.avm_config.core_id,
                    my_signing_key,
                )?;

                Ok(WitnessProof {
                    outputs,
                    zkp_receipt: Some(receipt),
                    execution_proof_bytes,
                    proof_type: ProofType::Dmap as u8,
                    dmap_input_hash: input_hash,
                    dmap_output_hash: output_hash,
                })
            }
            ValidationResult::Fatal => {
                let reason = outputs.rejection_reason
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                eprintln!("[FATAL] Core CL3: {}", reason);
                std::process::exit(78);
            }
            ValidationResult::Reject => {
                // Phase 2b.3: prefer typed pass-through when Core
                // gives us the structured ValidationError.
                match outputs.rejection_reason {
                    Some(ve) => Err(LambdaError::CoreRejected(Box::new(ve))),
                    None => Err(LambdaError::CoreValidationFailed("Unknown".to_string())),
                }
            }
        }
    }

    // ========================================================================
    // CL3 DMAP: Produce witness proof via DMAP attestation (single-pass)
    // ========================================================================

    /// Produce a DMAP witness proof.
    ///
    /// Single-pass execution: AVM interpreter runs core validation AND collects
    /// DMAP checkpoints simultaneously. No duplicate execution.
    #[allow(clippy::too_many_arguments)]
    /// UMP-safe witness CL3 entry — takes the canonical typed
    /// `WitnessRequest` by reference and pulls every wire field from
    /// it directly. Adding a new field to the envelope flows through
    /// to `PublicInputs` automatically; this signature does NOT grow.
    ///
    /// The remaining arguments are values Lambda derives from local
    /// storage (`wallet_state`, `frozen_wallets`, `nabla_stake_proof`)
    /// plus Lambda's own crypto material (`my_*`). None of them
    /// duplicate envelope fields.
    ///
    /// History — each previous version of this signature added more
    /// args as new envelope fields landed (audit_confirmation,
    /// audit_response, clara_attestation, group_member_index, …).
    /// Every addition was a place a field could be missed: the
    /// pattern that produced task #143's residual 20%
    /// FactInsufficientWitnesses on the redeem side (`fee_breakdown`
    /// defaulted to `Vec::new()` for weeks before instrumentation
    /// surfaced it). Same shape resolved here for CL3.
    /// Build + sign the DMAP attestation, CBOR-encode it, FAIL CLOSED if the AVM
    /// collected no trace.
    ///
    /// Extracted 2026-08-01 (KI#50) so the DMAP and ZKP paths share ONE builder.
    /// Before this, the ZKP path called `execute_avm` (no trace capture) and
    /// hardcoded `dmap_input_hash`/`dmap_output_hash` to zero, so a validator
    /// serving ZKP emitted NO DMAP attestation at all and could not honour the
    /// fail-closed rule below. DMAP is the BASE service every validator owes
    /// every client; the STARK is additional.
    fn build_dmap_execution_proof(
        &self,
        avm_result: &axiom_dmap_vm::AvmExecutionResult,
        input_hash: [u8; 32],
        output_hash: [u8; 32],
        dmap_validator_pk: [u8; 32],
        my_signing_key: Option<&ed25519_dalek::SigningKey>,
    ) -> Result<Vec<u8>, LambdaError> {
        let Some(ref trace) = avm_result.dmap_trace else {
            // FAIL CLOSED. A missing DMAP trace is an error, never a
            // degradation (CLAUDE.md §13). Shipping empty proof bytes here
            // produced a witness signature carrying no execution proof:
            // consensus.rs's `if !execution_proof_bytes.is_empty()` simply omits
            // it, so a validator running without a valid ELF (or built without
            // `riscv-interpreter`) witnessed traffic while attesting nothing —
            // and the YPX-006 §0.3 argument that a modified Core is caught by
            // divergent attestations cannot catch an ABSENT one.
            return Err(LambdaError::CoreExecutionError(
                "CL3: DMAP attestation requested but no trace was collected \
                 (riscv-interpreter disabled or no valid Core ELF loaded). \
                 Refusing to witness without an execution proof."
                    .to_string(),
            ));
        };
        let mut attestation = DmapAttestation::from_trace(
            self.avm_config.core_id,
            input_hash,
            output_hash,
            trace,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            dmap_validator_pk,
        );
        if let Some(sk) = my_signing_key {
            use ed25519_dalek::Signer;
            let payload = attestation.signing_payload();
            let sig = sk.sign(&payload);
            attestation.set_signature(sig.to_bytes().to_vec());
        }
        debug!("CL3: DMAP attestation built ({} checkpoints, ~{} bytes, signed={})",
            attestation.total_checkpoints, attestation.estimated_size(),
            !attestation.signature.is_empty());
        // CBOR, never JSON — the attestation carries Dilithium bytes and Merkle
        // proofs; JSON's int-array coercion shifts byte-string semantics.
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&attestation, &mut buf)
            .map_err(|e| LambdaError::CoreExecutionError(format!("DMAP serialize: {}", e)))?;
        Ok(buf)
    }

    pub fn produce_witness_dmap(
        &self,
        envelope: &axiom_core_logic::types::WitnessRequest,
        // Lambda-derived inputs (NOT envelope fields).
        wallet_state: Option<&WalletState>,
        frozen_wallets: Option<Vec<[u8; 32]>>,
        nabla_stake_proof: Option<axiom_core_logic::types::NablaStakeProof>,
        // Lambda's own crypto material.
        my_validator_pk: Option<Vec<u8>>,
        vbc_bundle: Option<VBCProofBundle>,
        my_dilithium_sk: Option<Vec<u8>>,
        my_dilithium_pk: Option<Vec<u8>>,
        my_validator_id: Option<[u8; 32]>,
        // AUDIT-FIX v2.11.14: Signing key for DMAP attestation signature.
        my_signing_key: Option<&ed25519_dalek::SigningKey>,
        // YPX-009: true only from `finalize_transaction` (the recorded execution).
        audited: bool,
        // YPX-009 §4.4: Lambda's answer to Core's pending audit (see produce_witness).
        pulse_audit_response: Option<axiom_core_logic::types::PulseAuditResponse>,
        // YP §26.17.6.5 B4 — Lambda-assembled certificate set for the chain.
        fact_certificates: Vec<VBCProofBundle>,
    ) -> Result<WitnessProof, LambdaError> {
        debug!("CL3: Producing witness proof (DMAP attestation, single-pass)");

        // Locals for readability; every binding is `envelope.<field>`.
        let transaction = &envelope.transaction;

        // Extract validator_pk for DMAP challenge derivation before it's moved into PublicInputs
        let dmap_validator_pk: [u8; 32] = my_validator_pk.as_deref()
            .and_then(|pk| <[u8; 32]>::try_from(pk).ok())
            .unwrap_or([0u8; 32]);

        let inputs = PublicInputs {
            zkq_request: None,
            fact_certificates,
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
            receiver_witness: None,
            receiver_signing_key: None,
            recall_attestation: None,
            // §4.2a — the finalize (CL3) computes the RECEIPT's state hash; an
            // emission claim's produced state carries `attestation.epoch`, so
            // CL3 must see the same attestation CL2 did (live gate #3,
            // 2026-09-14: the receipt anchored epoch 0, the wallet expected the
            // attested epoch, and the SDK refused its own commit).
            fob_claim_attestation: envelope.fob_claim_attestation.clone(),
            // §5.2.2b rides into CL3 as well: unlike the RECALL/FOB gates
            // (which live in `modes.rs::execute_cl2`), the admission gate is in
            // `validate_transaction`, so the finalize pass re-applies it.
            claimant_vbc: envelope.claimant_vbc.clone(),
            mode: CoreLogicMode::CL3,
            local_core_id: self.avm_config.core_id,
            // ── Envelope-sourced fields ───────────────────────────
            // EVERY assignment below is `envelope.<field>` — no
            // per-arg shadow, no `Vec::new()` / `None` defaults on
            // wire fields. A new envelope field flows through here
            // ONCE, then ships to Core CL3 automatically.
            transaction: transaction.clone(),
            prev_receipts: envelope.prev_receipts.clone(),
            overlapped_signatures: envelope.overlapped_signatures.clone(),
            group_member_index: envelope.group_member_index.map(|i| i as u32),
            sender_fact_chain: envelope.sender_fact_chain.clone(),
            audit_confirmation: envelope.audit_confirmation.clone(),
            audit_response: pulse_audit_response.clone().or_else(|| envelope.audit_response.clone()),
            clara_attestation: envelope.clara_attestation.clone(),
            // YPX-021 §8.2 — client-fetched Nabla OODS reading, forwarded
            // VERBATIM (the YPX-020 lesson: dropping a UMP-carried field
            // here silently breaks the protocol downstream).
            oods_attestation: envelope.oods_attestation.clone(),
            // ── Lambda-derived values ─────────────────────────────
            current_state: wallet_state.cloned(),
            frozen_wallets,
            nabla_stake_proof,
            // ── Lambda's own crypto material ──────────────────────
            vbc_bundle,
            my_validator_pk,
            my_dilithium_sk,
            my_dilithium_pk,
            my_validator_id,
            max_fact_links: if self.max_fact_links > 0 { Some(self.max_fact_links as u32) } else { None },
            // ── Modes not applicable to CL3 / DMAP witness ────────
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            receiver_fact_chain: None,
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            zkp_nonce: None, // DMAP doesn't use ZKP nonce
            nonce_response: None,
            wallet_secret: None,
            fanout_message: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None,
            txid_attestation: None,
            cheque_claim_proof: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
        };

        // Compute hashes for attestation before consuming inputs.
        // CBOR not JSON — [[feedback_no_json_in_protocol_path]]. Hash bytes
        // are part of the cryptographic binding (DmapAttestation.input_hash),
        // so they must be deterministic. JSON's HashMap ordering / float
        // representation / escaping is too brittle for that role.
        let input_bytes_for_hash = {
            let mut buf = Vec::new();
            ciborium::into_writer(&inputs, &mut buf).expect("CBOR encode inputs");
            buf
        };
        let input_hash = *blake3::hash(&input_bytes_for_hash).as_bytes();

        // Single-pass: validate AND collect DMAP trace in one AVM execution
        // Core handles FACT signing + compression inside AVM
        let input_size = input_bytes_for_hash.len();
        let t_avm = std::time::Instant::now();
        let avm_result = self.execute_avm_with_dmap(inputs, audited)?;
        let avm_elapsed = t_avm.elapsed();
        if avm_elapsed.as_secs() >= 5 {
            eprintln!("[DMAP-TIMING] AVM took {:.1}s, input_size={}KB, instructions={}, result={:?}",
                avm_elapsed.as_secs_f64(),
                input_size / 1024,
                avm_result.dmap_trace.as_ref().map(|t| t.checkpoints.len() * 10000).unwrap_or(0),
                avm_result.outputs.result,
            );
        }

        match avm_result.outputs.result {
            ValidationResult::Accept => {
                // CBOR not JSON — [[feedback_no_json_in_protocol_path]].
                let output_hash = {
                    let mut buf = Vec::new();
                    ciborium::into_writer(&avm_result.outputs, &mut buf)
                        .expect("CBOR encode outputs");
                    *blake3::hash(&buf).as_bytes()
                };

                let execution_proof_bytes = self.build_dmap_execution_proof(
                    &avm_result,
                    input_hash,
                    output_hash,
                    dmap_validator_pk,
                    my_signing_key,
                )?;

                Ok(WitnessProof {
                    outputs: avm_result.outputs,
                    zkp_receipt: None,
                    execution_proof_bytes,
                    proof_type: ProofType::Dmap as u8,
                    dmap_input_hash: input_hash,
                    dmap_output_hash: output_hash,
                })
            }
            ValidationResult::Fatal => {
                let reason = avm_result.outputs.rejection_reason
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                eprintln!("[FATAL] Core CL3 (DMAP): {}", reason);
                std::process::exit(78);
            }
            ValidationResult::Reject => {
                match avm_result.outputs.rejection_reason {
                    Some(ve) => Err(LambdaError::CoreRejected(Box::new(ve))),
                    None => Err(LambdaError::CoreValidationFailed("Unknown".to_string())),
                }
            }
        }
    }

    // ========================================================================
    // CL5: Validate redeem
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    /// UMP-safe redeem entry — takes the canonical
    /// `RedeemRequestEnvelope` by reference and pulls every wire field
    /// from it directly. Adding a new field to the envelope flows
    /// through to `PublicInputs` automatically; the caller does NOT
    /// need to thread it as a new argument here.
    ///
    /// The remaining arguments are values Lambda computes from local
    /// storage (`current_balance`, `current_seq`, `new_balance`,
    /// `receiver_state_id`, the chain pointers) plus Lambda's own
    /// crypto material (`my_*`, `vbc_bundle`). None of them duplicate
    /// envelope fields.
    ///
    /// History — every previous version of this signature held a
    /// shadow copy of envelope fields as individual args. Each shadow
    /// was a place drift could land:
    ///   - `fee_breakdown` was hardcoded `Vec::new()` for weeks
    ///     before task #143 surfaced the residual 20%
    ///     FactInsufficientWitnesses class.
    ///   - `cheque_claim_proof` had the same shape pre-Stream B.
    ///   - `fact_witness_sigs` was added later as another arg.
    /// The canonical typed envelope is the single source of truth;
    /// referencing `envelope.<field>` inside `PublicInputs` means a
    /// future field needs ONE edit (the `PublicInputs { … }` literal
    /// below), not five (signature + caller + transport + parser).
    pub fn validate_redeem(
        &self,
        envelope: &axiom_core_logic::types::RedeemRequestEnvelope,
        // Lambda-computed values (not envelope fields).
        current_balance: u64,
        current_seq: u64,
        new_balance: u64,
        // §5.2.2c — the receiver's DECLARED stake lock (the envelope's
        // `current_state`). ⚠ Until 2026-10-01 this was "read from LAMBDA'S OWN
        // STORAGE … the ENFORCING copy"; a row-less validator fed `0` and a
        // stale one fed a stale value, so it enforced nothing (Fable review
        // F-1). Core CL5 now anchors the declared value to the receiver's last
        // k-signed receipt (`envelope.prev_receipts`), which is what refuses a
        // forged `0` (RULE 5: Core, not Lambda's row). The caller passes the
        // declared values verbatim (consensus.rs L2).
        current_wall_clock_lock: u64,
        current_emission_claimed_epoch: u64, // §4.2a — the sixth §15 field, declared + anchored like the lock
        current_stake_floor_until: u64, // ValidatorJoin §6b.13 — the seventh §15 field, same rule
        current_wallet_format: axiom_core_logic::types::WalletFormat, // §6b.13 — the format block
        // Chain pointers Lambda resolves before calling Core.
        sender_fact_chain: Option<FactChain>,
        receiver_state_id: Option<[u8; 32]>,
        receiver_fact_chain: Option<FactChain>,
        // Lambda's own crypto material.
        my_dilithium_sk: Option<Vec<u8>>,
        my_dilithium_pk: Option<Vec<u8>>,
        my_validator_id: Option<[u8; 32]>,
        vbc_bundle: Option<axiom_core_logic::types::VBCProofBundle>,
        // YP §26.17.6.5 B4 — Lambda-assembled certificate set for the sender's chain.
        fact_certificates: Vec<axiom_core_logic::types::VBCProofBundle>,
        // §23.14: the resolved SELF-audit confirmation, if one is pending (2026-09-24).
        audit_confirmation: Option<axiom_core_logic::types::AuditConfirmation>,
    ) -> Result<RedeemProof, LambdaError> {
        // Sanity binding — Core CL5 reads `inputs.receiver_pk` and
        // `inputs.cheque_bundle`; both are envelope-sourced. We hold
        // these as locals to keep the `PublicInputs` literal readable;
        // every assignment below is a direct `envelope.<field>` clone.
        let cheque_bundle = &envelope.cheque_bundle;
        let receiver_pk = envelope.receiver_pk.as_slice();
        debug!("CL5: Validating redeem request via AVM");

        // ── ONE builder for the CL5 stub (CLAUDE.md §12 instance 5; this site
        // consolidated 2026-09-10, the owner: "consolidate the validate_redeem
        // literal onto the shared builder"). The attestation-context inputs come
        // from the SAME function the SDK's `run_cl5` and Lambda's expected-hash
        // recompute (`consensus.rs`) use, so this stub can no longer drift from
        // them — the 2026-09-08 redeem-audit "chain hash mismatch" was exactly
        // this literal disagreeing with the record on `amount`.
        //
        // MEASURED before consolidating: Core's `execute_cl5` reads ONE stub
        // field, `transaction.epoch` (its clock, 0 on every path — a value to be
        // RULED, see YPX-009 §7a / handoff §16.5), and the redeem audit digest
        // reads `transaction.amount` + `current_state.balance`. All three are
        // identical before and after; the stub fields that now differ from the
        // old literal (consumed_state_id, client_pk, wallet_seq,
        // receiver_wallet_id, core_version) are read by nothing in CL5.
        let mut inputs: PublicInputs = axiom_core_logic::cl5_inputs::build_cl5_attestation_inputs(
            receiver_pk,
            cheque_bundle,
            current_balance,
            current_seq,
            // YPX-020 §2: the receiver's CURRENT hibernation is ENVELOPE-SOURCED
            // (client-declared current_state, exactly like the send path's
            // claimed_hibernation_until) — NOT a Lambda-derived value. Core CL5
            // carries it through on a stranger redeem and clears it on a
            // self-redeem, binding it into the produced state_hash. Hardcoding
            // it 0 (the 2026-06-24 stranger-redeem brick) is what this prevents.
            envelope.current_state.as_ref().map(|s| s.hibernation_until).unwrap_or(0),
            // §5.2.2c / §4.2a / §6b.13 — DECLARED (see the parameter doc), the
            // same values the SDK's attestation run hashed; Core anchors them.
            current_wall_clock_lock,
            current_emission_claimed_epoch,
            current_stake_floor_until,
            current_wallet_format,
            receiver_state_id.unwrap_or([0u8; 32]),
            // Fable review 2026-10-01 F-1(b) (L1) — the receiver's last k-signed
            // receipt: the anchor Core CL5 verifies the declared state against.
            envelope.prev_receipts.clone(),
            envelope.cheque_claim_proof.clone(),
            envelope.txid_attestation.clone(),
            envelope.oods_attestation.clone(), // YPX-021 §8.2 — forward verbatim
            self.avm_config.core_id,
        );
        // ── Lambda-side EXECUTION values, layered on the shared stub ──────
        // These are what make this the enforcing run rather than the
        // attestation recompute: Lambda's stored state and chain pointers, its
        // own keys, its operator cap. The client hashes none of them.
        inputs.current_state = receiver_state_id.map(|sid| axiom_core_logic::types::WalletState {
            public_key: receiver_pk.to_vec(),
            wall_clock_lock: current_wall_clock_lock,
            emission_claimed_epoch: current_emission_claimed_epoch,
            stake_floor_until: current_stake_floor_until,
            wallet_format: current_wallet_format,
            balance: current_balance,
            wallet_seq: current_seq,
            state_id: sid,
            auth_hash: None,
            hibernation_until: envelope.current_state.as_ref().map(|s| s.hibernation_until).unwrap_or(0),
            wallet_id: None,
            group_members: None,
        });
        // Lambda-computed, not the builder's derivation (the builder's is the
        // client-side expectation; Core recomputes and compares regardless).
        inputs.receiver_new_balance = Some(new_balance);
        inputs.vbc_bundle = vbc_bundle;
        inputs.fact_witness_sigs = envelope.fact_witness_sigs.clone();
        inputs.sender_fact_chain = sender_fact_chain;
        inputs.audit_confirmation = audit_confirmation;
        inputs.fact_certificates = fact_certificates;
        inputs.receiver_fact_chain = receiver_fact_chain;
        // The operator cap applies to the REAL execution only (the builder
        // forces None for the attestation context — see its doc).
        inputs.max_fact_links = if self.max_fact_links > 0 { Some(self.max_fact_links as u32) } else { None };
        inputs.my_dilithium_sk = my_dilithium_sk;
        inputs.my_dilithium_pk = my_dilithium_pk;
        inputs.my_validator_id = my_validator_id;

        let outputs = self.execute_avm_cl5_with_capture(inputs)?;

        match outputs.result {
            ValidationResult::Accept => {
                let new_state_id = outputs.produced_state_id
                    .ok_or_else(|| LambdaError::CoreExecutionError(
                        "CL5: Core did not return produced_state_id".into()
                    ))?;
                let commitment_hash = outputs.commitment_hash
                    .ok_or_else(|| LambdaError::CoreExecutionError(
                        "CL5: Core did not return commitment_hash".into()
                    ))?;

                Ok(RedeemProof {
                    new_state_id,
                    commitment_hash,
                    outputs,
                })
            }
            ValidationResult::Fatal => {
                let reason = outputs.rejection_reason
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                eprintln!("[FATAL] Core CL5: {}", reason);
                std::process::exit(78);
            }
            ValidationResult::Reject => {
                match outputs.rejection_reason {
                    Some(ve) => Err(LambdaError::CoreRejected(Box::new(ve))),
                    None => Err(LambdaError::CoreValidationFailed("Unknown".to_string())),
                }
            }
        }
    }

    // ========================================================================
    // CL1 ZKP: Validate client's execution proof
    // ========================================================================

    /// Validate a client's CL1 execution proof.
    ///
    /// Three-layer verification:
    ///   1. STARK proof cryptographically valid (RISC Zero receipt verification)
    ///   2. `outputs.result == Accept` (a valid proof of Reject is still a failure)
    ///   3. `outputs.zkp_nonce_hash == BLAKE3("AXIOM_ZKP_NONCE" || tx.zkp_nonce)` (anti-replay)
    ///
    /// Returns Ok(true) if proof is valid, Ok(false) if no proof was provided
    /// (CL2 still runs as normal), or Err on invalid/rejected proof.
    pub fn validate_client_proof(
        &self,
        proof: &ClientProof,
        expected_zkp_nonce: Option<&[u8; 32]>,
    ) -> Result<bool, LambdaError> {
        if proof.execution_proof.is_empty() {
            return Ok(false); // No proof — CL2 runs normally
        }

        // H3: DoS prevention — reject oversized proofs before deserialization
        const MAX_PROOF_SIZE: usize = 10 * 1024 * 1024; // 10MB
        if proof.execution_proof.len() > MAX_PROOF_SIZE {
            return Err(LambdaError::CoreValidationFailed(
                "CL1: proof exceeds size limit".into()
            ));
        }

        // Try DMAP attestation first (most common in dev/test mode).
        // DMAP attestations are CBOR-serialized DmapAttestation structs
        // (writer at core_client.rs ~459 uses ciborium::ser::into_writer).
        // ZKP proofs are binary STARK receipts that don't parse as CBOR.
        if let Ok(attestation) = ciborium::de::from_reader::<axiom_dmap_vm::dmap::DmapAttestation, _>(
            &proof.execution_proof[..]
        ) {
            // Verify DMAP structurally: CoreID + Merkle proofs.
            // CL1 uses the CLIENT's Ed25519 PK (from attestation.validator_pk).
            // The client signed the attestation with their own key.
            // CoreID-lineage accept-set (§11): a CL1 send-proof built under a blessed
            // prior Core (an in-flight send straddling a routine rotation) verifies
            // against the CoreID it was built with; anything non-blessed resolves to the
            // current CoreID → WrongCore. Same shared resolver as the redeem/register
            // sites. Empty accept-set ⇒ current-only (unchanged).
            let verify_core_id = axiom_core_logic::version::resolve_dmap_verify_core_id(
                &attestation.core_id, &self.avm_config.core_id,
            );
            let result = axiom_dmap_vm::dmap::verify_dmap_attestation(
                &attestation,
                &verify_core_id,
                &attestation.input_hash,
                &attestation.output_hash,
                &attestation.validator_pk, // client's PK for CL1
            );
            match result {
                axiom_dmap_vm::dmap::DmapResult::Valid => {
                    debug!("CL1 DMAP: Client proof verified — attestation valid");
                    return Ok(true);
                }
                other => {
                    return Err(LambdaError::CoreValidationFailed(
                        format!("CL1 DMAP: verification failed: {:?}", other)
                    ));
                }
            }
        }

        // Fall back to ZKP STARK receipt
        let receipt = axiom_zk_vm::ZkvmReceipt::from_bytes(&proof.execution_proof)
            .map_err(|e| LambdaError::CoreValidationFailed(format!("CL1 ZKP decode: {}", e)))?;

        let verifier = axiom_zk_vm::ZkvmVerifier::production()
            .map_err(|e| LambdaError::CoreExecutionError(format!("ZkvmVerifier: {}", e)))?;

        // verify_checkpoint: the guest commits ZkpCheckpointOutputs. Until
        // 2026-09-02 this decoded the journal as PublicOutputs, so CL1 ZKP
        // client-proof verification failed for every proof, valid or not.
        match verifier.verify_checkpoint(&receipt) {
            Ok(outputs) => {
                check_proof_outputs(&outputs, expected_zkp_nonce)?;
                debug!("CL1 ZKP: Client proof verified — Accept + nonce bound");
                Ok(true)
            }
            Err(e) => {
                Err(LambdaError::CoreValidationFailed(format!("CL1 ZKP invalid: {}", e)))
            }
        }
    }

    // ========================================================================
    // YPX-009 ignition = YPX-007 §9 ZKP qualification run (KI#125)
    // ========================================================================

    /// The synthetic ignition TX inputs (`reference = "AXIOM_IGNITION"`, CL1). Also
    /// the base of the `ZkpQualify` inputs — the mode reads only its own fields.
    fn ignition_inputs(&self) -> PublicInputs {
        PublicInputs {
            zkq_request: None,
            fact_certificates: Vec::new(),
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
            receiver_witness: None,
            receiver_signing_key: None,
            recall_attestation: None,
            fob_claim_attestation: None,
            claimant_vbc: None,
            mode: CoreLogicMode::CL1,
            oods_attestation: None,
            local_core_id: self.avm_config.core_id,
            transaction: Transaction {
                recall_target_tx_id: None,
                consumed_state_id: [0u8; 32],
                client_pk: vec![0u8; 32],
                sender_wallet_id: String::new(),
                wallet_seq: 0,
                receiver_wallet_id: String::new(),
                receiver_address: None,
                amount: 0,
                reference: "AXIOM_IGNITION".into(),
                nonce: 0,
                epoch: 0,
                client_sig: vec![],
                scar_passcode: None,
                burn_target_tx_id: None,
                required_k: 0,
                proof_type: 0,
                oracle_claim: None,
                core_version: String::new(),
                core_id: [0u8; 32],
                kind: TxKind::Normal,
            },
            prev_receipts: vec![],
            current_state: None,
            vbc_bundle: None,
            my_validator_pk: None,
            overlapped_signatures: vec![],
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            group_member_index: None,
            sender_fact_chain: None,
            max_fact_links: if self.max_fact_links > 0 { Some(self.max_fact_links as u32) } else { None },
            receiver_fact_chain: None,
            my_dilithium_sk: None,
            my_dilithium_pk: None,
            my_validator_id: None,
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            zkp_nonce: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
        
        }
    }

    /// The ignition job (YPX-009 §6.1 / §6.1a): the shared AVM, the prover taken
    /// OUT of this client, and the ignition TX inputs carrying `zkp_nonce` = the
    /// YPX-007 §9.3 challenge from the T0 Nabla reading (`None` when Nabla was
    /// unreachable). The caller runs [`CoreClient::ignite`] OUTSIDE the Core lock
    /// (the proof takes ≈200 s on a CPU prover) and hands the prover back with
    /// [`CoreClient::restore_prover`] (Fable review 2026-10-03, finding 2). While it
    /// is out, a ZKP-tier CL3 here fails loud ("prover unavailable"), never waits.
    pub fn ignition_job(&mut self, zkp_nonce: Option<[u8; 32]>)
        -> (Arc<AvmInterpreter>, Option<SubprocessProver>, PublicInputs)
    {
        let inputs = PublicInputs { zkp_nonce, ..self.ignition_inputs() };
        (self.avm.clone(), self.prover.take(), inputs)
    }

    /// Put the prover taken by [`CoreClient::ignition_job`] back.
    pub fn restore_prover(&mut self, prover: Option<SubprocessProver>) {
        if prover.is_some() {
            self.prover = prover;
        }
    }

    /// Run the ignition TX sequence (YPX-009 §6.1 / §6.1a). Blocking — call it
    /// from `spawn_blocking`, never under the Core lock.
    ///
    /// Core processes the ignition TX, the ONE existing prover call proves it, and
    /// `complete_ignition` unblocks Core (it checks only non-empty / ≤ 10 MB).
    /// - `Err` = the ignition ITSELF failed (`process_ignition` / `complete_ignition`):
    ///   with `pulse-gate` Core stays BLOCKED — the caller exits (finding 1).
    /// - `Ok(None)` = no prover; `Ok(Some(Ok(receipt)))` = proved, for the caller's
    ///   host verification + `ZkpQualify` run.
    /// - `Ok(Some(Err(_)))` = the prover FAILED: the ignition still completed with
    ///   the DMAP marker (exactly as a prover-less validator's does — service never
    ///   waits on the benchmark); the failure only reaches the operator status.
    ///
    /// This is also the restart penalty — when Core self-terminates due to
    /// pulse audit failure, restart requires a new ignition TX.
    #[allow(clippy::type_complexity)]
    pub fn ignite(
        avm: &AvmInterpreter,
        prover: Option<&mut SubprocessProver>,
        ignition_inputs: PublicInputs,
    ) -> Result<Option<Result<ZkvmReceipt, LambdaError>>, LambdaError> {
        info!("YPX-009: Starting ignition TX sequence (challenge={})", ignition_inputs.zkp_nonce.is_some());

        let outputs = avm.process_ignition(ignition_inputs.clone())
            .map_err(|e| LambdaError::CoreExecutionError(format!("Ignition TX: {}", e)))?;

        let proved = prover.map(|prover| prover.prove(ignition_inputs, Some(outputs))
            .map(|(_, receipt)| receipt)
            .map_err(|e| LambdaError::CoreExecutionError(format!("Ignition ZKVM prove: {}", e))));
        let proof_bytes = match &proved {
            Some(Ok(receipt)) => receipt.to_bytes(),
            // No prover (or a failed one) — the DMAP marker, as before.
            _ => blake3::hash(&b"AXIOM_IGNITION_DMAP"[..]).as_bytes().to_vec(),
        };

        // Non-empty / ≤ 10 MB only; then Argon2id self-benchmark; Core unblocks.
        avm.complete_ignition(&proof_bytes)
            .map_err(|e| LambdaError::CoreExecutionError(format!("Ignition complete: {}", e)))?;
        info!("YPX-009: Ignition complete — Core is ready to serve");
        Ok(proved)
    }

    /// Mode `ZkpQualify` (YPX-007 §9.4): Core judges the T0/T1 bracket + the
    /// challenge binding and signs the record with the validator's Dilithium key
    /// (passed INTO Core — the CL3 FACT-signing precedent). A Core refusal is
    /// `CoreRejected(reason)` — a RESULT for the operator status, never a fault.
    #[allow(clippy::too_many_arguments)]
    pub fn run_zkp_qualify(
        &self,
        before: NablaOodsAttestation,
        request: ZkpQualifyRequest,
        validator_id: [u8; 32],
        dilithium_pk: Vec<u8>,
        dilithium_sk: Vec<u8>,
        audit_confirmation: Option<AuditConfirmation>,
    ) -> Result<ZkpQualificationRecord, LambdaError> {
        let inputs = PublicInputs {
            mode: CoreLogicMode::ZkpQualify,
            oods_attestation: Some(before),
            zkq_request: Some(request),
            my_validator_id: Some(validator_id),
            my_dilithium_pk: Some(dilithium_pk),
            my_dilithium_sk: Some(dilithium_sk),
            // §23.14.6 — the DMAP-VM counts every execution against a pending
            // self demand; same injection as CL8.
            audit_confirmation,
            ..self.ignition_inputs()
        };
        let outputs = self.execute_avm(inputs)?;
        match (outputs.result, outputs.zkp_qualification) {
            (ValidationResult::Accept, Some(record)) => Ok(record),
            (ValidationResult::Accept, None) => Err(LambdaError::CoreExecutionError(
                "ZkpQualify accepted but returned no record".into())),
            _ => Err(LambdaError::CoreRejected(Box::new(
                outputs.rejection_reason.unwrap_or(ValidationError::InternalError)))),
        }
    }

    /// CL11: Validate a new Console Certificate via Core.
    ///
    /// Core verifies chain integrity, election resolution, and seat validity.
    /// Returns the chain hash on success (used to store the certificate).
    /// CL8: have Core sign a VBC/NBC with the issuer's SPHINCS+ key.
    ///
    /// Core is the signing BOUNDARY — Lambda and Nabla must never call
    /// `sign_sphincs` directly (`modes.rs::execute_cl8`). Core verifies the
    /// `NablaStakeProof` in seven steps (identity binding, receipt quorum,
    /// freshness, tier floor) before signing, and fail-stop verifies its own
    /// signature afterwards.
    ///
    /// `stake_proof` is REQUIRED for a VBC-shaped cert (3 issuers). Passing
    /// `None` there is refused with `InsufficientStake` — see
    /// `AXIOM_DESIGN_ValidatorJoin.md` §7.1. `None` remains correct for an
    /// NBC-shaped cert (1 issuer): Nabla nodes do not stake.
    ///
    /// Signing is DETERMINISTIC (`sign_sphincs` uses FIPS 205 hedged=false),
    /// so calling this twice for the same cert returns byte-identical bytes.
    /// Callers rely on that for retry safety instead of storing signatures.
    pub fn run_cl8(
        &self,
        bundle: &axiom_core_logic::types::VBCProofBundle,
        issuer_sphincs_sk: &[u8],
        // §5.3 — the client's fresh OODS reading. CL8 judges the issuing bar on
        // its attested TICK and FAILS CLOSED without it, so this was hardcoded
        // `None` and silently refused every certificate request no matter what
        // the client carried.
        oods_attestation: Option<axiom_core_logic::types::NablaOodsAttestation>,
        // §5.2.2e — the request transaction's epoch (unix seconds, the same
        // value every other mode reads as `transaction.epoch`). CL8's
        // candidacy-Pulse freshness check derives the request's Pulse epoch
        // from it. MEASURED 2026-09-09 (rotation #4, first gate): this stub
        // carried `epoch: 0`, so Core judged every self-audit proof against
        // Pulse epoch 0 and refused it E_VBC_CANDIDACY_PULSE_INVALID while the
        // four other checks passed offline. Gateway path: the caller's clock.
        tx_epoch: u64,
        // §23.14.6 — the resolved SELF-audit confirmation, if one is pending.
        // The DMAP-VM counts EVERY execution against a pending self demand
        // (measured 2026-09-24: "self-audit pending … but this CL8 execution
        // carries NO audit_confirmation" on gamma and delta during the VBC
        // gates), so an issuance burst with no witness traffic in between would
        // drain the countdown to AuditTimeout. Same injection as CL2/CL3/CL5.
        audit_confirmation: Option<axiom_core_logic::types::AuditConfirmation>,
    ) -> Result<Vec<u8>, LambdaError> {
        debug!(
            "CL8: signing cert for validator {} ({} issuers) — candidate; the stamp reads the stake (§6b.8a)",
            hex::encode(bundle.target_vbc.validator_id),
            bundle.target_vbc.issuer_set.len(),
        );

        let inputs = PublicInputs {
            zkq_request: None,
            fact_certificates: Vec::new(),
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
            receiver_witness: None,
            receiver_signing_key: None,
            recall_attestation: None,
            fob_claim_attestation: None,
            claimant_vbc: None,
            mode: CoreLogicMode::CL8,
            oods_attestation,
            local_core_id: self.avm_config.core_id,
            transaction: {
                let mut stub: axiom_core_logic::types::Transaction = serde_json::from_str(
                    r#"{"consumed_state_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"client_pk":[],"wallet_seq":0,"receiver_wallet_id":"","amount":0,"reference":"","nonce":0,"epoch":0,"client_sig":[]}"#
                ).map_err(|e| LambdaError::CoreExecutionError(format!("TX stub: {}", e)))?;
                stub.epoch = tx_epoch;
                stub
            },
            prev_receipts: vec![],
            current_state: None,
            vbc_bundle: Some(bundle.clone()),
            my_validator_pk: None,
            overlapped_signatures: vec![],
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            group_member_index: None,
            sender_fact_chain: None,
            max_fact_links: None,
            receiver_fact_chain: None,
            my_dilithium_sk: None,
            my_dilithium_pk: None,
            my_validator_id: None,
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: Some(issuer_sphincs_sk.to_vec()),
            cl1_execution_proof: None,
            zkp_nonce: None,
            audit_confirmation,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            // candidate_balance is the debug-only legacy path; production must
            // present a NablaStakeProof, so this stays None unconditionally.
            nabla_stake_proof: None, // §6b.8a — issuance has no stake check
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None,
            txid_attestation: None,
            cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
        };

        let outputs = self.execute_avm(inputs)?;

        match outputs.result {
            ValidationResult::Accept => {
                let sig = outputs.nbc_signature.ok_or_else(|| {
                    LambdaError::CoreExecutionError(
                        "CL8 accepted but returned no signature".to_string())
                })?;
                if sig.is_empty() {
                    return Err(LambdaError::CoreExecutionError(
                        "CL8 returned an empty signature".to_string()));
                }
                info!("CL8: signed cert for validator {} ({} bytes)",
                    hex::encode(bundle.target_vbc.validator_id), sig.len());
                Ok(sig)
            }
            ValidationResult::Reject | ValidationResult::Fatal => {
                let reason = outputs.rejection_reason
                    .map(|r| format!("{}", r))
                    .unwrap_or_else(|| "unknown".to_string());
                Err(LambdaError::CoreExecutionError(format!("CL8 rejected: {}", reason)))
            }
        }
    }

    pub fn validate_console_certificate(
        &self,
        current_cert: &axiom_core_logic::types::ConsoleCertificate,
        new_cert: &axiom_core_logic::types::ConsoleCertificate,
        selector_picks: &[axiom_core_logic::types::SelectorPick],
        nominations: &[[u8; 32]],
    ) -> Result<[u8; 32], LambdaError> {
        debug!("CL11: Validating Console Certificate gen {} → {}", current_cert.generation, new_cert.generation);

        let inputs = PublicInputs {
            zkq_request: None,
            fact_certificates: Vec::new(),
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
            receiver_witness: None,
            receiver_signing_key: None,
            recall_attestation: None,
            fob_claim_attestation: None,
            claimant_vbc: None,
            mode: CoreLogicMode::CL11,
            oods_attestation: None,
            local_core_id: self.avm_config.core_id,
            transaction: serde_json::from_str(
                r#"{"consumed_state_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"client_pk":[],"wallet_seq":0,"receiver_wallet_id":"","amount":0,"reference":"","nonce":0,"epoch":0,"client_sig":[]}"#
            ).map_err(|e| LambdaError::CoreExecutionError(format!("TX stub: {}", e)))?,
            prev_receipts: vec![],
            current_state: None,
            vbc_bundle: None,
            my_validator_pk: None,
            overlapped_signatures: vec![],
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            group_member_index: None,
            sender_fact_chain: None,
            max_fact_links: if self.max_fact_links > 0 { Some(self.max_fact_links as u32) } else { None },
            receiver_fact_chain: None,
            my_dilithium_sk: None,
            my_dilithium_pk: None,
            my_validator_id: None,
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            zkp_nonce: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: Some(current_cert.clone()),
            console_new_cert: Some(new_cert.clone()),
            console_selector_picks: Some(selector_picks.to_vec()),
            console_nominations: Some(nominations.to_vec()),
            txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
        
        };

        let outputs = self.execute_avm(inputs)?;

        match outputs.result {
            ValidationResult::Accept => {
                let hash = outputs.console_chain_hash.ok_or_else(|| {
                    LambdaError::CoreExecutionError("CL11 accepted but no chain hash returned".to_string())
                })?;
                info!("CL11: Console Certificate gen {} accepted, chain hash: {}",
                    new_cert.generation, hex::encode(hash));
                Ok(hash)
            }
            ValidationResult::Reject | ValidationResult::Fatal => {
                let reason = outputs.rejection_reason
                    .map(|r| format!("{}", r))
                    .unwrap_or_else(|| "unknown".to_string());
                Err(LambdaError::CoreExecutionError(format!("CL11 rejected: {}", reason)))
            }
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: construct PublicOutputs for testing check_proof_outputs
    /// Helper: construct ZkpCheckpointOutputs for testing check_proof_outputs.
    /// Retyped 2026-09-02 with the function it tests — the guest commits a
    /// checkpoint, so a PublicOutputs fixture here tested a shape the verifier
    /// never sees.
    fn make_outputs(
        result: ValidationResult,
        rejection_reason: Option<axiom_core_logic::types::ValidationError>,
        zkp_nonce_hash: Option<[u8; 32]>,
    ) -> axiom_core_logic::ZkpCheckpointOutputs {
        axiom_core_logic::ZkpCheckpointOutputs {
            input_hash: [0u8; 32],
            result,
            produced_state_id: None,
            new_balance: None,
            new_wallet_seq: None,
            zkp_nonce_hash,
            rejection_reason,
            fact_signature: None,
            txid: None,
        }
    }

    /// Helper: compute BLAKE3("AXIOM_ZKP_NONCE" || nonce)
    fn compute_nonce_hash(nonce: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_ZKP_NONCE");
        h.update(nonce);
        *h.finalize().as_bytes()
    }

    // ========================================================================
    // check_proof_outputs logic tests (no real STARK proofs needed)
    // ========================================================================

    /// Layer 2: Valid STARK proof of Reject → still rejected
    #[test]
    fn test_production_reject_result_fails() {
        let outputs = make_outputs(
            ValidationResult::Reject,
            Some(axiom_core_logic::types::ValidationError::InvalidClientSignature),
            None,
        );
        let result = check_proof_outputs(&outputs, None);
        assert!(result.is_err(), "Valid proof of Reject must be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("logic rejected"), "Error should say 'logic rejected': {}", err);
    }

    /// Layer 2: Fatal result → also rejected
    #[test]
    fn test_production_fatal_result_fails() {
        let outputs = make_outputs(ValidationResult::Fatal, None, None);
        let result = check_proof_outputs(&outputs, None);
        assert!(result.is_err(), "Fatal result must be rejected");
    }

    /// Layer 3: Nonce mismatch → rejected (anti-replay)
    #[test]
    fn test_production_nonce_mismatch_rejected() {
        let nonce_a = [0x42u8; 32];
        let nonce_b = [0x99u8; 32];
        let hash_a = compute_nonce_hash(&nonce_a);

        let outputs = make_outputs(ValidationResult::Accept, None, Some(hash_a));
        // Verify with nonce_b (wrong) → mismatch
        let result = check_proof_outputs(&outputs, Some(&nonce_b));
        assert!(result.is_err(), "Wrong nonce must be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("nonce binding mismatch"), "Error: {}", err);
    }

    /// Layer 3: Missing nonce hash when expected → rejected
    #[test]
    fn test_production_missing_nonce_hash_rejected() {
        let nonce = [0x42u8; 32];
        let outputs = make_outputs(ValidationResult::Accept, None, None);
        let result = check_proof_outputs(&outputs, Some(&nonce));
        assert!(result.is_err(), "Missing nonce hash must be rejected when nonce expected");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("nonce binding mismatch"), "Error: {}", err);
    }

    /// Layer 2+3: Accept with correct nonce → passes
    #[test]
    fn test_production_accept_with_correct_nonce() {
        let nonce = [0x42u8; 32];
        let hash = compute_nonce_hash(&nonce);
        let outputs = make_outputs(ValidationResult::Accept, None, Some(hash));
        let result = check_proof_outputs(&outputs, Some(&nonce));
        assert!(result.is_ok(), "Accept with correct nonce must pass: {:?}", result);
    }

    /// Accept without nonce check → passes (backwards compat)
    #[test]
    fn test_production_accept_no_nonce() {
        let outputs = make_outputs(ValidationResult::Accept, None, None);
        let result = check_proof_outputs(&outputs, None);
        assert!(result.is_ok(), "Accept without nonce must pass");
    }

    // ========================================================================
    // ProofType and DMAP integration tests
    // ========================================================================

    /// ProofType discriminator values match wire protocol
    #[test]
    fn test_proof_type_values() {
        assert_eq!(ProofType::Zkp as u8, 0);
        assert_eq!(ProofType::Dmap as u8, 1);
    }

    /// Minimal native `PublicOutputs` for `WitnessProof` fixtures.
    ///
    /// Deliberately separate from `make_outputs` (2026-09-02): `WitnessProof
    /// .outputs` is the NATIVE Core result and is genuinely a `PublicOutputs`,
    /// while `check_proof_outputs` reads a zkVM JOURNAL, which is a
    /// `ZkpCheckpointOutputs`. Same-looking values, different provenance —
    /// collapsing them into one helper is what made the wrong-type decode look
    /// reasonable for months.
    pub(super) fn make_native_outputs(result: ValidationResult) -> PublicOutputs {
        PublicOutputs {
            zkp_qualification: None,
            sender_state: None,
            ark_send_fact_chain: None,
            oods_flag: None,
            confidence_index: None,
            hibernation_until: 0,
            // §5.2.2c — no lock on a plain witness result. Only a subsidy
            // claim's redeem stamps one (`execute_cl5`).
            wall_clock_lock: 0,
            emission_claimed_epoch: 0,
            stake_floor_until: 0, wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            result,
            rejection_reason: None,
            produced_state_id: None,
            new_state_hash: None,
            new_wallet_seq: None,
            is_overlapped: None,
            txid: None,
            new_balance: None,
            commitment_hash: None,
            nbc_signature: None,
            fact_signature: None,
            zkp_nonce_hash: None,
            required_k: 0,
            extracted_proof_type: 0,
            audit_demand: None,
            audit_request: None,
            nonce_challenge: None,
            pulse_proof: None,
            audit_failed: false,
            fanout_new_ttl: None,
            console_chain_hash: None,
            compressed_fact_chain: None,
            receipt_commitment: None,
            receiver_fact_chain: None,
            is_dev_class: None,
        }
    }

    /// WitnessProof carries proof_type through
    #[test]
    fn test_witness_proof_carries_proof_type() {
        let proof_zkp = WitnessProof {
            outputs: make_native_outputs(ValidationResult::Accept),
            zkp_receipt: None,
            execution_proof_bytes: vec![0xAA],
            proof_type: ProofType::Zkp as u8,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
        };
        assert_eq!(proof_zkp.proof_type, 0);

        let proof_dmap = WitnessProof {
            outputs: make_native_outputs(ValidationResult::Accept),
            zkp_receipt: None,
            execution_proof_bytes: vec![0xBB],
            proof_type: ProofType::Dmap as u8,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
        };
        assert_eq!(proof_dmap.proof_type, 1);
    }

    /// AvmConfig from ELF bytes produces correct core_id
    #[test]
    fn test_avm_config_core_id() {
        let config = AvmConfig::from_elf(vec![0x7F, b'E', b'L', b'F']);
        assert_eq!(config.core_id, *blake3::hash(&[0x7F, b'E', b'L', b'F']).as_bytes());
    }

    /// DmapAttestation serializes to CBOR (wire format for execution_proof_bytes).
    /// CBOR preserves byte fields as major-type-2 (signature: Vec<u8> stays
    /// as Bytes, not coerced to integer-array as JSON would do).
    #[test]
    fn test_dmap_attestation_cbor_roundtrip() {
        let att = DmapAttestation {
            core_id: [0xAA; 32],
            input_hash: [0xBB; 32],
            output_hash: [0xCC; 32],
            total_checkpoints: 50,
            checkpoint_commitment: [0xDD; 32],
            revealed_checkpoints: vec![],
            signature: vec![],
            tick: 1710000000,
            validator_pk: [0x01; 32],
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&att, &mut buf).unwrap();
        let decoded: DmapAttestation = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.core_id, [0xAA; 32]);
        assert_eq!(decoded.total_checkpoints, 50);
        assert_eq!(decoded.tick, 1710000000);
    }

    // ========================================================================
    // Full pipeline tests require zkVM artifacts.
    // Run with: cargo test -p axiom-lambda --features zkp -- --ignored
    // ========================================================================

    // DELETED 2026-09-02: `mod production_stark` in full. Its five #[ignore]d
    // tests went in cc3573ac with `ZkvmProver::prove()`; these helpers
    // (`verify_and_check`, `make_accept_inputs`, `make_reject_inputs`) were
    // left behind and called the now-deleted `ZkvmVerifier::verify()`.
    // See that commit for what the tests were meant to assert and why
    // rebuilding them belongs on the `prove_checkpoint` contract.

    // ========================================================================
    // Core logic tests (existing)
    // ========================================================================

    /// ZKP nonce hash computed correctly in Core's execute_core()
    #[test]
    fn test_zkp_nonce_hash_computed() {
        use axiom_core_logic::execute_core;

        let nonce = [0x42u8; 32];
        let inputs = axiom_core_logic::PublicInputs {
            zkq_request: None,
            fact_certificates: Vec::new(),
            receiver_witness: None,
            receiver_signing_key: None,
            recall_attestation: None,
            fob_claim_attestation: None,
            claimant_vbc: None,
            oods_attestation: None,
            mode: axiom_core_logic::CoreLogicMode::CL1,
            local_core_id: [0u8; 32],
            transaction: axiom_core_logic::types::Transaction {
                recall_target_tx_id: None,
                consumed_state_id: [0u8; 32],
                client_pk: vec![0u8; 32],
                sender_wallet_id: String::new(),
                wallet_seq: 0,
                receiver_wallet_id: String::new(),
                receiver_address: None,
                amount: 0,
                reference: String::new(),
                nonce: 0,
                epoch: 0,
                client_sig: vec![],
                scar_passcode: None,
                burn_target_tx_id: None,
                required_k: 0,
                proof_type: 0,
                oracle_claim: None,
                core_version: String::new(),
                core_id: [0u8; 32],
                kind: TxKind::Normal,
            },
            prev_receipts: vec![],
            current_state: None,
            vbc_bundle: None,
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            my_validator_pk: None,
            overlapped_signatures: vec![],
            group_member_index: None,
            sender_fact_chain: None,
            max_fact_links: None,
            receiver_fact_chain: None,
            my_dilithium_sk: None,
            my_dilithium_pk: None,
            my_validator_id: None,
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            zkp_nonce: Some(nonce),
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
        
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
        };

        let outputs = execute_core(inputs);

        let expected_hash = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_ZKP_NONCE");
            h.update(&nonce);
            *h.finalize().as_bytes()
        };

        assert_eq!(
            outputs.zkp_nonce_hash,
            Some(expected_hash),
            "Core should compute BLAKE3 hash of nonce"
        );
    }

    /// No nonce → no hash (backwards compat)
    #[test]
    fn test_zkp_nonce_none_no_hash() {
        use axiom_core_logic::execute_core;

        let inputs = axiom_core_logic::PublicInputs {
            zkq_request: None,
            fact_certificates: Vec::new(),
            receiver_witness: None,
            receiver_signing_key: None,
            recall_attestation: None,
            fob_claim_attestation: None,
            claimant_vbc: None,
            oods_attestation: None,
            mode: axiom_core_logic::CoreLogicMode::CL1,
            local_core_id: [0u8; 32],
            transaction: axiom_core_logic::types::Transaction {
                recall_target_tx_id: None,
                consumed_state_id: [0u8; 32],
                client_pk: vec![0u8; 32],
                sender_wallet_id: String::new(),
                wallet_seq: 0,
                receiver_wallet_id: String::new(),
                receiver_address: None,
                amount: 0,
                reference: String::new(),
                nonce: 0,
                epoch: 0,
                client_sig: vec![],
                scar_passcode: None,
                burn_target_tx_id: None,
                required_k: 0,
                proof_type: 0,
                oracle_claim: None,
                core_version: String::new(),
                core_id: [0u8; 32],
                kind: TxKind::Normal,
            },
            prev_receipts: vec![],
            current_state: None,
            vbc_bundle: None,
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            my_validator_pk: None,
            overlapped_signatures: vec![],
            group_member_index: None,
            sender_fact_chain: None,
            max_fact_links: None,
            receiver_fact_chain: None,
            my_dilithium_sk: None,
            my_dilithium_pk: None,
            my_validator_id: None,
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            zkp_nonce: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
        
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
        };

        let outputs = execute_core(inputs);
        assert_eq!(
            outputs.zkp_nonce_hash,
            None,
            "No nonce → no hash (backwards compat)"
        );
    }

    /// WitnessRequest CL1 proof field serde roundtrip
    #[test]
    fn test_witness_request_cl1_proof_serde() {
        use crate::types::WitnessRequest;
        let proof_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let request = WitnessRequest {
            fact_certificates: Vec::new(),
            scar_consent_voucher: None,
            recall_attestation: None,
            fob_claim_attestation: None,
            claimant_vbc: None,
            oods_attestation: None,
            request_id: "test".to_string(),
            transaction: axiom_core_logic::types::Transaction {
                recall_target_tx_id: None,
                consumed_state_id: [0u8; 32],
                client_pk: vec![0u8; 32],
                sender_wallet_id: String::new(),
                wallet_seq: 0,
                receiver_wallet_id: "test".to_string(),
                receiver_address: None,
                amount: 0,
                reference: String::new(),
                nonce: 0,
                epoch: 0,
                client_sig: vec![],
                scar_passcode: None,
                burn_target_tx_id: None,
                required_k: 0,
                proof_type: 0,
                oracle_claim: None,
                core_version: String::new(),
                core_id: [0u8; 32],
                kind: TxKind::Normal,
            },
            overlapped_signatures: vec![],
            prev_receipts: vec![],
            claimed_balance_for_sabr: 0,
            claimed_hibernation_until: 0,
            claimed_wall_clock_lock: 0,
            claimed_emission_claimed_epoch: 0,
            claimed_stake_floor_until: 0,
            claimed_wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            requester_address: String::new(),
            offered_fee: 0,
            validator_hints: vec![],
            produced_state_id: None,
            commitment_hash: None,
            group_member_index: None,
            sender_fact_chain: None,
            cl1_execution_proof: proof_bytes.clone(),
            auth_hash: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            clara_attestation: None,
            nabla_hint: None,
            vbc_request: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let decoded: WitnessRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.cl1_execution_proof, proof_bytes);
    }

    /// ValidatorCheque carries proof bytes and nonce
    #[test]
    fn test_cheque_proof_attached() {
        let cheque = axiom_core_logic::types::ValidatorCheque {
            fact_certificates: Vec::new(),
            recall_target_tx_id: None,
            txid: [0x01; 32],
            validator_id: [0x00; 32],
            amount: 1000,
            rate_bps: 10,
            receiver_wallet_id: "test".to_string(),
            sender_wallet_id: "sender".to_string(),
            validator_pk: vec![0x02; 32],
            signature: vec![0x03; 64],
            state_hash: [0x04; 32],
            produced_state_id: [0x05; 32],
            execution_proof: vec![0xAA, 0xBB, 0xCC],
            vbc_bundle: None,
            carrier_type: "email".to_string(),
            carrier_address: "test@test.com".to_string(),
            reference: "ref".to_string(),
            epoch: 1,
            created_at: 0,
            sender_fact_chain: None,
            zkp_nonce: Some([0xDD; 32]),
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        };

        assert_eq!(cheque.execution_proof, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(cheque.zkp_nonce, Some([0xDD; 32]));

        let json = serde_json::to_string(&cheque).unwrap();
        let decoded: axiom_core_logic::types::ValidatorCheque = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.execution_proof, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(decoded.zkp_nonce, Some([0xDD; 32]));
    }

    /// PublicOutputs nonce hash roundtrip via JSON
    #[test]
    fn test_zkp_nonce_hash_json_roundtrip() {
        let hash = [0x77u8; 32];
        let outputs = axiom_core_logic::PublicOutputs {
            zkp_qualification: None,
            sender_state: None,
            ark_send_fact_chain: None,
            oods_flag: None,
            confidence_index: None,
            hibernation_until: 0,
            wall_clock_lock: 0,
            emission_claimed_epoch: 0,
            stake_floor_until: 0, wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            result: axiom_core_logic::ValidationResult::Accept,
            produced_state_id: None,
            new_state_hash: None,
            new_wallet_seq: None,
            is_overlapped: None,
            txid: None,
            new_balance: None,
            commitment_hash: None,
            rejection_reason: None,
            nbc_signature: None,
            fact_signature: None,
            zkp_nonce_hash: Some(hash),
            required_k: 0,
            extracted_proof_type: 0,
            audit_demand: None,
            audit_request: None,
            nonce_challenge: None,
            pulse_proof: None,
            audit_failed: false,
            fanout_new_ttl: None,
            console_chain_hash: None,
            compressed_fact_chain: None,
            receipt_commitment: None,
            receiver_fact_chain: None,
            is_dev_class: None,
        };

        let json = serde_json::to_string(&outputs).unwrap();
        let decoded: axiom_core_logic::PublicOutputs = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.zkp_nonce_hash, Some(hash), "zkp_nonce_hash should survive JSON roundtrip");
    }
}
// force rebuild

#[cfg(test)]
mod pulse_reject_tests {
    use super::*;

    /// YPX-009 §7.2: the refusal fires on `audit_failed` and on nothing else.
    /// Both arms are driven; mutate the predicate and one of them goes red.
    #[test]
    fn a_failed_self_audit_refuses_the_execution_and_a_passed_one_does_not() {
        let mut outputs = super::tests::make_native_outputs(ValidationResult::Accept);
        assert!(refuse_if_audit_failed(&outputs, "CL3 finalize").is_ok());
        outputs.audit_failed = true;
        match refuse_if_audit_failed(&outputs, "CL5 redeem") {
            Err(LambdaError::PulseAuditFailed(label)) => assert_eq!(label, "CL5 redeem"),
            other => panic!("expected PulseAuditFailed, got {:?}", other.map(|_| ())),
        }
        let sink = PulseSink::default();
        sink.absorb(&outputs, "CL5 redeem");
        assert_eq!(sink.audit_failures(), 1, "the refusal is COUNTED, not only logged");
    }
}

