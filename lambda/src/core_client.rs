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
fn check_proof_outputs(
    outputs: &PublicOutputs,
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
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_ZKP_NONCE");
            h.update(expected_nonce);
            *h.finalize().as_bytes()
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
        Ok(Self { avm_config, avm, prover: None, program_digest: [0u8; 32], max_fact_links: 0 })
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

    /// Execute core validation via persistent AVM interpreter.
    ///
    /// Returns PublicOutputs from the AVM execution.
    /// Uses the persistent AVM — audit buffer and wallet cache carry across TXs.
    fn execute_avm(&self, inputs: PublicInputs) -> Result<PublicOutputs, LambdaError> {
        let result = self.avm.execute(inputs)
            .map_err(|e| LambdaError::CoreExecutionError(format!("AVM: {}", e)))?;
        Ok(result)
    }

    fn execute_avm_cl5_with_capture(&self, inputs: PublicInputs) -> Result<PublicOutputs, LambdaError> {
        let input_bytes = serde_json::to_vec(&inputs).unwrap_or_default();
        let result = self.avm.execute(inputs)
            .map_err(|e| LambdaError::CoreExecutionError(format!("AVM: {}", e)));
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
    fn execute_avm_with_dmap(&self, inputs: PublicInputs) -> Result<axiom_dmap_vm::AvmExecutionResult, LambdaError> {
        let result = self.avm.execute_with_dmap(inputs)
            .map_err(|e| LambdaError::CoreExecutionError(format!("AVM DMAP: {}", e)))?;
        Ok(result)
    }

    // ========================================================================
    // CL2: Validator Core In — THE authoritative S-ABR + attestation gate
    // ========================================================================

    /// Run Core CL2 on an incoming witness request.
    ///
    /// CL2 is "Validator Core In": Core verifies the transaction against the
    /// supplied state view, verifies the CLARA attestation (Ed25519 + NBC
    /// trust anchor + eligibility + synthetic roll-forward), verifies the
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
    ) -> Result<PublicOutputs, LambdaError> {
        debug!("CL2: authoritative S-ABR + attestation gate (recall_att={}, clara_att={})",
               envelope.recall_attestation.is_some(), envelope.clara_attestation.is_some());

        let inputs = PublicInputs {
            mode: CoreLogicMode::CL2,
            local_core_id: self.avm_config.core_id,
            withdrawal_inputs: None,
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            nonce_response: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
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
    ) -> Result<WitnessProof, LambdaError> {
        debug!("CL3: Producing witness proof (real ZKP)");

        let inputs = PublicInputs {
            recall_attestation: None,
            mode: CoreLogicMode::CL3,
            local_core_id: self.avm_config.core_id,
            withdrawal_inputs: None,
            // ── Envelope-sourced fields ───────────────────────────
            transaction: envelope.transaction.clone(),
            prev_receipts: envelope.prev_receipts.clone(),
            overlapped_signatures: envelope.overlapped_signatures.clone(),
            group_member_index: envelope.group_member_index.map(|i| i as u32),
            sender_fact_chain: envelope.sender_fact_chain.clone(),
            audit_confirmation: envelope.audit_confirmation.clone(),
            audit_response: envelope.audit_response.clone(),
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            nonce_response: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
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

        // Execute via AVM interpreter — Core handles FACT signing + compression inside AVM
        let outputs = self.execute_avm(inputs.clone())?;

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

                // Prove via subprocess (prover-worker) — completely isolated
                // from Tokio's runtime, no Rayon deadlock possible.
                let prover = self.prover.as_mut()
                    .ok_or_else(|| LambdaError::CoreExecutionError(
                        "ZKP prover not initialized — call enable_zkp() or set proof.mode = \"dmap\"".into()
                    ))?;
                let (zkp_checkpoint, receipt) = prover.prove(zkvm_inputs, Some(outputs.clone()))
                    .map_err(|e| LambdaError::CoreExecutionError(format!("zkVM prove: {}", e)))?;

                if zkp_checkpoint.produced_state_id != outputs.produced_state_id {
                    return Err(LambdaError::CoreExecutionError(
                        "zkVM/AVM state_id mismatch — determinism failure".into()
                    ));
                }

                let proof_bytes = receipt.to_bytes();
                debug!("CL3: Real ZKP generated ({} bytes)", proof_bytes.len());
                let (zkp_receipt, execution_proof_bytes) = (Some(receipt), proof_bytes);

                Ok(WitnessProof {
                    outputs,
                    zkp_receipt,
                    execution_proof_bytes,
                    proof_type: ProofType::Zkp as u8,
                    dmap_input_hash: [0u8; 32],  // ZKP path: STARK proof is the verification, not DMAP
                    dmap_output_hash: [0u8; 32],
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
    ) -> Result<WitnessProof, LambdaError> {
        debug!("CL3: Producing witness proof (DMAP attestation, single-pass)");

        // Locals for readability; every binding is `envelope.<field>`.
        let transaction = &envelope.transaction;

        // Debug: check owner_proof before sending to Core
        if transaction.owner_proof.is_none() {
            let has_auth = wallet_state.and_then(|ws| ws.auth_hash).is_some();
            eprintln!("[OWNER_PROOF_DEBUG] DMAP CL3: owner_proof=None, wallet has_auth_hash={}, wseq={}",
                has_auth, transaction.wallet_seq);
        }

        // Extract validator_pk for DMAP challenge derivation before it's moved into PublicInputs
        let dmap_validator_pk: [u8; 32] = my_validator_pk.as_deref()
            .and_then(|pk| <[u8; 32]>::try_from(pk).ok())
            .unwrap_or([0u8; 32]);

        let inputs = PublicInputs {
            recall_attestation: None,
            mode: CoreLogicMode::CL3,
            local_core_id: self.avm_config.core_id,
            withdrawal_inputs: None,
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
            audit_response: envelope.audit_response.clone(),
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            nonce_response: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
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
        let avm_result = self.execute_avm_with_dmap(inputs)?;
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

                let execution_proof_bytes = if let Some(ref trace) = avm_result.dmap_trace {
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
                    // AUDIT-FIX v2.11.14: Sign the attestation with validator's Ed25519 key.
                    // Without this, verify_dmap_attestation rejects as InvalidSignature.
                    if let Some(sk) = my_signing_key {
                        use ed25519_dalek::Signer;
                        let payload = attestation.signing_payload();
                        let sig = sk.sign(&payload);
                        attestation.set_signature(sig.to_bytes().to_vec());
                    }
                    debug!("CL3: DMAP attestation built ({} checkpoints, ~{} bytes, signed={})",
                        attestation.total_checkpoints, attestation.estimated_size(),
                        !attestation.signature.is_empty());
                    // CBOR (not JSON) — DmapAttestation carries a Dilithium
                    // signature (3309 bytes) and Merkle proof bytes inside
                    // RevealedCheckpoint. JSON's int-array coercion of
                    // Vec<u8>/[u8; 32] silently shifts byte-string semantics
                    // on round-trip; CLAUDE.md §13 forbids that. All
                    // readers (consensus.rs:4958, consensus.rs:5065,
                    // core_client.rs:667) decode CBOR to match.
                    {
                        let mut buf = Vec::new();
                        ciborium::ser::into_writer(&attestation, &mut buf)
                            .map_err(|e| LambdaError::CoreExecutionError(
                                format!("DMAP serialize: {}", e)
                            ))?;
                        buf
                    }
                } else {
                    // Native mode (no riscv-interpreter): no trace available.
                    warn!("CL3: DMAP requested but no trace collected (riscv-interpreter not enabled)");
                    vec![]
                };

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
        // Chain pointers Lambda resolves before calling Core.
        sender_fact_chain: Option<FactChain>,
        receiver_state_id: Option<[u8; 32]>,
        receiver_fact_chain: Option<FactChain>,
        // Lambda's own crypto material.
        my_dilithium_sk: Option<Vec<u8>>,
        my_dilithium_pk: Option<Vec<u8>>,
        my_validator_id: Option<[u8; 32]>,
        vbc_bundle: Option<axiom_core_logic::types::VBCProofBundle>,
    ) -> Result<RedeemProof, LambdaError> {
        // Sanity binding — Core CL5 reads `inputs.receiver_pk` and
        // `inputs.cheque_bundle`; both are envelope-sourced. We hold
        // these as locals to keep the `PublicInputs` literal readable;
        // every assignment below is a direct `envelope.<field>` clone.
        let cheque_bundle = &envelope.cheque_bundle;
        let receiver_pk = envelope.receiver_pk.as_slice();
        debug!("CL5: Validating redeem request via AVM");

        let inputs: PublicInputs = PublicInputs {
            recall_attestation: None,
            mode: CoreLogicMode::CL5,
            local_core_id: self.avm_config.core_id,
            withdrawal_inputs: None,
            transaction: Transaction {
                recall_target_tx_id: None,
                consumed_state_id: [0u8; 32],
                client_pk: vec![],
                sender_wallet_id: String::new(),
                wallet_seq: 0,
                receiver_wallet_id: String::new(),
                receiver_address: None,
                amount: 0,
                reference: String::new(),
                nonce: 0,
                epoch: 0,
                client_sig: vec![],
                owner_proof: None,
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
            current_state: receiver_state_id.map(|sid| axiom_core_logic::types::WalletState { public_key: receiver_pk.to_vec(), balance: current_balance, wallet_seq: current_seq, state_id: sid, auth_hash: None, hibernation_until: envelope.current_state.as_ref().map(|s| s.hibernation_until).unwrap_or(0), wallet_id: None, group_members: None }),
            vbc_bundle,
            // ── Envelope-sourced fields ───────────────────────────
            // EVERY assignment in this block is `envelope.<field>` —
            // no per-arg shadow, no `Vec::new()` defaults. A new
            // envelope field flows through here ONCE, then ships to
            // Core CL5 automatically.
            cheque_bundle: Some(cheque_bundle.clone()),
            receiver_pk: Some(receiver_pk.to_vec()),
            txid_attestation: envelope.txid_attestation.clone(),
            oods_attestation: envelope.oods_attestation.clone(), // YPX-021 §8.2 — forward verbatim
            cheque_claim_proof: envelope.cheque_claim_proof.clone(),
            fact_witness_sigs: envelope.fact_witness_sigs.clone(),
            // YPX-020 §2: the receiver's CURRENT hibernation is ENVELOPE-SOURCED
            // (client-declared current_state, exactly like the send path's
            // claimed_hibernation_until) — NOT a Lambda-derived value. It lives
            // in THIS block on purpose: Core CL5 carries it through on a stranger
            // redeem and clears it on a self-redeem, binding it into the produced
            // state_hash. Hardcoding it None/0 (the 2026-06-24 stranger-redeem
            // brick) is exactly what this placement prevents.
            receiver_current_hibernation: envelope.current_state.as_ref().map(|s| s.hibernation_until),
            // fee_breakdown deleted from the wire envelope 2026-06-05 PM.
            // Core CL5 derives total_fee from the cheques' bound rate_bps.
            // ── Lambda-derived values ─────────────────────────────
            receiver_current_balance: Some(current_balance),
            receiver_wallet_seq: Some(current_seq),
            receiver_new_balance: Some(new_balance),
            receiver_new_state_id: None, // Core computes this
            sender_fact_chain,
            receiver_fact_chain,
            max_fact_links: if self.max_fact_links > 0 { Some(self.max_fact_links as u32) } else { None },
            my_dilithium_sk,
            my_dilithium_pk,
            my_validator_id,
            my_validator_pk: None,
            // ── Modes not applicable to CL5-redeem ────────────────
            overlapped_signatures: vec![],
            group_member_index: None,
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            zkp_nonce: None,
            audit_confirmation: None,
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
        };

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

        match verifier.verify(&receipt) {
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
    // YPX-009: Ignition TX — ZKVM round-trip benchmark at startup
    // ========================================================================

    /// Run the ignition TX sequence (YPX-009 §8.4).
    ///
    /// This is the full pipeline benchmark:
    /// 1. Build synthetic ignition TX
    /// 2. Core processes it (AVM records t0)
    /// 3. Lambda generates ZKVM proof (real STARK)
    /// 4. Core verifies proof + measures round-trip (AVM records t1, computes delta)
    /// 5. Core determines hardware tier from BLAKE3 benchmark
    /// 6. Core unblocks (pulse_ready = true)
    ///
    /// Called at Lambda startup when `pulse-gate` is enabled.
    /// This is also the restart penalty — when Core self-terminates due to
    /// pulse audit failure, restart requires a new ignition TX.
    pub fn ignite(&mut self) -> Result<(), LambdaError> {
        info!("YPX-009: Starting ignition TX sequence");

        // 1. Build synthetic ignition TX — minimal valid CL1 transaction
        let ignition_inputs = PublicInputs {
            recall_attestation: None,
            mode: CoreLogicMode::CL1,
            oods_attestation: None,
            local_core_id: self.avm_config.core_id,
            withdrawal_inputs: None,
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
                owner_proof: None,
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
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
        
        };

        // 2. Core processes ignition TX (records t0, bypasses pulse gate)
        let outputs = self.avm.process_ignition(ignition_inputs.clone())
            .map_err(|e| LambdaError::CoreExecutionError(format!("Ignition TX: {}", e)))?;

        info!("YPX-009: Ignition TX processed (result={:?}), generating ZKVM proof", outputs.result);

        // 3. Lambda generates ZKVM proof through full pipeline
        let proof_bytes = if let Some(ref mut prover) = self.prover {
            // Real ZKVM prover available — generate STARK proof
            let (_, receipt) = prover.prove(ignition_inputs, Some(outputs))
                .map_err(|e| LambdaError::CoreExecutionError(format!("Ignition ZKVM prove: {}", e)))?;
            receipt.to_bytes()
        } else {
            // DMAP mode — no ZKVM prover. Use DMAP attestation as proof.
            // The ignition still works: Core measures the AVM execution round-trip.
            let input_hash = *blake3::hash(&b"AXIOM_IGNITION_DMAP"[..]).as_bytes();
            input_hash.to_vec()
        };

        // 4. Core verifies proof + measures round-trip + determines tier + unblocks
        self.avm.complete_ignition(&proof_bytes)
            .map_err(|e| LambdaError::CoreExecutionError(format!("Ignition complete: {}", e)))?;

        info!("YPX-009: Ignition complete — Core is ready to serve");
        Ok(())
    }

    /// CL11: Validate a new Console Certificate via Core.
    ///
    /// Core verifies chain integrity, election resolution, and seat validity.
    /// Returns the chain hash on success (used to store the certificate).
    pub fn validate_console_certificate(
        &self,
        current_cert: &axiom_core_logic::types::ConsoleCertificate,
        new_cert: &axiom_core_logic::types::ConsoleCertificate,
        selector_picks: &[axiom_core_logic::types::SelectorPick],
        nominations: &[[u8; 32]],
    ) -> Result<[u8; 32], LambdaError> {
        debug!("CL11: Validating Console Certificate gen {} → {}", current_cert.generation, new_cert.generation);

        let inputs = PublicInputs {
            recall_attestation: None,
            mode: CoreLogicMode::CL11,
            oods_attestation: None,
            local_core_id: self.avm_config.core_id,
            withdrawal_inputs: None,
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            candidate_balance: None,
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

    /// CL13: Validate a validator-withdrawal mint via Core's AVM.
    ///
    /// Builds the CL13 PublicInputs from the operator-submitted withdrawal
    /// proof, executes through the AVM interpreter, and returns the raw
    /// PublicOutputs. Callers (`process_withdrawal_mint_witness`) decide
    /// what to do with Accept (sign the mint commitment) vs Reject
    /// (surface the rejection reason).
    pub fn execute_cl13(
        &self,
        withdrawal: &axiom_core_logic::wire_client::ValidatorWithdrawalRequest,
    ) -> Result<PublicOutputs, LambdaError> {
        let inputs = PublicInputs {
            recall_attestation: None,
            mode: CoreLogicMode::CL13,
            oods_attestation: None,
            local_core_id: self.avm_config.core_id,
            withdrawal_inputs: Some(withdrawal.clone()),
            // CL13 doesn't read any of the standard tx-pipeline fields.
            // Use explicit `Transaction::default()` rather than a hand-
            // rolled JSON stub (avoids the parser overhead and mirrors
            // the CL10 fan-out path).
            transaction: axiom_core_logic::types::Transaction::default(),
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
            nabla_stake_proof: None,
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
        self.execute_avm(inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: construct PublicOutputs for testing check_proof_outputs
    fn make_outputs(
        result: ValidationResult,
        rejection_reason: Option<axiom_core_logic::types::ValidationError>,
        zkp_nonce_hash: Option<[u8; 32]>,
    ) -> PublicOutputs {
        PublicOutputs {
            oods_flag: None,
            hibernation_until: 0,
            result,
            rejection_reason,
            produced_state_id: None,
            new_state_hash: None,
            new_wallet_seq: None,
            is_overlapped: None,
            txid: None,
            new_balance: None,
            commitment_hash: None,
            nbc_signature: None,
            fact_signature: None,
            zkp_nonce_hash,
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
            validator_withdrawal_mint: None,
            receiver_fact_chain: None,
            is_dev_class: None,
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

    /// WitnessProof carries proof_type through
    #[test]
    fn test_witness_proof_carries_proof_type() {
        let proof_zkp = WitnessProof {
            outputs: make_outputs(ValidationResult::Accept, None, None),
            zkp_receipt: None,
            execution_proof_bytes: vec![0xAA],
            proof_type: ProofType::Zkp as u8,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
        };
        assert_eq!(proof_zkp.proof_type, 0);

        let proof_dmap = WitnessProof {
            outputs: make_outputs(ValidationResult::Accept, None, None),
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

    #[cfg(feature = "zkp")]
    mod production_stark {
        use super::*;

        /// Helper: verify receipt and check outputs
        fn verify_and_check(
            verifier: &axiom_zk_vm::ZkvmVerifier,
            receipt: &axiom_zk_vm::ZkvmReceipt,
            expected_zkp_nonce: Option<&[u8; 32]>,
        ) -> Result<bool, LambdaError> {
            match verifier.verify(receipt) {
                Ok(outputs) => {
                    check_proof_outputs(&outputs, expected_zkp_nonce)?;
                    Ok(true)
                }
                Err(e) => {
                    Err(LambdaError::CoreValidationFailed(format!("CL1 ZKP invalid: {}", e)))
                }
            }
        }

        /// Create CL1 inputs that will produce Accept (properly signed TX)
        fn make_accept_inputs(nonce: Option<[u8; 32]>) -> axiom_core_logic::PublicInputs {
            let sender = axiom_test_utils::TestWallet::generate("sender@test.com", 1_000_000);
            let receiver = axiom_test_utils::TestWallet::generate("receiver@test.com", 0);
            let tx = sender.create_transaction(&receiver.address(), 100_000, "test", 42);
            axiom_core_logic::PublicInputs {
                recall_attestation: None,
                oods_attestation: None,
                mode: axiom_core_logic::CoreLogicMode::CL1,
                local_core_id: [0u8; 32],
                withdrawal_inputs: None,
                transaction: tx,
                prev_receipts: vec![],
                current_state: Some(sender.wallet_state()),
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
                zkp_nonce: nonce,
                audit_confirmation: None,
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
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

        /// Create CL1 inputs that will produce Reject (invalid signature)
        fn make_reject_inputs() -> axiom_core_logic::PublicInputs {
            axiom_core_logic::PublicInputs {
                recall_attestation: None,
                oods_attestation: None,
                mode: axiom_core_logic::CoreLogicMode::CL1,
                local_core_id: [0u8; 32],
                withdrawal_inputs: None,
                transaction: axiom_core_logic::types::Transaction {
                    recall_target_tx_id: None,
                    consumed_state_id: [0u8; 32],
                    client_pk: vec![0u8; 32],
                    sender_wallet_id: String::new(),
                    wallet_seq: 1,
                    receiver_wallet_id: "test@example.com/abc12345".into(),
                    receiver_address: None,
                    amount: 100_000,
                    reference: "test".into(),
                    nonce: 1,
                    epoch: 1,
                    client_sig: vec![0u8; 64],
                    owner_proof: None,
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
                current_state: Some(axiom_core_logic::types::WalletState {
                    public_key: vec![0u8; 32],
                    balance: 1_000_000,
                    wallet_seq: 0,
                    state_id: [0u8; 32],
                    auth_hash: None, hibernation_until: 0,
                    wallet_id: None,
                    group_members: None,
                }),
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
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

        /// Real STARK proof: Accept → verified successfully
        #[test]
        #[ignore] // ~20s — run with: cargo test -p axiom-lambda --features zkp -- production_stark --ignored
        fn test_production_real_stark_accept() {
            let inputs = make_accept_inputs(None);
            let mut prover = axiom_zk_vm::ZkvmProver::production()
                .expect("ZkvmProver::production() requires ~/.axiom/zkvm/ artifacts");
            let (outputs, receipt) = prover.prove(inputs).expect("Real prove failed");
            assert_eq!(outputs.result, ValidationResult::Accept, "CL1 must Accept valid TX");

            let verifier = axiom_zk_vm::ZkvmVerifier::production()
                .expect("ZkvmVerifier::production() requires artifacts");
            let verified = verifier.verify(&receipt).expect("Real verification failed");
            assert_eq!(verified.result, ValidationResult::Accept);
        }

        /// Real STARK proof: Reject → proof valid but logic rejected
        #[test]
        #[ignore]
        fn test_production_real_stark_reject_detected() {
            let inputs = make_reject_inputs();
            let mut prover = axiom_zk_vm::ZkvmProver::production()
                .expect("ZkvmProver::production() requires artifacts");
            let (outputs, receipt) = prover.prove(inputs).expect("Real prove failed");
            assert_eq!(outputs.result, ValidationResult::Reject, "Invalid sig must Reject");

            let verifier = axiom_zk_vm::ZkvmVerifier::production()
                .expect("ZkvmVerifier::production() requires artifacts");
            let result = verify_and_check(&verifier, &receipt, None);
            assert!(result.is_err(), "Valid proof of Reject must be rejected");
            let err = format!("{}", result.unwrap_err());
            assert!(err.contains("logic rejected"), "Error: {}", err);
        }

        /// Real STARK proof: tampered seal bytes → crypto verification fails
        #[test]
        #[ignore]
        fn test_production_real_stark_tampered_seal() {
            let inputs = make_accept_inputs(None);
            let mut prover = axiom_zk_vm::ZkvmProver::production()
                .expect("ZkvmProver::production() requires artifacts");
            let (_outputs, mut receipt) = prover.prove(inputs).expect("Real prove failed");

            if receipt.seal.len() > 10 {
                receipt.seal[5] ^= 0xFF;
                receipt.seal[10] ^= 0xFF;
            }

            let verifier = axiom_zk_vm::ZkvmVerifier::production()
                .expect("ZkvmVerifier::production() requires artifacts");
            let result = verify_and_check(&verifier, &receipt, None);
            assert!(result.is_err(), "Tampered seal must be rejected");
        }

        /// Real STARK proof: Accept with ZKP nonce binding → full anti-replay pipeline
        #[test]
        #[ignore]
        fn test_production_real_stark_nonce_binding() {
            let nonce: [u8; 32] = rand::random();
            let inputs = make_accept_inputs(Some(nonce));
            let mut prover = axiom_zk_vm::ZkvmProver::production()
                .expect("ZkvmProver::production() requires artifacts");
            let (outputs, receipt) = prover.prove(inputs).expect("Real prove failed");
            assert_eq!(outputs.result, ValidationResult::Accept);

            let expected_hash = compute_nonce_hash(&nonce);
            assert_eq!(outputs.zkp_nonce_hash, Some(expected_hash),
                "Core inside zkVM must compute nonce hash");

            let verifier = axiom_zk_vm::ZkvmVerifier::production()
                .expect("ZkvmVerifier::production() requires artifacts");
            let result = verify_and_check(&verifier, &receipt, Some(&nonce));
            assert!(result.is_ok(), "Accept + correct nonce must pass: {:?}", result);

            let wrong_nonce: [u8; 32] = rand::random();
            let result = verify_and_check(&verifier, &receipt, Some(&wrong_nonce));
            assert!(result.is_err(), "Different nonce must reject (anti-replay)");
            let err = format!("{}", result.unwrap_err());
            assert!(err.contains("nonce binding mismatch"), "Error: {}", err);
        }

        /// Real STARK proof: Reject with nonce → proof valid but logic rejected
        #[test]
        #[ignore]
        fn test_production_real_stark_reject_with_nonce() {
            let mut inputs = make_reject_inputs();
            let nonce: [u8; 32] = rand::random();
            inputs.zkp_nonce = Some(nonce);

            let mut prover = axiom_zk_vm::ZkvmProver::production()
                .expect("ZkvmProver::production() requires artifacts");
            let (outputs, receipt) = prover.prove(inputs).expect("Real prove failed");
            assert_eq!(outputs.result, ValidationResult::Reject);

            let expected_hash = compute_nonce_hash(&nonce);
            assert_eq!(outputs.zkp_nonce_hash, Some(expected_hash));

            let verifier = axiom_zk_vm::ZkvmVerifier::production()
                .expect("ZkvmVerifier::production() requires artifacts");
            let result = verify_and_check(&verifier, &receipt, Some(&nonce));
            assert!(result.is_err(), "Reject result must be rejected regardless of nonce");
            let err = format!("{}", result.unwrap_err());
            assert!(err.contains("logic rejected"), "Error: {}", err);
        }
    }

    // ========================================================================
    // Core logic tests (existing)
    // ========================================================================

    /// ZKP nonce hash computed correctly in Core's execute_core()
    #[test]
    fn test_zkp_nonce_hash_computed() {
        use axiom_core_logic::execute_core;

        let nonce = [0x42u8; 32];
        let inputs = axiom_core_logic::PublicInputs {
            recall_attestation: None,
            oods_attestation: None,
            mode: axiom_core_logic::CoreLogicMode::CL1,
            local_core_id: [0u8; 32],
            withdrawal_inputs: None,
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
                owner_proof: None,
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
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
            recall_attestation: None,
            oods_attestation: None,
            mode: axiom_core_logic::CoreLogicMode::CL1,
            local_core_id: [0u8; 32],
            withdrawal_inputs: None,
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
                owner_proof: None,
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
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
            scar_consent_voucher: None,
            recall_attestation: None,
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
                owner_proof: None,
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
        };

        let json = serde_json::to_string(&request).unwrap();
        let decoded: WitnessRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.cl1_execution_proof, proof_bytes);
    }

    /// ValidatorCheque carries proof bytes and nonce
    #[test]
    fn test_cheque_proof_attached() {
        let cheque = axiom_core_logic::types::ValidatorCheque {
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
            oods_flag: None,
            hibernation_until: 0,
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
            validator_withdrawal_mint: None,
            receiver_fact_chain: None,
            is_dev_class: None,
        };

        let json = serde_json::to_string(&outputs).unwrap();
        let decoded: axiom_core_logic::PublicOutputs = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.zkp_nonce_hash, Some(hash), "zkp_nonce_hash should survive JSON roundtrip");
    }
}
// force rebuild
