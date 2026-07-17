// AXIOM Lambda — validator-withdrawal verification (YP §19.6 + §20.10)
//
// Operator-driven (per-validator dashboard at :7700-7709). The validator
// queries Nabla twice (earnings + pool linkage), signs the withdrawal
// request with their SPHINCS+ key, and submits to Lambda. This module
// implements the verification: every check the validator must pass
// before the withdrawal round can be initiated.
//
// What this module does:
//   - SPHINCS+ identity binding (validator_id == BLAKE3(sphincs_pk))
//   - SPHINCS+ signature over the canonical withdrawal payload
//   - Nabla earnings attestation Ed25519 verify
//   - Pool linkage sanity (registered, matching validator_id, non-zero
//     linked_wallet_id)
//   - §20.10 conflict-of-interest check
//   - Net amount computation (gross × 90 / 100; 10% stays in DEED pool)
//
// What this module does NOT do (Step 9+):
//   - NBC chain verification of the Nabla node's signing pk. The
//     attestation's nbc_issuer_pk + nbc_signature + nbc_commitment
//     fields are present but not yet chain-walked. Pre-mainnet — every
//     Nabla node is a trusted member of the ceremony-bootstrapped mesh.
//   - The actual mint into linked_wallet_id. Requires a new protocol
//     primitive (validator-withdrawal Transaction kind) wired through
//     CL3. The dashboard surfaces "READY_TO_MINT" + the verified data
//     so a future protocol layer can complete the flow.
//   - Calling Nabla's MarkValidatorEarningsClaimed. That fires only
//     after the mint succeeds; doing it on verification would let the
//     operator pre-claim earnings they never receive.

use axiom_core_logic::wire_client::{
    EarningsEntry, QueryValidatorEarningsResponse, QueryValidatorPoolResponse,
    ValidatorWithdrawalRequest, ValidatorWithdrawalResponse,
};

/// Minimum number of distinct chosen witnesses (k=3 protocol floor).
const MIN_CHOSEN_WITNESSES: usize = 3;

/// Verify a withdrawal request. Returns a populated
/// `ValidatorWithdrawalResponse` with `status` indicating the outcome:
///
///   "VERIFIED"           — all checks pass; net amount + linkage filled in
///   "REJECTED_ID_MISMATCH"
///                       — validator_id != BLAKE3(sphincs_pk)
///   "REJECTED_WITHDRAWAL_SIG"
///                       — SPHINCS+ sig over canonical withdrawal payload
///                         doesn't verify
///   "REJECTED_EARNINGS_SIG"
///                       — Nabla's earnings Ed25519 signature doesn't verify
///   "REJECTED_NOT_AUTHORITATIVE"
///                       — earnings attestation was issued by a bloom-mode
///                         node (is_authoritative = false). Operator must
///                         query a hashmap-mode Nabla.
///   "REJECTED_POOL_VID_MISMATCH"
///                       — pool linkage is for a different validator_id
///   "REJECTED_POOL_NOT_REGISTERED"
///                       — operator hasn't called RegisterValidatorPool yet,
///                         or linked_wallet_id is zero
///   "REJECTED_CONFLICT_OF_INTEREST"
///                       — §20.10 violation: chosen witness was in some
///                         earnings entry's fee_breakdown
///   "REJECTED_WITNESS_COUNT"
///                       — fewer than MIN_CHOSEN_WITNESSES (3) chosen
///   "REJECTED_WITNESS_DUPLICATE"
///                       — chosen_witnesses contains duplicates
///
/// On VERIFIED, `net_amount` = `total_amount × 90 / 100` (integer
/// division floors; at scale the dust loss is negligible), and
/// `claimed_through_tick` = `until_tick` of the attestation.
pub fn verify_validator_withdrawal(
    req: &ValidatorWithdrawalRequest,
) -> ValidatorWithdrawalResponse {
    // (1) SPHINCS+ identity binding — validator_id == BLAKE3(sphincs_pk).
    let derived_vid: [u8; 32] = *blake3::hash(&req.sphincs_pk).as_bytes();
    if derived_vid != req.validator_id {
        return reject(req, "REJECTED_ID_MISMATCH");
    }

    // (2) chosen_witnesses sanity — k floor + no duplicates.
    if req.chosen_witnesses.len() < MIN_CHOSEN_WITNESSES {
        return reject(req, "REJECTED_WITNESS_COUNT");
    }
    use std::collections::BTreeSet;
    let unique: BTreeSet<[u8; 32]> = req.chosen_witnesses.iter().copied().collect();
    if unique.len() != req.chosen_witnesses.len() {
        return reject(req, "REJECTED_WITNESS_DUPLICATE");
    }

    // (3) Earnings attestation must be authoritative — bloom-mode
    //     response can't be trusted for amounts.
    if !req.earnings_attestation.is_authoritative {
        return reject(req, "REJECTED_NOT_AUTHORITATIVE");
    }

    // (4) Nabla earnings attestation Ed25519 verify. Lambda recomputes
    //     the canonical hash from the response fields and verifies the
    //     stored signature under the Nabla node's pk. Tampering with any
    //     field (validator_id, totals, entries, full_fee_breakdowns)
    //     invalidates the sig.
    if !verify_earnings_attestation(&req.earnings_attestation) {
        return reject(req, "REJECTED_EARNINGS_SIG");
    }

    // (5) Pool linkage sanity.
    if req.pool_linkage.validator_id != req.validator_id {
        return reject(req, "REJECTED_POOL_VID_MISMATCH");
    }
    if !req.pool_linkage.registered
        || req.pool_linkage.linked_wallet_id == [0u8; 32]
    {
        return reject(req, "REJECTED_POOL_NOT_REGISTERED");
    }

    // (6) SPHINCS+ withdrawal authorisation — operator signed the
    //     canonical withdrawal payload binding (validator_id,
    //     attestation_hash, chosen_witnesses). An attacker can't
    //     reuse the sig for a different attestation or witness set.
    let attestation_hash = compute_earnings_attestation_hash(&req.earnings_attestation);
    let withdrawal_payload = axiom_core_logic::compute::compute_validator_withdrawal_payload(
        &req.validator_id, &attestation_hash, &req.chosen_witnesses,
    );
    if axiom_core_logic::verify::verify_sphincs(
        &req.sphincs_pk, &withdrawal_payload, &req.sphincs_sig,
    ).is_err() {
        return reject(req, "REJECTED_WITHDRAWAL_SIG");
    }

    // (7) §20.10 — chosen_witnesses must be disjoint from the union of
    //     full_fee_breakdown across all earnings entries.
    if !axiom_core_logic::compute::check_validator_withdrawal_conflict(
        &req.earnings_attestation.entries, &req.chosen_witnesses,
    ) {
        return reject(req, "REJECTED_CONFLICT_OF_INTEREST");
    }

    // All checks passed — compute the net mint amount.
    //
    // The authoritative `net_balance` is sourced from PR3's per-validator
    // NET ledger and bound into the earnings attestation signature
    // (verified at check (4) above; `compute_earnings_attestation_hash`
    // folds `net_balance` in). SEC-12d: the legacy
    // `total_amount × 90/100` fallback (for pre-PR4 Nablas where the
    // field deserialised to 0) is removed per CLAUDE.md §13 — every
    // wire format is "current" pre-mainnet, and a signed `net_balance`
    // of 0 means there is nothing to withdraw. Reject rather than
    // silently substituting a different formula.
    if req.earnings_attestation.net_balance == 0 {
        return reject(req, "REJECTED_NET_BALANCE_ZERO");
    }
    let net_amount = req.earnings_attestation.net_balance;

    ValidatorWithdrawalResponse {
        status: "VERIFIED".to_string(),
        validator_id: req.validator_id,
        net_amount,
        linked_wallet_id: req.pool_linkage.linked_wallet_id,
        claimed_through_tick: req.earnings_attestation.until_tick,
    }
}

fn reject(req: &ValidatorWithdrawalRequest, status: &str) -> ValidatorWithdrawalResponse {
    ValidatorWithdrawalResponse {
        status: status.to_string(),
        validator_id: req.validator_id,
        net_amount: 0,
        linked_wallet_id: req.pool_linkage.linked_wallet_id,
        claimed_through_tick: req.earnings_attestation.until_tick,
    }
}

/// Recompute the canonical earnings attestation hash from the response
/// fields exactly as the responding Nabla signed it.
fn compute_earnings_attestation_hash(a: &QueryValidatorEarningsResponse) -> [u8; 32] {
    axiom_core_logic::compute::compute_earnings_attestation_payload(
        &a.nabla_node_id, &a.validator_id,
        a.since_tick, a.until_tick, a.total_amount,
        &a.entries, a.is_authoritative,
        a.net_balance,
    )
}

/// Verify the Nabla node's Ed25519 signature on the attestation.
fn verify_earnings_attestation(a: &QueryValidatorEarningsResponse) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if a.nabla_signature.len() != 64 || a.nabla_node_pk.len() != 32 {
        return false;
    }
    let pk_bytes: [u8; 32] = a.nabla_node_pk.as_slice().try_into()
        .expect("len == 32 checked above");
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else { return false };
    let sig_bytes: [u8; 64] = a.nabla_signature.as_slice().try_into()
        .expect("len == 64 checked above");
    let sig = Signature::from_bytes(&sig_bytes);
    let hash = compute_earnings_attestation_hash(a);
    vk.verify(&hash, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core_logic::types::FeeShare;
    use axiom_core_logic::wire_client::QueryValidatorPoolResponse;

    /// Build a complete signed request (operator + Nabla node both real).
    /// Returns (request, nabla_sk) so tests can corrupt sigs without
    /// rebuilding the whole structure.
    struct TestKit {
        req: ValidatorWithdrawalRequest,
        nabla_sk: ed25519_dalek::SigningKey,
        sphincs_sk: Vec<u8>,
    }

    fn build_test_kit(
        chosen_witnesses: Vec<[u8; 32]>,
        entries: Vec<EarningsEntry>,
        total_amount: u64,
        is_authoritative: bool,
        pool_registered: bool,
        linked_wallet_id: [u8; 32],
    ) -> TestKit {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        use fips205::traits::Signer;

        // Operator SPHINCS+ keypair.
        let (sphincs_pk, sphincs_sk) = slh_dsa_sha2_128s::try_keygen()
            .expect("sphincs keygen");
        let sphincs_pk_bytes = sphincs_pk.into_bytes().to_vec();
        let sphincs_sk_bytes = sphincs_sk.into_bytes().to_vec();
        let validator_id: [u8; 32] = *blake3::hash(&sphincs_pk_bytes).as_bytes();

        // Nabla Ed25519 keypair.
        let nabla_sk = ed25519_dalek::SigningKey::from_bytes(&[0xAB; 32]);
        let nabla_pk = nabla_sk.verifying_key().to_bytes().to_vec();
        let nabla_node_id = [0xCC; 32]; // arbitrary

        // Build earnings attestation + sign it.
        let mut earnings = QueryValidatorEarningsResponse {
            validator_id,
            since_tick: 0,
            until_tick: 100,
            total_amount,
            // SEC-12d: net_balance is now mandatory (the legacy
            // total_amount × 90/100 fallback was removed). The fixture
            // populates the authoritative NET-ledger value so VERIFIED
            // tests still assert the same net_amount; the zero-net case
            // is exercised explicitly in rejects_zero_net_balance.
            net_balance: total_amount * 90 / 100,
            entries,
            is_authoritative,
            nabla_node_id,
            nabla_node_pk: nabla_pk.clone(),
            nabla_signature: vec![], // filled below
            nbc_issuer_pk: vec![],
            nbc_signature: vec![],
            nbc_commitment: vec![],
        };
        let earnings_hash = compute_earnings_attestation_hash(&earnings);
        use ed25519_dalek::Signer as _;
        earnings.nabla_signature = nabla_sk.sign(&earnings_hash).to_bytes().to_vec();

        // SPHINCS+ withdrawal signature over the canonical payload.
        let withdrawal_payload = axiom_core_logic::compute::compute_validator_withdrawal_payload(
            &validator_id, &earnings_hash, &chosen_witnesses,
        );
        let sphincs_sig = axiom_core_logic::compute::sign_sphincs(
            &sphincs_sk_bytes, &withdrawal_payload,
        ).expect("sphincs sign");

        let pool_linkage = QueryValidatorPoolResponse {
            validator_id,
            registered: pool_registered,
            linked_wallet_id,
            linkage_epoch: 1,
            registered_at_tick: 50,
        };

        TestKit {
            req: ValidatorWithdrawalRequest {
                validator_id,
                earnings_attestation: earnings,
                pool_linkage,
                sphincs_pk: sphincs_pk_bytes,
                sphincs_sig,
                chosen_witnesses,
            },
            nabla_sk,
            sphincs_sk: sphincs_sk_bytes,
        }
    }

    fn vid(b: u8) -> [u8; 32] { let mut v = [0u8; 32]; v[0] = b; v }
    fn fs(v: u8, amt: u64) -> FeeShare {
        FeeShare { validator_id: vid(v), amount: amt }
    }
    fn ent(b: u8, amount: u64, tick: u64, fb: Vec<FeeShare>) -> EarningsEntry {
        let mut h = [0u8; 32]; h[0] = b;
        EarningsEntry { tx_hash: h, amount, tick, full_fee_breakdown: fb }
    }

    #[test]
    fn verifies_clean_withdrawal_and_computes_90_percent_net() {
        // Validator earned 30 gross. With DEED 10%, net = 27.
        let entries = vec![
            ent(0x01, 30, 5, vec![fs(0x11, 10), fs(0x22, 10), fs(0x33, 10)]),
        ];
        let kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x66)],
            entries, 30, true, true, [0xAA; 32],
        );
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "VERIFIED");
        assert_eq!(resp.net_amount, 27);
        assert_eq!(resp.linked_wallet_id, [0xAA; 32]);
        assert_eq!(resp.claimed_through_tick, 100);
    }

    #[test]
    fn rejects_conflict_of_interest() {
        // §20.10: validator earned from V11/V22/V33; chooses V22 as
        // a withdrawal witness — conflict.
        let entries = vec![
            ent(0x01, 30, 5, vec![fs(0x11, 10), fs(0x22, 10), fs(0x33, 10)]),
        ];
        let kit = build_test_kit(
            vec![vid(0x22), vid(0x55), vid(0x66)],
            entries, 30, true, true, [0xAA; 32],
        );
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "REJECTED_CONFLICT_OF_INTEREST");
        assert_eq!(resp.net_amount, 0);
    }

    #[test]
    fn rejects_bloom_mode_attestation() {
        let entries = vec![];
        let kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x66)],
            entries, 0, false, true, [0xAA; 32],   // is_authoritative=false
        );
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "REJECTED_NOT_AUTHORITATIVE");
    }

    #[test]
    fn rejects_tampered_attestation() {
        // Operator forges a higher total in the response.
        let entries = vec![
            ent(0x01, 30, 5, vec![fs(0x11, 10), fs(0x22, 10), fs(0x33, 10)]),
        ];
        let mut kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x66)],
            entries, 30, true, true, [0xAA; 32],
        );
        // Bump total_amount post-hoc — signature no longer matches.
        kit.req.earnings_attestation.total_amount = 3000;
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "REJECTED_EARNINGS_SIG");
    }

    #[test]
    fn rejects_zero_net_balance() {
        // SEC-12d: a withdrawal whose signed net_balance is 0 must be
        // rejected outright, NOT silently substituted with the old
        // total_amount × 90/100 formula. We re-sign the attestation with
        // net_balance = 0 so it passes the earnings-sig check and reaches
        // the net-amount gate.
        let entries = vec![
            ent(0x01, 30, 5, vec![fs(0x11, 10), fs(0x22, 10), fs(0x33, 10)]),
        ];
        let mut kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x66)],
            entries, 30, true, true, [0xAA; 32],
        );
        // Zero the NET balance and re-sign BOTH the Nabla earnings sig
        // (binds net_balance) and the operator SPHINCS+ withdrawal sig
        // (binds the attestation hash) so every prior gate passes and the
        // request reaches the net-amount gate under test.
        kit.req.earnings_attestation.net_balance = 0;
        let hash = compute_earnings_attestation_hash(&kit.req.earnings_attestation);
        use ed25519_dalek::Signer as _;
        kit.req.earnings_attestation.nabla_signature =
            kit.nabla_sk.sign(&hash).to_bytes().to_vec();
        let withdrawal_payload =
            axiom_core_logic::compute::compute_validator_withdrawal_payload(
                &kit.req.validator_id, &hash, &kit.req.chosen_witnesses,
            );
        kit.req.sphincs_sig = axiom_core_logic::compute::sign_sphincs(
            &kit.sphincs_sk, &withdrawal_payload,
        ).expect("sphincs sign");
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "REJECTED_NET_BALANCE_ZERO");
        assert_eq!(resp.net_amount, 0);
    }

    #[test]
    fn rejects_unregistered_pool() {
        let entries = vec![ent(0x01, 30, 5, vec![])];
        let kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x66)],
            entries, 30, true, false, [0u8; 32],   // pool not registered
        );
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "REJECTED_POOL_NOT_REGISTERED");
    }

    #[test]
    fn rejects_pool_validator_id_mismatch() {
        let entries = vec![ent(0x01, 30, 5, vec![])];
        let mut kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x66)],
            entries, 30, true, true, [0xAA; 32],
        );
        // Pool linkage belongs to a different validator.
        kit.req.pool_linkage.validator_id = [0xEE; 32];
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "REJECTED_POOL_VID_MISMATCH");
    }

    #[test]
    fn rejects_sphincs_id_mismatch() {
        let entries = vec![ent(0x01, 30, 5, vec![])];
        let mut kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x66)],
            entries, 30, true, true, [0xAA; 32],
        );
        // Claim a different validator_id; sphincs_pk no longer hashes to it.
        kit.req.validator_id = [0xFF; 32];
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "REJECTED_ID_MISMATCH");
    }

    #[test]
    fn rejects_below_k_floor_witnesses() {
        let entries = vec![ent(0x01, 30, 5, vec![])];
        let kit = build_test_kit(
            vec![vid(0x44), vid(0x55)],   // only 2
            entries, 30, true, true, [0xAA; 32],
        );
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "REJECTED_WITNESS_COUNT");
    }

    #[test]
    fn rejects_duplicate_chosen_witnesses() {
        let entries = vec![ent(0x01, 30, 5, vec![])];
        let kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x44)],   // V44 twice
            entries, 30, true, true, [0xAA; 32],
        );
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "REJECTED_WITNESS_DUPLICATE");
    }

    #[test]
    fn rejects_tampered_chosen_witnesses_after_sphincs_sign() {
        // Operator signs over (V44, V55, V66) but Lambda receives a
        // request with V44, V55, V77 — sphincs sig binds the original
        // set so the tampered request fails.
        let entries = vec![ent(0x01, 30, 5, vec![])];
        let mut kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x66)],
            entries, 30, true, true, [0xAA; 32],
        );
        // Swap last witness without re-signing.
        kit.req.chosen_witnesses[2] = vid(0x77);
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "REJECTED_WITHDRAWAL_SIG");
    }

    #[test]
    fn net_amount_rounds_down_on_uneven_division() {
        // 35 × 90 / 100 = 31 (integer floor). The 0.5 atom rounded
        // away goes to DEED (precision loss is by-design at scale).
        let entries = vec![
            ent(0x01, 35, 5, vec![fs(0x11, 35)]),
        ];
        let kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x66)],
            entries, 35, true, true, [0xAA; 32],
        );
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "VERIFIED");
        assert_eq!(resp.net_amount, 31);
    }

    #[test]
    fn verifies_multi_entry_witness_disjoint() {
        // 3 separate fee earnings, each from a different witness set.
        // Chosen witnesses are disjoint from the union.
        let entries = vec![
            ent(0x01, 10, 5, vec![fs(0x11, 10), fs(0x12, 10), fs(0x13, 10)]),
            ent(0x02, 10, 6, vec![fs(0x21, 10), fs(0x22, 10), fs(0x23, 10)]),
            ent(0x03, 10, 7, vec![fs(0x31, 10), fs(0x32, 10), fs(0x33, 10)]),
        ];
        let kit = build_test_kit(
            vec![vid(0x44), vid(0x55), vid(0x66)],
            entries, 90, true, true, [0xAA; 32],
        );
        let resp = verify_validator_withdrawal(&kit.req);
        assert_eq!(resp.status, "VERIFIED");
        assert_eq!(resp.net_amount, 81); // 90 × 90/100
    }
}
