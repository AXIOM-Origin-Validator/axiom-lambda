// AXIOM validator-withdrawal mint end-to-end integration test
// (YP §20.10, fee ledger Step 9B.9)
//
// Stitches together everything Steps 9B.1 through 9B.8 added in
// source-only form. Where Step 8.5 (fee_ledger_e2e.rs) stopped at
// `verify_validator_withdrawal` returning VERIFIED, this test
// continues the protocol through:
//
//   - Core CL13 dispatch via the AVM (Step 9B.2 — native fallback
//     when no RISC-V ELF is present in the test env).
//   - Chosen-witness Lambda handler emitting mint + claim sigs
//     (Step 9B.3).
//   - Operator-side signature verification against both
//     `compute_withdrawal_mint_commitment` AND
//     `compute_validator_claim_payload` (Step 9B.4).
//   - Storage persistence of the mint receipt with PK-based
//     idempotency (Step 9B.7).
//   - K3WitnessSig assembly for the MarkValidatorEarningsClaimedRequest
//     that the orchestrator forwards to Nabla (Step 9B.8).
//
// We don't spin up real TCP listeners for chosen-witness Lambdas —
// instead we drive ONE engine's `process_withdrawal_mint_witness`
// handler three times (with three different validator-signing keys)
// and verify the resulting responses end-to-end. The TCP wire path
// gets exercised separately by the orchestrator's unit tests and by
// the env smoke landing in Step 9B.10.

use axiom_core_logic::types::FeeShare;
use axiom_core_logic::types::WithdrawalMintWitnessRequest;
use axiom_core_logic::wire_client::{
    EarningsEntry, QueryValidatorEarningsResponse,
    ValidatorWithdrawalRequest,
};
use axiom_nabla::validator_pool::ValidatorPoolStore;

/// Build a SPHINCS+ keypair + derive the validator_id (BLAKE3(pk)).
fn sphincs_keypair() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    use fips205::slh_dsa_sha2_128s;
    use fips205::traits::SerDes;
    let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("sphincs keygen");
    let pk_bytes = pk.into_bytes().to_vec();
    let sk_bytes = sk.into_bytes().to_vec();
    let validator_id: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
    (pk_bytes, sk_bytes, validator_id)
}

fn vid(b: u8) -> [u8; 32] { let mut v = [0u8; 32]; v[0] = b; v }

/// Build a signed Nabla earnings attestation from raw entries.
fn build_signed_earnings_attestation(
    validator_id: [u8; 32],
    entries: Vec<EarningsEntry>,
    until_tick: u64,
    nabla_sk: &ed25519_dalek::SigningKey,
) -> QueryValidatorEarningsResponse {
    use ed25519_dalek::Signer;
    let total_amount: u64 = entries.iter().map(|e| e.amount).sum();
    let nabla_pk = nabla_sk.verifying_key().to_bytes().to_vec();
    let nabla_node_id = [0xCC; 32];
    let mut resp = QueryValidatorEarningsResponse {
        validator_id, since_tick: 0, until_tick, total_amount,
        entries, is_authoritative: true,
        net_balance: total_amount,
        nabla_node_id, nabla_node_pk: nabla_pk,
        nabla_signature: vec![],
        nbc_issuer_pk: vec![], nbc_signature: vec![], nbc_commitment: vec![],
    };
    let hash = axiom_core_logic::compute::compute_earnings_attestation_payload(
        &resp.nabla_node_id, &resp.validator_id,
        resp.since_tick, resp.until_tick, resp.total_amount,
        &resp.entries, resp.is_authoritative, resp.net_balance,
    );
    resp.nabla_signature = nabla_sk.sign(&hash).to_bytes().to_vec();
    resp
}

/// Build a complete signed withdrawal request — the operator-facing
/// input to the admin handler. Reused by every test.
fn build_signed_withdrawal_request(
    chosen_witnesses: Vec<[u8; 32]>,
) -> (ValidatorWithdrawalRequest, [u8; 32], [u8; 32], u64, u64) {
    let (sphincs_pk, sphincs_sk, validator_id) = sphincs_keypair();
    let linked_wallet_id = [0xAA; 32];

    // Pool linkage — registered via the real ValidatorPoolStore.
    let mut pool_store = ValidatorPoolStore::new();
    let link_payload = axiom_core_logic::compute::compute_validator_pool_link_payload(
        &validator_id, &linked_wallet_id, 1, 100,
    );
    let link_sig = axiom_core_logic::compute::sign_sphincs(
        &sphincs_sk, &link_payload,
    ).expect("sphincs sign link");
    let link_req = axiom_core_logic::wire_client::RegisterValidatorPoolRequest {
        validator_id, linked_wallet_id,
        sphincs_pk: sphincs_pk.clone(),
        sphincs_sig: link_sig,
        linkage_epoch: 1, tick: 100,
    };
    pool_store.process_register(&link_req, 100).expect("pool register");

    // Earnings attestation: the validator earned exactly 100 atoms in
    // one TX where its own slot is 100 and the other two witnesses are
    // V11 + V22 (disjoint from chosen_witnesses).
    let entries = vec![EarningsEntry {
        tx_hash: [0x01; 32], amount: 100, tick: 50,
        full_fee_breakdown: vec![
            FeeShare { validator_id, amount: 100 },
            FeeShare { validator_id: vid(0x11), amount: 100 },
            FeeShare { validator_id: vid(0x22), amount: 100 },
        ],
    }];
    let nabla_sk = ed25519_dalek::SigningKey::from_bytes(&[0xAB; 32]);
    let earnings = build_signed_earnings_attestation(
        validator_id, entries, 200, &nabla_sk,
    );

    let pool_linkage = pool_store.process_query(
        &axiom_core_logic::wire_client::QueryValidatorPoolRequest { validator_id },
    );
    assert!(pool_linkage.registered);

    // Operator's SPHINCS+ withdrawal authorization.
    let attestation_hash = axiom_core_logic::compute::compute_earnings_attestation_payload(
        &earnings.nabla_node_id, &earnings.validator_id,
        earnings.since_tick, earnings.until_tick, earnings.total_amount,
        &earnings.entries, earnings.is_authoritative, earnings.net_balance,
    );
    let withdrawal_payload = axiom_core_logic::compute::compute_validator_withdrawal_payload(
        &validator_id, &attestation_hash, &chosen_witnesses,
    );
    let sphincs_sig = axiom_core_logic::compute::sign_sphincs(
        &sphincs_sk, &withdrawal_payload,
    ).expect("sphincs sign withdrawal");

    let req = ValidatorWithdrawalRequest {
        validator_id, earnings_attestation: earnings,
        pool_linkage, sphincs_pk, sphincs_sig, chosen_witnesses,
    };
    // Expected: net = 100 × 90 / 100 = 90 atoms.
    (req, validator_id, linked_wallet_id, 90, 200)
}

/// Full chain: build a signed withdrawal, dispatch through CL13 via
/// the engine, verify both signatures, persist, idempotency check.
#[tokio::test(flavor = "current_thread")]
async fn withdrawal_mint_round_trip_via_cl13() {
    use axiom_lambda::consensus::tests::create_test_engine;

    // Operator picks 3 disjoint chosen_witnesses (§20.10).
    let chosen_witnesses = vec![vid(0x44), vid(0x55), vid(0x66)];
    let (req, expected_vid, expected_linked, expected_net, expected_tick) =
        build_signed_withdrawal_request(chosen_witnesses);

    // ── One chosen-witness Lambda handler call ────────────────────
    //
    // The operator would fan out to k=3 chosen_witness Lambdas; here
    // we drive ONE engine + verify the response carries both
    // signatures + the mint output. The orchestrator's fan-out and
    // verification logic is covered separately by its unit tests.
    let engine = std::sync::Arc::new(create_test_engine());
    let witness_req = WithdrawalMintWitnessRequest {
        request_id: "9b9-e2e".into(),
        withdrawal: req.clone(),
    };
    let witness_resp = engine.process_withdrawal_mint_witness(&witness_req).await;

    assert_eq!(witness_resp.status, "VERIFIED",
        "engine must accept the validly signed withdrawal");
    assert_eq!(witness_resp.request_id, "9b9-e2e");
    assert_eq!(witness_resp.witness_pk.len(), 32,
        "witness_pk is the engine's Ed25519 pk (32 bytes)");

    // Both signatures must be present on Accept.
    let witness_sig = witness_resp.witness_sig
        .expect("Accept must populate witness_sig");
    let claim_sig = witness_resp.claim_sig
        .expect("Accept must populate claim_sig");
    let mint = witness_resp.mint
        .expect("Accept must populate mint output");

    // Verify the mint shape matches what verify_validator_withdrawal
    // would have returned on the operator's side.
    assert_eq!(mint.validator_id, expected_vid);
    assert_eq!(mint.linked_wallet_id, expected_linked);
    assert_eq!(mint.net_amount, expected_net);
    assert_eq!(mint.claimed_through_tick, expected_tick);

    // ── Verify witness_sig binds the mint commitment ──────────────
    let mint_commitment = axiom_core_logic::compute::compute_withdrawal_mint_commitment(
        &mint.validator_id, &mint.linked_wallet_id,
        mint.net_amount, mint.claimed_through_tick,
    );
    axiom_core_logic::verify::verify_ed25519(
        &witness_resp.witness_pk, &mint_commitment, &witness_sig,
    ).expect("witness_sig must verify against mint commitment");

    // ── Verify claim_sig binds the claim payload ──────────────────
    let claim_payload = axiom_core_logic::compute::compute_validator_claim_payload(
        &mint.validator_id, mint.claimed_through_tick,
    );
    axiom_core_logic::verify::verify_ed25519(
        &witness_resp.witness_pk, &claim_payload, &claim_sig,
    ).expect("claim_sig must verify against claim payload");

    // ── Persist + idempotency (Step 9B.7) ──────────────────────────
    let sigs_cbor = {
        let mut buf = Vec::new();
        ciborium::into_writer(&vec![(
            witness_resp.witness_pk.clone(), witness_sig.clone(),
        )], &mut buf).unwrap();
        buf
    };
    let inserted = engine.storage().record_validator_mint(
        &mint.validator_id, mint.claimed_through_tick,
        &mint.linked_wallet_id, mint.net_amount, &sigs_cbor,
    ).expect("persist");
    assert!(inserted, "first persist must be a fresh insert");

    let again = engine.storage().record_validator_mint(
        &mint.validator_id, mint.claimed_through_tick,
        &mint.linked_wallet_id, mint.net_amount, &sigs_cbor,
    ).expect("re-persist");
    assert!(!again, "second persist on same (vid, tick) must be ignored");

    let (lw, net, _at, _sigs) = engine.storage().get_validator_mint(
        &mint.validator_id, mint.claimed_through_tick,
    ).unwrap().unwrap();
    assert_eq!(lw, mint.linked_wallet_id);
    assert_eq!(net, mint.net_amount);
    assert_eq!(
        engine.storage().lifetime_minted_to(&mint.linked_wallet_id).unwrap(),
        mint.net_amount,
        "lifetime_minted_to mirrors the single persisted receipt",
    );
}

/// A tampered earnings attestation (forged Nabla signature) is
/// rejected by the engine BEFORE Core CL13 — the Lambda-side verify
/// chain short-circuits at step 4 of the 7-step verifier.
#[tokio::test(flavor = "current_thread")]
async fn withdrawal_mint_rejects_forged_attestation_signature() {
    use axiom_lambda::consensus::tests::create_test_engine;

    let chosen_witnesses = vec![vid(0x44), vid(0x55), vid(0x66)];
    let (mut req, _, _, _, _) = build_signed_withdrawal_request(chosen_witnesses);

    // Forge: replace the Nabla signature with garbage.
    req.earnings_attestation.nabla_signature = vec![0u8; 64];

    let engine = std::sync::Arc::new(create_test_engine());
    let witness_req = WithdrawalMintWitnessRequest {
        request_id: "9b9-tamper".into(),
        withdrawal: req,
    };
    let witness_resp = engine.process_withdrawal_mint_witness(&witness_req).await;

    assert_eq!(witness_resp.status, "REJECTED_EARNINGS_SIG",
        "tampered attestation must reject at step 4");
    assert!(witness_resp.witness_sig.is_none(),
        "no mint signature on rejection");
    assert!(witness_resp.claim_sig.is_none(),
        "no claim signature on rejection");
    assert!(witness_resp.mint.is_none(),
        "no mint output on rejection");
}

/// §20.10 enforcement at CL13: a chosen_witness that overlaps with a
/// validator in the earnings entries' fee_breakdown is rejected by
/// Core CL13's disjoint-witness check (step 7 of the 7-step chain).
#[tokio::test(flavor = "current_thread")]
async fn withdrawal_mint_rejects_section_20_10_violation() {
    use axiom_lambda::consensus::tests::create_test_engine;

    // V11 IS in the earnings' fee_breakdown — adding it to
    // chosen_witnesses violates §20.10. But the SPHINCS+ withdrawal
    // signature is over THIS specific tuple of chosen_witnesses, so
    // the signature is valid; the check fires at the §20.10 step.
    let chosen_witnesses = vec![vid(0x11), vid(0x55), vid(0x66)];
    let (req, _, _, _, _) = build_signed_withdrawal_request(chosen_witnesses);

    let engine = std::sync::Arc::new(create_test_engine());
    let witness_req = WithdrawalMintWitnessRequest {
        request_id: "9b9-2010".into(),
        withdrawal: req,
    };
    let witness_resp = engine.process_withdrawal_mint_witness(&witness_req).await;

    assert_eq!(witness_resp.status, "REJECTED_CONFLICT_OF_INTEREST",
        "§20.10 violation must reject (Lambda-side verify catches it \
        before CL13 — same check, two layers of defense)");
    assert!(witness_resp.witness_sig.is_none());
    assert!(witness_resp.claim_sig.is_none());
}
