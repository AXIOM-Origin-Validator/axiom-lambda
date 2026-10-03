# AGENTS.md — lambda/ (Λ, the k=3 Consensus Engine)

AI-assistant orientation for `lambda/`. Read this before editing anything here.

## What Lambda is

Lambda is AXIOM's consensus layer: it coordinates k=3 witness rounds (floor
`MIN_WITNESSES = 3` in `src/consensus.rs`), runs the authoritative Core CL2/CL3/CL5
passes via the embedded DMAP-VM (`src/core_client.rs` — `run_cl2:223`,
`produce_witness:333` / `produce_witness_dmap:608`, `validate_redeem:808`), performs
S-ABR refill from its own records, and stores the results. Lambda is the HISTORIAN:
"Lambda has the DATA. Core makes the DECISION." (`src/storage.rs` header).

## Binding rules

- **Lambda is the ONLY layer that knows a wallet's current stored state.** Consensus
  state lives in `src/storage.rs` (`get_wallet_state:618`, `set_wallet_state:697`,
  YPX-016 `witness_cache` table `:479`). Any decision depending on stored state
  belongs in Lambda's CL2/CL3/CL5 pass — never in ANTIE, never in the SDK. ANTIE
  must never synthesize a `WalletState` for Lambda's job (CLAUDE.md §8).
- **Lambda does ZERO crypto.** Core is the sole cryptographic gatekeeper
  (`src/consensus.rs` module header + the "Lambda does ZERO crypto" audit path,
  `consensus.rs:1974`). No signature checks, no hashes-as-verdicts, no commitment
  recomputation here. If you need verification, put it in Core, not Lambda.
- **§15 proof gates — both mandatory, no fallback.** Send: empty
  `cl1_execution_proof` rejects with "CL1: missing execution proof" before any
  Core call. Redeem mirror: empty `cl5_execution_proof` returns
  `E_LAMBDA_CL5_PROOF_MISSING`. Both live in `src/consensus.rs`; grep the string.
  No "if present", no `serde(default)` on proof fields.
- **Receipts are stored only by the k-set finalizer** (`consensus.rs:1966`). Every
  validator stores `transaction_records`; only the finalizer stores receipts —
  lookups that must work on V1/V2 use transaction_records, not receipts.
- **Naming culture is mathematical/formal** — protocol-theory and quorum-system
  names (`S-ABR`, `DWP`, `k-witness`). Name new things like a paper citation.
- **Tuning constants live in `protocol_lambda.toml`** (generated via
  `src/tuning_gen.rs`), never as fresh consts in .rs files.

## The validator↔Nabla boundary

The core witness path makes ZERO Nabla calls. The only Lambda→Nabla dials are the
oracle stake pull (`consensus.rs:1128`, oracle-gated, oracle OFF) and the
fire-and-forget PulseProof (`consensus.rs:3352`, pulse OFF). VBC renewal is
sanctioned doctrine but has NO code: `vbc_renewal_interval_secs`
(`src/config.rs:305`) has zero consumers, and dev VBC expiry defaults to
`u64::MAX` (`consensus.rs:149`). Do not add a Nabla dependency to the witness or
redeem path; validators never contact validators either — witness rounds are
client-carried.

## Wire truth

- CBOR end-to-end on the protocol path (CLAUDE.md §10). Server framing is
  length-prefixed CBOR (`src/server.rs`). No JSON, no HTTP on the protocol path —
  the admin console (`src/admin.rs`, 127.0.0.1-only JSON) is the sanctioned exception.
- Errors are the Phase-2 structured stack only: `error_response: ErrorResponse`
  with `E_*` codes (`src/error_response.rs`, `docs/AXIOM_YellowPaper_Errors.md`).
  No legacy `error: Option<String>` anywhere.
- YPX-016 witness cache = idempotent replay: on state-id mismatch, the exact same
  prior TX replays its cached Core-endorsed response (read `consensus.rs:2689`,
  writes `:3623` / `:4033`). It recovers partial witnesses; it is not a shortcut.

## Read these first

1. `docs/AXIOM_DESIGN_Lambda.md` — the AI READER PREAMBLE at the top is binding:
   it tells you which sections are current and which are 2026-01 history.
2. The repo-root `CLAUDE.md` — §8 (layer roles), §10 (CBOR), §13 (no
   mirror structs; IPC types live in `axiom_core_logic::types` only), §15 (proof
   gates), §17.1.2 (quorum gate).
3. `docs/AXIOM_REF_LambdaERD.md` (DB schema), `docs/AXIOM_DESIGN_DWP_JFP.md`
   (`src/dwp_engine.rs` / `src/jfp_engine.rs`).

## Top traps

- **Line numbers drift** — in code comments and in this file. Locate code by its
  error string or symbol, never by a cited line.
- **JSON corrupts Dilithium bytes.** JSON round-trips drop CBOR byte-string types
  and silently invalidate Dilithium signatures — this is WHY the witness cache
  stores CBOR (`ciborium` at the `:3623`/`:4033` write sites). The BLAKE3-over-JSON
  tx_hash KEY is fine (determinism only); never JSON the cached VALUE.
- **No `.unwrap_or(0)` on wallet state** anywhere along the Lambda→Core boundary
  (balance / wallet_seq / state_id). Missing state on a non-genesis path = reject.
  The `unwrap_or(0)`s you'll find in `consensus.rs` are dashboard/stats counters —
  do not use them as precedent for state.
- **Do not re-add local verification.** `validate_sabr` / local FACT depth checks /
  mirror structs were all deleted deliberately (see the design doc's
  "layer-boundary cleanups"). CI grep-enforces via `scripts/check_layer_boundary.sh`.
- **`audit-chaos` is a DEV-ONLY feature** (`lambda/src/audit_chaos.rs`, YP §23.14 item 10a): a switch file
  beside `lambda.toml` makes this validator answer peer audits `lie` / `silent` / `forget`. Only the dev
  Lambda line in `axiom-env.py` passes it; preflight fails any other recipe. Never enable it elsewhere.
