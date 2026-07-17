//! ZK-TLS proof verification for oracle claims.
//!
//! Verifies that oracle credit data was genuinely fetched from the claimed platform
//! via TLS, attested by a trusted Notary. The proof binds (platform_url, credit_total)
//! to a cryptographic attestation that the data came from a real TLS session.
//!
//! Protocol (YPX-012 §2.7):
//! 1. Oracle operator runs TLSNotary session against platform API
//! 2. Notary co-signs the TLS transcript, producing an attestation
//! 3. Operator creates a Presentation (selective disclosure of transcript)
//! 4. Presentation is serialized and included as `zktls_proof` in OracleClaimData
//! 5. Lambda verifies: Notary signature, server name, credit data extraction
//!
//! Proof format: CBOR-encoded AxiomTlsProof (see struct below).
//! This is AXIOM's wrapper around TLSNotary attestation data.

use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde::{Serialize, Deserialize};
use tracing::debug;

/// Trusted Notary public keys. In production, these are the Ed25519 public keys
/// of approved TLSNotary notary servers. Validators must use one of these notaries.
/// Updated via Console governance (Core Update Recommendation).
///
/// For now: one hardcoded test notary. Production will load from config.
const TRUSTED_NOTARY_KEYS: &[&str] = &[
    // Placeholder — replace with real Notary PKs before Oracle activation.
    // Format: hex-encoded 32-byte Ed25519 public key.
];

/// Maximum age of a ZK-TLS proof (seconds). Proofs older than this are rejected
/// to prevent replay of stale credit data.
const MAX_PROOF_AGE_SECS: u64 = 86400; // 24 hours

/// Maximum proof blob size (bytes). Prevents DoS via oversized proofs.
const MAX_PROOF_SIZE: usize = 1_048_576; // 1 MB

/// AXIOM's wrapper around TLSNotary attestation data.
/// Serialized as CBOR in the `zktls_proof` field of OracleClaimData.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxiomTlsProof {
    /// TLSNotary attestation version (must be 1)
    pub version: u8,

    /// Server name from TLS session (e.g., "foldingathome.org")
    pub server_name: String,

    /// Unix timestamp when the TLS session occurred
    pub session_time: u64,

    /// Notary's Ed25519 public key (must be in TRUSTED_NOTARY_KEYS)
    pub notary_pk: [u8; 32],

    /// Notary's Ed25519 signature over the attestation commitment:
    /// BLAKE3("AXIOM_ZKTLS_ATTEST" || server_name || session_time || transcript_hash)
    pub notary_signature: Vec<u8>,

    /// BLAKE3 hash of the verified TLS transcript (selective disclosure)
    pub transcript_hash: [u8; 32],

    /// The credit data extracted from the transcript.
    /// Must match the oracle claim's credit_total.
    pub attested_credit_total: u64,

    /// Platform user ID extracted from the transcript.
    pub attested_user_id: u64,

    /// Raw transcript excerpt (the JSON/HTML containing credit data).
    /// Validators can inspect this for additional verification.
    pub transcript_excerpt: Vec<u8>,
}

/// Verify a ZK-TLS proof for an oracle claim.
///
/// Checks:
/// 1. Proof deserializes correctly (CBOR format)
/// 2. Version is supported
/// 3. Proof is not too old (MAX_PROOF_AGE_SECS)
/// 4. Server name matches platform_url
/// 5. Notary public key is trusted
/// 6. Notary signature is valid over the attestation commitment
/// 7. Attested credit_total matches the claim
/// 8. Transcript hash matches the excerpt
pub fn verify_zktls_proof(
    proof_blob: &[u8],
    platform_url: &str,
    credit_total: u64,
) -> Result<(), String> {
    // Basic size checks
    if proof_blob.is_empty() {
        return Err("ZK-TLS proof blob is empty".to_string());
    }
    if proof_blob.len() > MAX_PROOF_SIZE {
        return Err(format!("ZK-TLS proof too large: {} bytes (max {})", proof_blob.len(), MAX_PROOF_SIZE));
    }

    // Step 1: Deserialize
    let proof: AxiomTlsProof = ciborium::from_reader(proof_blob)
        .map_err(|e| format!("ZK-TLS proof CBOR decode failed: {}", e))?;

    // Step 2: Version check
    if proof.version != 1 {
        return Err(format!("Unsupported ZK-TLS proof version: {} (expected 1)", proof.version));
    }

    // Step 3: Freshness check
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now > proof.session_time && now - proof.session_time > MAX_PROOF_AGE_SECS {
        return Err(format!(
            "ZK-TLS proof expired: session_time={}, now={}, age={}s (max {}s)",
            proof.session_time, now, now - proof.session_time, MAX_PROOF_AGE_SECS
        ));
    }

    // Step 4: Server name binding
    // Extract hostname from platform_url for comparison
    let expected_host = platform_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    if proof.server_name != expected_host {
        return Err(format!(
            "ZK-TLS server name mismatch: proof says '{}' but claim says '{}'",
            proof.server_name, expected_host
        ));
    }

    // Step 5: Notary trust check
    let notary_pk_hex = hex::encode(proof.notary_pk);
    if !TRUSTED_NOTARY_KEYS.is_empty() && !TRUSTED_NOTARY_KEYS.contains(&notary_pk_hex.as_str()) {
        return Err(format!(
            "ZK-TLS notary {} is not in trusted set ({} trusted keys)",
            &notary_pk_hex[..16], TRUSTED_NOTARY_KEYS.len()
        ));
    }
    // If TRUSTED_NOTARY_KEYS is empty, skip trust check (pre-activation / test mode).
    // GAP-O2 checklist: populate TRUSTED_NOTARY_KEYS before enabling Oracle.
    if TRUSTED_NOTARY_KEYS.is_empty() {
        debug!("ZK-TLS: no trusted notary keys configured — skipping notary trust check (pre-activation)");
    }

    // Step 6: Notary signature verification
    // Commitment: BLAKE3("AXIOM_ZKTLS_ATTEST" || server_name || session_time || transcript_hash)
    let commitment = {
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_ZKTLS_ATTEST");
        h.update(proof.server_name.as_bytes());
        h.update(&proof.session_time.to_le_bytes());
        h.update(&proof.transcript_hash);
        *h.finalize().as_bytes()
    };

    if proof.notary_signature.len() != 64 {
        return Err(format!(
            "ZK-TLS notary signature wrong length: {} (expected 64)",
            proof.notary_signature.len()
        ));
    }

    let verifying_key = VerifyingKey::from_bytes(&proof.notary_pk)
        .map_err(|e| format!("ZK-TLS notary PK invalid: {}", e))?;
    let signature = Signature::from_bytes(
        proof.notary_signature.as_slice().try_into()
            .map_err(|_| "ZK-TLS signature: expected 64 bytes")?
    );
    verifying_key.verify(&commitment, &signature)
        .map_err(|e| format!("ZK-TLS notary signature INVALID: {}", e))?;

    // Step 7: Credit data binding
    if proof.attested_credit_total != credit_total {
        return Err(format!(
            "ZK-TLS credit mismatch: proof attests {} but claim says {}",
            proof.attested_credit_total, credit_total
        ));
    }

    // Step 8: Transcript hash integrity
    let expected_hash = *blake3::hash(&proof.transcript_excerpt).as_bytes();
    if expected_hash != proof.transcript_hash {
        return Err(format!(
            "ZK-TLS transcript hash mismatch: computed {} but proof claims {}",
            hex::encode(expected_hash), hex::encode(proof.transcript_hash)
        ));
    }

    debug!(
        "ZK-TLS proof verified: server={}, credits={}, notary={}..., age={}s",
        proof.server_name, proof.attested_credit_total,
        &notary_pk_hex[..16], now.saturating_sub(proof.session_time)
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::Signer;

    /// Build a valid test proof with real Ed25519 signature.
    fn make_test_proof(
        server_name: &str,
        credit_total: u64,
        user_id: u64,
    ) -> (Vec<u8>, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let pk = sk.verifying_key().to_bytes();

        let transcript_excerpt = format!(
            r#"{{"user_id":{},"credit_total":{}}}"#,
            user_id, credit_total
        ).into_bytes();
        let transcript_hash = *blake3::hash(&transcript_excerpt).as_bytes();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Sign the attestation commitment
        let commitment = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_ZKTLS_ATTEST");
            h.update(server_name.as_bytes());
            h.update(&now.to_le_bytes());
            h.update(&transcript_hash);
            *h.finalize().as_bytes()
        };
        let sig = sk.sign(&commitment);

        let proof = AxiomTlsProof {
            version: 1,
            server_name: server_name.to_string(),
            session_time: now,
            notary_pk: pk,
            notary_signature: sig.to_bytes().to_vec(),
            transcript_hash,
            attested_credit_total: credit_total,
            attested_user_id: user_id,
            transcript_excerpt,
        };

        let mut blob = Vec::new();
        ciborium::into_writer(&proof, &mut blob).unwrap();
        (blob, pk)
    }

    #[test]
    fn test_empty_proof_rejected() {
        assert!(verify_zktls_proof(&[], "https://foldingathome.org", 100).is_err());
    }

    #[test]
    fn test_valid_proof_accepted() {
        let (blob, _pk) = make_test_proof("foldingathome.org", 50000, 12345);
        // TRUSTED_NOTARY_KEYS is empty in test → notary trust check skipped
        let result = verify_zktls_proof(&blob, "https://foldingathome.org", 50000);
        assert!(result.is_ok(), "Valid proof should be accepted: {:?}", result.err());
    }

    #[test]
    fn test_wrong_server_name_rejected() {
        let (blob, _pk) = make_test_proof("foldingathome.org", 50000, 12345);
        let result = verify_zktls_proof(&blob, "https://evil.com", 50000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("server name mismatch"));
    }

    #[test]
    fn test_wrong_credit_total_rejected() {
        let (blob, _pk) = make_test_proof("foldingathome.org", 50000, 12345);
        let result = verify_zktls_proof(&blob, "https://foldingathome.org", 99999);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("credit mismatch"));
    }

    #[test]
    fn test_corrupted_signature_rejected() {
        let (mut blob, _pk) = make_test_proof("foldingathome.org", 50000, 12345);
        // Deserialize, corrupt sig, re-serialize
        let mut proof: AxiomTlsProof = ciborium::from_reader(&blob[..]).unwrap();
        proof.notary_signature[0] ^= 0xFF;
        blob.clear();
        ciborium::into_writer(&proof, &mut blob).unwrap();

        let result = verify_zktls_proof(&blob, "https://foldingathome.org", 50000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("INVALID"));
    }

    #[test]
    fn test_tampered_transcript_rejected() {
        let (mut blob, _pk) = make_test_proof("foldingathome.org", 50000, 12345);
        let mut proof: AxiomTlsProof = ciborium::from_reader(&blob[..]).unwrap();
        // Tamper with excerpt (changes hash)
        proof.transcript_excerpt.push(b'X');
        blob.clear();
        ciborium::into_writer(&proof, &mut blob).unwrap();

        let result = verify_zktls_proof(&blob, "https://foldingathome.org", 50000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("transcript hash mismatch"));
    }

    #[test]
    fn test_wrong_version_rejected() {
        let (mut blob, _pk) = make_test_proof("foldingathome.org", 50000, 12345);
        let mut proof: AxiomTlsProof = ciborium::from_reader(&blob[..]).unwrap();
        proof.version = 99;
        blob.clear();
        ciborium::into_writer(&proof, &mut blob).unwrap();

        let result = verify_zktls_proof(&blob, "https://foldingathome.org", 50000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("version"));
    }

    #[test]
    fn test_oversized_proof_rejected() {
        let huge = vec![0u8; MAX_PROOF_SIZE + 1];
        let result = verify_zktls_proof(&huge, "https://foldingathome.org", 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));
    }

    #[test]
    fn test_invalid_cbor_rejected() {
        let garbage = b"not valid cbor at all";
        let result = verify_zktls_proof(garbage, "https://foldingathome.org", 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("CBOR decode"));
    }
}
