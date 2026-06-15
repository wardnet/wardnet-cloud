//! Proof-of-work challenge verification (registration self-service).
//!
//! **Transient:** `PoW` self-service registration is slated for retirement when the
//! email instance-code enrollment lands. This whole module is removed then — it is
//! deliberately isolated so the removal is a single clean delete. The real-client-IP
//! helper that used to sit alongside it lives permanently in
//! [`crate::proxy_protocol::client_ip`].

/// `PoW` difficulty: number of leading zero bits required in
/// `SHA256(nonce\nname\npublic_key\nproof)`.
///
/// 24 bits → ~16 M expected hashes → ~160 ms on a Pi 4 (acceptable for a
/// one-time setup step), ~4 h to register all 900 word-pair names even on a
/// fast laptop, longer still on a typical residential IP limited by the
/// registration rate cap.
///
/// Consumed by the Tenants service when issuing challenges and by the `PoW`
/// tests; the issuance/rate-limit policy itself lives in that service.
pub const POW_DIFFICULTY: u32 = 24;

/// Verify a proof-of-work solution.
///
/// Returns `true` when
/// `SHA256(nonce\nname\npublic_key\nproof_decimal).leading_zeros() >= difficulty`.
///
/// The canonical payload uses `\n` separators — the same convention as the
/// request-signing scheme — so the derivation is unambiguous regardless of
/// field lengths.
#[must_use]
pub fn verify_pow(nonce: &str, name: &str, public_key: &str, proof: u64, difficulty: u32) -> bool {
    use sha2::{Digest, Sha256};
    let payload = format!("{nonce}\n{name}\n{public_key}\n{proof}");
    let hash = Sha256::digest(payload.as_bytes());

    let mut bits = 0u32;
    for byte in &hash {
        let z = byte.leading_zeros();
        bits += z;
        if z < 8 {
            break;
        }
    }
    bits >= difficulty
}

#[cfg(test)]
mod tests;
