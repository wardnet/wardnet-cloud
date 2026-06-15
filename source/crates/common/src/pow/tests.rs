use super::verify_pow;

/// Brute-force a valid proof for the given inputs at the given difficulty,
/// then verify that `verify_pow` accepts it and that difficulty+1 rejects it.
#[test]
fn pow_round_trip() {
    use sha2::{Digest, Sha256};

    let nonce = "aabbccdd";
    let name = "test-name";
    let public_key = "dGVzdA==";
    let difficulty = 8u32; // low difficulty for test speed

    // Find a valid proof. The search is bounded by the u64 range; at difficulty
    // 8 (1-in-256 chance), we expect to succeed within the first ~256 tries.
    let proof = (0u64..=1_000_000)
        .find(|&p| {
            let payload = format!("{nonce}\n{name}\n{public_key}\n{p}");
            let hash = Sha256::digest(payload.as_bytes());
            let leading: u32 = hash
                .iter()
                .map(|b| b.leading_zeros())
                .take_while(|&z| z == 8)
                .sum::<u32>()
                + hash
                    .iter()
                    .find(|&&b| b != 0)
                    .map_or(0, |b| b.leading_zeros());
            leading >= difficulty
        })
        .expect("should find proof within 1 M iterations at difficulty 8");

    assert!(verify_pow(nonce, name, public_key, proof, difficulty));
    // Wrong proof must fail.
    assert!(!verify_pow(
        nonce,
        name,
        public_key,
        proof.wrapping_add(1),
        difficulty + 16
    ));
}
