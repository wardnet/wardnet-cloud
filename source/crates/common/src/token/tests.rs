use base64::Engine as _;
use ed25519_dalek::SigningKey;

use super::{Claims, ClaimsSpec, Confirmation, PrincipalType, Signer, Verifier};
use crate::test_helpers::jwt_keypair_pem;

const TTL: i64 = 300;

/// Current wall-clock seconds. jsonwebtoken validates `exp` against the real
/// system clock, so tokens under test must be issued relative to "now".
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A daemon request-signing keypair plus the base64 `cnf` of its public key.
fn daemon_key(seed: u8) -> (SigningKey, String) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let cnf = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
    (key, cnf)
}

fn signer() -> (Signer, Verifier) {
    let (priv_pem, pub_pem) = jwt_keypair_pem(1);
    let signer = Signer::from_pem(priv_pem.as_bytes(), Some("k1".to_owned())).unwrap();
    let verifier = Verifier::from_pem(pub_pem.as_bytes()).unwrap();
    (signer, verifier)
}

/// A daemon, network-scoped token spec.
fn daemon_spec(cnf: &str) -> ClaimsSpec<'_> {
    ClaimsSpec {
        tenant_id: "tenant-1",
        principal_type: PrincipalType::Daemon,
        subject: "daemon-123",
        network: Some("net-1"),
        cnf_ed25519_b64: Some(cnf),
    }
}

// ── Envelope: sign / verify ────────────────────────────────────────────────────

#[test]
fn sign_then_verify_round_trips_daemon_claims() {
    let (signer, verifier) = signer();
    let (_daemon, cnf) = daemon_key(9);
    let iat = now();

    let token = signer.sign(&daemon_spec(&cnf), iat, TTL).unwrap();
    let claims = verifier.verify(&token).unwrap();

    assert_eq!(claims.iss, super::ISSUER);
    assert_eq!(claims.tid, "tenant-1");
    assert_eq!(claims.pt, PrincipalType::Daemon);
    assert_eq!(claims.sub, "daemon-123");
    assert_eq!(claims.net.as_deref(), Some("net-1"));
    assert_eq!(claims.iat, iat);
    assert_eq!(claims.exp, iat + TTL);
    // cnf decodes to the daemon's 32-byte public key.
    assert_eq!(claims.cnf.as_ref().unwrap().ed25519, cnf);
    assert_eq!(claims.pop_public_key().unwrap().len(), 32);
}

#[test]
fn user_token_has_no_cnf_or_network() {
    let (signer, verifier) = signer();
    let iat = now();
    let spec = ClaimsSpec {
        tenant_id: "tenant-1",
        principal_type: PrincipalType::User,
        subject: "user-7",
        network: None,
        cnf_ed25519_b64: None,
    };

    let token = signer.sign(&spec, iat, TTL).unwrap();
    let claims = verifier.verify(&token).unwrap();

    assert_eq!(claims.pt, PrincipalType::User);
    assert_eq!(claims.sub, "user-7");
    assert!(claims.net.is_none());
    assert!(claims.cnf.is_none());
    assert!(claims.pop_public_key().is_err());
}

#[test]
fn expired_token_is_rejected() {
    let (signer, verifier) = signer();
    let (_daemon, cnf) = daemon_key(9);

    // Issued far in the past with a short TTL → exp well before now (beyond leeway).
    let issued = now() - 10_000;
    let token = signer.sign(&daemon_spec(&cnf), issued, TTL).unwrap();

    assert!(verifier.verify(&token).is_err());
}

#[test]
fn wrong_issuer_is_rejected() {
    let (_signer, verifier) = signer();
    let (priv_pem, _pub_pem) = jwt_keypair_pem(1);
    let (_daemon, cnf) = daemon_key(9);
    let iat = now();

    // Forge a token signed by the *correct* key but with a foreign issuer.
    let claims = Claims {
        iss: "evil-corp".to_owned(),
        tid: "tenant-1".to_owned(),
        pt: PrincipalType::Daemon,
        sub: "daemon-123".to_owned(),
        net: Some("net-1".to_owned()),
        cnf: Some(Confirmation { ed25519: cnf }),
        iat,
        exp: iat + TTL,
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some("k1".to_owned());
    let key = jsonwebtoken::EncodingKey::from_ed_pem(priv_pem.as_bytes()).unwrap();
    let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();

    assert!(verifier.verify(&token).is_err());
}

#[test]
fn tampered_token_is_rejected() {
    let (signer, verifier) = signer();
    let (_daemon, cnf) = daemon_key(9);
    let token = signer.sign(&daemon_spec(&cnf), now(), TTL).unwrap();

    // Flip the last character of the signature segment.
    let mut chars: Vec<char> = token.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();

    assert!(verifier.verify(&tampered).is_err());
}

#[test]
fn token_from_a_different_signer_is_rejected() {
    let (signer, _verifier) = signer();
    let (_daemon, cnf) = daemon_key(9);
    let token = signer.sign(&daemon_spec(&cnf), now(), TTL).unwrap();

    // A verifier built from an unrelated keypair must reject the token.
    let (_other_priv, other_pub) = jwt_keypair_pem(2);
    let foreign = Verifier::from_pem(other_pub.as_bytes()).unwrap();
    assert!(foreign.verify(&token).is_err());
}

#[test]
fn signer_rejects_garbage_pem() {
    assert!(Signer::from_pem(b"not a pem", None).is_err());
    assert!(Verifier::from_pem(b"not a pem").is_err());
}
