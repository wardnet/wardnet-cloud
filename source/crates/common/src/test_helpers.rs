//! Test-only helpers for the `common` crate's in-crate unit tests.
//!
//! Reachable only from `#[cfg(test)]` code in this crate. Integration tests in
//! downstream crates cannot cross the `cfg(test)` boundary and keep their own
//! copies where needed (the same pattern the service crates use).

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

/// An `EdDSA` JWT signing keypair as PEM, mirroring what INFORGE provisions for
/// Tenants (`JWT_SIGNING_KEY_PATH` / `JWT_VERIFY_KEY_PATH`).
///
/// Generated from a fixed 32-byte seed so the keypair is deterministic per `seed`
/// — distinct seeds give independent keypairs (the "wrong-signer" rejection case).
#[must_use]
pub fn jwt_keypair_pem(seed: u8) -> (String, String) {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};

    let signing = SigningKey::from_bytes(&[seed; 32]);
    let private_pem = signing
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode JWT private key PEM")
        .to_string();
    let public_pem = signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("encode JWT public key PEM");
    (private_pem, public_pem)
}

/// A throwaway mesh certificate authority for mTLS tests.
///
/// Mirrors the deploy-minted mesh PKI: a single self-signed CA root that signs
/// service leaves (each a `cert + key` PEM pair). Tests build a [`TestMeshCa`],
/// mint a server leaf and a client leaf from it, and exercise the verifier — a
/// leaf from a *different* `TestMeshCa` is the "wrong-root" rejection case.
pub struct TestMeshCa {
    issuer: Issuer<'static, KeyPair>,
    root_pem: String,
}

/// A leaf certificate (and its private key) issued by a [`TestMeshCa`], in PEM.
pub struct TestLeaf {
    /// The leaf certificate chain PEM (leaf only — the root is the trust anchor).
    pub cert_pem: String,
    /// The leaf private key PEM (PKCS#8).
    pub key_pem: String,
}

impl TestMeshCa {
    /// Generate a fresh CA with a self-signed root capable of signing leaves.
    #[must_use]
    pub fn new() -> Self {
        let key = KeyPair::generate().expect("generate CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = params.self_signed(&key).expect("self-sign CA root");
        let root_pem = root.pem();
        Self {
            issuer: Issuer::new(params, key),
            root_pem,
        }
    }

    /// The CA root certificate PEM — the trust anchor distributed to peers.
    #[must_use]
    pub fn root_pem(&self) -> &str {
        &self.root_pem
    }

    /// Mint a leaf whose only SAN is the SPIFFE URI `spiffe_id`, carrying the given
    /// extended key usage (`ServerAuth` for a serving cert, `ClientAuth` for a mesh
    /// client cert). Mirrors inforge's mesh leaves: a SPIFFE URI SAN and **no DNS SAN**.
    #[must_use]
    pub fn leaf(&self, spiffe_id: &str, eku: ExtendedKeyUsagePurpose) -> TestLeaf {
        let key = KeyPair::generate().expect("generate leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.subject_alt_names = vec![rcgen::SanType::URI(
            spiffe_id
                .try_into()
                .expect("spiffe id is a valid IA5 string"),
        )];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![eku];
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        TestLeaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }
}

impl Default for TestMeshCa {
    fn default() -> Self {
        Self::new()
    }
}
