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

    /// Mint a leaf for `fqdn` carrying the given extended key usage
    /// (`ServerAuth` for a serving cert, `ClientAuth` for a mesh client cert).
    #[must_use]
    pub fn leaf(&self, fqdn: &str, eku: ExtendedKeyUsagePurpose) -> TestLeaf {
        let key = KeyPair::generate().expect("generate leaf key");
        let mut params = CertificateParams::new(vec![fqdn.to_owned()]).expect("leaf params");
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

/// Build a pool connected to an isolated per-test `PostgreSQL` database.
///
/// Requires a `PostgreSQL` server reachable at `CLOUD_TEST_DATABASE_URL`
/// (default: `postgres://postgres:postgres@127.0.0.1:5432`). The value must be a
/// bare server URL **without** a trailing `/database` path — this helper appends
/// its own database name. Start one locally with:
///
/// ```sh
/// docker compose up -d     # from source/
/// ```
///
/// In CI a `PostgreSQL` service container is started automatically.
///
/// Runs the **regional** migration set (`./migrations`).
pub async fn test_pool() -> sqlx::PgPool {
    let pool = fresh_database().await;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("apply regional migrations");
    pool
}

/// Like [`test_pool`] but for the **global Tenants DB** — runs the
/// `./migrations-global` set (identities, registration challenges, registration
/// log). Both pools share the same test server (`CLOUD_TEST_DATABASE_URL`); each
/// gets its own freshly-created database.
pub async fn test_pool_global() -> sqlx::PgPool {
    let pool = fresh_database().await;
    sqlx::migrate!("./migrations-global")
        .run(&pool)
        .await
        .expect("apply global migrations");
    pool
}

/// Create a fresh, empty per-test database on the test server and return a pool
/// connected to it (no migrations applied — the caller chooses the set).
async fn fresh_database() -> sqlx::PgPool {
    let base_url = std::env::var("CLOUD_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432".to_string());
    // We append `/<db>` below, so the override must be a bare server URL with no
    // database path component (otherwise we'd build `…/mydb/postgres`). Fail
    // fast on a misconfigured local override rather than emitting a cryptic
    // connection error. (The `postgres://` scheme has two leading slashes; a
    // database path is a third `/` after the host[:port].)
    assert!(
        base_url
            .strip_prefix("postgres://")
            .or_else(|| base_url.strip_prefix("postgresql://"))
            .is_some_and(|rest| !rest.contains('/')),
        "CLOUD_TEST_DATABASE_URL must be a bare server URL without a /database path, got: {base_url}"
    );

    // Connect to the maintenance database to issue CREATE DATABASE.
    let maintenance_pool = sqlx::PgPool::connect(&format!("{base_url}/postgres"))
        .await
        .expect("Postgres unreachable — run `docker compose up -d` from source/");

    let db_name = format!("t{}", uuid::Uuid::new_v4().simple());
    // `CREATE DATABASE` is DDL: Postgres cannot bind-parameterise the database
    // identifier, so this inline `format!` is the deliberate, test-only
    // exception to the "query strings are `const &str`" SQL convention — do not
    // copy this pattern into production DML. The name is a fresh UUID-derived
    // identifier (not user input); double-quote it so Postgres treats it as a
    // literal identifier.
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&maintenance_pool)
        .await
        .expect("CREATE DATABASE");
    drop(maintenance_pool);

    sqlx::PgPool::connect(&format!("{base_url}/{db_name}"))
        .await
        .expect("connect to test database")
}
