//! The Tenants service — global identity and naming.
//!
//! Owns the identity and challenge repositories (both in the global Tenants DB)
//! and encloses every business rule of registration: the per-IP rate limits, the
//! `PoW` challenge lifecycle, and the **single-transaction registration** (insert
//! identity + burn challenge atomically — the vanity-name UNIQUE constraint is the
//! allocation lock). Also owns install authentication and deregistration.

use std::sync::Arc;

use base64::Engine as _;
use chrono::Utc;
use uuid::Uuid;

use crate::repository::{
    ChallengeRepository, Identity, IdentityRepository, RegisterOutcome, RegistrationChallenge,
    Status,
};
use wardnet_common::pow::{POW_DIFFICULTY, verify_pow};
use wardnet_common::token::Signer;

/// Domain error for [`TenantsService`]. Transport-neutral — it carries no HTTP
/// status; the API layer maps it to an `ApiError` (`From` in `crate::error`), so
/// when the service later becomes a separate process this vocabulary survives the
/// split unchanged.
#[derive(Debug, thiserror::Error)]
pub enum TenantsError {
    /// A per-IP rate limit was exceeded.
    #[error("{0}")]
    RateLimited(String),
    /// The requested name is already allocated.
    #[error("{0}")]
    NameTaken(String),
    /// The `PoW` challenge was unknown, expired, IP-mismatched, replayed, or its
    /// proof failed.
    #[error("{0}")]
    BadChallenge(String),
    /// The operation is not permitted for this install — e.g. refreshing the JWT
    /// of an install that has been deregistered (tombstoned).
    #[error("{0}")]
    Forbidden(String),
    /// An unexpected repository/infrastructure failure.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Maximum registrations from the same remote IP per 24 hours. A legitimate Pi
/// registers exactly once; 3 covers a name-clash retry plus one transient error.
const REGISTRATIONS_PER_IP_PER_DAY: i64 = 3;

/// Challenge lifetime before the nonce expires and a new one must be fetched.
const CHALLENGE_EXPIRY_SECS: i64 = 300; // 5 minutes

/// Maximum challenges issued per remote IP per hour.
const CHALLENGES_PER_IP_PER_HOUR: i64 = 20;

/// Lifetime of a minted identity JWT. Short by design — the daemon refreshes it at
/// `POST /v1/token` (3d) by re-authenticating with its Ed25519 key. The JWT is not
/// yet verified by any service (that cutover is 3c), so this is the operational
/// value once the lifecycle is wired, not a load-bearing constant today.
const IDENTITY_JWT_TTL_SECS: i64 = 3600; // 1 hour

/// Inputs to [`TenantsService::register`] (the request has already been validated
/// and the public key decoded by the handler).
pub struct RegisterParams<'a> {
    /// Desired subdomain slug (already validated).
    pub name: &'a str,
    /// Base64 Ed25519 public key (already validated).
    pub public_key: &'a str,
    /// Raw Ed25519 public-key bytes, decoded from `public_key`.
    pub pub_key_bytes: [u8; 32],
    /// Challenge UUID from `GET /v1/register/challenge`.
    pub challenge_id: &'a str,
    /// `PoW` proof.
    pub proof: u64,
    /// The caller's remote IP (for challenge binding + rate-limit accounting).
    pub remote_ip: &'a str,
    /// Region this instance serves.
    pub region: &'a str,
}

/// Result of a successful registration. The handler shapes the HTTP response
/// (subdomain FQDN, region) from this plus config.
pub struct RegisterResult {
    /// Server-assigned install UUID.
    pub id: String,
    /// Opaque bearer token — returned to the caller exactly once.
    pub bearer_token: String,
    /// Tenants-signed identity JWT (sender-constrained via the daemon's `cnf` key).
    /// The daemon stores and carries this; verification by DDNS/Tunneller is 3c.
    pub identity_jwt: String,
}

/// Global identity + naming service. Holds the JWT [`Signer`] (a Tenants concern —
/// only Tenants mints tokens).
pub struct TenantsService {
    identities: Arc<dyn IdentityRepository>,
    challenges: Arc<dyn ChallengeRepository>,
    signer: Signer,
}

impl TenantsService {
    /// Wire the service over its repositories and the JWT signing key.
    #[must_use]
    pub fn new(
        identities: Arc<dyn IdentityRepository>,
        challenges: Arc<dyn ChallengeRepository>,
        signer: Signer,
    ) -> Self {
        Self {
            identities,
            challenges,
            signer,
        }
    }

    /// Issue a single-use `PoW` challenge, enforcing the per-IP hourly rate limit.
    ///
    /// # Errors
    /// [`TenantsError::RateLimited`] past the hourly cap; `Internal` on a
    /// repository error.
    pub async fn issue_challenge(
        &self,
        remote_ip: String,
    ) -> Result<RegistrationChallenge, TenantsError> {
        let since = Utc::now() - chrono::Duration::hours(1);
        let count = self.challenges.count_from_ip(&remote_ip, since).await?;
        if count >= CHALLENGES_PER_IP_PER_HOUR {
            return Err(TenantsError::RateLimited(
                "challenge rate limit exceeded (20 per IP per hour)".to_string(),
            ));
        }

        let mut nonce_bytes = [0u8; 32];
        rand::fill(&mut nonce_bytes);
        let now = Utc::now();
        let challenge = RegistrationChallenge {
            id: Uuid::new_v4().to_string(),
            nonce: hex::encode(nonce_bytes),
            difficulty: POW_DIFFICULTY,
            remote_ip,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(CHALLENGE_EXPIRY_SECS),
            used_at: None,
        };

        self.challenges.insert(&challenge).await?;
        Ok(challenge)
    }

    /// Whether `name` is already allocated in the global identity table.
    ///
    /// # Errors
    /// Propagates a repository error.
    pub async fn is_name_taken(&self, name: &str) -> anyhow::Result<bool> {
        self.identities.is_name_taken(name).await
    }

    /// Register a new installation in a single global-DB transaction.
    ///
    /// Rate-limit → validate the challenge (unexpired, IP-bound, `PoW`) →
    /// [`IdentityRepository::register`], which atomically burns the challenge and
    /// inserts the identity (the vanity-name UNIQUE constraint is the allocation
    /// lock). The transaction means a name clash never burns the challenge
    /// (invariant #3) and a reused challenge never leaves a half-registered
    /// identity — there is no compensating saga.
    ///
    /// # Errors
    /// [`TenantsError::RateLimited`], [`TenantsError::BadChallenge`]
    /// (unknown/expired/foreign/used challenge or failed `PoW`),
    /// [`TenantsError::NameTaken`], or `Internal`.
    pub async fn register(&self, p: RegisterParams<'_>) -> Result<RegisterResult, TenantsError> {
        self.check_registration_rate_limit(p.remote_ip).await?;
        self.validate_challenge(&p).await?;

        let id = Uuid::new_v4().to_string();
        let (bearer_token, token_hash) = generate_token();
        let now = Utc::now();

        // Mint the identity JWT BEFORE the DB transaction: a signing failure must
        // not leave a committed identity behind.
        let identity_jwt = self.mint_identity_jwt(&id, p.name, p.pub_key_bytes)?;

        let identity = Identity {
            id: id.clone(),
            name: p.name.to_owned(),
            region: p.region.to_owned(),
            public_key: p.public_key.to_owned(),
            pub_key_bytes: p.pub_key_bytes,
            token_hash,
            status: Status::Active,
            created_at: now,
        };

        match self
            .identities
            .register(&identity, p.challenge_id, now)
            .await?
        {
            RegisterOutcome::Registered => {}
            RegisterOutcome::NameTaken => {
                return Err(TenantsError::NameTaken(format!(
                    "name '{}' is already taken",
                    p.name
                )));
            }
            RegisterOutcome::ChallengeAlreadyUsed => {
                return Err(TenantsError::BadChallenge(
                    "challenge has already been used".to_string(),
                ));
            }
        }

        // Best-effort rate-limit accounting: the registration is already committed,
        // so a failure here (an advisory counter) must not fail the request.
        if let Err(e) = self.identities.log_registration(p.remote_ip, now).await {
            tracing::error!(install_id = %id, error = %e, "failed to log registration for rate-limiting");
        }

        tracing::info!(install_id = %id, name = %p.name, region = %p.region, "new installation registered");
        Ok(RegisterResult {
            id,
            bearer_token,
            identity_jwt,
        })
    }

    /// Authenticate an install by the hex SHA-256 of its bearer token.
    ///
    /// Used by the auth middleware. Returns the verified [`Identity`] (public key
    /// pre-decoded) or `None` for an unknown token or a deregistered install.
    ///
    /// # Errors
    /// Propagates a repository error.
    pub async fn authenticate(&self, token_hash: &str) -> anyhow::Result<Option<Identity>> {
        self.identities.find_by_token_hash(token_hash).await
    }

    /// Deregister an install: **tombstone** its identity (`status` →
    /// `deregistered`). The row and its name allocation survive (for
    /// introspection and audit), and a tombstoned install can neither
    /// authenticate (the `find_by_*` `status='active'` filter) nor refresh its
    /// JWT — so access ends within the JWT TTL. The regional operational row is
    /// torn down separately by `DdnsService`.
    ///
    /// # Errors
    /// Propagates a repository error.
    pub async fn deregister_identity(&self, id: &str) -> anyhow::Result<()> {
        self.identities.tombstone(id, Utc::now()).await
    }

    /// Issue a fresh identity JWT for an already-authenticated install
    /// (`POST /v1/installs/{id}/token`). Re-checks liveness: the active identity is
    /// loaded by `id`, so a tombstoned install (which may still hold a valid JWT)
    /// cannot refresh — its access ends at the current token's expiry. The new
    /// token's `cnf` is the install's registered key.
    ///
    /// # Errors
    /// [`TenantsError::Forbidden`] if the install has no active identity
    /// (deregistered or unknown); `Internal` on a repository or signing error.
    pub async fn refresh_token(&self, id: &str) -> Result<String, TenantsError> {
        let identity = self
            .identities
            .find_by_id(id)
            .await?
            .ok_or_else(|| TenantsError::Forbidden("installation is not active".to_string()))?;
        self.mint_identity_jwt(&identity.id, &identity.name, identity.pub_key_bytes)
    }

    /// Of the given install IDs, return those that have **no active identity**
    /// (tombstoned or never-registered). The DDNS reconcile reaper polls this to
    /// tear down DNS state for deregistered installs.
    ///
    /// # Errors
    /// Propagates a repository error.
    pub async fn introspect_inactive(&self, ids: &[String]) -> anyhow::Result<Vec<String>> {
        self.identities.find_inactive(ids).await
    }

    // ── private ────────────────────────────────────────────────────────────────

    /// Mint a Tenants-signed identity JWT. `cnf` is re-encoded from the validated
    /// 32 public-key bytes so it is always canonical base64, making the token
    /// sender-constrained against a byte-exact key.
    fn mint_identity_jwt(
        &self,
        id: &str,
        vanity: &str,
        pub_key_bytes: [u8; 32],
    ) -> Result<String, TenantsError> {
        let cnf_ed25519 = base64::engine::general_purpose::STANDARD.encode(pub_key_bytes);
        self.signer
            .sign(
                id,
                vanity,
                &cnf_ed25519,
                Utc::now().timestamp(),
                IDENTITY_JWT_TTL_SECS,
            )
            .map_err(TenantsError::Internal)
    }

    /// Enforce the per-IP registration rate limit (3 per IP per 24 h).
    async fn check_registration_rate_limit(&self, remote_ip: &str) -> Result<(), TenantsError> {
        let since_24h = Utc::now() - chrono::Duration::days(1);
        let reg_count = self
            .identities
            .count_registrations_from_ip(remote_ip, since_24h)
            .await?;
        if reg_count >= REGISTRATIONS_PER_IP_PER_DAY {
            return Err(TenantsError::RateLimited(
                "registration rate limit exceeded (3 per IP per 24 h)".to_string(),
            ));
        }
        Ok(())
    }

    /// Resolve the `PoW` challenge and verify expiry, IP binding, and proof. The
    /// authoritative single-use burn happens inside the registration transaction;
    /// this is the fail-fast advisory pre-check.
    async fn validate_challenge(&self, p: &RegisterParams<'_>) -> Result<(), TenantsError> {
        let challenge = self
            .challenges
            .find_by_id(p.challenge_id)
            .await?
            .ok_or_else(|| TenantsError::BadChallenge("unknown challenge_id".to_string()))?;

        if Utc::now() > challenge.expires_at {
            return Err(TenantsError::BadChallenge(
                "challenge has expired — fetch a new one from GET /v1/register/challenge"
                    .to_string(),
            ));
        }
        if challenge.remote_ip != p.remote_ip {
            return Err(TenantsError::BadChallenge(
                "challenge was issued to a different IP address".to_string(),
            ));
        }
        if !verify_pow(
            &challenge.nonce,
            p.name,
            p.public_key,
            p.proof,
            challenge.difficulty,
        ) {
            return Err(TenantsError::BadChallenge(
                "proof-of-work verification failed".to_string(),
            ));
        }
        Ok(())
    }
}

/// Generate a random 32-byte bearer token, returning `(raw_token_hex,
/// sha256_hex)`. Only the hash is stored; the raw token is returned once.
fn generate_token() -> (String, String) {
    use sha2::{Digest, Sha256};
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let token = hex::encode(bytes);
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    (token, hash)
}
