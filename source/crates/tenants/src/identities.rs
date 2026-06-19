//! `IdentitiesService` — the **Identities aggregate** (ADR-0009): the human/web
//! login plane. A segregated aggregate that owns **only** its own two repositories
//! ([`TenantIdentityRepository`], [`SessionRepository`]) plus a password hasher, the
//! federated providers, and a shared [`Signer`] (a capability, not aggregate state).
//!
//! It never holds the tenant/network/daemon/subscription repositories. It coordinates
//! with the tenant aggregate through the same one-way-edge + domain-event pattern the
//! subscription aggregate uses (invariant #23, ADR-0007):
//! - **Reads / create-delegation** are direct method calls on the owner
//!   ([`TenantsService::find_tenant_by_email`], [`TenantsService::register_tenant`],
//!   [`TenantsService::consume_signup_code`]) — a one-way `IdentitiesService →
//!   TenantsService` edge, mirroring `TenantsService → SubscriptionService::current`.
//! - **The reverse side-effect** (deregister → force-logout) rides a domain event: the
//!   identities reactor reacts to `TenantDeregistered` by calling
//!   [`IdentitiesService::purge_for`]. The FK cascade covers the eventual hard sweep.
//!
//! The login model (ADR-0009): a verified-email **two-gate** resolver
//! ([`resolve_identity`](Self::resolve_identity)) maps any login method to a tenant
//! (gate 1: email proven; gate 2: match→auto-link / no-match→web-first signup), a
//! revocable server-side **session** anchors the browser, and a silent
//! [`exchange_session`](Self::exchange_session) mints a short-TTL `USER` JWT.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};

use wardnet_common::token::{ClaimsSpec, PrincipalType, Signer};

use crate::error::IdentitiesError;
use crate::repository::identity::{TenantIdentity, TenantIdentityRepository};
use crate::repository::session::{Session, SessionRepository};
use crate::service::TenantsService;

pub mod provider;
pub mod reactor;

use provider::{ExternalIdentityProvider, VerifiedIdentity};

/// The `password` provider name (its `subject` is the email).
const PROVIDER_PASSWORD: &str = "password";
/// Minimum acceptable password length.
const MIN_PASSWORD_LEN: usize = 8;
/// Default `USER` JWT TTL (seconds). Short, because a leaked bearer token (without the
/// cookie) is bounded only by this; the cookie/session is the durable credential.
pub const DEFAULT_USER_JWT_TTL_SECS: i64 = 300;
/// Session sliding-window length (seconds) — 30 days, refreshed on each exchange.
const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// The human/web authentication aggregate.
pub struct IdentitiesService {
    identities: Arc<dyn TenantIdentityRepository>,
    sessions: Arc<dyn SessionRepository>,
    /// The tenant aggregate — read/create-delegation edge only (never its repos).
    tenants: Arc<TenantsService>,
    /// Federated providers keyed by name (`google` / `github`); empty in dev/test.
    providers: HashMap<String, Arc<dyn ExternalIdentityProvider>>,
    /// Shared signing capability — mints the `USER` JWT (`aud:[tenants]`).
    signer: Arc<Signer>,
    /// `USER` JWT lifetime (seconds).
    user_jwt_ttl_secs: i64,
}

impl IdentitiesService {
    #[must_use]
    pub fn new(
        identities: Arc<dyn TenantIdentityRepository>,
        sessions: Arc<dyn SessionRepository>,
        tenants: Arc<TenantsService>,
        providers: HashMap<String, Arc<dyn ExternalIdentityProvider>>,
        signer: Arc<Signer>,
        user_jwt_ttl_secs: i64,
    ) -> Self {
        Self {
            identities,
            sessions,
            tenants,
            providers,
            signer,
            user_jwt_ttl_secs,
        }
    }

    // ── Password ─────────────────────────────────────────────────────────────────

    /// Sign up with email + password. Gate 1 is the one-time `code` (consumed via the
    /// tenant aggregate, proving the email); the resolver then auto-links a matching
    /// tenant or creates one (web-first signup). Returns the raw session token.
    ///
    /// # Errors
    /// [`IdentitiesError::BadCode`] on a bad/expired code or an email mismatch;
    /// [`IdentitiesError::BadRequest`] on a too-weak password;
    /// [`IdentitiesError::Conflict`] if the email already has a password.
    pub async fn password_signup(
        &self,
        email: &str,
        code: &str,
        password: &str,
    ) -> Result<String, IdentitiesError> {
        check_password(password)?;
        // Gate 1: the code proves control of its email (a one-way edge to the tenant
        // aggregate, which owns the enrollment_codes table).
        let code_email = self
            .tenants
            .consume_signup_code(code)
            .await?
            .ok_or_else(|| IdentitiesError::BadCode("invalid or expired code".to_string()))?;
        if code_email != normalize_email(email)? {
            return Err(IdentitiesError::BadCode(
                "code was not issued for this email".to_string(),
            ));
        }
        let hash = hash_password(password)?;
        let verified = VerifiedIdentity {
            provider: PROVIDER_PASSWORD.to_string(),
            subject: code_email.clone(),
            email: code_email,
            email_verified: true,
        };
        let (tenant_id, existed) = self.resolve_identity(&verified, Some(hash)).await?;
        if existed {
            return Err(IdentitiesError::Conflict(
                "an account with this email already has a password".to_string(),
            ));
        }
        self.create_session(&tenant_id).await
    }

    /// Log in with email + password. Returns the raw session token.
    ///
    /// # Errors
    /// [`IdentitiesError::Unauthorized`] on an unknown email or a bad password.
    pub async fn password_login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<String, IdentitiesError> {
        let email = normalize_email(email)?;
        let identity = self
            .identities
            .find_by_provider_subject(PROVIDER_PASSWORD, &email)
            .await
            .map_err(IdentitiesError::Internal)?;
        // Verify even on a miss-shaped row to avoid leaking which emails exist via timing
        // is out of scope; a missing identity is a flat reject.
        let Some(identity) = identity else {
            return Err(IdentitiesError::Unauthorized(
                "invalid email or password".to_string(),
            ));
        };
        let ok = identity
            .secret_hash
            .as_deref()
            .is_some_and(|hash| verify_password(hash, password));
        if !ok {
            return Err(IdentitiesError::Unauthorized(
                "invalid email or password".to_string(),
            ));
        }
        self.create_session(&identity.tenant_id).await
    }

    /// Issue a one-time password-reset code for `email` (rate-limited per IP, emailed),
    /// reusing the signup-code primitive on the tenant aggregate. Returns the raw code
    /// only when no real email was sent (dev), mirroring the enrollment-code endpoint.
    ///
    /// # Errors
    /// [`IdentitiesError::BadRequest`] on a malformed email;
    /// [`IdentitiesError`] surfaced from the tenant aggregate (e.g. rate limit).
    pub async fn request_password_reset(
        &self,
        email: &str,
        remote_ip: &str,
    ) -> Result<String, IdentitiesError> {
        Ok(self.tenants.issue_signup_code(email, remote_ip).await?)
    }

    /// Reset (or set) a password from a one-time `code`. Burns the code (gate 1),
    /// resolves the tenant by the proven email, upserts its `password` identity, and
    /// **deletes all the tenant's sessions** (force re-login everywhere). A code for an
    /// email with no account is a silent no-op (no enumeration).
    ///
    /// # Errors
    /// [`IdentitiesError::BadCode`] on a bad/expired code;
    /// [`IdentitiesError::BadRequest`] on a too-weak password.
    pub async fn password_reset(
        &self,
        code: &str,
        new_password: &str,
    ) -> Result<(), IdentitiesError> {
        check_password(new_password)?;
        let email = self
            .tenants
            .consume_signup_code(code)
            .await?
            .ok_or_else(|| IdentitiesError::BadCode("invalid or expired code".to_string()))?;
        let Some(tenant) = self.tenants.find_tenant_by_email(&email).await? else {
            // The code proved an email with no live account; nothing to reset.
            return Ok(());
        };
        let hash = hash_password(new_password)?;
        // Upsert the password identity: replace the hash, or link a fresh password row
        // (e.g. an OIDC-born account setting its first password).
        let updated = self
            .identities
            .update_secret_hash(PROVIDER_PASSWORD, &email, &hash)
            .await
            .map_err(IdentitiesError::Internal)?;
        if !updated {
            self.identities
                .insert(&TenantIdentity {
                    tenant_id: tenant.id.clone(),
                    provider: PROVIDER_PASSWORD.to_string(),
                    subject: email.clone(),
                    secret_hash: Some(hash),
                    email: email.clone(),
                    created_at: Utc::now(),
                })
                .await
                .map_err(IdentitiesError::Internal)?;
        }
        // Revocation is the defence: a reset force-logs-out every existing session.
        self.sessions
            .delete_for_tenant(&tenant.id)
            .await
            .map_err(IdentitiesError::Internal)?;
        Ok(())
    }

    // ── Federated (OIDC / OAuth2) ──────────────────────────────────────────────────

    /// Begin a federated login: the authorize redirect + the CSRF/PKCE secrets the
    /// handler stashes in a signed cookie.
    ///
    /// # Errors
    /// [`IdentitiesError::BadRequest`] if `provider` is unknown/unconfigured.
    pub fn oidc_start(&self, provider: &str) -> Result<provider::AuthorizeRequest, IdentitiesError> {
        Ok(self.provider(provider)?.authorize_url())
    }

    /// Complete a federated login: exchange the `code` (with the stashed `verifier`),
    /// apply the two gates, ensure the identity row, and create a session. The handler
    /// has already validated the CSRF `state` against the signed cookie. Returns the
    /// raw session token.
    ///
    /// # Errors
    /// [`IdentitiesError::BadRequest`] for an unknown provider;
    /// [`IdentitiesError::Unauthorized`] if the provider did not verify the email;
    /// [`IdentitiesError::Internal`] on an exchange/verification failure.
    pub async fn oidc_callback(
        &self,
        provider: &str,
        code: &str,
        verifier: &str,
    ) -> Result<String, IdentitiesError> {
        let identity = self
            .provider(provider)?
            .exchange(code, verifier)
            .await
            .map_err(IdentitiesError::Internal)?;
        let (tenant_id, _existed) = self.resolve_identity(&identity, None).await?;
        self.create_session(&tenant_id).await
    }

    // ── Session lifecycle ──────────────────────────────────────────────────────────

    /// Silent exchange: resolve the cookie's session token to a tenant (sliding its
    /// expiry forward) and mint a short-TTL `USER` JWT (`aud:[tenants]`, `sub =
    /// tenant_id`). This is the auth plane's only cookie touchpoint — the API itself
    /// stays pure-JWT (invariant #18). "Am I logged in?" is answered by *attempting*
    /// this mint.
    ///
    /// # Errors
    /// [`IdentitiesError::Unauthorized`] if the session is absent or expired;
    /// [`IdentitiesError::Internal`] on a signing/repository failure.
    pub async fn exchange_session(&self, raw_token: &str) -> Result<String, IdentitiesError> {
        let now = Utc::now();
        let new_expires = now + Duration::seconds(SESSION_TTL_SECS);
        let tenant_id = self
            .sessions
            .touch_and_get_tenant(&hash_token(raw_token), now, new_expires)
            .await
            .map_err(IdentitiesError::Internal)?
            .ok_or_else(|| IdentitiesError::Unauthorized("no active session".to_string()))?;

        // User == Tenant 1:1, so `sub = tenant_id` (ADR-0009). aud = [tenants]
        // (ADR-0008): a user token never reaches the data plane.
        let spec = ClaimsSpec {
            tenant_id: &tenant_id,
            principal_type: PrincipalType::User,
            subject: &tenant_id,
            network: None,
            cnf_ed25519_b64: None,
            audience: vec!["tenants"],
        };
        self.signer
            .sign(&spec, now.timestamp(), self.user_jwt_ttl_secs)
            .map_err(IdentitiesError::Internal)
    }

    /// Log out the one session behind a cookie (delete its row). Idempotent.
    ///
    /// # Errors
    /// [`IdentitiesError::Internal`] on a repository failure.
    pub async fn logout(&self, raw_token: &str) -> Result<(), IdentitiesError> {
        self.sessions
            .delete(&hash_token(raw_token))
            .await
            .map_err(IdentitiesError::Internal)?;
        Ok(())
    }

    /// Log out **every** session for a tenant (kills all browsers). Idempotent.
    ///
    /// # Errors
    /// [`IdentitiesError::Internal`] on a repository failure.
    pub async fn logout_all(&self, tenant_id: &str) -> Result<(), IdentitiesError> {
        self.sessions
            .delete_for_tenant(tenant_id)
            .await
            .map_err(IdentitiesError::Internal)?;
        Ok(())
    }

    /// Force-logout + purge: delete a tenant's sessions **and** login methods. The
    /// reverse-direction side-effect the identities reactor runs on
    /// `TenantDeregistered` (ADR-0007 / invariant #23). Idempotent — the FK cascade
    /// also covers the eventual hard sweep.
    ///
    /// # Errors
    /// [`IdentitiesError::Internal`] on a repository failure.
    pub async fn purge_for(&self, tenant_id: &str) -> Result<(), IdentitiesError> {
        self.sessions
            .delete_for_tenant(tenant_id)
            .await
            .map_err(IdentitiesError::Internal)?;
        self.identities
            .delete_for_tenant(tenant_id)
            .await
            .map_err(IdentitiesError::Internal)?;
        tracing::info!(tenant_id, "purged identities + sessions for deregistered tenant");
        Ok(())
    }

    // ── Internals ──────────────────────────────────────────────────────────────────

    /// The two-gate verified-email resolver (ADR-0009). Returns `(tenant_id, existed)`,
    /// where `existed` is `true` when the `(provider, subject)` login method was
    /// already present (a returning user). For a new method it runs gate 1
    /// (`email_verified`), then gate 2 (match→auto-link / no-match→web-first signup via
    /// the tenant aggregate's `register_tenant`), and inserts the identity row.
    async fn resolve_identity(
        &self,
        verified: &VerifiedIdentity,
        secret_hash: Option<String>,
    ) -> Result<(String, bool), IdentitiesError> {
        if let Some(existing) = self
            .identities
            .find_by_provider_subject(&verified.provider, &verified.subject)
            .await
            .map_err(IdentitiesError::Internal)?
        {
            return Ok((existing.tenant_id, true));
        }

        // Gate 1: the provider must have proven control of the email.
        if !verified.email_verified {
            return Err(IdentitiesError::Unauthorized(
                "provider did not verify the email".to_string(),
            ));
        }
        let email = normalize_email(&verified.email)?;

        // Gate 2: a matching live tenant → auto-link; no match → web-first signup
        // (delegated to the owner so the write + `TenantCreated` stay in the tenant
        // aggregate). `IdentitiesService` never touches the tenant repository.
        let tenant_id = match self.tenants.find_tenant_by_email(&email).await? {
            Some(tenant) => tenant.id,
            None => self.tenants.register_tenant(&email).await?.id,
        };

        self.identities
            .insert(&TenantIdentity {
                tenant_id: tenant_id.clone(),
                provider: verified.provider.clone(),
                subject: verified.subject.clone(),
                secret_hash,
                email,
                created_at: Utc::now(),
            })
            .await
            .map_err(IdentitiesError::Internal)?;
        Ok((tenant_id, false))
    }

    /// Mint + persist a fresh session, returning the raw token (the only time it
    /// exists in cleartext; the cookie carries it, the DB stores only its hash).
    async fn create_session(&self, tenant_id: &str) -> Result<String, IdentitiesError> {
        let raw = random_token();
        let now = Utc::now();
        self.sessions
            .create(&Session {
                token_hash: hash_token(&raw),
                tenant_id: tenant_id.to_string(),
                expires_at: now + Duration::seconds(SESSION_TTL_SECS),
                created_at: now,
            })
            .await
            .map_err(IdentitiesError::Internal)?;
        Ok(raw)
    }

    /// Look up a configured provider by name.
    fn provider(&self, name: &str) -> Result<&Arc<dyn ExternalIdentityProvider>, IdentitiesError> {
        self.providers
            .get(name)
            .ok_or_else(|| IdentitiesError::BadRequest(format!("unknown provider '{name}'")))
    }
}

/// Lowercase + trim an email and apply a minimal shape check (mirrors the tenant
/// aggregate's normalization, so the join key matches).
fn normalize_email(email: &str) -> Result<String, IdentitiesError> {
    let e = email.trim().to_lowercase();
    if e.len() < 3 || !e.contains('@') {
        return Err(IdentitiesError::BadRequest("invalid email".to_string()));
    }
    Ok(e)
}

/// Reject too-short passwords up front.
fn check_password(password: &str) -> Result<(), IdentitiesError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(IdentitiesError::BadRequest(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

/// argon2id hash of a password (PHC string). The salt is drawn from `rand` (matching
/// the enrollment-code generator), avoiding an extra `getrandom` feature.
fn hash_password(password: &str) -> Result<String, IdentitiesError> {
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};

    let salt_bytes: [u8; 16] = rand::random();
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| IdentitiesError::Internal(anyhow::anyhow!("salt encode: {e}")))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| IdentitiesError::Internal(anyhow::anyhow!("password hashing failed: {e}")))
}

/// Verify a password against a stored argon2id PHC hash (constant-time inside argon2).
#[must_use]
fn verify_password(hash: &str, password: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    PasswordHash::new(hash)
        .and_then(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed))
        .is_ok()
}

/// A random opaque token (session token / OAuth state), hex of 32 random bytes.
#[must_use]
fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

/// SHA-256 hex of a raw token — the at-rest session form (invariant #1).
#[must_use]
fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests;
