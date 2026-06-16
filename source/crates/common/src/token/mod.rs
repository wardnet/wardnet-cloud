//! The Tenants-signed **JWT** — the credential a daemon or (later) a user carries
//! to every cloud service.
//!
//! Tenants holds the signing key ([`Signer`]) and mints short-TTL `EdDSA` tokens;
//! every service holds only the public verify key ([`Verifier`]) and verifies them
//! **offline** — no per-request identity RPC.
//!
//! ## Claims
//! One token shape serves both principal kinds (see [`PrincipalType`]):
//! - `tid` — the tenant the token acts for (**always present**).
//! - `pt` / `sub` — the principal kind and its id (a daemon id or a user id).
//! - `net` — an **optional** network scope (a network id); set once a daemon is
//!   bound to a network, absent on the tenant-scoped token used during enrollment.
//! - `cnf` — an **optional** RFC 7800 proof-of-possession key (the daemon's Ed25519
//!   public key). Present for daemons (the request signature is checked against it),
//!   absent for users.
//!
//! There is **no `aud`** claim — per-service grant scoping is a deferred design
//! question; caller-type authorization is handled separately by the auth layer.

use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// The only issuer this fleet trusts. Set on every minted token and required on
/// verify, so a token signed by anything but Tenants is rejected.
pub const ISSUER: &str = "tenants";

/// Which kind of principal a token was granted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalType {
    /// A wardnet daemon (device). Carries a `cnf` `PoP` key; its requests are signed.
    Daemon,
    /// A human account user (the management plane). No `cnf`; bearer-only.
    User,
}

/// RFC 7800 confirmation claim carrying the daemon's Ed25519 public key
/// (standard-base64 of the raw 32 bytes) for proof-of-possession.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Confirmation {
    /// Standard-base64 of the daemon's 32-byte Ed25519 public key.
    pub ed25519: String,
}

/// The claims carried by a token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Issuer — always [`ISSUER`].
    pub iss: String,
    /// Tenant id the token acts for (always present).
    pub tid: String,
    /// Principal kind.
    pub pt: PrincipalType,
    /// Principal id — a daemon id or a user id.
    pub sub: String,
    /// Optional network scope (a network id); absent on the enrollment-time
    /// tenant-scoped token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<String>,
    /// Optional proof-of-possession key (daemons only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
    /// Issued-at (Unix seconds).
    pub iat: i64,
    /// Expiry (Unix seconds).
    pub exp: i64,
}

impl Claims {
    /// Decode the `cnf` Ed25519 public key into raw bytes for `PoP`.
    ///
    /// # Errors
    /// Returns an error if `cnf` is absent or is not base64 of exactly 32 bytes.
    pub fn pop_public_key(&self) -> anyhow::Result<[u8; 32]> {
        let cnf = self
            .cnf
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("token carries no cnf proof-of-possession key"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(cnf.ed25519.trim())
            .map_err(|e| anyhow::anyhow!("cnf ed25519 is not valid base64: {e}"))?;
        bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("cnf ed25519 must be 32 bytes, got {}", v.len()))
    }
}

/// What to mint a token for. Built by the Tenants service per request.
#[derive(Debug, Clone)]
pub struct ClaimsSpec<'a> {
    /// Tenant id the token acts for.
    pub tenant_id: &'a str,
    /// Principal kind.
    pub principal_type: PrincipalType,
    /// Principal id (daemon id or user id).
    pub subject: &'a str,
    /// Optional network scope (network id).
    pub network: Option<&'a str>,
    /// Optional `cnf` `PoP` key — standard-base64 of the daemon's 32-byte public key.
    pub cnf_ed25519_b64: Option<&'a str>,
}

/// Mints JWTs. Held only by the Tenants service.
pub struct Signer {
    key: EncodingKey,
    header: Header,
}

impl Signer {
    /// Build a signer from the `EdDSA` private key PEM (PKCS#8 `BEGIN PRIVATE KEY`).
    ///
    /// `kid` is stamped into the JOSE header to support key rotation; pass `None`
    /// for a single-key deployment.
    ///
    /// # Errors
    /// Returns an error if the PEM is not a valid `EdDSA` private key.
    pub fn from_pem(private_key_pem: &[u8], kid: Option<String>) -> anyhow::Result<Self> {
        let key = EncodingKey::from_ed_pem(private_key_pem)
            .map_err(|e| anyhow::anyhow!("invalid JWT signing key PEM: {e}"))?;
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = kid;
        Ok(Self { key, header })
    }

    /// Mint a token from `spec`, valid for `ttl_secs` from `issued_at`.
    ///
    /// # Errors
    /// Returns an error if JWT encoding fails.
    pub fn sign(&self, spec: &ClaimsSpec, issued_at: i64, ttl_secs: i64) -> anyhow::Result<String> {
        let claims = Claims {
            iss: ISSUER.to_owned(),
            tid: spec.tenant_id.to_owned(),
            pt: spec.principal_type,
            sub: spec.subject.to_owned(),
            net: spec.network.map(str::to_owned),
            cnf: spec.cnf_ed25519_b64.map(|c| Confirmation {
                ed25519: c.to_owned(),
            }),
            iat: issued_at,
            exp: issued_at + ttl_secs,
        };
        jsonwebtoken::encode(&self.header, &claims, &self.key)
            .map_err(|e| anyhow::anyhow!("failed to sign JWT: {e}"))
    }
}

/// Verifies JWTs offline. Held by every service.
pub struct Verifier {
    key: DecodingKey,
    validation: Validation,
}

impl Verifier {
    /// Build a verifier from the `EdDSA` public key PEM (SPKI `BEGIN PUBLIC KEY`).
    ///
    /// Verification requires `EdDSA`, a matching [`ISSUER`], and an unexpired `exp`
    /// with **zero** leeway (offline revocation is bounded by the token TTL, so the
    /// default leeway would silently widen it). Audience validation is disabled.
    ///
    /// # Errors
    /// Returns an error if the PEM is not a valid `EdDSA` public key.
    pub fn from_pem(public_key_pem: &[u8]) -> anyhow::Result<Self> {
        let key = DecodingKey::from_ed_pem(public_key_pem)
            .map_err(|e| anyhow::anyhow!("invalid JWT verify key PEM: {e}"))?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[ISSUER]);
        validation.validate_exp = true;
        validation.validate_aud = false;
        validation.leeway = 0;
        Ok(Self { key, validation })
    }

    /// Verify the token envelope (signature, issuer, expiry) and return its claims.
    ///
    /// # Errors
    /// Returns an error if the signature, issuer, or expiry check fails.
    pub fn verify(&self, token: &str) -> anyhow::Result<Claims> {
        let data = jsonwebtoken::decode::<Claims>(token, &self.key, &self.validation)
            .map_err(|e| anyhow::anyhow!("JWT verification failed: {e}"))?;
        Ok(data.claims)
    }
}

/// The canonical request payload covered by the daemon's Ed25519 signature
/// (proof-of-possession): `"<METHOD>\n<path_and_query>\n<ts>\n<hex-sha256(body)>"`.
#[must_use]
pub fn canonical_request_payload(
    method: &str,
    path_and_query: &str,
    timestamp: i64,
    body_sha256_hex: &str,
) -> String {
    format!("{method}\n{path_and_query}\n{timestamp}\n{body_sha256_hex}")
}

#[cfg(test)]
mod tests;
