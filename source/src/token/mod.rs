//! The Tenants-signed **identity JWT** — the credential the daemon carries to all
//! three cloud services.
//!
//! **Status (#610):** this module is the verified credential core, not yet on the
//! request path. The auth middleware still authenticates the opaque bearer token;
//! the cutover (middleware verifies the JWT + `cnf` `PoP`, registration mints one)
//! lands in a later sub-step. Until then this is exercised only by its own tests.
//!
//! This replaces the opaque bearer token. Tenants signs a short-TTL `EdDSA` JWT at
//! registration (and refresh); DDNS and Tunneller **verify it offline** with the
//! Tenants public key — no per-request identity RPC. The token is
//! **sender-constrained** (RFC 7800 proof-of-possession): its `cnf` claim carries
//! the daemon's Ed25519 public key, and a verifier accepts a request only if the
//! request signature checks against that key. A stolen token is inert without the
//! daemon's private key, so a compromised service cannot replay a customer token
//! to a sibling service.
//!
//! ## Roles
//! - **Tenants** holds the JWT signing key ([`Signer`]) and mints tokens.
//! - **DDNS / Tunneller** hold only the public verify key ([`Verifier`]); they
//!   verify the envelope offline and then check the request signature
//!   against the embedded `cnf` key. Tunneller additionally reads the daemon
//!   pubkey straight from the verified `cnf` for its tunnel challenge-response —
//!   no pubkey lookup at all.
//!
//! Keys are distributed as PEM via the same `SecretsProvider`/tmpfs channel as the
//! mesh certs (`JWT_SIGNING_KEY_PATH` / `JWT_VERIFY_KEY_PATH`). Revocation is by
//! **short TTL** plus a thin Tenants introspection path (the DDNS reconcile reaper);
//! there is no JWT denylist here.

use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// The only issuer this fleet trusts. Set on every minted token and required on
/// verify, so a token signed by anything but Tenants is rejected.
pub const ISSUER: &str = "tenants";

/// RFC 7800 confirmation claim carrying the daemon's Ed25519 public key
/// (standard-base64 of the raw 32 bytes) for proof-of-possession.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Confirmation {
    /// Standard-base64 of the daemon's 32-byte Ed25519 public key.
    pub ed25519: String,
}

/// The identity claims carried by the token (`#610`: identity only — `#609` adds
/// entitlement/lease claims to this same envelope).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityClaims {
    /// Issuer — always [`ISSUER`].
    pub iss: String,
    /// Subject — the install id (UUID string).
    pub sub: String,
    /// The install's vanity name.
    pub vanity: String,
    /// Proof-of-possession key (the daemon's Ed25519 public key).
    pub cnf: Confirmation,
    /// Issued-at (Unix seconds).
    pub iat: i64,
    /// Expiry (Unix seconds).
    pub exp: i64,
}

impl IdentityClaims {
    /// Decode the `cnf` Ed25519 public key into raw bytes for `PoP` / tunnel
    /// challenge-response.
    ///
    /// # Errors
    /// Returns an error if the `cnf` value is not base64 of exactly 32 bytes.
    pub fn pop_public_key(&self) -> anyhow::Result<[u8; 32]> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(self.cnf.ed25519.trim())
            .map_err(|e| anyhow::anyhow!("cnf ed25519 is not valid base64: {e}"))?;
        bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("cnf ed25519 must be 32 bytes, got {}", v.len()))
    }
}

/// Mints identity JWTs. Held only by the Tenants service.
pub struct Signer {
    key: EncodingKey,
    header: Header,
}

impl Signer {
    /// Build a signer from the `EdDSA` private key PEM (PKCS#8 `BEGIN PRIVATE KEY`).
    ///
    /// `kid` is stamped into the JOSE header to support key rotation (verifiers
    /// select the matching public key); pass `None` for a single-key deployment.
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

    /// Mint a token for `install_id` / `vanity` bound to the daemon public key
    /// `cnf_ed25519_b64`, valid for `ttl_secs` from `issued_at`.
    ///
    /// # Errors
    /// Returns an error if JWT encoding fails.
    pub fn sign(
        &self,
        install_id: &str,
        vanity: &str,
        cnf_ed25519_b64: &str,
        issued_at: i64,
        ttl_secs: i64,
    ) -> anyhow::Result<String> {
        let claims = IdentityClaims {
            iss: ISSUER.to_owned(),
            sub: install_id.to_owned(),
            vanity: vanity.to_owned(),
            cnf: Confirmation {
                ed25519: cnf_ed25519_b64.to_owned(),
            },
            iat: issued_at,
            exp: issued_at + ttl_secs,
        };
        jsonwebtoken::encode(&self.header, &claims, &self.key)
            .map_err(|e| anyhow::anyhow!("failed to sign identity JWT: {e}"))
    }
}

/// Verifies identity JWTs offline. Held by DDNS and Tunneller (and Tenants for its
/// own refresh path).
pub struct Verifier {
    key: DecodingKey,
    validation: Validation,
}

impl Verifier {
    /// Build a verifier from the `EdDSA` public key PEM (SPKI `BEGIN PUBLIC KEY`).
    ///
    /// Verification requires `EdDSA`, a matching [`ISSUER`], and an unexpired `exp`
    /// (with jsonwebtoken's default leeway). Audience validation is disabled — the
    /// token is not audience-scoped.
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
        // Exact expiry: revocation on the offline path is bounded by the token TTL,
        // so the default 60 s leeway would silently widen that window. The request
        // freshness window (±60 s on `X-Wardnet-Timestamp`) is enforced separately.
        validation.leeway = 0;
        Ok(Self { key, validation })
    }

    /// Verify the token envelope (signature, issuer, expiry) and return its claims.
    ///
    /// This is the offline-verify step; the caller then binds the request to the
    /// token's `cnf` key by checking the request signature against it.
    ///
    /// # Errors
    /// Returns an error if the signature, issuer, or expiry check fails.
    pub fn verify(&self, token: &str) -> anyhow::Result<IdentityClaims> {
        let data = jsonwebtoken::decode::<IdentityClaims>(token, &self.key, &self.validation)
            .map_err(|e| anyhow::anyhow!("identity JWT verification failed: {e}"))?;
        Ok(data.claims)
    }
}

/// The canonical request payload covered by the daemon's Ed25519 signature
/// (proof-of-possession). Identical to the legacy bearer-auth payload so the
/// daemon's request-signing is unchanged: `"<METHOD>\n<path_and_query>\n<ts>\n<hex-sha256(body)>"`.
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
