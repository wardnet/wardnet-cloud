//! Shared authentication primitives.
//!
//! These are the transport-neutral building blocks every service uses to
//! authenticate a daemon request: the [`Principal`] a verified credential
//! resolves to, the [`AuthenticatedInstall`] extractor handlers read it through,
//! the identity-JWT → principal step ([`principal_from_jwt`]), and the raw
//! Ed25519 request-signature check ([`verify_signature_bytes`]).
//!
//! The full auth **middleware** (`auth_layer`) is per-service: it is coupled to a
//! concrete `AppState` (its replay cache, JWT verifier, and — for Tenants — the
//! opaque-bearer DB lookup), so it lives in each service crate and composes these
//! primitives.

use axum::http::request::Parts;
use axum::{Json, extract::FromRequestParts, http::StatusCode};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

use crate::error::ErrorBody;
use crate::token::Verifier;

// ── Authenticated principal ────────────────────────────────────────────────────

/// The install authenticated by the current request. Deliberately slim — it is
/// produced identically by every auth path (opaque bearer + identity JWT), and
/// carries only what handlers read (`id`, `name`). The daemon public key used to
/// verify the request signature stays local to the middleware (it is not stamped
/// into request extensions).
#[derive(Debug, Clone)]
pub struct Principal {
    /// Server-assigned install UUID.
    pub id: String,
    /// The install's vanity subdomain slug.
    pub name: String,
}

// ── Axum extractor ───────────────────────────────────────────────────────────

/// Extractor that resolves to the [`Principal`] authenticated by the current
/// request.
///
/// Reads the principal previously inserted into request extensions by the
/// service's auth middleware. Returns `401 Unauthorized` if absent — i.e. the
/// request reached an authenticated handler without a valid credential.
pub struct AuthenticatedInstall(pub Principal);

impl<S> FromRequestParts<S> for AuthenticatedInstall
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ErrorBody>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(AuthenticatedInstall)
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorBody {
                        error: "authentication required".to_string(),
                    }),
                )
            })
    }
}

// ── Credential resolution ───────────────────────────────────────────────────────

/// Resolve a [`Principal`] from a compact identity JWT, verifying it **offline**
/// with the Tenants public key (no DB lookup) and extracting the `cnf`
/// proof-of-possession key.
///
/// Returns the principal plus the daemon public key the request signature must
/// then verify against (the JWT's `cnf` key). A JWT that fails verification, or
/// whose `cnf` key is malformed, is an `Err` — the caller maps it to a hard 401.
///
/// # Errors
/// Returns an error if the JWT does not verify or its `cnf` key is malformed.
pub fn principal_from_jwt(
    verifier: &Verifier,
    token: &str,
) -> anyhow::Result<(Principal, [u8; 32])> {
    let claims = verifier.verify(token)?;
    let pub_key_bytes = claims.pop_public_key()?;
    let principal = Principal {
        id: claims.sub,
        name: claims.vanity,
    };
    Ok((principal, pub_key_bytes))
}

/// Whether a `Bearer` value has the compact-JWS shape (`header.payload.signature`)
/// — three base64url segments. The opaque bearer token is hex (no dots), so the
/// two are unambiguous.
#[must_use]
pub fn looks_like_jwt(token: &str) -> bool {
    token.split('.').count() == 3
}

// ── Signature verification ────────────────────────────────────────────────────

/// Verify an Ed25519 signature over `message` using the raw 32 public-key bytes.
///
/// # Errors
/// Returns an error if the key/signature are malformed or the signature does not
/// verify against `message`.
pub fn verify_signature_bytes(
    pub_key_bytes: &[u8; 32],
    message: &[u8],
    signature_b64: &str,
) -> anyhow::Result<()> {
    let verifying_key = VerifyingKey::from_bytes(pub_key_bytes)?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| anyhow::anyhow!("base64-decode signature: {e}"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 signature must be exactly 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key.verify(message, &signature)?;
    Ok(())
}
