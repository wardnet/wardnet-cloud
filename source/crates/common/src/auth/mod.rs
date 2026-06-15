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

use std::future::Future;

use axum::http::request::Parts;
use axum::{
    Json,
    extract::{FromRequestParts, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::ErrorBody;
use crate::replay_cache::ReplayCache;
use crate::token::{Verifier, canonical_request_payload};

/// Maximum allowed clock skew between the daemon and the service (seconds).
const TIMESTAMP_WINDOW_SECS: i64 = 60;

/// Hard body-size limit applied to **every** incoming request — a `DoS` guard that
/// runs before any auth check so an attacker cannot exhaust memory by streaming a
/// large body to an unauthenticated endpoint.
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// Path prefix for all authenticated install endpoints. The middleware only
/// attempts authentication when the request path starts with this prefix, so
/// unauthenticated endpoints never incur a credential resolution (closing a `DoS`
/// vector).
pub const AUTHENTICATED_PATH_PREFIX: &str = "/v1/installs/";

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

// ── Generic signed-request middleware ──────────────────────────────────────────

/// Per-service context the generic [`auth_layer`] middleware needs: the replay
/// cache and a service-specific credential resolver.
///
/// Each service's `AppState` implements this. The credential resolver is the only
/// part that differs between services — Tenants resolves both the identity JWT and
/// the opaque bearer (DB lookup); DDNS/Tunneller resolve the JWT **offline only**
/// (the identity DB lives in Tenants). Everything else — the body-size guard, the
/// `/v1/installs/*` path gate, the ±60 s timestamp window, the canonical-payload
/// Ed25519 proof-of-possession check, and the replay cache — is shared here so the
/// security-critical core is identical across services.
pub trait AuthContext: Clone + Send + Sync + 'static {
    /// The service's in-memory replay-prevention cache.
    fn replay_cache(&self) -> &ReplayCache;

    /// Resolve a `Bearer` value to the authenticated [`Principal`] plus the daemon
    /// public key its request signature must verify against. On failure, returns
    /// the HTTP [`Response`] to send (a hard `401`/`500`).
    fn resolve_credential(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<(Principal, [u8; 32]), Response>> + Send;
}

/// Axum middleware: an unconditional body-size guard, plus Ed25519 signed-request
/// authentication on `/v1/installs/*` endpoints carrying an `Authorization` header.
///
/// Generic over the service's [`AuthContext`]; pass `auth_layer::<MyState>` to
/// `axum::middleware::from_fn_with_state`. On success the verified [`Principal`] is
/// stamped into request extensions (read via [`AuthenticatedInstall`]).
pub async fn auth_layer<S: AuthContext>(
    State(state): State<S>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();

    // ── Body-size guard (runs for ALL requests) ───────────────────────────
    let Ok(body_bytes) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorBody {
                error: "request body exceeds 1 MiB limit".to_string(),
            }),
        )
            .into_response();
    };

    // ── Auth (only for /v1/installs/* when Authorization header is present) ─
    let path = parts.uri.path();
    let auth_header = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    if path.starts_with(AUTHENTICATED_PATH_PREFIX)
        && let Some(auth_str) = auth_header
    {
        let Some(token) = auth_str.strip_prefix("Bearer ") else {
            return unauthorized("invalid Authorization header format");
        };

        let (principal, pub_key_bytes) = match state.resolve_credential(token).await {
            Ok(resolved) => resolved,
            Err(rejection) => return rejection,
        };

        if let Err(rejection) =
            verify_signed_request(&parts, &body_bytes, &principal, &pub_key_bytes, &state)
        {
            return rejection;
        }

        parts.extensions.insert(principal);
    }

    // Reconstitute the request with the buffered body so downstream extractors
    // (`Json<T>`, `axum::body::Bytes`) see a normal body stream.
    let request = Request::from_parts(parts, axum::body::Body::from(body_bytes));
    next.run(request).await
}

/// The shared security core: the ±60 s timestamp window, the canonical signed
/// payload (method + path-and-query + timestamp + body hash), the Ed25519
/// signature/PoP check against `pub_key_bytes`, and the replay-cache insert (key
/// `{install_id}:{timestamp}:{body_hash}`). Returns the rejection `Response` on any
/// failure.
// The `Err` is a deliberately-constructed HTTP `Response`, not a large error enum
// that ought to be boxed — boxing would only add an allocation on the reject path.
#[allow(clippy::result_large_err)]
fn verify_signed_request<S: AuthContext>(
    parts: &Parts,
    body_bytes: &[u8],
    principal: &Principal,
    pub_key_bytes: &[u8; 32],
    state: &S,
) -> Result<(), Response> {
    // ── Timestamp window. ──
    let timestamp_str = parts
        .headers
        .get("X-Wardnet-Timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let timestamp: i64 = timestamp_str
        .parse()
        .map_err(|_| unauthorized("missing or invalid X-Wardnet-Timestamp"))?;
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > TIMESTAMP_WINDOW_SECS {
        return Err(unauthorized("X-Wardnet-Timestamp outside ±60 s window"));
    }

    // ── Canonical payload (path AND query covered). ──
    let method = parts.method.as_str();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), axum::http::uri::PathAndQuery::as_str);
    let body_hash = hex::encode(Sha256::digest(body_bytes));
    let payload = canonical_request_payload(method, path_and_query, timestamp, &body_hash);

    // ── Ed25519 signature check (PoP against the resolved key). ──
    let sig_b64 = parts
        .headers
        .get("X-Wardnet-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Err(e) = verify_signature_bytes(pub_key_bytes, payload.as_bytes(), sig_b64) {
        tracing::warn!(install_id = %principal.id, error = %e, "request signature verification failed");
        return Err(unauthorized("invalid request signature"));
    }

    // ── Replay check. ──
    let replay_key = format!("{}:{}:{}", principal.id, timestamp, body_hash);
    if state.replay_cache().contains_or_insert(&replay_key, now) {
        tracing::warn!(install_id = %principal.id, "replayed signed request rejected");
        return Err(unauthorized("replayed request"));
    }

    Ok(())
}

// ── Rejection helpers (shared by service credential resolvers) ──────────────────

/// Build a `401 Unauthorized` JSON response.
#[must_use]
pub fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorBody {
            error: msg.to_string(),
        }),
    )
        .into_response()
}

/// Build a `500 Internal Server Error` JSON response (for resolver infra errors).
#[must_use]
pub fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "internal server error".to_string(),
        }),
    )
        .into_response()
}
