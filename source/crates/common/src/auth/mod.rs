//! Unified authentication for every cloud service.
//!
//! One entry point — [`authenticate`] — is wired as a per-route middleware and
//! told which [`CallerType`]s a route accepts. It resolves the caller and rejects
//! anything outside the allowed set, stamping a [`Caller`] into request extensions
//! that handlers read via the extractor.
//!
//! Two authentication mechanisms back the three caller kinds:
//! - **`SERVICE`** — mutual TLS. The mesh listener only completes a handshake for a
//!   peer whose client certificate chains to the mesh CA, then stamps a
//!   [`ServiceIdentity`] into the request; its mere presence *is* the proof.
//! - **`DAEMON` / `USER`** — a Tenants-signed [`Verifier`]-checked JWT. A daemon
//!   token additionally proves possession of its `cnf` key: the request is Ed25519
//!   signed and [`verify_signed_request`] checks it (timestamp window + replay).
//!   A user token is bearer-only (no `PoP` this session).
//!
//! Three endpoints sit *outside* this layer because they mint the very credentials
//! above (new-signup code issue, daemon enroll, JWT issue); they carry their own
//! one-time-code / key-`PoP` checks in their handlers.

use axum::http::request::Parts;
use axum::{
    Json,
    extract::{FromRequestParts, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use bitflags::bitflags;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::ErrorBody;
use crate::replay_cache::ReplayCache;
use crate::token::{PrincipalType, Verifier, canonical_request_payload};

/// Maximum allowed clock skew between a daemon and the service (seconds).
const TIMESTAMP_WINDOW_SECS: i64 = 60;

/// Hard body-size limit applied to **every** authenticated request — a `DoS` guard
/// that buffers the body once (also needed to hash it for the daemon signature).
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

bitflags! {
    /// Which caller kinds a route accepts. An endpoint composes the set it allows
    /// (`SERVICE` only, `DAEMON | USER`, `all()`, …); [`authenticate`] rejects a
    /// resolved caller whose kind is not in the set.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CallerType: u8 {
        /// Another cloud service, authenticated by mesh mTLS (private API boundary).
        const SERVICE = 0b001;
        /// A wardnet daemon, authenticated by JWT + Ed25519 `PoP`.
        const DAEMON  = 0b010;
        /// A human account user, authenticated by JWT (bearer-only).
        const USER    = 0b100;
    }
}

// ── Resolved caller ─────────────────────────────────────────────────────────────

/// Identity of a peer service authenticated by mesh mTLS. Presence means the
/// handshake validated a client certificate chained to the mesh CA.
#[derive(Debug, Clone)]
pub struct ServiceIdentity {
    /// Best-effort peer leaf subject (currently unparsed — reserved for richer
    /// per-service authorization later). The trust decision is the handshake.
    pub subject: String,
}

/// A daemon caller resolved from a JWT (+ verified `PoP`).
#[derive(Debug, Clone)]
pub struct DaemonCaller {
    /// Tenant the daemon acts for.
    pub tenant_id: String,
    /// The daemon's id (token `sub`).
    pub daemon_id: String,
    /// Network scope, if the token is network-scoped.
    pub network: Option<String>,
}

/// A user caller resolved from a JWT.
#[derive(Debug, Clone)]
pub struct UserCaller {
    /// Tenant the user acts for.
    pub tenant_id: String,
    /// The user's id (token `sub`).
    pub user_id: String,
    /// Network scope, if the token is network-scoped.
    pub network: Option<String>,
}

/// The authenticated caller stamped into request extensions by [`authenticate`].
#[derive(Debug, Clone)]
pub enum Caller {
    /// A peer cloud service (mTLS).
    Service(ServiceIdentity),
    /// A wardnet daemon (JWT + `PoP`).
    Daemon(DaemonCaller),
    /// A human account user (JWT).
    User(UserCaller),
}

impl Caller {
    /// The single [`CallerType`] bit this caller represents.
    #[must_use]
    pub fn caller_type(&self) -> CallerType {
        match self {
            Caller::Service(_) => CallerType::SERVICE,
            Caller::Daemon(_) => CallerType::DAEMON,
            Caller::User(_) => CallerType::USER,
        }
    }

    /// The tenant this caller acts for, if any (services have no tenant).
    #[must_use]
    pub fn tenant_id(&self) -> Option<&str> {
        match self {
            Caller::Daemon(d) => Some(&d.tenant_id),
            Caller::User(u) => Some(&u.tenant_id),
            Caller::Service(_) => None,
        }
    }
}

/// Extractor handlers use to read the [`Caller`] resolved by [`authenticate`].
///
/// Returns `401` if absent — i.e. a handler guarded by no auth middleware, a
/// configuration error.
pub struct AuthCaller(pub Caller);

impl<S> FromRequestParts<S> for AuthCaller
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ErrorBody>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Caller>()
            .cloned()
            .map(AuthCaller)
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

// ── Per-service context ─────────────────────────────────────────────────────────

/// The per-service state [`authenticate`] needs: the offline JWT verifier and the
/// replay cache for daemon `PoP`. Every service's `AppState` implements this.
pub trait AuthContext: Clone + Send + Sync + 'static {
    /// Offline verifier for Tenants-signed JWTs.
    fn verifier(&self) -> &Verifier;
    /// In-memory replay-prevention cache (daemon signed requests).
    fn replay_cache(&self) -> &ReplayCache;
}

// ── Middleware ──────────────────────────────────────────────────────────────────

/// Authenticate the request, accepting only callers in `allowed`.
///
/// Wire per route via a closure, e.g.
/// `from_fn_with_state(state, move |s, r, n| authenticate(CallerType::DAEMON, s, r, n))`.
/// On success a [`Caller`] is stamped into request extensions (read via
/// [`AuthCaller`]); otherwise a `401`/`403`/`413` response is returned.
pub async fn authenticate<S: AuthContext>(
    allowed: CallerType,
    State(state): State<S>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();

    // Buffer the body once (size guard + needed to hash for daemon `PoP`).
    let Ok(body_bytes) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorBody {
                error: "request body exceeds 1 MiB limit".to_string(),
            }),
        )
            .into_response();
    };

    // ── SERVICE: a mesh peer cert was stamped by the mTLS listener. ──
    if let Some(service) = parts.extensions.get::<ServiceIdentity>().cloned() {
        if !allowed.contains(CallerType::SERVICE) {
            return forbidden("this endpoint does not accept service callers");
        }
        parts.extensions.insert(Caller::Service(service));
        return next
            .run(Request::from_parts(
                parts,
                axum::body::Body::from(body_bytes),
            ))
            .await;
    }

    // ── DAEMON / USER: a Tenants-signed JWT bearer. ──
    let Some(token) = bearer(&parts) else {
        return unauthorized("authentication required");
    };
    let claims = match state.verifier().verify(&token) {
        Ok(claims) => claims,
        Err(e) => {
            tracing::warn!(error = %e, "JWT verification failed");
            return unauthorized("invalid token");
        }
    };

    let caller = match claims.pt {
        PrincipalType::Daemon => {
            if !allowed.contains(CallerType::DAEMON) {
                return forbidden("this endpoint does not accept daemon callers");
            }
            let pub_key_bytes = match claims.pop_public_key() {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(error = %e, "daemon token missing/invalid cnf key");
                    return unauthorized("invalid token");
                }
            };
            if let Err(rejection) =
                verify_signed_request(&parts, &body_bytes, &claims.sub, &pub_key_bytes, &state)
            {
                return rejection;
            }
            Caller::Daemon(DaemonCaller {
                tenant_id: claims.tid,
                daemon_id: claims.sub,
                network: claims.net,
            })
        }
        PrincipalType::User => {
            if !allowed.contains(CallerType::USER) {
                return forbidden("this endpoint does not accept user callers");
            }
            Caller::User(UserCaller {
                tenant_id: claims.tid,
                user_id: claims.sub,
                network: claims.net,
            })
        }
    };

    parts.extensions.insert(caller);
    next.run(Request::from_parts(
        parts,
        axum::body::Body::from(body_bytes),
    ))
    .await
}

/// Extract a `Bearer` token from the `Authorization` header.
fn bearer(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
}

/// Verify an Ed25519 proof-of-possession over the canonical request payload.
///
/// Checks the `±TIMESTAMP_WINDOW_SECS` window, rebuilds the canonical payload
/// (method + path-and-query + timestamp + body hash), and verifies `signature_b64`
/// against `pub_key_bytes`. On success returns the body hash (hex) so the caller
/// can build a replay key. **Does not** touch the replay cache — that is the
/// caller's responsibility, since the replay subject differs per caller.
///
/// Bootstrap endpoints that mint credentials (the JWT-issue endpoint) call this
/// directly; the [`authenticate`] middleware uses it via [`verify_signed_request`].
///
/// # Errors
/// Returns an error if the timestamp is outside the window or the signature is
/// missing/malformed/invalid.
pub fn verify_pop(
    method: &str,
    path_and_query: &str,
    timestamp: i64,
    signature_b64: &str,
    body: &[u8],
    pub_key_bytes: &[u8; 32],
) -> anyhow::Result<String> {
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > TIMESTAMP_WINDOW_SECS {
        anyhow::bail!("timestamp outside ±{TIMESTAMP_WINDOW_SECS}s window");
    }
    let body_hash = hex::encode(Sha256::digest(body));
    let payload = canonical_request_payload(method, path_and_query, timestamp, &body_hash);
    verify_signature_bytes(pub_key_bytes, payload.as_bytes(), signature_b64)?;
    Ok(body_hash)
}

/// The middleware's daemon signed-request check: pull the timestamp/signature
/// headers, run [`verify_pop`], then record the replay key
/// `{subject}:{timestamp}:{body_hash}`. Returns the rejection on any failure.
// The `Err` is a deliberately-constructed HTTP `Response`, not a large error enum.
#[allow(clippy::result_large_err)]
fn verify_signed_request<S: AuthContext>(
    parts: &Parts,
    body_bytes: &[u8],
    subject: &str,
    pub_key_bytes: &[u8; 32],
    state: &S,
) -> Result<(), Response> {
    let timestamp: i64 = parts
        .headers
        .get("X-Wardnet-Timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .parse()
        .map_err(|_| unauthorized("missing or invalid X-Wardnet-Timestamp"))?;

    let sig_b64 = parts
        .headers
        .get("X-Wardnet-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let method = parts.method.as_str();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), axum::http::uri::PathAndQuery::as_str);

    let body_hash = verify_pop(
        method,
        path_and_query,
        timestamp,
        sig_b64,
        body_bytes,
        pub_key_bytes,
    )
    .map_err(|e| {
        tracing::warn!(daemon_id = %subject, error = %e, "request signature verification failed");
        unauthorized("invalid request signature")
    })?;

    let replay_key = format!("{subject}:{timestamp}:{body_hash}");
    if state
        .replay_cache()
        .contains_or_insert(&replay_key, chrono::Utc::now().timestamp())
    {
        tracing::warn!(daemon_id = %subject, "replayed signed request rejected");
        return Err(unauthorized("replayed request"));
    }

    Ok(())
}

// ── Signature verification ──────────────────────────────────────────────────────

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

// ── Rejection helpers ───────────────────────────────────────────────────────────

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

/// Build a `403 Forbidden` JSON response (authenticated but wrong caller kind).
#[must_use]
pub fn forbidden(msg: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: msg.to_string(),
        }),
    )
        .into_response()
}

/// Build a `500 Internal Server Error` JSON response.
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

#[cfg(test)]
mod tests;
