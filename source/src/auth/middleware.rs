use axum::http::request::Parts;
use axum::{
    Json,
    extract::{FromRequestParts, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::ErrorBody;
use crate::state::AppState;

/// Maximum allowed clock skew between the Pi and the bridge (seconds).
const TIMESTAMP_WINDOW_SECS: i64 = 60;

/// Hard body-size limit applied to **every** incoming request, regardless of
/// whether it carries an `Authorization` header.
///
/// This is a `DoS` guard — it runs before any auth check so an attacker cannot
/// exhaust server memory by streaming a large body to an unauthenticated
/// endpoint. Authenticated endpoints are equally protected.
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// Path prefix for all authenticated install endpoints.
///
/// The auth middleware only attempts authentication when the request path starts
/// with this prefix. Requests to unauthenticated endpoints (health, challenge,
/// register, names) never incur a DB round-trip (or JWT parse) regardless of
/// whether they carry an `Authorization` header — this closes a `DoS` vector.
const AUTHENTICATED_PATH_PREFIX: &str = "/v1/installs/";

// ── Authenticated principal ────────────────────────────────────────────────────

/// The install authenticated by the current request. Deliberately slim — it is
/// produced identically by both auth paths (opaque bearer + identity JWT), and
/// carries only what handlers read (`id`, `name`). The daemon public key used to
/// verify the request signature stays local to the middleware (it is not stamped
/// into request extensions). The JWT path has no `token_hash` / `region` /
/// `status`, so the full `Identity` is not used here.
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
/// Reads the principal previously inserted into request extensions by
/// [`auth_layer`]. Returns `401 Unauthorized` if absent — i.e. the request
/// reached an authenticated handler without a valid credential. Operational DNS
/// state is **not** carried here; handlers that need it call `DdnsService`, which
/// reads it fresh.
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

// ── Middleware ────────────────────────────────────────────────────────────────

/// Axum middleware: a body-size guard on all requests, plus authentication on
/// install-owned endpoints.
///
/// # Body-size guard (unconditional)
///
/// Every request body is buffered up to [`MAX_BODY_BYTES`] first; oversize bodies
/// are rejected with `413` before any auth/routing, preventing memory exhaustion
/// on unauthenticated endpoints such as `POST /v1/register`.
///
/// # Authentication (only for `/v1/installs/*` paths carrying `Authorization`)
///
/// Two credential forms are accepted (the **transition** while the daemon still
/// carries the opaque bearer; the JWT becomes the sole credential once the daemon
/// sends it — Step 5):
///
/// - **Identity JWT** (`Authorization: Bearer <jwt>`, recognised by its
///   three-segment shape): verified **offline** with the Tenants public key — no
///   DB lookup. The request `X-Wardnet-Signature` is then checked against the
///   `cnf` public key embedded in the verified claims (RFC 7800
///   proof-of-possession), so a stolen JWT is inert without the daemon key.
/// - **Opaque bearer token** (any other `Bearer <token>`): `SHA-256`-hashed and
///   looked up in the global identity table; the request signature is checked
///   against the install's registered key.
///
/// Both paths then share: `X-Wardnet-Timestamp` window (±60 s), the canonical
/// signed payload, the Ed25519 signature check, and the replay cache. On success
/// the verified [`Principal`] is stamped into request extensions.
pub async fn auth_layer(State(state): State<AppState>, request: Request, next: Next) -> Response {
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

        // Resolve the principal AND the public key its request signature must
        // verify against, by either credential path. A JWT-shaped token is never
        // retried as a bearer token — a malformed/expired JWT is a hard 401.
        let (principal, pub_key_bytes) = match resolve_credential(&state, token).await {
            Ok(resolved) => resolved,
            Err(rejection) => return rejection,
        };

        // ── Shared: timestamp window. ──
        let timestamp_str = parts
            .headers
            .get("X-Wardnet-Timestamp")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let timestamp: i64 = match timestamp_str.parse() {
            Ok(t) => t,
            Err(_) => return unauthorized("missing or invalid X-Wardnet-Timestamp"),
        };
        let now = chrono::Utc::now().timestamp();
        if (now - timestamp).abs() > TIMESTAMP_WINDOW_SECS {
            return unauthorized("X-Wardnet-Timestamp outside ±60 s window");
        }

        // ── Shared: canonical payload (path AND query covered). ──
        let method = parts.method.as_str();
        let path_and_query = parts
            .uri
            .path_and_query()
            .map_or(path, axum::http::uri::PathAndQuery::as_str);
        let body_hash = hex::encode(Sha256::digest(&body_bytes));
        let payload =
            crate::token::canonical_request_payload(method, path_and_query, timestamp, &body_hash);

        // ── Shared: Ed25519 signature check (PoP against the resolved key). ──
        let sig_b64 = parts
            .headers
            .get("X-Wardnet-Signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if let Err(e) = verify_signature_bytes(&pub_key_bytes, payload.as_bytes(), sig_b64) {
            tracing::warn!(
                install_id = %principal.id,
                error = %e,
                "request signature verification failed"
            );
            return unauthorized("invalid request signature");
        }

        // ── Shared: replay check. ──
        let replay_key = format!("{}:{}:{}", principal.id, timestamp, body_hash);
        if state.replay_cache().contains_or_insert(&replay_key, now) {
            tracing::warn!(install_id = %principal.id, "replayed signed request rejected");
            return unauthorized("replayed request");
        }

        // ── Shared: stamp the verified principal onto the request. ──
        parts.extensions.insert(principal);
    }

    // Reconstitute the request with the buffered body so downstream extractors
    // (`Json<T>`, `axum::body::Bytes`) see a normal body stream.
    let request = Request::from_parts(parts, axum::body::Body::from(body_bytes));
    next.run(request).await
}

/// Resolve the authenticated [`Principal`] from a `Bearer` value, by either path.
///
/// JWT-shaped values are verified offline (no DB); anything else is treated as an
/// opaque bearer token and looked up. A JWT that fails verification is a hard
/// rejection — it is never retried as a bearer token. Returns the [`Principal`]
/// plus the daemon public key the request signature must then verify against (the
/// install's registered key, or the JWT's `cnf` key — the same daemon key).
async fn resolve_credential(
    state: &AppState,
    token: &str,
) -> Result<(Principal, [u8; 32]), Response> {
    if looks_like_jwt(token) {
        // ── Identity JWT: offline verify + `cnf` extraction, no DB. ──
        let claims = state.jwt_verifier().verify(token).map_err(|e| {
            tracing::warn!(error = %e, "identity JWT verification failed");
            unauthorized("invalid identity token")
        })?;
        let pub_key_bytes = claims.pop_public_key().map_err(|e| {
            tracing::warn!(error = %e, "identity JWT cnf key is malformed");
            unauthorized("invalid identity token")
        })?;
        let principal = Principal {
            id: claims.sub,
            name: claims.vanity,
        };
        Ok((principal, pub_key_bytes))
    } else {
        // ── Opaque bearer token: look up by SHA-256(token). ──
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
        match state.tenants().authenticate(&token_hash).await {
            Ok(Some(identity)) => {
                let principal = Principal {
                    id: identity.id,
                    name: identity.name,
                };
                Ok((principal, identity.pub_key_bytes))
            }
            Ok(None) => Err(unauthorized("unknown bearer token")),
            Err(e) => {
                tracing::error!(error = %e, "database error during auth");
                Err(internal_error())
            }
        }
    }
}

/// Whether a `Bearer` value has the compact-JWS shape (`header.payload.signature`)
/// — three base64url segments. The opaque bearer token is hex (no dots), so the
/// two are unambiguous.
fn looks_like_jwt(token: &str) -> bool {
    token.split('.').count() == 3
}

// ── Signature verification ────────────────────────────────────────────────────

/// Verify an Ed25519 signature over `message` using the raw 32 public-key bytes.
fn verify_signature_bytes(
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

// ── Error helpers ─────────────────────────────────────────────────────────────

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorBody {
            error: msg.to_string(),
        }),
    )
        .into_response()
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "internal server error".to_string(),
        }),
    )
        .into_response()
}

// Full-stack auth middleware tests (both credential paths) live in tests/api.rs.
