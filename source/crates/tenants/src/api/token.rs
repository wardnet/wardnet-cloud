//! `POST /v1/token` — bootstrap endpoint (auth = daemon key proof-of-possession).
//!
//! The daemon signs the canonical request payload with the Ed25519 key it enrolled.
//! This endpoint cannot use the JWT middleware (it *mints* the JWT), so it verifies
//! the `PoP` directly: signature over `(method, path, timestamp, body-hash)` against
//! the public key in the body, a ±window timestamp, and a replay check. On success
//! it mints a tenant- or network-scoped identity JWT (per the key's binding).

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::verify_pop;
use wardnet_common::validation::validate_public_key;

use crate::error::ApiError;
use crate::state::AppState;

/// Register the token route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(issue_token))
}

/// Request body for `POST /v1/token`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct TokenRequest {
    /// Base64-encoded raw Ed25519 public key (32 bytes) — the enrolled/registered key.
    pub public_key: String,
}

/// Response body for `POST /v1/token`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TokenResponse {
    /// The minted identity JWT (`EdDSA`).
    pub token: String,
}

#[utoipa::path(
    post,
    path = "/v1/token",
    tag = "enrollment",
    description = "Mint an identity JWT for a daemon, authenticated by an Ed25519 \
                   proof-of-possession signature over the request (headers \
                   X-Wardnet-Timestamp / X-Wardnet-Signature). Tenant-scoped before \
                   the daemon registers a network, network-scoped after.",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Identity JWT minted", body = TokenResponse),
        (status = 401, description = "Bad signature / unknown or expired key"),
        (status = 400, description = "Invalid public key"),
    ),
    security(()),
)]
async fn issue_token(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<TokenResponse>, ApiError> {
    let req: TokenRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::BadRequest("invalid JSON body".to_string()))?;
    let pub_key_bytes = validate_public_key(&req.public_key)?;

    let timestamp: i64 = header(&headers, "X-Wardnet-Timestamp")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| {
            ApiError::Unauthorized("missing or invalid X-Wardnet-Timestamp".to_string())
        })?;
    let signature = header(&headers, "X-Wardnet-Signature").unwrap_or("");
    let path_and_query = uri
        .path_and_query()
        .map_or(uri.path(), axum::http::uri::PathAndQuery::as_str);

    let body_hash = verify_pop(
        method.as_str(),
        path_and_query,
        timestamp,
        signature,
        &body,
        &pub_key_bytes,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "token PoP verification failed");
        ApiError::Unauthorized("invalid request signature".to_string())
    })?;

    // Replay guard, keyed by the presenting key (its identity for this purpose).
    let replay_key = format!("{}:{timestamp}:{body_hash}", req.public_key);
    if state
        .replay_cache()
        .contains_or_insert(&replay_key, Utc::now().timestamp())
    {
        return Err(ApiError::Unauthorized("replayed request".to_string()));
    }

    let token = state.tenants().mint_jwt(&req.public_key).await?;
    Ok(Json(TokenResponse { token }))
}

/// Read a header as `&str`.
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}
