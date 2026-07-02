use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// JSON body returned for every error response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    pub error: String,
}

/// Application-level error variants that map to HTTP status codes.
///
/// Handlers return `Result<T, ApiError>`; the [`IntoResponse`] impl
/// converts each variant to the appropriate status + JSON body.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("too many requests: {0}")]
    TooManyRequests(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("internal server error")]
    Internal(#[from] anyhow::Error),
}

// The service-specific `From<TenantsError>` / `From<DdnsError>` mappings live in
// the crate that owns those domain error enums (the orphan rule permits the impl
// there since the local error type appears as the `From` parameter). `common`
// only defines the transport-neutral `ApiError` / `ErrorBody`.

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m.as_str()),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m.as_str()),
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.as_str()),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m.as_str()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.as_str()),
            ApiError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, m.as_str()),
            ApiError::ServiceUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m.as_str()),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
        };

        // Every error is logged: server faults (5xx) at ERROR so they are never
        // silent; client errors (4xx) at DEBUG so they are traceable without noise.
        match &self {
            ApiError::Internal(err) => {
                tracing::error!(status = status.as_u16(), error = %err, "request failed (internal error)");
            }
            client_err => {
                tracing::debug!(status = status.as_u16(), error = %client_err, "request rejected");
            }
        }

        (
            status,
            Json(ErrorBody {
                error: message.to_string(),
            }),
        )
            .into_response()
    }
}
