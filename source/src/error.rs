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

    #[error("internal server error")]
    Internal(#[from] anyhow::Error),
}

/// Map the Tenants service's transport-neutral domain error to its HTTP shape.
/// Keeping this mapping in the API layer lets the service stay HTTP-agnostic
/// (it survives the eventual process split unchanged).
impl From<crate::service::TenantsError> for ApiError {
    fn from(e: crate::service::TenantsError) -> Self {
        use crate::service::TenantsError;
        match e {
            TenantsError::RateLimited(m) => ApiError::TooManyRequests(m),
            TenantsError::NameTaken(m) => ApiError::Conflict(m),
            TenantsError::BadChallenge(m) => ApiError::BadRequest(m),
            TenantsError::Forbidden(m) => ApiError::Forbidden(m),
            TenantsError::Internal(e) => ApiError::Internal(e),
        }
    }
}

/// Map the DDNS service's domain error to its HTTP shape (same rationale).
impl From<crate::service::DdnsError> for ApiError {
    fn from(e: crate::service::DdnsError) -> Self {
        use crate::service::DdnsError;
        match e {
            DdnsError::Conflict(m) => ApiError::Conflict(m),
            DdnsError::Internal(e) => ApiError::Internal(e),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m.as_str()),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m.as_str()),
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.as_str()),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m.as_str()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.as_str()),
            ApiError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, m.as_str()),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
        };

        if let ApiError::Internal(err) = &self {
            tracing::error!(error = %err, "unhandled internal error");
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
