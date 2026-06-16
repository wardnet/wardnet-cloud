//! Tenants domain error + its HTTP mapping.
//!
//! [`ApiError`] / [`ErrorBody`] are the transport-neutral shapes from
//! [`wardnet_common::error`]. [`TenantsError`] is the service layer's
//! HTTP-agnostic error; the `From` mapping lives here (the orphan rule permits the
//! impl in the crate owning the local error type).

pub use wardnet_common::error::{ApiError, ErrorBody};

/// Service-layer domain error for [`TenantsService`](crate::service::TenantsService).
#[derive(Debug, thiserror::Error)]
pub enum TenantsError {
    /// A referenced tenant / network does not exist.
    #[error("{0}")]
    NotFound(String),
    /// A uniqueness conflict (vanity slug already taken).
    #[error("{0}")]
    Conflict(String),
    /// An entitlement limit (max networks / daemons) is exhausted.
    #[error("{0}")]
    EntitlementExceeded(String),
    /// Malformed input (invalid slug, bad public key, …).
    #[error("{0}")]
    BadRequest(String),
    /// The one-time enrollment code is unknown, expired, or already used.
    #[error("{0}")]
    BadCode(String),
    /// A per-IP rate limit was exceeded.
    #[error("{0}")]
    RateLimited(String),
    /// A provider/repository failure.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<TenantsError> for ApiError {
    fn from(e: TenantsError) -> Self {
        match e {
            TenantsError::NotFound(m) => ApiError::NotFound(m),
            TenantsError::Conflict(m) | TenantsError::EntitlementExceeded(m) => {
                ApiError::Conflict(m)
            }
            TenantsError::BadRequest(m) => ApiError::BadRequest(m),
            TenantsError::BadCode(m) => ApiError::Unauthorized(m),
            TenantsError::RateLimited(m) => ApiError::TooManyRequests(m),
            TenantsError::Internal(e) => ApiError::Internal(e),
        }
    }
}
