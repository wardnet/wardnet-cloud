//! Cloud error mapping.
//!
//! The transport-neutral [`ApiError`] / [`ErrorBody`] live in
//! [`wardnet_common::error`]. The service-specific `From` mappings stay here: the
//! orphan rule permits `impl From<LocalError> for ApiError` in the crate that owns
//! the local error enum (it appears as the `From` parameter), and this keeps the
//! domain services HTTP-agnostic — the mapping survives the eventual process split.

pub use wardnet_common::error::{ApiError, ErrorBody};

use crate::service::{DdnsError, TenantsError};

/// Map the Tenants service's transport-neutral domain error to its HTTP shape.
impl From<TenantsError> for ApiError {
    fn from(e: TenantsError) -> Self {
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
impl From<DdnsError> for ApiError {
    fn from(e: DdnsError) -> Self {
        match e {
            DdnsError::Conflict(m) => ApiError::Conflict(m),
            DdnsError::Internal(e) => ApiError::Internal(e),
        }
    }
}
