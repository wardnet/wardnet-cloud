//! Tenants error mapping.
//!
//! The transport-neutral [`ApiError`] / [`ErrorBody`] live in
//! [`wardnet_common::error`]. The `From<TenantsError>` mapping stays here: the
//! orphan rule permits the impl in the crate owning the local error enum, and it
//! keeps [`TenantsService`](crate::service::TenantsService) HTTP-agnostic.

pub use wardnet_common::error::{ApiError, ErrorBody};

use crate::service::TenantsError;

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
