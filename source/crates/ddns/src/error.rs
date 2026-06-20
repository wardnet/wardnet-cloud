//! DDNS error mapping.
//!
//! The transport-neutral [`ApiError`] / [`ErrorBody`] live in
//! [`wardnet_common::error`]. The DDNS service `From` mapping stays here: the
//! orphan rule permits `impl From<LocalError> for ApiError` in the crate owning
//! the local error enum, keeping the domain service HTTP-agnostic.

pub use wardnet_common::error::{ApiError, ErrorBody};

use crate::service::DdnsError;

/// Map the DDNS service's transport-neutral domain error to its HTTP shape.
impl From<DdnsError> for ApiError {
    fn from(e: DdnsError) -> Self {
        match e {
            DdnsError::Conflict(m) => ApiError::Conflict(m),
            DdnsError::Internal(e) => ApiError::Internal(e),
        }
    }
}
