//! Service-layer domain error for [`SubscriptionService`](crate::service::SubscriptionService).
//!
//! HTTP-agnostic. Consumers reach this aggregate through the
//! [`wardnet_common::ports`] traits (which return `anyhow::Result`), so the
//! `?`-conversion to `anyhow::Error` (via `thiserror`'s `std::error::Error` impl) is
//! all the cross-crate surface needed — there is deliberately no `ApiError` mapping
//! here (that belongs to whichever crate serves HTTP).

/// Things that can go wrong applying a subscription rule.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionError {
    /// A referenced tenant / subscription does not exist.
    #[error("{0}")]
    NotFound(String),
    /// Malformed input (e.g. an unknown plan).
    #[error("{0}")]
    BadRequest(String),
    /// A repository failure.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}
