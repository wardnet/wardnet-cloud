//! Tunneller error shape.
//!
//! The transport-neutral [`ApiError`] / [`ErrorBody`] live in
//! [`wardnet_common::error`]. The Tunneller has no domain-error enum of its own: its
//! single authenticated endpoint returns [`ApiError`] directly (the routing policy
//! maps a failed network/tenant read to `Forbidden`/`Internal`), and the mesh reads
//! surface `anyhow::Error`. Re-exported here so handlers can write
//! `crate::error::ApiError`.

pub use wardnet_common::error::{ApiError, ErrorBody};
