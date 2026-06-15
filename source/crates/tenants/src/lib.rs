//! Wardnet Tenants — the global identity/naming authority.
//!
//! Owns the global identity + challenge repositories, the identity-JWT [`Signer`],
//! and the [`TenantsService`] business rules (registration saga, challenge
//! lifecycle, name availability, install authentication, tombstone deregistration,
//! and mesh introspection). Serves a public, nginx-fronted router (daemon JWT /
//! bearer auth) plus an internal mesh-mTLS introspect listener (consumed by the
//! DDNS reaper).
//!
//! [`Signer`]: wardnet_common::token::Signer
//! [`TenantsService`]: crate::service::TenantsService

pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod mesh;
pub mod repository;
pub mod service;
pub mod state;

#[cfg(test)]
pub mod test_helpers;
