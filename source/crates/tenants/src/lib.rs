//! Wardnet Tenants — the global authority for the `tenant → network → daemon`
//! model.
//!
//! Owns the global DB (tenants, networks, daemons, enrollment artifacts), the
//! identity-JWT [`Signer`], and the [`TenantsService`] business rules: signup-code
//! issuance, the daemon enroll saga, JWT minting, network registration with
//! entitlement enforcement, the subscription-cancel cascade, and the mesh reconcile
//! transitions. Serves a public, nginx-fronted API plus an internal mesh-mTLS
//! work-queue listener consumed by the regional DDNS provisioner/reaper.
//!
//! [`Signer`]: wardnet_common::token::Signer
//! [`TenantsService`]: crate::service::TenantsService

pub mod api;
pub mod config;
pub mod db;
pub mod email;
pub mod error;
pub mod identities;
pub mod mesh;
pub mod reactor;
pub mod repository;
pub mod service;
pub mod state;
pub mod util;
