//! Wardnet cloud — temporary single bin (pre per-service carve).
//!
//! This crate is the post-WS-A holding pen for all service code that has not yet
//! been split into the `tenants` / `ddns` / `tunneller` binaries. It depends on
//! [`wardnet_common`] for every shared primitive (token, mTLS, validation, auth,
//! the PROXY front-door, the DNS-provider trait, the error shape, …). The
//! per-service carve is WS-B/C/D.

pub mod api;
pub mod auth;
pub mod cloudflare;
pub mod config;
pub mod db;
pub mod error;
pub mod repository;
pub mod service;
pub mod sni;
pub mod state;
pub mod tunnel;

#[cfg(test)]
pub mod test_helpers;
