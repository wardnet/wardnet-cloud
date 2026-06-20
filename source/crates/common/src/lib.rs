//! Shared primitives for the wardnet cloud services.
//!
//! This crate holds everything that is genuinely cross-service: identity tokens,
//! mesh mTLS, the PROXY-protocol front-door, the replay cache, the DNS-provider
//! trait, database pool plumbing, the HTTP error shape, request validation, the
//! unified caller-type auth layer, the hyper connection server, the health
//! endpoint, and the shared API contract DTOs (`contract`).

pub mod auth;
pub mod config;
pub mod contract;
pub mod db;
pub mod dns_provider;
pub mod error;
pub mod event;
pub mod health;
pub mod mtls;
pub mod proxy_protocol;
pub mod replay_cache;
pub mod serve;
pub mod token;
pub mod validation;

#[cfg(test)]
mod test_helpers;
