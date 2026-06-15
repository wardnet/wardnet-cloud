//! Shared primitives for the wardnet cloud services.
//!
//! This crate holds everything that is genuinely cross-service: identity tokens,
//! mesh mTLS, the PROXY-protocol front-door, the replay cache, the DNS-provider
//! trait, database pool plumbing, the HTTP error shape, request validation, the
//! generic auth primitives, the hyper connection server, the health endpoint, and
//! (transiently, until enrollment is redesigned) the proof-of-work helpers.

pub mod auth;
pub mod config;
pub mod db;
pub mod dns_provider;
pub mod error;
pub mod health;
pub mod mtls;
pub mod pow;
pub mod proxy_protocol;
pub mod replay_cache;
pub mod serve;
pub mod token;
pub mod validation;

#[cfg(test)]
mod test_helpers;
