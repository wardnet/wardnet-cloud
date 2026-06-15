//! Cloud auth wiring.
//!
//! The transport-neutral primitives ([`Principal`], [`AuthenticatedInstall`], the
//! JWT→principal step, the request-signature check) live in
//! [`wardnet_common::auth`]; the [`auth_layer`](middleware::auth_layer) middleware
//! that composes them around this bin's [`AppState`](crate::state::AppState) —
//! including the Tenants-only opaque-bearer DB path — lives in [`middleware`].

pub mod middleware;

pub use wardnet_common::auth::{AuthenticatedInstall, Principal};
