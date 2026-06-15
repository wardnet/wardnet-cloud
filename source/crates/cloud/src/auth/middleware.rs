//! Cloud (DDNS + Tunneller) credential resolution.
//!
//! Implements [`AuthContext`] for the cloud [`AppState`], giving the shared
//! [`auth_layer`](wardnet_common::auth::auth_layer) a **JWT-only** resolver:
//! these endpoints authenticate the external daemon by its Tenants-signed identity
//! JWT, verified **offline** (no DB) with `cnf` proof-of-possession. The opaque
//! bearer path is deliberately absent — the identity table lives in the Tenants
//! service, and inter-service (mesh) calls authenticate by mTLS, not JWT.

use axum::response::Response;

use wardnet_common::auth::{
    AuthContext, Principal, looks_like_jwt, principal_from_jwt, unauthorized,
};
use wardnet_common::replay_cache::ReplayCache;

use crate::state::AppState;

impl AuthContext for AppState {
    fn replay_cache(&self) -> &ReplayCache {
        AppState::replay_cache(self)
    }

    // The `Err` is a ready-to-send HTTP `Response` by design, not a large error
    // enum that ought to be boxed.
    #[allow(clippy::result_large_err)]
    async fn resolve_credential(&self, token: &str) -> Result<(Principal, [u8; 32]), Response> {
        // JWT-only: a non-JWT-shaped credential (e.g. the opaque bearer) is a hard
        // 401 here — only Tenants holds the table to resolve it.
        if !looks_like_jwt(token) {
            return Err(unauthorized(
                "this service accepts identity JWTs only; present your identity token",
            ));
        }
        principal_from_jwt(self.jwt_verifier(), token).map_err(|e| {
            tracing::warn!(error = %e, "identity JWT verification failed");
            unauthorized("invalid identity token")
        })
    }
}

// Full-stack auth tests (JWT path) live in tests/api.rs.
