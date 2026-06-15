//! Tenants credential resolution.
//!
//! Implements [`AuthContext`] for the Tenants [`AppState`], giving the shared
//! [`auth_layer`](wardnet_common::auth::auth_layer) its **dual-path** resolver:
//! a JWT-shaped credential is verified offline (no DB); anything else is an opaque
//! bearer token looked up in the global identity table. Only Tenants holds that
//! table, so only Tenants accepts the bearer path.

use axum::response::Response;
use sha2::{Digest, Sha256};

use wardnet_common::auth::{
    AuthContext, Principal, internal_error, looks_like_jwt, principal_from_jwt, unauthorized,
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
        if looks_like_jwt(token) {
            // ── Identity JWT: offline verify + `cnf` extraction, no DB. ──
            principal_from_jwt(self.jwt_verifier(), token).map_err(|e| {
                tracing::warn!(error = %e, "identity JWT verification failed");
                unauthorized("invalid identity token")
            })
        } else {
            // ── Opaque bearer token: look up by SHA-256(token). ──
            let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
            match self.tenants().authenticate(&token_hash).await {
                Ok(Some(identity)) => {
                    let principal = Principal {
                        id: identity.id,
                        name: identity.name,
                    };
                    Ok((principal, identity.pub_key_bytes))
                }
                Ok(None) => Err(unauthorized("unknown bearer token")),
                Err(e) => {
                    tracing::error!(error = %e, "database error during auth");
                    Err(internal_error())
                }
            }
        }
    }
}

// Full-stack auth tests (both credential paths) live in tests/api.rs.
