//! Small crate-internal helpers shared across the tenant and Identities aggregates,
//! so the rules live in exactly one place.

use sha2::{Digest, Sha256};

/// Lowercase + trim an email and apply a minimal shape check. The single source of
/// truth for the verified-email **join key**: `TenantsService` (which stores the email)
/// and `IdentitiesService` (which looks it up) must normalize identically, or the join
/// silently misses — so both call this. Returns a short reason on a malformed email;
/// each caller wraps it in its own error type.
///
/// # Errors
/// Returns `"invalid email"` if the trimmed value is shorter than 3 chars or has no `@`.
pub fn normalize_email(email: &str) -> Result<String, &'static str> {
    let e = email.trim().to_lowercase();
    if e.len() < 3 || !e.contains('@') {
        return Err("invalid email");
    }
    Ok(e)
}

/// A random opaque token (a one-time code, a session token, or an OAuth `state`): hex
/// of 32 random bytes. Only its [`sha256_hex`] is ever persisted (invariant #1).
#[must_use]
pub fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

/// SHA-256 hex of a value — the at-rest form for one-time codes and session tokens.
#[must_use]
pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
