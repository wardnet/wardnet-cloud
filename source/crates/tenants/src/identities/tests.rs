//! Unit tests for Identities internals that need access to private items. The
//! aggregate's public flows (resolve/password/session) are exercised end-to-end in
//! the composition crate's integration tests (`app-tenants/tests/identities.rs`),
//! which can wire the full `Harness`; only the argon2 primitives — private to this
//! module — stay here.

use super::{hash_password, verify_password};

#[test]
fn password_hash_round_trips() {
    let hash = hash_password("correct horse battery").unwrap();
    assert!(verify_password(&hash, "correct horse battery"));
    assert!(!verify_password(&hash, "wrong password"));
    // The PHC string is an argon2id hash, never the cleartext.
    assert!(hash.starts_with("$argon2id$"));
    assert!(!hash.contains("correct horse battery"));
}
