//! Shared configuration helpers.
//!
//! The cloud services load their configuration from the process environment. In
//! production the inforge bootstrapper injects deployment identity and secrets;
//! secret *material* (PEM keys) is projected onto tmpfs and only the **path** is
//! passed in the environment. These helpers are the reusable primitives every
//! service's `Config::from_env` builds on; the per-service `Config` structs
//! themselves live in each service crate.

/// Read a required environment variable.
///
/// # Errors
/// Returns an error if the variable is absent.
pub fn required(key: &str) -> anyhow::Result<String> {
    std::env::var(key)
        .map_err(|_| anyhow::anyhow!("required environment variable `{key}` is not set"))
}

/// Read a secret file whose path is given by the `path_var` environment variable.
///
/// INFORGE projects secrets (PEM keys, …) onto tmpfs and passes only the path in
/// the environment — the material itself never appears in an env var.
///
/// # Errors
/// Returns an error if `path_var` is unset or the file is unreadable.
pub fn read_secret_file(path_var: &str) -> anyhow::Result<String> {
    let path = required(path_var)?;
    std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("failed to read secret file at `{path_var}` ({path}): {e}"))
}

/// Load the Tenants JWT signing key (`EdDSA` PKCS#8 PEM) from the file at
/// `JWT_SIGNING_KEY_PATH`.
///
/// Deliberately not a config field: the private signing key is consumed once at
/// startup to build the JWT signer and must not live in the long-lived, `Clone`d
/// config shared into every handler.
///
/// # Errors
/// Returns an error if `JWT_SIGNING_KEY_PATH` is unset or the file is unreadable.
pub fn load_jwt_signing_key_pem() -> anyhow::Result<String> {
    read_secret_file("JWT_SIGNING_KEY_PATH")
}

/// Load the Tenants JWT **verify** key (`EdDSA` SPKI public-key PEM) from the file
/// at `JWT_VERIFY_KEY_PATH`.
///
/// # Errors
/// Returns an error if `JWT_VERIFY_KEY_PATH` is unset or the file is unreadable.
pub fn load_jwt_verify_key_pem() -> anyhow::Result<String> {
    read_secret_file("JWT_VERIFY_KEY_PATH")
}
