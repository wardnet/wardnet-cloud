//! Test-only helpers for the Tenants crate's in-crate (Postgres-backed) unit tests.
//!
//! The JWT-keypair helper lives in `wardnet_common::test_helpers` (reached only by
//! `common`'s own `cfg(test)` code); integration tests keep their own copy. This
//! pool helper stays here because `sqlx::migrate!` resolves its path relative to
//! this crate (`crates/tenants/migrations` — the global naming-authority set).

/// Build a pool connected to an isolated per-test database with the global
/// naming-authority migrations applied (identities, registration challenges,
/// registration log).
///
/// Requires a `PostgreSQL` server reachable at `CLOUD_TEST_DATABASE_URL`
/// (default: `postgres://postgres:postgres@127.0.0.1:5432`), a bare server URL
/// **without** a trailing `/database` path. Start one with `docker compose up -d`
/// from `source/`.
pub async fn test_pool_global() -> sqlx::PgPool {
    let pool = fresh_database().await;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("apply global migrations");
    pool
}

/// Create a fresh, empty per-test database on the test server and return a pool
/// connected to it (no migrations applied).
async fn fresh_database() -> sqlx::PgPool {
    let base_url = std::env::var("CLOUD_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432".to_string());
    assert!(
        base_url
            .strip_prefix("postgres://")
            .or_else(|| base_url.strip_prefix("postgresql://"))
            .is_some_and(|rest| !rest.contains('/')),
        "CLOUD_TEST_DATABASE_URL must be a bare server URL without a /database path, got: {base_url}"
    );

    let maintenance_pool = sqlx::PgPool::connect(&format!("{base_url}/postgres"))
        .await
        .expect("Postgres unreachable — run `docker compose up -d` from source/");

    let db_name = format!("t{}", uuid::Uuid::new_v4().simple());
    // `CREATE DATABASE` is DDL — Postgres cannot bind-parameterise the database
    // identifier, so this inline `format!` is the deliberate, test-only exception
    // to the "query strings are `const &str`" convention. The name is a fresh
    // UUID-derived identifier (not user input).
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&maintenance_pool)
        .await
        .expect("CREATE DATABASE");
    drop(maintenance_pool);

    sqlx::PgPool::connect(&format!("{base_url}/{db_name}"))
        .await
        .expect("connect to test database")
}
