//! Postgres-backed repository unit tests + their pool helper.
//!
//! These are `#[ignore]`'d (they need a live Postgres — `docker compose up -d`
//! from `source/`). The pool helper lives here under `cfg(test)` so it can use
//! dev-only `uuid` for per-test database isolation without pulling it into the
//! production dependency set; `sqlx::migrate!` resolves its path relative to this
//! crate.

mod operational;

/// Build a pool connected to an isolated per-test database with the regional
/// migration set applied.
///
/// Requires a `PostgreSQL` server reachable at `DDNS_TEST_DATABASE_URL`
/// (default: `postgres://postgres:postgres@127.0.0.1:5432`) — a bare server URL
/// **without** a trailing `/database` path.
async fn test_pool() -> sqlx::PgPool {
    let pool = fresh_database().await;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("apply regional migrations");
    pool
}

/// Create a fresh, empty per-test database and return a pool connected to it.
async fn fresh_database() -> sqlx::PgPool {
    let base_url = std::env::var("DDNS_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432".to_string());
    assert!(
        base_url
            .strip_prefix("postgres://")
            .or_else(|| base_url.strip_prefix("postgresql://"))
            .is_some_and(|rest| !rest.contains('/')),
        "DDNS_TEST_DATABASE_URL must be a bare server URL without a /database path, got: {base_url}"
    );

    let maintenance_pool = sqlx::PgPool::connect(&format!("{base_url}/postgres"))
        .await
        .expect("Postgres unreachable — run `docker compose up -d` from source/");

    let db_name = format!("t{}", uuid::Uuid::new_v4().simple());
    // `CREATE DATABASE` is DDL: the identifier cannot be bind-parameterised, so
    // this inline `format!` is the deliberate, test-only exception to the
    // "query strings are `const &str`" convention. The name is a fresh
    // UUID-derived identifier (not user input).
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE \"{db_name}\""
    )))
    .execute(&maintenance_pool)
    .await
    .expect("CREATE DATABASE");
    drop(maintenance_pool);

    sqlx::PgPool::connect(&format!("{base_url}/{db_name}"))
        .await
        .expect("connect to test database")
}
