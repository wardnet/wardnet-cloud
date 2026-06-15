use chrono::Utc;

use crate::db::DbPools;
use crate::repository::operational::{OperationalRepository, PgOperationalRepository};
use crate::test_helpers::test_pool;

/// `new()` is a trivial one-liner; call it once without `Postgres` so it shows covered.
#[tokio::test]
async fn new_from_lazy_pool() {
    let pool =
        sqlx::PgPool::connect_lazy("postgres://postgres:postgres@127.0.0.1:5432/dummy").unwrap();
    let _ = PgOperationalRepository::new(pool);
}

async fn repo() -> PgOperationalRepository {
    let pool = test_pool().await;
    PgOperationalRepository::new_pools(DbPools::single(pool))
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn upsert_ip_creates_then_updates_row() {
    let repo = repo().await;
    // No row until the first publish.
    assert!(repo.find_by_id("op-1").await.unwrap().is_none());

    repo.upsert_ip("op-1", "203.0.113.7", "cf-a-1", Utc::now())
        .await
        .unwrap();
    let row = repo.find_by_id("op-1").await.unwrap().expect("exists");
    assert_eq!(row.ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(row.cf_a_record_id.as_deref(), Some("cf-a-1"));

    repo.upsert_ip("op-1", "203.0.113.8", "cf-a-2", Utc::now())
        .await
        .unwrap();
    let row = repo.find_by_id("op-1").await.unwrap().expect("exists");
    assert_eq!(row.ip.as_deref(), Some("203.0.113.8"));
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn cas_acme_records_creates_and_replaces_on_match() {
    let repo = repo().await;
    // From the empty (no-row) state, expected `[]` succeeds and creates the row.
    let ok = repo
        .cas_acme_records("op-2", &[], &["txt-1".into(), "txt-2".into()], Utc::now())
        .await
        .unwrap();
    assert!(ok);
    let row = repo.find_by_id("op-2").await.unwrap().expect("exists");
    assert_eq!(row.cf_acme_record_ids, vec!["txt-1", "txt-2"]);

    // Replacing with the correct expected list succeeds.
    let ok = repo
        .cas_acme_records(
            "op-2",
            &["txt-1".into(), "txt-2".into()],
            &["txt-3".into()],
            Utc::now(),
        )
        .await
        .unwrap();
    assert!(ok);
    assert_eq!(
        repo.find_by_id("op-2")
            .await
            .unwrap()
            .unwrap()
            .cf_acme_record_ids,
        vec!["txt-3"]
    );
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn cas_acme_records_misses_on_stale_expected() {
    let repo = repo().await;
    repo.cas_acme_records("op-3", &[], &["txt-a".into()], Utc::now())
        .await
        .unwrap();

    // A writer that still thinks the list is empty loses the CAS.
    let ok = repo
        .cas_acme_records("op-3", &[], &["txt-b".into()], Utc::now())
        .await
        .unwrap();
    assert!(!ok, "CAS must miss when the stored list changed underneath");
    assert_eq!(
        repo.find_by_id("op-3")
            .await
            .unwrap()
            .unwrap()
            .cf_acme_record_ids,
        vec!["txt-a"],
        "the stored list must be untouched on a CAS miss"
    );
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn delete_removes_row() {
    let repo = repo().await;
    repo.upsert_ip("op-4", "203.0.113.9", "cf-a", Utc::now())
        .await
        .unwrap();
    repo.delete("op-4").await.unwrap();
    assert!(repo.find_by_id("op-4").await.unwrap().is_none());
}
