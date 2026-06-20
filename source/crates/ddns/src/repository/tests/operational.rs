use chrono::Utc;

use super::test_pool;
use crate::db::DbPools;
use crate::repository::operational::{OperationalRepository, PgOperationalRepository};

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
async fn record_ip_creates_then_updates_ip_only() {
    let repo = repo().await;
    // No row until the first report.
    assert!(repo.find_by_id("net-1").await.unwrap().is_none());

    repo.record_ip("net-1", "203.0.113.7", Utc::now())
        .await
        .unwrap();
    let row = repo.find_by_id("net-1").await.unwrap().expect("exists");
    assert_eq!(row.ip.as_deref(), Some("203.0.113.7"));
    // record_ip must not invent an fqdn / A-record claim.
    assert_eq!(row.fqdn, None);
    assert_eq!(row.cf_a_record_id, None);

    repo.record_ip("net-1", "203.0.113.8", Utc::now())
        .await
        .unwrap();
    assert_eq!(
        repo.find_by_id("net-1")
            .await
            .unwrap()
            .unwrap()
            .ip
            .as_deref(),
        Some("203.0.113.8")
    );
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn record_ip_never_clobbers_a_record_claim() {
    let repo = repo().await;
    repo.record_ip("net-2", "203.0.113.1", Utc::now())
        .await
        .unwrap();
    // The provisioner claims the A record.
    assert!(
        repo.claim_a_record("net-2", "x.example.com", "cf-a-2", Utc::now())
            .await
            .unwrap()
    );
    // A later IP report must update the IP but leave the fqdn / claim intact.
    repo.record_ip("net-2", "203.0.113.2", Utc::now())
        .await
        .unwrap();
    let row = repo.find_by_id("net-2").await.unwrap().unwrap();
    assert_eq!(row.ip.as_deref(), Some("203.0.113.2"));
    assert_eq!(row.fqdn.as_deref(), Some("x.example.com"));
    assert_eq!(row.cf_a_record_id.as_deref(), Some("cf-a-2"));
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn claim_a_record_cas_wins_once_then_loses() {
    let repo = repo().await;
    repo.record_ip("net-3", "203.0.113.3", Utc::now())
        .await
        .unwrap();

    // First claim wins.
    assert!(
        repo.claim_a_record("net-3", "y.example.com", "cf-a-first", Utc::now())
            .await
            .unwrap()
    );
    // A peer replica's claim loses (cf_a_record_id is no longer NULL).
    assert!(
        !repo
            .claim_a_record("net-3", "y.example.com", "cf-a-second", Utc::now())
            .await
            .unwrap()
    );
    assert_eq!(
        repo.find_by_id("net-3")
            .await
            .unwrap()
            .unwrap()
            .cf_a_record_id
            .as_deref(),
        Some("cf-a-first"),
        "the winner's record id must survive"
    );
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn cas_acme_records_creates_and_replaces_on_match() {
    let repo = repo().await;
    // From the empty (no-row) state, expected `[]` succeeds and creates the row.
    let ok = repo
        .cas_acme_records("net-4", &[], &["txt-1".into(), "txt-2".into()], Utc::now())
        .await
        .unwrap();
    assert!(ok);
    assert_eq!(
        repo.find_by_id("net-4")
            .await
            .unwrap()
            .unwrap()
            .cf_acme_record_ids,
        vec!["txt-1", "txt-2"]
    );

    // Replacing with the correct expected list succeeds.
    let ok = repo
        .cas_acme_records(
            "net-4",
            &["txt-1".into(), "txt-2".into()],
            &["txt-3".into()],
            Utc::now(),
        )
        .await
        .unwrap();
    assert!(ok);
    assert_eq!(
        repo.find_by_id("net-4")
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
    repo.cas_acme_records("net-5", &[], &["txt-a".into()], Utc::now())
        .await
        .unwrap();

    // A writer that still thinks the list is empty loses the CAS.
    let ok = repo
        .cas_acme_records("net-5", &[], &["txt-b".into()], Utc::now())
        .await
        .unwrap();
    assert!(!ok, "CAS must miss when the stored list changed underneath");
    assert_eq!(
        repo.find_by_id("net-5")
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
    repo.record_ip("net-6", "203.0.113.9", Utc::now())
        .await
        .unwrap();
    repo.delete("net-6").await.unwrap();
    assert!(repo.find_by_id("net-6").await.unwrap().is_none());
}
