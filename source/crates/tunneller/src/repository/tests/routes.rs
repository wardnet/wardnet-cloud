use chrono::Utc;

use super::test_pool;
use crate::db::DbPools;
use crate::repository::{PgTunnelRouteRepository, TunnelRouteRepository};

const NODE_A: &str = "node-a:9444";
const NODE_B: &str = "node-b:9444";

/// `new()` is a trivial one-liner; call it once without `Postgres` so it shows covered.
#[tokio::test]
async fn new_from_lazy_pool() {
    let pool =
        sqlx::PgPool::connect_lazy("postgres://postgres:postgres@127.0.0.1:5432/dummy").unwrap();
    let _ = PgTunnelRouteRepository::new(pool);
}

async fn repo() -> PgTunnelRouteRepository {
    let pool = test_pool().await;
    PgTunnelRouteRepository::new_pools(DbPools::single(pool))
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn upsert_find_and_move_owner() {
    let repo = repo().await;
    assert!(repo.find_by_slug("alice").await.unwrap().is_none());

    repo.upsert("alice", NODE_A, "net-1", "tenant-1")
        .await
        .unwrap();
    let row = repo.find_by_slug("alice").await.unwrap().expect("exists");
    assert_eq!(row.node_addr, NODE_A);
    assert_eq!(row.network_id, "net-1");
    assert_eq!(row.tenant_id, "tenant-1");

    // A reconnect onto a different node moves ownership.
    repo.upsert("alice", NODE_B, "net-1", "tenant-1")
        .await
        .unwrap();
    assert_eq!(
        repo.find_by_slug("alice").await.unwrap().unwrap().node_addr,
        NODE_B
    );
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn list_owned_filters_by_node() {
    let repo = repo().await;
    repo.upsert("a", NODE_A, "n1", "t1").await.unwrap();
    repo.upsert("b", NODE_A, "n2", "t1").await.unwrap();
    repo.upsert("c", NODE_B, "n3", "t2").await.unwrap();

    let owned = repo.list_owned(NODE_A).await.unwrap();
    let mut slugs: Vec<String> = owned.into_iter().map(|r| r.slug).collect();
    slugs.sort();
    assert_eq!(slugs, vec!["a".to_string(), "b".to_string()]);
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn delete_is_own_node_guarded() {
    let repo = repo().await;
    repo.upsert("alice", NODE_A, "n1", "t1").await.unwrap();

    // A different node cannot delete the row.
    assert!(!repo.delete("alice", NODE_B).await.unwrap());
    assert!(repo.find_by_slug("alice").await.unwrap().is_some());

    // The owner can.
    assert!(repo.delete("alice", NODE_A).await.unwrap());
    assert!(repo.find_by_slug("alice").await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn touch_refreshes_last_seen_for_owner_only() {
    let repo = repo().await;
    repo.upsert("alice", NODE_A, "n1", "t1").await.unwrap();
    let before = repo.find_by_slug("alice").await.unwrap().unwrap().last_seen;

    // A non-owner touch is a no-op.
    assert!(!repo.touch("alice", NODE_B).await.unwrap());

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(repo.touch("alice", NODE_A).await.unwrap());
    let after = repo.find_by_slug("alice").await.unwrap().unwrap().last_seen;
    assert!(after > before, "owner touch must advance last_seen");
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn reap_expired_purges_stale_rows() {
    let repo = repo().await;
    repo.upsert("fresh", NODE_A, "n1", "t1").await.unwrap();
    repo.upsert("stale", NODE_B, "n2", "t2").await.unwrap();

    // Everything older than "now" — only the freshly-stamped rows survive a deadline
    // in the past, so use a future deadline to purge both, and a past one to keep.
    let purged = repo
        .reap_expired(Utc::now() - chrono::Duration::seconds(60))
        .await
        .unwrap();
    assert_eq!(purged, 0, "no rows are older than 60s ago");

    let purged = repo
        .reap_expired(Utc::now() + chrono::Duration::seconds(60))
        .await
        .unwrap();
    assert_eq!(purged, 2, "a future deadline purges every row");
    assert!(repo.find_by_slug("fresh").await.unwrap().is_none());
}
