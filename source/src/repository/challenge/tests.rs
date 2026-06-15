use chrono::Utc;

use crate::db::DbPools;
use crate::repository::challenge::{
    ChallengeRepository, PgChallengeRepository, RegistrationChallenge,
};
use crate::test_helpers::test_pool_global;

/// `new()` is a trivial one-liner; call it once without `Postgres` so it shows covered.
#[tokio::test]
async fn new_from_lazy_pool() {
    let pool =
        sqlx::PgPool::connect_lazy("postgres://postgres:postgres@127.0.0.1:5432/dummy").unwrap();
    let _ = PgChallengeRepository::new(pool);
}

async fn repo() -> PgChallengeRepository {
    let pool = test_pool_global().await;
    PgChallengeRepository::new_pools(DbPools::single(pool))
}

fn sample(id: &str, ip: &str) -> RegistrationChallenge {
    let now = Utc::now();
    RegistrationChallenge {
        id: id.to_string(),
        nonce: "abcdef1234567890".repeat(4),
        difficulty: 24,
        remote_ip: ip.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        used_at: None,
    }
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn insert_and_find() {
    let repo = repo().await;
    repo.insert(&sample("c-1", "1.2.3.4")).await.unwrap();

    let found = repo.find_by_id("c-1").await.unwrap().expect("should exist");
    assert_eq!(found.difficulty, 24);
    assert!(found.used_at.is_none());
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn count_from_ip() {
    let repo = repo().await;
    repo.insert(&sample("c-3", "10.0.0.1")).await.unwrap();
    repo.insert(&sample("c-4", "10.0.0.1")).await.unwrap();
    repo.insert(&sample("c-5", "10.0.0.2")).await.unwrap();

    let since = Utc::now() - chrono::Duration::hours(1);
    assert_eq!(repo.count_from_ip("10.0.0.1", since).await.unwrap(), 2);
    assert_eq!(repo.count_from_ip("10.0.0.2", since).await.unwrap(), 1);
    assert_eq!(repo.count_from_ip("9.9.9.9", since).await.unwrap(), 0);
}
