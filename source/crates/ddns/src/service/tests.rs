//! Unit tests for [`DdnsService`] over the in-memory operational repo + mock DNS
//! provider (no Postgres, no Cloudflare).

use std::sync::Arc;

use crate::service::{DdnsError, DdnsService};
use crate::test_helpers::{InMemoryOperational, MockDnsProvider};

const FQDN: &str = "host.my.wardnet.services";

fn service(op: &InMemoryOperational, dns: &MockDnsProvider) -> DdnsService {
    DdnsService::new(Arc::new(op.clone()), Arc::new(dns.clone()))
}

#[tokio::test]
async fn report_ip_without_a_record_stores_ip_and_never_calls_cloudflare() {
    let op = InMemoryOperational::new();
    let dns = MockDnsProvider::new();
    let svc = service(&op, &dns);

    svc.report_ip("net-1", "203.0.113.5").await.unwrap();

    // report-IP must never create a Cloudflare record (only the provisioner does).
    assert_eq!(dns.a_creates(), 0);
    assert_eq!(dns.a_updates(), 0);
    let row = op.get("net-1").expect("row created");
    assert_eq!(row.ip.as_deref(), Some("203.0.113.5"));
    assert_eq!(row.cf_a_record_id, None);
    assert_eq!(row.fqdn, None);
}

#[tokio::test]
async fn report_ip_after_provision_updates_a_record_in_place() {
    let op = InMemoryOperational::new();
    let dns = MockDnsProvider::new();
    let svc = service(&op, &dns);

    // First report creates the row (no CF write); provisioner publishes the record.
    svc.report_ip("net-2", "203.0.113.1").await.unwrap();
    svc.provision("net-2", FQDN, "203.0.113.1").await.unwrap();
    assert_eq!(dns.a_creates(), 1);

    // A later report updates the existing record in place — never a second create.
    svc.report_ip("net-2", "203.0.113.2").await.unwrap();
    assert_eq!(dns.a_creates(), 1);
    assert_eq!(dns.a_updates(), 1);
    assert_eq!(dns.a_record_count(), 1);
    assert_eq!(op.get("net-2").unwrap().ip.as_deref(), Some("203.0.113.2"));
}

#[tokio::test]
async fn provision_is_idempotent_and_does_not_duplicate_records() {
    let op = InMemoryOperational::new();
    let dns = MockDnsProvider::new();
    let svc = service(&op, &dns);

    svc.report_ip("net-3", "203.0.113.7").await.unwrap();

    svc.provision("net-3", FQDN, "203.0.113.7").await.unwrap();
    // A second provision (another replica, or a retried tick) adopts the existing
    // record and loses the CAS — it must NOT delete the live record.
    svc.provision("net-3", FQDN, "203.0.113.7").await.unwrap();

    assert_eq!(dns.a_record_count(), 1, "no duplicate A record");
    assert!(
        dns.deleted().is_empty(),
        "the live record must not be deleted"
    );
    assert_eq!(
        op.get("net-3").unwrap().cf_a_record_id.as_deref(),
        Some("a-1")
    );
}

#[tokio::test]
async fn provision_losing_cas_after_a_fresh_create_deletes_the_duplicate() {
    let op = InMemoryOperational::new();
    let dns = MockDnsProvider::new();
    let svc = service(&op, &dns);

    // A peer replica already claimed this network with its own record id, but no
    // A record exists in CF for this fqdn (so we take the *create* path).
    op.seed_claimed("net-4", FQDN, "peer-id");

    svc.provision("net-4", FQDN, "203.0.113.9").await.unwrap();

    // We created a fresh record, lost the CAS, and dropped our duplicate.
    assert_eq!(dns.deleted(), vec!["a-1".to_string()]);
    assert_eq!(dns.a_record_count(), 0);
    assert_eq!(
        op.get("net-4").unwrap().cf_a_record_id.as_deref(),
        Some("peer-id"),
        "the winner's claim must survive"
    );
}

#[tokio::test]
async fn set_acme_challenge_creates_txt_records_and_persists_ids() {
    let op = InMemoryOperational::new();
    let dns = MockDnsProvider::new();
    let svc = service(&op, &dns);

    svc.set_acme_challenge(
        "net-5",
        "_acme-challenge.host.my.wardnet.services",
        &["v1".to_string(), "v2".to_string()],
    )
    .await
    .unwrap();

    let ids = op.get("net-5").unwrap().cf_acme_record_ids;
    assert_eq!(ids.len(), 2, "one TXT record per value");
}

#[tokio::test]
async fn set_acme_challenge_maps_cas_miss_to_conflict() {
    let op = InMemoryOperational::new();
    let dns = MockDnsProvider::new();
    let svc = service(&op, &dns);

    op.force_next_acme_cas_miss();

    let err = svc
        .set_acme_challenge(
            "net-6",
            "_acme-challenge.host.my.wardnet.services",
            &["v1".to_string()],
        )
        .await
        .expect_err("a CAS miss must surface as Conflict");
    assert!(matches!(err, DdnsError::Conflict(_)));
}

#[tokio::test]
async fn clear_acme_challenge_is_noop_when_none_live() {
    let op = InMemoryOperational::new();
    let dns = MockDnsProvider::new();
    let svc = service(&op, &dns);

    svc.clear_acme_challenge("net-7").await.unwrap();
    assert!(dns.deleted().is_empty());
}

#[tokio::test]
async fn delete_records_tears_down_a_and_txt_then_drops_the_row() {
    let op = InMemoryOperational::new();
    let dns = MockDnsProvider::new();
    let svc = service(&op, &dns);

    svc.report_ip("net-8", "203.0.113.3").await.unwrap();
    svc.provision("net-8", FQDN, "203.0.113.3").await.unwrap();
    svc.set_acme_challenge(
        "net-8",
        "_acme-challenge.host.my.wardnet.services",
        &["v1".to_string()],
    )
    .await
    .unwrap();

    svc.delete_records("net-8").await.unwrap();

    assert_eq!(dns.a_record_count(), 0);
    assert!(op.get("net-8").is_none(), "operational row dropped");
}

#[tokio::test]
async fn delete_records_is_noop_when_no_row() {
    let op = InMemoryOperational::new();
    let dns = MockDnsProvider::new();
    let svc = service(&op, &dns);

    svc.delete_records("absent").await.unwrap();
    assert!(dns.deleted().is_empty());
}
