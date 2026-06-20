//! Unit tests for the reconcile loop *ticks* (the loops themselves run forever;
//! the ticks are the testable unit) over mock work-queue + DNS + operational repo.

use std::sync::Arc;

use chrono::Utc;

use super::{provisioner_tick, reaper_tick};
use crate::repository::OperationalRepository;
use crate::service::DdnsService;
use crate::test_helpers::{InMemoryOperational, MockDnsProvider, MockWorkQueue};
use wardnet_common::contract::ProvisioningState;

use crate::work_queue::{NetworkView, WorkQueue};

const REGION: &str = "use1";
const PARENT: &str = "my.wardnet.services";

fn view(id: &str, slug: &str, state: &str) -> NetworkView {
    NetworkView {
        id: id.to_string(),
        tenant_id: "t1".to_string(),
        slug: slug.to_string(),
        display_name: slug.to_string(),
        region: REGION.to_string(),
        provisioning_state: ProvisioningState::from_db(state).unwrap(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test]
async fn provisioner_publishes_and_reports_active_when_ip_present() {
    let work = MockWorkQueue::new();
    work.seed(view("n1", "happy", "provisioning"));
    let op = InMemoryOperational::new();
    op.record_ip("n1", "203.0.113.1", Utc::now()).await.unwrap();
    let dns = MockDnsProvider::new();
    let svc = Arc::new(DdnsService::new(
        Arc::new(op.clone()),
        Arc::new(dns.clone()),
    ));

    let work_dyn: Arc<dyn WorkQueue> = Arc::new(work.clone());
    let op_dyn: Arc<dyn OperationalRepository> = Arc::new(op.clone());
    provisioner_tick(&work_dyn, &svc, &op_dyn, REGION, PARENT).await;

    assert_eq!(dns.a_creates(), 1, "the A record was published");
    assert_eq!(
        work.transitions(),
        vec![("n1".to_string(), "active".to_string())]
    );
    assert_eq!(
        op.get("n1").unwrap().fqdn.as_deref(),
        Some("happy.my.wardnet.services")
    );
}

#[tokio::test]
async fn provisioner_skips_network_without_an_ip() {
    let work = MockWorkQueue::new();
    work.seed(view("n2", "noip", "provisioning"));
    let op = InMemoryOperational::new(); // no row for n2 → no IP yet
    let dns = MockDnsProvider::new();
    let svc = Arc::new(DdnsService::new(
        Arc::new(op.clone()),
        Arc::new(dns.clone()),
    ));

    let work_dyn: Arc<dyn WorkQueue> = Arc::new(work.clone());
    let op_dyn: Arc<dyn OperationalRepository> = Arc::new(op.clone());
    provisioner_tick(&work_dyn, &svc, &op_dyn, REGION, PARENT).await;

    assert_eq!(dns.a_creates(), 0, "nothing published without an IP");
    assert!(
        work.transitions().is_empty(),
        "no transition for a skipped network"
    );
}

#[tokio::test]
async fn reaper_tears_down_dns_and_reports_deprovisioned() {
    let work = MockWorkQueue::new();
    work.seed(view("n3", "gone", "deprovisioning"));
    let op = InMemoryOperational::new();
    op.seed_claimed("n3", "gone.my.wardnet.services", "a-rid");
    let dns = MockDnsProvider::new();
    let svc = Arc::new(DdnsService::new(
        Arc::new(op.clone()),
        Arc::new(dns.clone()),
    ));

    let work_dyn: Arc<dyn WorkQueue> = Arc::new(work.clone());
    reaper_tick(&work_dyn, &svc, REGION).await;

    assert!(
        dns.deleted().contains(&"a-rid".to_string()),
        "A record torn down"
    );
    assert_eq!(
        work.transitions(),
        vec![("n3".to_string(), "deprovisioned".to_string())]
    );
    assert!(op.get("n3").is_none(), "operational row dropped");
}

#[tokio::test]
async fn reaper_does_not_crash_when_transition_fails() {
    let work = MockWorkQueue::new();
    work.seed(view("n4", "gone", "deprovisioning"));
    work.fail_transitions();
    let op = InMemoryOperational::new();
    op.seed_claimed("n4", "gone.my.wardnet.services", "a-rid");
    let dns = MockDnsProvider::new();
    let svc = Arc::new(DdnsService::new(
        Arc::new(op.clone()),
        Arc::new(dns.clone()),
    ));

    let work_dyn: Arc<dyn WorkQueue> = Arc::new(work.clone());
    // Must complete without panicking even though the PATCH fails.
    reaper_tick(&work_dyn, &svc, REGION).await;

    // DNS teardown still happened; the failed report was logged, not propagated.
    assert!(dns.deleted().contains(&"a-rid".to_string()));
    assert!(
        work.transitions().is_empty(),
        "no transition recorded on PATCH failure (retried next tick)"
    );
}

#[tokio::test]
async fn provisioner_does_not_crash_when_transition_fails() {
    let work = MockWorkQueue::new();
    work.seed(view("n5", "happy", "provisioning"));
    work.fail_transitions();
    let op = InMemoryOperational::new();
    op.record_ip("n5", "203.0.113.1", Utc::now()).await.unwrap();
    let dns = MockDnsProvider::new();
    let svc = Arc::new(DdnsService::new(
        Arc::new(op.clone()),
        Arc::new(dns.clone()),
    ));

    let work_dyn: Arc<dyn WorkQueue> = Arc::new(work.clone());
    let op_dyn: Arc<dyn OperationalRepository> = Arc::new(op.clone());
    provisioner_tick(&work_dyn, &svc, &op_dyn, REGION, PARENT).await;

    assert_eq!(
        dns.a_creates(),
        1,
        "record published before the failed report"
    );
    assert!(work.transitions().is_empty());
}

/// Smallest network count that forces a second cursor page (a full first page + one more).
fn over_one_page() -> usize {
    usize::try_from(super::PAGE_LIMIT).expect("PAGE_LIMIT fits usize") + 1
}

/// Seed `total` provisioning networks (each with a reported IP iff `with_ip`) and run one
/// provisioner tick over them, returning the DNS + work-queue mocks for assertions.
async fn run_provisioner_over(total: usize, with_ip: bool) -> (MockDnsProvider, MockWorkQueue) {
    let work = MockWorkQueue::new();
    let op = InMemoryOperational::new();
    for i in 0..total {
        let id = format!("n{i:03}");
        work.seed(view(&id, &format!("net{i:03}"), "provisioning"));
        if with_ip {
            op.record_ip(&id, "203.0.113.1", Utc::now()).await.unwrap();
        }
    }
    let dns = MockDnsProvider::new();
    let svc = Arc::new(DdnsService::new(
        Arc::new(op.clone()),
        Arc::new(dns.clone()),
    ));
    let work_dyn: Arc<dyn WorkQueue> = Arc::new(work.clone());
    let op_dyn: Arc<dyn OperationalRepository> = Arc::new(op.clone());
    provisioner_tick(&work_dyn, &svc, &op_dyn, REGION, PARENT).await;
    (dns, work)
}

#[tokio::test]
async fn provisioner_drains_more_than_one_page() {
    // Just over PAGE_LIMIT, each with an IP: the provisioner must publish + transition
    // every one, exercising the cursor loop (`after`/`full`) single-page tests never reach.
    let (dns, work) = run_provisioner_over(over_one_page(), true).await;
    assert_eq!(
        dns.a_creates(),
        over_one_page(),
        "every network across both pages was published"
    );
    assert_eq!(
        work.transitions().len(),
        over_one_page(),
        "every network across both pages transitioned to active"
    );
}

#[tokio::test]
async fn provisioner_cursor_advances_past_skipped_networks() {
    // The same >PAGE_LIMIT count, but none has an IP: every row is *skipped*. The tick must
    // still terminate — the cursor advances past skipped rows rather than re-reading a
    // wedged page forever (ADR-0001). A hang here would mean the cursor failed to advance.
    let (dns, work) = run_provisioner_over(over_one_page(), false).await;
    assert_eq!(dns.a_creates(), 0, "no IP reported yet → nothing published");
    assert!(
        work.transitions().is_empty(),
        "skipped networks are not transitioned"
    );
}
