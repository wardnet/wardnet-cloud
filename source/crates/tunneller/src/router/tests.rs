use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};

use super::{LocalRouter, TunnelRouter};
use crate::mesh::InterNodeForwarder;
use crate::repository::{TunnelRoute, TunnelRouteRepository};
use crate::test_helpers::{InMemoryRoutes, TEST_NODE_ADDR};
use crate::tunnel::TunnelRegistry;

const NET: &str = "net-1";
const TENANT: &str = "tenant-1";
const PEER_NODE: &str = "node-b.tunneller.mesh:9444";

/// Records every inter-node forward it is asked to make (and drops the stream).
#[derive(Default)]
struct MockForwarder(Mutex<Vec<(String, String, u16)>>);

impl MockForwarder {
    fn calls(&self) -> Vec<(String, String, u16)> {
        self.0.lock().unwrap().clone()
    }
}

#[async_trait]
impl InterNodeForwarder for MockForwarder {
    async fn forward(
        &self,
        node_addr: &str,
        slug: &str,
        dest_port: u16,
        _client: TcpStream,
    ) -> anyhow::Result<()> {
        self.0
            .lock()
            .unwrap()
            .push((node_addr.to_string(), slug.to_string(), dest_port));
        Ok(())
    }
}

/// A connected client `TcpStream` (the SNI-accepted side).
async fn client_stream() -> TcpStream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let _server = listener.accept().await.unwrap();
    client
}

fn build_router(
    registry: Arc<TunnelRegistry>,
    routes: InMemoryRoutes,
    forwarder: Arc<MockForwarder>,
) -> LocalRouter {
    LocalRouter::new(
        registry,
        Arc::new(routes) as Arc<dyn TunnelRouteRepository>,
        forwarder as Arc<dyn InterNodeForwarder>,
        TEST_NODE_ADDR.to_string(),
    )
}

#[tokio::test]
async fn routes_local_slug_to_registry() {
    let registry = Arc::new(TunnelRegistry::new());
    let mut registration = registry.register("alice");
    let forwarder = Arc::new(MockForwarder::default());
    let subject = build_router(
        Arc::clone(&registry),
        InMemoryRoutes::new(),
        forwarder.clone(),
    );

    subject.route("alice", client_stream().await, 443).await;

    // Delivered locally; no inter-node forward.
    let got = registration.rx.recv().await.expect("local delivery");
    assert_eq!(got.dest_port, 443);
    assert!(forwarder.calls().is_empty());
}

#[tokio::test]
async fn forwards_remote_slug_to_owning_node() {
    let registry = Arc::new(TunnelRegistry::new());
    let routes = InMemoryRoutes::new();
    // The slug is owned by a different node.
    routes.upsert("bob", PEER_NODE, NET, TENANT).await.unwrap();
    let forwarder = Arc::new(MockForwarder::default());
    let subject = build_router(registry, routes, forwarder.clone());

    subject.route("bob", client_stream().await, 853).await;

    assert_eq!(
        forwarder.calls(),
        vec![(PEER_NODE.to_string(), "bob".to_string(), 853)]
    );
}

#[tokio::test]
async fn drops_unknown_slug() {
    let registry = Arc::new(TunnelRegistry::new());
    let forwarder = Arc::new(MockForwarder::default());
    let subject = build_router(registry, InMemoryRoutes::new(), forwarder.clone());

    subject.route("nobody", client_stream().await, 443).await;

    assert!(forwarder.calls().is_empty());
}

#[tokio::test]
async fn drops_stale_local_route_with_no_live_tunnel() {
    let registry = Arc::new(TunnelRegistry::new());
    let routes = InMemoryRoutes::new();
    // The table says we own it, but the registry has no live tunnel (post-restart).
    routes.seed(TunnelRoute {
        slug: "carol".to_string(),
        node_addr: TEST_NODE_ADDR.to_string(),
        network_id: NET.to_string(),
        tenant_id: TENANT.to_string(),
        last_seen: chrono::Utc::now(),
    });
    let forwarder = Arc::new(MockForwarder::default());
    let subject = build_router(registry, routes, forwarder.clone());

    subject.route("carol", client_stream().await, 443).await;

    // Fail closed: not forwarded anywhere.
    assert!(forwarder.calls().is_empty());
}
