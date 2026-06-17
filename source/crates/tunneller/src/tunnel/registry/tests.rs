use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use super::{ForwardRequest, ForwardResult, TunnelRegistry};

/// A connected local `TcpStream`, boxed as a tunnel stream.
async fn boxed_stream() -> Box<dyn super::TunnelStream> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = TcpStream::connect(addr).await.unwrap();
    Box::new(stream)
}

#[tokio::test]
async fn register_and_unregister() {
    let reg = TunnelRegistry::new();
    assert!(!reg.is_connected("alice"));

    let registration = reg.register("alice");
    assert!(reg.is_connected("alice"));

    assert!(reg.unregister("alice", registration.generation));
    assert!(!reg.is_connected("alice"));
}

#[tokio::test]
async fn forward_delivers_request() {
    let reg = Arc::new(TunnelRegistry::new());
    let mut registration = reg.register("bob");

    let req = ForwardRequest {
        stream: boxed_stream().await,
        dest_port: 443,
    };
    let result = reg.forward("bob", req);
    assert!(matches!(result, ForwardResult::Accepted));

    let received = registration.rx.recv().await;
    assert!(received.is_some());
    assert_eq!(received.unwrap().dest_port, 443);
}

#[tokio::test]
async fn forward_returns_not_connected_when_unregistered() {
    let reg = TunnelRegistry::new();
    let req = ForwardRequest {
        stream: boxed_stream().await,
        dest_port: 443,
    };
    assert!(matches!(
        reg.forward("nobody", req),
        ForwardResult::NotConnected
    ));
}

#[tokio::test]
async fn forward_returns_buffer_full_when_channel_saturated() {
    let reg = TunnelRegistry::new();
    let registration = reg.register("frank");

    // Fill the channel to capacity (64 slots).
    for _ in 0..64 {
        let result = reg.forward(
            "frank",
            ForwardRequest {
                stream: boxed_stream().await,
                dest_port: 443,
            },
        );
        assert!(matches!(result, ForwardResult::Accepted));
    }

    let result = reg.forward(
        "frank",
        ForwardRequest {
            stream: boxed_stream().await,
            dest_port: 443,
        },
    );
    assert!(matches!(result, ForwardResult::BufferFull));

    drop(registration);
}

#[tokio::test]
async fn forward_returns_not_connected_when_receiver_dropped() {
    let reg = TunnelRegistry::new();
    // Register and immediately drop the registration (its receiver) — the sender
    // stays in the map but try_send returns Closed.
    drop(reg.register("grace"));

    let result = reg.forward(
        "grace",
        ForwardRequest {
            stream: boxed_stream().await,
            dest_port: 443,
        },
    );
    assert!(matches!(result, ForwardResult::NotConnected));
}

#[tokio::test]
async fn second_register_aborts_and_replaces_first() {
    let reg = TunnelRegistry::new();
    let first = reg.register("carol");
    // A reconnect replaces the registration and fires the displaced one's token.
    let second = reg.register("carol");
    assert!(first.abort.is_cancelled());
    assert!(!second.abort.is_cancelled());
    assert!(reg.is_connected("carol"));

    // The superseded generation must not evict the live registration.
    assert!(!reg.unregister("carol", first.generation));
    assert!(reg.is_connected("carol"));

    // The owning generation removes it.
    assert!(reg.unregister("carol", second.generation));
    assert!(!reg.is_connected("carol"));
}

#[tokio::test]
async fn abort_cancels_token_and_removes() {
    let reg = TunnelRegistry::new();
    let registration = reg.register("dave");
    assert!(reg.abort("dave"));
    assert!(registration.abort.is_cancelled());
    assert!(!reg.is_connected("dave"));
    // Aborting an absent slug is a no-op.
    assert!(!reg.abort("dave"));
}
