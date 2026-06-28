//! Cross-aggregate domain-event bus — a **port**, with an in-process adapter.
//!
//! Services **raise domain events; others react.** A service never reaches into
//! another aggregate's repository to drive a side-effect — instead it publishes a
//! [`DomainEvent`] through the [`EventBus`] port and a long-running *reactor*
//! (subscribed to the bus) calls the owning service's method. Reads stay direct
//! (a synchronous query/command port — see [`crate::ports`]); only write-side
//! side-effects flow as events.
//!
//! The port deliberately leaks **no transport type**: `subscribe` hands back a
//! `Box<dyn EventStream>`, not a `tokio::broadcast::Receiver`. The only adapter
//! shipped today is the in-process [`InProcessEventBus`] (a `tokio::broadcast`
//! channel); a durable broker (AMQP/RabbitMQ) adapter is a later drop-in that uses
//! the `group` argument for competing consumers across replicas and a real broker
//! ack in [`Delivery::ack`]. Because of that future, [`DomainEvent`] is
//! serde-serializable with a **stable, versioned wire format** ([`EVENT_WIRE_VERSION`]).
//!
//! Across **both** transports the same invariant holds: events are a best-effort
//! **fast path**; the periodic reconcile (owned by the repo-owning service) is the
//! **correctness guarantee**. A slow/absent subscriber may miss an event, so every
//! reactor must be **idempotent** and tolerate **at-least-once** delivery. The
//! broker buys durability/decoupling, never correctness.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// A cross-aggregate domain event.
///
/// Serde-serializable with a stable, `snake_case`, internally-tagged shape so the
/// future broker adapter is a drop-in (see [`WireEnvelope`]). The wire format is
/// **additive-only**: new variants and new optional fields are backward-compatible;
/// never rename or repurpose an existing variant/field without bumping
/// [`EVENT_WIRE_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainEvent {
    /// A tenant account was created. The subscription aggregate reacts by creating
    /// the tenant's free **trial** subscription.
    TenantCreated { tenant_id: String },
    /// A tenant account was deregistered (tombstoned). The subscription aggregate
    /// reacts by **cancelling** the tenant's current subscription; the identities
    /// aggregate reacts by purging the tenant's login methods + sessions.
    TenantDeregistered { tenant_id: String },
    /// A tenant's subscription became inactive (cancelled, or lapsed past its
    /// grace). The tenants aggregate reacts by **deprovisioning** the tenant's
    /// networks.
    SubscriptionDeactivated { tenant_id: String },
}

/// Wire-format version for the serialized [`DomainEvent`] envelope. Bump only on a
/// **breaking** change to the shape (a rename/removal); additive changes do not.
pub const EVENT_WIRE_VERSION: u32 = 1;

/// The versioned envelope a broker adapter puts on the wire: `{ "v": 1, "type":
/// "tenant_created", "tenant_id": "…" }`. The in-process adapter does not serialize
/// (it passes the [`DomainEvent`] by value), so this exists for the future broker
/// adapter and for round-trip tests pinning the format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    /// The wire-format version ([`EVENT_WIRE_VERSION`]).
    pub v: u32,
    /// The event payload.
    #[serde(flatten)]
    pub event: DomainEvent,
}

impl WireEnvelope {
    /// Wrap an event in the current versioned envelope.
    #[must_use]
    pub fn new(event: DomainEvent) -> Self {
        Self {
            v: EVENT_WIRE_VERSION,
            event,
        }
    }
}

/// One delivered event plus its acknowledgement handle.
///
/// In-process delivery is **auto-acked** ([`Delivery::ack`] is a no-op): the
/// reconcile loop is the safety net, so there is nothing to redeliver. A broker
/// adapter carries a real ack handle here so a reactor acks only after its effect
/// lands (at-least-once).
pub struct Delivery {
    event: DomainEvent,
}

impl Delivery {
    /// Borrow the delivered event.
    #[must_use]
    pub fn event(&self) -> &DomainEvent {
        &self.event
    }

    /// Acknowledge the delivery. No-op for the in-process adapter; a broker adapter
    /// confirms the message here so it is not redelivered (hence `async` + `self` by
    /// value — part of the port contract, even though the in-proc body is empty).
    #[allow(clippy::unused_async)]
    pub async fn ack(self) {}
}

/// Domain-event **publishing** port. Transport-free: no `tokio` type appears in any
/// signature. Services take an `Arc<dyn EventBus>`.
#[async_trait]
pub trait EventBus: Send + Sync {
    /// Publish a domain event. Best-effort: success does not guarantee any
    /// subscriber observed it (the reconcile loop is the guarantee).
    ///
    /// # Errors
    /// Returns an error only if the underlying transport fails to accept the event
    /// (the in-process adapter never errors).
    async fn publish(&self, event: &DomainEvent) -> anyhow::Result<()>;

    /// Open a subscription stream. `group` names a competing-consumer group: a no-op
    /// for the in-process adapter (every subscriber sees every event), the
    /// shared-queue key for a future broker adapter (one delivery per group).
    ///
    /// # Errors
    /// Returns an error if the transport cannot establish the subscription (the
    /// in-process adapter never errors).
    async fn subscribe(&self, group: &str) -> anyhow::Result<Box<dyn EventStream>>;
}

/// A live subscription stream. Transport-free; the concrete receiver is hidden
/// inside the adapter's implementation.
#[async_trait]
pub trait EventStream: Send {
    /// The next delivery, or `None` once the bus is closed (no more events will
    /// ever arrive).
    async fn next(&mut self) -> Option<Delivery>;
}

/// In-process [`EventBus`] adapter backed by [`tokio::sync::broadcast`].
///
/// Clone-friendly — wraps a `broadcast::Sender`, which is `Clone`. A publish with no
/// live subscribers is a no-op (the reconcile loop is the safety net), so publishing
/// never blocks and never fails the caller. `group` is ignored: every subscriber
/// sees every event (parity with the prior in-process behaviour).
#[derive(Debug, Clone)]
pub struct InProcessEventBus {
    sender: broadcast::Sender<DomainEvent>,
}

impl InProcessEventBus {
    /// Create a bus whose channel buffers up to `capacity` undelivered events per
    /// subscriber before the slowest subscriber starts lagging.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }
}

#[async_trait]
impl EventBus for InProcessEventBus {
    async fn publish(&self, event: &DomainEvent) -> anyhow::Result<()> {
        // An error here only means there are no subscribers — harmless; the periodic
        // reconcile re-derives the desired state regardless.
        let _ = self.sender.send(event.clone());
        Ok(())
    }

    async fn subscribe(&self, _group: &str) -> anyhow::Result<Box<dyn EventStream>> {
        Ok(Box::new(BroadcastStream {
            rx: self.sender.subscribe(),
        }))
    }
}

/// In-process [`EventStream`] over a `broadcast::Receiver`. A `Lagged` gap is
/// swallowed (logged) and the stream continues — the reconcile loop closes the gap.
struct BroadcastStream {
    rx: broadcast::Receiver<DomainEvent>,
}

#[async_trait]
impl EventStream for BroadcastStream {
    async fn next(&mut self) -> Option<Delivery> {
        loop {
            match self.rx.recv().await {
                Ok(event) => return Some(Delivery { event }),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "event stream lagged; reconcile is the safety net");
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests;
