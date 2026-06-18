//! In-process domain-event bus for cross-aggregate decoupling.
//!
//! Services **raise domain events; others react.** A service never reaches into
//! another aggregate's repository to drive a side-effect — instead it publishes a
//! [`DomainEvent`] and a long-running *reactor* (subscribed to the bus) calls the
//! owning service's method. Reads stay direct (a service method call); only
//! write-side side-effects flow as events.
//!
//! The transport is a best-effort [`tokio::sync::broadcast`] channel: a slow or
//! absent subscriber may miss an event, so **reactors must be idempotent** and a
//! periodic reconcile (owned by the repo-owning service) closes any gap. Events are
//! the fast path; reconciliation is the guarantee. This mirrors the daemon's
//! `wardnet_common::event` design.

use tokio::sync::broadcast;

/// A cross-aggregate domain event. Cloneable so it can fan out over the broadcast
/// channel to every subscriber.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainEvent {
    /// A tenant account was created. The subscription aggregate reacts by creating
    /// the tenant's free **trial** subscription.
    TenantCreated { tenant_id: String },
    /// A tenant account was deregistered (tombstoned). The subscription aggregate
    /// reacts by **cancelling** the tenant's current subscription.
    TenantDeregistered { tenant_id: String },
    /// A tenant's subscription became inactive (cancelled, or lapsed past its
    /// grace). The tenants aggregate reacts by **deprovisioning** the tenant's
    /// networks.
    SubscriptionDeactivated { tenant_id: String },
}

/// Abstraction over domain-event publishing and subscribing.
///
/// A trait so services can take an `Arc<dyn EventPublisher>` and tests can assert
/// "event X was raised" with a recording fake instead of a live channel.
pub trait EventPublisher: Send + Sync {
    /// Publish a domain event to all current subscribers.
    fn publish(&self, event: DomainEvent);

    /// Create a new subscriber that receives events published from now on.
    fn subscribe(&self) -> broadcast::Receiver<DomainEvent>;
}

/// Default [`EventPublisher`] backed by [`tokio::sync::broadcast`].
///
/// Clone-friendly — wraps a `broadcast::Sender`, which is `Clone`. A send with no
/// live subscribers is a no-op (the reconcile loop is the safety net), so publishing
/// never blocks and never fails the caller.
#[derive(Debug, Clone)]
pub struct BroadcastEventBus {
    sender: broadcast::Sender<DomainEvent>,
}

impl BroadcastEventBus {
    /// Create a bus whose channel buffers up to `capacity` undelivered events per
    /// subscriber before the slowest subscriber starts lagging.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }
}

impl EventPublisher for BroadcastEventBus {
    fn publish(&self, event: DomainEvent) {
        // An error here only means there are no subscribers — harmless; the periodic
        // reconcile re-derives the desired state regardless.
        let _ = self.sender.send(event);
    }

    fn subscribe(&self) -> broadcast::Receiver<DomainEvent> {
        self.sender.subscribe()
    }
}

#[cfg(test)]
mod tests;
