//! Stripe integration behind a [`StripeGateway`] trait.
//!
//! The trait normalizes the bits of Stripe we use into our own types so the
//! [`SubscriptionService`](crate::subscription::SubscriptionService) (and its tests)
//! never touch `async-stripe` directly. [`StripeClient`] is the production impl over
//! `async-stripe` (rustls runtime); tests use a recording fake. Webhook signatures
//! are verified by `async-stripe`'s `Webhook::construct_event` — the signature *is*
//! the credential, so the ingress endpoint is unauthenticated.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};

use crate::repository::subscription::{Entitlement, SubscriptionStatus};

/// The URL of a created Stripe session (checkout or billing portal), plus the Stripe
/// Customer id when the session surfaced one.
#[derive(Debug, Clone)]
pub struct CheckoutSession {
    pub url: String,
    pub customer_id: Option<String>,
}

/// A normalized Stripe webhook event — only the cases the billing lifecycle cares
/// about; everything else is [`StripeEventKind::Ignored`].
#[derive(Debug, Clone)]
pub struct StripeEvent {
    /// The Stripe event id (webhook idempotency key).
    pub id: String,
    pub kind: StripeEventKind,
}

#[derive(Debug, Clone)]
pub enum StripeEventKind {
    /// `customer.subscription.created` / `.updated` — reconcile our row to this state.
    SubscriptionUpsert(SubscriptionData),
    /// `customer.subscription.deleted` — cancel the matching subscription.
    SubscriptionDeleted { stripe_subscription_id: String },
    /// `invoice.payment_failed` — move the matching subscription to `past_due`.
    PaymentFailed { stripe_subscription_id: String },
    /// Any other event type.
    Ignored,
}

/// The fields we extract from a Stripe `Subscription` object.
#[derive(Debug, Clone)]
pub struct SubscriptionData {
    /// `subscription.metadata.tenant_id` (set on the checkout session).
    pub tenant_id: Option<String>,
    pub stripe_subscription_id: String,
    pub stripe_customer_id: String,
    pub price_id: Option<String>,
    /// Parsed from the purchased price's `max_networks` / `max_daemons` metadata;
    /// `None` when absent/unparseable (the caller then declines to grant).
    pub entitlement: Option<Entitlement>,
    pub status: SubscriptionStatus,
    pub current_period_end: Option<DateTime<Utc>>,
}

/// Normalized access to Stripe. Implemented by [`StripeClient`] in production and a
/// recording fake in tests.
#[async_trait]
pub trait StripeGateway: Send + Sync {
    /// Create a subscription-mode Checkout Session for `price_id`, reusing
    /// `customer_id` when known (else collecting via `email`), and stamping
    /// `tenant_id` into the subscription metadata so the webhook can resolve it.
    async fn create_checkout_session(
        &self,
        customer_id: Option<&str>,
        email: &str,
        price_id: &str,
        tenant_id: &str,
    ) -> anyhow::Result<CheckoutSession>;

    /// Create a Billing Portal session for `customer_id`, returning its URL.
    async fn create_billing_portal_session(&self, customer_id: &str) -> anyhow::Result<String>;

    /// Verify the webhook signature and normalize the event. The signature is the
    /// credential — a bad signature is an error (the handler returns `400`).
    fn construct_event(&self, payload: &[u8], sig_header: &str) -> anyhow::Result<StripeEvent>;
}

/// Production [`StripeGateway`] over `async-stripe`.
pub struct StripeClient {
    client: stripe::Client,
    webhook_secret: String,
    /// Base URL for the account SPA; checkout success/cancel + portal return URLs hang
    /// off it.
    account_base_url: String,
}

impl StripeClient {
    /// Build a client against the real Stripe API.
    #[must_use]
    pub fn new(secret_key: &str, webhook_secret: &str, account_base_url: &str) -> Self {
        Self {
            client: stripe::Client::new(secret_key.to_string()),
            webhook_secret: webhook_secret.to_string(),
            account_base_url: account_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Build a client pointed at `base_url` (the e2e wiremock seam).
    #[must_use]
    pub fn from_url(
        base_url: &str,
        secret_key: &str,
        webhook_secret: &str,
        account_base_url: &str,
    ) -> Self {
        Self {
            client: stripe::Client::from_url(base_url, secret_key.to_string()),
            webhook_secret: webhook_secret.to_string(),
            account_base_url: account_base_url.trim_end_matches('/').to_string(),
        }
    }
}

#[async_trait]
impl StripeGateway for StripeClient {
    async fn create_checkout_session(
        &self,
        customer_id: Option<&str>,
        email: &str,
        price_id: &str,
        tenant_id: &str,
    ) -> anyhow::Result<CheckoutSession> {
        let success_url = format!("{}/billing/success", self.account_base_url);
        let cancel_url = format!("{}/billing/cancel", self.account_base_url);

        let mut params = stripe::CreateCheckoutSession::new();
        params.mode = Some(stripe::CheckoutSessionMode::Subscription);
        params.success_url = Some(&success_url);
        params.cancel_url = Some(&cancel_url);
        params.line_items = Some(vec![stripe::CreateCheckoutSessionLineItems {
            price: Some(price_id.to_string()),
            quantity: Some(1),
            ..Default::default()
        }]);
        // Carry the tenant id into the subscription so the webhook can resolve it.
        let mut metadata = HashMap::new();
        metadata.insert("tenant_id".to_string(), tenant_id.to_string());
        params.subscription_data = Some(stripe::CreateCheckoutSessionSubscriptionData {
            metadata: Some(metadata),
            ..Default::default()
        });
        match customer_id {
            Some(cid) => {
                params.customer = Some(
                    cid.parse()
                        .map_err(|_| anyhow::anyhow!("invalid Stripe customer id"))?,
                );
            }
            None => params.customer_email = Some(email),
        }

        let session = stripe::CheckoutSession::create(&self.client, params).await?;
        let url = session
            .url
            .ok_or_else(|| anyhow::anyhow!("Stripe checkout session has no URL"))?;
        let customer_id = session.customer.map(|c| c.id().to_string());
        Ok(CheckoutSession { url, customer_id })
    }

    async fn create_billing_portal_session(&self, customer_id: &str) -> anyhow::Result<String> {
        let customer = customer_id
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid Stripe customer id"))?;
        let return_url = format!("{}/billing", self.account_base_url);
        let mut params = stripe::CreateBillingPortalSession::new(customer);
        params.return_url = Some(&return_url);
        let session = stripe::BillingPortalSession::create(&self.client, params).await?;
        Ok(session.url)
    }

    fn construct_event(&self, payload: &[u8], sig_header: &str) -> anyhow::Result<StripeEvent> {
        let payload = std::str::from_utf8(payload)
            .map_err(|_| anyhow::anyhow!("webhook payload is not valid UTF-8"))?;
        let event = stripe::Webhook::construct_event(payload, sig_header, &self.webhook_secret)?;
        let id = event.id.to_string();
        let kind = match event.type_ {
            stripe::EventType::CustomerSubscriptionCreated
            | stripe::EventType::CustomerSubscriptionUpdated => match event.data.object {
                stripe::EventObject::Subscription(sub) => {
                    StripeEventKind::SubscriptionUpsert(map_subscription(&sub))
                }
                _ => StripeEventKind::Ignored,
            },
            stripe::EventType::CustomerSubscriptionDeleted => match event.data.object {
                stripe::EventObject::Subscription(sub) => StripeEventKind::SubscriptionDeleted {
                    stripe_subscription_id: sub.id.to_string(),
                },
                _ => StripeEventKind::Ignored,
            },
            stripe::EventType::InvoicePaymentFailed => match event.data.object {
                stripe::EventObject::Invoice(inv) => match inv.subscription {
                    Some(sub) => StripeEventKind::PaymentFailed {
                        stripe_subscription_id: sub.id().to_string(),
                    },
                    None => StripeEventKind::Ignored,
                },
                _ => StripeEventKind::Ignored,
            },
            _ => StripeEventKind::Ignored,
        };
        Ok(StripeEvent { id, kind })
    }
}

/// Extract our [`SubscriptionData`] from a Stripe `Subscription`.
fn map_subscription(sub: &stripe::Subscription) -> SubscriptionData {
    let price = sub.items.data.first().and_then(|item| item.price.as_ref());
    SubscriptionData {
        tenant_id: sub.metadata.get("tenant_id").cloned(),
        stripe_subscription_id: sub.id.to_string(),
        stripe_customer_id: sub.customer.id().to_string(),
        price_id: price.map(|p| p.id.to_string()),
        entitlement: price.and_then(entitlement_from_price),
        status: map_status(sub.status),
        current_period_end: Utc.timestamp_opt(sub.current_period_end, 0).single(),
    }
}

/// Read `{max_networks, max_daemons}` from a price's metadata; `None` if either is
/// missing or unparseable (so the caller declines to grant rather than guess).
fn entitlement_from_price(price: &stripe::Price) -> Option<Entitlement> {
    let metadata = price.metadata.as_ref()?;
    let max_networks = metadata.get("max_networks")?.parse().ok()?;
    let max_daemons = metadata.get("max_daemons")?.parse().ok()?;
    Some(Entitlement {
        max_networks,
        max_daemons,
    })
}

/// Map Stripe's subscription status to ours. Stripe `trialing` (a paid sub in its
/// Stripe-side trial) maps to `Active` — entitling; our *own* card-less trial is a
/// separate `Trialing` row with no Stripe ids.
fn map_status(status: stripe::SubscriptionStatus) -> SubscriptionStatus {
    use stripe::SubscriptionStatus as S;
    match status {
        S::Active | S::Trialing => SubscriptionStatus::Active,
        S::PastDue | S::Unpaid => SubscriptionStatus::PastDue,
        S::Canceled | S::Incomplete | S::IncompleteExpired | S::Paused => {
            SubscriptionStatus::Canceled
        }
    }
}
