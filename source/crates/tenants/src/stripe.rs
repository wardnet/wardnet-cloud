//! Stripe integration behind a [`StripeGateway`] trait.
//!
//! The trait normalizes the bits of Stripe we use into our own types so the
//! [`SubscriptionService`](crate::subscription::SubscriptionService) (and its tests)
//! never touch Stripe's wire format directly. [`StripeClient`] is the production impl
//! — a hand-rolled `reqwest` client against the Stripe REST API (the same pattern we
//! use for GitHub `OAuth2`); tests use a recording fake. Webhook signatures are
//! verified in-process ([`verify_signature`]) — the signature *is* the credential, so
//! the ingress endpoint is unauthenticated.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac, digest::KeyInit};
use serde::Deserialize;
use sha2::Sha256;

use crate::repository::subscription::{Entitlement, SubscriptionStatus};

/// Stripe's webhook signatures are HMAC-SHA256.
type HmacSha256 = Hmac<Sha256>;

/// Tolerance for the `t=` timestamp in the `Stripe-Signature` header (±5 min), to
/// bound replay of a captured-but-valid signature. Matches Stripe's own default.
const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// The production Stripe API base. Overridable via [`StripeClient::from_url`] (the e2e
/// wiremock seam).
const STRIPE_API_BASE: &str = "https://api.stripe.com";

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

/// Production [`StripeGateway`] — a hand-rolled `reqwest` client over the Stripe REST
/// API.
pub struct StripeClient {
    http: reqwest::Client,
    /// Stripe REST API base (no trailing slash); `STRIPE_API_BASE` in production.
    api_base: String,
    secret_key: String,
    webhook_secret: String,
    /// Base URL for the account SPA; checkout success/cancel + portal return URLs hang
    /// off it.
    account_base_url: String,
}

impl StripeClient {
    /// Build a client against the real Stripe API.
    ///
    /// # Panics
    /// Panics only if the `reqwest` client cannot be constructed (no rustls backend),
    /// which is a build/environment misconfiguration, not a runtime condition.
    #[must_use]
    pub fn new(secret_key: &str, webhook_secret: &str, account_base_url: &str) -> Self {
        Self::with_base(
            STRIPE_API_BASE,
            secret_key,
            webhook_secret,
            account_base_url,
        )
    }

    /// Build a client pointed at `base_url` (the e2e wiremock seam).
    ///
    /// # Panics
    /// See [`StripeClient::new`].
    #[must_use]
    pub fn from_url(
        base_url: &str,
        secret_key: &str,
        webhook_secret: &str,
        account_base_url: &str,
    ) -> Self {
        Self::with_base(base_url, secret_key, webhook_secret, account_base_url)
    }

    fn with_base(
        base_url: &str,
        secret_key: &str,
        webhook_secret: &str,
        account_base_url: &str,
    ) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("wardnet-cloud")
            // The Stripe API never legitimately 3xx-redirects these POSTs; never
            // follow a redirect with the bearer key attached (matches the GitHub
            // OAuth2 client in `identities::provider`).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client builds with the rustls backend");
        Self {
            http,
            api_base: base_url.trim_end_matches('/').to_string(),
            secret_key: secret_key.to_string(),
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

        // Stripe takes nested params as bracketed form keys (`a[b][c]=v`).
        let mut form: Vec<(String, String)> = vec![
            ("mode".into(), "subscription".into()),
            ("success_url".into(), success_url),
            ("cancel_url".into(), cancel_url),
            ("line_items[0][price]".into(), price_id.to_string()),
            ("line_items[0][quantity]".into(), "1".into()),
            // Carry the tenant id into the subscription so the webhook can resolve it.
            (
                "subscription_data[metadata][tenant_id]".into(),
                tenant_id.to_string(),
            ),
        ];
        match customer_id {
            Some(cid) => form.push(("customer".into(), cid.to_string())),
            None => form.push(("customer_email".into(), email.to_string())),
        }

        let session: SessionResponse = self.post_form("/v1/checkout/sessions", &form).await?;
        let url = session
            .url
            .ok_or_else(|| anyhow::anyhow!("Stripe checkout session has no URL"))?;
        Ok(CheckoutSession {
            url,
            customer_id: session.customer.map(Expandable::into_id),
        })
    }

    async fn create_billing_portal_session(&self, customer_id: &str) -> anyhow::Result<String> {
        let return_url = format!("{}/billing", self.account_base_url);
        let form = [
            ("customer", customer_id),
            ("return_url", return_url.as_str()),
        ];
        let session: SessionResponse = self.post_form("/v1/billing_portal/sessions", &form).await?;
        session
            .url
            .ok_or_else(|| anyhow::anyhow!("Stripe billing portal session has no URL"))
    }

    fn construct_event(&self, payload: &[u8], sig_header: &str) -> anyhow::Result<StripeEvent> {
        verify_signature(
            payload,
            sig_header,
            &self.webhook_secret,
            Utc::now().timestamp(),
        )?;
        let event: WebhookEvent = serde_json::from_slice(payload)
            .map_err(|e| anyhow::anyhow!("malformed Stripe webhook payload: {e}"))?;
        normalize_event(event)
    }
}

impl StripeClient {
    /// POST a form-encoded body to `path` with the Bearer secret key and decode the
    /// JSON response, surfacing a non-2xx as an error.
    ///
    /// On failure the error carries only the HTTP status and Stripe's machine-readable
    /// error `type`/`code` — **never the raw response body**, which can echo customer
    /// email / ids (PII) and would leak into logs (invariant #9).
    async fn post_form<T: serde::Serialize + ?Sized, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        form: &T,
    ) -> anyhow::Result<R> {
        let resp = self
            .http
            .post(format!("{}{path}", self.api_base))
            .bearer_auth(&self.secret_key)
            .form(form)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            // Parse out Stripe's safe error type/code; fall back to the status alone.
            let detail = serde_json::from_str::<StripeErrorEnvelope>(&body)
                .ok()
                .map_or_else(String::new, |e| e.error.describe());
            anyhow::bail!("Stripe {path} returned {status}{detail}");
        }
        serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("malformed Stripe response from {path}: {e}"))
    }
}

/// Verify a `Stripe-Signature` header against `payload` using the webhook signing
/// `secret`. `now` is the current unix time (injected for testability).
///
/// The scheme: the header is `t=<unix>,v1=<hex>,…`; the signed payload is
/// `"{t}.{payload}"` and each `v1` is its HMAC-SHA256 under `secret`. We require at
/// least one `v1` to match (constant-time compare) **and** `t` to be within
/// [`SIGNATURE_TOLERANCE_SECS`] of `now` (replay bound).
///
/// # Errors
/// Returns an error if the header is malformed, no signature matches, or the timestamp
/// is outside the tolerance.
fn verify_signature(
    payload: &[u8],
    sig_header: &str,
    secret: &str,
    now: i64,
) -> anyhow::Result<()> {
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<&str> = Vec::new();
    for part in sig_header.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        match key.trim() {
            "t" => timestamp = value.trim().parse().ok(),
            "v1" => signatures.push(value.trim()),
            _ => {}
        }
    }
    let timestamp = timestamp
        .ok_or_else(|| anyhow::anyhow!("Stripe-Signature header has no valid timestamp"))?;
    if signatures.is_empty() {
        anyhow::bail!("Stripe-Signature header has no v1 signature");
    }

    // HMAC-SHA256 over "{t}.{payload}".
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);

    // Constant-time compare against each provided v1 (decode hex first). `verify_slice`
    // does the comparison in constant time via the vetted `hmac` primitive; a fresh
    // clone per candidate keeps the unfinalized MAC reusable.
    let matched = signatures.iter().any(|sig| {
        hex::decode(sig)
            .ok()
            .is_some_and(|bytes| mac.clone().verify_slice(&bytes).is_ok())
    });
    if !matched {
        anyhow::bail!("no Stripe webhook signature matched");
    }

    // `saturating_sub` so an attacker-supplied extreme `t=` (only reachable with a
    // valid HMAC) can't overflow `i64` here.
    if now.saturating_sub(timestamp).saturating_abs() > SIGNATURE_TOLERANCE_SECS {
        anyhow::bail!("Stripe webhook timestamp outside tolerance");
    }
    Ok(())
}

/// Map a parsed Stripe webhook event to our normalized [`StripeEvent`].
///
/// A deserialization failure of a *handled* event's object is an **error**, not a
/// silent [`StripeEventKind::Ignored`]: `construct_event` propagates it, the webhook
/// handler returns a non-2xx, and Stripe redelivers (the failure is visible and
/// retried). `Ignored` is reserved for event *types* we genuinely don't handle (and the
/// one real "nothing to do" case: a failed invoice with no associated subscription) —
/// never for "we couldn't parse a type we do handle", which the idempotency ledger would
/// otherwise record as permanently processed.
fn normalize_event(event: WebhookEvent) -> anyhow::Result<StripeEvent> {
    let kind = match event.event_type.as_str() {
        "customer.subscription.created" | "customer.subscription.updated" => {
            let sub: StripeSubscription = parse_object(event.data.object, &event.event_type)?;
            StripeEventKind::SubscriptionUpsert(map_subscription(&sub))
        }
        "customer.subscription.deleted" => {
            let sub: StripeSubscription = parse_object(event.data.object, &event.event_type)?;
            StripeEventKind::SubscriptionDeleted {
                stripe_subscription_id: sub.id,
            }
        }
        "invoice.payment_failed" => {
            let invoice: StripeInvoice = parse_object(event.data.object, &event.event_type)?;
            match invoice.subscription_id() {
                Some(id) => StripeEventKind::PaymentFailed {
                    stripe_subscription_id: id,
                },
                // A failed *one-off* invoice (no subscription) is a real, ignorable case.
                None => StripeEventKind::Ignored,
            }
        }
        _ => StripeEventKind::Ignored,
    };
    Ok(StripeEvent { id: event.id, kind })
}

/// Deserialize a webhook `data.object`, turning a parse failure into a descriptive
/// error (so the handler retries) rather than a silent drop.
fn parse_object<T: serde::de::DeserializeOwned>(
    object: serde_json::Value,
    event_type: &str,
) -> anyhow::Result<T> {
    serde_json::from_value(object)
        .map_err(|e| anyhow::anyhow!("malformed Stripe {event_type} object: {e}"))
}

/// Extract our [`SubscriptionData`] from a Stripe `Subscription`.
fn map_subscription(sub: &StripeSubscription) -> SubscriptionData {
    let first_item = sub.items.data.first();
    let price = first_item.and_then(|item| item.price.as_ref());
    // `current_period_end` was a top-level field until Stripe API 2025-03-31, which moved
    // it onto each subscription item. Read whichever the account's API version sends.
    let period_end = sub
        .current_period_end
        .or_else(|| first_item.and_then(|item| item.current_period_end));
    SubscriptionData {
        tenant_id: sub.metadata.get("tenant_id").cloned(),
        stripe_subscription_id: sub.id.clone(),
        stripe_customer_id: sub.customer.clone().into_id(),
        price_id: price.map(|p| p.id.clone()),
        entitlement: price.and_then(entitlement_from_price),
        status: map_status(&sub.status),
        current_period_end: period_end.and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
    }
}

/// Read `{max_networks, max_daemons}` from a price's metadata; `None` if either is
/// missing or unparseable (so the caller declines to grant rather than guess).
fn entitlement_from_price(price: &StripePrice) -> Option<Entitlement> {
    let max_networks = price.metadata.get("max_networks")?.parse().ok()?;
    let max_daemons = price.metadata.get("max_daemons")?.parse().ok()?;
    Some(Entitlement {
        max_networks,
        max_daemons,
    })
}

/// Map Stripe's subscription status string to ours. Stripe `trialing` (a paid sub in
/// its Stripe-side trial) maps to `Active` — entitling; our *own* card-less trial is a
/// separate `Trialing` row with no Stripe ids. Any unknown status is **safe-closed** to
/// `Canceled` (invariant #22 — an unknown billing state must not grant service).
fn map_status(status: &str) -> SubscriptionStatus {
    match status {
        "active" | "trialing" => SubscriptionStatus::Active,
        "past_due" | "unpaid" => SubscriptionStatus::PastDue,
        _ => SubscriptionStatus::Canceled,
    }
}

// ── Stripe wire types (only the fields we read) ─────────────────────────────────

/// `checkout.Session` / `billing_portal.Session` response — both surface a `url`; the
/// checkout session also surfaces the (expandable) `customer`.
#[derive(Deserialize)]
struct SessionResponse {
    url: Option<String>,
    #[serde(default)]
    customer: Option<Expandable>,
}

#[derive(Deserialize)]
struct WebhookEvent {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    data: WebhookData,
}

#[derive(Deserialize)]
struct WebhookData {
    object: serde_json::Value,
}

#[derive(Deserialize)]
struct StripeSubscription {
    id: String,
    customer: Expandable,
    status: String,
    /// Present at the top level only up to Stripe API 2025-03-31; see [`map_subscription`].
    #[serde(default)]
    current_period_end: Option<i64>,
    #[serde(default)]
    metadata: HashMap<String, String>,
    #[serde(default)]
    items: StripeSubscriptionItems,
}

#[derive(Deserialize, Default)]
struct StripeSubscriptionItems {
    #[serde(default)]
    data: Vec<StripeSubscriptionItem>,
}

#[derive(Deserialize)]
struct StripeSubscriptionItem {
    #[serde(default)]
    price: Option<StripePrice>,
    /// Where `current_period_end` lives on Stripe API 2025-03-31+.
    #[serde(default)]
    current_period_end: Option<i64>,
}

#[derive(Deserialize)]
struct StripePrice {
    id: String,
    #[serde(default)]
    metadata: HashMap<String, String>,
}

#[derive(Deserialize)]
struct StripeInvoice {
    /// The subscription ref was a top-level field until Stripe API 2025-03-31, which
    /// relocated it under `parent.subscription_details`.
    #[serde(default)]
    subscription: Option<Expandable>,
    #[serde(default)]
    parent: Option<InvoiceParent>,
}

impl StripeInvoice {
    /// The associated subscription id, from whichever location the account's API
    /// version uses; `None` for a one-off invoice with no subscription.
    fn subscription_id(self) -> Option<String> {
        self.subscription
            .or_else(|| {
                self.parent
                    .and_then(|p| p.subscription_details)
                    .and_then(|d| d.subscription)
            })
            .map(Expandable::into_id)
    }
}

#[derive(Deserialize)]
struct InvoiceParent {
    #[serde(default)]
    subscription_details: Option<InvoiceSubscriptionDetails>,
}

#[derive(Deserialize)]
struct InvoiceSubscriptionDetails {
    #[serde(default)]
    subscription: Option<Expandable>,
}

/// Stripe's error response envelope (`{"error": {...}}`). We surface only the
/// machine-readable `type`/`code` in errors — never the free-text `message` or the raw
/// body, which can carry customer PII (invariant #9).
#[derive(Deserialize)]
struct StripeErrorEnvelope {
    error: StripeApiError,
}

#[derive(Deserialize)]
struct StripeApiError {
    #[serde(default, rename = "type")]
    error_type: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

impl StripeApiError {
    /// A safe-to-log `" (type=…, code=…)"` suffix, or empty when neither is present.
    fn describe(&self) -> String {
        match (&self.error_type, &self.code) {
            (None, None) => String::new(),
            (t, c) => format!(
                " (type={}, code={})",
                t.as_deref().unwrap_or("?"),
                c.as_deref().unwrap_or("?")
            ),
        }
    }
}

/// A Stripe "expandable" reference: either the bare id string, or — if the request
/// expanded it — the full object (from which we take `id`). We never expand, so the
/// string arm is the live path; the object arm is defensive.
#[derive(Deserialize, Clone)]
#[serde(untagged)]
enum Expandable {
    Id(String),
    Object { id: String },
}

impl Expandable {
    fn into_id(self) -> String {
        match self {
            Expandable::Id(id) | Expandable::Object { id } => id,
        }
    }
}

#[cfg(test)]
mod tests;
