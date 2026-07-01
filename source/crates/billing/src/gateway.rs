//! Stripe integration behind a [`StripeGateway`] trait (the `PaymentProvider` port).
//!
//! The trait normalizes the bits of Stripe we use into our own types so
//! [`BillingService`](crate::service::BillingService) (and its tests) never touch
//! Stripe's wire format directly. [`StripeClient`] is the production impl — a
//! hand-rolled `reqwest` client against the Stripe REST API (the same pattern we use
//! for GitHub `OAuth2`); tests use a recording fake. Webhook signatures are verified
//! in-process ([`verify_signature`]) — the signature *is* the credential, so the
//! ingress endpoint is unauthenticated.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac, digest::KeyInit};
use serde::Deserialize;
use sha2::Sha256;

use wardnet_common::contract::{
    Entitlement, InvoiceStatus, InvoiceView, PaymentMethodView, SubscriptionStatus,
};

/// Stripe's webhook signatures are HMAC-SHA256.
type HmacSha256 = Hmac<Sha256>;

/// Tolerance for the `t=` timestamp in the `Stripe-Signature` header (±5 min), to
/// bound replay of a captured-but-valid signature. Matches Stripe's own default.
const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// The production Stripe API base. Overridable via [`StripeClient::from_url`] (the e2e
/// wiremock seam).
const STRIPE_API_BASE: &str = "https://api.stripe.com";

/// How many invoices the history endpoint pulls (newest first). A bounded page keeps the
/// account-page table small; Stripe's max is 100.
const INVOICE_PAGE_LIMIT: &str = "24";

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
    /// `checkout.session.completed` for a **`setup`-mode** session — the user added/replaced
    /// a card. The new payment method must be promoted to the customer's (and its
    /// subscription's) default, or renewals keep charging the old card.
    CardSetupCompleted {
        stripe_customer_id: String,
        setup_intent_id: String,
    },
    /// A catalog object changed in Stripe (`price.*` / `product.*` / `coupon.*` /
    /// `promotion_code.*`) — trigger a projection resync. The event carries no data we
    /// need (we re-list the whole catalog), so it is a unit variant.
    CatalogChanged,
    /// Any other event type.
    Ignored,
}

/// One purchasable plan as read from Stripe's price catalog (the pre-projection shape).
/// `level` / `entitlement` are `Option` so an ill-formed price is dropped by the sync
/// (safe-closed) rather than failing the whole list.
#[derive(Debug, Clone)]
pub struct PlanData {
    pub price_id: String,
    pub product_id: String,
    pub name: String,
    pub level: Option<u32>,
    pub entitlement: Option<Entitlement>,
    pub amount_cents: i64,
    pub currency: String,
    pub interval: String,
    pub active: bool,
}

/// One promotion (Stripe coupon) as read from the catalog. The active window is
/// `[start, redeem_by]`; `auto_apply` gates whether it participates in the auto-applied
/// catalog at all.
#[derive(Debug, Clone)]
pub struct PromotionData {
    pub coupon_id: String,
    pub name: String,
    pub percent_off: Option<f64>,
    pub amount_off: Option<i64>,
    pub currency: Option<String>,
    pub applies_to_products: Vec<String>,
    pub start: Option<DateTime<Utc>>,
    pub redeem_by: Option<DateTime<Utc>>,
    pub auto_apply: bool,
}

/// Live details of a Stripe subscription needed to change its plan.
#[derive(Debug, Clone)]
pub struct SubscriptionDetails {
    /// The (single) subscription item id — the target of a price swap.
    pub item_id: String,
    /// The price the subscription is currently billed at.
    pub price_id: String,
    /// End of the current paid period — when a scheduled downgrade takes effect.
    pub current_period_end: DateTime<Utc>,
    /// The attached subscription schedule id, if any (a pending change exists).
    pub schedule_id: Option<String>,
    /// Whether the subscription is still in its Stripe trial (a trial-preserving sub,
    /// ADR-0012). An upgrade of such a sub must end the trial so it charges now.
    pub trialing: bool,
}

/// A pending scheduled plan change read from a subscription schedule's future phase.
#[derive(Debug, Clone)]
pub struct ScheduledChange {
    pub price_id: String,
    pub effective_at: DateTime<Utc>,
}

/// Marker error: Stripe rejected an applied coupon (expired / invalid / exhausted). The
/// billing service downcasts the `anyhow::Error` to this to surface
/// [`BillingError::PromoUnavailable`](wardnet_common::ports::BillingError::PromoUnavailable)
/// and offer a full-price retry, rather than silently charging full price.
#[derive(Debug, thiserror::Error)]
#[error("stripe rejected the applied coupon")]
pub struct CouponRejected;

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
    /// When `coupon` is `Some`, it is auto-applied (`discounts[0][coupon]`); a Stripe
    /// rejection of the coupon surfaces as a [`CouponRejected`] error.
    /// When `trial_end` is `Some` (a future unix timestamp), the subscription is created
    /// with `subscription_data[trial_end]` so the first charge defers to that date — the
    /// trial-preserving subscribe of ADR-0012.
    async fn create_checkout_session(
        &self,
        customer_id: Option<&str>,
        email: &str,
        price_id: &str,
        tenant_id: &str,
        coupon: Option<&str>,
        trial_end: Option<i64>,
    ) -> anyhow::Result<CheckoutSession>;

    /// Create a `setup`-mode Checkout Session for `customer_id` (collect/replace a card,
    /// no purchase), returning its URL. Replaces the removed Billing Portal card-update.
    /// `currency` is required by Stripe for setup mode (no line items to infer it from) and
    /// should match the customer's subscription currency.
    async fn create_setup_checkout_session(
        &self,
        customer_id: &str,
        currency: &str,
    ) -> anyhow::Result<String>;

    /// List the purchasable plans from Stripe (active recurring prices + their products).
    /// The sync worker filters/validates these into the projection.
    async fn list_plans(&self) -> anyhow::Result<Vec<PlanData>>;

    /// List the promotions (coupons) from Stripe. The sync worker keeps only the
    /// `auto_apply` ones.
    async fn list_promotions(&self) -> anyhow::Result<Vec<PromotionData>>;

    /// Read the live details of a subscription needed to change its plan (item id,
    /// current price, period end, attached schedule).
    async fn get_subscription(&self, subscription_id: &str) -> anyhow::Result<SubscriptionDetails>;

    /// The pending scheduled change (a schedule's future phase), or `None`. Used for the
    /// account-page "downgrades on DATE" surface. Takes the `schedule_id` and
    /// `current_period_end` the caller already has from [`get_subscription`](Self::get_subscription)
    /// so it need not re-fetch the subscription.
    async fn pending_scheduled_change(
        &self,
        schedule_id: &str,
        current_period_end: DateTime<Utc>,
    ) -> anyhow::Result<Option<ScheduledChange>>;

    /// Apply an **immediate** price change (an upgrade) to `subscription_id`'s item,
    /// prorating onto the next invoice. When `coupon` is `Some` it is applied; a Stripe
    /// rejection of the coupon surfaces as a [`CouponRejected`] error. When `end_trial` is
    /// true (upgrading a subscription still in its Stripe trial) the trial is ended now so
    /// the upgrade charges immediately (ADR-0012).
    async fn upgrade_subscription(
        &self,
        subscription_id: &str,
        item_id: &str,
        new_price_id: &str,
        coupon: Option<&str>,
        end_trial: bool,
    ) -> anyhow::Result<()>;

    /// Schedule a **downgrade** of `subscription_id` to `new_price_id` taking effect at
    /// `current_period_end` (a Stripe subscription schedule; the tenant keeps the current
    /// entitlement until then). Returns the effective time. `current_price_id` seeds the
    /// preserved current phase.
    async fn schedule_downgrade(
        &self,
        subscription_id: &str,
        current_price_id: &str,
        new_price_id: &str,
        current_period_end: DateTime<Utc>,
    ) -> anyhow::Result<DateTime<Utc>>;

    /// Release the subscription schedule `schedule_id` (cancel a pending change),
    /// returning the subscription to plain billing. Idempotent from the caller's view.
    async fn release_schedule(&self, schedule_id: &str) -> anyhow::Result<()>;

    /// Promote the card collected by a completed setup-mode Checkout to the default:
    /// resolve the `setup_intent`'s payment method, set it as `customer_id`'s
    /// `invoice_settings.default_payment_method`, and — when `subscription_id` is given —
    /// as that subscription's `default_payment_method` (so the next renewal uses the new
    /// card, not the old one).
    async fn set_default_payment_method_from_setup(
        &self,
        customer_id: &str,
        subscription_id: Option<&str>,
        setup_intent_id: &str,
    ) -> anyhow::Result<()>;

    /// Verify the webhook signature and normalize the event. The signature is the
    /// credential — a bad signature is an error (the handler returns `400`).
    fn construct_event(&self, payload: &[u8], sig_header: &str) -> anyhow::Result<StripeEvent>;

    /// Retrieve `customer_id`'s default payment method as a provider-agnostic summary,
    /// or `None` when the customer has none on file. A **read** — never PAN/CVC, only the
    /// brand/last4/expiry (SAQ-A safe).
    async fn default_payment_method(
        &self,
        customer_id: &str,
    ) -> anyhow::Result<Option<PaymentMethodView>>;

    /// List `customer_id`'s recent invoices, newest first, as provider-agnostic rows.
    async fn list_invoices(&self, customer_id: &str) -> anyhow::Result<Vec<InvoiceView>>;
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
        coupon: Option<&str>,
        trial_end: Option<i64>,
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
        // Auto-apply the promotion (the user never passes a code; we re-derive server-side).
        if let Some(c) = coupon {
            form.push(("discounts[0][coupon]".into(), c.to_string()));
        }
        // Trial-preserving subscribe (ADR-0012): defer the first charge to the tenant's
        // original trial end. Stripe keeps the subscription `trialing` (entitling, no
        // charge) until then.
        if let Some(ts) = trial_end {
            form.push(("subscription_data[trial_end]".into(), ts.to_string()));
        }

        let session: SessionResponse = self
            .post_form_coupon_aware("/v1/checkout/sessions", &form, coupon.is_some())
            .await?;
        let url = session
            .url
            .ok_or_else(|| anyhow::anyhow!("Stripe checkout session has no URL"))?;
        Ok(CheckoutSession {
            url,
            customer_id: session.customer.map(Expandable::into_id),
        })
    }

    async fn create_setup_checkout_session(
        &self,
        customer_id: &str,
        currency: &str,
    ) -> anyhow::Result<String> {
        let success_url = format!("{}/billing/success", self.account_base_url);
        let cancel_url = format!("{}/billing", self.account_base_url);
        let form = [
            ("mode", "setup"),
            ("customer", customer_id),
            // Setup mode has no line items to infer the currency from, so Stripe requires
            // it explicitly (a 400 `parameter_missing` otherwise) — matched to the plan.
            ("currency", currency),
            ("success_url", success_url.as_str()),
            ("cancel_url", cancel_url.as_str()),
        ];
        let session: SessionResponse = self.post_form("/v1/checkout/sessions", &form).await?;
        session
            .url
            .ok_or_else(|| anyhow::anyhow!("Stripe setup session has no URL"))
    }

    async fn list_plans(&self) -> anyhow::Result<Vec<PlanData>> {
        // Active recurring prices with their product expanded — one call gives id, amount,
        // currency, interval, metadata, and the product name.
        let page: StripeList<StripePriceFull> = self
            .get_json(
                "/v1/prices",
                &[
                    ("active", "true"),
                    ("type", "recurring"),
                    ("limit", "100"),
                    ("expand[]", "data.product"),
                ],
            )
            .await?;
        Ok(page.data.into_iter().filter_map(map_plan).collect())
    }

    async fn list_promotions(&self) -> anyhow::Result<Vec<PromotionData>> {
        let page: StripeList<StripeCoupon> =
            self.get_json("/v1/coupons", &[("limit", "100")]).await?;
        Ok(page.data.into_iter().map(map_coupon).collect())
    }

    async fn get_subscription(&self, subscription_id: &str) -> anyhow::Result<SubscriptionDetails> {
        let sub: StripeSubscription = self
            .get_json(
                &format!("/v1/subscriptions/{subscription_id}"),
                &[("expand[]", "schedule")],
            )
            .await?;
        let item = sub
            .items
            .data
            .first()
            .ok_or_else(|| anyhow::anyhow!("Stripe subscription has no items"))?;
        let item_id = item
            .id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Stripe subscription item has no id"))?;
        let price_id = item
            .price
            .as_ref()
            .map(|p| p.id.clone())
            .ok_or_else(|| anyhow::anyhow!("Stripe subscription item has no price"))?;
        let period_end_ts = sub
            .current_period_end
            .or(item.current_period_end)
            .ok_or_else(|| anyhow::anyhow!("Stripe subscription has no current_period_end"))?;
        let current_period_end = Utc
            .timestamp_opt(period_end_ts, 0)
            .single()
            .ok_or_else(|| anyhow::anyhow!("invalid current_period_end timestamp"))?;
        Ok(SubscriptionDetails {
            item_id,
            price_id,
            current_period_end,
            schedule_id: sub.schedule.map(Expandable::into_id),
            trialing: sub.status == "trialing",
        })
    }

    async fn pending_scheduled_change(
        &self,
        schedule_id: &str,
        current_period_end: DateTime<Utc>,
    ) -> anyhow::Result<Option<ScheduledChange>> {
        let schedule: StripeSubscriptionSchedule = self
            .get_json(&format!("/v1/subscription_schedules/{schedule_id}"), &[])
            .await?;
        // The future phase is the one whose start is at/after the current period end.
        let cutoff = current_period_end.timestamp();
        let future = schedule
            .phases
            .into_iter()
            .find(|p| p.start_date.is_some_and(|s| s >= cutoff));
        Ok(future.and_then(|phase| {
            let price_id = phase.items.first().and_then(|i| i.price.clone())?;
            let effective_at = phase
                .start_date
                .and_then(|s| Utc.timestamp_opt(s, 0).single())?;
            Some(ScheduledChange {
                price_id,
                effective_at,
            })
        }))
    }

    async fn upgrade_subscription(
        &self,
        subscription_id: &str,
        item_id: &str,
        new_price_id: &str,
        coupon: Option<&str>,
        end_trial: bool,
    ) -> anyhow::Result<()> {
        let mut form: Vec<(String, String)> = vec![
            ("items[0][id]".into(), item_id.to_string()),
            ("items[0][price]".into(), new_price_id.to_string()),
            ("proration_behavior".into(), "create_prorations".into()),
        ];
        if let Some(c) = coupon {
            form.push(("discounts[0][coupon]".into(), c.to_string()));
        }
        // Ending the trial now makes the upgrade bill immediately (ADR-0012).
        if end_trial {
            form.push(("trial_end".into(), "now".into()));
        }
        let _: serde_json::Value = self
            .post_form_coupon_aware(
                &format!("/v1/subscriptions/{subscription_id}"),
                &form,
                coupon.is_some(),
            )
            .await?;
        Ok(())
    }

    async fn schedule_downgrade(
        &self,
        subscription_id: &str,
        current_price_id: &str,
        new_price_id: &str,
        current_period_end: DateTime<Utc>,
    ) -> anyhow::Result<DateTime<Utc>> {
        // 1. Wrap the subscription in a schedule (seeds phase[0] from the live sub).
        let created: StripeSubscriptionSchedule = self
            .post_form(
                "/v1/subscription_schedules",
                &[("from_subscription", subscription_id)],
            )
            .await?;
        let phase0_start = created
            .phases
            .first()
            .and_then(|p| p.start_date)
            .ok_or_else(|| anyhow::anyhow!("Stripe schedule has no seeded phase"))?;
        let boundary = current_period_end.timestamp();

        // 2. Replace phases: keep the current price until the period end, then the new one.
        //    `proration_behavior=none` (no credit/charge at the boundary) and
        //    `end_behavior=release` (return to plain billing after the new phase).
        let form: Vec<(String, String)> = vec![
            ("end_behavior".into(), "release".into()),
            ("proration_behavior".into(), "none".into()),
            (
                "phases[0][items][0][price]".into(),
                current_price_id.to_string(),
            ),
            ("phases[0][start_date]".into(), phase0_start.to_string()),
            ("phases[0][end_date]".into(), boundary.to_string()),
            (
                "phases[1][items][0][price]".into(),
                new_price_id.to_string(),
            ),
            ("phases[1][start_date]".into(), boundary.to_string()),
        ];
        let _: serde_json::Value = self
            .post_form(&format!("/v1/subscription_schedules/{}", created.id), &form)
            .await?;
        Ok(current_period_end)
    }

    async fn release_schedule(&self, schedule_id: &str) -> anyhow::Result<()> {
        let _: serde_json::Value = self
            .post_form::<[(&str, &str)], _>(
                &format!("/v1/subscription_schedules/{schedule_id}/release"),
                &[],
            )
            .await?;
        Ok(())
    }

    async fn set_default_payment_method_from_setup(
        &self,
        customer_id: &str,
        subscription_id: Option<&str>,
        setup_intent_id: &str,
    ) -> anyhow::Result<()> {
        // 1. Resolve the payment method the setup session collected.
        let setup: StripeSetupIntent = self
            .get_json(&format!("/v1/setup_intents/{setup_intent_id}"), &[])
            .await?;
        let payment_method = setup
            .payment_method
            .map(Expandable::into_id)
            .ok_or_else(|| anyhow::anyhow!("setup intent has no payment method"))?;
        // 2. Make it the customer's default for future invoices.
        let _: serde_json::Value = self
            .post_form(
                &format!("/v1/customers/{customer_id}"),
                &[(
                    "invoice_settings[default_payment_method]",
                    payment_method.as_str(),
                )],
            )
            .await?;
        // 3. And the subscription's own default (Stripe prefers it over the customer's).
        if let Some(sub_id) = subscription_id {
            let _: serde_json::Value = self
                .post_form(
                    &format!("/v1/subscriptions/{sub_id}"),
                    &[("default_payment_method", payment_method.as_str())],
                )
                .await?;
        }
        Ok(())
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

    async fn default_payment_method(
        &self,
        customer_id: &str,
    ) -> anyhow::Result<Option<PaymentMethodView>> {
        // Retrieve the customer with the default payment method expanded — one call gets
        // both the pointer (`invoice_settings.default_payment_method`) and the card fields.
        let customer: StripeCustomer = self
            .get_json(
                &format!("/v1/customers/{customer_id}"),
                &[("expand[]", "invoice_settings.default_payment_method")],
            )
            .await?;
        Ok(customer
            .invoice_settings
            .and_then(|s| s.default_payment_method)
            .and_then(|pm| pm.card)
            .map(|card| PaymentMethodView {
                brand: card.brand,
                last4: card.last4,
                exp_month: card.exp_month,
                exp_year: card.exp_year,
            }))
    }

    async fn list_invoices(&self, customer_id: &str) -> anyhow::Result<Vec<InvoiceView>> {
        // Stripe returns invoices newest first; cap the page so the history table is bounded.
        let page: StripeList<StripeInvoiceRow> = self
            .get_json(
                "/v1/invoices",
                &[("customer", customer_id), ("limit", INVOICE_PAGE_LIMIT)],
            )
            .await?;
        // `draft` invoices (and any status we don't model) are skipped — the table shows
        // only issued invoices the user can act on.
        Ok(page.data.into_iter().filter_map(map_invoice).collect())
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
        Self::decode_response(path, resp).await
    }

    /// POST like [`post_form`](Self::post_form), but when `coupon_applied` is set and
    /// Stripe rejects the request **specifically because of the coupon** (a `400` whose
    /// machine-readable error is coupon/discount-related — see
    /// [`StripeApiError::is_coupon_related`]), surface a [`CouponRejected`] marker instead
    /// of a generic error. The service downcasts this to a `PromoUnavailable` and re-tries
    /// at full price. A `400` from any *other* cause (e.g. an archived price) falls through
    /// to the normal error path, so it is not misreported as a lapsed promotion.
    async fn post_form_coupon_aware<
        T: serde::Serialize + ?Sized,
        R: serde::de::DeserializeOwned,
    >(
        &self,
        path: &str,
        form: &T,
        coupon_applied: bool,
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
        if status.is_success() {
            return serde_json::from_str(&body)
                .map_err(|e| anyhow::anyhow!("malformed Stripe response from {path}: {e}"));
        }
        let envelope = serde_json::from_str::<StripeErrorEnvelope>(&body).ok();
        if coupon_applied
            && status == reqwest::StatusCode::BAD_REQUEST
            && envelope
                .as_ref()
                .is_some_and(|e| e.error.is_coupon_related())
        {
            return Err(anyhow::Error::new(CouponRejected));
        }
        let detail = envelope.map_or_else(String::new, |e| e.error.describe());
        anyhow::bail!("Stripe {path} returned {status}{detail}");
    }

    /// GET `path` with the Bearer secret key and the given query params, decoding the JSON
    /// response. Same PII-safe error contract as [`post_form`](Self::post_form): a non-2xx
    /// surfaces only the status + Stripe's machine-readable `type`/`code`, never the raw
    /// body (invariant #9).
    async fn get_json<R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> anyhow::Result<R> {
        let resp = self
            .http
            .get(format!("{}{path}", self.api_base))
            .bearer_auth(&self.secret_key)
            .query(query)
            .send()
            .await?;
        Self::decode_response(path, resp).await
    }

    /// Shared response tail for [`post_form`](Self::post_form) / [`get_json`](Self::get_json):
    /// decode the JSON body, surfacing a non-2xx as an error.
    ///
    /// On failure the error carries only the HTTP status and Stripe's machine-readable
    /// error `type`/`code` — **never the raw response body**, which can echo customer
    /// email / ids (PII) and would leak into logs (invariant #9). Both verbs route through
    /// here so the sanitization lives in exactly one place.
    async fn decode_response<R: serde::de::DeserializeOwned>(
        path: &str,
        resp: reqwest::Response,
    ) -> anyhow::Result<R> {
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
        "checkout.session.completed" => {
            let session: CheckoutSessionObject =
                parse_object(event.data.object, &event.event_type)?;
            // Only a setup-mode session is a card update; a subscription-mode completion is
            // handled via customer.subscription.created. Ignore anything without the refs.
            match (
                session.mode.as_deref(),
                session.customer.map(Expandable::into_id),
                session.setup_intent.map(Expandable::into_id),
            ) {
                (Some("setup"), Some(customer), Some(setup_intent)) => {
                    StripeEventKind::CardSetupCompleted {
                        stripe_customer_id: customer,
                        setup_intent_id: setup_intent,
                    }
                }
                _ => StripeEventKind::Ignored,
            }
        }
        // A catalog object changed in Stripe → resync the projection. We re-list the whole
        // (small) catalog, so the object body is irrelevant and is not parsed.
        t if is_catalog_event(t) => StripeEventKind::CatalogChanged,
        _ => StripeEventKind::Ignored,
    };
    Ok(StripeEvent { id: event.id, kind })
}

/// Whether a Stripe event type signals a catalog change (a price / product / coupon /
/// promotion-code create/update/delete) — any of which should resync the projection.
fn is_catalog_event(event_type: &str) -> bool {
    event_type.starts_with("price.")
        || event_type.starts_with("product.")
        || event_type.starts_with("coupon.")
        || event_type.starts_with("promotion_code.")
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
    entitlement_from_meta(&price.metadata)
}

/// Read `{max_networks, max_daemons}` from a metadata map (shared by the webhook price
/// path and the catalog list path).
fn entitlement_from_meta(metadata: &HashMap<String, String>) -> Option<Entitlement> {
    let max_networks = metadata.get("max_networks")?.parse().ok()?;
    let max_daemons = metadata.get("max_daemons")?.parse().ok()?;
    Some(Entitlement {
        max_networks,
        max_daemons,
    })
}

/// Map a Stripe catalog price (with expanded product) to our [`PlanData`]. Returns `None`
/// for a price that can't be a plan — no amount, no recurring interval, or no product.
/// `level` / `entitlement` are passed through as `Option` (the sync worker drops a price
/// missing either, safe-closed).
fn map_plan(price: StripePriceFull) -> Option<PlanData> {
    let product = price.product?;
    let amount_cents = price.unit_amount?;
    let interval = price.recurring?.interval;
    Some(PlanData {
        level: price.metadata.get("level").and_then(|v| v.parse().ok()),
        entitlement: entitlement_from_meta(&price.metadata),
        price_id: price.id,
        product_id: product.id,
        name: product.name.unwrap_or_default(),
        amount_cents,
        currency: price.currency,
        interval,
        active: price.active,
    })
}

/// Map a Stripe coupon to our [`PromotionData`]. The active window start comes from the
/// `wardnet_promo_start` metadata (RFC3339); the end from the native `redeem_by`; the
/// `wardnet_auto_apply` metadata flag gates participation in the auto-applied catalog.
fn map_coupon(c: StripeCoupon) -> PromotionData {
    PromotionData {
        coupon_id: c.id,
        name: c.name.unwrap_or_default(),
        percent_off: c.percent_off,
        amount_off: c.amount_off,
        currency: c.currency,
        applies_to_products: c.applies_to.map(|a| a.products).unwrap_or_default(),
        start: c
            .metadata
            .get("wardnet_promo_start")
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc)),
        redeem_by: c.redeem_by.and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
        auto_apply: c
            .metadata
            .get("wardnet_auto_apply")
            .is_some_and(|v| v == "true"),
    }
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

/// Map a Stripe invoice list row to our [`InvoiceView`]. Returns `None` for an invoice we
/// don't surface (a `draft`, or any status we don't model) — the caller skips it.
fn map_invoice(row: StripeInvoiceRow) -> Option<InvoiceView> {
    let status = match row.status.as_deref() {
        Some("paid") => InvoiceStatus::Paid,
        Some("open") => InvoiceStatus::Open,
        Some("void") => InvoiceStatus::Void,
        Some("uncollectible") => InvoiceStatus::Uncollectible,
        // `draft` is not yet issued — a legitimate, expected skip.
        Some("draft") | None => return None,
        // Any *other* value is a status Stripe added that we don't model yet: skip it (so
        // the history table stays consistent) but warn, so a silently-dropped real invoice
        // is visible in logs rather than vanishing (cf. `map_status`' safe-close). The
        // status string is a small closed enum, not PII (invariant #9).
        Some(other) => {
            tracing::warn!(status = %other, "unrecognized Stripe invoice status; skipping row");
            return None;
        }
    };
    let date = Utc
        .timestamp_opt(row.created?, 0)
        .single()?
        .format("%Y-%m-%d")
        .to_string();
    Some(InvoiceView {
        date,
        amount_cents: row.total,
        currency: row.currency,
        status,
        hosted_url: row.hosted_invoice_url,
    })
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

/// The `checkout.session.completed` event object — we read only the fields needed to
/// recognize a setup-mode card update.
#[derive(Deserialize)]
struct CheckoutSessionObject {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    customer: Option<Expandable>,
    #[serde(default)]
    setup_intent: Option<Expandable>,
}

/// A Stripe `SetupIntent` — we read only its resulting payment method.
#[derive(Deserialize)]
struct StripeSetupIntent {
    #[serde(default)]
    payment_method: Option<Expandable>,
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
    /// The attached subscription schedule (expanded via `expand[]=schedule`), if any. We
    /// read only its id; `None` when the subscription has no pending scheduled change.
    #[serde(default)]
    schedule: Option<Expandable>,
}

#[derive(Deserialize, Default)]
struct StripeSubscriptionItems {
    #[serde(default)]
    data: Vec<StripeSubscriptionItem>,
}

#[derive(Deserialize)]
struct StripeSubscriptionItem {
    /// The item id — needed to target a price swap on a subscription update.
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    price: Option<StripePrice>,
    /// Where `current_period_end` lives on Stripe API 2025-03-31+.
    #[serde(default)]
    current_period_end: Option<i64>,
}

/// A Stripe catalog `Price` (the `/v1/prices` list shape) with its product expanded —
/// distinct from the webhook-embedded [`StripePrice`], which carries only id + metadata.
#[derive(Deserialize)]
struct StripePriceFull {
    id: String,
    #[serde(default)]
    unit_amount: Option<i64>,
    #[serde(default)]
    currency: String,
    #[serde(default)]
    recurring: Option<StripeRecurring>,
    #[serde(default)]
    active: bool,
    /// Expanded via `expand[]=data.product`.
    #[serde(default)]
    product: Option<StripeProduct>,
    #[serde(default)]
    metadata: HashMap<String, String>,
}

#[derive(Deserialize)]
struct StripeRecurring {
    #[serde(default)]
    interval: String,
}

#[derive(Deserialize)]
struct StripeProduct {
    id: String,
    #[serde(default)]
    name: Option<String>,
}

/// A Stripe `Coupon` (the `/v1/coupons` list shape).
#[derive(Deserialize)]
struct StripeCoupon {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    percent_off: Option<f64>,
    #[serde(default)]
    amount_off: Option<i64>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    redeem_by: Option<i64>,
    #[serde(default)]
    applies_to: Option<StripeAppliesTo>,
    #[serde(default)]
    metadata: HashMap<String, String>,
}

#[derive(Deserialize)]
struct StripeAppliesTo {
    #[serde(default)]
    products: Vec<String>,
}

/// A Stripe `SubscriptionSchedule` — we read its id and phases (each phase's start +
/// price) to drive downgrades and surface a pending change.
#[derive(Deserialize)]
struct StripeSubscriptionSchedule {
    id: String,
    #[serde(default)]
    phases: Vec<StripeSchedulePhase>,
}

#[derive(Deserialize)]
struct StripeSchedulePhase {
    #[serde(default)]
    start_date: Option<i64>,
    #[serde(default)]
    items: Vec<StripeSchedulePhaseItem>,
}

#[derive(Deserialize)]
struct StripeSchedulePhaseItem {
    /// The phase item's price id (unexpanded — a bare id string).
    #[serde(default)]
    price: Option<String>,
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
    /// The offending request parameter (e.g. `discounts[0][coupon]`), when Stripe reports
    /// one. Used to attribute a `400` to the coupon vs some other field.
    #[serde(default)]
    param: Option<String>,
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

    /// Whether this error is specifically about the applied coupon/discount — either a
    /// coupon-specific `code` (e.g. `coupon_expired`) or a `param` pointing at the
    /// `discounts`/`coupon` field. Used to distinguish a lapsed promo (retryable at full
    /// price) from an unrelated `400` (e.g. an archived price).
    fn is_coupon_related(&self) -> bool {
        let code_hit = self
            .code
            .as_deref()
            .is_some_and(|c| c.contains("coupon") || c.contains("promotion"));
        let param_hit = self
            .param
            .as_deref()
            .is_some_and(|p| p.contains("coupon") || p.contains("discount"));
        code_hit || param_hit
    }
}

/// A Stripe `list` envelope (`{"object":"list","data":[…]}`) — we read only `data`.
#[derive(Deserialize)]
struct StripeList<T> {
    // The path form (not bare `#[serde(default)]`) avoids serde deriving a spurious
    // `T: Default` bound on the generic — `Vec::new` needs no bound on `T`.
    #[serde(default = "Vec::new")]
    data: Vec<T>,
}

/// A Stripe `Customer` — we read only its default-payment-method pointer (expanded).
#[derive(Deserialize)]
struct StripeCustomer {
    #[serde(default)]
    invoice_settings: Option<StripeInvoiceSettings>,
}

#[derive(Deserialize)]
struct StripeInvoiceSettings {
    /// Expanded via `expand[]=invoice_settings.default_payment_method`; `None` when the
    /// customer has no default card on file.
    #[serde(default)]
    default_payment_method: Option<StripePaymentMethod>,
}

#[derive(Deserialize)]
struct StripePaymentMethod {
    /// Present for card payment methods (the only kind we render).
    #[serde(default)]
    card: Option<StripeCard>,
}

#[derive(Deserialize)]
struct StripeCard {
    brand: String,
    last4: String,
    exp_month: u32,
    exp_year: u32,
}

/// A Stripe `Invoice` as it appears in the **list** endpoint (distinct from the
/// webhook-shaped [`StripeInvoice`] above, which only carries the subscription ref).
#[derive(Deserialize)]
struct StripeInvoiceRow {
    /// Creation time (unix seconds). Optional so one degenerate row (e.g. API drift that
    /// omits it) is skipped by `map_invoice` rather than failing the whole page parse.
    #[serde(default)]
    created: Option<i64>,
    /// Invoice total in the currency's minor units.
    #[serde(default)]
    total: i64,
    #[serde(default)]
    currency: String,
    /// `draft` | `open` | `paid` | `void` | `uncollectible`.
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    hosted_invoice_url: Option<String>,
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
