//! Transactional email behind an [`EmailSender`] trait.
//!
//! Production sends the one-time verification code via Resend ([`ResendEmailSender`]);
//! dev/test uses [`NoopEmailSender`] (logs, never sends). The trait's
//! [`delivers`](EmailSender::delivers) tells the API whether a real email went out —
//! when it did, the code is **not** echoed in the HTTP response (it's in the inbox);
//! when it didn't (dev), the response still carries the code so the flow stays
//! exercisable without a mailbox. The [`CodePurpose`] selects the subject + body so a
//! password-reset code never arrives wearing daemon-enrollment wording (PR3).

use std::time::Duration;

use askama::Template;
use async_trait::async_trait;
use serde::Serialize;
use wardnet_common::contract::CodePurpose;

/// The default Resend API base URL.
const RESEND_API_BASE: &str = "https://api.resend.com";
/// Connect/request timeouts for the Resend call.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Sends a one-time verification code to a user's email.
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Send the one-time `code` to `to`, with subject/body matching `purpose`.
    ///
    /// # Errors
    /// Returns an error if the provider rejects the send.
    async fn send_code(&self, to: &str, code: &str, purpose: CodePurpose) -> anyhow::Result<()>;

    /// Whether this sender actually delivers mail (a real provider) versus a dev
    /// no-op. The API uses this to decide whether to echo the code in the response.
    fn delivers(&self) -> bool;
}

/// Per-purpose copy: `(subject, intro, note)`. `intro` is the line above the code,
/// `note` the reassurance line below it — shared by the plain-text and HTML bodies.
fn code_copy(purpose: CodePurpose) -> (&'static str, &'static str, &'static str) {
    match purpose {
        CodePurpose::Signup => (
            "Your Wardnet sign-up code",
            "Use this code to finish creating your Wardnet account:",
            "It expires shortly. If you didn't request this, you can ignore this email.",
        ),
        CodePurpose::PasswordReset => (
            "Your Wardnet password-reset code",
            "Use this code to set a new password on your Wardnet account:",
            "It expires shortly. If you didn't request this, you can ignore this email.",
        ),
        CodePurpose::PasswordChange => (
            "Confirm your Wardnet password change",
            "Use this code to confirm the password change on your Wardnet account:",
            "It expires shortly. If you didn't request this, ignore this email and your \
             password stays unchanged.",
        ),
        CodePurpose::Enrollment => (
            "Your Wardnet enrollment code",
            "Use this code in the install wizard to continue:",
            "It expires shortly.",
        ),
    }
}

/// Branded HTML body (extends the shared `_layout.html`). `logo_url` empty → CSS
/// wordmark; set → hosted `<img>`.
#[derive(Template)]
#[template(path = "email/verification_code.html")]
struct VerificationCodeHtml<'a> {
    logo_url: &'a str,
    intro: &'a str,
    code: &'a str,
    note: &'a str,
}

/// Plain-text fallback body (for clients that don't render HTML).
#[derive(Template)]
#[template(path = "email/verification_code.txt")]
struct VerificationCodeText<'a> {
    intro: &'a str,
    code: &'a str,
    note: &'a str,
}

/// Production [`EmailSender`] over Resend's REST API.
pub struct ResendEmailSender {
    http: reqwest::Client,
    from: String,
    base_url: String,
    /// Absolute logo URL for the HTML email (empty → CSS wordmark fallback).
    logo_url: String,
}

impl ResendEmailSender {
    /// Build a sender from a Resend API key, a verified `from` address, and the brand
    /// `logo_url` (empty for the wordmark fallback).
    ///
    /// # Errors
    /// Returns an error if the API key contains invalid header characters or the HTTP
    /// client cannot be built.
    pub fn new(api_key: &str, from: &str, logo_url: &str) -> anyhow::Result<Self> {
        Self::with_base_url(api_key, from, logo_url, RESEND_API_BASE)
    }

    /// Build a sender against `base_url` (the e2e wiremock seam).
    ///
    /// # Errors
    /// As [`ResendEmailSender::new`].
    pub fn with_base_url(
        api_key: &str,
        from: &str,
        logo_url: &str,
        base_url: &str,
    ) -> anyhow::Result<Self> {
        use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        let auth = HeaderValue::from_str(&format!("Bearer {api_key}"))
            .map_err(|_| anyhow::anyhow!("Resend API key contains invalid header characters"))?;
        headers.insert(AUTHORIZATION, auth);
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            from: from.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            logo_url: logo_url.to_string(),
        })
    }
}

/// Resend `POST /emails` request body. Both `html` (rendered by most clients) and
/// `text` (fallback) are sent.
#[derive(Serialize)]
struct ResendEmail<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    html: String,
    text: String,
}

#[async_trait]
impl EmailSender for ResendEmailSender {
    async fn send_code(&self, to: &str, code: &str, purpose: CodePurpose) -> anyhow::Result<()> {
        let (subject, intro, note) = code_copy(purpose);
        let html = VerificationCodeHtml {
            logo_url: &self.logo_url,
            intro,
            code,
            note,
        }
        .render()
        .map_err(|e| anyhow::anyhow!("email HTML template render failed: {e}"))?;
        let text = VerificationCodeText { intro, code, note }
            .render()
            .map_err(|e| anyhow::anyhow!("email text template render failed: {e}"))?;
        let body = ResendEmail {
            from: &self.from,
            to: [to],
            subject,
            html,
            text,
        };
        let resp = self
            .http
            .post(format!("{}/emails", self.base_url))
            .json(&body)
            .send()
            .await?;
        resp.error_for_status()?;
        Ok(())
    }

    fn delivers(&self) -> bool {
        true
    }
}

/// Dev/test [`EmailSender`] that logs the code instead of sending it.
pub struct NoopEmailSender;

#[async_trait]
impl EmailSender for NoopEmailSender {
    async fn send_code(&self, to: &str, code: &str, purpose: CodePurpose) -> anyhow::Result<()> {
        tracing::info!(
            to,
            code,
            purpose = purpose.as_str(),
            "dev email sender: would send code"
        );
        Ok(())
    }

    fn delivers(&self) -> bool {
        false
    }
}
