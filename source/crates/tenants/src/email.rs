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

/// The subject + body text for a one-time code of `purpose`.
fn code_email(purpose: CodePurpose, code: &str) -> (&'static str, String) {
    match purpose {
        CodePurpose::Signup => (
            "Your wardnet sign-up code",
            format!(
                "Your one-time wardnet sign-up code is:\n\n    {code}\n\n\
                 Enter it to finish creating your account. It expires shortly."
            ),
        ),
        CodePurpose::PasswordReset => (
            "Your wardnet password-reset code",
            format!(
                "Your one-time wardnet password-reset code is:\n\n    {code}\n\n\
                 Enter it to set a new password. It expires shortly. If you did not \
                 request this, you can ignore this email."
            ),
        ),
        CodePurpose::Enrollment => (
            "Your wardnet enrollment code",
            format!(
                "Your one-time wardnet enrollment code is:\n\n    {code}\n\n\
                 Enter it in the install wizard to continue. It expires shortly."
            ),
        ),
    }
}

/// Production [`EmailSender`] over Resend's REST API.
pub struct ResendEmailSender {
    http: reqwest::Client,
    from: String,
    base_url: String,
}

impl ResendEmailSender {
    /// Build a sender from a Resend API key and a verified `from` address.
    ///
    /// # Errors
    /// Returns an error if the API key contains invalid header characters or the HTTP
    /// client cannot be built.
    pub fn new(api_key: &str, from: &str) -> anyhow::Result<Self> {
        Self::with_base_url(api_key, from, RESEND_API_BASE)
    }

    /// Build a sender against `base_url` (the e2e wiremock seam).
    ///
    /// # Errors
    /// As [`ResendEmailSender::new`].
    pub fn with_base_url(api_key: &str, from: &str, base_url: &str) -> anyhow::Result<Self> {
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
        })
    }
}

/// Resend `POST /emails` request body.
#[derive(Serialize)]
struct ResendEmail<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    text: String,
}

#[async_trait]
impl EmailSender for ResendEmailSender {
    async fn send_code(&self, to: &str, code: &str, purpose: CodePurpose) -> anyhow::Result<()> {
        let (subject, text) = code_email(purpose, code);
        let body = ResendEmail {
            from: &self.from,
            to: [to],
            subject,
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
