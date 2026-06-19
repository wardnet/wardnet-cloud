//! External identity providers behind one trait (ADR-0009).
//!
//! Federated login differs by protocol — **Google is full OIDC** (discovery +
//! `id_token` + JWKS, via `openidconnect`), **GitHub is plain `OAuth2`** (no
//! `id_token`; call the user/emails API, via `reqwest`) — so both sit behind
//! [`ExternalIdentityProvider`]. Each yields a [`VerifiedIdentity`] the
//! [`IdentitiesService`](super::IdentitiesService) resolves to a tenant by the
//! verified-email join key.

use async_trait::async_trait;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest as oidc_reqwest;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};

/// A provider-verified identity — the input to the two-gate resolver (ADR-0009).
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// Login method (`google` / `github` / …).
    pub provider: String,
    /// The provider's stable subject (its opaque user id).
    pub subject: String,
    /// The email the provider associates with the subject (lowercased on use).
    pub email: String,
    /// Whether the provider **proved control** of the email (gate 1). A provider may
    /// assert an email without verifying it; an unverified email never resolves.
    pub email_verified: bool,
}

/// The redirect to send the browser to, plus the secrets to stash in the signed
/// cookie and hand back to [`ExternalIdentityProvider::exchange`].
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    /// The provider authorize URL to 302 the browser to.
    pub url: String,
    /// CSRF state to echo back; the callback compares it against the query `state`.
    pub csrf_state: String,
    /// Opaque per-provider secret bundle (PKCE verifier + nonce for OIDC; empty for
    /// GitHub) — stored in the short-lived signed cookie, never seen by the browser.
    pub verifier: String,
}

/// One federated login provider.
#[async_trait]
pub trait ExternalIdentityProvider: Send + Sync {
    /// Build the authorize redirect + the CSRF/PKCE secrets to stash.
    fn authorize_url(&self) -> AuthorizeRequest;

    /// Exchange the callback `code` (with the stashed `verifier` bundle) for a
    /// [`VerifiedIdentity`].
    ///
    /// # Errors
    /// Returns an error if the code exchange, token verification, or profile fetch
    /// fails.
    async fn exchange(&self, code: &str, verifier: &str) -> anyhow::Result<VerifiedIdentity>;
}

/// The OIDC secret bundle stashed across the redirect (JSON in the signed cookie).
#[derive(Serialize, Deserialize)]
struct OidcVerifier {
    pkce: String,
    nonce: String,
}

// ── Generic OIDC (Google + any discovery-based provider) ────────────────────────

/// A full-OIDC provider (Google): metadata is discovered once at construction; each
/// request rebuilds the (cheap, network-free) client from the stored metadata.
pub struct OidcProvider {
    name: String,
    metadata: CoreProviderMetadata,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_url: RedirectUrl,
    http: oidc_reqwest::Client,
}

impl OidcProvider {
    /// Discover the provider's metadata (one network call) and build the provider.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be built, the issuer/redirect URLs
    /// are invalid, or discovery fails.
    pub async fn discover(
        name: &str,
        issuer_url: &str,
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> anyhow::Result<Self> {
        // Never follow redirects from the provider's endpoints (SSRF guard).
        let http = oidc_reqwest::ClientBuilder::new()
            .redirect(oidc_reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| anyhow::anyhow!("build OIDC HTTP client: {e}"))?;
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url.to_string())
                .map_err(|e| anyhow::anyhow!("invalid issuer URL: {e}"))?,
            &http,
        )
        .await
        .map_err(|e| anyhow::anyhow!("OIDC discovery for {name} failed: {e}"))?;
        Ok(Self {
            name: name.to_string(),
            metadata,
            client_id: ClientId::new(client_id),
            client_secret: ClientSecret::new(client_secret),
            redirect_url: RedirectUrl::new(redirect_url)
                .map_err(|e| anyhow::anyhow!("invalid redirect URL: {e}"))?,
            http,
        })
    }

    /// Rebuild the configured client from the stored metadata (no network).
    fn client(
        &self,
    ) -> CoreClient<
        openidconnect::EndpointSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointMaybeSet,
        openidconnect::EndpointMaybeSet,
    > {
        CoreClient::from_provider_metadata(
            self.metadata.clone(),
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
        .set_redirect_uri(self.redirect_url.clone())
    }
}

#[async_trait]
impl ExternalIdentityProvider for OidcProvider {
    fn authorize_url(&self) -> AuthorizeRequest {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, csrf, nonce) = self
            .client()
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();
        let verifier = serde_json::to_string(&OidcVerifier {
            pkce: pkce_verifier.into_secret(),
            nonce: nonce.secret().clone(),
        })
        .unwrap_or_default();
        AuthorizeRequest {
            url: url.to_string(),
            csrf_state: csrf.secret().clone(),
            verifier,
        }
    }

    async fn exchange(&self, code: &str, verifier: &str) -> anyhow::Result<VerifiedIdentity> {
        let bundle: OidcVerifier = serde_json::from_str(verifier)
            .map_err(|e| anyhow::anyhow!("malformed OIDC verifier bundle: {e}"))?;
        let client = self.client();
        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(bundle.pkce))
            .request_async(&self.http)
            .await
            .map_err(|e| anyhow::anyhow!("OIDC code exchange failed: {e}"))?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow::anyhow!("provider returned no id_token"))?;
        let claims = id_token.claims(&client.id_token_verifier(), &Nonce::new(bundle.nonce))?;

        let email = claims
            .email()
            .map(|e| e.as_str().to_lowercase())
            .ok_or_else(|| anyhow::anyhow!("id_token carries no email"))?;
        Ok(VerifiedIdentity {
            provider: self.name.clone(),
            subject: claims.subject().as_str().to_string(),
            email,
            email_verified: claims.email_verified().unwrap_or(false),
        })
    }
}

// ── GitHub (plain `OAuth2`, no id_token) ──────────────────────────────────────────

/// GitHub `OAuth2` endpoints (overridable for tests against a mock server).
const GITHUB_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_API_BASE: &str = "https://api.github.com";

/// A GitHub `OAuth2` provider. GitHub issues no `id_token`, so the verified identity is
/// assembled from the `user` + `user/emails` API.
pub struct GitHubProvider {
    client_id: String,
    client_secret: String,
    redirect_url: String,
    http: reqwest::Client,
    authorize_url: String,
    token_url: String,
    api_base: String,
}

impl GitHubProvider {
    /// Build a GitHub provider against the production endpoints.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("wardnet-cloud")
            .build()
            .map_err(|e| anyhow::anyhow!("build GitHub HTTP client: {e}"))?;
        Ok(Self {
            client_id,
            client_secret,
            redirect_url,
            http,
            authorize_url: GITHUB_AUTHORIZE_URL.to_string(),
            token_url: GITHUB_TOKEN_URL.to_string(),
            api_base: GITHUB_API_BASE.to_string(),
        })
    }
}

/// GitHub `POST /login/oauth/access_token` JSON response.
#[derive(Deserialize)]
struct GitHubToken {
    access_token: Option<String>,
}

/// GitHub `GET /user` (the bits we need).
#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
}

/// GitHub `GET /user/emails` entry.
#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[async_trait]
impl ExternalIdentityProvider for GitHubProvider {
    fn authorize_url(&self) -> AuthorizeRequest {
        let state = crate::util::random_token();
        let mut url = reqwest::Url::parse(&self.authorize_url)
            .expect("GitHub authorize URL is a valid constant");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("scope", "read:user user:email")
            .append_pair("state", &state)
            .append_pair("allow_signup", "true");
        AuthorizeRequest {
            url: url.to_string(),
            csrf_state: state,
            // GitHub does not support PKCE; the signed-cookie `state` is the CSRF guard.
            verifier: String::new(),
        }
    }

    async fn exchange(&self, code: &str, _verifier: &str) -> anyhow::Result<VerifiedIdentity> {
        use reqwest::header::ACCEPT;

        let token: GitHubToken = self
            .http
            .post(&self.token_url)
            .header(ACCEPT, "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", self.redirect_url.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let access = token
            .access_token
            .ok_or_else(|| anyhow::anyhow!("GitHub returned no access token"))?;
        let bearer = format!("Bearer {access}");

        let user: GitHubUser = self
            .http
            .get(format!("{}/user", self.api_base))
            .header(reqwest::header::AUTHORIZATION, &bearer)
            .header(ACCEPT, "application/vnd.github+json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let emails: Vec<GitHubEmail> = self
            .http
            .get(format!("{}/user/emails", self.api_base))
            .header(reqwest::header::AUTHORIZATION, &bearer)
            .header(ACCEPT, "application/vnd.github+json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        // Prefer the primary verified address; fall back to any verified one.
        let chosen = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .or_else(|| emails.iter().find(|e| e.verified))
            .ok_or_else(|| anyhow::anyhow!("no verified GitHub email"))?;

        Ok(VerifiedIdentity {
            provider: "github".to_string(),
            subject: user.id.to_string(),
            email: chosen.email.to_lowercase(),
            email_verified: chosen.verified,
        })
    }
}
