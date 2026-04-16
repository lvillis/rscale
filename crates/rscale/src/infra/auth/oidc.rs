use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use axum::http::header::{AUTHORIZATION, HeaderValue};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use graviola::hashing::{Hash, Sha256};
use jsonwebtoken::jwk::{JwkSet, PublicKeyUse};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use reqx::TlsVersion;
use reqx::prelude::{Client, RetryPolicy};
use serde::{Deserialize, Serialize};

use crate::config::OidcConfig;
use crate::error::{AppError, AppResult};
use crate::infra::db::PendingOidcAuthRequest;

#[derive(Clone)]
pub struct OidcProviderClient {
    client: Client,
    issuer_url: String,
}

#[derive(Clone)]
pub struct OidcRuntime {
    client: OidcProviderClient,
    discovery: OidcDiscoveryDocument,
    public_base_url: String,
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    allowed_domains: BTreeSet<String>,
    allowed_users: BTreeSet<String>,
    allowed_groups: BTreeSet<String>,
    extra_params: BTreeMap<String, String>,
    auth_flow_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcPrincipal {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
}

impl OidcProviderClient {
    pub fn from_config(config: &OidcConfig) -> AppResult<Self> {
        validate(config)?;

        let issuer_url =
            normalize_url(config.issuer_url.as_deref().ok_or_else(|| {
                AppError::InvalidConfig("OIDC issuer_url is missing".to_string())
            })?);

        let client = Client::builder(issuer_url.clone())
            .client_name("rscale-oidc")
            .request_timeout(Duration::from_secs(config.request_timeout_secs))
            .total_timeout(Duration::from_secs(config.total_timeout_secs))
            .retry_policy(
                RetryPolicy::standard()
                    .max_attempts(2)
                    .base_backoff(Duration::from_millis(100))
                    .max_backoff(Duration::from_millis(500)),
            )
            .tls_min_version(TlsVersion::V1_2)
            .build()
            .map_err(|err| {
                AppError::Bootstrap(format!("failed to build OIDC HTTP client: {err}"))
            })?;

        Ok(Self { client, issuer_url })
    }

    pub async fn fetch_discovery(&self) -> AppResult<OidcDiscoveryDocument> {
        let document: OidcDiscoveryDocument = self
            .client
            .get("/.well-known/openid-configuration")
            .send_json()
            .await
            .map_err(|err| {
                AppError::Bootstrap(format!(
                    "failed to fetch OIDC discovery document from {}: {err}",
                    self.issuer_url
                ))
            })?;

        validate_discovery_document(&self.issuer_url, &document)?;

        Ok(document)
    }

    async fn exchange_code(
        &self,
        discovery: &OidcDiscoveryDocument,
        callback_url: &str,
        code: &str,
        client_id: &str,
        client_secret: &str,
        code_verifier: &str,
    ) -> AppResult<OidcTokenResponse> {
        let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));
        let authorization = HeaderValue::from_str(&format!("Basic {basic}")).map_err(|err| {
            AppError::Bootstrap(format!(
                "failed to build OIDC token authorization header: {err}"
            ))
        })?;

        self.client
            .post(&discovery.token_endpoint)
            .header(AUTHORIZATION, authorization)
            .form(&OidcTokenRequest {
                grant_type: "authorization_code",
                code,
                redirect_uri: callback_url,
                client_id,
                code_verifier,
            })
            .map_err(AppError::from)?
            .send_json()
            .await
            .map_err(|err| {
                AppError::Unauthorized(format!("failed to exchange OIDC authorization code: {err}"))
            })
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> AppResult<JwkSet> {
        self.client.get(jwks_uri).send_json().await.map_err(|err| {
            AppError::Bootstrap(format!(
                "failed to fetch OIDC JWKS from {}: {err}",
                jwks_uri
            ))
        })
    }

    async fn fetch_userinfo(
        &self,
        userinfo_endpoint: &str,
        access_token: &str,
    ) -> AppResult<OidcUserInfo> {
        let authorization =
            HeaderValue::from_str(&format!("Bearer {access_token}")).map_err(|err| {
                AppError::Bootstrap(format!(
                    "failed to build OIDC userinfo authorization header: {err}"
                ))
            })?;

        self.client
            .get(userinfo_endpoint)
            .header(AUTHORIZATION, authorization)
            .send_json()
            .await
            .map_err(|err| AppError::Unauthorized(format!("failed to fetch OIDC userinfo: {err}")))
    }
}

impl OidcRuntime {
    pub async fn from_config(
        config: &OidcConfig,
        public_base_url: Option<&str>,
    ) -> AppResult<Option<Self>> {
        validate(config)?;

        if !config.enabled {
            return Ok(None);
        }

        let public_base_url = normalize_url(public_base_url.ok_or_else(|| {
            AppError::InvalidConfig(
                "server.public_base_url is required when OIDC is enabled".to_string(),
            )
        })?);
        let client = OidcProviderClient::from_config(config)?;
        let discovery = client.fetch_discovery().await?;

        Ok(Some(Self {
            client,
            discovery,
            public_base_url,
            client_id: config.client_id.clone().ok_or_else(|| {
                AppError::InvalidConfig(
                    "auth.oidc.client_id is required when OIDC is enabled".to_string(),
                )
            })?,
            client_secret: config.client_secret.clone().ok_or_else(|| {
                AppError::InvalidConfig(
                    "auth.oidc.client_secret is required when OIDC is enabled".to_string(),
                )
            })?,
            scopes: config.scopes.clone(),
            allowed_domains: normalized_set(&config.allowed_domains),
            allowed_users: normalized_set(&config.allowed_users),
            allowed_groups: normalized_set(&config.allowed_groups),
            extra_params: config.extra_params.clone(),
            auth_flow_ttl_secs: config.auth_flow_ttl_secs,
        }))
    }

    pub fn auth_flow_ttl_secs(&self) -> u64 {
        self.auth_flow_ttl_secs
    }

    pub fn registration_url(&self, auth_id: &str) -> String {
        format!("{}/register/{auth_id}", self.public_base_url)
    }

    pub fn callback_url(&self) -> String {
        format!("{}/oidc/callback", self.public_base_url)
    }

    pub fn authorization_redirect_url(
        &self,
        pending: &PendingOidcAuthRequest,
    ) -> AppResult<String> {
        self.authorization_redirect_url_for_flow(
            &pending.oidc_state,
            &pending.oidc_nonce,
            &pending.pkce_verifier,
        )
    }

    pub fn authorization_redirect_url_for_flow(
        &self,
        oidc_state: &str,
        oidc_nonce: &str,
        pkce_verifier: &str,
    ) -> AppResult<String> {
        let mut query = BTreeMap::from([
            ("response_type".to_string(), "code".to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("redirect_uri".to_string(), self.callback_url()),
            ("scope".to_string(), self.scopes.join(" ")),
            ("state".to_string(), oidc_state.to_string()),
            ("nonce".to_string(), oidc_nonce.to_string()),
            ("code_challenge".to_string(), pkce_challenge(pkce_verifier)),
            ("code_challenge_method".to_string(), "S256".to_string()),
        ]);
        for (key, value) in &self.extra_params {
            query.insert(key.clone(), value.clone());
        }

        let encoded = serde_urlencoded::to_string(query).map_err(|err| {
            AppError::Bootstrap(format!("failed to encode OIDC authorization query: {err}"))
        })?;

        Ok(append_query(
            &self.discovery.authorization_endpoint,
            &encoded,
        ))
    }

    pub async fn complete_authorization(
        &self,
        pending: &PendingOidcAuthRequest,
        code: &str,
    ) -> AppResult<OidcPrincipal> {
        self.complete_authorization_for_flow(&pending.oidc_nonce, &pending.pkce_verifier, code)
            .await
    }

    pub async fn complete_authorization_for_flow(
        &self,
        oidc_nonce: &str,
        pkce_verifier: &str,
        code: &str,
    ) -> AppResult<OidcPrincipal> {
        let tokens = self
            .client
            .exchange_code(
                &self.discovery,
                &self.callback_url(),
                code,
                &self.client_id,
                &self.client_secret,
                pkce_verifier,
            )
            .await?;
        let jwks = self.client.fetch_jwks(&self.discovery.jwks_uri).await?;
        let claims = verify_id_token(
            &self.discovery,
            &self.client_id,
            &tokens.id_token,
            oidc_nonce,
            &jwks,
        )?;

        let userinfo = match (
            self.discovery.userinfo_endpoint.as_deref(),
            tokens.access_token.as_deref(),
        ) {
            (Some(endpoint), Some(access_token)) if !access_token.is_empty() => Some(
                self.client
                    .fetch_userinfo(endpoint, access_token)
                    .await
                    .map_err(|err| {
                        AppError::Unauthorized(format!(
                            "OIDC authentication succeeded but userinfo lookup failed: {err}"
                        ))
                    })?,
            ),
            _ => None,
        };

        let principal = merged_principal(&self.discovery.issuer, claims, userinfo);
        self.authorize_principal(&principal)?;
        Ok(principal)
    }

    fn authorize_principal(&self, principal: &OidcPrincipal) -> AppResult<()> {
        if !self.allowed_domains.is_empty() {
            let email = principal.email.as_deref().ok_or_else(|| {
                AppError::Unauthorized(
                    "OIDC login is missing an email claim required by allowed_domains".to_string(),
                )
            })?;
            let Some((_, domain)) = email.rsplit_once('@') else {
                return Err(AppError::Unauthorized(
                    "OIDC login email claim is malformed".to_string(),
                ));
            };
            if !self.allowed_domains.contains(&domain.to_ascii_lowercase()) {
                return Err(AppError::Unauthorized(
                    "OIDC login email domain is not allowed".to_string(),
                ));
            }
        }

        if !self.allowed_users.is_empty() {
            let mut candidates = BTreeSet::from([principal.subject.to_ascii_lowercase()]);
            if let Some(email) = &principal.email {
                candidates.insert(email.to_ascii_lowercase());
            }
            if !candidates
                .iter()
                .any(|candidate| self.allowed_users.contains(candidate))
            {
                return Err(AppError::Unauthorized(
                    "OIDC login subject is not in the allowed_users policy".to_string(),
                ));
            }
        }

        if !self.allowed_groups.is_empty()
            && !principal
                .groups
                .iter()
                .map(|group| group.to_ascii_lowercase())
                .any(|group| self.allowed_groups.contains(&group))
        {
            return Err(AppError::Unauthorized(
                "OIDC login does not satisfy the allowed_groups policy".to_string(),
            ));
        }

        Ok(())
    }
}

pub async fn bootstrap(config: &OidcConfig) -> AppResult<Option<OidcDiscoveryDocument>> {
    validate(config)?;

    if !config.enabled || !config.validate_discovery_on_startup {
        return Ok(None);
    }

    let client = OidcProviderClient::from_config(config)?;
    Ok(Some(client.fetch_discovery().await?))
}

pub fn validate(config: &OidcConfig) -> AppResult<()> {
    if !config.enabled {
        return Ok(());
    }

    let issuer_url = config
        .issuer_url
        .as_deref()
        .ok_or_else(|| AppError::InvalidConfig("OIDC issuer_url is missing".to_string()))?;

    if issuer_url.is_empty() {
        return Err(AppError::InvalidConfig(
            "OIDC issuer_url must not be empty".to_string(),
        ));
    }

    if config.client_id.as_deref().is_none_or(str::is_empty) {
        return Err(AppError::InvalidConfig(
            "OIDC client_id must not be empty when OIDC is enabled".to_string(),
        ));
    }

    if config.client_secret.as_deref().is_none_or(str::is_empty) {
        return Err(AppError::InvalidConfig(
            "OIDC client_secret must not be empty when OIDC is enabled".to_string(),
        ));
    }

    if config.request_timeout_secs == 0 {
        return Err(AppError::InvalidConfig(
            "OIDC request_timeout_secs must be greater than zero".to_string(),
        ));
    }

    if config.total_timeout_secs == 0 {
        return Err(AppError::InvalidConfig(
            "OIDC total_timeout_secs must be greater than zero".to_string(),
        ));
    }

    if config.total_timeout_secs < config.request_timeout_secs {
        return Err(AppError::InvalidConfig(
            "OIDC total_timeout_secs must be greater than or equal to request_timeout_secs"
                .to_string(),
        ));
    }

    if config.auth_flow_ttl_secs == 0 {
        return Err(AppError::InvalidConfig(
            "OIDC auth_flow_ttl_secs must be greater than zero".to_string(),
        ));
    }

    if config.scopes.is_empty() || config.scopes.iter().any(|scope| scope.trim().is_empty()) {
        return Err(AppError::InvalidConfig(
            "OIDC scopes must contain at least one non-empty scope".to_string(),
        ));
    }

    let normalized = normalize_url(issuer_url);
    if !is_secure_or_local(&normalized) {
        return Err(AppError::InvalidConfig(
            "OIDC issuer_url must use https unless it points to a local development endpoint"
                .to_string(),
        ));
    }

    Ok(())
}

fn verify_id_token(
    discovery: &OidcDiscoveryDocument,
    client_id: &str,
    id_token: &str,
    expected_nonce: &str,
    jwks: &JwkSet,
) -> AppResult<OidcIdTokenClaims> {
    let header = decode_header(id_token).map_err(|err| {
        AppError::Unauthorized(format!("failed to decode OIDC ID token header: {err}"))
    })?;
    let jwk = select_verification_key(jwks, header.kid.as_deref(), header.alg)?;
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|err| {
        AppError::Unauthorized(format!("failed to construct OIDC verification key: {err}"))
    })?;

    let mut validation = Validation::new(header.alg);
    validation.leeway = 30;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(&[normalize_url(&discovery.issuer)]);
    validation.set_audience(&[client_id]);

    let claims = decode::<OidcIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|err| AppError::Unauthorized(format!("failed to validate OIDC ID token: {err}")))?
        .claims;

    if claims.nonce.as_deref() != Some(expected_nonce) {
        return Err(AppError::Unauthorized(
            "OIDC ID token nonce mismatch".to_string(),
        ));
    }

    if claims.email.is_some() && claims.email_verified == Some(false) {
        return Err(AppError::Unauthorized(
            "OIDC email claim is present but not verified".to_string(),
        ));
    }

    Ok(claims)
}

fn select_verification_key<'a>(
    jwks: &'a JwkSet,
    kid: Option<&str>,
    algorithm: jsonwebtoken::Algorithm,
) -> AppResult<&'a jsonwebtoken::jwk::Jwk> {
    let candidates = jwks
        .keys
        .iter()
        .filter(|jwk| {
            jwk.common
                .public_key_use
                .as_ref()
                .is_none_or(|value| *value == PublicKeyUse::Signature)
        })
        .collect::<Vec<_>>();

    let selected = if let Some(kid) = kid {
        candidates
            .into_iter()
            .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
    } else {
        candidates.into_iter().next()
    };

    selected.ok_or_else(|| {
        AppError::Unauthorized(format!(
            "OIDC provider JWKS does not contain a usable signing key for {algorithm:?}"
        ))
    })
}

fn merged_principal(
    issuer: &str,
    claims: OidcIdTokenClaims,
    userinfo: Option<OidcUserInfo>,
) -> OidcPrincipal {
    let email = userinfo
        .as_ref()
        .and_then(|value| value.email.clone())
        .or(claims.email)
        .map(normalize_email);
    let display_name = userinfo
        .as_ref()
        .and_then(|value| value.name.clone())
        .or(claims.name)
        .or(claims.preferred_username);
    let groups = userinfo
        .as_ref()
        .and_then(|value| value.groups.clone())
        .unwrap_or(claims.groups)
        .into_iter()
        .filter(|group| !group.trim().is_empty())
        .collect();

    OidcPrincipal {
        issuer: normalize_url(issuer),
        subject: claims.sub,
        email,
        display_name,
        groups,
    }
}

fn validate_discovery_document(
    expected_issuer: &str,
    document: &OidcDiscoveryDocument,
) -> AppResult<()> {
    let actual_issuer = normalize_url(&document.issuer);
    if actual_issuer != normalize_url(expected_issuer) {
        return Err(AppError::Bootstrap(format!(
            "OIDC discovery issuer mismatch: expected {expected_issuer}, got {}",
            document.issuer
        )));
    }

    if document.authorization_endpoint.is_empty() {
        return Err(AppError::Bootstrap(
            "OIDC discovery authorization_endpoint must not be empty".to_string(),
        ));
    }

    if document.token_endpoint.is_empty() {
        return Err(AppError::Bootstrap(
            "OIDC discovery token_endpoint must not be empty".to_string(),
        ));
    }

    if document.jwks_uri.is_empty() {
        return Err(AppError::Bootstrap(
            "OIDC discovery jwks_uri must not be empty".to_string(),
        ));
    }

    Ok(())
}

fn normalize_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
}

fn normalize_email(value: String) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalized_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn is_secure_or_local(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://127.0.0.1")
        || value.starts_with("http://localhost")
        || value.starts_with("http://[::1]")
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::hash(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

fn append_query(base: &str, encoded_query: &str) -> String {
    if base.contains('?') {
        format!("{base}&{encoded_query}")
    } else {
        format!("{base}?{encoded_query}")
    }
}

#[derive(Debug, Serialize)]
struct OidcTokenRequest<'a> {
    grant_type: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
    client_id: &'a str,
    code_verifier: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
struct OidcTokenResponse {
    access_token: Option<String>,
    id_token: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OidcIdTokenClaims {
    sub: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OidcUserInfo {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use axum::Json;
    use axum::routing::get;
    use tokio::net::TcpListener;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn test_config(base_url: String) -> OidcConfig {
        OidcConfig {
            enabled: true,
            issuer_url: Some(base_url),
            client_id: Some("rscale".to_string()),
            client_secret: Some("secret".to_string()),
            scopes: vec!["openid".to_string(), "email".to_string()],
            allowed_domains: Vec::new(),
            allowed_users: Vec::new(),
            allowed_groups: Vec::new(),
            extra_params: BTreeMap::new(),
            request_timeout_secs: 2,
            total_timeout_secs: 5,
            auth_flow_ttl_secs: 300,
            validate_discovery_on_startup: true,
        }
    }

    #[tokio::test]
    async fn bootstrap_fetches_discovery_document() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let issuer = format!("http://{addr}");

        let app = axum::Router::new().route(
            "/.well-known/openid-configuration",
            get({
                let issuer = issuer.clone();
                move || async move {
                    Json(OidcDiscoveryDocument {
                        issuer: issuer.clone(),
                        authorization_endpoint: format!("{issuer}/authorize"),
                        token_endpoint: format!("{issuer}/token"),
                        jwks_uri: format!("{issuer}/jwks.json"),
                        userinfo_endpoint: Some(format!("{issuer}/userinfo")),
                        end_session_endpoint: None,
                    })
                }
            }),
        );

        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let config = test_config(issuer.clone());
        let discovery = bootstrap(&config)
            .await?
            .ok_or_else(|| std::io::Error::other("discovery should be returned"))?;

        assert_eq!(discovery.issuer, issuer);

        server.abort();
        Ok(())
    }

    #[test]
    fn validate_rejects_non_secure_non_local_issuer() {
        let config = test_config("http://example.com".to_string());
        assert!(validate(&config).is_err());
    }

    #[test]
    fn authorization_redirect_includes_state_nonce_and_pkce() -> TestResult {
        let runtime = OidcRuntime {
            client: OidcProviderClient {
                client: Client::builder("https://issuer.example.com").build()?,
                issuer_url: "https://issuer.example.com".to_string(),
            },
            discovery: OidcDiscoveryDocument {
                issuer: "https://issuer.example.com".to_string(),
                authorization_endpoint: "https://issuer.example.com/authorize".to_string(),
                token_endpoint: "https://issuer.example.com/token".to_string(),
                jwks_uri: "https://issuer.example.com/jwks.json".to_string(),
                userinfo_endpoint: None,
                end_session_endpoint: None,
            },
            public_base_url: "https://rscale.example.com".to_string(),
            client_id: "rscale".to_string(),
            client_secret: "secret".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
            allowed_domains: BTreeSet::new(),
            allowed_users: BTreeSet::new(),
            allowed_groups: BTreeSet::new(),
            extra_params: BTreeMap::from([("prompt".to_string(), "login".to_string())]),
            auth_flow_ttl_secs: 300,
        };
        let pending = PendingOidcAuthRequest {
            auth_id: "auth-1".to_string(),
            machine_key: "mkey:1".to_string(),
            node_key: "nodekey:1".to_string(),
            oidc_state: "state".to_string(),
            oidc_nonce: "nonce".to_string(),
            pkce_verifier: "verifier".to_string(),
            principal_issuer: None,
            principal_sub: None,
            principal_email: None,
            principal_name: None,
            principal_groups: Vec::new(),
            node_id: None,
            expires_at_unix_secs: 1,
            completed_at_unix_secs: None,
        };

        let redirect = runtime.authorization_redirect_url(&pending)?;

        assert!(redirect.contains("state=state"));
        assert!(redirect.contains("nonce=nonce"));
        assert!(redirect.contains("code_challenge_method=S256"));
        assert!(redirect.contains("prompt=login"));

        Ok(())
    }
}
