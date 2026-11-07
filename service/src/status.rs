//! siros-status-service client boundary (design §9). Allocation happens at
//! credential-signing time; revocation PATCHes the allocated index. The
//! core owns the wire types (`siros_issuer_core::status_client`); this is
//! the service's transport against the deployed AS + ingestion endpoints.
//! With no status service configured, issuance fails closed: no credential
//! is minted without a revocation handle.

use siros_issuer_core::status_client::{AllocateRequest, Status, StatusRef, UpdateRequest};
use siros_issuer_core::{Error, Result};
use url::Url;

#[async_trait::async_trait]
pub trait StatusAllocator: Send + Sync {
    /// Allocate a status-list index for one credential.
    async fn allocate(&self, exp: Option<String>) -> Result<StatusRef>;
    /// Update the status bit of an allocated index.
    async fn update(&self, list_url: &Url, index: u64, status: Status) -> Result<()>;
}

/// Fail-closed default when no status service is configured.
pub struct NoAllocator;

#[async_trait::async_trait]
impl StatusAllocator for NoAllocator {
    async fn allocate(&self, _exp: Option<String>) -> Result<StatusRef> {
        Err(Error::configuration(
            "no status service configured; a credential cannot be issued without a revocation handle",
        ))
    }

    async fn update(&self, _list_url: &Url, _index: u64, _status: Status) -> Result<()> {
        Err(Error::configuration(
            "no status service configured; revocation is unavailable",
        ))
    }
}

/// The deployed siros-status-service: a client-assertion token from the AS,
/// then `POST /allocate` and `PATCH /status/{id}/{n}` through the ingestion
/// base URL. Wire shapes per the status service's README.
pub struct SirosStatusClient {
    client: reqwest::Client,
    as_url: Url,
    ingestion_base: Url,
    /// The signer for the RFC 7523 client assertion (HSM-capable, §11.1).
    signer: std::sync::Arc<dyn siros_issuer_core::signer::Signer>,
    issuer_id: String,
}

#[derive(serde::Deserialize)]
struct TokenReply {
    access_token: String,
}

#[derive(serde::Deserialize)]
struct AllocateReplyWire {
    list_url: Url,
    index: u64,
    /// The allocation's expiry. Carried through to credential `exp`
    /// alignment with P2's deferred issuance (design §16.1 D8).
    #[serde(default)]
    #[allow(dead_code)]
    exp: Option<String>,
}

impl SirosStatusClient {
    pub fn new(
        as_url: Url,
        ingestion_base: Url,
        signer: std::sync::Arc<dyn siros_issuer_core::signer::Signer>,
        issuer_id: String,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            as_url,
            ingestion_base,
            signer,
            issuer_id,
        }
    }

    fn list_id(&self, list_url: &Url) -> Result<String> {
        list_url
            .path_segments()
            .and_then(|mut s| s.next_back().map(str::to_owned))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::transport("list_url has no id segment"))
    }

    async fn access_token(&self) -> Result<String> {
        // RFC 7523 client assertion: iss == sub == the issuer's id,
        // aud == the AS's *token endpoint* (siros-status-service's
        // clientassertion.Verify checks BASE_URL + "/token").
        let now = now_unix();
        let kid = self.signer.public_jwk()?.kid.clone().unwrap_or_default();
        // Explicit path construction: `Url::join("token")` on a base
        // without a trailing slash replaces the last segment (the AS
        // under a path prefix would lose it).
        let mut token_url = self.as_url.clone();
        let base_path = token_url.path().trim_end_matches('/');
        token_url.set_path(&format!("{base_path}/token"));
        let claims = serde_json::json!({
            "iss": self.issuer_id,
            "sub": self.issuer_id,
            "aud": token_url.as_str(),
            "iat": now,
            "exp": now + 300,
            "jti": format!("{kid}{}", now),
        });
        let mut header = jose_rs::JoseHeader::new("ES256");
        header.kid = Some(kid);
        // Embed the public JWK (RFC 7523 §3 / the AS's clientassertion
        // verifies against the header's key material — jwk or x5c; a bare
        // kid gives it nothing to verify with).
        let public = self.signer.public_jwk()?;
        header.jwk =
            Some(serde_json::to_value(&public).map_err(|e| Error::invalid_input(e.to_string()))?);
        let payload =
            serde_json::to_vec(&claims).map_err(|e| Error::invalid_input(e.to_string()))?;
        let assertion = self.signer.sign_es256(&header, &payload)?;
        let response = self
            .client
            .post(token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| Error::transport(format!("status AS: {e}")))?;
        if !response.status().is_success() {
            return Err(Error::transport(format!(
                "status AS answered HTTP {}",
                response.status()
            )));
        }
        let reply: TokenReply = response
            .json()
            .await
            .map_err(|e| Error::transport(format!("status AS reply: {e}")))?;
        Ok(reply.access_token)
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[async_trait::async_trait]
impl StatusAllocator for SirosStatusClient {
    async fn allocate(&self, exp: Option<String>) -> Result<StatusRef> {
        let token = self.access_token().await?;
        let path = self.ingestion_base.path().trim_end_matches('/').to_owned();
        let mut url = self.ingestion_base.clone();
        url.set_path(&format!("{path}/allocate"));
        let reply = self
            .client
            .post(url)
            .bearer_auth(&token)
            .json(&AllocateRequest { exp })
            .send()
            .await
            .map_err(|e| Error::transport(format!("status allocation: {e}")))?;
        if !reply.status().is_success() {
            return Err(Error::transport(format!(
                "status allocation answered HTTP {}",
                reply.status()
            )));
        }
        let wire: AllocateReplyWire = reply
            .json()
            .await
            .map_err(|e| Error::transport(format!("allocation reply: {e}")))?;
        Ok(StatusRef {
            list_url: wire.list_url,
            index: wire.index,
        })
    }

    async fn update(&self, list_url: &Url, index: u64, status: Status) -> Result<()> {
        let token = self.access_token().await?;
        let list_id = self.list_id(list_url)?;
        let url = self
            .ingestion_base
            .join(&format!("status/{list_id}/{index}"))
            .map_err(|e| Error::configuration(e.to_string()))?;
        let response = self
            .client
            .patch(url)
            .bearer_auth(&token)
            .json(&UpdateRequest { status })
            .send()
            .await
            .map_err(|e| Error::transport(format!("status update: {e}")))?;
        if !response.status().is_success() {
            return Err(Error::transport(format!(
                "status update answered HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}
