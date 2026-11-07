//! The trust decision point boundary (design §11). go-trust decides; the
//! issuer constructs AuthZEN evidence and consumes a permit. Fail-closed:
//! any transport or parse failure, or a non-Permit decision, is a refusal
//! (`pdp_unavailable` / `pdp_denied`). There is no local trust fallback.

use serde::Deserialize;
use siros_issuer_core::error::code;
use siros_issuer_core::trust::IssuanceTrustQuery;
use siros_issuer_core::{Error, Result};

#[async_trait::async_trait]
pub trait TrustPdp: Send + Sync {
    async fn permit(&self, query: &IssuanceTrustQuery) -> Result<()>;

    /// Mode B (design §7.3): trust in a *presented* credential — the
    /// AuthZEN query verifier-core builds from a verified presentation.
    /// Fails closed by default: an implementation that does not decide
    /// presentations never permits them.
    async fn permit_presentation(
        &self,
        _query: &siros_verifier_core::trust::TrustQuery,
    ) -> Result<()> {
        Err(Error::new(
            code::PDP_UNAVAILABLE,
            "this trust decision point does not evaluate presentations; refusing",
        ))
    }
}

/// No PDP configured: every decision is `pdp_unavailable`. Issuance cannot
/// proceed; metadata and readiness still serve.
pub struct FailClosedPdp;

#[async_trait::async_trait]
impl TrustPdp for FailClosedPdp {
    async fn permit(&self, _query: &IssuanceTrustQuery) -> Result<()> {
        Err(Error::new(
            code::PDP_UNAVAILABLE,
            "no trust decision point is configured; refusing issuance",
        ))
    }
}

/// go-trust client over the AuthZEN evaluation endpoint.
pub struct AuthZenPdp {
    url: url::Url,
    client: reqwest::Client,
}

/// go-trust answers `{"decision": true, ...}`; AuthZEN drafts show the
/// string "Permit". Accept both.
#[derive(Deserialize)]
struct EvaluationResponse {
    decision: serde_json::Value,
}

#[async_trait::async_trait]
impl TrustPdp for AuthZenPdp {
    async fn permit(&self, query: &IssuanceTrustQuery) -> Result<()> {
        self.evaluate(&query.to_authzen()).await
    }

    async fn permit_presentation(
        &self,
        query: &siros_verifier_core::trust::TrustQuery,
    ) -> Result<()> {
        self.evaluate(&query.to_authzen()).await
    }
}

impl AuthZenPdp {
    pub fn new(url: url::Url) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
        }
    }

    /// One AuthZEN evaluation (design §11): go-trust decides; anything
    /// but a Permit is a refusal. Shared by both query kinds.
    async fn evaluate(&self, authzen: &serde_json::Value) -> Result<()> {
        let response = self
            .client
            .post(self.url.as_str())
            .json(authzen)
            .send()
            .await
            .map_err(|e| Error::new(code::PDP_UNAVAILABLE, format!("pdp transport: {e}")))?;
        if !response.status().is_success() {
            return Err(Error::new(
                code::PDP_UNAVAILABLE,
                format!("pdp answered HTTP {}", response.status()),
            ));
        }
        let body: EvaluationResponse = response.json().await.map_err(|e| {
            Error::new(
                code::PDP_UNAVAILABLE,
                format!("pdp response unreadable: {e}"),
            )
        })?;
        let permitted = match &body.decision {
            serde_json::Value::Bool(value) => *value,
            serde_json::Value::String(value) => value == "Permit",
            _ => false,
        };
        if permitted {
            Ok(())
        } else {
            Err(Error::new(
                code::PDP_DENIED,
                format!("pdp decision {}", body.decision),
            ))
        }
    }
}
