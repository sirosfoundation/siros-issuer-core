//! HTTP surface (design §6, §7). Wallet-facing OID4VCI endpoints and the
//! backend session API share one session store and one event channel:
//! both grants and both authorization modes converge on the core state
//! machine, never a parallel path.

mod backend;
mod presentation_auth;
mod wallet;

use crate::pdp::TrustPdp;
use crate::status::StatusAllocator;
use crate::store::StateLabel;
use crate::vault::Vault;
use siros_issuer_core::session::{SessionEvent, SessionId};
use siros_issuer_core::signer::Signer;
use siros_issuer_core::{Error, Result};
use siros_verifier_core::ts11::Catalog;
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use url::Url;

#[derive(Debug, Default)]
pub struct RefreshStatus {
    /// Unix seconds of the last successful refresh; 0 = never.
    pub last_ok_unix: AtomicI64,
    /// Last refresh error; cleared on success.
    pub last_error: RwLock<Option<String>>,
}

/// A session-state event for the SSE stream (and later, observers).
#[derive(Debug, Clone)]
pub struct SessionEventMessage {
    pub session_id: String,
    pub state: &'static str,
    pub unix: i64,
}

#[derive(Clone)]
pub struct AppState {
    /// Current working catalog snapshot. Readers clone the Arc; the
    /// refresh task swaps the whole snapshot (design §8.1).
    pub catalog: Arc<RwLock<Arc<Catalog>>>,
    pub issuer_base: Url,
    pub authorization_servers: Vec<Url>,
    pub refresh: Arc<RefreshStatus>,
    /// The session store. A trait object: the in-memory backend serves
    /// tests and single-process dev; production runs MongoDB behind the
    /// same contract (design §6.4) — atomic single-use offer/code claims
    /// across replicas.
    pub sessions: Arc<dyn crate::store::SessionStore>,
    /// DPoP proof validation (RFC 9449): replay cache + freshness window.
    pub dpop: Arc<crate::dpop::DpopValidator>,
    /// The most recent c_nonce minted at the public nonce endpoint (Final
    /// §7.1), where proofs bind before any session linkage exists.
    pub last_public_nonce: Arc<std::sync::Mutex<String>>,
    /// Mode A login handoff target (design §7.2): the integrator's page.
    pub login_url: Option<url::Url>,
    /// Pre-registered clients for the AS surface (design §12.2-resolved).
    pub clients: std::sync::Arc<crate::client_auth::ClientRegistry>,
    /// The attestation policy layer (vc translation).
    pub attestation: std::sync::Arc<dyn crate::client_auth::AttestationPolicy>,
    /// §5.1.2 scope → credential_configuration_id.
    pub scopes: std::collections::HashMap<String, String>,
    /// Endpoint paths + the request-encryption JWK (public members) for metadata.
    pub endpoint_paths: siros_issuer_core::oid4vci::EndpointPaths,
    /// The request-encryption key (private material, in-memory only) for
    /// decrypting wallet requests sent as application/jwt.
    pub request_encryption_key: Option<jose_rs::jwk::Jwk>,
    /// The issuer's certificate chain (DER, leaf first): the mdoc
    /// IssuerSigned x5chain. Loaded from signing.cert_chain_path.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// The signing effect interface (design §11.1): in-memory JWK provider
    /// or PKCS#11 HSM provider — issuance code never touches key material.
    pub signer: Arc<dyn Signer>,
    pub vault: Arc<Vault>,
    pub pdp: Arc<dyn TrustPdp>,
    pub allocator: Arc<dyn StatusAllocator>,
    pub events_tx: broadcast::Sender<SessionEventMessage>,
    pub credential_validity_seconds: i64,
    pub access_token_ttl_seconds: i64,
    pub c_nonce_ttl_seconds: i64,
    /// ZK rulebooks (design §8.3 item 5): name → bundle. General data —
    /// issuance resolves the one bundle governing the session's
    /// credential (startup validation guarantees uniqueness).
    pub rulebooks: std::collections::HashMap<String, crate::config::RulebookCfg>,
    /// The circuit catalog (§8.3 item 1): zk issuance parameters by
    /// system+doctype. `None` = no source configured (a pinned rulebook
    /// stands in; unpinned zk_systems refuse).
    pub circuit_manifest: Option<std::sync::Arc<siros_issuer_core::zk::circuit::CircuitManifest>>,
    /// Wallet-surface rate limiting (§11): vc defaults unless configured.
    pub rate_limit: crate::rate_limit::RateLimitCfg,
}

impl AppState {
    /// The one rulebook governing a credential configuration (design
    /// §8.3 item 5), if any: a plain (non-ZK) credential has none.
    pub fn rulebook_for(
        &self,
        credential_configuration_id: &str,
    ) -> Option<(&str, &crate::config::RulebookCfg)> {
        self.rulebooks
            .iter()
            .find(|(_, rulebook)| {
                rulebook
                    .credentials
                    .iter()
                    .any(|credential| credential == credential_configuration_id)
            })
            .map(|(name, rulebook)| (name.as_str(), rulebook))
    }
}

impl AppState {
    /// §5.1.2: resolve a scope to a credential configuration id from the
    /// deployment's scope map.
    pub fn configuration_for_scope(&self, scope: &str) -> Option<String> {
        self.scopes.get(scope).cloned()
    }

    /// The registered client's first configured scope, for PAR requests
    /// that carry neither authorization_details nor a scope parameter.
    pub fn scopes_for_client(&self, client_id: &str) -> Option<String> {
        self.clients
            .clients
            .get(client_id)
            .and_then(|client| client.scope.clone())
    }

    pub fn catalog_snapshot(&self) -> Arc<Catalog> {
        self.catalog.read().expect("catalog lock poisoned").clone()
    }

    /// Apply a state-machine event and broadcast it. Every transition in
    /// every handler goes through here — the store checks legality, this
    /// publishes the result.
    pub async fn step(
        &self,
        id: &SessionId,
        event: SessionEvent,
    ) -> Result<crate::store::SessionRecord> {
        let now = crate::status::now_unix();
        let record = self.sessions.transition(id, event, now).await?;
        let _ = self.events_tx.send(SessionEventMessage {
            session_id: id.as_str().to_owned(),
            state: record.state.label(),
            unix: now,
        });
        Ok(record)
    }
}

pub fn router(state: AppState) -> axum::Router {
    let limits = crate::rate_limit::RateLimits {
        inner: std::sync::Arc::new(crate::rate_limit::WalletRateLimits::from_config(
            &state.rate_limit,
        )),
    };
    axum::Router::new()
        // Both spellings, for wallet compatibility (vc registers the
        // trailing-slash variant for the wwWallet; design §7.1).
        .route(
            "/.well-known/openid-credential-issuer",
            axum::routing::get(wallet::credential_issuer_metadata),
        )
        .route(
            "/.well-known/openid-credential-issuer/",
            axum::routing::get(wallet::credential_issuer_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(wallet::oauth_authorization_server),
        )
        .route("/jwks", axum::routing::get(wallet::jwks))
        .route("/healthz", axum::routing::get(wallet::health))
        // Wallet-facing issuance endpoints (P1: pre-authorized grant).
        .route(
            "/credential-offer/{uuid}",
            axum::routing::get(wallet::credential_offer),
        )
        .route("/nonce", axum::routing::post(wallet::nonce))
        // P2: the wallet-initiated authorization-code grant (design §7.2).
        .route("/op/par", axum::routing::post(wallet::par))
        // P3: Mode B — authorization via OpenID4VP presentation (§7.3).
        .route(
            "/authorization-challenge",
            axum::routing::post(presentation_auth::authorization_challenge),
        )
        .route(
            "/authorization-challenge/response/{challenge_handle}",
            axum::routing::post(presentation_auth::authorization_challenge_response),
        )
        .route("/authorize", axum::routing::get(wallet::authorize))
        .route("/token", axum::routing::post(wallet::token))
        .route("/credential", axum::routing::post(wallet::credential))
        .route(
            "/batch-credential",
            axum::routing::post(wallet::batch_credential),
        )
        .route("/notification", axum::routing::post(wallet::notification))
        // Backend session API (design §6.1).
        .route(
            "/api/v1/issuance/sessions",
            axum::routing::post(backend::create_session),
        )
        .route(
            "/api/v1/issuance/sessions/{issuer_state}/authorize",
            axum::routing::post(backend::complete_authorization),
        )
        .route(
            "/api/v1/issuance/sessions/{id}",
            axum::routing::get(backend::get_session).delete(backend::delete_session),
        )
        .route(
            "/api/v1/issuance/sessions/{id}/events",
            axum::routing::get(backend::session_events),
        )
        .route(
            "/api/v1/issuance/sessions/{id}/revoke",
            axum::routing::post(backend::revoke_session),
        )
        .route(
            "/api/v1/issuance/sessions/{id}/preview",
            axum::routing::get(backend::preview_session),
        )
        .layer(axum::middleware::from_fn_with_state(
            limits.clone(),
            crate::rate_limit::rate_limit_middleware,
        ))
        .with_state(state)
}

/// Random handles: pre-auth codes, access tokens, nonces, offer uuids,
/// notification ids. All opaque, unguessable, and never derived from
/// subject data.
pub fn random_handle(prefix: &str, bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("OS randomness");
    format!("{prefix}{}", siros_issuer_core::sdjwt_issue::b64u(&buf))
}

pub fn session_id_from_str(value: &str) -> Result<SessionId> {
    SessionId::from_hex(value).map_err(|_| Error::invalid_input("malformed session id"))
}

/// Order the label rows for a consistent SSE/history JSON shape.
pub fn history_json(record: &crate::store::SessionRecord) -> serde_json::Value {
    serde_json::json!({
        "session_id": record.id.as_str(),
        "state": record.state.label(),
        "created_at_unix": record.created_at_unix,
        "expires_at_unix": record.expires_at_unix,
        "events": record.history.iter().map(|(unix, state)| {
            serde_json::json!({"unix": unix, "state": state})
        }).collect::<Vec<_>>(),
    })
}
