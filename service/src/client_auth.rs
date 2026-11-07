//! Client authentication for the AS surface (design §7.2, §12.2-resolved):
//! pre-registered clients with configured JWK sets, verified by RFC 7523
//! `private_key_jwt` client assertions — the only client_auth_type the
//! OIDF issuer plan selects modules for.
//!
//! **Client attestation policy layer** (translated from vc's
//! `pkg/trust/wallet_attestation_policy.go`): vc separates *trust* (the
//! PDP validates the wallet provider) from *tier authorization* (an
//! extensible, config-driven rule engine decides which attestation tier
//! may request which credential scope; default-open when unconfigured).
//! The translation keeps that split with two providers:
//!
//! - `WildcardRulesPolicy` — vc's documented rule shape
//!   `(wallet (attestation_source <tier>)(scope <scope>)(issuer <issuer>))`
//!   as native config (`rules = [{ attestation_source = "…", scope = "…",
//!   issuer = "…" }]`), `*` wildcards, empty rules = default open.
//! - `PdpAttestationPolicy` — the same three attributes as AuthZEN
//!   parameters to go-trust: the production path, keeping every trust
//!   decision external (AGENTS).
//!
//! The attestation-JWT verification itself (etsi x5c / ietf iss-JWKS
//! modes, vc's `WalletAttestationEvaluator`) is the follow-up when the
//! suite's `client_attestation` variants come into scope; the policy layer
//! it feeds is the piece that had to land now, shaped like vc's.

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use siros_issuer_core::error::code;
use siros_issuer_core::sdjwt_issue::{b64u, b64u_decode};
use siros_issuer_core::{Error, Result};
use std::collections::HashMap;
use std::sync::RwLock;

/// One pre-registered client (the OIDF plan's `client_id`/jwks config
/// fields map here). Attestation-based clients need no entry — vc's
/// wallet-attestation tier.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientRegistration {
    /// The client's public keys (JWK set members), for private_key_jwt.
    #[serde(default)]
    pub jwks: Vec<Value>,
    /// Allowed OAuth redirect_uris for the authorization-code grant.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Local-test-only: accept any redirect_uri for this client. The
    /// conformance suite generates its own callback URIs per module, so
    /// an exhaustive allowlist is impossible there. Never set this
    /// outside a test deployment.
    #[serde(default)]
    pub allow_any_redirect_uri: bool,
    /// The client's credential scope (§5.1.2), for PAR requests that
    /// carry no authorization_details and no scope parameter.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Transparent: `[authorization.clients.<client_id>]` maps the client_id
/// straight to its registration (no `clients` wrapper in TOML).
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(transparent)]
pub struct ClientRegistry {
    pub clients: HashMap<String, ClientRegistration>,
}

impl ClientRegistry {
    pub fn client(&self, client_id: &str) -> Result<&ClientRegistration> {
        self.clients
            .get(client_id)
            .ok_or_else(|| Error::new(code::INVALID_INPUT, format!("unknown client {client_id}")))
    }
}

/// The attributes vc's policy layer queries on: attestation tier, the
/// requested scope, and the wallet provider issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationAttributes {
    pub attestation_source: String,
    pub scope: String,
    pub issuer: String,
}

impl AttestationAttributes {
    /// vc's "unknown"/"*" defaults for absent attributes.
    pub fn defaults(&self) -> Self {
        Self {
            attestation_source: if self.attestation_source.is_empty() {
                "unknown".to_owned()
            } else {
                self.attestation_source.clone()
            },
            scope: if self.scope.is_empty() {
                "*".to_owned()
            } else {
                self.scope.clone()
            },
            issuer: if self.issuer.is_empty() {
                "*".to_owned()
            } else {
                self.issuer.clone()
            },
        }
    }
}

/// The policy layer (vc `WalletAttestationPolicyEngine` translated): runs
/// *after* trust, decides tier → scope authorization. Async so the PDP
/// provider can call go-trust.
#[async_trait::async_trait]
pub trait AttestationPolicy: Send + Sync {
    async fn authorize(&self, attributes: &AttestationAttributes) -> Result<()>;
}

/// One rule: attribute match with `*` wildcards — vc's rule semantics.
#[derive(Debug, Clone, Deserialize)]
pub struct AttestationRule {
    #[serde(default)]
    pub attestation_source: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub issuer: String,
}

impl AttestationRule {
    fn matches(&self, attributes: &AttestationAttributes) -> bool {
        let wildcard = |rule: &str, value: &str| rule == "*" || rule.is_empty() || rule == value;
        wildcard(&self.attestation_source, &attributes.attestation_source)
            && wildcard(&self.scope, &attributes.scope)
            && wildcard(&self.issuer, &attributes.issuer)
    }
}

/// vc's default-open semantics: no rules ⇒ every trusted wallet authorized.
pub struct WildcardRulesPolicy {
    rules: Vec<AttestationRule>,
}

impl WildcardRulesPolicy {
    pub fn new(rules: Vec<AttestationRule>) -> Self {
        Self { rules }
    }
}

#[async_trait::async_trait]
impl AttestationPolicy for WildcardRulesPolicy {
    async fn authorize(&self, attributes: &AttestationAttributes) -> Result<()> {
        if self.rules.is_empty() {
            return Ok(()); // default open, exactly vc's nil-engine behavior
        }
        let attributes = attributes.defaults();
        if self.rules.iter().any(|rule| rule.matches(&attributes)) {
            Ok(())
        } else {
            Err(Error::new(
                code::PDP_DENIED,
                format!(
                    "attestation tier {:?} not authorized for scope {:?}",
                    attributes.attestation_source, attributes.scope
                ),
            ))
        }
    }
}

/// The production path: the same three attributes as AuthZEN parameters
/// to go-trust. Trust stays external; this is the issuer-side analogue of
/// vc pointing its evaluator at the PDP.
pub struct PdpAttestationPolicy {
    pdp: std::sync::Arc<dyn crate::pdp::TrustPdp>,
}

impl PdpAttestationPolicy {
    pub fn new(pdp: std::sync::Arc<dyn crate::pdp::TrustPdp>) -> Self {
        Self { pdp }
    }
}

#[async_trait::async_trait]
impl AttestationPolicy for PdpAttestationPolicy {
    async fn authorize(&self, attributes: &AttestationAttributes) -> Result<()> {
        let attributes = attributes.defaults();
        let query = siros_issuer_core::trust::IssuanceTrustQuery::new(
            format!("attestation:{}", attributes.attestation_source),
            Vec::new(),
            Value::Null,
            attributes.scope.clone(),
            Some(attributes.issuer.clone()),
        );
        self.pdp.permit(&query).await
    }
}

/// RFC 7523 private_key_jwt verification for one pre-registered client:
/// ES256, iss == sub == client_id, aud matches, exp/iat windows, signature
/// against one of the client's registered keys. DPoP jkt is not part of
/// the assertion; the token endpoint binds it separately.
pub fn verify_private_key_jwt(
    registry: &ClientRegistry,
    assertion: &str,
    client_id: Option<&str>,
    expected_aud: &url::Url,
    now: i64,
    leeway_secs: i64,
) -> Result<()> {
    // RFC 7523 §3: the client may be identified by the assertion's iss
    // alone — the suite's token requests carry no client_id form param.
    let derived_client_id: String;
    let client_id: &str = match client_id {
        Some(id) => id,
        None => {
            let payload_b64 = assertion.split('.').nth(1).unwrap_or_default();
            let claims: Value = serde_json::from_slice(
                &b64u_decode(payload_b64)
                    .map_err(|_| Error::new(code::INVALID_INPUT, "assertion payload"))?,
            )
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("assertion claims: {e}")))?;
            derived_client_id = claims
                .get("iss")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::new(code::INVALID_INPUT, "assertion has no iss"))?
                .to_owned();
            &derived_client_id
        }
    };
    let client = registry.client(client_id)?;
    if client.jwks.is_empty() {
        return Err(Error::new(
            code::INVALID_INPUT,
            "client has no registered keys for private_key_jwt",
        ));
    }
    let mut parts = assertion.split('.');
    let (h, _p, _s) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) if parts.next().is_none() => (h, p, s),
        _ => {
            return Err(Error::new(
                code::INVALID_INPUT,
                "client assertion is not a compact JWT",
            ))
        }
    };
    let header: Value = serde_json::from_slice(
        &b64u_decode(h).map_err(|_| Error::new(code::INVALID_INPUT, "assertion header"))?,
    )
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("assertion header: {e}")))?;
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(Error::new(
            code::INVALID_INPUT,
            "assertion alg is not ES256",
        ));
    }

    // Claims before signature: the signature check needs the key, and the
    // key choice is the client's registered set (never the token's own
    // embedded jwk — the registry is authoritative).
    let payload_b64 = assertion.split('.').nth(1).unwrap_or_default();
    let claims: Value = serde_json::from_slice(
        &b64u_decode(payload_b64)
            .map_err(|_| Error::new(code::INVALID_INPUT, "assertion payload"))?,
    )
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("assertion claims: {e}")))?;
    let iss = claims.get("iss").and_then(Value::as_str);
    let sub = claims.get("sub").and_then(Value::as_str);
    if iss != Some(client_id) || sub != Some(client_id) {
        return Err(Error::new(
            code::INVALID_INPUT,
            "assertion iss/sub != client_id",
        ));
    }
    let aud = claims
        .get("aud")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "assertion has no aud"))?;
    if aud != siros_issuer_core::oid4vci::issuer_identifier(expected_aud) {
        return Err(Error::new(code::INVALID_INPUT, "assertion aud mismatch"));
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "assertion has no exp"))?;
    if now >= exp + leeway_secs {
        return Err(Error::new(code::INVALID_INPUT, "assertion expired"));
    }
    if let Some(iat) = claims.get("iat").and_then(Value::as_i64) {
        if iat > now + leeway_secs {
            return Err(Error::new(
                code::INVALID_INPUT,
                "assertion issued in the future",
            ));
        }
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let _ = jti; // registry clients are pre-registered; replay is a P2+ cache concern

    // Signature: try each registered key; one must verify.
    let mut verified = false;
    for jwk_value in &client.jwks {
        let jwk: jose_rs::jwk::Jwk = match serde_json::from_value(jwk_value.clone()) {
            Ok(jwk) => jwk,
            Err(_) => continue,
        };
        if jose_rs::jws::compact::verify_with_jwk(&jwk, assertion).is_ok() {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(Error::new(
            code::INVALID_INPUT,
            "assertion signature verification failed",
        ));
    }
    Ok(())
}

/// sha256 thumbprint helper (registry key ids, debugging).
pub fn thumbprint_of(jwk_value: &Value) -> String {
    let canonical = serde_json::json!({
        "crv": jwk_value.get("crv"),
        "kty": jwk_value.get("kty"),
        "x": jwk_value.get("x"),
        "y": jwk_value.get("y"),
    });
    b64u(&Sha256::digest(canonical.to_string().as_bytes()))
}

/// A jti replay cache for client assertions (P2 hardening; kept simple
/// and bounded, mirroring the DPoP cache).
pub struct AssertionReplayCache {
    seen: RwLock<HashMap<String, i64>>,
    window_secs: i64,
}

impl AssertionReplayCache {
    pub fn new(window_secs: i64) -> Self {
        Self {
            seen: RwLock::new(HashMap::new()),
            window_secs,
        }
    }

    pub fn check_and_record(&self, jti: &str, iat: i64, now: i64) -> Result<()> {
        let mut seen = self
            .seen
            .write()
            .map_err(|_| Error::new(code::TRANSPORT, "replay cache lock poisoned"))?;
        seen.retain(|_, seen_iat| now.saturating_sub(*seen_iat) <= 2 * self.window_secs);
        if seen.insert(jti.to_owned(), iat).is_some() {
            return Err(Error::new(code::INVALID_INPUT, "assertion jti replayed"));
        }
        Ok(())
    }
}
