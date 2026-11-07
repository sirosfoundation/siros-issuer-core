//! Wallet-surface rate limiting (design §11): per-endpoint, per-client
//! counters with 1-minute TTL windows — vc's `httphelpers.RateLimiter`
//! semantics, ported as config (`[rate_limit]`; vc's defaults are this
//! crate's defaults). Fail-closed: a limiter failure is 503, never an
//! open window.
//!
//! The limiter is in-process state (vc uses the shared cache counter for
//! multi-replica deployments; a Mongo `RateLimitCounter` backend is the
//! same shape if a deployment needs cross-replica limits — the in-memory
//! counter serves the single-process default and tests).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use siros_issuer_core::{Error, Result};

/// One limiter per endpoint: `requests_per_minute` per client per window.
#[derive(Debug)]
pub struct RateLimiter {
    requests_per_minute: u64,
    window: std::time::Duration,
    /// (endpoint, client) → (count, window start). Pruned on tick.
    counters: Mutex<HashMap<(String, String), (u64, Instant)>>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u64) -> Self {
        Self {
            requests_per_minute,
            window: std::time::Duration::from_secs(60),
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Count one request from `client` at `endpoint`. `true` = allowed;
    /// `false` = the window's budget is spent (429 territory). A poisoned
    /// lock is a limiter failure: fail closed.
    pub fn allow(&self, endpoint: &str, client: &str) -> Result<bool> {
        let mut counters = self.counters.lock().map_err(|_| {
            Error::new(
                siros_issuer_core::error::code::TRANSPORT,
                "rate limiter unavailable",
            )
        })?;
        let now = Instant::now();
        let key = (endpoint.to_owned(), client.to_owned());
        let entry = counters.get_mut(&key);
        let (count, start) = match entry {
            Some((count, start)) if now.duration_since(*start) < self.window => (*count, *start),
            _ => {
                // New (or expired) window.
                counters.insert(key.clone(), (0, now));
                (0, now)
            }
        };
        let allowed = count < self.requests_per_minute;
        if allowed {
            counters.insert(key, (count + 1, start));
        }
        // Prune expired windows opportunistically (bounded by distinct
        // clients per endpoint — fine in-process).
        counters.retain(|_, (_, start)| now.duration_since(*start) < self.window);
        Ok(allowed)
    }
}

/// `[rate_limit]` — vc's defaults ported as config (its
/// `CredentialOfferRequestsPerMinute`/`CredentialRequestsPerMinute`/
/// `AuthorizationChallengeRequestsPerMinute`/`TokenRequestsPerMinute`).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitCfg {
    #[serde(default = "default_offer_rpm")]
    pub offer_per_minute: u64,
    /// The credential + batch-credential endpoints.
    #[serde(default = "default_credential_rpm")]
    pub credential_per_minute: u64,
    /// The token endpoint (both grants).
    #[serde(default = "default_token_rpm")]
    pub token_per_minute: u64,
    /// The authorization-challenge endpoint (Mode B).
    #[serde(default = "default_challenge_rpm")]
    pub challenge_per_minute: u64,
}

fn default_offer_rpm() -> u64 {
    20
}
fn default_credential_rpm() -> u64 {
    30
}
fn default_token_rpm() -> u64 {
    20
}
fn default_challenge_rpm() -> u64 {
    20
}

impl Default for RateLimitCfg {
    fn default() -> Self {
        Self {
            offer_per_minute: default_offer_rpm(),
            credential_per_minute: default_credential_rpm(),
            token_per_minute: default_token_rpm(),
            challenge_per_minute: default_challenge_rpm(),
        }
    }
}

/// The wallet surface's limiters (per-endpoint).
#[derive(Debug)]
pub struct WalletRateLimits {
    pub offer: RateLimiter,
    pub credential: RateLimiter,
    pub token: RateLimiter,
    pub challenge: RateLimiter,
}

impl WalletRateLimits {
    pub fn from_config(cfg: &RateLimitCfg) -> Self {
        Self {
            offer: RateLimiter::new(cfg.offer_per_minute),
            credential: RateLimiter::new(cfg.credential_per_minute),
            token: RateLimiter::new(cfg.token_per_minute),
            challenge: RateLimiter::new(cfg.challenge_per_minute),
        }
    }
}

/// The client key for one request: the connecting peer's IP. The
/// forwarded-for chain is deliberately NOT trusted here (the TLS proxy is
/// the only hop that may set it; which proxy to trust is deployment
/// config, and the in-process default counts by what actually connects).
pub fn client_key(remote: Option<&std::net::SocketAddr>) -> String {
    remote
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

// ─────────────────────────────────────────────────────────────────────────
// The middleware layer (per-endpoint, per-client; 429 on budget spent,
// 503 on limiter failure — fail closed)
// ─────────────────────────────────────────────────────────────────────────

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use std::sync::Arc;

/// Which limiter serves one request (by path + method). The wallet
/// surface's rate-sensitive endpoints (design §11; the metadata/JWKS/
/// health GETs stay unlimited — cache-friendly read paths).
#[derive(Clone)]
pub struct RateLimits {
    pub inner: Arc<WalletRateLimits>,
}

/// The middleware: per-endpoint, per-client budget; 429 when spent,
/// 503 on limiter failure (fail closed — vc's semantics). The
/// `ConnectInfo` extension supplies the remote when the server is
/// built with it (main is).
pub async fn rate_limit_middleware(
    axum::extract::State(limits): axum::extract::State<RateLimits>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    // The remote rides the request extensions when the server was built
    // with into_make_service_with_connect_info (main is); absent (tests
    // that serve the router plainly) the key falls back to "unknown"
    // — one budget, still enforced.
    let remote = request.extensions().get::<std::net::SocketAddr>().copied();
    let client = client_key(remote.as_ref());
    let allowed = |limiter: &RateLimiter| limiter.allow(&path, &client);
    let result = match (method.as_str(), path.as_str()) {
        ("GET", p) if p.starts_with("/credential-offer/") => allowed(&limits.inner.offer),
        ("POST", "/token") => allowed(&limits.inner.token),
        ("POST", "/credential") | ("POST", "/batch-credential") => {
            allowed(&limits.inner.credential)
        }
        ("POST", "/authorization-challenge") => allowed(&limits.inner.challenge),
        ("POST", p) if p.starts_with("/authorization-challenge/response/") => {
            // The Mode B response callback — the challenge budget
            // (a wallet answering the challenge it was given).
            allowed(&limits.inner.challenge)
        }
        // Unlimited by default: metadata GETs, JWKS, health, the
        // backend session API (authenticator-authenticated).
        _ => Ok(true),
    };
    match result {
        Ok(true) => next.run(request).await,
        // 429 + the no-store cache discipline (a rate response is never
        // cacheable). The OAuth error shape (RFC 6753 style).
        Ok(false) => axum::response::IntoResponse::into_response((
            StatusCode::TOO_MANY_REQUESTS,
            [("cache-control", "no-store")],
            axum::Json(serde_json::json!({
                "error": "rate_limit_exceeded",
                "error_description": "Too many requests. Please try again later.",
            })),
        )),
        // A limiter failure fails closed (vc's semantics).
        Err(_) => axum::response::IntoResponse::into_response((
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "error": "service_unavailable",
                "error_description": "Rate limiter unavailable. Please try again later.",
            })),
        )),
    }
}
