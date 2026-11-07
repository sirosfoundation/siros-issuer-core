//! Wallet-surface rate limiting tests (design §11, vc's `RateLimiter`
//! semantics ported): per-endpoint per-client budget, 1-minute window,
//! fail-closed.

use siros_issuer_service::rate_limit::{client_key, RateLimiter, WalletRateLimits};

#[test]
fn budget_per_client_per_window() {
    let limiter = RateLimiter::new(3);
    for i in 0..3 {
        assert!(
            limiter.allow("/credential", "client-a").unwrap(),
            "request {i}"
        );
    }
    // The 4th from the same client in the window: refused.
    assert!(!limiter.allow("/credential", "client-a").unwrap());
    // A DIFFERENT client has its own budget.
    assert!(limiter.allow("/credential", "client-b").unwrap());
    // A different ENDPOINT has its own budget.
    assert!(limiter.allow("/token", "client-a").unwrap());
}

#[test]
fn counts_are_per_endpoint_not_per_raw_path() {
    // The credential endpoint's budget covers the plain path — no
    // budget multiplication per parameterized route.
    let limiter = RateLimiter::new(2);
    assert!(limiter.allow("/credential", "a").unwrap());
    assert!(limiter.allow("/credential", "a").unwrap());
    assert!(!limiter.allow("/credential", "a").unwrap());
}

#[test]
fn the_defaults_are_vc_s_ported() {
    let cfg = siros_issuer_service::rate_limit::RateLimitCfg::default();
    assert_eq!(cfg.offer_per_minute, 20);
    assert_eq!(cfg.credential_per_minute, 30);
    assert_eq!(cfg.token_per_minute, 20);
    assert_eq!(cfg.challenge_per_minute, 20);
    let limits = WalletRateLimits::from_config(&cfg);
    // Distinct limiters per endpoint (per-endpoint budgets).
    assert!(limits.offer.allow("/x", "a").unwrap());
    assert!(limits.credential.allow("/x", "a").unwrap());
    assert!(limits.token.allow("/x", "a").unwrap());
    assert!(limits.challenge.allow("/x", "a").unwrap());
}

#[test]
fn client_key_is_the_peer_ip() {
    use std::net::SocketAddr;
    let addr: SocketAddr = "127.0.0.1:44211".parse().unwrap();
    assert_eq!(client_key(Some(&addr)), "127.0.0.1");
    // Absent remote: one shared budget (still enforced).
    assert_eq!(client_key(None), "unknown");
}
