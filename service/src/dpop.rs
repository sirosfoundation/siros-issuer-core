//! DPoP proof validation (RFC 9449) — the sender-constraining the OIDF
//! suite's `sender_constrain: dpop` variants require. Bearer access
//! tokens minted with a DPoP proof are bound to the proof key's RFC 7638
//! thumbprint (`jkt`); the credential endpoint then requires a fresh
//! proof carrying `ath` (hash of the access token) from the same key.
//!
//! Fail-closed: missing/invalid/replayed proofs are refusals. Replay is
//! tracked per (jkt, jti) with expiry pruning — a bounded cache, like
//! the vc token_log.

use jose_rs::jwk::Jwk;
use jose_rs::JoseHeader;
use sha2::{Digest, Sha256};
use siros_issuer_core::error::code;
use siros_issuer_core::oid4vci::DpopClaims;
use siros_issuer_core::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct DpopValidator {
    /// Proof freshness window (RFC 9449 §4.1: +/- from iat).
    window_secs: i64,
    /// (jkt, jti) -> iat; pruned lazily by the window.
    seen: Mutex<HashMap<(String, String), i64>>,
}

/// A validated DPoP proof.
pub struct DpopVerified {
    pub jwk: Jwk,
    pub jkt: String,
    pub claims: DpopClaims,
}

impl DpopValidator {
    pub fn new(window_secs: i64) -> Self {
        Self {
            window_secs,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Validate a DPoP proof for one request. `ath` is the required
    /// access-token hash at resource endpoints (RFC 9449 §4.1/§4.3);
    /// `None` at the token endpoint, where the proof binds the *new*
    /// token instead.
    pub fn validate(
        &self,
        proof: &str,
        htm: &str,
        htu: &url::Url,
        now: i64,
        ath: Option<&str>,
    ) -> Result<DpopVerified> {
        let mut parts = proof.split('.');
        let (h, _p, _s) = match (parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s)) if parts.next().is_none() => (h, p, s),
            _ => {
                return Err(Error::new(
                    code::INVALID_INPUT,
                    "DPoP proof is not a compact JWT",
                ))
            }
        };
        let header: JoseHeader = serde_json::from_slice(
            &siros_issuer_core::sdjwt_issue::b64u_decode(h)
                .map_err(|_| Error::new(code::INVALID_INPUT, "DPoP header is not base64url"))?,
        )
        .map_err(|e| Error::new(code::INVALID_INPUT, format!("DPoP header: {e}")))?;
        if header.typ.as_deref() != Some("dpop+jwt") {
            return Err(Error::new(
                code::INVALID_INPUT,
                format!("DPoP typ {:?} is not dpop+jwt", header.typ),
            ));
        }
        if header.alg != "ES256" {
            return Err(Error::new(
                code::INVALID_INPUT,
                format!("DPoP alg {} is not ES256 (as advertised)", header.alg),
            ));
        }
        let jwk_value = header
            .jwk
            .clone()
            .ok_or_else(|| Error::new(code::INVALID_INPUT, "DPoP header carries no jwk"))?;
        let jwk: Jwk = serde_json::from_value(jwk_value)
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("DPoP jwk: {e}")))?;
        if jwk.d.is_some() {
            return Err(Error::new(
                code::INVALID_INPUT,
                "DPoP jwk carries private material",
            ));
        }

        let payload = jose_rs::jws::compact::verify_with_jwk(&jwk, proof)
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("DPoP signature: {e}")))?;
        let claims: DpopClaims = serde_json::from_slice(&payload)
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("DPoP claims: {e}")))?;

        // htm/htu: exact method and target (query and fragment excluded,
        // RFC 9449 §4.1 — none of our endpoints carry a query).
        if !claims.htm.eq_ignore_ascii_case(htm) {
            return Err(Error::new(code::INVALID_INPUT, "DPoP htm mismatch"));
        }
        if claims.htu != strip_default_port(htu) {
            return Err(Error::new(code::INVALID_INPUT, "DPoP htu mismatch"));
        }
        // Freshness.
        if (claims.iat - now).abs() > self.window_secs {
            return Err(Error::new(
                code::INVALID_INPUT,
                "DPoP iat outside the window",
            ));
        }
        // ath: required when the caller demands it.
        match (ath, &claims.ath) {
            (Some(expected), Some(given)) if given == expected => {}
            (Some(_), _) => {
                return Err(Error::new(code::INVALID_INPUT, "DPoP ath missing or wrong"))
            }
            (None, Some(_)) => {
                return Err(Error::new(
                    code::INVALID_INPUT,
                    "DPoP ath must be absent at the token endpoint",
                ))
            }
            (None, None) => {}
        }
        // Replay: (jkt, jti) must be unseen and unexpired.
        let jkt = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk)
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("thumbprint: {e}")))?;
        {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| Error::new(code::TRANSPORT, "DPoP replay cache lock poisoned"))?;
            // Prune entries older than the window on both sides.
            let window = self.window_secs;
            seen.retain(|_, iat| now.saturating_sub(*iat) <= 2 * window);
            if seen
                .insert((jkt.clone(), claims.jti.clone()), claims.iat)
                .is_some()
            {
                return Err(Error::new(code::INVALID_INPUT, "DPoP jti replayed"));
            }
        }
        Ok(DpopVerified { jwk, jkt, claims })
    }
}

/// b64u(sha256(token)) — the `ath` claim (RFC 9449 §4.1).
pub fn access_token_hash(token: &str) -> String {
    siros_issuer_core::sdjwt_issue::b64u(&Sha256::digest(token.as_bytes()))
}

/// The htu comparison form: no fragment, no default port (RFC 9449 §4.1
/// htu normalization as commonly implemented).
fn strip_default_port(url: &url::Url) -> String {
    let mut normalized = url.clone();
    normalized.set_fragment(None);
    match (normalized.scheme(), normalized.port()) {
        ("http", Some(80)) | ("https", Some(443)) => {
            normalized.set_port(None).ok();
        }
        _ => {}
    }
    normalized.into()
}
