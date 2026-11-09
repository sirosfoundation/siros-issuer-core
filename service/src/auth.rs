//! Integrator authentication for the backend session API (design §6):
//! a Bearer JWT client assertion (RFC 7523-shaped), signed by a key embedded
//! in the JOSE header (`jwk`) or referenced by `x5c`. No pre-registration;
//! the PDP decides whether the key may issue anything.
//!
//! Verified here: signature, `aud` == this issuer, `iss` == `sub`,
//! `exp`/`iat` windows. The subject id is the RFC 7638 thumbprint of the
//! asserting key — the PDP's subject.

use jose_rs::jwk::Jwk;
use jose_rs::JoseHeader;
use serde_json::Value;
use siros_issuer_core::error::code;
use siros_issuer_core::{Error, Result};

pub struct IntegratorIdentity {
    /// The integrator's ENTITY identity — the assertion's `iss` — what
    /// an entity-keyed trust registry (go-trust's whitelist: URL lists
    /// per action) matches the subject against. The KEY binding rides
    /// `jwk` (the resource): the registry fingerprint-checks it
    /// against the entity's registered JWKS keys.
    pub subject_id: String,
    pub client_id: String,
    /// The asserting key's public JWK, for PDP evidence (`resource.key`).
    pub jwk: serde_json::Value,
}

/// Verify a Bearer client-assertion JWT. `expected_aud` is the credential
/// issuer's own URL (the session API's audience).
pub fn verify_bearer_assertion(
    token: &str,
    expected_aud: &url::Url,
    now: i64,
    leeway_secs: i64,
) -> Result<IntegratorIdentity> {
    let mut parts = token.split('.');
    let (h, _p, _s) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) if parts.next().is_none() => (h, p, s),
        _ => {
            return Err(Error::new(
                code::INVALID_INPUT,
                "assertion is not a compact JWT",
            ))
        }
    };
    let header: JoseHeader = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(h)
            .map_err(|_| Error::new(code::INVALID_INPUT, "assertion header is not base64url"))?,
    )
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("assertion header: {e}")))?;
    if header.alg != "ES256" {
        return Err(Error::new(
            code::INVALID_INPUT,
            format!("assertion alg {} is not ES256", header.alg),
        ));
    }
    let jwk_value = header
        .jwk
        .clone()
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "assertion header carries no jwk"))?;
    let jwk: Jwk = serde_json::from_value(jwk_value)
        .map_err(|e| Error::new(code::INVALID_INPUT, format!("assertion jwk: {e}")))?;
    if jwk.d.is_some() {
        return Err(Error::new(
            code::INVALID_INPUT,
            "assertion jwk carries private material",
        ));
    }
    let payload = jose_rs::jws::compact::verify_with_jwk(&jwk, token)
        .map_err(|e| Error::new(code::INVALID_INPUT, format!("assertion signature: {e}")))?;
    let claims: Value = serde_json::from_slice(&payload)
        .map_err(|e| Error::new(code::INVALID_INPUT, format!("assertion claims: {e}")))?;

    let aud = claims
        .get("aud")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "assertion has no aud"))?;
    // §12.2.3 byte-identity: the identifier carries no empty-path slash
    // (`Url`'s Display would add one), and assertions are signed with the
    // configured form.
    if aud != siros_issuer_core::oid4vci::issuer_identifier(expected_aud) {
        return Err(Error::new(code::INVALID_INPUT, "assertion aud mismatch"));
    }
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "assertion has no iss"))?;
    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "assertion has no sub"))?;
    if iss != sub {
        return Err(Error::new(code::INVALID_INPUT, "assertion iss != sub"));
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

    // The ENTITY identity, not the key fingerprint: go-trust's whitelist
    // is entity-keyed (URL lists per action — subject.id matches the
    // list), with the key binding checked via the resource's key
    // against the entity's registered JWKS keys (fingerprint match).
    // Proven live on gdc: subject.id = the deployment URL + resource
    // key = its own JWKS key ⇒ Permit from the real go-trust; the
    // fingerprint-as-subject form matched no list.
    let subject_id = iss.to_owned();
    Ok(IntegratorIdentity {
        subject_id,
        client_id: iss.to_owned(),
        jwk: serde_json::to_value(jwk).map_err(|e| {
            Error::new(code::INVALID_INPUT, format!("assertion jwk serialize: {e}"))
        })?,
    })
}

/// RFC 7638 thumbprint of an EC public JWK — the PDP subject id.
pub fn thumbprint(jwk: &Jwk) -> Result<String> {
    jose_rs::jwk::thumbprint::thumbprint_sha256(jwk)
        .map_err(|e| Error::new(code::INVALID_INPUT, format!("thumbprint: {e}")))
}

/// Verify a wallet's JWT proof (OpenID4VCI ID1 §7.2 jwt proof type): ES256,
/// key embedded in the JOSE header, `aud` == the credential issuer,
/// `nonce` == the session's current c_nonce, `iat` inside the window.
/// Returns the holder key (the SD-JWT `cnf`).
pub fn verify_jwt_proof(
    proof: &str,
    expected_aud: &url::Url,
    expected_nonce: &str,
    now: i64,
    leeway_secs: i64,
) -> Result<Jwk> {
    let mut parts = proof.split('.');
    let (h, _p, _s) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) if parts.next().is_none() => (h, p, s),
        _ => {
            return Err(Error::new(
                code::INVALID_INPUT,
                "proof is not a compact JWT",
            ))
        }
    };
    let header: JoseHeader = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(h)
            .map_err(|_| Error::new(code::INVALID_INPUT, "proof header is not base64url"))?,
    )
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("proof header: {e}")))?;
    if header.alg != "ES256" {
        return Err(Error::new(
            code::INVALID_INPUT,
            format!("proof alg {} is not ES256", header.alg),
        ));
    }
    let jwk_value = header
        .jwk
        .clone()
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "proof header carries no jwk"))?;
    let jwk: Jwk = serde_json::from_value(jwk_value)
        .map_err(|e| Error::new(code::INVALID_INPUT, format!("proof jwk: {e}")))?;
    if jwk.d.is_some() {
        return Err(Error::new(
            code::INVALID_INPUT,
            "proof jwk carries private material",
        ));
    }
    let payload = jose_rs::jws::compact::verify_with_jwk(&jwk, proof)
        .map_err(|e| Error::new(code::INVALID_PROOF, format!("proof signature: {e}")))?;
    let claims: Value = serde_json::from_slice(&payload)
        .map_err(|e| Error::new(code::INVALID_INPUT, format!("proof claims: {e}")))?;
    let aud = claims
        .get("aud")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "proof has no aud"))?;
    if aud != siros_issuer_core::oid4vci::issuer_identifier(expected_aud) {
        return Err(Error::new(code::INVALID_INPUT, "proof aud mismatch"));
    }
    let nonce = claims
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(code::INVALID_PROOF, "proof has no nonce"))?;
    if nonce != expected_nonce {
        // A wrong c_nonce value is `invalid_nonce`; a missing one is
        // `invalid_proof` (OID4VCI 1.0 Final §8.3.1.1 error registry).
        return Err(Error::new(code::INVALID_NONCE, "proof nonce mismatch"));
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "proof has no iat"))?;
    if iat > now + leeway_secs || now >= iat + 5 * leeway_secs {
        return Err(Error::new(
            code::INVALID_INPUT,
            "proof iat outside the window",
        ));
    }
    Ok(jwk)
}

/// An attestation proof (OpenID4VCI 1.0 Appendix D.1): a JWT whose
/// `attested_keys` claim carries the device key(s) and whose signature
/// verifies against its own `x5c` leaf (self-consistency — trust in the
/// attestation issuer is the PDP's job, vc `ProofAttestation.Verify`).
///
/// Verify an attestation proof (OpenID4VCI 1.0 ID1 Appendix D.1) and
/// return **all** its attested keys: `attested_keys` carries the device
/// key(s) the credential binds to — one credential per key in batch
/// issuance (vc `Proofs.ExtractAllJWKs`: "For Attestation, all keys
/// from the attested_keys claim are returned"); the c_nonce binding
/// rides the `nonce` claim like the JWT proof's.
pub fn verify_attestation_proof_all(
    proof: &str,
    expected_aud: &url::Url,
    expected_nonce: &str,
    now: i64,
    leeway_secs: i64,
) -> Result<Vec<Jwk>> {
    let mut parts = proof.split('.');
    let (h, _p, _s) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) if parts.next().is_none() => (h, p, s),
        _ => {
            return Err(Error::new(
                code::INVALID_PROOF,
                "attestation proof is not a compact JWT",
            ))
        }
    };
    let header: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(h)
            .map_err(|_| Error::new(code::INVALID_PROOF, "attestation header"))?,
    )
    .map_err(|e| Error::new(code::INVALID_PROOF, format!("attestation header: {e}")))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // ES256 is the one method the mso_mdoc configurations advertise in
    // proof_types_supported; the alg is pinned before any verification
    // runs so the token's own choice is never trusted.
    if alg != "ES256" {
        return Err(Error::new(
            code::INVALID_PROOF,
            format!("attestation alg {alg:?} is not ES256 (as advertised)"),
        ));
    }
    if header.get("typ").and_then(Value::as_str) != Some("key-attestation+jwt") {
        return Err(Error::new(
            code::INVALID_PROOF,
            "attestation typ is not key-attestation+jwt",
        ));
    }

    // Signature against the x5c leaf's key — self-consistency (Appendix
    // D.1/F.3; trust in the attestation issuer itself goes to the PDP,
    // mirroring vc's boundary). RFC 7515 §4.1.6 x5c: standard base64 DER.
    let x5c = header
        .get("x5c")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            Error::new(
                code::INVALID_PROOF,
                "attestation has no x5c header (no kid-based resolution is supported)",
            )
        })?;
    let leaf_b64 = x5c[0]
        .as_str()
        .ok_or_else(|| Error::new(code::INVALID_PROOF, "attestation x5c[0] not base64"))?;
    let leaf_der = siros_issuer_core::sdjwt_issue::b64u_decode(leaf_b64)
        .or_else(|_| siros_issuer_core::sdjwt_issue::b64_decode_std(leaf_b64))
        .map_err(|_| Error::new(code::INVALID_PROOF, "attestation x5c[0] not base64"))?;
    let leaf = leaf_verifying_key(&leaf_der)?;
    let leaf_jwk = leaf_to_jwk(&leaf)?;
    // jose_rs applies the full JWS-layer binding (raw ES256 r||s
    // handling, alg/key consistency) — the same path the jwt proof uses.
    let payload = jose_rs::jws::compact::verify_with_jwk(&leaf_jwk, proof)
        .map_err(|e| Error::new(code::INVALID_PROOF, format!("attestation signature: {e}")))?;

    // Claims from the verified bytes. `attested_keys` carries the device
    // key(s) this issuance binds to — **all** of them for batch issuance
    // (vc `ExtractAllJWKs`: "For Attestation, all keys from the
    // attested_keys claim are returned", one credential per key); nonce
    // + aud + expiry carry the §7.1 policy (the OIDF suite's attestation
    // sets iat/exp/attested_keys/nonce and no aud — aud is checked when
    // present, never demanded).
    let claims: Value = serde_json::from_slice(&payload)
        .map_err(|e| Error::new(code::INVALID_PROOF, format!("attestation claims: {e}")))?;
    let attested: &[Value] = claims
        .get("attested_keys")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| Error::new(code::INVALID_PROOF, "attested_keys missing or empty"))?;
    let mut device_jwks = Vec::with_capacity(attested.len());
    for key in attested {
        let jwk: Jwk = serde_json::from_value(key.clone())
            .map_err(|e| Error::new(code::INVALID_PROOF, format!("attested key: {e}")))?;
        if jwk.d.is_some() {
            return Err(Error::new(
                code::INVALID_PROOF,
                "attested key carries private material",
            ));
        }
        device_jwks.push(jwk);
    }

    let nonce = claims
        .get("nonce")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if nonce.is_empty() {
        return Err(Error::new(code::INVALID_PROOF, "attestation has no nonce"));
    }
    if nonce != expected_nonce {
        return Err(Error::new(
            code::INVALID_NONCE,
            "attestation nonce mismatch",
        ));
    }
    let aud = claims.get("aud").and_then(Value::as_str);
    if let Some(aud) = aud {
        if aud != siros_issuer_core::oid4vci::issuer_identifier(expected_aud) {
            return Err(Error::new(code::INVALID_PROOF, "attestation aud mismatch"));
        }
    }
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64) {
        if now >= exp + leeway_secs {
            return Err(Error::new(code::INVALID_PROOF, "attestation expired"));
        }
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| Error::new(code::INVALID_PROOF, "attestation has no iat"))?;
    if iat > now + leeway_secs {
        return Err(Error::new(
            code::INVALID_PROOF,
            "attestation issued in the future",
        ));
    }
    Ok(device_jwks)
}

/// Single-key attestation verification (Appendix D.1): the first
/// attested key — the single-issuance path's device key.
pub fn verify_attestation_proof(
    proof: &str,
    expected_aud: &url::Url,
    expected_nonce: &str,
    now: i64,
    leeway_secs: i64,
) -> Result<Jwk> {
    let mut keys =
        verify_attestation_proof_all(proof, expected_aud, expected_nonce, now, leeway_secs)?;
    Ok(keys.remove(0))
}

fn leaf_verifying_key(der: &[u8]) -> Result<p256::ecdsa::VerifyingKey> {
    use x509_cert::der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|_| Error::new(code::INVALID_PROOF, "x5c leaf not a certificate"))?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::new(code::INVALID_PROOF, "x5c leaf SPKI"))?;
    let sec1 = spki_raw_bytes(&spki)
        .ok_or_else(|| Error::new(code::INVALID_PROOF, "x5c leaf key not P-256"))?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| Error::new(code::INVALID_PROOF, "x5c leaf key not P-256"))
}

/// Extract the raw SEC1 point bytes from a DER SubjectPublicKeyInfo.
fn spki_raw_bytes(spki_der: &[u8]) -> Option<Vec<u8>> {
    use x509_cert::der::Decode;
    let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(spki_der).ok()?;
    // der 0.7's `raw_bytes` is the BIT STRING content without the
    // unused-bits count (verifier-core's mdoc leaf uses the same): the
    // SEC1 uncompressed point, 0x04 || X || Y — 65 bytes for P-256.
    let point = spki.subject_public_key.raw_bytes();
    if point.len() != 65 || point[0] != 0x04 {
        return None;
    }
    Some(point.to_vec())
}

/// The x5c leaf's P-256 public key as a JWK (no alg pin — jose_rs checks
/// the header alg against the key's curve) for `verify_with_jwk`.
fn leaf_to_jwk(key: &p256::ecdsa::VerifyingKey) -> Result<Jwk> {
    let point = key.to_encoded_point(false);
    let bytes = point.as_bytes();
    // SEC1 uncompressed: 0x04 || X || Y.
    let (x, y) = (&bytes[1..33], &bytes[33..]);
    serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": siros_issuer_core::sdjwt_issue::b64u(x),
        "y": siros_issuer_core::sdjwt_issue::b64u(y),
    }))
    .map_err(|e| Error::new(code::INVALID_PROOF, format!("leaf jwk: {e}")))
}
