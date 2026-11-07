//! Key-attestation proof verification (OpenID4VCI 1.0 ID1 Appendix D.1).
//!
//! Sources of truth: the attested_keys claim carries the device key(s) the
//! credential binds to; the JWT's signature verifies against its own `x5c`
//! leaf (self-consistency); `nonce` binds the session's c_nonce and `aud`,
//! when present, the issuer identifier — same policy as the §7.1 jwt
//! proof. Trust in the attestation *issuer* is the PDP's decision, not the
//! proof check's (design §8.2, mirroring vc's `ProofAttestation.Verify`
//! boundary). Claim shape verified against the OIDF suite's
//! `VCIGenerateKeyAttestationIfNecessary` (iat/exp/attested_keys/nonce —
//! aud NOT set): the conformance mdoc variants send exactly that.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;
use url::Url;

use siros_issuer_core::error::code;
use siros_issuer_core::oid4vci::issuer_identifier;
use siros_issuer_service::auth::verify_attestation_proof;

const ISSUER_BASE: &str = "https://issuer.example.org:9443";
const C_NONCE: &str = "c_nonce-attestation-test";
const NOW: i64 = 1_793_000_000;

/// Fixed test keys (never production) — the conformance client fixtures.
/// The attestation key signs the proof and self-signs the x5c leaf; the
/// device key is the attested holder key.
fn attestation_jwk() -> jose_rs::jwk::Jwk {
    serde_json::from_str(
        r#"{"kty":"EC","x":"ktT77AqMntawPyU772lBg8nd7cwENrYyOL_KWbYN8Jc","y":"67lPXEq5gJdimDYD0AacxLfRfIm2-fSNd3HBqyXXvBI","crv":"P-256","d":"KJEKZo2PQq6E40P6HMenViCVBRXoWD2FDyevRsJnlG0","kid":"attestation-1","alg":"ES256","use":"sig"}"#,
    )
    .unwrap()
}

fn device_jwk() -> jose_rs::jwk::Jwk {
    serde_json::from_str(
        r#"{"kty":"EC","x":"_MUU-7kbV7WJXhrXJuDaAhHKqvDBHq-a4NH1ekAqo8I","y":"7JpnjHEJoyGLdjw_HkNBI9KU7CsswTrDTb7RSmLZ5m0","crv":"P-256","kid":"device-1","alg":"ES256","use":"sig"}"#,
    )
    .unwrap()
}

/// The device key's private part (the conformance client-2 fixture) —
/// only the signature-mismatch test signs with it.
fn other_signer_jwk() -> jose_rs::jwk::Jwk {
    serde_json::from_str(
        r#"{"kty":"EC","x":"_MUU-7kbV7WJXhrXJuDaAhHKqvDBHq-a4NH1ekAqo8I","y":"7JpnjHEJoyGLdjw_HkNBI9KU7CsswTrDTb7RSmLZ5m0","crv":"P-256","d":"SZK0jDoqr-5R3zqMGVq7DY2tLozo7mPxEKmOkN9TNWE","kid":"device-1","alg":"ES256","use":"sig"}"#,
    )
    .unwrap()
}

/// A self-signed certificate over the attestation key: the x5c leaf whose
/// SPKI the signature must verify against (rcgen over the JWK's key, the
/// mdoc-roundtrip pattern — the SPKI must match the signing key).
fn attestation_cert_der() -> Vec<u8> {
    let jwk = attestation_jwk();
    let key = p256::ecdsa::SigningKey::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            jwk.d.as_deref().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    use p256::pkcs8::EncodePrivateKey;
    let pkcs8 = key.to_pkcs8_der().unwrap();
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["attestation.example.org".to_string()]).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    cert.der().to_vec()
}

/// A key-attestation JWT per Appendix D.1: `typ: key-attestation+jwt`,
/// `x5c` carrying the leaf (RFC 7515 standard base64 DER), `attested_keys`
/// carrying the device key, `nonce`/`aud`/`iat`/`exp` claims.
fn attestation_jwt(typ: &str, nonce: &str, signer: &jose_rs::jwk::Jwk, with_aud: bool) -> String {
    let mut header = jose_rs::JoseHeader::new("ES256");
    header.typ = Some(typ.to_owned());
    // RFC 7515 §4.1.6: standard base64 of the DER certificate.
    header.x5c = Some(vec![STANDARD.encode(attestation_cert_der())]);
    let mut claims = json!({
        "attested_keys": [serde_json::to_value(device_jwk()).unwrap()],
        "nonce": nonce,
        "iat": NOW,
        "exp": NOW + 300,
    });
    if with_aud {
        claims["aud"] = json!(issuer_identifier(&Url::parse(ISSUER_BASE).unwrap()));
    }
    let payload = serde_json::to_vec(&claims).unwrap();
    // x5c is a key-reference member: signing with it in the header needs
    // the option enabled.
    let opts = jose_rs::jws::compact::SignOptions::new().with_key_reference_headers(true);
    jose_rs::jws::compact::sign_with_jwk_options(signer, &payload, &header, &opts).expect("signs")
}

fn base() -> Url {
    Url::parse(ISSUER_BASE).unwrap()
}

/// The verified proof yields `attested_keys[0]` — the device key the
/// credential binds to (Appendix D.1) — after the signature verifies
/// against the x5c leaf.
#[test]
fn attestation_proof_yields_the_attested_device_key() {
    let proof = attestation_jwt("key-attestation+jwt", C_NONCE, &attestation_jwk(), true);
    let device = verify_attestation_proof(&proof, &base(), C_NONCE, NOW + 30, 60)
        .expect("a well-formed attestation with aud verifies");
    // The returned key IS attested_keys[0] (public coordinates only).
    assert_eq!(device.x, device_jwk().x);
    assert_eq!(device.y, device_jwk().y);
    assert!(device.d.is_none(), "no private material may come back");
}

/// The OIDF suite's attestation carries iat/exp/attested_keys/nonce and
/// NO aud (its `VCIGenerateKeyAttestationIfNecessary`): aud is verified
/// when present, never demanded (Appendix D.1 shows aud as a claim, the
/// conformance profile omits it — accepting both is the interop shape).
#[test]
fn attestation_proof_without_aud_verifies() {
    let proof = attestation_jwt("key-attestation+jwt", C_NONCE, &attestation_jwk(), false);
    let device = verify_attestation_proof(&proof, &base(), C_NONCE, NOW + 30, 60)
        .expect("the suite-shape attestation (no aud) must verify");
    assert_eq!(device.x, device_jwk().x);
}

/// When aud IS present it must be the issuer identifier (§7.1 policy).
#[test]
fn attestation_proof_with_wrong_aud_is_invalid_proof() {
    let mut header = jose_rs::JoseHeader::new("ES256");
    header.typ = Some("key-attestation+jwt".to_owned());
    header.x5c = Some(vec![STANDARD.encode(attestation_cert_der())]);
    let claims = json!({
        "attested_keys": [serde_json::to_value(device_jwk()).unwrap()],
        "nonce": C_NONCE,
        "aud": "https://someone-else.example.org",
        "iat": NOW,
        "exp": NOW + 300,
    });
    let payload = serde_json::to_vec(&claims).unwrap();
    let opts = jose_rs::jws::compact::SignOptions::new().with_key_reference_headers(true);
    let proof =
        jose_rs::jws::compact::sign_with_jwk_options(&attestation_jwk(), &payload, &header, &opts)
            .expect("signs");
    let err = verify_attestation_proof(&proof, &base(), C_NONCE, NOW + 30, 60)
        .expect_err("aud for another issuer must be refused");
    assert_eq!(err.code, code::INVALID_PROOF, "{err}");
}

/// The nonce binds: a proof minted for another c_nonce is `invalid_nonce`
/// (§7.2.2, same code the suite's invalid-nonce module reads).
#[test]
fn attestation_proof_with_wrong_nonce_is_invalid_nonce() {
    let proof = attestation_jwt(
        "key-attestation+jwt",
        "a-different-nonce",
        &attestation_jwk(),
        false,
    );
    let err = verify_attestation_proof(&proof, &base(), C_NONCE, NOW + 30, 60)
        .expect_err("nonce mismatch must be refused");
    assert_eq!(err.code, code::INVALID_NONCE, "{err}");
}

/// `typ` names the proof type (Appendix D.1): anything else is
/// `invalid_proof`, not parsed as an attestation.
#[test]
fn attestation_proof_with_wrong_typ_is_invalid_proof() {
    let proof = attestation_jwt("openid4vci-proof+jwt", C_NONCE, &attestation_jwk(), false);
    let err = verify_attestation_proof(&proof, &base(), C_NONCE, NOW + 30, 60)
        .expect_err("wrong typ must be refused");
    assert_eq!(err.code, code::INVALID_PROOF, "{err}");
}

/// Self-consistency: the signature must verify against the x5c leaf's key.
/// A proof signed by a different key than the leaf it embeds is
/// `invalid_proof` — the x5c is what the verifier trusts, so a mismatched
/// signature is a forgery, not a parse error.
#[test]
fn attestation_proof_signed_by_other_key_than_leaf_is_invalid_proof() {
    // The device key's private part signs, but the x5c leaf still covers
    // the attestation key: signature and leaf disagree.
    let proof = attestation_jwt("key-attestation+jwt", C_NONCE, &other_signer_jwk(), false);
    let err = verify_attestation_proof(&proof, &base(), C_NONCE, NOW + 30, 60)
        .expect_err("signature not over the leaf's key must be refused");
    assert_eq!(err.code, code::INVALID_PROOF, "{err}");
}

/// An expired attestation is refused (same time policy as §7.1).
#[test]
fn expired_attestation_proof_is_refused() {
    let proof = attestation_jwt("key-attestation+jwt", C_NONCE, &attestation_jwk(), false);
    let err = verify_attestation_proof(&proof, &base(), C_NONCE, NOW + 600, 60)
        .expect_err("expired attestation must be refused");
    assert_eq!(err.code, code::INVALID_PROOF, "{err}");
}

/// `attested_keys` is REQUIRED and non-empty (Appendix D.1): a proof
/// without it never yields a device key.
#[test]
fn attestation_proof_without_attested_keys_is_refused() {
    let mut header = jose_rs::JoseHeader::new("ES256");
    header.typ = Some("key-attestation+jwt".to_owned());
    header.x5c = Some(vec![STANDARD.encode(attestation_cert_der())]);
    let claims = json!({
        "nonce": C_NONCE,
        "iat": NOW,
        "exp": NOW + 300,
    });
    let payload = serde_json::to_vec(&claims).unwrap();
    let opts = jose_rs::jws::compact::SignOptions::new().with_key_reference_headers(true);
    let proof =
        jose_rs::jws::compact::sign_with_jwk_options(&attestation_jwk(), &payload, &header, &opts)
            .expect("signs");
    let err = verify_attestation_proof(&proof, &base(), C_NONCE, NOW + 30, 60)
        .expect_err("missing attested_keys must be refused");
    assert_eq!(err.code, code::INVALID_PROOF, "{err}");
}

/// Sanity on the fixtures: the x5c leaf's SPKI covers the attestation key.
#[test]
fn attestation_leaf_covers_the_attestation_key() {
    let der = attestation_cert_der();
    let key = p256::ecdsa::SigningKey::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            attestation_jwk().d.as_deref().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    use x509_cert::der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(&der).unwrap();
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();
    use p256::pkcs8::DecodePublicKey;
    let leaf = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der).unwrap();
    assert_eq!(
        &leaf,
        key.verifying_key(),
        "leaf SPKI must cover the signer"
    );
}
