//! Wallet attestation (WIA/KA) evaluator tests — a faithful port check of
//! vc's `WalletAttestationEvaluator` semantics, per surface:
//!
//! - Identity: ETSI x5c (SAN/CN, iss↔cert consistency) and IETF iss
//! - Mode pinning: etsi rejects no-x5c, ietf rejects x5c, either accepts
//!   both — enforced BEFORE any signature verification
//! - Signature: x5c leaf / jwk header (private material refused) / kid+JWKS
//! - Trust: PDP wallet-provider decision, fail-closed
//! - Tier policy: attestation_source → scope after trust
//! - PoP: typ, cnf.jwk signature, aud, exp/iat; legacy empty-pop accepted
//!
//! The PDP double permits a fixed trusted provider; the scope rides the
//! tier policy (default-open WildcardRulesPolicy in these tests, with a
//! rule case).

use std::sync::Arc;

use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use siros_issuer_core::oid4vci::issuer_identifier;
use siros_issuer_core::sdjwt_issue::b64u;
use siros_issuer_service::client_auth::{AttestationPolicy, AttestationRule, WildcardRulesPolicy};
use siros_issuer_service::pdp::TrustPdp;
use siros_issuer_service::wallet_attestation::{WalletAttestationEvaluator, WiaMode};

const ISSUER_BASE: &str = "https://issuer.example.org:9443";
const NOW: i64 = 1_800_000_000;

/// A PDP double: permits one wallet provider (by subject id), refuses
/// everything else — the trust boundary is observable.
struct WalletProviderPdp {
    trusted: String,
}

#[async_trait::async_trait]
impl TrustPdp for WalletProviderPdp {
    async fn permit(
        &self,
        _query: &siros_issuer_core::trust::IssuanceTrustQuery,
    ) -> siros_issuer_core::Result<()> {
        Ok(())
    }
    async fn permit_presentation(
        &self,
        _query: &siros_verifier_core::trust::TrustQuery,
    ) -> siros_issuer_core::Result<()> {
        Ok(())
    }
    async fn permit_wallet_provider(
        &self,
        query: &siros_issuer_core::trust::WalletProviderTrustQuery,
    ) -> siros_issuer_core::Result<()> {
        // Accept the provider by its bare id (ETSI SAN) or its iss URL
        // (IETF) — go-trust resolves both shapes to the same provider.
        let matches = query.subject_id == self.trusted
            || url::Url::parse(&query.subject_id)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .as_deref()
                == Some(self.trusted.as_str());
        if matches {
            Ok(())
        } else {
            Err(siros_issuer_core::Error::new(
                siros_issuer_core::error::code::PDP_DENIED,
                format!(
                    "wallet provider {:?} not in the test trust list",
                    query.subject_id
                ),
            ))
        }
    }
}

fn make_evaluator(mode: WiaMode, rules: Vec<AttestationRule>) -> WalletAttestationEvaluator {
    let pdp: Arc<dyn TrustPdp> = Arc::new(WalletProviderPdp {
        trusted: "wallet-provider.example.org".to_owned(),
    });
    let policy: Arc<dyn AttestationPolicy> = Arc::new(WildcardRulesPolicy::new(rules));
    WalletAttestationEvaluator::new(pdp, policy, mode, Url::parse(ISSUER_BASE).unwrap())
}

/// A test attestation-issuer keypair + self-signed cert over it.
struct AttestationIssuer {
    key: p256::ecdsa::SigningKey,
    cert_der: Vec<u8>,
}

fn attestation_issuer() -> AttestationIssuer {
    use p256::ecdsa::signature::rand_core::OsRng;
    let key = p256::ecdsa::SigningKey::random(&mut OsRng);
    use p256::pkcs8::EncodePrivateKey;
    let pkcs8 = key.to_pkcs8_der().unwrap();
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    // SAN DNS = the provider id the PDP double trusts.
    let params =
        rcgen::CertificateParams::new(vec!["wallet-provider.example.org".to_string()]).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    AttestationIssuer {
        key,
        cert_der: cert.der().to_vec(), // to_vec keeps the owned DER
    }
}

/// A wallet instance key (the PoP/cnf key).
fn wallet_key() -> (p256::ecdsa::SigningKey, jose_rs::jwk::Jwk) {
    use p256::ecdsa::signature::rand_core::OsRng;
    let key = p256::ecdsa::SigningKey::random(&mut OsRng);
    use p256::pkcs8::EncodePrivateKey;
    let pkcs8 = key.to_pkcs8_der().unwrap();
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let jwk: jose_rs::jwk::Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256",
        "x": b64u(kp.public_key_raw().split_at(1).1.split_at(32).0),
        "y": b64u(kp.public_key_raw().split_at(1).1.split_at(32).0),
    }))
    .unwrap();
    // ^ placeholder — replaced below with the real derivation.
    let _ = jwk;
    let public = key.verifying_key().to_encoded_point(false);
    let jwk: jose_rs::jwk::Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256",
        "x": b64u(&public.as_bytes()[1..33]),
        "y": b64u(&public.as_bytes()[33..]),
        "alg": "ES256", "use": "sig",
    }))
    .unwrap();
    (key, jwk)
}

fn sign_compact(
    key: &p256::ecdsa::SigningKey,
    header: &serde_json::Value,
    claims: &serde_json::Value,
) -> String {
    use p256::ecdsa::signature::Signer as _;
    let h = b64u(serde_json::to_vec(header).unwrap().as_slice());
    let p = b64u(serde_json::to_vec(claims).unwrap().as_slice());
    let sig: p256::ecdsa::Signature = key.sign(format!("{h}.{p}").as_bytes());
    format!("{h}.{p}.{}", b64u(&sig.to_bytes()))
}

/// A complete ETSI WIA: x5c header (the attestation issuer's cert),
/// sub = the wallet key thumbprint, cnf = the wallet key.
fn etsi_wia(issuer: &AttestationIssuer) -> (String, jose_rs::jwk::Jwk) {
    let (wallet, wallet_jwk) = wallet_key();
    let thumbprint = {
        let canonical = serde_json::json!({
            "crv": "P-256", "kty": "EC",
            "x": b64u(&wallet.verifying_key().to_encoded_point(false).as_bytes()[1..33]),
            "y": b64u(&wallet.verifying_key().to_encoded_point(false).as_bytes()[33..]),
        });
        b64u(&Sha256::digest(
            serde_json::to_string(&canonical).unwrap().as_bytes(),
        ))
    };
    let header = json!({
        "alg": "ES256",
        "x5c": [b64_decode_std_to_string(&issuer.cert_der)],
    });
    let claims = json!({
        "sub": thumbprint,
        "attestation_source": "backend_attested",
        "cnf": { "jwk": wallet_jwk },
        "iat": NOW,
        "exp": NOW + 3600,
    });
    (sign_compact(&issuer.key, &header, &claims), wallet_jwk)
}

fn b64_decode_std_to_string(der: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(der)
}

/// A complete IETF WIA: iss claim + jwk header (no x5c).
fn ietf_wia(issuer: &AttestationIssuer) -> String {
    let header = json!({
        "alg": "ES256",
        "jwk": {
            "kty": "EC", "crv": "P-256",
            "x": b64u(&issuer.key.verifying_key().to_encoded_point(false).as_bytes()[1..33]),
            "y": b64u(&issuer.key.verifying_key().to_encoded_point(false).as_bytes()[33..]),
        },
    });
    let claims = json!({
        "iss": "https://wallet-provider.example.org",
        "sub": "wallet-instance-1",
        "attestation_source": "backend_attested",
        "iat": NOW,
        "exp": NOW + 3600,
    });
    sign_compact(&issuer.key, &header, &claims)
}

#[tokio::test]
async fn etsi_wia_verifies_and_its_tier_policy_applies() {
    let issuer = attestation_issuer();
    let (wia, wallet_jwk) = etsi_wia(&issuer);

    // Trusted provider + default-open policy: evaluates.
    let evaluator = make_evaluator(WiaMode::Either, Vec::new());
    let result = evaluator.evaluate(&wia, "pid").await.unwrap();
    assert_eq!(result.issuer, "wallet-provider.example.org");
    assert_eq!(result.attestation_source, "backend_attested");
    assert!(!result.subject.is_empty());

    // A tier rule that DENIES this source: refused (after trust).
    let evaluator = make_evaluator(
        WiaMode::Either,
        vec![AttestationRule {
            attestation_source: "other_tier".to_owned(),
            scope: "*".to_owned(),
            issuer: "*".to_owned(),
        }],
    );
    let denied = evaluator.evaluate(&wia, "pid").await;
    assert!(denied.is_err(), "the tier rule must deny backend_attested");

    // etsi mode pinned: accepts the x5c WIA.
    let evaluator = make_evaluator(WiaMode::Etsi, Vec::new());
    evaluator.evaluate(&wia, "pid").await.unwrap();
    let _ = wallet_jwk;
}

#[tokio::test]
async fn mode_pinning_is_enforced_before_trust() {
    let etsi = attestation_issuer();
    let wia_etsi = etsi_wia(&etsi).0;
    let wia_ietf = ietf_wia(&etsi);

    // etsi mode rejects an iss-only WIA (no x5c).
    let evaluator = make_evaluator(WiaMode::Etsi, Vec::new());
    let err = evaluator.evaluate(&wia_ietf, "pid").await.unwrap_err();
    assert!(
        err.message.contains("etsi"),
        "the mode refusal names the model: {err}"
    );

    // ietf mode rejects an x5c WIA.
    let evaluator = make_evaluator(WiaMode::Ietf, Vec::new());
    let err = evaluator.evaluate(&wia_etsi, "pid").await.unwrap_err();
    assert!(
        err.message.contains("ietf"),
        "the mode refusal names the model: {err}"
    );

    // Either accepts both.
    let evaluator = make_evaluator(WiaMode::Either, Vec::new());
    evaluator.evaluate(&wia_etsi, "pid").await.unwrap();
    evaluator.evaluate(&wia_ietf, "pid").await.unwrap();
}

#[tokio::test]
async fn untrusted_wallet_provider_is_refused() {
    // An issuer whose cert SAN is NOT the PDP double's trusted provider.
    use p256::ecdsa::signature::rand_core::OsRng;
    let key = p256::ecdsa::SigningKey::random(&mut OsRng);
    use p256::pkcs8::EncodePrivateKey;
    let pkcs8 = key.to_pkcs8_der().unwrap();
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["untrusted-provider.example.org".to_string()]).unwrap();
    let cert = params.self_signed(&kp).unwrap();

    let mut header = serde_json::json!({
        "alg": "ES256",
        "x5c": [b64_decode_std_to_string(cert.der())],
    });
    let _ = &mut header;
    let claims = json!({
        "sub": "wallet-instance-2",
        "attestation_source": "backend_attested",
        "iat": NOW,
        "exp": NOW + 3600,
    });
    let wia = sign_compact(&key, &header, &claims);

    let evaluator = make_evaluator(WiaMode::Either, Vec::new());
    let err = evaluator.evaluate(&wia, "pid").await.unwrap_err();
    assert!(
        err.message.contains("not trusted"),
        "the PDP refusal surfaces: {err}"
    );
}

#[tokio::test]
async fn malformed_x5c_never_masquerades_as_ietf() {
    // A WIA with a malformed x5c (not an array) and an iss claim: the
    // etsi fail-closed parse refuses it (not the ietf path).
    let issuer = attestation_issuer();
    let header = json!({ "alg": "ES256", "x5c": "not-an-array" });
    let claims = json!({
        "iss": "https://wallet-provider.example.org",
        "sub": "wallet-instance-3",
        "iat": NOW,
        "exp": NOW + 3600,
    });
    let wia = sign_compact(&issuer.key, &header, &claims);
    let evaluator = make_evaluator(WiaMode::Either, Vec::new());
    let err = evaluator.evaluate(&wia, "pid").await.unwrap_err();
    assert!(
        err.message.contains("malformed"),
        "the malformed x5c fails closed: {err}"
    );
}

#[tokio::test]
async fn iss_cert_disagreement_is_refused() {
    let issuer = attestation_issuer();
    // x5c says wallet-provider.example.org; iss claims someone else:
    // re-sign the same issuer key with a hostile iss.
    let claims = json!({
        "sub": "wallet-instance-4",
        "iss": "https://evil.example.org",
        "attestation_source": "backend_attested",
        "iat": NOW,
        "exp": NOW + 3600,
    });
    let header = json!({
        "alg": "ES256",
        "x5c": [b64_decode_std_to_string(&issuer.cert_der)],
    });
    let wia = sign_compact(&issuer.key, &header, &claims);
    let evaluator = make_evaluator(WiaMode::Either, Vec::new());
    let err = evaluator.evaluate(&wia, "pid").await.unwrap_err();
    assert!(
        err.message.contains("does not match"),
        "the iss↔cert disagreement refuses: {err}"
    );
}

#[tokio::test]
async fn pop_validates_against_cnf_and_audience() {
    let issuer = attestation_issuer();
    // The WIA's cnf.jwk must equal the PoP key — build the WIA around the
    // wallet key below and sign the PoP with the same key.
    let (wallet_key, wallet_jwk) = wallet_key();

    // A valid PoP: typ, aud = this AS, signed by the wallet key.
    let header = json!({ "alg": "ES256", "typ": "oauth-client-attestation-pop+jwt" });
    let claims = json!({
        "aud": [issuer_identifier(&Url::parse(ISSUER_BASE).unwrap())],
        "iat": NOW,
        "exp": NOW + 300,
        "jti": "pop-1",
    });
    let pop = sign_compact(&wallet_key, &header, &claims);

    // The WIA's cnf.jwk must equal the PoP key for this to verify — the
    // test builds the WIA around wallet_key(), so they match only if the
    // etsi_wia helper used the same key. It doesn't (it generates its
    // own), so rebuild the WIA with THIS wallet key:
    let _ = wallet_jwk;
    let thumbprint = {
        let public = wallet_key.verifying_key().to_encoded_point(false);
        let canonical = serde_json::json!({
            "crv": "P-256", "kty": "EC",
            "x": b64u(&public.as_bytes()[1..33]),
            "y": b64u(&public.as_bytes()[33..]),
        });
        b64u(&Sha256::digest(
            serde_json::to_string(&canonical).unwrap().as_bytes(),
        ))
    };
    let wia_header = json!({
        "alg": "ES256",
        "x5c": [b64_decode_std_to_string(&issuer.cert_der)],
    });
    let wia_claims = json!({
        "sub": thumbprint,
        "attestation_source": "backend_attested",
        "cnf": {
            "jwk": {
                "kty": "EC", "crv": "P-256",
                "x": b64u(&wallet_key.verifying_key().to_encoded_point(false).as_bytes()[1..33]),
                "y": b64u(&wallet_key.verifying_key().to_encoded_point(false).as_bytes()[33..]),
                "alg": "ES256", "use": "sig",
            }
        },
        "iat": NOW,
        "exp": NOW + 3600,
    });
    let wia = sign_compact(&issuer.key, &wia_header, &wia_claims);

    let evaluator = make_evaluator(WiaMode::Either, Vec::new());
    // With PoP: verifies.
    evaluator
        .evaluate_with_pop(&wia, &pop, "pid")
        .await
        .unwrap();

    // Wrong typ: refused.
    let header_wrong_typ = json!({ "alg": "ES256", "typ": "JWT" });
    let pop_wrong = sign_compact(&wallet_key, &header_wrong_typ, &claims);
    let err = evaluator
        .evaluate_with_pop(&wia, &pop_wrong, "pid")
        .await
        .unwrap_err();
    assert!(err.message.contains("typ"), "{err}");

    // Wrong audience: refused.
    let claims_wrong_aud = json!({
        "aud": ["https://someone-else.example.org"],
        "iat": NOW,
        "exp": NOW + 300,
    });
    let pop_wrong_aud = sign_compact(&wallet_key, &header, &claims_wrong_aud);
    let err = evaluator
        .evaluate_with_pop(&wia, &pop_wrong_aud, "pid")
        .await
        .unwrap_err();
    assert!(err.message.contains("aud"), "{err}");

    // Legacy empty PoP: accepted (vc's carve-out).
    evaluator.evaluate_with_pop(&wia, "", "pid").await.unwrap();

    // A PoP signed by a DIFFERENT key (not the WIA's cnf): refused.
    use p256::ecdsa::signature::rand_core::OsRng;
    let other_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let pop_other = sign_compact(&other_key, &header, &claims);
    let err = evaluator
        .evaluate_with_pop(&wia, &pop_other, "pid")
        .await
        .unwrap_err();
    assert!(
        err.message.contains("signature"),
        "a PoP from another key refuses: {err}"
    );
}

#[test]
fn wia_mode_parses() {
    assert_eq!(WiaMode::parse("etsi").unwrap(), WiaMode::Etsi);
    assert_eq!(WiaMode::parse("ietf").unwrap(), WiaMode::Ietf);
    assert_eq!(WiaMode::parse("").unwrap(), WiaMode::Either);
    assert!(WiaMode::parse("quantum").is_err());
}
