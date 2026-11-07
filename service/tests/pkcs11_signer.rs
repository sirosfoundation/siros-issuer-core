//! The PKCS#11 signer provider e2e (design §11.1): the HSM path proves out
//! against a **real SoftHSM token** — a genuine PKCS#11 module, not a mock.
//!
//! Sources of truth: `signer::Signer`'s contract (the issuance code cannot
//! tell providers apart), RFC 7515 ES256 (compact JWS), and RFC 9052
//! (COSE Sig_structure). The oracle for every signature is the token's
//! **public** key (`public_jwk()`) — the private key never leaves the
//! token, so if the JWS/COSE verify under it, the HSM signed them.
//!
//! The full-issuance proof (SD-JWT + mdoc through the service, HSM
//! signing) lives in `issuance_e2e.rs::hsm_*` — the service helpers are
//! there; this file covers the provider contract itself.
//!
//! Provisioning mirrors a real ceremony: the key is generated in
//! software, a self-signed certificate is issued over it, and the
//! private key is imported into the token (`softhsm2-util --import`) —
//! an HSM deployment with an offline key ceremony. Skips when
//! softhsm2-util is not installed (the module is optional).

#[path = "pkcs11_provision.rs"]
mod provision;

use provision::{provider, provision, public_verifying_key};

use serde_json::json;

use siros_issuer_core::signer::Signer;

/// The provider contract: compact ES256 JWS (RFC 7515) and raw RFC 9052
/// Sig_structure (COSE, mdoc issuerAuth) — both issuer signature shapes
/// — verify under the token's public key. The private key never left the
/// token: `public_jwk()` reads CKA_EC_POINT, so every oracle passing
/// proves the HSM signed.
#[test]
fn pkcs11_signer_signs_both_issuer_signatures() {
    let Some(token) = provision() else {
        eprintln!("skipping: softhsm2-util is not installed (or provisioning failed)");
        return;
    };
    let signer = provider(&token);
    let public = signer.public_jwk().expect("public jwk");

    // public_jwk() read the TOKEN's key: it matches the software key that
    // was imported — so the oracles below verify under the HSM's own key.
    let token_key = public_verifying_key(&signer);
    assert_eq!(
        token_key.to_encoded_point(false).as_bytes(),
        token.public.to_encoded_point(false).as_bytes()
    );

    // 1. Compact ES256 JWS (RFC 7515): jose_rs applies the full JWS-layer
    //    binding — the same path a wallet runs.
    let header = jose_rs::JoseHeader::new("ES256");
    let payload = serde_json::to_vec(&json!({"proof": "the hsm signs"})).unwrap();
    let jws = signer.sign_es256(&header, &payload).expect("jws signs");
    let verified = jose_rs::jws::compact::verify_with_jwk(&public, &jws)
        .expect("the HSM-signed JWS verifies under the token's public key");
    assert_eq!(verified, payload);

    // 2. Raw RFC 9052 Sig_structure (COSE, mdoc issuerAuth): SHA-256
    //    pre-hash, raw `r || s` (64 bytes for P-256) — verified under the
    //    token's public key directly.
    let tbs = b"SIG_STRUCTURE_BYTES";
    let raw = signer.sign_es256_raw(tbs).expect("raw Sig_structure signs");
    assert_eq!(raw.len(), 64, "raw r||s, 2x32 bytes for P-256");
    let signature = p256::ecdsa::Signature::from_slice(&raw).expect("raw signature parses");
    use p256::ecdsa::signature::Verifier as _;
    // p256's `verify` SHA-256-hashes the message internally — the same
    // pre-hash kryptering applies before C_Sign.
    token
        .public
        .verify(tbs.as_slice(), &signature)
        .expect("the raw HSM signature verifies under the token's public key");
}
