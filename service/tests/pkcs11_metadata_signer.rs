//! The metadata signer's provider selection (design §11.1) against a real
//! SoftHSM token. Its own test binary: SoftHSM reads its configuration once
//! per process, so a process sees one token.
//!
//! The oracle for each signature is the software key that was imported into
//! the token.

#[path = "pkcs11_provision.rs"]
mod provision;

use provision::{import_key, provision, self_signed, write_chain, KID, LABEL, MODULE, PIN};
use siros_issuer_core::signer::Signer;
use siros_issuer_service::config::SigningCfg;
use siros_issuer_service::pkcs11::Pkcs11Cfg;
use siros_issuer_service::signers;

const METADATA_LABEL: &str = "issuer-metadata-hsm";

/// The credential key and the metadata key on one token, the deployment
/// `[signing.metadata_pkcs11]` is for: both sign, each under its own key.
/// PKCS#11 refuses a second login on the token, so this only holds when the
/// keys share a session. The shared login never checks the second PIN, so a
/// different one is refused, not ignored. A chain for the other key on the
/// token is refused too (RFC 7515 §4.1.6).
#[test]
fn hsm_holds_the_credential_key_and_the_metadata_key() {
    let Some(token) = provision() else {
        eprintln!("skipping: softhsm2-util is not installed (or provisioning failed)");
        return;
    };
    let metadata_key =
        import_key(&token.conf_dir, METADATA_LABEL, "02").expect("imports the metadata key");
    std::env::set_var("SOFTHSM2_CONF", token.conf_dir.join("softhsm2.conf"));
    let key = |label: &str, kid: &str, pin: &str| Pkcs11Cfg {
        module_path: MODULE.to_owned(),
        slot_id: None,
        pin: Some(pin.to_owned()),
        key_label: label.to_owned(),
        kid: kid.to_owned(),
    };
    let (own_chain, other_chain) = (
        token.conf_dir.join("metadata-chain.pem"),
        token.conf_dir.join("credential-chain.pem"),
    );
    write_chain(&own_chain, &[&self_signed(&metadata_key).unwrap()]);
    write_chain(&other_chain, &[&token.cert_der]);
    let signing = |metadata_pin: &str, metadata_chain: &std::path::Path| SigningCfg {
        metadata_cert_chain_path: Some(metadata_chain.to_owned()),
        pkcs11: Some(key(LABEL, KID, PIN)),
        metadata_pkcs11: Some(key(METADATA_LABEL, "metadata-kid", metadata_pin)),
        ..Default::default()
    };

    let refused = signers::from_config(&signing("another-pin", &own_chain))
        .err()
        .expect("a different PIN for the same token is refused");
    assert_eq!(refused.code, "configuration");
    let refused = signers::from_config(&signing(PIN, &other_chain))
        .err()
        .expect("a chain for the other key is refused");
    assert_eq!(refused.code, "configuration");

    let built = signers::from_config(&signing(PIN, &own_chain)).expect("both keys connect");
    let (metadata, _) = built.metadata.expect("a metadata signer");
    assert_signs_under(built.credential.as_ref(), &token.public, KID);
    assert_signs_under(
        metadata.as_ref(),
        metadata_key.verifying_key(),
        "metadata-kid",
    );
}

fn assert_signs_under(signer: &dyn Signer, key: &p256::ecdsa::VerifyingKey, kid: &str) {
    use p256::ecdsa::signature::Verifier as _;
    let jwk = signer.public_jwk().expect("public jwk");
    assert_eq!(jwk.kid.as_deref(), Some(kid));
    let jws = signer
        .sign_es256(&jose_rs::JoseHeader::new("ES256"), b"{}")
        .expect("signs");
    jose_rs::jws::compact::verify_with_jwk(&jwk, &jws).expect("verifies under the public JWK");
    let (input, signature) = jws.rsplit_once('.').expect("compact JWS");
    let signature = siros_issuer_core::sdjwt_issue::b64u_decode(signature).expect("base64url");
    key.verify(
        input.as_bytes(),
        &p256::ecdsa::Signature::from_slice(&signature).expect("raw r||s"),
    )
    .expect("verifies under the imported key");
}
