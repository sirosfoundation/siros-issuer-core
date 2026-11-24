//! The certificate chains `[signing]` configures. Source of truth: RFC 7515
//! §4.1.6 (`x5c`) and RFC 9360 §2 (`x5chain`): the first certificate carries
//! the public key of the signing key.

#[path = "pkcs11_provision.rs"]
mod provision;

use provision::{self_signed, write_chain};
use siros_issuer_service::config::SigningCfg;
use siros_issuer_service::signers;

/// Both chains (credential and metadata) are accepted in order when their
/// leaf certifies their key, and a startup refusal when it does not: another
/// key's certificate, the right certificates in the wrong order, or bytes
/// that are not a certificate.
#[test]
fn a_chain_must_certify_its_signing_key() {
    let directory = tempfile::tempdir().unwrap();
    let file = |name: &str| directory.path().join(name);
    let mut jwks = Vec::new();
    let mut certificates = Vec::new();
    for name in ["credential.jwk", "metadata.jwk"] {
        let jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        std::fs::write(file(name), serde_json::to_string(&jwk).unwrap()).unwrap();
        let d = siros_issuer_core::sdjwt_issue::b64u_decode(jwk.d.as_deref().unwrap()).unwrap();
        certificates.push(self_signed(&p256::ecdsa::SigningKey::from_slice(&d).unwrap()).unwrap());
        jwks.push(file(name));
    }
    // Any other certificate stands in for the issuing CA's.
    let ca = self_signed(&p256::ecdsa::SigningKey::random(
        &mut p256::ecdsa::signature::rand_core::OsRng,
    ))
    .unwrap();

    let build = |surface: usize, chain: &[&[u8]]| {
        let path = file("chain.pem");
        write_chain(&path, chain);
        let mut signing = SigningCfg {
            jwk_path: Some(jwks[0].clone()),
            ..Default::default()
        };
        if surface == 0 {
            signing.cert_chain_path = Some(path);
        } else {
            signing.metadata_jwk_path = Some(jwks[1].clone());
            signing.metadata_cert_chain_path = Some(path);
        }
        signers::from_config(&signing).map(|built| {
            if surface == 0 {
                built.credential_chain
            } else {
                built.metadata.expect("a metadata signer").1
            }
        })
    };
    for surface in [0, 1] {
        let (own, other) = (&certificates[surface], &certificates[1 - surface]);
        assert_eq!(
            build(surface, &[own, &ca]).expect("its own leaf"),
            vec![own.clone(), ca.clone()]
        );
        for refused in [
            &[other.as_slice()][..],
            &[ca.as_slice(), own.as_slice()][..],
            &[b"not a certificate".as_slice()][..],
            &[][..],
        ] {
            assert_eq!(build(surface, refused).unwrap_err().code, "configuration");
        }
    }
}
