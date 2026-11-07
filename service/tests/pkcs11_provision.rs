//! Shared SoftHSM provisioning for the PKCS#11 tests (design §11.1):
//! a **real SoftHSM token** per test — config dir, software-generated
//! key imported into the token, certificate over the same key.
//!
//! Provisioning mirrors a real ceremony: key generated in software,
//! certificate issued over it, private key imported into the token
//! (`softhsm2-util --import`). Skips when softhsm2-util is absent
//! (the module is optional).

use std::path::PathBuf;
use std::process::Command;

use siros_issuer_core::signer::Signer;
use siros_issuer_service::pkcs11::{Pkcs11Cfg, Pkcs11SignerProvider};

pub const LABEL: &str = "issuer-signing-hsm";
pub const PIN: &str = "issuer-test-pin-4321";
pub const KID: &str = "issuer-signing-hsm-1";

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

/// A provisioned SoftHSM token.
pub struct SoftHsmToken {
    pub conf_dir: PathBuf,
    /// The software key's public half — the oracle: signatures verified
    /// under it prove the token's (imported) key signed.
    pub public: p256::ecdsa::VerifyingKey,
    /// A self-signed certificate over the same key (the mdoc x5chain —
    /// read by the issuance e2e; unused by the contract test).
    #[allow(dead_code)]
    pub cert_der: Vec<u8>,
}

/// Provision a fresh token, or `None` to skip (softhsm2-util absent or
/// provisioning failed).
pub fn provision() -> Option<SoftHsmToken> {
    if !which("softhsm2-util") {
        return None;
    }
    let dir = std::env::temp_dir().join(format!(
        "siros-issuer-softhsm-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos()
    ));
    let tokens = dir.join("tokens");
    std::fs::create_dir_all(&tokens).ok()?;
    let conf = dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .ok()?;

    // The key: software-generated P-256 (the issuer's algorithm).
    let secret = p256::ecdsa::SigningKey::random(&mut p256::ecdsa::signature::rand_core::OsRng);
    let key_pem_text = secret.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).ok()?;
    let key_pem = dir.join("signing-key.pem");
    std::fs::write(&key_pem, &key_pem_text).ok()?;
    use p256::pkcs8::EncodePrivateKey as _;
    let pkcs8_der = secret.to_pkcs8_der().ok()?;

    // A self-signed certificate over the same key (the mdoc x5chain).
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8_der.as_bytes()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .ok()?;
    let params = rcgen::CertificateParams::new(vec!["issuer.example.org".to_string()]).ok()?;
    let cert = params.self_signed(&kp).ok()?;

    // Import the private key into a fresh token.
    let run = |args: &[&str]| {
        Command::new("softhsm2-util")
            .env("SOFTHSM2_CONF", &conf)
            .args(args)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    };
    if !run(&[
        "--init-token",
        "--free",
        "--label",
        "issuer-test",
        "--so-pin",
        "issuer-test-so-pin",
        "--pin",
        PIN,
    ]) {
        return None;
    }
    if !run(&[
        "--import",
        key_pem.to_str()?,
        "--token",
        "issuer-test",
        "--label",
        LABEL,
        "--id",
        "01",
        "--pin",
        PIN,
    ]) {
        return None;
    }

    Some(SoftHsmToken {
        conf_dir: dir,
        public: *secret.verifying_key(),
        cert_der: cert.der().to_vec(),
    })
}

/// Connect the provider against a provisioned token.
pub fn provider(token: &SoftHsmToken) -> Pkcs11SignerProvider {
    // SoftHSM locates its token store via SOFTHSM2_CONF.
    std::env::set_var("SOFTHSM2_CONF", token.conf_dir.join("softhsm2.conf"));
    Pkcs11SignerProvider::connect(&Pkcs11Cfg {
        module_path: "/usr/lib/softhsm/libsofthsm2.so".to_owned(),
        slot_id: None,
        pin: Some(PIN.to_owned()),
        key_label: LABEL.to_owned(),
        kid: KID.to_owned(),
    })
    .expect("connects to the provisioned SoftHSM token")
}

/// The provider's public JWK as a p256 verifying key (the oracle form).
pub fn public_verifying_key(provider: &Pkcs11SignerProvider) -> p256::ecdsa::VerifyingKey {
    let public = provider.public_jwk().expect("public jwk");
    let x = siros_issuer_core::sdjwt_issue::b64u_decode(public.x.as_deref().unwrap())
        .expect("x decodes");
    let y = siros_issuer_core::sdjwt_issue::b64u_decode(public.y.as_deref().unwrap())
        .expect("y decodes");
    // SEC1 uncompressed: 0x04 || X || Y.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).expect("token key parses")
}
