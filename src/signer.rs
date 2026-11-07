//! The signing effect interface (design §11.1).
//!
//! All issuer signatures — SD-JWT (and later mdoc) credentials, and the
//! siros-status-service client assertion — cross this trait. No code path
//! may require private key material in memory: an HSM-resident key must be
//! usable for every issuer signature without export. Public keys are public
//! material and are served from `public_jwk()` (JWKS, evidence, thumbprints).
//!
//! Providers, not flags: `JwkSigner` is the in-memory provider (dev, tests,
//! key-file deployments); the production provider is PKCS#11 via
//! kryptering's `cryptoki` feature (the verifier-core ReaderAuth stack),
//! which implements this same trait in the service crate.

use crate::error::{code, Error, Result};
use jose_rs::jwk::Jwk;
use jose_rs::JoseHeader;

/// One signing surface: compact ES256 JWTs with a caller-supplied header.
pub trait Signer: Send + Sync {
    /// Sign `payload` under `header` and return the compact JWT. The
    /// provider owns serialization; ES256 is the only advertised issuer
    /// algorithm (see credential_signing_alg_values_expected).
    fn sign_es256(&self, header: &JoseHeader, payload: &[u8]) -> Result<String>;

    /// ES256 over raw bytes (RFC 9052 Sig_structure): SHA-256 then ECDSA,
    /// returning the raw `r || s` signature. COSE_Sign1 (mdoc issuerAuth)
    /// needs this; the JWS compact form cannot express it. HSM providers
    /// implement it with the same key the JWS path uses.
    fn sign_es256_raw(&self, tbs: &[u8]) -> Result<Vec<u8>>;

    /// The signing key's public JWK, `kid` set. Safe to publish (JWKS).
    fn public_jwk(&self) -> Result<Jwk>;
}

/// The in-memory provider: wraps a private JWK. Dev, tests, and key-file
/// deployments. Production HSM deployments use the PKCS#11 provider in the
/// service crate instead.
#[derive(Clone)]
pub struct JwkSigner {
    private: Jwk,
    public: Jwk,
}

impl JwkSigner {
    pub fn new(private: Jwk) -> Result<Self> {
        if private.d.is_none() {
            return Err(Error::configuration("JwkSigner needs a private JWK"));
        }
        let mut public = private.to_public_jwk();
        public.kid = private.kid.clone();
        Ok(Self { private, public })
    }
}

impl Signer for JwkSigner {
    fn sign_es256(&self, header: &JoseHeader, payload: &[u8]) -> Result<String> {
        // Key-reference members (x5c) are allowed whenever present; jose-rs
        // gates them behind this option and the HSM provider has the same
        // freedom — the header is the issuer's own choice.
        let opts = jose_rs::jws::compact::SignOptions::new().with_key_reference_headers(true);
        jose_rs::jws::compact::sign_with_jwk_options(&self.private, payload, header, &opts)
            .map_err(|e| Error::new(code::TRANSPORT, format!("signing: {e}")))
    }

    /// RFC 9052 Sig_structure signing: SHA-256 then ECDSA over the raw
    /// bytes (mdoc issuerAuth). Same private key, no JWS envelope. The
    /// private scalar comes from the JWK `d` (base64url, 32 bytes).
    fn sign_es256_raw(&self, tbs: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::Signer;
        let d = self.private.d.clone().ok_or_else(|| {
            Error::new(code::CONFIGURATION, "signing JWK has no private scalar d")
        })?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &d)
            .map_err(|_| Error::new(code::CONFIGURATION, "signing JWK d not base64url"))?;
        let key = p256::ecdsa::SigningKey::from_bytes(bytes.as_slice().into())
            .map_err(|e| Error::new(code::CONFIGURATION, format!("signing key: {e}")))?;
        let signature: p256::ecdsa::Signature = key.sign(tbs);
        Ok(signature.to_bytes().to_vec())
    }

    fn public_jwk(&self) -> Result<Jwk> {
        Ok(self.public.clone())
    }
}
