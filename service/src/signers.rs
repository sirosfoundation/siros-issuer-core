//! Signer provider selection (design §11.1): one rule for every signing
//! surface. A `pkcs11` section selects the HSM provider, a JWK path the
//! in-memory one; `Config::validate` refuses both at once. A certificate
//! chain is accepted only for the key it certifies.

use std::path::Path;
use std::sync::Arc;

use siros_issuer_core::signer::{JwkSigner, Signer, JWS_ALG};
use siros_issuer_core::{Error, Result};

use crate::api::MetadataSigner;
use crate::auth;
use crate::config::SigningCfg;
use crate::pkcs11::{Pkcs11Cfg, Pkcs11Tokens};

/// The issuer's signers, as configured.
pub struct Signers {
    /// Signs credentials and status-service client assertions, and the
    /// issuer metadata when `metadata` is None.
    pub credential: Arc<dyn Signer>,
    /// The credential key's chain (DER, leaf first); empty when
    /// `cert_chain_path` is not set.
    pub credential_chain: Vec<Vec<u8>>,
    /// Signs the issuer metadata (Final §12.2.2), and only it.
    pub metadata: Option<MetadataSigner>,
}

/// Build the signers `[signing]` configures. Startup work: a missing key
/// file, module or token key, or a chain for another key, refuses here,
/// never at first issuance.
pub fn from_config(signing: &SigningCfg) -> Result<Signers> {
    let mut tokens = Pkcs11Tokens::default();
    let credential: Arc<dyn Signer> = match configured(
        &mut tokens,
        ("signing.pkcs11", signing.pkcs11.as_ref()),
        signing.jwk_path.as_deref(),
    )? {
        Some(signer) => signer,
        None => {
            tracing::warn!(
                "no signing.jwk_path configured: an ephemeral dev key signs this process's \
                 credentials; restarts rotate the key — development only"
            );
            let jwk = jose_rs::jwk::generate_ec("P-256")
                .map_err(|e| Error::configuration(format!("keygen: {e}")))?;
            Arc::new(jwk_signer(jwk)?)
        }
    };
    let credential_chain = match &signing.cert_chain_path {
        Some(path) => chain("signing.cert_chain_path", path, credential.as_ref())?,
        None => Vec::new(),
    };
    let metadata = match configured(
        &mut tokens,
        ("signing.metadata_pkcs11", signing.metadata_pkcs11.as_ref()),
        signing.metadata_jwk_path.as_deref(),
    )? {
        Some(signer) => {
            let path = signing.metadata_cert_chain_path.as_deref().ok_or_else(|| {
                Error::configuration("the metadata key needs signing.metadata_cert_chain_path")
            })?;
            let chain = chain("signing.metadata_cert_chain_path", path, signer.as_ref())?;
            Some((signer, chain))
        }
        None => None,
    };
    Ok(Signers {
        credential,
        credential_chain,
        metadata,
    })
}

/// The provider one signing surface configures; None when it configures
/// none.
fn configured(
    tokens: &mut Pkcs11Tokens,
    (section, pkcs11): (&str, Option<&Pkcs11Cfg>),
    jwk_path: Option<&Path>,
) -> Result<Option<Arc<dyn Signer>>> {
    if let Some(pkcs11) = pkcs11 {
        return Ok(Some(Arc::new(tokens.signer(section, pkcs11)?)));
    }
    let Some(path) = jwk_path else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::configuration(format!("reading {}: {e}", path.display())))?;
    let jwk = serde_json::from_str(&text)
        .map_err(|e| Error::configuration(format!("parsing {}: {e}", path.display())))?;
    Ok(Some(Arc::new(jwk_signer(jwk)?)))
}

fn jwk_signer(mut jwk: jose_rs::jwk::Jwk) -> Result<JwkSigner> {
    if jwk.alg.is_none() {
        jwk.alg = Some(JWS_ALG.to_owned());
    }
    if jwk.kid.is_none() {
        jwk.kid = Some(auth::thumbprint(&jwk).map_err(|e| Error::configuration(e.to_string()))?);
    }
    JwkSigner::new(jwk)
}

/// Load a PEM chain (DER, leaf first) for `signer`. The first certificate
/// must certify the signing key (RFC 7515 §4.1.6, RFC 9360 §2): a relying
/// party that trusts the key through the chain rejects every signature
/// otherwise, while the issuer looks healthy.
fn chain(name: &str, path: &Path, signer: &dyn Signer) -> Result<Vec<Vec<u8>>> {
    let refuse =
        |reason: String| Error::configuration(format!("{name} {}: {reason}", path.display()));
    let text = std::fs::read_to_string(path).map_err(|e| refuse(e.to_string()))?;
    let mut chain = Vec::new();
    for block in text.split("-----END CERTIFICATE-----") {
        let Some((_, b64)) = block.split_once("-----BEGIN CERTIFICATE-----") else {
            continue;
        };
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        chain.push(
            siros_issuer_core::sdjwt_issue::b64_decode_std(&cleaned)
                .map_err(|e| refuse(e.to_string()))?,
        );
    }
    let leaf = chain
        .first()
        .ok_or_else(|| refuse("contains no certificates".to_owned()))?;
    let leaf = auth::leaf_verifying_key(leaf)
        .and_then(|key| auth::leaf_to_jwk(&key))
        .and_then(|jwk| auth::thumbprint(&jwk))
        .map_err(|e| refuse(e.to_string()))?;
    if leaf != auth::thumbprint(&signer.public_jwk()?).map_err(|e| refuse(e.to_string()))? {
        return Err(refuse(
            "the first certificate is not for the signing key (wrong chain, or not leaf first)"
                .to_owned(),
        ));
    }
    Ok(chain)
}
