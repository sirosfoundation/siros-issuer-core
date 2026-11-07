//! The PKCS#11 signer provider (design §11.1): the production signing
//! path — keys live on an HSM (or a SoftHSM slot for dev/tests), and no
//! issuer code path may require private key material in memory.
//!
//! All issuer signatures — compact ES256 JWTs (SD-JWT credentials, the
//! status-service client assertion, signed metadata) and RFC 9052
//! Sig_structures (mdoc issuerAuth) — cross `signer::Signer` exactly as
//! they do with the in-memory JWK provider; the issuance code cannot
//! tell the providers apart (that is the trait's point).
//!
//! kryptering's `Pkcs11Signer` signs with `CKM_ECDSA` over the
//! pre-hashed data and returns **raw `r || s`** — the shapes both JWS
//! compact ES256 and COSE ES256 want, so no DER/raw translation is
//! needed on either path.
//!
//! `public_jwk()` reads the token's public key (CKA_EC_POINT +
//! CKA_EC_PARAMS) and converts it to a JWK — public material, served
//! for JWKS/evidence/thumbprints; the private key never leaves the
//! token.

use std::path::Path;

use kryptering::pkcs11::{Pkcs11Provider, Pkcs11Session, Pkcs11Signer as KrypteringSigner};

use siros_issuer_core::error::code;
use siros_issuer_core::signer::Signer;
use siros_issuer_core::{Error, Result};

/// PKCS#11 signing configuration (`[signing.pkcs11]`). Present ⇒ the
/// PKCS#11 provider replaces the in-memory JWK (the two are mutually
/// exclusive: one signing key, one provider).
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pkcs11Cfg {
    /// The PKCS#11 module (vendor `.so` path; `/usr/lib/softhsm/
    /// libsofthsm2.so` for dev/tests).
    pub module_path: String,
    /// Token slot id. Absent = the provider picks the first slot with a
    /// token present.
    #[serde(default)]
    pub slot_id: Option<u64>,
    /// The token's user PIN (SO PIN never). Production deployments
    /// inject it via the secret manager / environment, never the config
    /// file; absent works with read-only sessions where the vendor
    /// permits it.
    #[serde(default)]
    pub pin: Option<String>,
    /// The private key's CKA_LABEL.
    pub key_label: String,
    /// The `kid` the issuer advertises (JWKS, header `kid`). From
    /// configuration — never derived from private key material
    /// (design §11.1: `kid`s come from config or the public handle).
    pub kid: String,
}

/// The PKCS#11 `signer::Signer` provider: an authenticated session to
/// a token, a private-key handle found by label, and kryptering's
/// `Pkcs11Signer` doing the C_Sign work. The session and handle are
/// opened at startup; `sign` only locks and signs.
pub struct Pkcs11SignerProvider {
    signer: KrypteringSigner,
    public: jose_rs::jwk::Jwk,
}

impl Pkcs11SignerProvider {
    /// Open the session, find the key, and read the public JWK: startup
    /// work, so a misconfigured module/key fails fast at boot — never
    /// at first issuance.
    pub fn connect(cfg: &Pkcs11Cfg) -> Result<Self> {
        if !Path::new(&cfg.module_path).is_file() {
            return Err(Error::configuration(format!(
                "signing.pkcs11.module_path {} is not a file",
                cfg.module_path
            )));
        }
        let started = std::time::Instant::now();
        let provider = match cfg.slot_id {
            Some(slot) => Pkcs11Provider::new_with_slot_id(Path::new(&cfg.module_path), slot),
            None => Pkcs11Provider::new(Path::new(&cfg.module_path)),
        }
        .map_err(|e| {
            Error::configuration(format!("signing.pkcs11 module {}: {e}", cfg.module_path))
        })?;
        let elapsed = started.elapsed();
        if elapsed > std::time::Duration::from_secs(5) {
            // kryptering has no logging dependency — the caller warns.
            tracing::warn!(
                seconds = elapsed.as_secs(),
                "pkcs11 module initialization was slow (a healthy local SoftHSM takes milliseconds; a network HSM client should be well under a second)"
            );
        }

        let session = match cfg.pin.as_deref() {
            Some(pin) => provider.open_session(pin),
            None => provider.open_session_bytes(b""),
        }
        .map_err(|e| {
            Error::configuration(format!(
                "signing.pkcs11 session on slot {}: {e}",
                provider.slot_id()
            ))
        })?;

        // ES256 is the one issuer algorithm (advertised everywhere);
        // kryptering validates the key's curve (CKA_EC_PARAMS) against it
        // at handle time.
        let algorithm = jose_rs::JwsAlgorithm::from_str("ES256")
            .expect("ES256 is a known JWS algorithm")
            .to_crypto()
            .expect("ES256 maps to a crypto algorithm");
        let signer = KrypteringSigner::new(&session, &cfg.key_label, algorithm).map_err(|e| {
            Error::configuration(format!("signing.pkcs11 key {:?}: {e}", cfg.key_label))
        })?;

        // The public JWK from the token (public material): the private
        // key never leaves it.
        let public = public_jwk(&session, &cfg.key_label, &cfg.kid)?;
        Ok(Self { signer, public })
    }
}

impl Signer for Pkcs11SignerProvider {
    /// Compact ES256 JWT: kryptering digests (SHA-256) and C_Signs,
    /// returning raw `r || s` (RFC 7515 §5.2's exact ES256 shape —
    /// kryptering validates the 64-byte length); the compact form is
    /// assembled here.
    fn sign_es256(&self, header: &jose_rs::JoseHeader, payload: &[u8]) -> Result<String> {
        use kryptering::Signer as _;
        // RFC 7515 §5.2: the JWS Signing Input is the ASCII
        // `b64(header) || "." || b64(payload)` — kryptering SHA-256-prehashes
        // and C_Signs exactly those bytes (raw `r || s` out: ES256's JWS
        // form).
        let header_bytes =
            serde_json::to_vec(header).map_err(|e| Error::invalid_input(format!("{e}")))?;
        let h = siros_issuer_core::sdjwt_issue::b64u(&header_bytes);
        let p = siros_issuer_core::sdjwt_issue::b64u(payload);
        let signing_input = format!("{h}.{p}");
        let signature = self
            .signer
            .sign(signing_input.as_bytes())
            .map_err(|e| Error::new(code::TRANSPORT, format!("pkcs11 signing: {e}")))?;
        let s = siros_issuer_core::sdjwt_issue::b64u(&signature);
        Ok(format!("{h}.{p}.{s}"))
    }

    /// RFC 9052 Sig_structure (mdoc issuerAuth): the tbs bytes signed
    /// raw — the same C_Sign (SHA-256 pre-hash, raw `r || s`), no JWS
    /// envelope.
    fn sign_es256_raw(&self, tbs: &[u8]) -> Result<Vec<u8>> {
        use kryptering::Signer as _;
        self.signer
            .sign(tbs)
            .map_err(|e| Error::new(code::TRANSPORT, format!("pkcs11 raw signing: {e}")))
    }

    /// The token's public key as a JWK (`kid` from configuration).
    fn public_jwk(&self) -> Result<jose_rs::jwk::Jwk> {
        Ok(self.public.clone())
    }
}

/// Read the token's public key (found by the private key's label) and
/// convert it to a P-256 JWK. Public material only.
fn public_jwk(session: &Pkcs11Session, label: &str, kid: &str) -> Result<jose_rs::jwk::Jwk> {
    let handle = session
        .find_public_key(label)
        .map_err(|e| Error::configuration(format!("signing.pkcs11 public key {:?}: {e}", label)))?;
    let inner = session.session();
    let guard = inner
        .lock()
        .map_err(|e| Error::configuration(format!("pkcs11 session lock poisoned: {e}")))?;
    use cryptoki::object::AttributeType;
    let attributes = guard
        .get_attributes(handle, &[AttributeType::EcPoint])
        .map_err(|e| Error::configuration(format!("reading the public key: {e}")))?;
    let mut ec_point = None;
    for attribute in attributes {
        if let cryptoki::object::Attribute::EcPoint(bytes) = attribute {
            ec_point = Some(bytes);
        }
    }
    let ec_point =
        ec_point.ok_or_else(|| Error::configuration("the public key has no CKA_EC_POINT"))?;
    // SEC1 uncompressed point: 0x04 || X || Y (65 bytes for P-256). PKCS#11
    // v2.40 publishes CKA_EC_POINT **DER-encoded** — most vendors (incl.
    // SoftHSM) wrap it in an OCTET STRING (`04 41 <point>`); a raw point
    // is accepted too.
    let mut point: &[u8] = ec_point.as_ref();
    if point.len() == 67 && point[0] == 0x04 && point[1] == 65 {
        point = &point[2..];
    }
    let bytes: &[u8] = point;
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(Error::configuration(
            "the token's public key is not an uncompressed P-256 point",
        ));
    }
    let (x, y) = (&bytes[1..33], &bytes[33..]);
    serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": siros_issuer_core::sdjwt_issue::b64u(x),
        "y": siros_issuer_core::sdjwt_issue::b64u(y),
        "kid": kid,
        "alg": "ES256",
        "use": "sig",
    }))
    .map_err(|e| Error::configuration(format!("public jwk: {e}")))
}
