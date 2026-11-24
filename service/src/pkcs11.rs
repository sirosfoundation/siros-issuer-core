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

use std::path::{Path, PathBuf};

use kryptering::pkcs11::{Pkcs11Provider, Pkcs11Session, Pkcs11Signer as KrypteringSigner};

use siros_issuer_core::error::code;
use siros_issuer_core::signer::Signer;
use siros_issuer_core::{Error, Result};

/// PKCS#11 signing configuration (`[signing.pkcs11]`,
/// `[signing.metadata_pkcs11]`). Present ⇒ the PKCS#11 provider replaces
/// the in-memory JWK for that signing surface (the two are mutually
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
    /// Connect `[signing.pkcs11]` alone.
    pub fn connect(cfg: &Pkcs11Cfg) -> Result<Self> {
        Pkcs11Tokens::default().signer("signing.pkcs11", cfg)
    }
}

/// The tokens logged in to during startup, so that keys on one token share
/// its session. PKCS#11 login state belongs to the application and the
/// token, not to the session: a second `C_Login` on the same token fails
/// with `CKR_USER_ALREADY_LOGGED_IN` without checking the PIN (PKCS#11
/// v2.40 §5.6, `C_Login`).
#[derive(Default)]
pub struct Pkcs11Tokens(Vec<Token>);

struct Token {
    module: PathBuf,
    slot: u64,
    pin: Option<String>,
    session: Pkcs11Session,
}

impl Pkcs11Tokens {
    /// Open the session (or reuse the token's), find the key, and read the
    /// public JWK: startup work, so a misconfigured module/key fails fast
    /// at boot — never at first issuance. `section` names the configuration
    /// section in refusals.
    pub fn signer(&mut self, section: &str, cfg: &Pkcs11Cfg) -> Result<Pkcs11SignerProvider> {
        let session = self.session(section, cfg)?;

        // ES256 is the one issuer algorithm (advertised everywhere);
        // kryptering validates the key's curve (CKA_EC_PARAMS) against it
        // at handle time.
        let algorithm = jose_rs::JwsAlgorithm::from_str(siros_issuer_core::signer::JWS_ALG)
            .expect("ES256 is a known JWS algorithm")
            .to_crypto()
            .expect("ES256 maps to a crypto algorithm");
        let signer = KrypteringSigner::new(session, &cfg.key_label, algorithm)
            .map_err(|e| Error::configuration(format!("{section} key {:?}: {e}", cfg.key_label)))?;

        // The public JWK from the token (public material): the private
        // key never leaves it.
        let public = public_jwk(section, session, &cfg.key_label, &cfg.kid)?;
        Ok(Pkcs11SignerProvider { signer, public })
    }

    /// The authenticated session on the token `cfg` selects.
    fn session(&mut self, section: &str, cfg: &Pkcs11Cfg) -> Result<&Pkcs11Session> {
        if !Path::new(&cfg.module_path).is_file() {
            return Err(Error::configuration(format!(
                "{section}.module_path {} is not a file",
                cfg.module_path
            )));
        }
        let module = Path::new(&cfg.module_path).canonicalize().map_err(|e| {
            Error::configuration(format!("{section} module {}: {e}", cfg.module_path))
        })?;
        let started = std::time::Instant::now();
        let provider = match cfg.slot_id {
            Some(slot) => Pkcs11Provider::new_with_slot_id(&module, slot),
            None => Pkcs11Provider::new(&module),
        }
        .map_err(|e| Error::configuration(format!("{section} module {}: {e}", cfg.module_path)))?;
        let elapsed = started.elapsed();
        if elapsed > std::time::Duration::from_secs(5) {
            // kryptering has no logging dependency — the caller warns.
            tracing::warn!(
                seconds = elapsed.as_secs(),
                "pkcs11 module initialization was slow (a healthy local SoftHSM takes milliseconds; a network HSM client should be well under a second)"
            );
        }

        // The resolved slot, not the configured one: an absent slot_id and
        // an explicit one can select the same token.
        let slot = provider.slot_id();
        if let Some(index) = self
            .0
            .iter()
            .position(|token| token.module == module && token.slot == slot)
        {
            // The token would not check this PIN, so a different one is
            // refused here.
            if self.0[index].pin != cfg.pin {
                return Err(Error::configuration(format!(
                    "{section}.pin differs from the PIN already used for the same token (slot {slot})"
                )));
            }
            return Ok(&self.0[index].session);
        }

        let session = match cfg.pin.as_deref() {
            Some(pin) => provider.open_session(pin),
            None => provider.open_session_bytes(b""),
        }
        .map_err(|e| Error::configuration(format!("{section} session on slot {slot}: {e}")))?;
        self.0.push(Token {
            module,
            slot,
            pin: cfg.pin.clone(),
            session,
        });
        Ok(&self.0.last().expect("just pushed").session)
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
fn public_jwk(
    section: &str,
    session: &Pkcs11Session,
    label: &str,
    kid: &str,
) -> Result<jose_rs::jwk::Jwk> {
    let handle = session
        .find_public_key(label)
        .map_err(|e| Error::configuration(format!("{section} public key {label:?}: {e}")))?;
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
        "alg": siros_issuer_core::signer::JWS_ALG,
        "use": "sig",
    }))
    .map_err(|e| Error::configuration(format!("public jwk: {e}")))
}
