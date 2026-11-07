//! Service configuration (design §4.3). TOML, matching verifier-core's
//! deployment schema convention. Deployment settings never leak into the
//! core.

use serde::Deserialize;
use siros_issuer_core::{Error, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer: IssuerCfg,
    #[serde(default)]
    pub signing: SigningCfg,
    #[serde(default)]
    pub authorization: AuthorizationCfg,
    #[serde(default)]
    pub catalog: CatalogCfg,
    #[serde(default)]
    pub storage: StorageCfg,
    /// Wallet-surface rate limiting (§11): vc's defaults unless set.
    #[serde(default)]
    pub rate_limit: crate::rate_limit::RateLimitCfg,
    #[serde(default)]
    pub zk: ZkCfg,
    #[serde(default)]
    pub issuance: IssuanceCfg,
    #[serde(default)]
    pub service: ServiceCfg,
    #[serde(default)]
    pub session: SessionCfg,
    #[serde(default)]
    pub status_service: Option<StatusServiceCfg>,
    #[serde(default)]
    pub pdp: Option<PdpCfg>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationCfg {
    /// Mode A login handoff target (design §7.2). None: wallet-initiated
    /// issuance is disabled (the authorize endpoint refuses).
    pub login_url: Option<String>,
    /// Pre-registered clients (design §12.2, resolved): client_id → JWK
    /// set + redirect_uri allowlist. The OIDF issuer plan verifies
    /// private_key_jwt against these.
    #[serde(default)]
    pub clients: crate::client_auth::ClientRegistry,
    /// §5.1.2 scope-based credential requests: scope →
    /// credential_configuration_id (the OIDF plan's client.scope form).
    #[serde(default)]
    pub scopes: std::collections::HashMap<String, String>,
    /// The attestation policy layer (vc translation): rules = default-open
    /// wildcard rules; a PDP provider is the production path.
    #[serde(default)]
    pub attestation: AttestationCfg,
}

/// A rulebook (design §8.3 item 5): the bundle that makes a credential
/// ZK-provable. **General**: a rulebook governs any set of credentials,
/// binds them to zk proof systems (resolved through the circuit catalog,
/// §8.3 item 1), and carries the auxiliary-data plan. nym_auth is rulebook
/// #1 — configured here as data; new rulebooks need no code changes
/// unless they need a new derivation primitive.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulebookCfg {
    /// The credential configuration ids (vct / doctype) this rulebook
    /// governs. General: a rulebook may govern several; a credential may
    /// match at most one (ambiguity is a startup refusal).
    #[serde(default)]
    pub credentials: Vec<String>,
    /// The zk proof systems the credentials are provable under (e.g.
    /// "vega-mc"). The circuit catalog resolves their issuance parameters
    /// (§8.3 item 1); this is the general proof-system binding, never a
    /// credential name.
    #[serde(default)]
    pub zk_systems: Vec<String>,
    /// Optional pinned salt length (vc `zk_salt_bytes` override): stands
    /// in when the catalog cannot answer (unreachable, system not
    /// published), wins-but-logs against a disagreeing live answer, and
    /// **never** overrides a live catalog refusal.
    #[serde(default)]
    pub pinned_salt_bytes: Option<usize>,
    /// Auxiliary data: to_wallet entries (openings the issuer derives and
    /// returns) and to_issuer entries (commitments the wallet sends).
    #[serde(default)]
    pub auxiliary_data: AuxiliaryDataCfg,
}

/// Auxiliary data configuration (vc `AuxiliaryDataSupported` shape).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuxiliaryDataCfg {
    #[serde(default)]
    pub to_wallet: Vec<AuxiliaryEntryCfg>,
    #[serde(default)]
    pub to_issuer: Vec<AuxiliaryEntryCfg>,
}

/// One auxiliary-data entry (vc `AuxiliaryDataEntry`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuxiliaryEntryCfg {
    /// sha-256 (the one alg the extension defines).
    pub alg: String,
    /// The claims path the commitment is written to.
    pub path: Vec<String>,
    /// How the opening is derived (to_wallet only).
    #[serde(default)]
    pub opening: Option<OpeningCfg>,
    /// How the commitment is encoded in the document claim.
    #[serde(default)]
    pub encoding: Option<String>,
}

/// How a to_wallet opening is derived (vc `OpeningArgs`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpeningCfg {
    #[default]
    None,
    Hkdf {
        secret_b64url: String,
        inputs: Vec<String>,
        bytes: usize,
    },
    Random {
        bytes: usize,
    },
    Claim {
        input: String,
    },
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AttestationCfg {
    /// vc's rule shape as native config; empty = default open.
    #[serde(default)]
    pub rules: Vec<crate::client_auth::AttestationRule>,
    /// Route tier authorization through the PDP instead of local rules.
    #[serde(default)]
    pub use_pdp: bool,
}

/// The ZK layer's deployment configuration (design §8.3): where circuit
/// constraints come from, and the rulebooks. General: systems and
/// rulebooks are data — the code is the engine.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ZkCfg {
    /// The circuit catalog (§8.3 item 1): the source of zk issuance
    /// parameters. Exactly one source mode, like `[catalog]`.
    #[serde(default)]
    pub circuits: ZkCircuitsCfg,
    /// Rulebooks (§8.3 item 5): name → bundle. nym_auth is #1.
    #[serde(default)]
    pub rulebooks: std::collections::HashMap<String, RulebookCfg>,
}

/// Storage configuration (design §6.4): the session store backend —
/// MongoDB is the production deployment, the in-memory store the default
/// (tests, single-process dev). One backend, exclusively.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StorageCfg {
    /// The MongoDB connection: present ⇒ the Mongo backend serves
    /// `SessionStore` (database/collection are the deployment's clean
    /// separation — one tenant per database, purely from config).
    /// Absent ⇒ in-memory.
    #[serde(default)]
    pub mongodb: Option<MongoCfg>,
}

/// `[storage.mongodb]`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MongoCfg {
    /// The connection URI (`mongodb://…`). HTTP-only URIs are refused
    /// in production by the URL policy; `mongodb+srv` needs the
    /// dns-resolver feature — the default service build resolves
    /// hostnames via the URI's.
    pub uri: String,
    /// One tenant per database, purely from config (design §6.4).
    pub database: String,
    /// The sessions collection.
    #[serde(default = "default_sessions_collection")]
    pub collection: String,
}

fn default_sessions_collection() -> String {
    "sessions".to_owned()
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ZkCircuitsCfg {
    /// Static fixture mode (air-gapped / tests): a directory of circuit
    /// manifest JSON files, loaded at startup.
    pub static_dir: Option<std::path::PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SigningCfg {
    /// Path to the SD-JWT signing key (JWK JSON). Absent: an ephemeral
    /// dev key is generated at startup and the credential_issuer metadata
    /// advertises it — fine for development, never for production.
    pub jwk_path: Option<std::path::PathBuf>,
    /// The PKCS#11 (HSM) signing provider (design §11.1): present ⇒ the
    /// token's key signs every issuer signature and **`jwk_path` must be
    /// absent** — one signing key, one provider, and an HSM deployment
    /// must never silently fall back to a file key.
    #[serde(default)]
    pub pkcs11: Option<crate::pkcs11::Pkcs11Cfg>,
    /// Request-encryption key (JWK JSON): published as
    /// credential_request_encryption.jwks, used to decrypt wallet
    /// requests sent as application/jwt (Final §8.2/§12.2.4). Absent:
    /// credential_request_encryption is omitted from metadata (the
    /// metadata suite warns then, in plain variants).
    pub request_encryption_jwk_path: Option<std::path::PathBuf>,
    /// The issuer's certificate chain (PEM, leaf first): the mdoc
    /// IssuerSigned x5chain. Required for mso_mdoc issuance.
    pub cert_chain_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IssuanceCfg {
    /// SD-JWT VC lifetime (`exp` − `iat`).
    #[serde(default = "default_credential_validity")]
    pub credential_validity_seconds: i64,
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl_seconds: i64,
    #[serde(default = "default_c_nonce_ttl")]
    pub c_nonce_ttl_seconds: i64,
    /// Batch issuance (Final §12.2.2): the advertised `batch_size`,
    /// enabling the batch endpoint. Absent = batch issuance not
    /// supported (the metadata omits `batch_credential_issuance` and
    /// the suite's batch module skips — permitted). Must be ≥ 2.
    #[serde(default)]
    pub batch_size: Option<u32>,
}

fn default_credential_validity() -> i64 {
    3600
}
fn default_access_token_ttl() -> i64 {
    300
}
fn default_c_nonce_ttl() -> i64 {
    300
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerCfg {
    /// HTTPS, or HTTP on loopback for development.
    pub url: String,
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// Local-test-only: allow plain-HTTP non-loopback URLs (the conformance
    /// compose network). The verifier-core conformance fixtures carry the
    /// same escape hatch (allow_invalid_status_list_certificates). Never
    /// set this outside a test deployment.
    #[serde(default)]
    pub allow_insecure_url: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CatalogCfg {
    /// TS11 registry mirrors, tried in order; the first that answers wins
    /// (design §8.1). Empty when `static_dir` is used.
    #[serde(default)]
    pub mirrors: Vec<String>,
    /// Development/fixture mode: load the catalog from this directory and
    /// never touch the network. Exactly one of this and `mirrors` is valid.
    pub static_dir: Option<PathBuf>,
    /// Refresh interval for the working catalog. 0 disables refresh.
    #[serde(default = "default_refresh_seconds")]
    pub refresh_seconds: u64,
}

fn default_refresh_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceCfg {
    pub bind: String,
}

impl Default for ServiceCfg {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".to_owned(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionCfg {
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub retention_after_final_seconds: u64,
    /// The retention sweeper's period (design §6.3): every pass expires
    /// TTL-lapsed sessions, purges sealed data off final records, and
    /// hard-deletes past `retention_after_final_seconds`. 0 disables
    /// the sweeper (expiry then happens lazily at access).
    #[serde(default = "default_sweep_interval_seconds")]
    pub sweep_interval_seconds: u64,
}

fn default_sweep_interval_seconds() -> u64 {
    60
}

impl Default for SessionCfg {
    fn default() -> Self {
        Self {
            default_ttl_seconds: 300,
            max_ttl_seconds: 3600,
            retention_after_final_seconds: 86_400,
            sweep_interval_seconds: default_sweep_interval_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusServiceCfg {
    pub as_url: String,
    pub ingestion_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdpCfg {
    pub url: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::configuration(format!("reading {}: {e}", path.display())))?;
        Self::from_toml_str(&text)
    }

    pub fn from_toml_str(text: &str) -> Result<Self> {
        let config: Config = toml::from_str(text)
            .map_err(|e| Error::configuration(format!("invalid configuration: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Fail-closed startup validation (design §11). With
    /// `allow_insecure_url`, plain-HTTP non-loopback URLs are accepted —
    /// a documented local-test escape hatch, never a production setting.
    fn validate(&self) -> Result<()> {
        let url_check = |label: &str, value: &str| -> Result<()> {
            let result = if self.issuer.allow_insecure_url {
                url::Url::parse(value)
                    .map(|_| ())
                    .map_err(|e| Error::configuration(format!("{label}: {e}")))
            } else {
                siros_verifier_core::ts11::https_url(value)
                    .map(|_| ())
                    .map_err(|e| Error::configuration(format!("{label}: {e}")))
            };
            result
        };
        url_check("issuer.url", &self.issuer.url)?;

        let has_mirrors = !self.catalog.mirrors.is_empty();
        let has_static = self.catalog.static_dir.is_some();
        if has_mirrors == has_static {
            return Err(Error::configuration(
                "catalog must have exactly one of static_dir (dev) or mirrors (live)",
            ));
        }
        for mirror in &self.catalog.mirrors {
            siros_verifier_core::ts11::https_url(mirror)
                .map_err(|e| Error::configuration(format!("catalog mirror {mirror}: {e}")))?;
        }
        for server in &self.issuer.authorization_servers {
            url_check("authorization server", server)?;
        }
        if let Some(status) = &self.status_service {
            url_check("status_service.as_url", &status.as_url)?;
            url_check("status_service.ingestion_url", &status.ingestion_url)?;
        }
        if let Some(pdp) = &self.pdp {
            url_check("pdp.url", &pdp.url)?;
        }
        if let Some(login) = &self.authorization.login_url {
            url_check("authorization.login_url", login)?;
        }
        if let Some(signing) = &self.signing.jwk_path {
            if !signing.is_file() {
                return Err(Error::configuration(format!(
                    "signing.jwk_path {} does not exist",
                    signing.display()
                )));
            }
        }
        if self.session.default_ttl_seconds == 0
            || self.session.default_ttl_seconds > self.session.max_ttl_seconds
        {
            return Err(Error::configuration(
                "session.default_ttl_seconds must be in 1..=max_ttl_seconds",
            ));
        }
        // One signing key, one provider: a PKCS#11 configuration is an HSM
        // deployment and must never silently fall back to a file key.
        if let Some(pkcs11) = &self.signing.pkcs11 {
            if self.signing.jwk_path.is_some() {
                return Err(Error::configuration(
                    "signing.jwk_path and signing.pkcs11 are mutually exclusive — the HSM provider signs or the file key does, never both",
                ));
            }
            if pkcs11.key_label.is_empty() || pkcs11.module_path.is_empty() {
                return Err(Error::configuration(
                    "signing.pkcs11 needs module_path and key_label",
                ));
            }
        }
        // A credential governed by two rulebooks is ambiguous — which
        // bundle governs its issuance? Refused at startup, never picked
        // (design §8.3 item 5: resolution is unambiguous or refused).
        let mut governed_by: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::new();
        for (name, rulebook) in &self.zk.rulebooks {
            if rulebook.credentials.is_empty() {
                return Err(Error::configuration(format!(
                    "zk.rulebooks.{name} governs no credentials"
                )));
            }
            for credential in &rulebook.credentials {
                if let Some(other) = governed_by.insert(credential, name) {
                    return Err(Error::configuration(format!(
                        "credential {credential:?} is governed by both rulebook {other:?} and {name:?} — exactly one must govern it"
                    )));
                }
            }
            if let Some(pin) = rulebook.pinned_salt_bytes {
                if !(siros_issuer_core::zk::MIN_SALT_BYTES..=siros_issuer_core::zk::MAX_SALT_BYTES)
                    .contains(&pin)
                {
                    return Err(Error::configuration(format!(
                        "zk.rulebooks.{name}.pinned_salt_bytes {pin} is outside [{}, {}]",
                        siros_issuer_core::zk::MIN_SALT_BYTES,
                        siros_issuer_core::zk::MAX_SALT_BYTES
                    )));
                }
            }
        }
        Ok(())
    }
}
