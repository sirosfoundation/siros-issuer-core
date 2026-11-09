//! OpenID4VCI issuer metadata, generated entirely from the TS11 catalog
//! (design §7, §8.1). OpenID4VCI 1.0 ID1 §11.2.1.
//!
//! Configuration ids are the credential's catalog identifier (vct for
//! dc+sd-jwt, doctype for mso_mdoc) — the same identifier the backend
//! session API accepts, so `POST /issuance/sessions {"credential": ...}`
//! and the wallet's `credential_configuration_id` name the same thing
//! without a translation table. A collision between two credentials'
//! identifiers is a catalog refusal.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use siros_verifier_core::ts11::{Catalog, ClaimMetadata, CredentialType};
use std::collections::BTreeMap;
use url::Url;

pub const SD_JWT_FORMAT: &str = "dc+sd-jwt";
pub const MDOC_FORMAT: &str = "mso_mdoc";

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CredentialIssuerMetadata {
    /// Byte-identical to the configured Credential Issuer Identifier
    /// (Final §12.2.3): serialized without the empty path's trailing
    /// slash, which `Url`'s Display would add.
    pub credential_issuer: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<Url>,
    pub credential_endpoint: Url,
    /// Advertised only when deferred issuance is implemented (P2 remainder).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<Url>,
    pub nonce_endpoint: Option<Url>,
    pub notification_endpoint: Option<Url>,
    /// Final §12.2.4: issuer-level response encryption. `encryption_required`
    /// is false — plain responses are served when the wallet does not
    /// request encryption.
    pub credential_response_encryption: IssuerResponseEncryption,
    /// Final §12.2.4: request encryption (the wallet encrypts its
    /// Credential/Batch/Deferred requests to this key). Declared only
    /// when a request-encryption key is configured; the credential
    /// endpoint then accepts `application/jwt` request bodies.
    /// (Never serialized as null — the suite rejects a non-object.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_request_encryption: Option<IssuerRequestEncryption>,
    /// OID4VCI 1.0 Final §12.2.1 has no jwks/jwks_uri member at the issuer
    /// level (the conformance schema's additionalProperties is false) —
    /// wallets resolve the issuer's keys via the AS metadata's jwks_uri
    /// (`GET /jwks` still serves them).
    pub credential_configurations_supported: BTreeMap<String, CredentialConfiguration>,
    /// Final §12.2.2: batch credential issuance support — the batch
    /// endpoint and the maximum batch size (≥ 2, an integer). Advertised
    /// only when the issuer supports batch issuance; the suite's
    /// batch-issuance module skips (permitted) when the member is absent
    /// and runs its checks when present: one credential per proof, all
    /// datasets in a batch identical (the same subject data, issued once
    /// per proof key), distinct and unpredictable status indices.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,
}

/// The `batch_credential_issuance` metadata object (Final §12.2.2).
#[derive(Debug, Serialize)]
pub struct BatchCredentialIssuance {
    /// `batch_size`: REQUIRED, an integer ≥ 2 (the suite refuses
    /// anything smaller — a batch of one is not a batch).
    pub batch_size: u32,
}

/// `auxiliary_data_supported` — the Credential Auxiliary Data extension's
/// per-configuration member (vc `pkg/openid4vci/auxiliary_data.go`
/// `AuxiliaryDataSupported`, OpenID4VCI 1.1's extension): the entries a
/// governed configuration is issued with. `to_wallet` — the openings the
/// issuer derives and returns with each response; `to_issuer` — the
/// commitments the wallet sends in key proofs. Advertised ONLY on
/// rulebook-governed configurations (the plan is config data — design
/// §8.3 item 3); ungoverned configurations omit the member, so the
/// conformance profile's metadata is unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuxiliaryDataSupported {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_wallet: Vec<AuxiliaryDataWireEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_issuer: Vec<AuxiliaryDataWireEntry>,
}

/// One advertised auxiliary-data entry (vc `AuxiliaryDataEntry`). In
/// **metadata** an entry describes the mechanism — no opening or
/// commitment values ride it (those ride responses and proofs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuxiliaryDataWireEntry {
    /// `hash_commitment` — the one Auxiliary Data Type the extension
    /// defines.
    #[serde(rename = "type")]
    pub entry_type: String,
    /// sha-256 — the one hash_commitment alg the extension defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// The claims-path pointer of the claim that holds the commitment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    /// to_issuer only: the wallet MUST send this entry.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    /// How the claim at `path` represents the commitment: base64url,
    /// base64, hex text, or the raw bytes when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CredentialConfiguration {
    pub format: &'static str,
    /// dc+sd-jwt only: the vct is a bare member of the configuration
    /// (OID4VCI 1.0 Final §12.2.4 — the draft-era credential_definition
    /// wrapper is gone; the conformance schema enforces this).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    /// mso_mdoc only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    /// dc+sd-jwt: claims description objects at the configuration level
    /// (Appendix B.2). mso_mdoc: namespace → claim name → metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    /// Final §12.2.4: co-present with proof_types_supported (both or
    /// neither — VCIValidateProofTypesCoPresence).
    pub cryptographic_binding_methods_supported: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<Display>,
    pub proof_types_supported: BTreeMap<&'static str, ProofType>,
    /// sd-jwt: JWS names; mdoc: COSE integer ids (-7 = ES256).
    pub credential_signing_alg_values_supported: serde_json::Value,
    /// The Credential Auxiliary Data extension's per-configuration plan
    /// (§8.3 item 3): present only on rulebook-governed configurations —
    /// the service derives it from `[zk.rulebooks.<name>].auxiliary_data`
    /// at startup. Absent on ungoverned configurations (the conformance
    /// profile's metadata is unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auxiliary_data_supported: Option<AuxiliaryDataSupported>,
}

/// Final §12.2.4 proof type entry: proof_signing_alg_values_supported is
/// REQUIRED per proof type.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ProofType {
    pub proof_signing_alg_values_supported: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ClaimMetadataWire {
    /// Path segments; `None` is an array index (VCTM/TS 119 602 path shape).
    pub path: Vec<Option<String>>,
    pub mandatory: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<Display>,
}

/// mdoc claims carry no `path`: their position in the namespace map *is*
/// the path (OpenID4VCI ID1 mso_mdoc claims).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MdocClaimMetadataWire {
    pub mandatory: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<Display>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Display {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ResponseEncryption {
    pub alg_values_supported: Vec<&'static str>,
    pub enc_values_supported: Vec<&'static str>,
}

/// Final §12.2.4 issuer-level member (all three sub-members required).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IssuerResponseEncryption {
    pub alg_values_supported: Vec<&'static str>,
    pub enc_values_supported: Vec<&'static str>,
    pub encryption_required: bool,
}

/// Final §12.2.4 `credential_request_encryption`: the wallet encrypts
/// requests to this JWKS. `encryption_required: false` — plain request
/// bodies are accepted too. The suite's 1.0 Final metadata schema closes
/// this object to jwks/enc_values_supported/encryption_required (+zip) —
/// alg_values_supported is NOT a member (response side only).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IssuerRequestEncryption {
    pub jwks: serde_json::Value,
    pub enc_values_supported: Vec<&'static str>,
    pub encryption_required: bool,
}

/// Endpoints derived from the issuer base URL. Design §7. `deferred`
/// stays None until deferred issuance is implemented — discovery
/// advertises only implemented behavior.
#[derive(Debug, Clone)]
pub struct EndpointPaths {
    pub credential: &'static str,
    pub deferred_credential: Option<&'static str>,
    /// The batch endpoint (Final §12.2.2 `batch_credential_endpoint`).
    /// `None` = batch issuance not supported (the metadata omits
    /// `batch_credential_issuance` and the suite's batch module skips —
    /// permitted behavior). `Some` advertises the endpoint plus the
    /// batch size.
    pub batch_credential: Option<(&'static str, u32)>,
    pub nonce: Option<&'static str>,
    pub notification: Option<&'static str>,
    /// Request-encryption key (JWK JSON), published in
    /// credential_request_encryption.jwks.
    pub request_encryption_jwk: Option<serde_json::Value>,
}

impl Default for EndpointPaths {
    fn default() -> Self {
        Self {
            credential: "credential",
            deferred_credential: None,
            batch_credential: None,
            nonce: Some("nonce"),
            notification: Some("notification"),
            request_encryption_jwk: None,
        }
    }
}

/// Generate the credential-issuer metadata document from the working
/// catalog. Empty catalogs produce empty `credential_configurations_supported`
/// — the host decides whether to serve that (readiness concern).
///
/// `auxiliary_data_plans`: the per-configuration
/// Credential-Auxiliary-Data plans (§8.3 item 3) — the service derives
/// them from its rulebook config at startup; an empty map means no
/// configuration advertises `auxiliary_data_supported` (the conformance
/// profile).
pub fn metadata_from_catalog(
    issuer_base: &Url,
    catalog: &Catalog,
    authorization_servers: Vec<Url>,
    paths: &EndpointPaths,
    auxiliary_data_plans: &BTreeMap<String, AuxiliaryDataSupported>,
) -> Result<CredentialIssuerMetadata> {
    let credential_request_encryption = paths.request_encryption_jwk.as_ref().map(|jwk| {
        // Publish the PUBLIC members only: `d` never leaves the
        // server (RFC 7517 §4 — a private member in a discovery
        // document is a key-disclosure bug).
        let mut public = jwk.clone();
        if let Some(object) = public.as_object_mut() {
            object.remove("d");
        }
        IssuerRequestEncryption {
            jwks: serde_json::json!({ "keys": [public] }),
            enc_values_supported: vec!["A128GCM"],
            encryption_required: false,
        }
    });
    let join = |path: &str| -> Result<Url> {
        issuer_base
            .join(path)
            .map_err(|e| crate::error::Error::configuration(format!("issuer base URL: {e}")))
    };

    let mut configurations = BTreeMap::new();
    for credential in &catalog.credentials {
        let id = credential.identifier.clone();
        let auxiliary_data = auxiliary_data_plans.get(&id);
        // A credential without an identifier has nothing to issue
        // under — a registry document missing both vct and doctype
        // (two such collide on the empty identifier). Skipped, not
        // refused: the metadata documents what THIS deployment can
        // issue; a resolve of the skipped type still fails closed.
        if id.trim().is_empty() {
            continue;
        }
        match credential.format.as_str() {
            // This issuer issues exactly these two formats (design
            // §8.2); a catalog that ALSO carries other formats (a live
            // registry publishes types this deployment cannot issue)
            // advertises only what it issues — `credential_configurations_supported`
            // is the issuer's own offer, and a resolve of the skipped
            // type still fails closed at issuance.
            SD_JWT_FORMAT | MDOC_FORMAT => {}
            other => {
                // The skip is silent-by-design at this layer: the
                // metadata documents what THIS deployment issues, and
                // the catalog's own log surface (the service's refresh
                // logging) reports the catalog's full contents.
                let _ = other;
                continue;
            }
        }
        let configuration = match credential.format.as_str() {
            SD_JWT_FORMAT => sd_jwt_configuration(credential, auxiliary_data),
            MDOC_FORMAT => mdoc_configuration(credential, auxiliary_data),
            // Unreachable: the match above filtered to these two.
            _ => unreachable!("the format was just filtered"),
        };
        if configurations.insert(id, configuration).is_some() {
            return Err(crate::error::Error::catalog_invalid(
                "two catalog credentials share one configuration id",
            ));
        }
    }

    Ok(CredentialIssuerMetadata {
        credential_issuer: issuer_identifier(issuer_base),
        authorization_servers,
        credential_endpoint: join(paths.credential)?,
        deferred_credential_endpoint: paths.deferred_credential.map(join).transpose()?,
        // No `batch_credential_endpoint` member: the suite's metadata
        // schema (credential_issuer_metadata-1_0.json) defines none, and
        // 1.0 Final §12.2.2 runs batch issuance ON the credential
        // endpoint (the suite's batch module POSTs there; vc's metadata
        // carries only batch_credential_issuance). The `/batch-credential`
        // route remains an unadvertised alias for wallets that prefer it.
        nonce_endpoint: paths.nonce.map(join).transpose()?,
        notification_endpoint: paths.notification.map(join).transpose()?,
        credential_response_encryption: IssuerResponseEncryption {
            alg_values_supported: vec!["ECDH-ES"],
            enc_values_supported: vec!["A128GCM"],
            encryption_required: false,
        },
        credential_request_encryption,
        credential_configurations_supported: configurations,
        batch_credential_issuance: paths
            .batch_credential
            .map(|(_, batch_size)| BatchCredentialIssuance { batch_size }),
    })
}

fn sd_jwt_configuration(
    credential: &CredentialType,
    auxiliary_data: Option<&AuxiliaryDataSupported>,
) -> CredentialConfiguration {
    CredentialConfiguration {
        format: SD_JWT_FORMAT,
        vct: Some(credential.identifier.clone()),
        doctype: None,
        claims: Some(
            serde_json::to_value(
                credential
                    .claims
                    .iter()
                    .map(claim_metadata_wire)
                    .collect::<Vec<_>>(),
            )
            .expect("claims serialize"),
        ),
        // Final §12.2.4 + Appendix D: jwt proofs bind via the proof's jwk.
        cryptographic_binding_methods_supported: vec!["jwk"],
        display: vec![Display {
            name: credential.label.clone(),
            locale: None,
        }],
        proof_types_supported: BTreeMap::from([(
            "jwt",
            ProofType {
                proof_signing_alg_values_supported: vec!["ES256"],
            },
        )]),
        credential_signing_alg_values_supported: serde_json::json!(["ES256"]),
        auxiliary_data_supported: auxiliary_data.cloned(),
    }
}

fn mdoc_configuration(
    credential: &CredentialType,
    auxiliary_data: Option<&AuxiliaryDataSupported>,
) -> CredentialConfiguration {
    CredentialConfiguration {
        format: MDOC_FORMAT,
        vct: None,
        doctype: Some(credential.identifier.clone()),
        // No `claims` member for mso_mdoc: the conformance suite's
        // credential_issuer_metadata-1_0.json mso_mdoc branch defines only
        // `doctype` and `credential_signing_alg_values_supported`
        // (unevaluatedProperties:false — anything else warns as an unknown
        // extension), unlike the dc+sd-jwt branch which carries claims.
        // The catalog's claims still drive issuance (schema gate, elements).
        claims: None,
        // mdoc device keys arrive as COSE Keys (attestation proofs).
        cryptographic_binding_methods_supported: vec!["cose_key"],
        display: vec![Display {
            name: credential.label.clone(),
            locale: None,
        }],
        proof_types_supported: BTreeMap::from([(
            "attestation",
            ProofType {
                proof_signing_alg_values_supported: vec!["ES256"],
            },
        )]),
        // mdoc signs with COSE algorithm ids: -7 = ES256.
        credential_signing_alg_values_supported: serde_json::json!([-7]),
        auxiliary_data_supported: auxiliary_data.cloned(),
    }
}

fn claim_metadata_wire(metadata: &ClaimMetadata) -> ClaimMetadataWire {
    ClaimMetadataWire {
        path: metadata.path.clone(),
        mandatory: metadata.mandatory,
        display: vec![Display {
            name: metadata.label.clone(),
            locale: None,
        }],
    }
}

/// The `/.well-known/oauth-authorization-server` document. P2: both
/// grants are live — the authorization-code grant over PAR + authorize +
/// Mode A login handoff (design §7.2), the pre-authorized grant as of
/// P1. PKCE S256 is required for public clients; DPoP (RFC 9449) is
/// supported at the token and credential endpoints for
/// sender-constrained access tokens. The authorization-challenge
/// endpoint (Mode B, design §7.3) is advertised when it lands.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub pushed_authorization_request_endpoint: Url,
    pub jwks_uri: Url,
    pub grant_types_supported: Vec<&'static str>,
    pub response_types_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    /// Public clients only: `client_id` + PKCE, no client secret
    /// (OAuth 2.1 posture; the suite's and the vc profile's clients are
    /// public).
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    /// RFC 9449 DPoP.
    pub dpop_signing_alg_values_supported: Vec<&'static str>,
    /// RFC 9396 authorization details types (the suite requires
    /// openid_credential when the client requests no scope).
    pub authorization_details_types_supported: Vec<&'static str>,
}

/// The Credential Issuer Identifier as configured: `Url`'s Display
/// appends "/" to the empty path (and `set_path("")` normalizes back to
/// it for special schemes), breaking §12.2.3's byte-identical
/// comparison against the configured identifier — strip at the string
/// level.
pub fn issuer_identifier(base: &Url) -> String {
    let value = base.as_str();
    if base.path() == "/" {
        value.strip_suffix('/').unwrap_or(value).to_owned()
    } else {
        value.to_owned()
    }
}

pub const GRANT_PRE_AUTHORIZED_CODE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
pub const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";

pub fn authorization_server_metadata(issuer_base: &Url) -> Result<AuthorizationServerMetadata> {
    let join = |path: &str| -> Result<Url> {
        issuer_base
            .join(path)
            .map_err(|e| crate::error::Error::configuration(format!("issuer base URL: {e}")))
    };
    Ok(AuthorizationServerMetadata {
        issuer: issuer_identifier(issuer_base),
        authorization_endpoint: join("authorize")?,
        token_endpoint: join("token")?,
        pushed_authorization_request_endpoint: join("op/par")?,
        jwks_uri: join("jwks")?,
        grant_types_supported: vec![GRANT_AUTHORIZATION_CODE, GRANT_PRE_AUTHORIZED_CODE],
        response_types_supported: vec!["code"],
        code_challenge_methods_supported: vec!["S256"],
        token_endpoint_auth_methods_supported: vec!["none"],
        dpop_signing_alg_values_supported: vec!["ES256"],
        authorization_details_types_supported: vec!["openid_credential"],
    })
}

// ─── Credential offer (ID1 §4.1) ─────────────────────────────────────────

/// The credential offer object served by `GET /credential-offer/{uuid}`
/// and carried in the wallet deep link. The pre-authorized grant only in
/// P1; `authorization_code` joins with P2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CredentialOffer {
    /// §4.1 + §12.2.3 byte-identity: the identifier, no empty-path slash.
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GrantPreAuthorizedCode {
    /// OID4VCI ID1 §4.1.1: hyphenated, like the grant URN's tail
    /// (`pre-authorized_code`), not snake_case.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TxCode {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl CredentialOffer {
    /// The same-device deep link: pass the offer by URI reference
    /// (`openid-credential-offer://?credential_offer_uri=<uri>`).
    pub fn deep_link(offer_uri: &Url) -> Url {
        let mut link = Url::parse("openid-credential-offer://").expect("static base URL");
        link.query_pairs_mut()
            .append_pair("credential_offer_uri", offer_uri.as_str());
        link
    }
}

// ─── Token endpoint (ID1 §5, pre-authorized grant) ────────────────────────

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    /// pre-authorized grant: the code from the offer.
    #[serde(default)]
    pub pre_authorized_code: Option<String>,
    /// tx_code, when the offer carries one.
    #[serde(default)]
    pub tx_code: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub c_nonce: String,
    pub c_nonce_expires_in: i64,
}

// ─── Proof and credential (ID1 §7) ───────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CredentialRequest {
    /// Final §8.2: one of credential_configuration_id or
    /// credential_identifiers MUST be present.
    #[serde(default)]
    pub credential_configuration_id: Option<String>,
    /// Final §8.2: identifiers of previously issued credentials. An
    /// identifier this issuer never issued is `unknown_credential_identifier`.
    #[serde(default)]
    pub credential_identifiers: Option<Vec<String>>,
    /// Singular form used by the suite's identifier flows (§8.2 batch
    /// request uses `credential_identifiers`; the wallet-issued form
    /// carries one `credential_identifier`).
    #[serde(default)]
    pub credential_identifier: Option<String>,
    /// Draft-era single proof: `{"proof_type": "jwt", "jwt": "..."}`.
    #[serde(default)]
    pub proof: Option<Proof>,
    /// 1.0 Final `proofs` (§8.2): proof type → array of proof values.
    /// The suite sends this shape.
    #[serde(default)]
    pub proofs: Option<std::collections::BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
}

impl CredentialRequest {
    /// The jwt proofs under whichever shape they arrived (Final `proofs`
    /// first, draft `proof` fallback).
    pub fn jwt_proofs(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(proofs) = &self.proofs {
            for (proof_type, values) in proofs {
                for value in values {
                    out.push((proof_type.clone(), value.clone()));
                }
            }
        }
        if out.is_empty() {
            if let Some(proof) = &self.proof {
                out.push((proof.proof_type.clone(), proof.jwt.clone()));
            }
        }
        out
    }
}

#[derive(Debug, Deserialize)]
pub struct Proof {
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Debug, Deserialize)]
pub struct CredentialResponseEncryption {
    pub jwk: serde_json::Value,
    pub alg: String,
    pub enc: String,
}

#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    /// Final §8.3: `credentials` — an array of issued credentials, each
    /// `{"format": ..., "credential": ...}` (the draft-era singular
    /// `credential` member is gone; the suite requires the array).
    /// Absent in the deferred-pending response: §8.3 MUST NOT be used
    /// when `transaction_id` is present.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<CredentialEntry>,
    /// Final §9: present (with `credentials` absent) when the issuer
    /// defers — the wallet polls `deferred_credential_endpoint` with it.
    /// MUST be invalidated once the credential has been obtained
    /// (single-use, atomic — design §7.6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Final §9: poll-interval guidance (seconds) emitted with
    /// `transaction_id` (design §7.6: vc's `interval` guidance).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// Final §8.3: `notification_id` — the wallet echoes it to the
    /// notification endpoint on credential_accepted/…/credential_deleted.
    /// c_nonce/c_nonce_expires_in are NOT members of the credential
    /// response in 1.0 Final (the nonce endpoint is the source;
    /// VCIValidateNoUnknownKeysInCredentialResponse enforces the closed
    /// set {credentials, transaction_id, notification_id, interval}).
    /// MUST NOT be present when `credentials` is absent (§8.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_id: Option<String>,
    /// The auxiliary-data extension (design §8.3 item 3, vc
    /// `pkg/openid4vci/auxiliary_data.go`): response-level openings for
    /// the rulebook's commitments, under `credential_metadata`. Present
    /// only for rulebook-governed credentials (ZK issuance) — the OIDF
    /// schema has no such member, and the conformance variants never
    /// request a rulebook credential, so the closed set above never sees
    /// it. Wallets that implement the extension read the openings here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_metadata: Option<CredentialMetadata>,
}

/// Response-level credential metadata (the auxiliary-data extension's
/// carrier).
#[derive(Debug, Serialize)]
pub struct CredentialMetadata {
    pub auxiliary_data: Vec<crate::zk::AuxiliaryDataEntry>,
}

#[derive(Debug, Serialize)]
pub struct CredentialEntry {
    pub format: String,
    pub credential: String,
}

/// `POST /deferred-credential` body (Final §9 Deferred Credential Request):
/// the `transaction_id` from the pending credential response, plus —
/// optionally — response-encryption parameters for THIS response. §9.1 is
/// explicit: the Deferred Credential Response is encrypted per the
/// parameters in *this* request, "regardless of what was sent in the
/// initial Credential Request" — they are read here and never inherited
/// from the initial request.
#[derive(Debug, Deserialize)]
pub struct DeferredCredentialRequest {
    pub transaction_id: String,
    #[serde(default)]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
}

// ─── Notification (ID1 §11.3) ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct NotificationRequest {
    pub notification_id: String,
    pub event: String,
    #[serde(default)]
    pub event_description: Option<String>,
}

pub const NOTIFICATION_ACCEPTED: &str = "credential_accepted";
pub const NOTIFICATION_FAILURE: &str = "credential_failure";
pub const NOTIFICATION_DELETED: &str = "credential_deleted";

// ─── Identity match (design §6.5 v2, vc `pkg/openid4vci/identity_match.go`) ─

/// `IdentityMatch` decides whether the Holder who presented a credential is
/// the one an issuance was prepared for — the pre-auth grant's strong
/// binding (design §6.5 v2). A faithful port of vc's semantics:
///
/// Supplied by the CALLER that prepared the issuance (the backend session
/// API), never read from configuration: only that caller knows what "the
/// same user" means for its own session. Every entry must pass; an **empty
/// rule is refused** rather than treated as "anything matches" — a caller
/// that supplies no rule has not said the issuance is unbound, it has said
/// nothing, and the difference is the whole point of the mechanism.
/// Omission is not the way to ask for an unbound issuance either: binding
/// deployments refuse a creation without one (vc `PrepareIssuance`:
/// required, not omittable). An offer any wallet may complete is the
/// plain pre-authorized grant, asked for by name.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityMatch {
    /// A claim path on the presented credential → the test it must pass.
    /// The path is interpreted the way the presented credential's format
    /// interprets it: nested for SD-JWT VC, one literal namespace-qualified
    /// key for mdoc.
    pub claims: std::collections::BTreeMap<String, ClaimTest>,
}

/// How one claim is compared. An object rather than a bare value so a
/// comparison added later does not change the shape of a request a caller
/// already sends (vc `ClaimTest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimTest {
    /// The exact value the claim must have. Where the claim is an array,
    /// at least one element must equal it. Exact, deliberately not
    /// case-folded or normalised: folding a personal name is
    /// locale-dependent and gets it wrong for someone (vc's rationale).
    pub equals: String,
}

impl IdentityMatch {
    /// Refuse a rule that cannot do its job — at acceptance, not at
    /// evaluation (vc `Validate`): a caller that mistypes is told while it
    /// prepares the issuance, not when a Holder is standing there with a
    /// wallet open.
    pub fn validate(&self) -> Result<()> {
        if self.claims.is_empty() {
            return Err(crate::error::Error::invalid_input(
                "identity match: no claims to match on; a rule that matches anything is refused — an issuance any wallet may complete is the plain pre-authorized grant, which is a different request",
            ));
        }
        for (path, test) in &self.claims {
            if path.trim().is_empty() {
                return Err(crate::error::Error::invalid_input(
                    "identity match: a claim path is empty",
                ));
            }
            if test.equals.is_empty() {
                return Err(crate::error::Error::invalid_input(format!(
                    "identity match: claim {path:?} has no comparison; the only one supported is \"equals\", and it may not be empty"
                )));
            }
        }
        Ok(())
    }

    /// The paths this rule tests, in a stable order (sorted — a log line
    /// or error naming them reads the same way twice; vc `ClaimPaths`).
    pub fn claim_paths(&self) -> Vec<&str> {
        self.claims.keys().map(String::as_str).collect()
    }

    /// Evaluate the rule against a presented credential's verified claims
    /// (vc `matchPresentedIdentity` + `lookupClaimPath`, ported): every
    /// entry must pass; an absent claim is a mismatch, never a skip. The
    /// path lookup is format-aware — `is_mdoc` tries the literal
    /// namespace-qualified key first (a flat `"org.iso.18013.5.1"`
    /// entry), and SD-JWT walks nested objects only, so a flat dotted key
    /// cannot satisfy a nested requirement.
    pub fn matches(&self, claims: &serde_json::Value, is_mdoc: bool) -> Result<bool> {
        for (path, test) in &self.claims {
            let Some(value) = lookup_claim_path(claims, path, is_mdoc) else {
                return Ok(false);
            };
            if !claim_value_matches(&value, &test.equals) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Resolve a claim path against a claims object, format-aware (vc
/// `lookupClaimPath`): mdoc tries the literal key first; a path without a
/// dot is a direct lookup; otherwise the segments walk nested objects.
/// Missing or non-object intermediates resolve to nothing.
fn lookup_claim_path(
    claims: &serde_json::Value,
    path: &str,
    is_mdoc: bool,
) -> Option<serde_json::Value> {
    if is_mdoc {
        if let Some(value) = claims.get(path) {
            return Some(value.clone());
        }
    }
    if !path.contains('.') {
        return claims.get(path).cloned();
    }
    let mut cursor = claims;
    for segment in path.split('.') {
        cursor = cursor.get(segment)?;
    }
    Some(cursor.clone())
}

/// Does the presented value satisfy `equals` (vc `claimValueMatches`)? A
/// bare string compares exactly; an array matches when at least one
/// element equals it. Other shapes (numbers, objects) do not match a
/// string rule — compare as strings when the value is one.
fn claim_value_matches(value: &serde_json::Value, equals: &str) -> bool {
    match value {
        serde_json::Value::String(s) => s == equals,
        serde_json::Value::Array(elements) => elements
            .iter()
            .any(|element| element.as_str() == Some(equals)),
        _ => false,
    }
}

// ─── PAR and the authorization-code grant (ID1 §4.2.2; design §7.2) ───────

/// `POST /op/par` body (RFC 9126 §2.1 form encoding; the suite posts
/// form-encoded — JSON accepted where a client sends it). Public client;
/// PKCE required; the requested credentials ride in
/// `authorization_details` (a JSON array, form-encoded per RFC 9126 §2.1).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ParRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    /// `authorization_details` (RFC 9396): the wallet's credential requests.
    /// RFC 9396 authorization details (JSON array; in form encoding the
    /// parameter is a JSON string).
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_json_value")]
    pub authorization_details: Vec<serde_json::Value>,
    pub code_challenge: String,
    #[serde(default = "default_code_challenge_method")]
    pub code_challenge_method: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

fn default_code_challenge_method() -> String {
    "S256".to_owned()
}

/// Deserialize a JSON value from either an embedded JSON string (form
/// encoding) or the value itself (JSON body).
fn deserialize_json_value<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(text) => serde_json::from_str(&text)
            .map_err(|e| D::Error::custom(format!("authorization_details JSON: {e}"))),
        serde_json::Value::Array(items) => Ok(items),
        other => Err(D::Error::custom(format!(
            "authorization_details must be an array or a JSON string, got {}",
            other
        ))),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ParReply {
    pub request_uri: String,
    pub expires_in: i64,
}

// ─── DPoP (RFC 9449) ─────────────────────────────────────────────────────

/// The validated essence of a DPoP proof: the binding key and freshness.
#[derive(Debug, Clone)]
pub struct DpopBinding {
    /// RFC 7638 thumbprint of the proof's jwk.
    pub jkt: String,
}

/// The claims a DPoP proof must carry (RFC 9449 §4.1). `ath` is required
/// at resource endpoints and absent at the token endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DpopClaims {
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    pub jti: String,
    #[serde(default)]
    pub ath: Option<String>,
}

/// The media type of the signed credential-issuer metadata JWS (OID4VCI
/// 1.0 Final §12.2.2: `application/jwt`; the JWS `typ` header — the
/// conformance suite's `VCIDecodeSignedCredentialIssuerMetadata` requires
/// exactly this value).
pub const SIGNED_METADATA_TYP: &str = "openidvci-issuer-metadata+jwt";

/// Sign the credential-issuer metadata document (OID4VCI 1.0 Final
/// §12.2.2, content negotiation per RFC 8414 §3.2 practice): a compact
/// ES256 JWS whose payload is the metadata document **merged with the
/// JWT claims** — `sub` = the credential issuer identifier,
/// byte-identical to `credential_issuer` (§12.2.3 discipline); `iss` the
/// same (string); `iat`/`exp` the signing time and window — and whose
/// header carries `typ: openidvci-issuer-metadata+jwt` and the signing
/// key (`jwk` — public members only, never `d`). The suite's
/// `VCIDecodeSignedCredentialIssuerMetadata` verifies the JWS against
/// the header key, checks `sub` against the configured issuer
/// identifier, strips the four JWT claims, and runs the standard
/// metadata validation on what remains — so the document rides at the
/// top level of the payload, not in a claim and not as the bare
/// document.
///
/// Signatures cross the `signer::Signer` boundary like every other
/// issuer signature (design §11.1) — HSM-backed signers serve this the
/// same as credentials.
pub fn signed_metadata_jws(
    metadata: &CredentialIssuerMetadata,
    now: i64,
    validity_secs: i64,
    signer: &dyn crate::signer::Signer,
) -> Result<String> {
    let mut payload = serde_json::to_value(metadata)
        .map_err(|e| crate::Error::invalid_input(format!("metadata serialization: {e}")))?;
    let identifier = metadata.credential_issuer.as_str();
    {
        let claims = payload
            .as_object_mut()
            .ok_or_else(|| crate::Error::invalid_input("metadata must be a JSON object"))?;
        claims.insert("sub".into(), serde_json::json!(identifier));
        claims.insert("iss".into(), serde_json::json!(identifier));
        claims.insert("iat".into(), serde_json::json!(now));
        claims.insert("exp".into(), serde_json::json!(now + validity_secs));
    }
    let payload = serde_json::to_vec(&payload)
        .map_err(|e| crate::Error::invalid_input(format!("metadata serialization: {e}")))?;
    let public = signer.public_jwk()?;
    let mut header = jose_rs::JoseHeader::new("ES256");
    header.typ = Some(SIGNED_METADATA_TYP.to_owned());
    // The verification key rides the header (the suite accepts jwk or
    // x5c; the public JWK is the portable shape). `d` cannot be present:
    // public_jwk is the public view.
    header.jwk = Some(
        serde_json::to_value(&public)
            .map_err(|e| crate::Error::invalid_input(format!("public jwk serialization: {e}")))?,
    );
    signer.sign_es256(&header, &payload)
}
