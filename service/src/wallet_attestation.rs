//! Wallet attestation (WIA/KA) — attestation-based client authentication
//! (design §12.1, §16.2): a faithful port of vc's
//! `pkg/trust/wallet_attestation.go` `WalletAttestationEvaluator`.
//!
//! The split, exactly vc's:
//!
//! 1. **Signature verification is local.** The evaluator verifies the WIA's
//!    own signature against its own key material — x5c (ETSI TS 119 472-3),
//!    an embedded `jwk` header, or `kid` + JWKS discovery at the `iss`
//!    (IETF draft-ietf-oauth-attestation-based-client-auth). The PDP never
//!    verifies signatures.
//! 2. **Trust is external.** The go-trust PDP decides whether the
//!    already-verified key belongs to a trusted wallet provider
//!    (`TrustPdp::permit_wallet_provider`, action `wallet_provider` —
//!    vc's `RoleWalletProvider`).
//! 3. **Tier authorization is the policy layer.** After trust, the
//!    `AttestationPolicy` decides attestation_source → scope (vc's SPOCP
//!    `WalletAttestationPolicyEngine`; `WildcardRulesPolicy` is the native
//!    rule shape, `PdpAttestationPolicy` the AuthZEN path).
//!
//! Two WIA trust models (vc's `Mode`): `etsi` (x5c-based — identity from the
//! leaf cert's SAN/CN, `iss` must be consistent with it) and `ietf`
//! (`iss`/JWKS-based). Pinned by config; unpinned accepts either, as the
//! WIA itself determines.
//!
//! PoP (draft §5.2, `EvaluateWithPoP`): `typ: oauth-client-attestation-pop+jwt`,
//! signature against the WIA's `cnf.jwk`, `aud` containing this AS,
//! `exp`/`iat` windows. The legacy form-body mode carries no PoP.

use serde_json::Value;
use siros_issuer_core::error::code;
use siros_issuer_core::sdjwt_issue::{b64_decode_std, b64u_decode};
use siros_issuer_core::trust::WalletProviderTrustQuery;
use siros_issuer_core::{Error, Result};

use crate::client_auth::{AttestationAttributes, AttestationPolicy};
use crate::pdp::TrustPdp;
use std::sync::Arc;

/// The WIA trust models (vc `WIAModeETSI`/`WIAModeIETF`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WiaMode {
    /// ETSI TS 119 472-3: x5c-based — identity from the leaf certificate.
    Etsi,
    /// IETF draft: `iss`/JWKS-based.
    Ietf,
    /// Unpinned: accept either, as the WIA itself determines (vc's
    /// pre-Mode default).
    #[default]
    Either,
}

impl WiaMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "etsi" => Ok(Self::Etsi),
            "ietf" => Ok(Self::Ietf),
            "" => Ok(Self::Either),
            other => Err(Error::configuration(format!(
                "unknown wallet attestation mode {other:?} (etsi, ietf, or empty)"
            ))),
        }
    }
}

/// The outcome of a successful evaluation (vc `WalletAttestationResult`,
/// trusted subset — the PDP's reason/framework details stay in the PDP).
#[derive(Debug, Clone)]
pub struct WalletAttestationResult {
    /// The wallet provider identifier (`iss` claim or x5c leaf SAN/CN).
    pub issuer: String,
    /// The wallet instance identifier (`sub` claim = JWK thumbprint).
    pub subject: String,
    /// The attestation tier (e.g. "backend_attested") — may be empty.
    pub attestation_source: String,
}

/// The evaluator (vc `WalletAttestationEvaluator`): verify → trust → tier.
pub struct WalletAttestationEvaluator {
    pdp: Arc<dyn TrustPdp>,
    policy: Arc<dyn AttestationPolicy>,
    mode: WiaMode,
    /// This AS's issuer URL — the PoP `aud` (vc `PublicURL`).
    audience: String,
    /// The JWKS HTTP resolver (IETF `iss` mode).
    jwks: JwksResolver,
}

impl WalletAttestationEvaluator {
    /// Builder-style construction, vc's `NewWalletAttestationEvaluator`.
    pub fn new(
        pdp: Arc<dyn TrustPdp>,
        policy: Arc<dyn AttestationPolicy>,
        mode: WiaMode,
        audience: url::Url,
    ) -> Self {
        Self {
            pdp,
            policy,
            mode,
            audience: siros_issuer_core::oid4vci::issuer_identifier(&audience).to_owned(),
            jwks: JwksResolver::new(reqwest::Client::new()),
        }
    }

    /// Verify a WIA, evaluate wallet-provider trust (PDP), and run the tier
    /// policy (vc `Evaluate` + the token handler's `Authorize` call).
    ///
    /// `scope`: the credential scope the authorization is for — the bound
    /// code's scope (what was authorized at PAR/offer time), never a
    /// caller-supplied wildcard (vc re-checks against the bound scope).
    pub async fn evaluate(
        &self,
        attestation: &str,
        scope: &str,
    ) -> Result<WalletAttestationResult> {
        // 1. Identity (vc parseAttestationIdentity): iss / x5c, fail-closed
        //    on malformed x5c and on iss↔x5c disagreement.
        let identity = parse_attestation_identity(attestation)?;

        // 2. Mode enforcement BEFORE any signature verification (vc
        //    Evaluate's switch): a mismatched WIA is rejected cheaply and
        //    never reaches the PDP with the wrong model's key data.
        match self.mode {
            WiaMode::Etsi if !identity.has_x5c => {
                return Err(Error::new(
                    code::INVALID_INPUT,
                    "this deployment requires the etsi (x5c) trust model, but the WIA has no x5c header",
                ));
            }
            WiaMode::Ietf if identity.has_x5c => {
                return Err(Error::new(
                    code::INVALID_INPUT,
                    "this deployment requires the ietf (iss/JWKS) trust model, but the WIA has an x5c header",
                ));
            }
            _ => {}
        }

        // 3. Signature verification, local (vc VerifyJWTSignature): x5c
        //    leaf / jwk header / kid+JWKS at iss. The verified key
        //    material is what the PDP judges.
        let key = self.verify_signature(attestation, &identity).await?;

        // Belt-and-suspenders (vc's check): for iss-only WIAs the generic
        // resolution's issuer must match the identity extraction's.
        if !identity.has_x5c {
            if let (Some(verified_iss), Some(iss)) = (&key.issuer, &identity.iss) {
                if verified_iss != iss {
                    return Err(Error::new(
                        code::INVALID_INPUT,
                        format!(
                            "wallet attestation issuer mismatch: iss claim {iss:?} does not match verified key issuer {verified_iss:?}"
                        ),
                    ));
                }
            }
        }
        let issuer = identity
            .cert_identity
            .clone()
            .or(identity.iss.clone())
            .or_else(|| key.issuer.clone())
            .ok_or_else(|| {
                Error::new(
                    code::INVALID_INPUT,
                    "wallet attestation has neither an iss claim nor x5c identity",
                )
            })?;

        // 4. Wallet-provider trust — the PDP decides (vc
        //    RoleWalletProvider). Fail-closed by the trait.
        let query = if identity.has_x5c {
            WalletProviderTrustQuery::new(issuer.clone(), identity.x5c.clone(), Value::Null)
        } else {
            WalletProviderTrustQuery::new(
                issuer.clone(),
                Vec::new(),
                serde_json::to_value(&key.jwk).map_err(|e| {
                    Error::new(code::INVALID_INPUT, format!("attestation key: {e}"))
                })?,
            )
        };
        self.pdp.permit_wallet_provider(&query).await.map_err(|e| {
            Error::new(
                code::PDP_DENIED,
                format!("wallet provider {issuer:?} not trusted: {e}"),
            )
        })?;

        // sub is required (vc's post-decision check).
        let subject = identity.sub.clone().ok_or_else(|| {
            Error::new(
                code::INVALID_INPUT,
                "wallet attestation missing required 'sub' claim",
            )
        })?;

        let result = WalletAttestationResult {
            issuer,
            subject,
            attestation_source: identity.attestation_source.unwrap_or_default(),
        };

        // 5. Tier authorization (vc's token-handler Authorize call, after
        //    trust): attestation_source → scope, default-open when the
        //    policy has no rules.
        self.policy
            .authorize(&AttestationAttributes {
                attestation_source: result.attestation_source.clone(),
                scope: scope.to_owned(),
                issuer: result.issuer.clone(),
            })
            .await?;
        Ok(result)
    }

    /// Verify the WIA and its PoP (vc `EvaluateWithPoP`): the WIA first
    /// (trust + tier), then the PoP JWT — `typ:
    /// oauth-client-attestation-pop+jwt`, signature against the WIA's
    /// `cnf.jwk`, `aud` containing this AS, `exp`/`iat` windows.
    ///
    /// An empty `pop` is the legacy form-body mode (PoP not required) —
    /// exactly vc's compatibility carve-out.
    pub async fn evaluate_with_pop(
        &self,
        attestation: &str,
        pop: &str,
        scope: &str,
    ) -> Result<WalletAttestationResult> {
        let result = self.evaluate(attestation, scope).await?;
        if pop.is_empty() {
            // Legacy form-body mode (vc): WIA only.
            return Ok(result);
        }
        validate_attestation_pop(attestation, pop, &self.audience)?;
        Ok(result)
    }

    /// Signature verification (vc VerifyJWTSignature, scoped to the WIA's
    /// resolution strategies): x5c leaf / embedded jwk / kid+JWKS(iss).
    async fn verify_signature(
        &self,
        attestation: &str,
        identity: &AttestationIdentity,
    ) -> Result<VerifiedKey> {
        let mut parts = attestation.split('.');
        let (h, p, s) = match (parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s)) if parts.next().is_none() => (h, p, s),
            _ => {
                return Err(Error::new(
                    code::INVALID_INPUT,
                    "wallet attestation is not a compact JWT",
                ))
            }
        };
        let header: Value = serde_json::from_slice(
            &b64u_decode(h).map_err(|_| Error::new(code::INVALID_INPUT, "attestation header"))?,
        )
        .map_err(|e| Error::new(code::INVALID_INPUT, format!("attestation header: {e}")))?;
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !matches!(alg, "ES256") {
            return Err(Error::new(
                code::INVALID_INPUT,
                format!("attestation alg {alg:?} is not ES256"),
            ));
        }

        // x5c: verify against the leaf (ETSI). The chain's trust is the
        // PDP's to judge (this is signature verification only).
        if identity.has_x5c {
            let leaf_b64 = identity.x5c.first().ok_or_else(|| {
                Error::new(
                    code::INVALID_INPUT,
                    "x5c header present but carries no certificates",
                )
            })?;
            let leaf_der = b64_decode_std(leaf_b64)
                .map_err(|_| Error::new(code::INVALID_INPUT, "x5c leaf not base64"))?;
            let leaf = leaf_verifying_key(&leaf_der)?;
            let tbs = format!("{h}.{p}");
            let sig = b64u_decode(s)
                .map_err(|_| Error::new(code::INVALID_INPUT, "attestation signature"))?;
            let signature = p256::ecdsa::Signature::from_slice(&sig)
                .map_err(|_| Error::new(code::INVALID_INPUT, "attestation signature form"))?;
            use p256::ecdsa::signature::Verifier as _;
            leaf.verify(tbs.as_bytes(), &signature).map_err(|_| {
                Error::new(
                    code::INVALID_INPUT,
                    "attestation signature verification failed",
                )
            })?;
            return Ok(VerifiedKey {
                jwk: leaf_to_jwk(&leaf)?,
                issuer: identity.cert_identity.clone(),
            });
        }

        // jwk header: verify against the embedded key.
        if let Some(jwk_value) = header.get("jwk").filter(|v| v.is_object()) {
            let jwk: jose_rs::jwk::Jwk = serde_json::from_value(jwk_value.clone())
                .map_err(|e| Error::new(code::INVALID_INPUT, format!("attestation jwk: {e}")))?;
            if jwk.d.is_some() {
                return Err(Error::new(
                    code::INVALID_INPUT,
                    "attestation jwk carries private material",
                ));
            }
            let _ = jose_rs::jws::compact::verify_with_jwk(&jwk, attestation).map_err(|_| {
                Error::new(
                    code::INVALID_INPUT,
                    "attestation signature verification failed",
                )
            })?;
            return Ok(VerifiedKey {
                jwk,
                issuer: identity.iss.clone(),
            });
        }

        // kid + JWKS at iss (IETF): resolve by kid, verify against the match.
        let kid = header.get("kid").and_then(Value::as_str).ok_or_else(|| {
            Error::new(
                code::INVALID_INPUT,
                "attestation resolves by neither x5c, jwk header, nor kid",
            )
        })?;
        let iss = identity.iss.clone().ok_or_else(|| {
            Error::new(
                code::INVALID_INPUT,
                "kid resolution needs the iss claim (JWKS discovery)",
            )
        })?;
        let jwk = self.jwks.resolve(&iss, kid).await?;
        let _ = jose_rs::jws::compact::verify_with_jwk(&jwk, attestation).map_err(|_| {
            Error::new(
                code::INVALID_INPUT,
                "attestation signature verification failed",
            )
        })?;
        Ok(VerifiedKey {
            jwk,
            issuer: Some(iss),
        })
    }
}

/// The WIA's verified signing key + its issuer resolution.
struct VerifiedKey {
    jwk: jose_rs::jwk::Jwk,
    issuer: Option<String>,
}

/// The parsed identity (vc `attestationIdentity`).
struct AttestationIdentity {
    iss: Option<String>,
    sub: Option<String>,
    attestation_source: Option<String>,
    has_x5c: bool,
    x5c: Vec<String>,
    /// The x5c leaf's SAN/CN identity (ETSI).
    cert_identity: Option<String>,
}

/// JWKS resolution at the issuer (vc `JWKSKeyResolver`, scoped to the WIA
/// path): `{iss}/.well-known/jwks.json` → the `kid` match. Bounded fetch
/// (30s), https-only.
struct JwksResolver {
    http: reqwest::Client,
}

impl JwksResolver {
    fn new(http: reqwest::Client) -> Self {
        Self { http }
    }

    async fn resolve(&self, iss: &str, kid: &str) -> Result<jose_rs::jwk::Jwk> {
        let base = url::Url::parse(iss)
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("attestation iss: {e}")))?;
        // https only — a wallet provider on plain HTTP is refused, the
        // same discipline as every other issuer URL the service touches.
        if base.scheme() != "https" {
            return Err(Error::new(
                code::INVALID_INPUT,
                format!("attestation iss scheme {:?} is not https", base.scheme()),
            ));
        }
        let jwks_url = base
            .join(".well-known/jwks.json")
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("jwks url: {e}")))?;
        let response = self
            .http
            .get(jwks_url.as_str())
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| Error::new(code::TRANSPORT, format!("jwks fetch: {e}")))?;
        if !response.status().is_success() {
            return Err(Error::new(
                code::TRANSPORT,
                format!("jwks fetch answered HTTP {}", response.status()),
            ));
        }
        let jwks: Value = response
            .json()
            .await
            .map_err(|e| Error::new(code::TRANSPORT, format!("jwks parse: {e}")))?;
        for key in jwks["keys"].as_array().cloned().unwrap_or_default() {
            if key.get("kid").and_then(Value::as_str) == Some(kid) {
                let jwk: jose_rs::jwk::Jwk = serde_json::from_value(key)
                    .map_err(|e| Error::new(code::TRANSPORT, format!("jwk: {e}")))?;
                if jwk.d.is_some() {
                    return Err(Error::new(
                        code::TRANSPORT,
                        "the provider's JWKS carries private material",
                    ));
                }
                return Ok(jwk);
            }
        }
        Err(Error::new(
            code::TRANSPORT,
            format!("no key {kid:?} in the provider's JWKS"),
        ))
    }
}

/// Parse the WIA's identity (vc `parseAttestationIdentity`): iss / x5c
/// with the fail-closed discipline on malformed x5c and on iss↔cert
/// disagreement.
fn parse_attestation_identity(attestation: &str) -> Result<AttestationIdentity> {
    let payload = attestation
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "attestation is not a compact JWT"))?;
    let claims: Value = serde_json::from_slice(
        &b64u_decode(payload).map_err(|_| Error::new(code::INVALID_INPUT, "attestation claims"))?,
    )
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("attestation claims: {e}")))?;
    let header: Value = serde_json::from_slice(
        &b64u_decode(attestation.split('.').next().unwrap_or_default())
            .map_err(|_| Error::new(code::INVALID_INPUT, "attestation header"))?,
    )
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("attestation header: {e}")))?;

    let mut identity = AttestationIdentity {
        iss: claims.get("iss").and_then(Value::as_str).map(str::to_owned),
        sub: claims.get("sub").and_then(Value::as_str).map(str::to_owned),
        attestation_source: claims
            .get("attestation_source")
            .and_then(Value::as_str)
            .map(str::to_owned),
        has_x5c: false,
        x5c: Vec::new(),
        cert_identity: None,
    };

    if let Some(x5c_raw) = header.get("x5c") {
        // Fail closed (vc): a malformed x5c array never masquerades as an
        // iss-only WIA (that would slip past the ietf mode's rejection).
        let certs = x5c_raw
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or_else(|| {
                Error::new(
                    code::INVALID_INPUT,
                    "x5c header present but malformed (not a non-empty array)",
                )
            })?;
        identity.has_x5c = true;
        identity.x5c = certs
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if identity.x5c.is_empty() {
            return Err(Error::new(
                code::INVALID_INPUT,
                "x5c header present but contains no certificate strings",
            ));
        }

        // Identity from the leaf (vc issuerFromX5CLeaf: SAN DNS > SAN URI > CN).
        let leaf_der = b64_decode_std(&identity.x5c[0])
            .map_err(|_| Error::new(code::INVALID_INPUT, "x5c leaf not base64"))?;
        let cert_identity = issuer_from_x5c_leaf(&leaf_der)?;
        // iss consistency when present (vc issMatchesCertIdentity: the
        // URL-vs-hostname shape difference is accounted for).
        if let Some(iss) = &identity.iss {
            if !iss_matches_cert_identity(iss, &cert_identity) {
                return Err(Error::new(
                    code::INVALID_INPUT,
                    format!(
                        "iss claim {iss:?} does not match x5c certificate identity {cert_identity:?}"
                    ),
                ));
            }
        }
        identity.cert_identity = Some(cert_identity);
    }

    if identity.iss.is_none() && !identity.has_x5c {
        return Err(Error::new(
            code::INVALID_INPUT,
            "wallet attestation has neither an iss claim nor x5c identity",
        ));
    }

    Ok(identity)
}

/// The x5c leaf's wallet-provider identity (vc `issuerFromX5CLeaf`):
/// SAN DNS name > SAN URI > Subject CN.
fn issuer_from_x5c_leaf(der: &[u8]) -> Result<String> {
    use x509_cert::der::Decode;
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|_| Error::new(code::INVALID_INPUT, "x5c leaf not a certificate"))?;

    // SAN (2.5.29.17): DNS name > URI.
    use x509_cert::der::asn1::ObjectIdentifier;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;
    let san_oid = ObjectIdentifier::new_unwrap("2.5.29.17");
    for extension in cert.tbs_certificate.extensions.iter().flatten() {
        if extension.extn_id != san_oid {
            continue;
        }
        let san = SubjectAltName::from_der(extension.extn_value.as_bytes())
            .map_err(|_| Error::new(code::INVALID_INPUT, "x5c leaf SAN"))?;
        for name in &san.0 {
            if let GeneralName::DnsName(dns) = name {
                return Ok(dns.to_string());
            }
        }
    }
    // Subject CN (2.5.4.3): RdnSequence → each RDN's ATV set.
    let cn_oid = ObjectIdentifier::new_unwrap("2.5.4.3");
    for rdn in &cert.tbs_certificate.subject.0 {
        for atv in rdn.0.iter() {
            if atv.oid != cn_oid {
                continue;
            }
            // The value is an Any (unconstrained): decode as UTF-8
            // when it is one (der 0.7's Utf8StringRef is a Decodable).
            if let Ok(value) = x509_cert::der::asn1::Utf8StringRef::from_der(atv.value.value()) {
                return Ok(value.to_string());
            }
        }
    }
    Err(Error::new(
        code::INVALID_INPUT,
        "x5c leaf has no SAN or CN to derive issuer identity",
    ))
}

/// iss↔cert consistency (vc `issMatchesCertIdentity`): exact, or the
/// iss URL's host matches the cert's DNS SAN.
fn iss_matches_cert_identity(iss: &str, cert_identity: &str) -> bool {
    if iss == cert_identity {
        return true;
    }
    if let Ok(url) = url::Url::parse(iss) {
        if let Some(host) = url.host_str() {
            if host == cert_identity {
                return true;
            }
        }
    }
    false
}

/// PoP validation (draft §5.2, vc `validateAttestationPoP`): typ, signature
/// against the WIA's cnf.jwk, aud, exp/iat.
fn validate_attestation_pop(attestation: &str, pop: &str, expected_audience: &str) -> Result<()> {
    // cnf.jwk from the (already-trusted) WIA.
    let payload = attestation.split('.').nth(1).unwrap_or_default();
    let claims: Value = serde_json::from_slice(
        &b64u_decode(payload).map_err(|_| Error::new(code::INVALID_INPUT, "attestation claims"))?,
    )
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("attestation claims: {e}")))?;
    let cnf_jwk = claims["cnf"]["jwk"].clone();
    let cnf: jose_rs::jwk::Jwk = serde_json::from_value(cnf_jwk)
        .map_err(|_| Error::new(code::INVALID_INPUT, "WIA cnf missing a usable jwk"))?;
    if cnf.d.is_some() {
        return Err(Error::new(
            code::INVALID_INPUT,
            "WIA cnf.jwk carries private material",
        ));
    }

    // The PoP header: typ is the attestation-PoP media type.
    let pop_header: Value = serde_json::from_slice(
        &b64u_decode(pop.split('.').next().unwrap_or_default())
            .map_err(|_| Error::new(code::INVALID_INPUT, "pop header"))?,
    )
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("pop header: {e}")))?;
    if pop_header.get("typ").and_then(Value::as_str) != Some("oauth-client-attestation-pop+jwt") {
        return Err(Error::new(
            code::INVALID_INPUT,
            "pop typ is not oauth-client-attestation-pop+jwt",
        ));
    }

    // Signature against cnf.jwk (ES256 — the one alg this AS accepts).
    let pop_claims: Value = serde_json::from_slice(
        &jose_rs::jws::compact::verify_with_jwk(&cnf, pop)
            .map_err(|_| Error::new(code::INVALID_INPUT, "pop signature verification failed"))?,
    )
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("pop claims: {e}")))?;

    // aud contains this AS (vc contains the issuer URL).
    let auds = pop_claims["aud"].as_array().cloned().unwrap_or_default();
    let aud_strings: Vec<&str> = auds.iter().filter_map(Value::as_str).collect();
    if !aud_strings.contains(&expected_audience) {
        return Err(Error::new(
            code::INVALID_INPUT,
            format!("pop aud {aud_strings:?} does not contain {expected_audience:?}"),
        ));
    }

    // exp required, not past (leeway 30s); iat present.
    let now = crate::status::now_unix();
    let exp = pop_claims["exp"]
        .as_i64()
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "pop missing exp claim"))?;
    if now >= exp + 30 {
        return Err(Error::new(code::INVALID_INPUT, "pop expired"));
    }
    if pop_claims["iat"].is_null() {
        return Err(Error::new(code::INVALID_INPUT, "pop missing iat claim"));
    }
    Ok(())
}

fn leaf_verifying_key(der: &[u8]) -> Result<p256::ecdsa::VerifyingKey> {
    use x509_cert::der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|_| Error::new(code::INVALID_INPUT, "x5c leaf not a certificate"))?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::new(code::INVALID_INPUT, "x5c leaf SPKI"))?;
    let parsed = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&spki)
        .map_err(|_| Error::new(code::INVALID_INPUT, "x5c leaf SPKI"))?;
    let bytes = parsed
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::new(code::INVALID_INPUT, "x5c leaf key not P-256"))?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|_| Error::new(code::INVALID_INPUT, "x5c leaf key not P-256"))
}

fn leaf_to_jwk(key: &p256::ecdsa::VerifyingKey) -> Result<jose_rs::jwk::Jwk> {
    let point = key.to_encoded_point(false);
    let bytes = point.as_bytes();
    let (x, y) = (&bytes[1..33], &bytes[33..]);
    serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": siros_issuer_core::sdjwt_issue::b64u(x),
        "y": siros_issuer_core::sdjwt_issue::b64u(y),
        "alg": "ES256",
        "use": "sig",
    }))
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("leaf jwk: {e}")))
}
