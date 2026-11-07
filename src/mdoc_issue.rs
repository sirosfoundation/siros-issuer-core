//! mso_mdoc issuance (ISO/IEC 18013-5): IssuerSigned construction, MSO
//! building and COSE_Sign1 signing, ported from vc's `pkg/mdoc` (mso.go,
//! cose.go, issuer.go) with the structure the verifier's `mdoc.rs` accepts.
//!
//! Signing goes through the `Signer` trait (design §11.1): COSE's raw
//! ES256-over-Sig_structure rides the same HSM-capable surface as JWS.
//!
//! Wire contract (established against verifier-core `verify_document`):
//!
//! ```text
//! IssuerSigned = {
//!   nameSpaces: { <ns>: [ #6.24(bstr .cbor IssuerSignedItem), ... ] },
//!   issuerAuth: COSE_Sign1,   // [protected, unprotected, payload, signature]
//! }
//! IssuerSignedItem = {
//!   digestID: uint, random: bstr, elementIdentifier: text, elementValue: any
//! }
//! MSO (the tag-24 payload) = {
//!   version: "1.0", digestAlgorithm, docType,
//!   valueDigests: { <ns>: { digestID: bstr } },
//!   deviceKeyInfo: { deviceKey: COSE_Key },
//!   validityInfo: { signed/validFrom/validUntil: #0(text) },
//! }
//! ```
//!
//! Digests are SHA-256 over each tag-24-wrapped IssuerSignedItem. The
//! x5chain rides the UNPROTECTED header (RFC 9360 / mdoc convention;
//! protected carries only alg — a strict verifier rejects more).

use crate::error::{code, Error, Result};
use crate::signer::Signer;
pub use crate::zk::SaltPolicy;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// COSE algorithm: ES256 (RFC 9053 §2).
pub const ALG_ES256: i64 = -7;
/// COSE header label: x5chain (RFC 9360 §2).
pub const HEADER_X5CHAIN: i64 = 33;
/// COSE key values (RFC 9052 §7): kty=2 (EC2), crv=1 (P-256).
const KTY_EC2: i64 = 2;
const CRV_P256: i64 = 1;

pub type Cbor = ciborium::Value;

fn enc(v: &Cbor) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out)
        .map_err(|e| Error::new(code::TRANSPORT, format!("cbor encode: {e}")))?;
    Ok(out)
}

fn tmap(entries: Vec<(Cbor, Cbor)>) -> Cbor {
    Cbor::Map(entries.into_iter().collect())
}

fn tstr(s: &str) -> Cbor {
    Cbor::Text(s.to_owned())
}

fn bstr(b: &[u8]) -> Cbor {
    Cbor::Bytes(b.to_vec())
}

/// One signed data element (ISO 18013-5 §9.1.2.4).
pub struct IssuerSignedItem {
    pub digest_id: u64,
    pub random: Vec<u8>,
    pub element_id: String,
    /// The element value as CBOR: typed values (full-date, RFC 8943 tag
    /// 1004) are built by the typed `add_*` methods; JSON subject data
    /// converts via `json_to_cbor`.
    pub element_value: Cbor,
}

impl IssuerSignedItem {
    /// CBOR map per the wire contract; key order fixed by assignment.
    fn cbor(&self) -> Cbor {
        tmap(vec![
            (tstr("digestID"), Cbor::Integer(self.digest_id.into())),
            (tstr("random"), bstr(&self.random)),
            (tstr("elementIdentifier"), tstr(&self.element_id)),
            (tstr("elementValue"), self.element_value.clone()),
        ])
    }
}

fn json_to_cbor(v: &Value) -> Cbor {
    match v {
        Value::Null => Cbor::Null,
        Value::Bool(b) => Cbor::Bool(*b),
        Value::Number(n) => Cbor::Integer(
            n.as_i64()
                .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok()))
                .unwrap_or(0)
                .into(),
        ),
        Value::String(s) => Cbor::Text(s.clone()),
        Value::Array(items) => Cbor::Array(items.iter().map(json_to_cbor).collect()),
        Value::Object(map) => tmap(
            map.iter()
                .map(|(k, val)| (Cbor::Text(k.clone()), json_to_cbor(val)))
                .collect(),
        ),
    }
}

/// An issuance in progress: elements accumulate per namespace, then `build`
/// computes digests, assembles and signs the MSO.
pub struct MsoBuilder {
    doc_type: String,
    salt_policy: SaltPolicy,
    namespaces: Vec<(String, Vec<IssuerSignedItem>)>,
    digest_counters: Vec<(String, u64)>,
}

impl MsoBuilder {
    pub fn new(doc_type: &str, salt_policy: SaltPolicy) -> Self {
        Self {
            doc_type: doc_type.to_owned(),
            salt_policy,
            namespaces: Vec::new(),
            digest_counters: Vec::new(),
        }
    }

    /// Add one data element from JSON subject data; the salt is sized by
    /// the policy (design §8.3 item 1: random for plain mdocs,
    /// catalog-pinned length for ZK-provable ones).
    pub fn add_element(
        &mut self,
        namespace: &str,
        element_id: &str,
        element_value: Value,
    ) -> Result<()> {
        self.push_item(namespace, element_id, json_to_cbor(&element_value))
    }

    /// Add a full-date element (ISO 18013-5 element typing: `YYYY-MM-DD`
    /// text under RFC 8943 CBOR tag 1004 — the mdoc full-date
    /// convention; vc's `mdoc.FullDate` marshals the same tag).
    pub fn add_full_date(&mut self, namespace: &str, element_id: &str, date: &str) -> Result<()> {
        self.push_item(namespace, element_id, Cbor::Tag(1004, Box::new(tstr(date))))
    }

    fn push_item(&mut self, namespace: &str, element_id: &str, element_value: Cbor) -> Result<()> {
        let salt_len = self.salt_policy.salt_bytes_for(element_id)?;
        let mut random = vec![0u8; salt_len];
        getrandom::fill(&mut random)
            .map_err(|e| Error::new(code::TRANSPORT, format!("OS randomness: {e}")))?;
        let digest_id = match self
            .digest_counters
            .iter_mut()
            .find(|(ns, _)| ns == namespace)
        {
            Some((_, counter)) => {
                let id = *counter;
                *counter += 1;
                id
            }
            None => {
                self.digest_counters.push((namespace.to_owned(), 1));
                0
            }
        };
        match self.namespaces.iter_mut().find(|(ns, _)| ns == namespace) {
            Some((_, items)) => items.push(IssuerSignedItem {
                digest_id,
                random,
                element_id: element_id.to_owned(),
                element_value,
            }),
            None => self.namespaces.push((
                namespace.to_owned(),
                vec![IssuerSignedItem {
                    digest_id,
                    random,
                    element_id: element_id.to_owned(),
                    element_value,
                }],
            )),
        }
        Ok(())
    }

    /// Build the MSO and the tag-24-wrapped nameSpaces. Returns
    /// `(issuerAuth CoseSign1 array, nameSpaces map, mso bytes)`.
    pub fn build(
        mut self,
        signer: &dyn Signer,
        device_key: &Cbor,
        cert_chain_der: &[Vec<u8>],
        validity: Validity,
    ) -> Result<IssuerSigned> {
        if self.namespaces.iter().all(|(_, items)| items.is_empty()) {
            return Err(Error::invalid_input(
                "an MSO needs at least one data element",
            ));
        }

        // Deterministic namespace order; digest IDs assigned in
        // insertion order above.
        self.namespaces.sort_by(|a, b| a.0.cmp(&b.0));

        let mut name_spaces_entries: Vec<(Cbor, Cbor)> = Vec::new();
        let mut value_digests_entries: Vec<(Cbor, Cbor)> = Vec::new();
        for (namespace, items) in &self.namespaces {
            let mut tagged_item_entries = Vec::new();
            let mut ns_digests_entries: Vec<(Cbor, Cbor)> = Vec::new();
            for item in items {
                // Digest over the tag-24 encoded item (the exact bytes
                // the verifier recomputes from).
                let inner = enc(&item.cbor())?;
                let digest =
                    Sha256::digest(&enc(&Cbor::Tag(24, Box::new(Cbor::Bytes(inner.clone()))))?);
                ns_digests_entries.push((
                    Cbor::Integer(item.digest_id.into()),
                    Cbor::Bytes(digest.to_vec()),
                ));
                tagged_item_entries.push(Cbor::Tag(24, Box::new(Cbor::Bytes(inner))));
            }
            name_spaces_entries.push((tstr(namespace), Cbor::Array(tagged_item_entries)));
            value_digests_entries.push((tstr(namespace), Cbor::Map(ns_digests_entries)));
        }
        let name_spaces = Cbor::Map(name_spaces_entries);
        let value_digests = Cbor::Map(value_digests_entries);

        let mso = tmap(vec![
            (tstr("version"), tstr("1.0")),
            (tstr("digestAlgorithm"), tstr("SHA-256")),
            (tstr("docType"), tstr(&self.doc_type)),
            (tstr("valueDigests"), value_digests),
            (
                tstr("deviceKeyInfo"),
                tmap(vec![(tstr("deviceKey"), device_key.clone())]),
            ),
            (
                tstr("validityInfo"),
                tmap(vec![
                    (tstr("signed"), tdate(&validity.signed)),
                    (tstr("validFrom"), tdate(&validity.valid_from)),
                    (tstr("validUntil"), tdate(&validity.valid_until)),
                ]),
            ),
        ]);

        // COSE_Sign1 payload: tag-24 wrapped MSO.
        let mso_bytes = enc(&mso)?;
        let payload = enc(&Cbor::Tag(24, Box::new(Cbor::Bytes(mso_bytes.clone()))))?;

        // Protected: alg only (strict verifiers reject more). x5chain in
        // the unprotected header (RFC 9360 / mdoc convention).
        let protected = enc(&tmap(vec![(
            Cbor::Integer(1.into()),
            Cbor::Integer(ALG_ES256.into()),
        )]))?;
        let sig_structure = sig_structure_bytes(&protected, &payload);
        let signature = signer.sign_es256_raw(&sig_structure)?;
        let unprotected = tmap(vec![(
            Cbor::Integer(HEADER_X5CHAIN.into()),
            Cbor::Array(
                cert_chain_der
                    .iter()
                    .map(|der| Cbor::Bytes(der.clone()))
                    .collect(),
            ),
        )]);
        let issuer_auth = Cbor::Array(vec![
            Cbor::Bytes(protected),
            unprotected,
            Cbor::Bytes(payload),
            Cbor::Bytes(signature),
        ]);

        Ok(IssuerSigned {
            doc_type: self.doc_type,
            issuer_auth,
            name_spaces,
            mso_bytes,
        })
    }
}

/// RFC 9901 §10.1: mdoc validityInfo timestamps are rounded to a bucket
/// so close issuances cannot be linked by their times — same rationale as
/// the SD-JWT iat/exp rounding.
pub struct Validity {
    pub signed: i64,
    pub valid_from: i64,
    pub valid_until: i64,
}

impl Validity {
    pub fn rounded(now: i64, ttl_secs: i64, bucket_secs: i64) -> Self {
        let valid_from = now - now.rem_euclid(bucket_secs.max(1));
        Self {
            signed: valid_from,
            valid_from,
            valid_until: valid_from + ttl_secs,
        }
    }
}

/// `tdate` (tag 0) text: `YYYY-MM-DDThh:mm:ssZ`, UTC, no fraction (the
/// one form verifier-core's `tdate` parser accepts).
fn tdate(secs: &i64) -> Cbor {
    Cbor::Tag(0, Box::new(Cbor::Text(format_utc(*secs))))
}

pub fn format_utc(secs: i64) -> String {
    // Civil-from-days (RFC 9901 / Howard Hinnant's algorithm); no chrono
    // dependency for a fixed format the parser pins exactly.
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (h, mi, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Sig_structure (RFC 9052 §4.1): ["Signature1", protected, h'', payload].
fn sig_structure_bytes(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let v = Cbor::Array(vec![
        Cbor::Text("Signature1".to_owned()),
        Cbor::Bytes(protected.to_vec()),
        Cbor::Bytes(Vec::new()),
        Cbor::Bytes(payload.to_vec()),
    ]);
    enc(&v).expect("in-memory cbor encode")
}

/// The built IssuerSigned object.
pub struct IssuerSigned {
    pub doc_type: String,
    /// The four-element COSE_Sign1 array (issuerAuth).
    pub issuer_auth: Cbor,
    /// `{ <ns>: [tag24(item), ...] }`.
    pub name_spaces: Cbor,
    /// The tag-24-wrapped MSO bytes (the COSE_Sign1 payload) — for
    /// response encryption and debugging.
    pub mso_bytes: Vec<u8>,
}

impl IssuerSigned {
    /// The full IssuerSigned CBOR object
    /// (`{nameSpaces, issuerAuth}`) — the OID4VCI mso_mdoc credential.
    pub fn cbor(&self) -> Cbor {
        tmap(vec![
            (tstr("nameSpaces"), self.name_spaces.clone()),
            (tstr("issuerAuth"), self.issuer_auth.clone()),
        ])
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        enc(&self.cbor())
    }
}

/// Build a COSE_Key (map form) for a P-256 device key from its JWK.
pub fn cose_key_p256(jwk: &jose_rs::jwk::Jwk) -> Result<Cbor> {
    let kty = jwk.kty.as_str();
    let (Some(x), Some(y)) = (jwk.x.as_deref(), jwk.y.as_deref()) else {
        return Err(Error::invalid_input("device JWK lacks x/y"));
    };
    if kty != "EC" || jwk.crv.as_deref() != Some("P-256") {
        return Err(Error::invalid_input("device key must be EC P-256"));
    }
    let x = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, x)
        .map_err(|_| Error::invalid_input("device JWK x not base64url"))?;
    let y = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, y)
        .map_err(|_| Error::invalid_input("device JWK y not base64url"))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::invalid_input("device JWK x/y must be 32 bytes"));
    }
    // COSE_Key map (RFC 9052 §7): label 1 = kty (2 = EC2),
    // label -1 = crv (1 = P-256), label -2 = x, label -3 = y.
    Ok(tmap(vec![
        (Cbor::Integer(1.into()), Cbor::Integer(KTY_EC2.into())),
        (Cbor::Integer((-1).into()), Cbor::Integer(CRV_P256.into())),
        (Cbor::Integer((-2).into()), Cbor::Bytes(x)),
        (Cbor::Integer((-3).into()), Cbor::Bytes(y)),
    ]))
}
