//! The CWT form of the Status List Token (draft-ietf-oauth-status-list
//! **-21** §5.2) — the mdoc status form the ARF specifies.
//!
//! The two forms of one list share EVERYTHING but the container: the
//! same zlib-compressed byte array (the JWT form base64url-encodes it
//! into `status_list.lst`, this form carries it as raw CBOR bytes), the
//! same signing key — a deployment serves both from one allocation and
//! a consumer picks by Accept. `StatusRef` (the `uri`/`idx` a
//! credential embeds) is format-agnostic: nothing in the issuance path
//! changes (gap-analysis gap 2).
//!
//! Wire shape (§5.2 — the -21 shape, verified BYTE-IDENTICAL against
//! the draft's own §5.2 example; vc's `pkg/tokenstatuslist/cwt.go` is
//! the older -06-era shape — claim numbers 65534/65535 swapped and
//! integer status_list keys — and is NOT the target):
//!
//! ```text
//! CWT          = #6.18(COSE_Sign1)                     (tagged, §5.2)
//! COSE_Sign1   = [ protected, {}, payload, signature ]
//! protected    = { 1: -7 (ES256), 16: "application/statuslist+cwt" }
//! payload      = { 2: sub (REQUIRED — the list URI, == the
//!                     Referenced Token's status uri),
//!                  6: iat, 4?: exp,
//!                  65534?: ttl,                       (§5.2: 65534 = ttl)
//!                  65533: { "bits": 1|2|4|8,          (TEXT keys, §4.3)
//!                           "lst": raw zlib bytes,
//!                           "aggregation_uri"?: tstr } }
//! signature    = ES256 over Sig_structure ["Signature1", protected, h'', payload]
//! ```
//!
//! ES256 only — the one alg this issuer's COSE surface speaks (the
//! HSM-capable Signer trait promises exactly it).

use crate::error::Result;
use crate::mdoc_issue::{enc, tmap, Cbor};
use crate::signer::Signer;

/// The media type (§5.2): the Accept value that selects this form at a
/// list URI — `application/statuslist+jwt` remains the default — and
/// the protected header's typ (label 16) value.
pub const MEDIA_TYPE_CWT: &str = "application/statuslist+cwt";

/// COSE protected header labels (RFC 9052): algorithm (1), content
/// type (16). kid rides the UNPROTECTED header per §5.2's example
/// (either is legal COSE; the draft's example is the shape consumers
/// have seen the most).
const HEADER_ALG: i64 = 1;
const HEADER_TYP: i64 = 16;

/// CWT claim labels (RFC 8392 + §5.2): subject (2) — REQUIRED, the
/// list URI; expiration time (4); issued at (6); ttl (65534);
/// status_list (65533). The issuer (1) is OPTIONAL ("MAY contain other
/// claims") — carried when the deployment wants the JWT form's `iss`
/// present in both containers.
const CLAIM_SUB: i64 = 2;
const CLAIM_EXP: i64 = 4;
const CLAIM_IAT: i64 = 6;
const CLAIM_ISS: i64 = 1;
const CLAIM_TTL: i64 = 65534;
const CLAIM_STATUS_LIST: i64 = 65533;

/// Build the Status List Token in CWT form (§5.2).
///
/// * `subject` — REQUIRED (§5.2): the URI of THIS Status List Token —
///   the same value the Referenced Tokens' `status.uri` carries, i.e.
///   the `list_url` of the `StatusRef` that seeded every entry.
/// * `lst_compressed` — the §4.1 compressed byte array: DEFLATE in the
///   **ZLIB** format (RFC 1950) — the exact same bytes the JWT form
///   base64url-encodes. The producer never compresses itself: one
///   allocation, two containers.
/// * `bits` — 1, 2, 4 or 8 (§4.1); the packing is LSB-first and the
///   CALLER owns it (the list is already packed before compression).
///
/// The emission order of the claims map matches §5.2's own example
/// (sub, iat, exp, ttl, status_list) so a fixed input reproduces the
/// example's payload bytes exactly — the oracle `cwt_matches_the_drafts_own_example`
/// asserts.
/// The token's variable parts (§5.2): everything a list serves is
/// either the deployment's identity or the draft's optionals.
#[derive(Debug, Clone, Default)]
pub struct StatusListCwt<'a> {
    /// REQUIRED (§5.2): the URI of THIS Status List Token — the value
    /// the Referenced Tokens' `status.uri` carries (the `StatusRef`'s
    /// `list_url`).
    pub subject: &'a str,
    /// OPTIONAL issuer (§5.2 "MAY contain other claims"): carried when
    /// the deployment wants the JWT form's `iss` in both containers.
    pub issuer: Option<&'a str>,
    pub iat: i64,
    pub exp: Option<i64>,
    pub ttl: Option<i64>,
    /// The §4.1 compressed byte array: DEFLATE in the **ZLIB** format
    /// (RFC 1950) — the exact same bytes the JWT form base64url-encodes.
    /// The producer never compresses: one allocation, two containers.
    pub lst_compressed: &'a [u8],
    /// 1, 2, 4 or 8 (§4.1); the packing is LSB-first and the CALLER
    /// owns it (the list is packed before compression).
    pub bits: u64,
    pub aggregation_uri: Option<&'a str>,
    /// RFC 9052 label 4 — rides the UNPROTECTED header (§5.2's example).
    pub kid: Option<&'a str>,
}

/// Build the Status List Token in CWT form (§5.2).
///
/// The claims' emission order matches §5.2's own example (sub, iss,
/// iat, exp, ttl, status_list) so a fixed input reproduces the
/// example's payload bytes exactly — the oracle
/// `cwt_matches_the_drafts_own_example` asserts.
#[allow(clippy::result_large_err)]
pub fn status_list_cwt(signer: &dyn Signer, spec: &StatusListCwt<'_>) -> Result<Vec<u8>> {
    let StatusListCwt {
        subject,
        issuer,
        iat,
        exp,
        ttl,
        lst_compressed,
        bits,
        aggregation_uri,
        kid,
    } = *spec;
    // The claims, in §5.2's example order.
    let mut claims: Vec<(Cbor, Cbor)> = vec![(
        Cbor::Integer(CLAIM_SUB.into()),
        Cbor::Text(subject.to_owned()),
    )];
    if let Some(iss) = issuer {
        claims.push((Cbor::Integer(CLAIM_ISS.into()), Cbor::Text(iss.to_owned())));
    }
    claims.push((Cbor::Integer(CLAIM_IAT.into()), Cbor::Integer(iat.into())));
    if let Some(exp) = exp {
        claims.push((Cbor::Integer(CLAIM_EXP.into()), Cbor::Integer(exp.into())));
    }
    if let Some(ttl) = ttl {
        claims.push((Cbor::Integer(CLAIM_TTL.into()), Cbor::Integer(ttl.into())));
    }
    // status_list (§4.3): a CBOR map with TEXT keys — bits (uint),
    // lst (the RAW compressed bytes), aggregation_uri (tstr, optional).
    let mut status_list: Vec<(Cbor, Cbor)> = vec![
        (
            Cbor::Text("bits".to_owned()),
            Cbor::Integer((bits as i64).into()),
        ),
        (
            Cbor::Text("lst".to_owned()),
            Cbor::Bytes(lst_compressed.to_vec()),
        ),
    ];
    if let Some(uri) = aggregation_uri {
        status_list.push((
            Cbor::Text("aggregation_uri".to_owned()),
            Cbor::Text(uri.to_owned()),
        ));
    }
    claims.push((Cbor::Integer(CLAIM_STATUS_LIST.into()), tmap(status_list)));
    let payload = enc(&tmap(claims))?;

    // Protected: { alg: ES256, typ: application/statuslist+cwt } —
    // §5.2's example shape (kid, when given, rides UNPROTECTED).
    let protected_bytes = enc(&tmap(vec![
        (
            Cbor::Integer(HEADER_ALG.into()),
            Cbor::Integer((-7i64).into()),
        ),
        (
            Cbor::Integer(HEADER_TYP.into()),
            Cbor::Text(MEDIA_TYPE_CWT.to_owned()),
        ),
    ]))?;
    let unprotected: Vec<(Cbor, Cbor)> = match kid {
        // RFC 9052 label 4 (kid); §5.2's example carries it here.
        Some(kid) => vec![(Cbor::Integer(4i64.into()), Cbor::Text(kid.to_owned()))],
        None => Vec::new(),
    };

    // Sig_structure (RFC 9052 §4.1): ["Signature1", protected, h'', payload].
    let sig_structure = enc(&Cbor::Array(vec![
        Cbor::Text("Signature1".to_owned()),
        Cbor::Bytes(protected_bytes.clone()),
        Cbor::Bytes(Vec::new()),
        Cbor::Bytes(payload.clone()),
    ]))?;
    let signature = signer.sign_es256_raw(&sig_structure)?;

    // COSE_Sign1, TAGGED (§5.2: "MUST be the tagged COSE_Sign1_Tagged
    // (18) or COSE_Mac0_Tagged (17)") — #6.18([...]).
    enc(&Cbor::Tag(
        18,
        Box::new(Cbor::Array(vec![
            Cbor::Bytes(protected_bytes),
            tmap(unprotected),
            Cbor::Bytes(payload),
            Cbor::Bytes(signature),
        ])),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value as CborValue;

    fn decode(bytes: &[u8]) -> CborValue {
        ciborium::from_reader(bytes).expect("valid cbor")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Map lookup by integer label (CBOR maps iterate (&Value, &Value)).
    fn get_key(entries: &[(CborValue, CborValue)], key: i128) -> CborValue {
        let needle = CborValue::Integer((key as i64).into());
        entries
            .iter()
            .find(|(k, _)| *k == needle)
            .map(|(_, v)| v.clone())
            .expect("key present")
    }

    /// The COSE_Sign1 under the tag: (protected, payload, signature).
    fn cose_parts(cwt: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let decoded = decode(cwt);
        let CborValue::Tag(18, inner) = decoded else {
            panic!("the tag-18 wrap (§5.2)")
        };
        let CborValue::Array(parts) = *inner else {
            panic!("cose array")
        };
        assert_eq!(parts.len(), 4, "the COSE_Sign1 four elements");
        let CborValue::Bytes(protected) = &parts[0] else {
            panic!("protected bstr")
        };
        let CborValue::Bytes(payload) = &parts[2] else {
            panic!("payload bstr")
        };
        let CborValue::Bytes(signature) = &parts[3] else {
            panic!("signature bstr")
        };
        (protected.clone(), payload.clone(), signature.clone())
    }

    /// THE ORACLE: fixed inputs reproduce §5.2's own example — the
    /// protected header and the claims payload BYTE-IDENTICAL to the
    /// draft's hex (the signature differs: a different key). The
    /// example's inputs: sub = https://example.com/statuslists/1,
    /// iat = 0x648c5bea, exp = 0x8898dfea, ttl = 43200, bits = 1,
    /// lst = the Appendix C 1-bit vector's zlib bytes
    /// 78dadbb918000217015d (statuses 1,0,0,1,1,1,0,1,1,1,0,0,0,1,0,1).
    #[test]
    fn cwt_matches_the_drafts_own_example() {
        let jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
        let signer = crate::signer::JwkSigner::new(jwk).expect("signer");

        let lst = [0x78, 0xda, 0xdb, 0xb9, 0x18, 0x00, 0x02, 0x17, 0x01, 0x5d];
        let cwt = status_list_cwt(
            &signer,
            &StatusListCwt {
                subject: "https://example.com/statuslists/1",
                bits: 1,
                lst_compressed: &lst,
                iat: 0x648c_5bea_i64,
                exp: Some(0x8898_dfea_i64),
                ttl: Some(43200),
                ..StatusListCwt::default()
            },
        )
        .expect("the cwt builds");

        let (protected, payload, _signature) = cose_parts(&cwt);
        // §5.2's protected: a2 01 26 10 78 1a "application/statuslist+cwt"
        assert_eq!(
            hex(&protected),
            "a2012610781a6170706c69636174696f6e2f7374617475736c6973742b637774",
            "protected == the draft's example bytes"
        );
        // §5.2's payload (a5 = map(5): sub, iat, exp, ttl, status_list).
        assert_eq!(
            hex(&payload),
            "a502782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c69737473\
             2f31061a648c5bea041a8898dfea19fffe19a8c019fffda2646269747301636c7374\
             4a78dadbb918000217015d",
            "payload == the draft's example bytes (the same claim order)"
        );
    }

    /// The signature verifies: ES256 over the Sig_structure with the
    /// signer's public key — the same construction mdoc's COSE rides
    /// (one HSM-capable surface for every COSE this issuer produces).
    #[test]
    fn cwt_signature_verifies_over_the_sig_structure() {
        let jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
        let signer = crate::signer::JwkSigner::new(jwk.clone()).expect("signer");

        let lst = [0x78, 0xda, 0xdb, 0xb9, 0x18, 0x00, 0x02, 0x17, 0x01, 0x5d];
        let cwt = status_list_cwt(
            &signer,
            &StatusListCwt {
                subject: "https://example.com/statuslists/1",
                bits: 2,
                lst_compressed: &lst,
                iat: 1_000,
                exp: Some(2_000),
                ttl: None,
                ..StatusListCwt::default()
            },
        )
        .expect("the cwt builds");

        let (protected, payload, signature) = cose_parts(&cwt);
        let sig_structure = {
            let mut buf = Vec::new();
            ciborium::into_writer(
                &CborValue::Array(vec![
                    CborValue::Text("Signature1".into()),
                    CborValue::Bytes(protected.clone()),
                    CborValue::Bytes(Vec::new()),
                    CborValue::Bytes(payload.clone()),
                ]),
                &mut buf,
            )
            .expect("sig structure encode");
            buf
        };
        let x = crate::sdjwt_issue::b64u_decode(jwk.x.as_deref().expect("x")).expect("x bytes");
        let y = crate::sdjwt_issue::b64u_decode(jwk.y.as_deref().expect("y")).expect("y bytes");
        let mut uncompressed = vec![0x04u8];
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        let verifying = VerifyingKey::from_encoded_point(
            &p256::EncodedPoint::from_bytes(uncompressed.as_slice()).expect("point"),
        )
        .expect("verifying key");
        let sig = Signature::from_slice(&signature).expect("the raw r||s signature");
        verifying
            .verify(&sig_structure, &sig)
            .expect("ES256 verifies");
    }

    /// The forms share the compressed bytes: whatever the JWT form
    /// base64url-encodes, the CWT form carries verbatim — one
    /// allocation, two containers.
    #[test]
    fn cwt_lst_is_the_same_compressed_bytes_the_jwt_form_encodes() {
        let jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
        let signer = crate::signer::JwkSigner::new(jwk).expect("signer");
        let lst = [0x78, 0xda, 0xdb, 0xb9, 0x18, 0x00, 0x02, 0x17, 0x01, 0x5d];
        let cwt = status_list_cwt(
            &signer,
            &StatusListCwt {
                subject: "https://i.example.org/lists/1",
                bits: 1,
                lst_compressed: &lst,
                iat: 0,
                exp: None,
                ttl: None,
                ..StatusListCwt::default()
            },
        )
        .expect("cwt");
        let (_, payload, _) = cose_parts(&cwt);
        let claims = decode(&payload);
        let CborValue::Map(entries) = claims else {
            panic!("claims")
        };
        // §5.2: status_list is 65533 — TEXT keys inside (§4.3).
        let status_list = get_key(&entries, 65533);
        let CborValue::Map(sl) = status_list else {
            panic!("status_list map")
        };
        let lst_back = sl
            .iter()
            .find(|(k, _)| *k == CborValue::Text("lst".into()))
            .map(|(_, v)| v.clone())
            .expect("lst");
        // Exactly the input, verbatim — the b64u() the JWT form applies
        // never happens here.
        assert_eq!(lst_back, CborValue::Bytes(lst.to_vec()));
    }

    /// The JWT form's lst for the SAME list is the b64u of the CWT
    /// form's lst — the Appendix C 1-bit vector, cross-checked against
    /// §4.2's own example value.
    #[test]
    fn the_vectors_lst_matches_the_drafts_json_example() {
        let lst = [0x78, 0xda, 0xdb, 0xb9, 0x18, 0x00, 0x02, 0x17, 0x01, 0x5d];
        // §4.2: { "bits": 1, "lst": "eNrbuRgAAhcBXQ" } — the same bytes.
        assert_eq!(crate::sdjwt_issue::b64u(&lst), "eNrbuRgAAhcBXQ");
    }
}
