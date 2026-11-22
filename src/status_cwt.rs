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
