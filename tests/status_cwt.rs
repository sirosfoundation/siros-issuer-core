//! The draft-21 CWT status token (src/status_cwt.rs, the producer):
//! the byte oracle — fixed inputs reproduce the draft's own §5.2
//! example byte for byte, and the signature verifies over the COSE
//! Sig_structure with the signer's public key (the same construction
//! mdoc's COSE rides — one HSM-capable surface for every COSE this
//! issuer produces). Lives in tests/ per the workspace rule: tests
//! exercise the public API, no #[cfg(test)] under src/.

use ciborium::Value as CborValue;
use siros_issuer_core::status_cwt::{status_list_cwt, StatusListCwt};

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
    let signer = siros_issuer_core::signer::JwkSigner::new(jwk).expect("signer");

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
    let signer = siros_issuer_core::signer::JwkSigner::new(jwk.clone()).expect("signer");

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
    let x =
        siros_issuer_core::sdjwt_issue::b64u_decode(jwk.x.as_deref().expect("x")).expect("x bytes");
    let y =
        siros_issuer_core::sdjwt_issue::b64u_decode(jwk.y.as_deref().expect("y")).expect("y bytes");
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
    let signer = siros_issuer_core::signer::JwkSigner::new(jwk).expect("signer");
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
    assert_eq!(siros_issuer_core::sdjwt_issue::b64u(&lst), "eNrbuRgAAhcBXQ");
}
