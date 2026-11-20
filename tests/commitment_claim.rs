//! The derived commitment's credential-claim form (issue #43):
//! `catalog::commitment_claim_form` — the catalog's declared
//! `value_type` is the wire contract the wallets bind. `bstr` carries
//! the raw bytes (the nym_auth ssc the presenter reads as one 32-byte
//! byte string for `SHA256(seed) == ssc`); `tstr` the configured-
//! encoding text; anything else, including an undeclared type, is a
//! refusal — never a guessed encoding. The leniency this replaces
//! delivered a 43-char base64url TEXT ssc past the encoding-aware
//! issuance gate and refused at presentation, after consent.

use siros_issuer_core::catalog::{commitment_claim_form, CommitmentClaimForm};
use siros_verifier_core::ts11::CredentialType;

fn credential_with_value_type(value_type: Option<&str>) -> CredentialType {
    let mut claims = serde_json::json!({
        "eu.europa.ec.eudi.nym_auth.1": {
            "ssc": {"mandatory": false}
        }
    });
    if let Some(t) = value_type {
        claims["eu.europa.ec.eudi.nym_auth.1"]["ssc"]["value_type"] = serde_json::json!(t);
    }
    CredentialType {
        schema_id: "schema".to_owned(),
        version: "1".to_owned(),
        format: "mso_mdoc".to_owned(),
        identifier: "eu.europa.ec.eudi.nym_auth.1".to_owned(),
        label: "label".to_owned(),
        claims: Vec::new(),
        dcql: serde_json::json!(null),
        supported: true,
        raw: serde_json::json!({"doctype": "eu.europa.ec.eudi.nym_auth.1", "claims": claims}),
    }
}

const BYTES: [u8; 32] = [0x42; 32];

/// A `bstr`-typed claim carries the RAW commitment bytes — the form the
/// presenter binds (`SHA256(seed) == ssc` over a 32-byte byte string).
#[test]
fn a_bstr_claim_carries_the_raw_bytes() {
    let credential = credential_with_value_type(Some("bstr"));
    let value_type = siros_issuer_core::catalog::claim_value_type(
        &credential,
        "eu.europa.ec.eudi.nym_auth.1",
        "ssc",
    );
    assert_eq!(value_type, Some("bstr"));
    let form = commitment_claim_form(value_type, BYTES.to_vec(), "text".to_owned())
        .expect("bstr is a commitment carrier");
    match form {
        CommitmentClaimForm::Bytes(bytes) => assert_eq!(bytes, BYTES.to_vec()),
        CommitmentClaimForm::Text(_) => panic!("a bstr claim carries bytes, not text"),
    }
}

/// A `tstr`-typed claim carries the configured-encoding text (a
/// rulebook whose commitment claim is text-typed by its catalog).
#[test]
fn a_tstr_claim_carries_the_encoded_text() {
    let form = commitment_claim_form(
        Some("tstr"),
        BYTES.to_vec(),
        "+fkG82HJwQnMyYSvrUebVafkbMQIu1QPq0ld-fbJONkwj".to_owned(),
    )
    .expect("tstr is a commitment carrier");
    match form {
        CommitmentClaimForm::Text(text) => {
            assert_eq!(text, "+fkG82HJwQnMyYSvrUebVafkbMQIu1QPq0ld-fbJONkwj")
        }
        CommitmentClaimForm::Bytes(_) => panic!("a tstr claim carries text, not bytes"),
    }
}

/// An UNDECLARED value_type is a refusal — the issuance-side gate that
/// issue #43's live failure demanded. The refusal fires before any
/// credential exists, with a stable catalog-invalid code, never a
/// guessed encoding that detonates at presentation after consent.
#[test]
fn an_undeclared_value_type_refuses_at_issuance() {
    let err = commitment_claim_form(None, BYTES.to_vec(), "text".to_owned())
        .expect_err("an undeclared type is never guessed");
    assert_eq!(err.code, "catalog_invalid", "the refusal names its class");
}

/// A declared non-carrier type is a refusal with the same class (a
/// catalog that types a commitment claim as full-date has declared
/// nonsense; the issuer says so rather than encoding anything).
#[test]
fn a_non_carrier_type_refuses() {
    let err = commitment_claim_form(Some("full-date"), BYTES.to_vec(), "text".to_owned())
        .expect_err("full-date is not a commitment carrier");
    assert_eq!(err.code, "catalog_invalid", "the refusal names its class");
}
