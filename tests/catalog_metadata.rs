//! OpenID4VCI metadata generation from the TS11 catalog, against fixtures
//! shaped like the live registry. Sources of truth: OpenID4VCI 1.0 ID1
//! §11.2.1 (metadata document), TS 119 602 (VCTM/MDDL shapes), and the
//! verifier-core catalog contract.

use serde_json::json;
use siros_issuer_core::catalog::{build_catalog, resolve};
use siros_issuer_core::oid4vci::{
    authorization_server_metadata, metadata_from_catalog, EndpointPaths, MDOC_FORMAT, SD_JWT_FORMAT,
};
use siros_verifier_core::ts11::{parse_schema_page, RegistryDocument, SchemaMeta};
use url::Url;

fn fixtures() -> (Vec<SchemaMeta>, Vec<RegistryDocument>) {
    let page = parse_schema_page(include_bytes!("../testdata/ts11/schema-page.json"))
        .expect("fixture schema page parses");
    let entries: Vec<DocumentFile> =
        serde_json::from_str(include_str!("../testdata/ts11/documents.json"))
            .expect("fixture documents parse");
    let documents = entries
        .into_iter()
        .map(|entry| RegistryDocument {
            schema: page
                .schemas
                .iter()
                .find(|schema| schema.schema_uris.iter().any(|uri| uri.uri == entry.uri))
                .expect("fixture document uri is declared by its schema")
                .clone(),
            format: entry.format,
            uri: entry.uri,
            body: serde_json::to_vec(&entry.body).expect("body serializes"),
        })
        .collect();
    (page.schemas, documents)
}

#[derive(serde::Deserialize)]
struct DocumentFile {
    format: String,
    uri: String,
    body: serde_json::Value,
}

fn issuer_base() -> Url {
    Url::parse("https://issuer.example.org").unwrap()
}

/// The live catalog's two PID formats become two configurations keyed by
/// their catalog identifiers, and the backend's `credential` field resolves
/// to the same identifiers — OpenID4VCI ID1 §11.2.1 configuration ids.
#[test]
fn catalog_drives_metadata_and_configuration_ids() {
    let (_, documents) = fixtures();
    let catalog = build_catalog(documents).unwrap();
    let metadata =
        metadata_from_catalog(&issuer_base(), &catalog, vec![], &EndpointPaths::default()).unwrap();

    let sdjwt = metadata
        .credential_configurations_supported
        .get("urn:eudi:pid:1")
        .expect("dc+sd-jwt configuration keyed by vct");
    assert_eq!(sdjwt.format, SD_JWT_FORMAT);
    // OID4VCI 1.0 Final §12.2.4: the vct is a bare member of the
    // configuration — no draft-era credential_definition wrapper.
    assert_eq!(sdjwt.vct.as_deref(), Some("urn:eudi:pid:1"));
    let claims = sdjwt.claims.as_ref().unwrap().as_array().unwrap();
    assert_eq!(claims.len(), 3);
    assert!(claims
        .iter()
        .any(|claim| claim["path"] == json!(["birth_date"]) && claim["mandatory"] == json!(false)));
    // Final §12.2.4: binding methods co-present with proof types, and
    // each proof type carries its required signing algs.
    assert_eq!(sdjwt.cryptographic_binding_methods_supported, vec!["jwk"]);
    assert_eq!(
        sdjwt.proof_types_supported["jwt"].proof_signing_alg_values_supported,
        vec!["ES256"]
    );

    let mdoc = metadata
        .credential_configurations_supported
        .get("eu.europa.ec.eudi.pid.1")
        .expect("mso_mdoc configuration keyed by doctype");
    assert_eq!(mdoc.format, MDOC_FORMAT);
    assert_eq!(mdoc.doctype.as_deref(), Some("eu.europa.ec.eudi.pid.1"));
    // No claims member for mso_mdoc: the conformance suite's
    // credential_issuer_metadata-1_0.json mso_mdoc branch defines only
    // doctype and credential_signing_alg_values_supported
    // (unevaluatedProperties:false — a claims member warns as an unknown
    // extension), unlike the dc+sd-jwt branch which carries claims. The
    // catalog's claims still drive issuance (schema gate, elements) —
    // verified by the mdoc issuance e2e test.
    assert!(mdoc.claims.is_none());

    // Final §12.2.4: response encryption is an issuer-level member with
    // encryption_required (not per-configuration, the draft-era shape).
    assert_eq!(
        metadata.credential_response_encryption.alg_values_supported,
        vec!["ECDH-ES"]
    );
    assert!(!metadata.credential_response_encryption.encryption_required);

    // Endpoints hang off the issuer base (ID1 §11.2.1 credential_endpoint).
    assert_eq!(
        metadata.credential_endpoint.as_str(),
        "https://issuer.example.org/credential"
    );
    // Deferred issuance is not advertised (design §7: advertise only
    // implemented behavior); P2+ restores it with the endpoint.
    assert!(metadata.deferred_credential_endpoint.is_none());
}

/// Proof types follow the format: jwt proofs for dc+sd-jwt, mdoc attestation
/// proofs for mso_mdoc (ID1 attestation proof type). Offering a jwt proof for
/// mso_mdoc would let a wallet skip device-key binding.
#[test]
fn proof_types_follow_the_format() {
    let (_, documents) = fixtures();
    let catalog = build_catalog(documents).unwrap();
    let metadata =
        metadata_from_catalog(&issuer_base(), &catalog, vec![], &EndpointPaths::default()).unwrap();

    let sdjwt = &metadata.credential_configurations_supported["urn:eudi:pid:1"];
    assert!(sdjwt.proof_types_supported.contains_key("jwt"));
    assert!(!sdjwt.proof_types_supported.contains_key("attestation"));

    let mdoc = &metadata.credential_configurations_supported["eu.europa.ec.eudi.pid.1"];
    assert!(mdoc.proof_types_supported.contains_key("attestation"));
    assert!(!mdoc.proof_types_supported.contains_key("jwt"));
    // mdoc signing algs are COSE integer ids, not JWS names.
    assert_eq!(mdoc.credential_signing_alg_values_supported, json!([-7]));
}

/// Discovery advertises the implemented P2 surface (design §12.1): both
/// grants (PAR + Mode A authorize for authorization_code), PKCE S256,
/// public-client auth, and DPoP (RFC 9449) for sender-constraining. The
/// authorization-challenge endpoint (Mode B) is absent until it lands.
#[test]
fn authorization_server_metadata_advertises_the_p2_surface() {
    let metadata = authorization_server_metadata(&issuer_base()).unwrap();
    assert_eq!(
        metadata.grant_types_supported,
        vec![
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        ]
    );
    assert_eq!(metadata.code_challenge_methods_supported, vec!["S256"]);
    assert_eq!(metadata.token_endpoint_auth_methods_supported, vec!["none"]);
    assert_eq!(metadata.dpop_signing_alg_values_supported, vec!["ES256"]);
    assert_eq!(
        metadata.authorization_endpoint.as_str(),
        "https://issuer.example.org/authorize"
    );
    assert_eq!(
        metadata.pushed_authorization_request_endpoint.as_str(),
        "https://issuer.example.org/op/par"
    );
    let wire = serde_json::to_value(&metadata).unwrap();
    // Mode B (design §7.3) is not advertised until implemented.
    assert!(wire.get("authorization_challenge_endpoint").is_none());
}

/// A document whose URI is not declared by its schema is refused with the
/// stable catalog code — the catalog never invents trust for a stray body.
#[test]
fn undeclared_document_uri_is_refused() {
    let (schemas, documents) = fixtures();
    let mut stray = documents;
    stray[0].uri = "http://127.0.0.1:9/schemas/undeclared.json".to_owned();
    let _ = schemas;
    let error = build_catalog(stray).unwrap_err();
    assert_eq!(error.code, "catalog_invalid");
}

/// Resolution by identifier is unambiguous: each of vct, doctype and schema
/// id resolves to its credential, and an unknown identifier is refused with
/// the stable unsupported_credential code (design §6.2 validation).
#[test]
fn resolution_is_unambiguous_or_refused() {
    let (_, documents) = fixtures();
    let catalog = build_catalog(documents).unwrap();

    assert_eq!(
        resolve(&catalog, "urn:eudi:pid:1").unwrap().format,
        SD_JWT_FORMAT
    );
    assert_eq!(
        resolve(&catalog, "eu.europa.ec.eudi.pid.1").unwrap().format,
        MDOC_FORMAT
    );

    let error = resolve(&catalog, "urn:example:nope:1").unwrap_err();
    assert_eq!(error.code, "unsupported_credential");
}

/// The backend session API's `credential` field and the wallet-facing
/// configuration id are the same identifier — verified by resolving the
/// configuration ids the metadata advertises.
#[test]
fn session_api_identifiers_match_configuration_ids() {
    let (_, documents) = fixtures();
    let catalog = build_catalog(documents).unwrap();
    let metadata =
        metadata_from_catalog(&issuer_base(), &catalog, vec![], &EndpointPaths::default()).unwrap();
    for configuration_id in metadata.credential_configurations_supported.keys() {
        let credential = resolve(&catalog, configuration_id)
            .expect("every advertised configuration id resolves");
        assert_eq!(&credential.identifier, configuration_id);
    }
}

/// 1.0 Final §12.2.4 credential_request_encryption members: the suite's
/// schema closes the object to jwks/enc_values_supported/encryption_required
/// (+ zip) — alg_values_supported is NOT a member (response side only).
#[test]
fn credential_request_encryption_carries_only_final_schema_members() {
    let (_, documents) = fixtures();
    let catalog = siros_issuer_core::catalog::build_catalog(documents).unwrap();
    let paths = EndpointPaths {
        request_encryption_jwk: Some(json!({
            "kty": "EC", "crv": "P-256", "x": "aa", "y": "bb",
            "alg": "ECDH-ES", "use": "enc", "kid": "k", "d": "secret",
        })),
        ..Default::default()
    };
    let metadata = metadata_from_catalog(&issuer_base(), &catalog, vec![], &paths).unwrap();
    let cre = metadata.credential_request_encryption.expect("declared");
    let wire = serde_json::to_value(&cre).unwrap();
    let object = wire.as_object().expect("an object");
    // The closed member SET (order-insensitive: JSON object member
    // order is not semantic — and the `mongo` feature build pulls
    // bson's serde_json/preserve_order unification).
    let mut keys = object.keys().collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["enc_values_supported", "encryption_required", "jwks"]
    );
    // RFC 7517: the private member never leaves the server.
    assert!(object["jwks"]["keys"][0].get("d").is_none());
}
