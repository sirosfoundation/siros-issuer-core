//! OpenID4VCI metadata generation from the TS11 catalog, against fixtures
//! shaped like the live registry. Sources of truth: OpenID4VCI 1.0 ID1
//! §11.2.1 (metadata document), TS 119 602 (VCTM/MDDL shapes), and the
//! verifier-core catalog contract.

use serde_json::json;
use siros_issuer_core::catalog::{build_catalog, credential_claims, resolve};
use siros_issuer_core::oid4vci::{
    authorization_server_metadata, metadata_from_catalog, DisclosurePolicy, EndpointPaths,
    MDOC_FORMAT, SD_JWT_FORMAT,
};
use siros_verifier_core::ts11::{parse_schema_page, CredentialType, RegistryDocument, SchemaMeta};
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
    let metadata = metadata_from_catalog(
        &issuer_base(),
        &catalog,
        vec![],
        &EndpointPaths::default(),
        &std::collections::BTreeMap::new(),
        // The default posture (issue #21): required.
        true,
        // The ARF disclosure policies (gap 3): empty — absent everywhere
        // (the conformance shape).
        &std::collections::BTreeMap::new(),
    )
    .unwrap();

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
    // The default posture (issue #21): encryption required — the site
    // below passes true.
    assert!(metadata.credential_response_encryption.encryption_required);

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
    let metadata = metadata_from_catalog(
        &issuer_base(),
        &catalog,
        vec![],
        &EndpointPaths::default(),
        &std::collections::BTreeMap::new(),
        // The default posture (issue #21): required.
        true,
        // The ARF disclosure policies (gap 3): empty — absent everywhere
        // (the conformance shape).
        &std::collections::BTreeMap::new(),
    )
    .unwrap();

    let sdjwt = &metadata.credential_configurations_supported["urn:eudi:pid:1"];
    assert!(sdjwt.proof_types_supported.contains_key("jwt"));
    assert!(!sdjwt.proof_types_supported.contains_key("attestation"));

    let mdoc = &metadata.credential_configurations_supported["eu.europa.ec.eudi.pid.1"];
    // mso_mdoc advertises BOTH proof types (issue #4): the `jwt` proof
    // wallet engines plan from this metadata (the endpoint's proof
    // verification is format-agnostic — a JWK-bound jwt proof delivers
    // the device key the credential binds as a COSE Key) AND the
    // `attestation` proof (Appendix D.1). Attestation-only metadata is
    // the mid-flow refusal engines make (WMP -31005 "Capability not
    // supported", proven live on the realeyes demo).
    assert!(mdoc.proof_types_supported.contains_key("attestation"));
    assert!(mdoc.proof_types_supported.contains_key("jwt"));
    // Each entry carries the algs the endpoint actually accepts —
    // ES256, never the wider set other issuers advertise (a metadata
    // lie is its own bug class, the #3 lesson).
    for proof_type in ["jwt", "attestation"] {
        assert_eq!(
            mdoc.proof_types_supported[proof_type].proof_signing_alg_values_supported,
            vec!["ES256"]
        );
    }
    // mdoc signing algs are COSE integer ids, not JWS names.
    assert_eq!(mdoc.credential_signing_alg_values_supported, json!([-7]));
}

/// Discovery advertises the implemented P2 surface (design §12.1): both
/// grants (PAR + Mode A authorize for authorization_code), PKCE S256,
/// no client-auth method until the deployment adds one (RFC 8414 §2:
/// the member is present, as an empty array, so it never defaults to
/// client_secret_basic), and DPoP (RFC 9449) for sender-constraining. The
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
    assert!(metadata.token_endpoint_auth_methods_supported.is_empty());
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
    assert_eq!(wire["token_endpoint_auth_methods_supported"], json!([]));
    // Mode B (design §7.3) is not advertised until implemented.
    assert!(wire.get("authorization_challenge_endpoint").is_none());
    // No attestation-based client auth without it being enabled.
    assert!(wire
        .get("client_attestation_signing_alg_values_supported")
        .is_none());
}

/// draft-ietf-oauth-attestation-based-client-auth-07 §10.1: advertising
/// attest_jwt_client_auth MUST carry both alg members, as JSON arrays
/// (§13.3) — ES256, the one alg the token endpoint verifies.
#[test]
fn client_attestation_advertises_method_and_alg_arrays() {
    let mut metadata = authorization_server_metadata(&issuer_base()).unwrap();
    metadata.advertise_client_attestation();
    let wire = serde_json::to_value(&metadata).unwrap();
    assert_eq!(
        wire["token_endpoint_auth_methods_supported"],
        json!(["attest_jwt_client_auth"])
    );
    assert_eq!(
        wire["client_attestation_signing_alg_values_supported"],
        json!(["ES256"])
    );
    assert_eq!(
        wire["client_attestation_pop_signing_alg_values_supported"],
        json!(["ES256"])
    );
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
    let metadata = metadata_from_catalog(
        &issuer_base(),
        &catalog,
        vec![],
        &EndpointPaths::default(),
        &std::collections::BTreeMap::new(),
        // The default posture (issue #21): required.
        true,
        // The ARF disclosure policies (gap 3): empty — absent everywhere
        // (the conformance shape).
        &std::collections::BTreeMap::new(),
    )
    .unwrap();
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
    let metadata = metadata_from_catalog(
        &issuer_base(),
        &catalog,
        vec![],
        &paths,
        &std::collections::BTreeMap::new(),
        // The default posture (issue #21): required.
        true,
        // The ARF disclosure policies (gap 3): empty — absent everywhere
        // (the conformance shape).
        &std::collections::BTreeMap::new(),
    )
    .unwrap();
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

/// 1.0 Final §12.2.4 issuer `display`: the configured name rides the
/// document (and the signed metadata, which serializes the same struct);
/// unconfigured, the member is absent. The identifier never changes.
#[test]
fn issuer_display_is_present_only_when_configured() {
    let (_, documents) = fixtures();
    let catalog = build_catalog(documents).unwrap();
    let wire = |issuer_display_name: Option<String>| {
        let metadata = metadata_from_catalog(
            &issuer_base(),
            &catalog,
            vec![],
            &EndpointPaths {
                issuer_display_name,
                ..Default::default()
            },
            &std::collections::BTreeMap::new(),
            true,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
        serde_json::to_value(&metadata).unwrap()
    };
    let named = wire(Some("Example Issuer".to_owned()));
    assert_eq!(named["display"], json!([{ "name": "Example Issuer" }]));
    let unnamed = wire(None);
    assert!(unnamed.get("display").is_none());
    assert_eq!(named["credential_issuer"], unnamed["credential_issuer"]);
}

/// Gap 3: a configured ARF disclosure policy (the vc/ARF shape — CIR
/// 2024/2979 Annex III / ETSI TS 119 472-3 §4.2.5, openid/OpenID4VCI#384:
/// no stable normative layout yet) embeds on THAT credential's
/// configuration — and only that one; the others stay absent (the
/// conformance closed set is exercised only by deployment config).
#[test]
fn a_configured_disclosure_policy_rides_its_own_configuration() {
    let (_, documents) = fixtures();
    let catalog = build_catalog(documents).unwrap();
    let mut policies = std::collections::BTreeMap::new();
    policies.insert(
        "urn:eudi:pid:1".to_owned(),
        DisclosurePolicy {
            policy_type: "authorized_relying_parties".to_owned(),
            authorized_relying_parties: vec!["RP-SE-000001".to_owned()],
            trusted_roots: Vec::new(),
        },
    );
    let metadata = metadata_from_catalog(
        &issuer_base(),
        &catalog,
        vec![],
        &EndpointPaths::default(),
        &std::collections::BTreeMap::new(),
        true,
        &policies,
    )
    .unwrap();
    let pid = metadata
        .credential_configurations_supported
        .get("urn:eudi:pid:1")
        .expect("the pid configuration");
    let policy = pid.disclosure_policy.as_ref().expect("the policy rides");
    assert_eq!(policy.policy_type, "authorized_relying_parties");
    assert_eq!(policy.authorized_relying_parties, vec!["RP-SE-000001"]);
    assert!(policy.trusted_roots.is_empty());
    // Every OTHER configuration stays absent — the conformance closed
    // set is exercised only where configured.
    for (id, configuration) in &metadata.credential_configurations_supported {
        if id == "urn:eudi:pid:1" {
            continue;
        }
        assert!(
            configuration.disclosure_policy.is_none(),
            "{id} carries no policy (unconfigured): {configuration:?}"
        );
    }
    // And the EMPTY map (the default): absent everywhere.
    let metadata = metadata_from_catalog(
        &issuer_base(),
        &catalog,
        vec![],
        &EndpointPaths::default(),
        &std::collections::BTreeMap::new(),
        true,
        &std::collections::BTreeMap::new(),
    )
    .unwrap();
    for (id, configuration) in &metadata.credential_configurations_supported {
        assert!(
            configuration.disclosure_policy.is_none(),
            "{id} absent by default: {configuration:?}"
        );
    }
}

/// The PID of the fixtures with its claim metadata replaced.
fn pid_with_claims(claims: serde_json::Value) -> siros_issuer_core::Result<CredentialType> {
    let (_, mut documents) = fixtures();
    let document = documents
        .iter_mut()
        .find(|document| document.format == SD_JWT_FORMAT)
        .unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&document.body).unwrap();
    body["claims"] = claims;
    document.body = serde_json::to_vec(&body).unwrap();
    let catalog = build_catalog(documents)?;
    Ok(resolve(&catalog, "urn:eudi:pid:1").unwrap().clone())
}

/// TS 119 602 / SD-JWT VC claim paths: a nested claim is a member of its
/// parent, whichever is listed first, and never a top-level claim of its
/// own. Undeclared siblings of a claim the metadata names only by its
/// members stay out; a path into an array issues with the array.
#[test]
fn nested_claims_issue_at_their_own_path() {
    let credential = pid_with_claims(json!([
        {"path": ["address", "post_code"]},
        {"path": ["address"]},
        {"path": ["activity"]},
        {"path": ["activity", "code"]},
        {"path": ["contact", "email"]},
        {"path": ["contact", "website"]},
        {"path": ["representatives", null]},
        {"path": ["representatives"]},
    ]))
    .unwrap();
    let claims = credential_claims(
        &credential,
        &json!({
            "address": {"post_code": "8900", "post_name": "Brønnøysund"},
            "activity": {"code": "49.410"},
            "contact": {"email": "a@example.org", "internal": "x"},
            "representatives": [{"name": "Kari"}],
        }),
    );
    assert_eq!(
        serde_json::Value::Object(claims),
        json!({
            "address": {"post_code": "8900", "post_name": "Brønnøysund"},
            "activity": {"code": "49.410"},
            "contact": {"email": "a@example.org"},
            "representatives": [{"name": "Kari"}],
        })
    );
}

/// Design §8.1: the elements of an array issue with the array's own claim,
/// so a path into an array whose own path is not declared is a catalog
/// fault, never a claim that is silently absent. A declared ancestor of the
/// array is not the array.
#[test]
fn a_path_into_an_undeclared_array_is_refused() {
    for claims in [
        json!([{"path": ["representatives", null]}]),
        json!([{"path": ["org"]}, {"path": ["org", "representatives", null]}]),
        json!([{"path": [null]}]),
    ] {
        let error = pid_with_claims(claims.clone()).expect_err(&claims.to_string());
        assert_eq!(error.code, "catalog_invalid", "{claims}");
    }
    pid_with_claims(json!([
        {"path": ["org", "representatives", null]},
        {"path": ["org", "representatives"]},
    ]))
    .expect("the array's own path is declared");
}
