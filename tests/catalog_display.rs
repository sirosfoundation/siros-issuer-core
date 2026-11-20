//! The response-level display members (issue #41): `catalog::display_members` —
//! the mapping from a TS11 catalog document's display content to the
//! response credential_metadata members (OpenID4VCI 1.0 ID1 §12.2.4 and its
//! Appendix B.2 claim descriptions; vc's Generate mapping as the
//! ported-semantics reference, design doc Appendix A).

use serde_json::json;
use siros_issuer_core::catalog::display_members;
use siros_verifier_core::ts11::CredentialType;

fn credential(format: &str, raw: serde_json::Value) -> CredentialType {
    CredentialType {
        schema_id: "schema".to_owned(),
        version: "1".to_owned(),
        format: format.to_owned(),
        identifier: "id".to_owned(),
        label: "label".to_owned(),
        claims: Vec::new(),
        dcql: json!(null),
        supported: true,
        raw,
    }
}

/// The mdoc mapping (issue #41, vc's Generate): namespaced claims
/// leave as sorted B.2 descriptions, the label rule works both
/// ways, and the SVG template doubles as the logo.
#[test]
fn mdoc_display_members_mirror_the_generate_mapping() {
    let raw = json!({
        "doctype": "eu.europa.ec.eudi.nym_auth.1",
        "display": [{
            "name": "Nym authentication",
            "locale": "en-US",
            "description": "Anonymous/pseudonymous authentication attestation",
            "background_color": "#006400",
            "text_color": "#ffffff",
            "rendering": {
                "svg_templates": [{
                    "uri": "data:image/svg+xml;base64,PHN2Zy8+",
                    "properties": {"orientation": "landscape"}
                }]
            }
        }],
        "claims": {
            "eu.europa.ec.eudi.nym_auth.1": {
                "ssc": {"mandatory": false, "value_type": "bstr"},
                "birth_date": {
                    "mandatory": true,
                    "value_type": "full-date",
                    "svg_id": "birth",
                    "display": [{"name": "Date of birth", "locale": "en-US"}]
                }
            }
        }
    });
    let (display, claims) = display_members(&credential("mso_mdoc", raw));

    assert_eq!(display.len(), 1);
    let d = &display[0];
    assert_eq!(d.name, "Nym authentication");
    assert_eq!(d.locale.as_deref(), Some("en-US"));
    assert_eq!(d.background_color.as_deref(), Some("#006400"));
    assert_eq!(d.text_color.as_deref(), Some("#ffffff"));
    let rendering = d.rendering.as_ref().expect("the svg rendering");
    assert_eq!(rendering.svg_templates.len(), 1);
    assert_eq!(
        rendering.svg_templates[0].uri,
        "data:image/svg+xml;base64,PHN2Zy8+"
    );
    assert_eq!(
        rendering.svg_templates[0]
            .properties
            .as_ref()
            .and_then(|p| p.orientation.as_deref()),
        Some("landscape")
    );
    // vc's mapSvgTemplates: the first template doubles as the logo.
    assert_eq!(
        d.logo.as_ref().map(|l| l.uri.as_str()),
        Some("data:image/svg+xml;base64,PHN2Zy8+")
    );

    // Sorted [namespace, element] paths; the label rule fills both
    // members from one spelling; svg_id and mandatory travel.
    assert_eq!(
        claims
            .iter()
            .map(|c| serde_json::to_value(&c.path).unwrap())
            .collect::<Vec<_>>(),
        vec![
            json!(["eu.europa.ec.eudi.nym_auth.1", "birth_date"]),
            json!(["eu.europa.ec.eudi.nym_auth.1", "ssc"]),
        ]
    );
    let birth_date = &claims[0];
    assert!(birth_date.mandatory);
    assert_eq!(birth_date.svg_id.as_deref(), Some("birth"));
    assert_eq!(birth_date.display[0].name.as_deref(), Some("Date of birth"));
    assert_eq!(
        birth_date.display[0].label.as_deref(),
        Some("Date of birth")
    );
    assert_eq!(birth_date.display[0].locale.as_deref(), Some("en-US"));
    let ssc = &claims[1];
    assert!(!ssc.mandatory);
    assert!(ssc.svg_id.is_none());
    assert!(ssc.display.is_empty(), "an unlabeled claim stays unlabeled");
}

/// The sd-jwt mapping: B.2 lists pass through with their wildcards
/// preserved, and the label spelling arrives as both members.
#[test]
fn sdjwt_display_members_preserve_the_b2_lists() {
    let raw = json!({
        "vct": "urn:eudi:pid:1",
        "display": [{"name": "Person Identification Data (PID)", "locale": "en"}],
        "claims": [
            {
                "path": ["nationalities", null],
                "mandatory": true,
                "display": [{"label": "Nationalities", "locale": "en"}]
            },
            {"path": ["birth_date"], "mandatory": false}
        ]
    });
    let (display, claims) = display_members(&credential("dc+sd-jwt", raw));

    assert_eq!(display.len(), 1);
    assert_eq!(display[0].name, "Person Identification Data (PID)");
    assert_eq!(claims.len(), 2);
    // The null segment (an array-element wildcard) travels as-is.
    assert_eq!(
        serde_json::to_value(&claims[0].path).unwrap(),
        json!(["nationalities", null])
    );
    assert!(claims[0].mandatory);
    assert_eq!(claims[0].display[0].name.as_deref(), Some("Nationalities"));
    assert_eq!(claims[0].display[0].label.as_deref(), Some("Nationalities"));
    assert!(!claims[1].mandatory);
}

/// A document without display content maps to empty vectors — the
/// response then carries no display members, whatever the knob.
#[test]
fn a_document_without_display_content_maps_to_nothing() {
    let raw = json!({"doctype": "eu.europa.ec.eudi.pid.1"});
    let (display, claims) = display_members(&credential("mso_mdoc", raw));
    assert!(display.is_empty());
    assert!(claims.is_empty());
}

/// A display entry without a name is skipped, never guessed (vc
/// validates `name` as REQUIRED).
#[test]
fn a_display_entry_without_a_name_is_skipped() {
    let raw = json!({
        "display": [{"locale": "en"}, {"name": "Named", "locale": "en"}],
    });
    let (display, _) = display_members(&credential("mso_mdoc", raw));
    assert_eq!(display.len(), 1);
    assert_eq!(display[0].name, "Named");
}
