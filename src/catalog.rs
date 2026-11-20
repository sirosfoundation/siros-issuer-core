//! The issuer's working catalog: TS 119 602 / TS11 registry documents mapped
//! through `siros-verifier-core` into an issuance catalog.
//!
//! The catalog is authoritative and fail-closed (design §8.1): a schema that
//! does not parse, does not verify its SRI, or is absent is refused, never
//! patched up. Credential resolution by identifier is unambiguous — multiple
//! schemas sharing an identifier yield no answer, not a random pick.

use crate::error::{code, Error, Result};
use siros_verifier_core::ts11::{Catalog, CredentialType, RegistryDocument};

/// Build the working catalog from registry documents. Verifier-core
/// validation errors are mapped to the `catalog_invalid` refusal.
pub fn build_catalog(documents: Vec<RegistryDocument>) -> Result<Catalog> {
    Catalog::from_documents(documents).map_err(Error::from)
}

/// Resolve a credential by any of its identifiers: vct (dc+sd-jwt), doctype
/// (mso_mdoc), or TS11 schema id. Unambiguous identifiers only — a vct,
/// doctype or schema id that matches more than one distinct credential is a
/// refusal, not a random pick.
///
/// This scans `catalog.credentials` directly instead of
/// `Catalog::resolve_vct`/`resolve_doctype`: the pinned verifier-core rev
/// (fa7f491) records index maps *before* its final `credentials.sort_by`,
/// so the maps point at stale positions in any catalog whose insertion
/// order differs from its sort order — `resolve_vct` then returns the wrong
/// credential. Remove this comment and consider the maps again only after
/// the upstream fix (siros-verifier-core, `Catalog::from_documents`,
/// src/ts11.rs).
pub fn resolve<'a>(catalog: &'a Catalog, identifier: &str) -> Result<&'a CredentialType> {
    fn push_unique<'a>(matches: &mut Vec<&'a CredentialType>, credential: &'a CredentialType) {
        if !matches.iter().any(|found| std::ptr::eq(*found, credential)) {
            matches.push(credential);
        }
    }

    let mut matches: Vec<&CredentialType> = Vec::new();
    for credential in &catalog.credentials {
        // `identifier` is the vct for dc+sd-jwt and the doctype for
        // mso_mdoc (verifier-core's CredentialType contract), so both
        // resolve by the same field.
        if credential.identifier == identifier || credential.schema_id == identifier {
            push_unique(&mut matches, credential);
        }
    }

    match matches.len() {
        0 => Err(Error::new(
            code::UNSUPPORTED_CREDENTIAL,
            format!("no catalog credential matches {identifier}"),
        )),
        1 => Ok(matches[0]),
        _ => Err(Error::unsupported_credential(format!(
            "identifier {identifier} matches multiple catalog credentials"
        ))),
    }
}

/// The response-level display members for a catalog credential (issue
/// #41): `display` — the localized display objects — and `claims` —
/// the Appendix B.2 claim descriptions — read from the credential's raw
/// TS11 document body.
///
/// This is vc's `Generate` mapping (`pkg/model/config.go`) carried to
/// the response: mdoc claims arrive namespaced (`{namespace: {element:
/// …}}`) and sd-jwt claims as B.2 lists, and both leave as B.2
/// descriptions in sorted path order; a display entry's SVG templates
/// ride `rendering`, and the first template doubles as the `logo` when
/// the document carries none (vc's `mapSvgTemplates` — the data: URI
/// card art is what a wallet's simple-rendering path draws). The
/// claim-label rule is vc's, both ways: the label falls back to the
/// name and the name to the label, so an MDDL `name` and a VCTM
/// `label` both come out as both members.
///
/// The mapping never invents: a document without display content maps
/// to empty vectors, and the response then carries no display members
/// (an empty `credential_metadata` object never reaches the wire — the
/// knob's gate in the service decides, and the OIDF suite's closed
/// response set never sees an unknown member).
pub fn display_members(
    credential: &CredentialType,
) -> (
    Vec<crate::oid4vci::CredentialMetadataDisplay>,
    Vec<crate::oid4vci::ClaimDescription>,
) {
    use crate::oid4vci::{
        ClaimDescription, ClaimDisplayProperties, CredentialMetadataDisplay, MetadataLogo,
        MetadataRendering, MetadataSvgTemplate,
    };
    use serde_json::Value;

    fn text(value: &Value, member: &str) -> Option<String> {
        value
            .get(member)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    }

    fn logo_of(value: &Value) -> Option<MetadataLogo> {
        let uri = text(value, "uri")?;
        Some(MetadataLogo {
            uri,
            alt_text: text(value, "alt_text"),
        })
    }

    // One claim description at a (pre-resolved) path — vc's Generate
    // claim mapping.
    fn claim(meta: &Value, path: Vec<Option<String>>) -> ClaimDescription {
        let mut display = Vec::new();
        for entry in meta
            .get("display")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = text(entry, "name");
            let label = text(entry, "label");
            display.push(ClaimDisplayProperties {
                // vc's both-ways rule: the MDDL branch keeps Name and
                // the label (fallback to Name) in step; the VCTM branch
                // labels only. One spelling in, both members out.
                name: name.clone().or_else(|| label.clone()),
                label: label.or(name),
                locale: text(entry, "locale"),
            });
        }
        ClaimDescription {
            path,
            svg_id: text(meta, "svg_id"),
            mandatory: meta
                .get("mandatory")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            display,
        }
    }

    // One display object. `name` is REQUIRED (vc validates it); an
    // entry without one is skipped, never guessed.
    fn display(entry: &Value) -> Option<CredentialMetadataDisplay> {
        let mut out = CredentialMetadataDisplay {
            name: text(entry, "name")?,
            locale: text(entry, "locale"),
            description: text(entry, "description"),
            logo: entry.get("logo").and_then(logo_of),
            background_color: text(entry, "background_color"),
            text_color: text(entry, "text_color"),
            rendering: None,
        };
        if let Some(rendering) = entry.get("rendering") {
            // The VCTM `simple` block (the sd-jwt display shape):
            // colors and logo under `simple`, merged only where the
            // entry itself did not carry them (vc's VCTM branch).
            if let Some(simple) = rendering.get("simple") {
                if out.background_color.is_none() {
                    out.background_color = text(simple, "background_color");
                }
                if out.text_color.is_none() {
                    out.text_color = text(simple, "text_color");
                }
                if out.logo.is_none() {
                    out.logo = simple.get("logo").and_then(logo_of);
                }
            }
            let templates: Vec<MetadataSvgTemplate> = rendering
                .get("svg_templates")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|template| serde_json::from_value(template.clone()).ok())
                .collect();
            if !templates.is_empty() {
                // vc's mapSvgTemplates: the first template doubles as
                // the logo when the entry carries none — the card art
                // is the simple-rendering fallback.
                if out.logo.is_none() {
                    out.logo = Some(MetadataLogo {
                        uri: templates[0].uri.clone(),
                        alt_text: None,
                    });
                }
                out.rendering = Some(MetadataRendering {
                    svg_templates: templates,
                });
            }
        }
        Some(out)
    }

    let raw = &credential.raw;
    let display: Vec<_> = raw
        .get("display")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(display)
        .collect();
    let mut claims = Vec::new();
    if credential.format == "mso_mdoc" {
        // Namespaced claims, both levels in sorted order (vc's Generate
        // sorts; the wire order is stable whatever the document's).
        if let Some(namespaces) = raw.get("claims").and_then(Value::as_object) {
            let mut namespaces: Vec<(&String, &Value)> = namespaces.iter().collect();
            namespaces.sort_by(|a, b| a.0.cmp(b.0));
            for (namespace, elements_value) in namespaces {
                let Some(elements) = elements_value.as_object() else {
                    continue;
                };
                let mut elements: Vec<(&String, &Value)> = elements.iter().collect();
                elements.sort_by(|a, b| a.0.cmp(b.0));
                for (element, meta) in elements {
                    claims.push(claim(
                        meta,
                        vec![Some(namespace.clone()), Some(element.clone())],
                    ));
                }
            }
        }
    } else {
        // dc+sd-jwt: the claims are already B.2 lists; a null path
        // segment (an array-element wildcard) is preserved as-is.
        for meta in raw
            .get("claims")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let path = meta
                .get("path")
                .and_then(Value::as_array)
                .map(|segments| {
                    segments
                        .iter()
                        .map(|segment| segment.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            claims.push(claim(meta, path));
        }
    }
    (display, claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
}
