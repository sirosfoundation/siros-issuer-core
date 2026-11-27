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
    let catalog = Catalog::from_documents(documents).map_err(Error::from)?;
    for credential in &catalog.credentials {
        array_claims_declared(credential)?;
        never_disclosable(credential)?;
    }
    Ok(catalog)
}

/// A path into an array (`null` segment, which verifier-core accepts only
/// in last position) has no claim of its own: its elements issue with the
/// array's claim (see [`credential_claims`]). Without that claim it would
/// be silently absent from every credential, so the catalog is refused.
fn array_claims_declared(credential: &CredentialType) -> Result<()> {
    for claim in &credential.claims {
        let Some((None, array)) = claim.path.split_last() else {
            continue;
        };
        if !credential.claims.iter().any(|other| other.path == array) {
            return Err(Error::catalog_invalid(format!(
                "{}: claim path {} addresses the elements of an array whose own path is not declared",
                credential.identifier,
                serde_json::json!(claim.path),
            )));
        }
    }
    Ok(())
}

/// The `sd` of every all-name claim path of a dc+sd-jwt credential's type
/// metadata (SD-JWT VC, claim selective disclosure metadata): `true` =
/// `never`. Absent `sd` is the specification's default `allowed`. A path
/// listed twice is `never` only if both entries are. Any other value is
/// refused: the catalog is fail-closed, and a misspelt `never` must not
/// silently issue something else.
fn never_disclosable(
    credential: &CredentialType,
) -> Result<std::collections::BTreeMap<Vec<String>, bool>> {
    use serde_json::Value;

    let mut never = std::collections::BTreeMap::new();
    if credential.format != crate::oid4vci::SD_JWT_FORMAT {
        return Ok(never);
    }
    for claim in credential
        .raw
        .get("claims")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let is_never = match claim.get("sd").map(Value::as_str) {
            None | Some(Some("allowed" | "always")) => false,
            Some(Some("never")) => true,
            Some(_) => {
                return Err(Error::new(
                    code::CATALOG_INVALID,
                    format!(
                        "{}: claim sd must be always, allowed or never",
                        credential.identifier
                    ),
                ))
            }
        };
        // A path into an array (null segment) addresses no claim of
        // its own here: it issues as part of the array.
        let path: Option<Vec<String>> = claim
            .get("path")
            .and_then(Value::as_array)
            .filter(|path| !path.is_empty())
            .and_then(|path| {
                path.iter()
                    .map(|segment| segment.as_str().map(str::to_owned))
                    .collect()
            });
        if let Some(path) = path {
            *never.entry(path).or_insert(true) &= is_never;
        }
    }
    Ok(never)
}

/// The dc+sd-jwt credential claims of a subject: every catalog claim the
/// subject has, at its own path — `["registered_address", "post_code"]`
/// is a member of `registered_address`, never a top-level `post_code`.
/// Nothing the catalog does not name becomes a claim.
pub fn credential_claims(
    credential: &CredentialType,
    subject: &serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    use serde_json::{Map, Value};

    let mut claims = Map::new();
    'claims: for claim in &credential.claims {
        let mut value = subject;
        let mut names = Vec::new();
        for segment in &claim.path {
            // Absent optional claims are skipped (mandatories were gated at
            // session creation), and so is a path into an array: the
            // array's own claim carries its elements, and `build_catalog`
            // refuses a catalog that does not declare it.
            let Some(name) = segment.as_deref() else {
                continue 'claims;
            };
            let Some(next) = value.get(name) else {
                continue 'claims;
            };
            names.push(name);
            value = next;
        }
        let Some((last, parents)) = names.split_last() else {
            continue;
        };
        // The claims mirror the subject's own structure, so every parent
        // is an object, whichever of parent and child is listed first.
        let mut target = &mut claims;
        for parent in parents {
            let Some(object) = target
                .entry(*parent)
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
            else {
                continue 'claims;
            };
            target = object;
        }
        target.insert((*last).to_owned(), value.clone());
    }
    claims
}

/// The paths of `claims` (from [`credential_claims`]) to conceal: every
/// top-level claim, whole, unless the type metadata declares it
/// `sd: "never"`. A `never` object rides in the clear, and only its
/// members that are declared without `never` are concealed, one by one.
/// An object the metadata names only through its members is in the clear
/// as soon as one of them is `never`: concealing it would conceal that
/// member too.
pub fn concealed_claims(
    credential: &CredentialType,
    claims: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<Vec<String>>> {
    let never = never_disclosable(credential)?;
    let mut concealed = Vec::new();
    for name in claims.keys() {
        let own = std::slice::from_ref(name);
        let members = never
            .iter()
            .filter(|(path, _)| path.len() > 1 && path[0] == *name);
        let in_the_clear = match never.get(own) {
            Some(never) => *never,
            None => members.clone().any(|(_, never)| *never),
        };
        if !in_the_clear {
            concealed.push(own.to_vec());
            continue;
        }
        concealed.extend(
            members
                .filter(|(path, never)| {
                    !**never
                        && path[1..]
                            .iter()
                            .try_fold(&claims[name], |value, segment| value.get(segment))
                            .is_some()
                })
                .map(|(path, _)| path.clone()),
        );
    }
    Ok(concealed)
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
/// #41, OpenID4VCI 1.0 ID1 §12.2.4): `display` — the localized display
/// objects — and `claims` — the §12.2.4 Appendix B.2 claim
/// descriptions — read from the credential's raw TS11 document body.
///
/// This is vc's `Generate` mapping (`pkg/model/config.go`, the
/// ported-semantics reference — design doc Appendix A) carried to the
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

/// The catalog's declared `value_type` for one mdoc claim (the raw TS11
/// body: `claims.<namespace>.<element>.value_type`). The declared type
/// is the wire contract the wallets bind — the credential claim's CBOR
/// encoding follows it, never a guess.
pub fn claim_value_type<'a>(
    credential: &'a CredentialType,
    namespace: &str,
    element: &str,
) -> Option<&'a str> {
    credential
        .raw
        .get("claims")?
        .get(namespace)?
        .get(element)?
        .get("value_type")?
        .as_str()
}

/// The credential-claim form a derived commitment takes (issue #43).
#[derive(Debug)]
pub enum CommitmentClaimForm {
    /// A `value_type: "bstr"` claim: the raw commitment bytes as a CBOR
    /// byte string — a 32-byte sha-256 commitment carried as bytes,
    /// not a text encoding of them.
    Bytes(Vec<u8>),
    /// A `value_type: "tstr"` claim: the configured-encoding text.
    Text(String),
}

/// Decide the credential-claim form of a derived commitment from the
/// catalog's declared `value_type` (issue #43): `bstr` carries the raw
/// bytes, `tstr` the configured-encoding text — anything else,
/// **including an undeclared type, is a refusal**, never a guessed
/// encoding. The leniency this replaces delivered the nym_auth ssc as
/// 43-char base64url TEXT past the (encoding-aware) issuance gate and
/// detonated at presentation, after consent, where the presenter binds
/// the circuit input per the catalog type (SECRET_COMMITMENT,
/// `SHA256(seed) == ssc` on a byte string that never was one).
pub fn commitment_claim_form(
    value_type: Option<&str>,
    bytes: Vec<u8>,
    text: String,
) -> Result<CommitmentClaimForm> {
    match value_type {
        Some("bstr") => Ok(CommitmentClaimForm::Bytes(bytes)),
        Some("tstr") => Ok(CommitmentClaimForm::Text(text)),
        Some(other) => Err(Error::catalog_invalid(format!(
            "the catalog declares value_type {other:?} for a commitment claim — not a commitment carrier"
        ))),
        None => Err(Error::catalog_invalid(
            "the catalog element declares no value_type — a commitment claim's encoding would be a guess",
        )),
    }
}
