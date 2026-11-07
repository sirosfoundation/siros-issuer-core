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
