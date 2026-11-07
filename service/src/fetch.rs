//! Bounded TS11 catalog transport. The core stays sans-I/O; this module is
//! the service's transport adapter (design §8.1). Remote URLs are hostile
//! I/O targets: scheme/host policy from verifier-core's ts11, redirects
//! capped, and byte budgets enforced while streaming, before allocation.

use siros_issuer_core::{Error, Result};
use siros_verifier_core::ts11::{
    https_url, parse_schema_page, RegistryDocument, SchemaMeta, MAX_CATALOGUE_BYTES,
    MAX_DOCUMENT_BYTES,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Hard cap on catalog pagination: a registry that never converges is a
/// refusal, not an unbounded loop.
const MAX_PAGES: usize = 64;

pub enum CatalogSource {
    /// Live registry: mirrors tried in order, first answer wins.
    Http {
        client: reqwest::Client,
        mirrors: Vec<url::Url>,
    },
    /// Fixtures / air-gapped deployment: `schema-page.json` plus
    /// `documents.json` (a list of `{format, uri, body}` entries). URIs are
    /// matched, never fetched.
    Static(PathBuf),
}

impl CatalogSource {
    pub fn from_config(cfg: &crate::config::CatalogCfg) -> Result<Self> {
        if let Some(dir) = &cfg.static_dir {
            return Ok(CatalogSource::Static(dir.clone()));
        }
        let mirrors = cfg
            .mirrors
            .iter()
            .map(|mirror| {
                https_url(mirror)
                    .map_err(|e| Error::configuration(format!("catalog mirror {mirror}: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        // Redirect cap: a registry that bounces is a misconfiguration.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .map_err(|e| Error::configuration(format!("catalog HTTP client: {e}")))?;
        Ok(CatalogSource::Http { client, mirrors })
    }
}

/// Load the full working catalog: page through the registry, fetch every
/// indexed-format schema document, and hand the result to the fail-closed
/// core builder (design §8.1).
pub async fn load_catalog(source: &CatalogSource) -> Result<siros_verifier_core::ts11::Catalog> {
    let schemas = load_schemas(source).await?;
    let mut documents = Vec::new();
    for schema in &schemas {
        // The catalog indexes exactly these formats (design §8.2).
        for link in &schema.schema_uris {
            if link.format_identifier != "dc+sd-jwt" && link.format_identifier != "mso_mdoc" {
                continue;
            }
            let body = fetch_document(source, &link.uri).await?;
            documents.push(RegistryDocument {
                schema: schema.clone(),
                format: link.format_identifier.clone(),
                uri: link.uri.clone(),
                body,
            });
        }
    }
    siros_issuer_core::catalog::build_catalog(documents)
}

async fn load_schemas(source: &CatalogSource) -> Result<Vec<SchemaMeta>> {
    match source {
        CatalogSource::Static(dir) => {
            let page_path = dir.join("schema-page.json");
            let body = std::fs::read(&page_path).map_err(|e| {
                Error::configuration(format!("reading {}: {e}", page_path.display()))
            })?;
            Ok(parse_schema_page(&body)?.schemas)
        }
        CatalogSource::Http { client, mirrors } => {
            let mut schemas = Vec::new();
            for mirror in mirrors {
                match fetch_paginated(client, mirror).await {
                    Ok(mut found) => {
                        schemas.append(&mut found);
                        break; // First mirror that answers wins.
                    }
                    Err(error) => {
                        tracing::warn!("catalog mirror {mirror} failed: {error}");
                    }
                }
            }
            if schemas.is_empty() {
                return Err(Error::new(
                    siros_issuer_core::error::code::TRANSPORT,
                    "no catalog mirror answered",
                ));
            }
            Ok(schemas)
        }
    }
}

async fn fetch_paginated(client: &reqwest::Client, mirror: &url::Url) -> Result<Vec<SchemaMeta>> {
    let mut schemas = Vec::new();
    let mut offset = 0usize;
    for _ in 0..MAX_PAGES {
        let mut page_url = mirror.clone();
        page_url
            .query_pairs_mut()
            .append_pair("offset", &offset.to_string())
            .append_pair("limit", "64");
        let body = bounded_get(client, page_url.as_str(), MAX_CATALOGUE_BYTES).await?;
        let page = parse_schema_page(&body)?;
        schemas.extend(page.schemas);
        offset += page.limit.max(1);
        if offset >= page.total {
            return Ok(schemas);
        }
    }
    Err(Error::transport("catalog pagination exceeded the page cap"))
}

async fn fetch_document(source: &CatalogSource, uri: &str) -> Result<Vec<u8>> {
    match source {
        CatalogSource::Static(dir) => {
            let entries: Vec<StaticDocument> = {
                let path = dir.join("documents.json");
                let body = std::fs::read(&path).map_err(|e| {
                    Error::configuration(format!("reading {}: {e}", path.display()))
                })?;
                serde_json::from_slice(&body)
                    .map_err(|e| Error::configuration(format!("documents.json: {e}")))?
            };
            let by_uri: BTreeMap<String, Vec<u8>> = {
                let mut map = BTreeMap::new();
                for entry in entries {
                    let body = serde_json::to_vec(&entry.body)
                        .map_err(|e| Error::configuration(format!("document body: {e}")))?;
                    map.insert(entry.uri, body);
                }
                map
            };
            by_uri.get(uri).cloned().ok_or_else(|| {
                Error::configuration(format!("static catalog has no document for {uri}"))
            })
        }
        CatalogSource::Http { client, .. } => {
            // Schema URIs were validated by parse_schema_page; re-check before
            // the network anyway (defense in depth against refactor drift).
            https_url(uri).map_err(|e| Error::transport(e.to_string()))?;
            bounded_get(client, uri, MAX_DOCUMENT_BYTES).await
        }
    }
}

#[derive(serde::Deserialize)]
struct StaticDocument {
    #[allow(dead_code)]
    format: String,
    uri: String,
    body: serde_json::Value,
}

/// Streamed, budget-checked body read: never allocates beyond the cap, and
/// refuses early on a Content-Length that already exceeds it.
async fn bounded_get(client: &reqwest::Client, uri: &str, cap: usize) -> Result<Vec<u8>> {
    let response = client
        .get(uri)
        .send()
        .await
        .map_err(|e| Error::transport(format!("fetching {uri}: {e}")))?;
    if !response.status().is_success() {
        return Err(Error::transport(format!(
            "fetching {uri}: HTTP {}",
            response.status()
        )));
    }
    if let Some(length) = response.content_length() {
        if length as usize > cap {
            return Err(Error::transport(format!(
                "fetching {uri}: content length exceeds the byte budget"
            )));
        }
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::transport(format!("reading {uri}: {e}")))?
    {
        if body.len() + chunk.len() > cap {
            return Err(Error::transport(format!(
                "fetching {uri}: response exceeds the byte budget"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
