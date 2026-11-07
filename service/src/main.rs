//! siros-issuer-service: the deployable HTTP service around
//! siros-issuer-core. P0/P1 scope (design §13.1): config, catalog load +
//! refresh, wallet-facing well-knowns, the pre-authorized grant end to
//! end (offer → token → credential → notification), and the backend
//! session API behind client-assertion auth + PDP + status allocation.

use siros_issuer_service::{api, config, fetch, pdp, status, store, vault, zk_load};

use api::{AppState, RefreshStatus};
use config::Config;
use siros_verifier_core::ts11::Catalog;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use url::Url;

/// Build the signer provider (design §11.1). P1/P2: the in-memory JWK
/// provider — a configured JWK file, or an ephemeral dev key. P5 adds the
/// PKCS#11 provider (kryptering `cryptoki`) for HSM-resident keys.
fn build_signer(
    config: &Config,
) -> siros_issuer_core::Result<siros_issuer_core::signer::JwkSigner> {
    let mut jwk = match &config.signing.jwk_path {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| {
                siros_issuer_core::Error::configuration(format!("reading {}: {e}", path.display()))
            })?;
            serde_json::from_str::<jose_rs::jwk::Jwk>(&text).map_err(|e| {
                siros_issuer_core::Error::configuration(format!("parsing {}: {e}", path.display()))
            })?
        }
        None => {
            tracing::warn!(
                "no signing.jwk_path configured: an ephemeral dev key signs this process's \
                 credentials; restarts rotate the key — development only"
            );
            jose_rs::jwk::generate_ec("P-256")
                .map_err(|e| siros_issuer_core::Error::configuration(format!("keygen: {e}")))?
        }
    };
    if jwk.alg.is_none() {
        jwk.alg = Some("ES256".to_owned());
    }
    if jwk.kid.is_none() {
        jwk.kid = Some(
            siros_issuer_service::auth::thumbprint(&jwk)
                .map_err(|e| siros_issuer_core::Error::configuration(e.to_string()))?,
        );
    }
    siros_issuer_core::signer::JwkSigner::new(jwk)
}

fn main() {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_owned());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("building the tokio runtime");
    if let Err(error) = runtime.block_on(run(&config_path)) {
        eprintln!("siros-issuer-service: {error}");
        std::process::exit(1);
    }
}

async fn run(config_path: &str) -> siros_issuer_core::Result<()> {
    use std::sync::{Arc, RwLock};
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load(std::path::Path::new(config_path))?;
    let source = fetch::CatalogSource::from_config(&config.catalog)?;

    // Fail-closed startup: no catalog, no service (design §8.1).
    let catalog = fetch::load_catalog(&source).await?;
    tracing::info!(
        "catalog loaded: {} credential types",
        catalog.credentials.len()
    );

    let issuer_base = Url::parse(&config.issuer.url)
        .map_err(|e| siros_issuer_core::Error::configuration(format!("issuer.url: {e}")))?;
    let authorization_servers = config
        .issuer
        .authorization_servers
        .iter()
        .map(|server| {
            Url::parse(server).map_err(|e| {
                siros_issuer_core::Error::configuration(format!(
                    "authorization server {server}: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (events_tx, _) = tokio::sync::broadcast::channel(64);

    // Provider selection is configuration (design §11.1): PKCS#11 (HSM)
    // when `[signing.pkcs11]` is present (mutually exclusive with
    // jwk_path — validated at startup), the in-memory JWK otherwise.
    // One `signer::Signer` either way; the issuance code cannot tell.
    let signer_dyn: Arc<dyn siros_issuer_core::signer::Signer> = match &config.signing.pkcs11 {
        Some(pkcs11_cfg) => Arc::new(
            siros_issuer_service::pkcs11::Pkcs11SignerProvider::connect(pkcs11_cfg).unwrap_or_else(
                |e| {
                    eprintln!("siros-issuer-service: {e}");
                    std::process::exit(1);
                },
            ),
        ),
        None => {
            let signer: Arc<siros_issuer_core::signer::JwkSigner> =
                Arc::new(build_signer(&config).unwrap_or_else(|e| {
                    eprintln!("siros-issuer-service: {e}");
                    std::process::exit(1);
                }));
            signer
        }
    };
    let request_encryption_jwk: Option<serde_json::Value> =
        match &config.signing.request_encryption_jwk_path {
            Some(path) => {
                let text = std::fs::read_to_string(path).map_err(|e| {
                    siros_issuer_core::Error::configuration(format!("reading {path:?}: {e}"))
                })?;
                Some(serde_json::from_str(&text).map_err(|e| {
                    siros_issuer_core::Error::configuration(format!("parsing {path:?}: {e}"))
                })?)
            }
            None => None,
        };
    let request_encryption_key: Option<jose_rs::jwk::Jwk> = match &request_encryption_jwk {
        Some(value) => Some(serde_json::from_value(value.clone()).map_err(|e| {
            siros_issuer_core::Error::configuration(format!("request encryption jwk: {e}"))
        })?),
        None => None,
    };
    let endpoint_paths = siros_issuer_core::oid4vci::EndpointPaths {
        request_encryption_jwk,
        // Deferred issuance (§7.6, Final §9): advertised when configured;
        // the credential endpoint then answers pending and
        // `/deferred-credential` completes the issuance.
        deferred_credential: config.issuance.deferred.then_some("deferred-credential"),
        // Batch issuance (Final §12.2.2): advertised when configured; the
        // configured size is the advertised batch_size (validated ≥ 2 at
        // startup below).
        batch_credential: config
            .issuance
            .batch_size
            .map(|size| ("batch-credential", size)),
        ..Default::default()
    };
    // The advertised batch size must be an integer ≥ 2 (the suite refuses
    // smaller — a batch of one is not a batch).
    if let Some(size) = config.issuance.batch_size {
        if size < 2 {
            eprintln!("siros-issuer-service: issuance.batch_size must be 2 or greater");
            std::process::exit(1);
        }
    }

    // Provider selection is configuration (§11.1): the same signing
    // surface for an HSM-resident key as for a JWK file.
    let pdp: Arc<dyn pdp::TrustPdp> = match &config.pdp {
        Some(pdp_cfg) => Arc::new(pdp::AuthZenPdp::new(
            Url::parse(&pdp_cfg.url)
                .map_err(|e| siros_issuer_core::Error::configuration(format!("pdp.url: {e}")))?,
        )),
        None => {
            tracing::warn!("no pdp configured: every issuance decision is pdp_unavailable");
            Arc::new(pdp::FailClosedPdp)
        }
    };
    let allocator: Arc<dyn status::StatusAllocator> = match &config.status_service {
        Some(status_cfg) => Arc::new(status::SirosStatusClient::new(
            Url::parse(&status_cfg.as_url).map_err(|e| {
                siros_issuer_core::Error::configuration(format!("status_service.as_url: {e}"))
            })?,
            Url::parse(&status_cfg.ingestion_url).map_err(|e| {
                siros_issuer_core::Error::configuration(format!(
                    "status_service.ingestion_url: {e}"
                ))
            })?,
            signer_dyn.clone(),
            config.issuer.url.clone(),
        )),
        None => {
            tracing::warn!(
                "no status_service configured: issuance fails closed (no revocation handle)"
            );
            Arc::new(status::NoAllocator)
        }
    };
    // Storage backend selection (design §6.4): `[storage.mongodb]` ⇒
    // the Mongo `SessionStore` (atomic single-use claims across
    // replicas, TTL-indexed retention) — in the `mongo` feature build;
    // absent (or a build without the feature) ⇒ the in-memory store
    // (tests, single-process dev). One `SessionStore` trait object
    // either way.
    #[cfg(feature = "mongo")]
    let sessions_dyn: Arc<dyn store::SessionStore> = match &config.storage.mongodb {
        Some(mongo) => {
            let store = siros_issuer_service::mongo_store::MongoStore::connect(
                &mongo.uri,
                &mongo.database,
                &mongo.collection,
                config.session.retention_after_final_seconds as i64,
            )
            .await
            .unwrap_or_else(|e| {
                eprintln!("siros-issuer-service: MongoDB connect: {e}");
                std::process::exit(1);
            });
            Arc::new(store)
        }
        None => Arc::new(store::MemoryStore::new()),
    };
    #[cfg(not(feature = "mongo"))]
    let sessions_dyn: Arc<dyn store::SessionStore> = {
        if config.storage.mongodb.is_some() {
            eprintln!(
                "siros-issuer-service: [storage.mongodb] configured but this build lacks the `mongo` feature — refusing to silently fall back to the in-memory store"
            );
            std::process::exit(1);
        }
        Arc::new(store::MemoryStore::new())
    };

    // The attestation tier policy (design §12.1): the same layer serves
    // wallet attestation (WIA/KA) — vc's WalletAttestationPolicyEngine.
    let attestation_policy: std::sync::Arc<
        dyn siros_issuer_service::client_auth::AttestationPolicy,
    > = if config.authorization.attestation.use_pdp {
        Arc::new(siros_issuer_service::client_auth::PdpAttestationPolicy::new(pdp.clone()))
    } else {
        Arc::new(siros_issuer_service::client_auth::WildcardRulesPolicy::new(
            config.authorization.attestation.rules.clone(),
        ))
    };
    // Wallet attestation (§12.1): the evaluator over the same policy
    // layer — `None` when unconfigured (private_key_jwt only).
    let wallet_attestation = config
        .authorization
        .attestation
        .wallet
        .as_ref()
        .map(|wallet_cfg| {
            std::sync::Arc::new(
                siros_issuer_service::wallet_attestation::WalletAttestationEvaluator::new(
                    pdp.clone(),
                    attestation_policy.clone(),
                    siros_issuer_service::wallet_attestation::WiaMode::parse(&wallet_cfg.mode)
                        .unwrap_or_else(|e| {
                            eprintln!("siros-issuer-service: {e}");
                            std::process::exit(1);
                        }),
                    issuer_base.clone(),
                ),
            )
        });

    let state = AppState {
        catalog: Arc::new(RwLock::new(Arc::new(catalog))),
        issuer_base,
        authorization_servers,
        refresh: Arc::new(RefreshStatus::default()),
        sessions: sessions_dyn,
        dpop: Arc::new(siros_issuer_service::dpop::DpopValidator::new(60)),
        last_public_nonce: Arc::new(std::sync::Mutex::new(String::new())),
        login_url: config
            .authorization
            .login_url
            .as_deref()
            .map(|url| {
                Url::parse(url).map_err(|e| {
                    siros_issuer_core::Error::configuration(format!("authorization.login_url: {e}"))
                })
            })
            .transpose()?,
        clients: Arc::new(config.authorization.clients.clone()),
        scopes: config.authorization.scopes.clone(),
        endpoint_paths,
        request_encryption_key,
        cert_chain_der: load_cert_chain(&config),
        attestation: attestation_policy.clone(),
        wallet_attestation,
        signer: signer_dyn.clone(),
        vault: Arc::new(vault::Vault::new()?),
        pdp,
        allocator,
        events_tx,
        credential_validity_seconds: config.issuance.credential_validity_seconds,
        access_token_ttl_seconds: config.issuance.access_token_ttl_seconds,
        c_nonce_ttl_seconds: config.issuance.c_nonce_ttl_seconds,
        rulebooks: config.zk.rulebooks.clone(),
        circuit_manifest: config
            .zk
            .circuits
            .static_dir
            .as_deref()
            .map(zk_load::load_circuit_manifest)
            .transpose()?
            .map(std::sync::Arc::new),
        rate_limit: config.rate_limit.clone(),
    };
    mark_refresh_ok(&state.refresh);

    if config.catalog.refresh_seconds > 0 {
        tokio::spawn(refresh_loop(
            source,
            state.catalog.clone(),
            state.refresh.clone(),
            Duration::from_secs(config.catalog.refresh_seconds),
        ));
    }

    // The retention sweeper (design §6.3): every pass expires
    // TTL-lapsed sessions (SSE broadcast — one state machine, two
    // audiences, §7.7), purges sealed subject data off final records
    // (the notification handler does it immediately; this is the
    // backstop for unnotified finals), and hard-deletes records final
    // past `retention_after_final_seconds`. 0 disables the loop.
    if config.session.sweep_interval_seconds > 0 {
        let sessions = state.sessions.clone();
        let events_tx = state.events_tx.clone();
        let retention = config.session.retention_after_final_seconds as i64;
        let interval = Duration::from_secs(config.session.sweep_interval_seconds);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let now = status::now_unix();
                match sessions.sweep(now, retention).await {
                    Ok(report) => {
                        for id in &report.expired_ids {
                            let _ = events_tx.send(api::SessionEventMessage {
                                session_id: id.clone(),
                                state: "expired",
                                unix: now,
                            });
                        }
                        if report.purged > 0 || report.deleted > 0 || !report.expired_ids.is_empty()
                        {
                            tracing::debug!(
                                expired = report.expired_ids.len(),
                                purged = report.purged,
                                deleted = report.deleted,
                                "retention sweep"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("retention sweep failed: {e}");
                    }
                }
            }
        });
    }

    let bind = config.service.bind.clone();
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| siros_issuer_core::Error::configuration(format!("binding {bind}: {e}")))?;
    tracing::info!("listening on {bind}");
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await
        .map_err(|e| siros_issuer_core::Error::transport(format!("server: {e}")))?;
    Ok(())
}

/// Keep the last good catalog on refresh failure (design §8.1): a broken
/// registry never empties the working metadata, and health reports it.
async fn refresh_loop(
    source: fetch::CatalogSource,
    catalog: Arc<RwLock<Arc<Catalog>>>,
    refresh: Arc<RefreshStatus>,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        match fetch::load_catalog(&source).await {
            Ok(next) => {
                *catalog.write().expect("catalog lock poisoned") = Arc::new(next);
                mark_refresh_ok(&refresh);
            }
            Err(error) => {
                tracing::warn!("catalog refresh failed, keeping last good: {error}");
                *refresh
                    .last_error
                    .write()
                    .expect("refresh status lock poisoned") = Some(error.to_string());
            }
        }
    }
}

fn mark_refresh_ok(refresh: &RefreshStatus) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    refresh.last_ok_unix.store(now, Ordering::Relaxed);
    *refresh
        .last_error
        .write()
        .expect("refresh status lock poisoned") = None;
}

/// Load the issuer's certificate chain (DER, leaf first) for the mdoc
/// x5chain. Empty when no chain is configured (dev ephemeral key).
fn load_cert_chain(config: &Config) -> Vec<Vec<u8>> {
    let Some(path) = &config.signing.cert_chain_path else {
        return Vec::new();
    };
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("siros-issuer-service: reading cert chain {path:?}: {e}");
        std::process::exit(1);
    });
    let mut chain = Vec::new();
    for block in text.split("-----END CERTIFICATE-----") {
        let Some(b64) = block
            .split_once("-----BEGIN CERTIFICATE-----")
            .map(|(_, rest)| rest)
        else {
            continue;
        };
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        let der = siros_issuer_core::sdjwt_issue::b64_decode_std(&cleaned).unwrap_or_else(|e| {
            eprintln!("siros-issuer-service: parsing cert chain {path:?}: {e}");
            std::process::exit(1);
        });
        chain.push(der);
    }
    if chain.is_empty() {
        eprintln!("siros-issuer-service: cert chain {path:?} contains no certificates");
        std::process::exit(1);
    }
    chain
}
