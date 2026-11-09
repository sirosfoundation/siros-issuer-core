//! Seed-provider loading (§8.3 item 2) and the `auxiliary_data_supported`
//! plan derivation (§8.3 item 3) — fail-closed startup surfaces, each
//! tested against the documented contract (the design doc's §8.3 items,
//! vc's `AuxiliaryDataSupported` wire shape).

use std::collections::HashMap;

use siros_issuer_service::config::{AuxiliaryDataCfg, AuxiliaryEntryCfg, RulebookCfg};
use siros_issuer_service::zk_seeds::SeedProviders;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("siros-issuer-seeds-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_secret(path: &std::path::Path, bytes: usize) {
    std::fs::write(path, vec![7u8; bytes]).unwrap();
}

#[test]
fn seed_providers_load_and_fail_closed() {
    let dir = temp_dir("load");
    let good = dir.join("good.secret");
    write_secret(&good, 32);

    // A well-formed provider loads; the secret is retrievable.
    let mut providers = HashMap::new();
    providers.insert(
        "nym_auth".to_owned(),
        siros_issuer_service::config::SeedProviderCfg {
            secret_path: good.to_str().unwrap().to_owned(),
        },
    );
    let loaded = SeedProviders::load(&providers).unwrap();
    assert!(loaded.secret("nym_auth").unwrap().len() >= 43);

    // Unknown name = fail-closed, never a default secret.
    assert!(loaded.secret("other").is_err());

    // A missing file refuses startup.
    let mut missing = HashMap::new();
    missing.insert(
        "gone".to_owned(),
        siros_issuer_service::config::SeedProviderCfg {
            secret_path: dir.join("nope.secret").to_str().unwrap().to_owned(),
        },
    );
    assert!(SeedProviders::load(&missing).is_err());

    // An undersized secret refuses startup: HKDF keys under 32 bytes
    // are refused by the core's derivation; refuse them at load time.
    let short = dir.join("short.secret");
    write_secret(&short, 16);
    let mut undersized = HashMap::new();
    undersized.insert(
        "short".to_owned(),
        siros_issuer_service::config::SeedProviderCfg {
            secret_path: short.to_str().unwrap().to_owned(),
        },
    );
    assert!(SeedProviders::load(&undersized).is_err());

    std::fs::remove_dir_all(&dir).ok();
}

/// The `auxiliary_data_supported` plans (§8.3 item 3): a rulebook's plan
/// maps to the per-configuration metadata member — mechanism only (no
/// opening/commitment values), to_wallet entries never `required`,
/// to_issuer entries `required`, and fail-closed validation on
/// alg/encoding/path.
#[test]
fn auxiliary_data_plans_derive_the_metadata_member() {
    let mut rulebooks = HashMap::new();
    rulebooks.insert(
        "nym_auth".to_owned(),
        RulebookCfg {
            credentials: vec!["eu.europa.ec.eudi.nym_auth.1".to_owned()],
            zk_systems: vec!["vega-mc".to_owned()],
            pinned_salt_bytes: Some(32),
            auxiliary_data: AuxiliaryDataCfg {
                to_wallet: vec![AuxiliaryEntryCfg {
                    alg: "sha-256".to_owned(),
                    path: vec!["eu.europa.ec.eudi.nym_auth.1".to_owned(), "ssc".to_owned()],
                    opening: None,
                    encoding: Some("base64url".to_owned()),
                }],
                to_issuer: vec![AuxiliaryEntryCfg {
                    alg: "sha-256".to_owned(),
                    path: vec!["eu.europa.ec.eudi.nym_auth.1".to_owned(), "psc".to_owned()],
                    opening: None,
                    encoding: None,
                }],
            },
        },
    );

    let plans = siros_issuer_service::api::auxiliary_data_plans(&rulebooks).unwrap();
    let plan = &plans["eu.europa.ec.eudi.nym_auth.1"];
    assert_eq!(plan.to_wallet.len(), 1);
    assert_eq!(plan.to_issuer.len(), 1);
    // Mechanism only: type/alg/path/encoding — never opening values.
    let entry = &plan.to_wallet[0];
    assert_eq!(entry.entry_type, "hash_commitment");
    assert_eq!(entry.alg.as_deref(), Some("sha-256"));
    assert_eq!(entry.path, vec!["eu.europa.ec.eudi.nym_auth.1", "ssc"]);
    assert!(!entry.required, "to_wallet entries are never required");
    // to_issuer entries are required in metadata (the wallet must send).
    assert!(plan.to_issuer[0].required);

    // Fail-closed: a non-sha-256 alg refuses the plan.
    let mut bad_alg = rulebooks.clone();
    let mut mutated = bad_alg.get_mut("nym_auth").unwrap().auxiliary_data.clone();
    mutated.to_wallet[0].alg = "sha-512".to_owned();
    bad_alg.get_mut("nym_auth").unwrap().auxiliary_data = mutated;
    assert!(siros_issuer_service::api::auxiliary_data_plans(&bad_alg).is_err());

    // Fail-closed: an unknown encoding refuses.
    let mut bad_enc = rulebooks.clone();
    let mut mutated = bad_enc.get_mut("nym_auth").unwrap().auxiliary_data.clone();
    mutated.to_wallet[0].encoding = Some("base32".to_owned());
    bad_enc.get_mut("nym_auth").unwrap().auxiliary_data = mutated;
    assert!(siros_issuer_service::api::auxiliary_data_plans(&bad_enc).is_err());

    // Fail-closed: an empty path refuses.
    let mut bad_path = rulebooks.clone();
    let mut mutated = bad_path.get_mut("nym_auth").unwrap().auxiliary_data.clone();
    mutated.to_wallet[0].path = Vec::new();
    bad_path.get_mut("nym_auth").unwrap().auxiliary_data = mutated;
    assert!(siros_issuer_service::api::auxiliary_data_plans(&bad_path).is_err());
}

/// The rule config surface: `[authorization.pre_auth_binding]` parses
/// (the §6.5 v2 deployment gate).
#[test]
fn pre_auth_binding_config_parses() {
    let base = r#"
[issuer]
url = "https://issuer.example.org:9443"
[catalog]
static_dir = "testdata/ts11"
"#;
    let config = siros_issuer_service::config::Config::from_toml_str(&format!(
        "{base}\n[authorization.pre_auth_binding]\npresentation_credential = \"eu.europa.ec.eudi.pid.1\"\n"
    ))
    .unwrap();
    let binding = config.authorization.pre_auth_binding.expect("parsed");
    assert_eq!(binding.presentation_credential, "eu.europa.ec.eudi.pid.1");

    // The deny-unknown-fields discipline holds on the binding table.
    assert!(siros_issuer_service::config::Config::from_toml_str(&format!(
        "{base}\n[authorization.pre_auth_binding]\npresentation_credential = \"eu.europa.ec.eudi.pid.1\"\ntypo_field = true\n"
    ))
    .is_err());
}
