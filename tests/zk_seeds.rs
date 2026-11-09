//! Seed-provider derivation semantics (§8.3 item 2): the `domain_info`
//! contract — one secret, separated roles. The source of truth is the
//! design's derivation contract (`derive(ref, info, inputs, bytes)`:
//! HKDF with domain separation, `info` binding rulebook + credential +
//! transform), which this file enforces against `Opening::Hkdf`.

use serde_json::json;
use siros_issuer_core::zk::Opening;
use std::collections::BTreeMap;

fn secret() -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32])
}

fn claims() -> BTreeMap<String, serde_json::Value> {
    let mut claims = BTreeMap::new();
    claims.insert(
        "personal_administrative_number".to_owned(),
        json!("18880307-9999"),
    );
    claims
}

#[test]
fn domain_info_separates_one_secret_into_distinct_roles() {
    let claims = claims();
    // The same secret, the same inputs, DIFFERENT domain info →
    // different openings: one provider secret never serves two
    // derivations unseparated (the §8.3 derivation contract).
    let ssc = Opening::Hkdf {
        secret_b64url: secret(),
        inputs: vec!["personal_administrative_number".to_owned()],
        domain_info: vec![
            "nym_auth".to_owned(),
            "eu.europa.ec.eudi.nym_auth.1".to_owned(),
            "ssc".to_owned(),
        ],
        bytes: 32,
    }
    .open(&claims)
    .unwrap();
    let psc = Opening::Hkdf {
        secret_b64url: secret(),
        inputs: vec!["personal_administrative_number".to_owned()],
        domain_info: vec![
            "nym_auth".to_owned(),
            "eu.europa.ec.eudi.nym_auth.1".to_owned(),
            "psc".to_owned(),
        ],
        bytes: 32,
    }
    .open(&claims)
    .unwrap();
    assert_ne!(ssc, psc, "distinct domain_info derives distinct openings");

    // Empty domain_info (the vc-shaped in-line fixture vocabulary)
    // derives yet another value — and matches the historical
    // in-line-hkdf derivation, so fixture continuity holds.
    let bare = Opening::Hkdf {
        secret_b64url: secret(),
        inputs: vec!["personal_administrative_number".to_owned()],
        domain_info: Vec::new(),
        bytes: 32,
    }
    .open(&claims)
    .unwrap();
    assert_ne!(bare, ssc);
}

#[test]
fn domain_info_order_is_part_of_the_derivation() {
    let claims = claims();
    let a = Opening::Hkdf {
        secret_b64url: secret(),
        inputs: vec![],
        domain_info: vec!["role-one".to_owned(), "role-two".to_owned()],
        bytes: 32,
    }
    .open(&claims)
    .unwrap();
    let b = Opening::Hkdf {
        secret_b64url: secret(),
        inputs: vec![],
        domain_info: vec!["role-two".to_owned(), "role-one".to_owned()],
        bytes: 32,
    }
    .open(&claims)
    .unwrap();
    assert_ne!(
        a, b,
        "every field is length-prefixed in order (vc appendField)"
    );
}

#[test]
fn different_secrets_still_derive_different_openings() {
    use base64::Engine;
    let claims = claims();
    let other = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
    let a = Opening::Hkdf {
        secret_b64url: secret(),
        inputs: vec![],
        domain_info: vec!["role".to_owned()],
        bytes: 32,
    }
    .open(&claims)
    .unwrap();
    let b = Opening::Hkdf {
        secret_b64url: other,
        inputs: vec![],
        domain_info: vec!["role".to_owned()],
        bytes: 32,
    }
    .open(&claims)
    .unwrap();
    assert_ne!(a, b);
}
