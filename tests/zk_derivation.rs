//! The ZK derivation vocabulary (src/zk.rs): the HKDF opening's domain
//! separation and order sensitivity (vc's exact `appendField` message
//! layout), the salt policy bounds (a Fixed length outside [8, 64] is
//! refused at the point of use), and the commitment codec (SHA-256 of
//! the opening, encodable base64url/base64/hex). Lives in tests/ per
//! the workspace rule: tests exercise the public API, no #[cfg(test)]
//! under src/.

use std::collections::BTreeMap;

use siros_issuer_core::zk::{
    decode_commitment, encode_commitment, hash_commitment, Opening, SaltPolicy,
};

/// vc's exact HKDF message layout: label, length in decimal, then each
/// input value, each two-byte-length-prefixed (vc `appendField`) —
/// so ["ab", "c"] and ["a", "bc"] derive differently.
#[test]
fn hkdf_opening_is_domain_separated_and_order_sensitive() {
    let mut claims = BTreeMap::new();
    claims.insert("a".to_owned(), serde_json::json!("val1"));
    claims.insert("b".to_owned(), serde_json::json!("val2"));
    let secret =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7u8; 32]);
    let o1 = Opening::Hkdf {
        secret_b64url: secret.clone(),
        inputs: vec!["a".to_owned(), "b".to_owned()],
        domain_info: Vec::new(),
        bytes: 32,
    }
    .open(&claims)
    .unwrap();
    let o2 = Opening::Hkdf {
        secret_b64url: secret,
        inputs: vec!["b".to_owned(), "a".to_owned()],
        domain_info: Vec::new(),
        bytes: 32,
    }
    .open(&claims)
    .unwrap();
    assert_ne!(o1, o2, "input order is part of the derivation");

    // A different secret derives a different opening.
    let claims2 = claims.clone();
    let other_secret =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [9u8; 32]);
    let o3 = Opening::Hkdf {
        secret_b64url: other_secret,
        inputs: vec!["a".to_owned(), "b".to_owned()],
        domain_info: Vec::new(),
        bytes: 32,
    }
    .open(&claims2)
    .unwrap();
    assert_ne!(o1, o3);
}

/// The salt policy bounds: a Fixed length outside [8, 64] is refused
/// at the point of use, not just in config validation.
#[test]
fn salt_policy_bounds_are_enforced() {
    assert_eq!(
        SaltPolicy::DefaultSizing
            .salt_bytes_for("family_name")
            .unwrap(),
        16
    );
    assert_eq!(
        SaltPolicy::DefaultSizing
            .salt_bytes_for("pseudonym_seed")
            .unwrap(),
        8
    );
    assert!(SaltPolicy::Fixed(0).salt_bytes_for("x").is_err());
    assert!(SaltPolicy::Fixed(65).salt_bytes_for("x").is_err());
    assert_eq!(SaltPolicy::Fixed(32).salt_bytes_for("x").unwrap(), 32);
}

/// Commitments are SHA-256 of the opening, encodable per the entry.
#[test]
fn commitment_is_sha256_and_encodable() {
    let opening = [1u8; 32];
    let c = hash_commitment("sha-256", &opening).unwrap();
    assert_eq!(c.len(), 32);
    let b64url = encode_commitment("base64url", &c).unwrap();
    assert_eq!(decode_commitment(&b64url).unwrap(), c);
    let hexform = encode_commitment("hex", &c).unwrap();
    assert!(hexform.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(hash_commitment("sha-512", &opening).is_err());
    assert!(hash_commitment("sha-256", &[]).is_err());
}
