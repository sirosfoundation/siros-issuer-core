//! The circuit catalog (design §8.3 item 1): zk issuance parameters
//! resolved per (system, doctype). Sources of truth: the resolution
//! semantics ported verbatim from vc's `zkcircuit`/`zk_salt.go` — each
//! test below pins one direction of that contract, positive and
//! negative, with the refusal as a stable code.

use serde_json::json;
use siros_issuer_core::error::code;
use siros_issuer_core::zk::circuit::{resolve_salt, CircuitManifest, PARAM_SALT_BYTES};
use siros_issuer_core::zk::SaltPolicy;

const DOCTYPE: &str = "eu.europa.ec.eudi.nym_auth.1";

/// A manifest fixture: vega-mc (saltBytes "32") + longfellow (no salt
/// param) for the nym_auth doctype — the shapes the live catalog
/// publishes (string and integer params respectively).
fn manifest() -> CircuitManifest {
    serde_json::from_value(json!({
        "circuits": [
            {
                "id": "vega-nym-auth-v1",
                "system": "vega-mc",
                "docTypes": [DOCTYPE],
                "published": true,
                "status": "active",
                "params": { "saltBytes": "32" }
            },
            {
                "id": "longfellow-nym-auth-v1",
                "system": "longfellow",
                "docTypes": [DOCTYPE],
                "published": true,
                "status": "active",
                "params": { "num_attributes": 2 }
            }
        ]
    }))
    .expect("fixture manifest parses")
}

#[test]
fn active_circuit_resolves_its_salt_length() {
    let m = manifest();
    let c = m.constraints("vega-mc", DOCTYPE).expect("resolves");
    assert_eq!(c.salt_bytes, 32);
    assert_eq!(c.circuit_ids, vec!["vega-nym-auth-v1".to_owned()]);
    // A decimal STRING param parses (the live vega catalog publishes
    // "32"; a consumer must not need to know which spelling a publisher
    // chose).
}

#[test]
fn system_without_salt_param_states_no_constraint() {
    let m = manifest();
    let c = m.constraints("longfellow", DOCTYPE).expect("resolves");
    // 0 = no constraint (default per-element sizing), NOT "zero bytes".
    assert_eq!(c.salt_bytes, 0);
}

#[test]
fn unknown_system_is_distinguished_from_withdrawn() {
    let m = manifest();
    // A system the manifest has never carried (not published yet).
    let err = m.constraints("vega-mc2", DOCTYPE).expect_err("refuses");
    assert_eq!(err.code, code::CATALOG_INVALID);
    assert!(err.message.contains("unknown zk system"), "{err}");
    // A system the manifest knows but has withdrawn: no active circuit
    // for this doctype (the fixture's longfellow scoped elsewhere).
    let err = m
        .constraints("longfellow", "org.example.other.1")
        .expect_err("refuses");
    assert_eq!(err.code, code::CATALOG_INVALID);
    assert!(err.message.contains("no active circuit"), "{err}");
    // Both are catalog refusals at the resolve_salt level — distinct
    // only in message; a pin may stand in for NEITHER is not the
    // contract… (see resolve tests below for the pin direction).
}

#[test]
fn unpublished_and_deprecated_circuits_are_not_active() {
    let m: CircuitManifest = serde_json::from_value(json!({
        "circuits": [
            {
                "id": "unpublished",
                "system": "vega-mc",
                "docTypes": [DOCTYPE],
                "published": false,
                "status": "active",
                "params": { "saltBytes": 32 }
            },
            {
                "id": "deprecated",
                "system": "vega-mc",
                "docTypes": [DOCTYPE],
                "published": true,
                "status": "deprecated",
                "params": { "saltBytes": 32 }
            }
        ]
    }))
    .expect("parses");
    let err = m
        .constraints("vega-mc", DOCTYPE)
        .expect_err("no active circuit");
    assert!(err.message.contains("no active circuit"), "{err}");
}

#[test]
fn unscoped_circuit_is_never_applied_to_every_doctype() {
    // A circuit declaring no doctypes is skipped, never assumed to apply
    // to all — inferring "all" from silence is how a constraint meant
    // for an mDL ends up applied to something else.
    let m: CircuitManifest = serde_json::from_value(json!({
        "circuits": [
            {
                "id": "unscoped",
                "system": "vega-mc",
                "published": true,
                "status": "active",
                "params": { "saltBytes": 32 }
            }
        ]
    }))
    .expect("parses");
    let err = m.constraints("vega-mc", DOCTYPE).expect_err("refuses");
    // The manifest carries vega-mc but the circuit is unscoped: refused.
    assert_eq!(err.code, code::CATALOG_INVALID);
}

#[test]
fn disagreeing_active_circuits_refuse_rather_than_pick() {
    let m: CircuitManifest = serde_json::from_value(json!({
        "circuits": [
            {
                "id": "a",
                "system": "vega-mc",
                "docTypes": [DOCTYPE],
                "published": true,
                "status": "active",
                "params": { "saltBytes": 32 }
            },
            {
                "id": "b",
                "system": "vega-mc",
                "docTypes": [DOCTYPE],
                "published": true,
                "status": "active",
                "params": { "saltBytes": 16 }
            }
        ]
    }))
    .expect("parses");
    let err = m.constraints("vega-mc", DOCTYPE).expect_err("refuses");
    assert!(err.message.contains("disagree"), "{err}");
}

#[test]
fn present_but_unreadable_param_is_a_refusal_not_an_absence() {
    // "32.0" / an object / null is present-but-unreadable: a constraint
    // nobody can honour, never "no constraint" (fails open otherwise).
    for bad in [json!("32.0"), json!({}), json!(serde_json::Value::Null)] {
        let m: CircuitManifest = serde_json::from_value(json!({
            "circuits": [{
                "id": "c",
                "system": "vega-mc",
                "docTypes": [DOCTYPE],
                "published": true,
                "status": "active",
                "params": { "saltBytes": bad }
            }]
        }))
        .expect("parses");
        let err = m.constraints("vega-mc", DOCTYPE).expect_err("refuses");
        assert!(err.message.contains("not an integer"), "{err}");
    }
}

#[test]
fn constrained_and_unconstrained_mix_for_one_system_refuses() {
    // One credential carries one salt per item: a system whose circuits
    // publish a length AND publish none is a catalog inconsistency.
    let m: CircuitManifest = serde_json::from_value(json!({
        "circuits": [
            {
                "id": "constrained",
                "system": "vega-mc",
                "docTypes": [DOCTYPE],
                "published": true,
                "status": "active",
                "params": { "saltBytes": 32 }
            },
            {
                "id": "unconstrained",
                "system": "vega-mc",
                "docTypes": [DOCTYPE],
                "published": true,
                "status": "active",
                "params": {}
            }
        ]
    }))
    .expect("parses");
    let err = m.constraints("vega-mc", DOCTYPE).expect_err("refuses");
    assert!(err.message.contains("publishing none"), "{err}");
}

#[test]
fn out_of_range_salt_length_refuses() {
    for bad in [7, 65] {
        let m: CircuitManifest = serde_json::from_value(json!({
            "circuits": [{
                "id": "c",
                "system": "vega-mc",
                "docTypes": [DOCTYPE],
                "published": true,
                "status": "active",
                "params": { "saltBytes": bad }
            }]
        }))
        .expect("parses");
        let err = m.constraints("vega-mc", DOCTYPE).expect_err("refuses");
        assert!(err.message.contains("outside the accepted range"), "{err}");
    }
}

// ─── resolve_salt (the issuance precedence; vc `resolveZkSaltBytes`) ────

#[test]
fn no_zk_systems_is_not_asking() {
    // A credential without zk_systems: its pin (normally none) is used
    // as-is; the catalog is never consulted.
    let r = resolve_salt(None, &[], DOCTYPE, 0).expect("resolves");
    assert_eq!(r.policy, SaltPolicy::DefaultSizing);
    assert!(!r.catalog_resolved);

    let r = resolve_salt(None, &[], DOCTYPE, 32).expect("resolves");
    assert_eq!(r.policy, SaltPolicy::Fixed(32));
}

#[test]
fn catalog_resolves_the_salt_length() {
    let m = manifest();
    let r = resolve_salt(Some(&m), &["vega-mc".to_owned()], DOCTYPE, 0).expect("resolves");
    assert_eq!(r.policy, SaltPolicy::Fixed(32));
    assert!(r.catalog_resolved);
}

#[test]
fn unconstrained_system_serves_default_sizing() {
    let m = manifest();
    let r = resolve_salt(Some(&m), &["longfellow".to_owned()], DOCTYPE, 0).expect("resolves");
    assert_eq!(r.policy, SaltPolicy::DefaultSizing);
}

#[test]
fn multiple_systems_agreeing_resolve() {
    let m = manifest();
    // vega-mc says 32; longfellow states no constraint — compatible.
    let r = resolve_salt(
        Some(&m),
        &["vega-mc".to_owned(), "longfellow".to_owned()],
        DOCTYPE,
        0,
    )
    .expect("resolves");
    assert_eq!(r.policy, SaltPolicy::Fixed(32));
}

#[test]
fn pin_stands_in_when_no_catalog_is_configured() {
    let r = resolve_salt(None, &["vega-mc".to_owned()], DOCTYPE, 32).expect("pin stands in");
    assert_eq!(r.policy, SaltPolicy::Fixed(32));
    assert!(r.pin_stood_in_for_unavailable);
    assert!(!r.pin_overrode_catalog);

    // Without a pin and without a catalog: REFUSE — minting a guess
    // fails opaquely in the wallet's hands at presentation time.
    let err = resolve_salt(None, &["vega-mc".to_owned()], DOCTYPE, 0).expect_err("refuses");
    assert_eq!(err.code, code::CONFIGURATION);
}

#[test]
fn pin_stands_in_for_a_system_not_published_yet() {
    let m = manifest();
    // vega-mc exists but the manifest has never carried vega-mc-next.
    let r =
        resolve_salt(Some(&m), &["vega-mc-next".to_owned()], DOCTYPE, 32).expect("pin stands in");
    assert_eq!(r.policy, SaltPolicy::Fixed(32));
    assert!(r.pin_stood_in_for_unavailable);
}

#[test]
fn pin_never_overrides_a_live_refusal() {
    let m: CircuitManifest = serde_json::from_value(json!({
        "circuits": [{
            "id": "deprecated-only",
            "system": "vega-mc",
            "docTypes": [DOCTYPE],
            "published": true,
            "status": "deprecated",
            "params": { "saltBytes": 32 }
        }]
    }))
    .expect("parses");
    // The catalog knows vega-mc but has withdrawn it: a live refusal —
    // the pin must NOT stand in (it would sign a credential the
    // catalog just said must not be issued).
    let err = resolve_salt(Some(&m), &["vega-mc".to_owned()], DOCTYPE, 32)
        .expect_err("a withdrawal is a live refusal");
    assert_eq!(err.code, code::CATALOG_INVALID);
    assert!(err.message.contains("no active circuit"), "{err}");
}

#[test]
fn pin_disagreeing_with_the_live_answer_wins_but_not_quietly() {
    let m = manifest();
    let r = resolve_salt(Some(&m), &["vega-mc".to_owned()], DOCTYPE, 16).expect("the pin wins");
    // The pin wins (air-gapped / interop deployments)…
    assert_eq!(r.policy, SaltPolicy::Fixed(16));
    // …but the disagreement is reported, never quiet.
    assert!(r.pin_overrode_catalog);
    assert!(r.catalog_resolved);
}

#[test]
fn param_key_is_the_published_name() {
    // The constraint key is "saltBytes" — the name the catalog
    // publishes; nothing here invents a private spelling.
    assert_eq!(PARAM_SALT_BYTES, "saltBytes");
}
