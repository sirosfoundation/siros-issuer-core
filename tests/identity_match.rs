//! IdentityMatch semantics (design §6.5 v2) — a faithful port check of
//! vc's `pkg/openid4vci/identity_match.go` + `lookupClaimPath` +
//! `claimValueMatches`. The source of truth is vc's rule discipline and
//! format-aware path resolution (Appendix A of the design doc); every
//! expected value here is from that contract, never from the
//! implementation.

use serde_json::json;
use siros_issuer_core::oid4vci::{ClaimTest, IdentityMatch};

fn rule(pairs: &[(&str, &str)]) -> IdentityMatch {
    IdentityMatch {
        claims: pairs
            .iter()
            .map(|(path, equals)| {
                (
                    (*path).to_owned(),
                    ClaimTest {
                        equals: (*equals).to_owned(),
                    },
                )
            })
            .collect(),
    }
}

fn claims() -> serde_json::Value {
    json!({
        "given_name": "Presented",
        "family_name": "Subject",
        "identity": { "birthdate": "1999-12-31", "number": "19990101-0000" },
        "org.iso.18013.5.1.birth_date": "1999-12-31",
        "roles": ["admin", "signatory"],
    })
}

#[test]
fn validate_refuses_rules_that_cannot_do_their_job() {
    // Empty: refused — "a rule that matches anything" is not a rule
    // (vc Validate).
    assert!(IdentityMatch {
        claims: Default::default()
    }
    .validate()
    .is_err());
    // Empty path refused.
    assert!(rule(&[("", "x")]).validate().is_err());
    // Whitespace-only path refused.
    assert!(rule(&[("  ", "x")]).validate().is_err());
    // Empty equals refused (the only comparison may not be empty).
    assert!(rule(&[("given_name", "")]).validate().is_err());
    // A well-formed rule validates.
    rule(&[("given_name", "Presented")]).validate().unwrap();
}

#[test]
fn claim_paths_are_stable_ordered() {
    let r = rule(&[("b.claim", "1"), ("a.claim", "2")]);
    assert_eq!(r.claim_paths(), vec!["a.claim", "b.claim"]);
}

#[test]
fn exact_string_claims_match_and_mismatch() {
    let r = rule(&[("given_name", "Presented"), ("family_name", "Subject")]);
    assert!(r.matches(&claims(), false).unwrap());
    let wrong = rule(&[("given_name", "presented")]);
    assert!(
        !wrong.matches(&claims(), false).unwrap(),
        "exact, deliberately not case-folded (vc's rationale: folding a personal name is locale-dependent)"
    );
}

#[test]
fn absent_claim_is_a_mismatch_never_a_skip() {
    let r = rule(&[("not_present", "anything")]);
    assert!(!r.matches(&claims(), false).unwrap());
}

#[test]
fn nested_paths_walk_objects_for_sd_jwt() {
    let r = rule(&[("identity.birthdate", "1999-12-31")]);
    assert!(r.matches(&claims(), false).unwrap());
    let wrong = rule(&[("identity.birthdate", "2000-01-01")]);
    assert!(!wrong.matches(&claims(), false).unwrap());
}

#[test]
fn sd_jwt_does_not_take_a_flat_dotted_key_for_a_nested_path() {
    // vc lookupClaimPath: for SD-JWT the literal fallback is
    // intentionally skipped, so a flat "identity.number" key cannot
    // satisfy a nested "identity.number" requirement.
    let value = json!({ "identity.number": "19990101-0000" });
    let r = rule(&[("identity.number", "19990101-0000")]);
    assert!(!r.matches(&value, false).unwrap());
}

#[test]
fn mdoc_takes_the_literal_namespace_qualified_key_first() {
    let r = rule(&[("org.iso.18013.5.1.birth_date", "1999-12-31")]);
    assert!(r.matches(&claims(), true).unwrap());
    // The same path with the is_mdoc shape OFF walks segments and finds
    // nothing (the flat key is not nested objects).
    assert!(!r.matches(&claims(), false).unwrap());
}

#[test]
fn array_claims_match_when_any_element_equals() {
    let r = rule(&[("roles", "signatory")]);
    assert!(r.matches(&claims(), false).unwrap());
    let wrong = rule(&[("roles", "auditor")]);
    assert!(!wrong.matches(&claims(), false).unwrap());
}

#[test]
fn non_string_scalars_do_not_satisfy_a_string_rule() {
    let value = json!({ "age": 42, "active": true, "nested": {"a": 1} });
    assert!(!rule(&[("age", "42")]).matches(&value, false).unwrap());
    assert!(!rule(&[("active", "true")]).matches(&value, false).unwrap());
    assert!(!rule(&[("nested", "anything")])
        .matches(&value, false)
        .unwrap());
}

#[test]
fn every_entry_must_pass() {
    let r = rule(&[("given_name", "Presented"), ("family_name", "Wrong")]);
    assert!(!r.matches(&claims(), false).unwrap());
}
