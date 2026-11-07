//! The circuit catalog (design §8.3 item 1): the source of truth for the
//! issuance parameters ZK proof systems require — today the
//! `IssuerSignedItem` salt length, tomorrow whatever a new system
//! publishes. A property of the **circuit build**, not of any credential
//! schema: zk-cred-vega bakes its digest-ID byte offset into the R1CS at
//! setup time, and a credential whose salt is any other length shifts
//! every field out of position and fails verification opaquely in the
//! wallet's hands at presentation time.
//!
//! General by construction: circuits belong to **systems** (vega-mc,
//! longfellow, …), scope themselves to doctypes, and publish params.
//! Nothing here knows a rulebook or a credential; the manifest answers
//! `(system, doctype) → constraints`, fail-closed in every direction.
//!
//! Resolution semantics are vc's `zkcircuit`/`zk_salt.go` ported verbatim:
//! unknown-system ≠ no-active-circuit ≠ catalog-unavailable (only the
//! first two may be pinned over — a pin never overrides a live
//! refusal); active circuits that disagree refuse rather than pick; a
//! param that is present but unreadable is a constraint nobody can
//! honour, not an absent one.

use crate::error::{code, Error, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

use super::{MAX_SALT_BYTES, MIN_SALT_BYTES};

/// The catalog params key carrying the required salt length (vc
/// `zkcircuit.ParamSaltBytes`; published as `"32"` by vega-mc, `32` by
/// others — both shapes parse).
pub const PARAM_SALT_BYTES: &str = "saltBytes";

/// The only status an issuer may build for (vc `StatusActive`): a
/// deprecated circuit's constraints describe credentials that should no
/// longer be minted.
pub const STATUS_ACTIVE: &str = "active";

/// One circuit in the manifest (vc `CircuitDescriptor`, field-for-field).
/// `params` is deliberately loosely typed — format-specific meta
/// (`version`, `num_attributes`, `circuit_hash`) varies in JSON shape;
/// read it through [`CircuitDescriptor::param_int`] etc., never directly.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitDescriptor {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// The proof system this circuit belongs to (e.g. "vega-mc",
    /// "longfellow") — the general key, never a credential name.
    #[serde(default)]
    pub system: String,
    #[serde(default)]
    pub system_version: String,
    /// The doctypes this circuit serves. An entry declaring none is NOT
    /// assumed to apply to every doctype — it is skipped (an unscoped
    /// circuit is a catalog that has not said what it is for).
    #[serde(default)]
    pub doc_types: Vec<String>,
    #[serde(default)]
    pub published: bool,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub params: BTreeMap<String, serde_json::Value>,
}

impl CircuitDescriptor {
    /// Read a numeric params entry as `usize`. Returns `None` if the key
    /// is absent, not numeric, not integral, or outside range — all
    /// shapes that would otherwise truncate a remote value into a
    /// nonsense length. A decimal *string* holding an integer is
    /// accepted (the live catalog publishes both spellings); `"32.0"`,
    /// `"0x20"`, `" 32 "` and `""` are all refused.
    pub fn param_int(&self, key: &str) -> Option<usize> {
        match self.params.get(key)? {
            serde_json::Value::Number(n) => n.as_u64().map(|v| v as usize),
            serde_json::Value::String(s) => s.parse::<usize>().ok(),
            _ => None,
        }
    }

    /// Whether `key` is present at all, whatever shape its value has —
    /// including JSON null. The companion to `param_int`: absent means
    /// no constraint, malformed means a constraint nobody can honour,
    /// and reading the second as the first fails open.
    pub fn has_param(&self, key: &str) -> bool {
        self.params.contains_key(key)
    }

    fn declares_doctype(&self, doctype: &str) -> bool {
        self.doc_types.iter().any(|d| d == doctype)
    }
}

/// The manifest a circuit source serves: the catalog's published
/// circuits. Systems and constraints are derived; the file is data.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CircuitManifest {
    #[serde(default)]
    pub circuits: Vec<CircuitDescriptor>,
}

impl CircuitManifest {
    /// The published, active circuits for `system` serving `doctype`, in
    /// manifest order (vc `ActiveCircuits`: unscoped entries are skipped,
    /// never assumed to apply to every doctype).
    pub fn active_circuits(&self, system: &str, doctype: &str) -> Vec<&CircuitDescriptor> {
        self.circuits
            .iter()
            .filter(|c| {
                c.published
                    && c.status == STATUS_ACTIVE
                    && c.system.eq_ignore_ascii_case(system)
                    && c.declares_doctype(doctype)
            })
            .collect()
    }

    /// Whether the manifest carries any circuit naming `system` at all —
    /// under any status, published flag, or doctype. Separates "the
    /// catalog has never carried this system" (not published yet — a pin
    /// may stand in) from a withdrawal (all deprecated, unpublished, or
    /// scoped elsewhere — a live refusal).
    pub fn knows_system(&self, system: &str) -> bool {
        self.circuits
            .iter()
            .any(|c| c.system.eq_ignore_ascii_case(system))
    }

    /// Resolve one system's wire-shape constraints for `doctype` (vc
    /// `Manifest.Constraints`, verbatim): active circuits that disagree
    /// with each other refuse rather than pick; a `saltBytes` that is
    /// present but unreadable is refused rather than treated as no
    /// constraint; a salt length outside `[8, 64]` is refused (it is read
    /// from a remote source and reaches `vec![0u8; n]` in every issued
    /// credential).
    pub fn constraints(&self, system: &str, doctype: &str) -> Result<SystemConstraints> {
        let circuits = self.active_circuits(system, doctype);
        if circuits.is_empty() {
            if !self.knows_system(system) {
                return Err(Error::new(
                    code::CATALOG_INVALID,
                    format!("unknown zk system {system:?} — the circuit catalog carries no circuit naming it"),
                ));
            }
            return Err(Error::new(
                code::CATALOG_INVALID,
                format!("no active circuit for zk system {system:?} and doctype {doctype:?}"),
            ));
        }

        let mut resolved = SystemConstraints {
            system: system.to_owned(),
            circuit_ids: circuits.iter().map(|c| c.id.clone()).collect(),
            salt_bytes: 0,
        };
        // Which circuit each distinct salt value came from (a disagreement
        // is reported as the catalog inconsistency it is) and which
        // circuits publish none at all (a constraint of its own).
        let mut salt_from: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        let mut unconstrained: Vec<String> = Vec::new();

        for circuit in circuits {
            match circuit.param_int(PARAM_SALT_BYTES) {
                Some(salt) => {
                    if !(MIN_SALT_BYTES..=MAX_SALT_BYTES).contains(&salt) {
                        return Err(Error::new(
                            code::CATALOG_INVALID,
                            format!(
                                "circuit {:?} publishes {PARAM_SALT_BYTES} {salt}, outside the accepted range [{MIN_SALT_BYTES}, {MAX_SALT_BYTES}]",
                                circuit.id
                            ),
                        ));
                    }
                    salt_from.entry(salt).or_default().push(circuit.id.clone());
                }
                None => {
                    if circuit.has_param(PARAM_SALT_BYTES) {
                        // Present but unreadable — a constraint nobody can
                        // honour, never an absent one (fails open if read
                        // the other way).
                        return Err(Error::new(
                            code::CATALOG_INVALID,
                            format!(
                                "circuit {:?} publishes {PARAM_SALT_BYTES} as {:?}, which is not an integer — refusing rather than treating it as no constraint",
                                circuit.id, circuit.params.get(PARAM_SALT_BYTES)
                            ),
                        ));
                    }
                    // Genuinely absent: this circuit states no salt
                    // constraint (legitimate — longfellow publishes
                    // none) — recorded, and the refusal below applies
                    // when it mixes with circuits that do.
                    unconstrained.push(circuit.id.clone());
                }
            }
        }

        match salt_from.len() {
            0 => {
                // No active circuit publishes a length: the system states
                // no salt constraint (default per-element sizing serves
                // it). salt_bytes stays 0 — "no constraint", NOT "zero
                // bytes".
                Ok(resolved)
            }
            1 => {
                let (salt, ids) = salt_from.iter().next().expect("len checked == 1");
                if !unconstrained.is_empty() {
                    // Naming systems is only meaningful while they agree:
                    // one credential carries one salt per item, so a
                    // constrained and an unconstrained circuit for the
                    // same system+doctype is an inconsistency the catalog
                    // must resolve, not the issuer.
                    return Err(Error::new(
                        code::CATALOG_INVALID,
                        format!(
                            "zk system {system:?} has circuits publishing {PARAM_SALT_BYTES} {salt} ({ids:?}) and circuits publishing none ({unconstrained:?}) — refusing rather than picking"
                        ),
                    ));
                }
                resolved.salt_bytes = *salt;
                Ok(resolved)
            }
            _ => {
                let detail: Vec<String> = salt_from
                    .iter()
                    .map(|(salt, ids)| format!("{salt} from {ids:?}"))
                    .collect();
                Err(Error::new(
                    code::CATALOG_INVALID,
                    format!(
                        "active circuits for zk system {system:?} and doctype {doctype:?} disagree on {PARAM_SALT_BYTES}: {} — refusing rather than picking",
                        detail.join(", ")
                    ),
                ))
            }
        }
    }
}

/// What the catalog publishes about one system's active circuits (vc
/// `SystemConstraints`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemConstraints {
    pub system: String,
    pub circuit_ids: Vec<String>,
    /// The required salt length, or 0 = the system states no salt
    /// constraint (NOT "zero bytes").
    pub salt_bytes: usize,
}

/// The outcome of resolving the salt policy for one issuance: the
/// policy, plus the diagnostics the caller logs (a pin overriding a
/// catalog answer — or standing in for an unreachable one — must never
/// win quietly; vc `zk_salt.go` logs both at error).
#[derive(Debug)]
pub struct SaltResolution {
    pub policy: super::SaltPolicy,
    /// The pin won against the catalog's live, different answer.
    pub pin_overrode_catalog: bool,
    /// The pin stood in for a catalog that could not answer
    /// (unreachable, or system not published yet).
    pub pin_stood_in_for_unavailable: bool,
    /// The catalog answered with the pin agreeing.
    pub catalog_resolved: bool,
}

/// Resolve the salt policy for one credential's zk systems (vc
/// `resolveZkSaltBytes`, verbatim precedence):
///
/// 1. No zk systems declared → the credential is not asking; its pinned
///    value (normally none) is used as-is.
/// 2. Otherwise the catalog is the source of truth.
/// 3. A pin stands in only for a catalog that cannot answer — the system
///    is not published at all, or the catalog is unreachable. A catalog
///    that answers with a refusal (withdrawn circuit, constraint
///    disagreement, malformed metadata) is a live refusal and the pin
///    NEVER overrides it: a credential minted against it fails opaquely
///    in the wallet's hands.
/// 4. A pin that disagrees with a live catalog answer still wins (it is
///    for air-gapped and interop deployments) — but the disagreement is
///    reported, never quiet.
pub fn resolve_salt(
    manifest: Option<&CircuitManifest>,
    zk_systems: &[String],
    doctype: &str,
    pinned_salt_bytes: usize,
) -> Result<SaltResolution> {
    // 1. Not asking.
    if zk_systems.is_empty() {
        return Ok(SaltResolution {
            policy: pinned_policy(pinned_salt_bytes)?,
            pin_overrode_catalog: false,
            pin_stood_in_for_unavailable: false,
            catalog_resolved: false,
        });
    }

    // 2. No source configured at all: a real configuration (an issuer
    //    offering no ZK-provable mdoc never asks; an operator cut off
    //    from the network says so by configuring no sources and pinning).
    let Some(manifest) = manifest else {
        if pinned_salt_bytes != 0 {
            return Ok(SaltResolution {
                policy: pinned_policy(pinned_salt_bytes)?,
                pin_overrode_catalog: false,
                pin_stood_in_for_unavailable: true,
                catalog_resolved: false,
            });
        }
        return Err(Error::new(
            code::CONFIGURATION,
            format!(
                "credential {doctype:?} declares zk_systems {zk_systems:?} but no circuit catalog source is configured and no salt length is pinned"
            ),
        ));
    };

    // 3. Every declared system must answer, and agree (one credential
    //    carries one salt per item).
    let mut resolved: usize = 0;
    for system in zk_systems {
        // Distinguish the two ways a catalog can fail to serve a
        // system (vc `ErrUnknownSystem` vs `ErrNoActiveCircuit`): a
        // system the manifest has NEVER carried is "not published yet"
        // — a pin may stand in; a system it knows but has withdrawn,
        // unpublished, or scoped elsewhere is a live refusal.
        if !manifest.knows_system(system) {
            if pinned_salt_bytes != 0 {
                return Ok(SaltResolution {
                    policy: pinned_policy(pinned_salt_bytes)?,
                    pin_overrode_catalog: false,
                    pin_stood_in_for_unavailable: true,
                    catalog_resolved: false,
                });
            }
            return Err(Error::new(
                code::CONFIGURATION,
                format!(
                    "credential {doctype:?} declares zk_system {system:?} but the circuit catalog carries no circuit naming it and no salt length is pinned"
                ),
            ));
        }
        let constraints = manifest.constraints(system, doctype)?;
        if constraints.salt_bytes != 0 {
            if resolved != 0 && resolved != constraints.salt_bytes {
                return Err(Error::new(
                    code::CATALOG_INVALID,
                    format!(
                        "zk systems for {doctype:?} disagree on {PARAM_SALT_BYTES}: {resolved} vs {} — refusing rather than picking",
                        constraints.salt_bytes
                    ),
                ));
            }
            resolved = constraints.salt_bytes;
        }
    }

    // 4. The pin vs the live answer.
    if pinned_salt_bytes != 0 && resolved != 0 && pinned_salt_bytes != resolved {
        return Ok(SaltResolution {
            policy: pinned_policy(pinned_salt_bytes)?,
            pin_overrode_catalog: true,
            pin_stood_in_for_unavailable: false,
            catalog_resolved: true,
        });
    }

    let policy = if resolved != 0 {
        super::SaltPolicy::Fixed(resolved)
    } else {
        // No active circuit publishes a length: the systems state no salt
        // constraint — default per-element sizing serves them.
        super::SaltPolicy::DefaultSizing
    };
    Ok(SaltResolution {
        policy,
        pin_overrode_catalog: false,
        pin_stood_in_for_unavailable: false,
        catalog_resolved: true,
    })
}

fn pinned_policy(pinned: usize) -> Result<super::SaltPolicy> {
    if pinned == 0 {
        Ok(super::SaltPolicy::DefaultSizing)
    } else {
        Ok(super::SaltPolicy::Fixed(pinned))
    }
}
