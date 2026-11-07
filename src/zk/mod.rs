//! The ZK capability layer (design §8.3).
//!
//! General, rulebook-driven machinery: seeds, commitments, and the
//! IssuerSignedItem salt policy. `nym_auth` is the first rulebook built on
//! these; a second rulebook must require only a new module against these
//! traits, never changes inside them.
//!
//! The salt policy translates verbatim from vc's `zkcircuit` semantics:
//! `SaltPolicy::default_sizing` sizes salts per element (16 bytes, 8 for
//! the 32-byte `pseudonym_seed` value, per zk-cred-longfellow's total-item
//! ceiling); a rulebook that names zk systems resolves a pinned length from
//! the circuit catalog instead — fail-closed on a catalog that cannot
//! answer, and never letting a pin override a live refusal.

pub mod circuit;

use crate::error::{code, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub use circuit::{
    resolve_salt, CircuitDescriptor, CircuitManifest, SaltResolution, SystemConstraints,
    PARAM_SALT_BYTES, STATUS_ACTIVE,
};

/// The lower and upper bounds a catalog-published salt length may take
/// (vc `zkcircuit.MinSaltBytes`/`MaxSaltBytes`).
pub const MIN_SALT_BYTES: usize = 8;
pub const MAX_SALT_BYTES: usize = 64;

/// The per-element default salt lengths (vc `mso.WithSaltBytes(0)`):
/// 16 bytes for a claim, 8 for the 32-byte `pseudonym_seed` value, whose
/// size plus a 16-byte salt would blow zk-cred-longfellow's ~119-byte
/// total IssuerSignedItem ceiling.
pub const DEFAULT_SALT_BYTES: usize = 16;
pub const PSEUDONYM_SEED_SALT_BYTES: usize = 8;

/// How an IssuerSignedItem salt is sized (design §8.3 item 1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaltPolicy {
    /// Per-element sizing: 16 bytes, 8 for `pseudonym_seed`.
    #[default]
    DefaultSizing,
    /// Every element's salt is exactly this many bytes (a catalog-pinned
    /// length — e.g. zk-cred-vega's 32, whose circuit hardcodes the byte
    /// offset of the digestID/element fields on that assumption).
    Fixed(#[serde(default)] usize),
}

impl SaltPolicy {
    /// The salt length for one element under this policy.
    pub fn salt_bytes_for(&self, element_id: &str) -> Result<usize> {
        match self {
            SaltPolicy::DefaultSizing => Ok(if element_id == "pseudonym_seed" {
                PSEUDONYM_SEED_SALT_BYTES
            } else {
                DEFAULT_SALT_BYTES
            }),
            SaltPolicy::Fixed(n) => {
                // Enforced here rather than trusting config validation
                // alone, mirroring vc's builder-side check: a Fixed(0)
                // would silently mean "default" in vc's encoding, and a
                // value out of range mints credentials no circuit verifies.
                if *n < MIN_SALT_BYTES || *n > MAX_SALT_BYTES {
                    return Err(Error::invalid_input(format!(
                        "salt length {n} outside [{MIN_SALT_BYTES}, {MAX_SALT_BYTES}]"
                    )));
                }
                Ok(*n)
            }
        }
    }
}

/// A hash commitment (design §8.3 item 3): SHA-256 of the opening.
pub fn hash_commitment(alg: &str, opening: &[u8]) -> Result<Vec<u8>> {
    if opening.is_empty() {
        return Err(Error::invalid_input(
            "hash_commitment: the opening is empty",
        ));
    }
    match alg {
        "sha-256" => Ok(Sha256::digest(opening).to_vec()),
        other => Err(Error::invalid_input(format!(
            "auxiliary data: alg {other:?} is not sha-256"
        ))),
    }
}

/// How a to_wallet commitment opening is derived (vc `OpeningArgs`,
/// generalized; exactly one variant set).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Opening {
    /// HKDF-SHA256 (RFC 5869) keyed with a secret, over the input claim
    /// values in order (vc `HKDFOpeningArgs`).
    Hkdf {
        /// The secret: base64url, decoding to at least 32 bytes.
        secret_b64url: String,
        /// The source-claim names whose values feed the derivation, in
        /// order (part of the derivation).
        inputs: Vec<String>,
        /// The opening length in bytes, 16 to 64.
        bytes: usize,
    },
    /// A random opening (vc `RandomOpeningArgs`).
    Random { bytes: usize },
    /// The opening is a source claim's value: base64url, 16 to 64 bytes
    /// (vc `ClaimOpeningArgs`).
    Claim { input: String },
}

impl Opening {
    /// The domain-separation label (vc `keyedFunction.label()`).
    const HKDF_LABEL: &'static str = "vc/hash_commitment/hkdf/v1";

    /// Produce the opening from the source claims (the presented PID's
    /// claims in Mode B, or the session's subject data otherwise).
    pub fn open(&self, claims: &BTreeMap<String, serde_json::Value>) -> Result<Vec<u8>> {
        match self {
            Opening::Random { bytes } => {
                if *bytes < 16 || *bytes > 64 {
                    return Err(Error::invalid_input(
                        "random opening: bytes outside [16, 64]",
                    ));
                }
                let mut buf = vec![0u8; *bytes];
                getrandom::fill(&mut buf)
                    .map_err(|e| Error::new(code::TRANSPORT, format!("OS randomness: {e}")))?;
                Ok(buf)
            }
            Opening::Claim { input } => {
                let value = claims
                    .get(input.as_str())
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        Error::invalid_input(format!(
                            "claim opening: source claim {input:?} missing or not text"
                        ))
                    })?;
                let bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    value,
                )
                .map_err(|_| Error::invalid_input("claim opening: not base64url"))?;
                if bytes.len() < 16 || bytes.len() > 64 {
                    return Err(Error::invalid_input(
                        "claim opening: decoded length outside [16, 64]",
                    ));
                }
                Ok(bytes)
            }
            Opening::Hkdf {
                secret_b64url,
                inputs,
                bytes,
            } => {
                if *bytes < 16 || *bytes > 64 {
                    return Err(Error::invalid_input("hkdf opening: bytes outside [16, 64]"));
                }
                let secret = base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    secret_b64url,
                )
                .map_err(|_| Error::invalid_input("hkdf opening: secret not base64url"))?;
                if secret.len() < 32 {
                    return Err(Error::invalid_input(
                        "hkdf opening: secret decodes under 32 bytes",
                    ));
                }
                // Message: label, length in decimal, then each input value,
                // each field two-byte-big-endian-length-prefixed (vc
                // `appendField`) so no concatenation of distinct values
                // can collide.
                let mut message = Vec::new();
                append_field(&mut message, Self::HKDF_LABEL);
                append_field(&mut message, &bytes.to_string());
                for input in inputs {
                    let value = claims
                        .get(input.as_str())
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            Error::invalid_input(format!(
                                "hkdf opening: input claim {input:?} missing or not text"
                            ))
                        })?;
                    append_field(&mut message, value);
                }
                let mut okm = vec![0u8; *bytes];
                hkdf::Hkdf::<Sha256>::new(None, &secret)
                    .expand(&message, &mut okm)
                    .map_err(|_| Error::invalid_input("hkdf opening: expand"))?;
                Ok(okm)
            }
        }
    }
}

/// vc `appendField`: two-byte length prefix, then the field bytes.
fn append_field(message: &mut Vec<u8>, field: &str) {
    let len = u16::try_from(field.len()).unwrap_or(u16::MAX);
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(field.as_bytes());
}

/// One auxiliary-data entry (vc `AuxiliaryDataEntry`, generalized). `type`
/// is fixed at `hash_commitment` — the one type the extension defines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuxiliaryDataEntry {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: String,
    pub path: Vec<String>,
    /// Set in a to_issuer entry the wallet sends (its commitment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    /// Set in a to_wallet entry the issuer returns (its opening).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opening: Option<String>,
    /// to_issuer: the wallet MUST send a commitment for this path.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    /// How the claim at Path carries the commitment in the credential:
    /// "base64url", "base64" or "hex".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

/// Encode a commitment for the credential claim at Path (vc
/// `EncodeCommitment`).
pub fn encode_commitment(encoding: &str, commitment: &[u8]) -> Result<String> {
    match encoding {
        "base64url" => Ok(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            commitment,
        )),
        "base64" => Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            commitment,
        )),
        "hex" => Ok(hex(commitment)),
        other => Err(Error::invalid_input(format!(
            "auxiliary data encoding {other:?} is none of base64url, base64, hex"
        ))),
    }
}

/// Decode a commitment the wallet sent (base64url; the to_issuer shape).
pub fn decode_commitment(value: &str) -> Result<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, value)
        .map_err(|_| Error::invalid_input("wallet commitment not base64url"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            bytes: 32,
        }
        .open(&claims)
        .unwrap();
        let o2 = Opening::Hkdf {
            secret_b64url: secret,
            inputs: vec!["b".to_owned(), "a".to_owned()],
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
}
