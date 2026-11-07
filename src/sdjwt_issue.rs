//! SD-JWT VC issuance (dc+sd-jwt): disclosure construction and signing.
//!
//! Ported from siros-verifier-core's `src/testutil.rs` (BSD-2-Clause, SIROS
//! Foundation) — the same primitives its tests use to issue credentials, so
//! verifier-compatible output is guaranteed by construction rather than by
//! re-implementation. Production differences: this crate's error type, and
//! claims (`iss`, `iat`, `exp`, `vct`, `status`, …) are supplied by the
//! caller in `IssueSpec::claims`; this module adds no claims of its own.
//!
//! Selective disclosure per SD-JWT VC: concealed claims move into
//! `_<digest>` disclosures, digests land in the parent's `_sd` array
//! (sorted), and the holder key (OID4VCI proof) becomes `cnf.jwk`.

use crate::error::{code, Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use jose_rs::jwk::Jwk;

use jose_rs::JoseHeader;
use serde_json::{json, Value};
use siros_verifier_core::sdjwt::HashAlg;

pub fn b64u(data: &[u8]) -> String {
    B64U.encode(data)
}

pub fn b64u_decode(data: &str) -> Result<Vec<u8>> {
    B64U.decode(data)
        .map_err(|e| Error::invalid_input(format!("base64url decode: {e}")))
}

/// A path segment into the claims tree.
#[derive(Clone, Debug)]
pub enum Seg {
    Key(String),
    Idx(usize),
}

/// What to issue. `claims` must already carry the registered claims
/// (`iss`, `iat`, `exp`, `vct`, optionally `status`); `conceal` selects
/// which claims become disclosures.
#[derive(Clone, Debug)]
pub struct IssueSpec {
    pub claims: Value,
    /// Paths to conceal. Parents and children may both be listed.
    pub conceal: Vec<Vec<Seg>>,
    pub decoys: usize,
    pub hash: HashAlg,
    pub holder_pub: Option<Jwk>,
    pub x5c_der: Vec<Vec<u8>>,
    pub typ: &'static str,
}

impl IssueSpec {
    pub fn new(claims: Value) -> Self {
        Self {
            claims,
            conceal: vec![],
            decoys: 0,
            hash: HashAlg::Sha256,
            holder_pub: None,
            x5c_der: vec![],
            typ: "dc+sd-jwt",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Issued {
    pub jwt: String,
    /// Raw disclosure strings in creation order (children before parents).
    pub disclosures: Vec<String>,
}

/// The complete SD-JWT serialization: `jwt~d1~d2…~` — a trailing `~`
/// terminates the SD-JWT (the KB-JWT would follow it; key binding is the
/// holder's, created at presentation time). SD-JWT VC §4 / the
/// verifier's split().
impl Issued {
    pub fn presentation(&self) -> String {
        let mut s = self.jwt.clone();
        s.push('~');
        for disclosure in &self.disclosures {
            s.push_str(disclosure);
            s.push('~');
        }
        s
    }
}

fn salt() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b)
        .map_err(|e| Error::new(code::TRANSPORT, format!("OS randomness: {e}")))?;
    Ok(b64u(&b))
}

fn navigate<'a>(root: &'a mut Value, path: &[Seg]) -> Result<&'a mut Value> {
    let mut cur = root;
    for seg in path {
        cur = match seg {
            Seg::Key(k) => cur
                .get_mut(k.as_str())
                .ok_or_else(|| Error::invalid_input(format!("conceal path key {k} missing")))?,
            Seg::Idx(i) => cur
                .get_mut(*i)
                .ok_or_else(|| Error::invalid_input(format!("conceal path index {i} missing")))?,
        };
    }
    Ok(cur)
}

/// Issue an SD-JWT. Conceals (deepest paths first), adds decoys, binds the
/// holder key, and signs with the issuer JWK.
pub fn issue(signer: &dyn crate::signer::Signer, spec: &IssueSpec) -> Result<Issued> {
    let mut claims = spec.claims.clone();
    let mut disclosures = Vec::new();

    let mut paths = spec.conceal.clone();
    paths.sort_by_key(|p| std::cmp::Reverse(p.len()));
    for path in &paths {
        let (last, parent_path) = path
            .split_last()
            .ok_or_else(|| Error::invalid_input("empty conceal path"))?;
        let parent = navigate(&mut claims, parent_path)?;
        match last {
            Seg::Key(name) => {
                let obj = parent
                    .as_object_mut()
                    .ok_or_else(|| Error::invalid_input("conceal parent is not an object"))?;
                let value = obj.remove(name.as_str()).ok_or_else(|| {
                    Error::invalid_input(format!("claim {name} to conceal missing"))
                })?;
                let raw = b64u(
                    serde_json::to_string(&json!([salt()?, name, value]))
                        .map_err(|e| Error::invalid_input(e.to_string()))?
                        .as_bytes(),
                );
                let digest = spec.hash.digest_b64u(raw.as_bytes());
                obj.entry("_sd")
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
                    .ok_or_else(|| Error::invalid_input("_sd is not an array"))?
                    .push(json!(digest));
                disclosures.push(raw);
            }
            Seg::Idx(i) => {
                let arr = parent
                    .as_array_mut()
                    .ok_or_else(|| Error::invalid_input("conceal parent is not an array"))?;
                let value = arr
                    .get(*i)
                    .cloned()
                    .ok_or_else(|| Error::invalid_input("conceal index out of bounds"))?;
                let raw = b64u(
                    serde_json::to_string(&json!([salt()?, value]))
                        .map_err(|e| Error::invalid_input(e.to_string()))?
                        .as_bytes(),
                );
                let digest = spec.hash.digest_b64u(raw.as_bytes());
                arr[*i] = json!({ "...": digest });
                disclosures.push(raw);
            }
        }
    }

    let top = claims
        .as_object_mut()
        .ok_or_else(|| Error::invalid_input("claims must be an object"))?;
    for _ in 0..spec.decoys {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b)
            .map_err(|e| Error::new(code::TRANSPORT, format!("OS randomness: {e}")))?;
        top.entry("_sd")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| Error::invalid_input("_sd is not an array"))?
            .push(json!(spec.hash.digest_b64u(&b)));
    }
    if let Some(sd) = top.get_mut("_sd").and_then(Value::as_array_mut) {
        sd.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    }
    if spec.hash != HashAlg::Sha256 {
        top.insert("_sd_alg".into(), json!(spec.hash.name()));
    }
    if let Some(holder) = &spec.holder_pub {
        let mut public = holder.to_public_jwk();
        public.alg = None;
        top.insert("cnf".into(), json!({ "jwk": public }));
    }

    let mut header = JoseHeader::new("ES256");
    header.typ = Some(spec.typ.to_owned());
    header.kid = signer.public_jwk()?.kid.clone();
    if !spec.x5c_der.is_empty() {
        header.x5c = Some(
            spec.x5c_der
                .iter()
                .map(|d| base64::engine::general_purpose::STANDARD.encode(d))
                .collect(),
        );
    }
    let payload = serde_json::to_vec(&claims)
        .map_err(|e| Error::invalid_input(format!("claims serialize: {e}")))?;
    let jwt = signer.sign_es256(&header, &payload)?;
    Ok(Issued { jwt, disclosures })
}

/// RFC 7638 thumbprint of an EC public JWK: the PDP subject id for
/// client-assertion keys (design §6.1, §11).
pub fn jwk_thumbprint(jwk: &Jwk) -> Result<String> {
    let public = jwk.to_public_jwk();
    let canonical = json!({
        "crv": public.crv,
        "kty": public.kty,
        "x": public.x,
        "y": public.y,
    });
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|e| Error::invalid_input(format!("thumbprint serialize: {e}")))?;
    use sha2::{Digest, Sha256};
    Ok(b64u(&Sha256::digest(bytes)))
}

/// Standard (padded) base64 decode — the x5c header convention.
pub fn b64_decode_std(data: &str) -> Result<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data)
        .map_err(|e| Error::invalid_input(format!("base64 decode: {e}")))
}
