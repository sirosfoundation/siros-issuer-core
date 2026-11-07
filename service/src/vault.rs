//! Sealed subject-data vault (design §6.3). AES-256-GCM with a per-process
//! key: claims arrive over the authenticated S2S channel and are sealed
//! before touching storage, deleted on final states, purge on `DELETE`,
//! and never logged. A restart loses only *pending* sealed sessions — an
//! acceptable dev/one-process posture for P1; MongoDB + a persisted key
//! follows with the production store (design §16.1 D1).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use serde_json::Value;
use siros_issuer_core::error::code;
use siros_issuer_core::{Error, Result};

pub struct Vault {
    cipher: Aes256Gcm,
}

impl Vault {
    pub fn new() -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)
            .map_err(|e| Error::new(code::TRANSPORT, format!("OS randomness: {e}")))?;
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(&key)
                .map_err(|_| Error::new(code::TRANSPORT, "vault key"))?,
        })
    }

    /// Seal a claims object. The AAD binds the session id: sealed bytes are
    /// only unsealable by and for that session.
    pub fn seal(&self, session_id: &str, claims: &Value) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce)
            .map_err(|e| Error::new(code::TRANSPORT, format!("OS randomness: {e}")))?;
        let plaintext =
            serde_json::to_vec(claims).map_err(|e| Error::invalid_input(e.to_string()))?;
        let sealed = self
            .cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: session_id.as_bytes(),
                },
            )
            .map_err(|_| Error::new(code::TRANSPORT, "vault encryption failed"))?;
        let mut out = Vec::with_capacity(nonce.len() + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn unseal(&self, session_id: &str, sealed: &[u8]) -> Result<Value> {
        if sealed.len() < 12 + 16 {
            return Err(Error::invalid_input("sealed data truncated"));
        }
        let (nonce, ct) = sealed.split_at(12);
        let nonce: [u8; 12] = nonce
            .try_into()
            .map_err(|_| Error::invalid_input("sealed nonce truncated"))?;
        let plaintext = self
            .cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: ct,
                    aad: session_id.as_bytes(),
                },
            )
            .map_err(|_| Error::new(code::TRANSPORT, "vault decryption failed"))?;
        serde_json::from_slice(&plaintext).map_err(|e| Error::invalid_input(e.to_string()))
    }
}
