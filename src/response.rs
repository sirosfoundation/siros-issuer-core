//! ECDHE-ES credential-response encryption (OpenID4VCI ID1 credential
//! response encryption; design §7.5).
//!
//! Ported from siros-verifier-core's `src/testutil.rs::encrypt_response`
//! (BSD-2-Clause, SIROS Foundation) — the same agreement and AES-GCM
//! primitives the verifier uses, so a credential response this crate
//! encrypts decrypts in the verifier's test wallet by construction.
//! The JWE protected header is `{alg: ECDH-ES, enc, kid?, epk}`; the
//! recipient is the wallet key from the credential request.

use crate::error::{code, Error, Result};
use crate::sdjwt_issue::{b64u, b64u_decode};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwk::Jwk;
use jose_rs::JoseHeader;

/// Encrypt `plaintext` to `recipient` and return the compact JWE.
pub fn encrypt_response(
    recipient: &Jwk,
    plaintext: &[u8],
    kid: Option<&str>,
    enc: JweEncryption,
) -> Result<String> {
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, enc);
    if let Some(kid) = kid {
        header.kid = Some(kid.to_owned());
    }
    let ephemeral = jose_rs::jwk::generate_ec("P-256")
        .map_err(|e| Error::new(code::TRANSPORT, format!("ephemeral key: {e}")))?;
    header.extra.insert(
        "epk".into(),
        serde_json::to_value(ephemeral.to_public_jwk())
            .map_err(|e| Error::invalid_input(e.to_string()))?,
    );
    let protected =
        b64u(&serde_json::to_vec(&header).map_err(|e| Error::invalid_input(e.to_string()))?);
    let own = jose_rs::jwk::agreement::agreement_key(&ephemeral)
        .map_err(|e| Error::new(code::TRANSPORT, format!("agreement key: {e}")))?;
    let peer = jose_rs::jwk::agreement::peer_key(recipient)
        .map_err(|e| Error::invalid_input(format!("recipient key: {e}")))?;
    let cek = own
        .derive_key(
            &peer,
            enc.as_str(),
            header.extra.get("apu").and_then(serde_json::Value::as_str),
            header.extra.get("apv").and_then(serde_json::Value::as_str),
            match enc {
                JweEncryption::A128GCM => 16,
                JweEncryption::A256GCM => 32,
                _ => return Err(Error::configuration("unsupported response enc")),
            },
        )
        .map_err(|e| Error::new(code::TRANSPORT, format!("key derivation: {e}")))?;

    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv)
        .map_err(|e| Error::new(code::TRANSPORT, format!("OS randomness: {e}")))?;
    let authenticated = match enc {
        JweEncryption::A128GCM => Aes128Gcm::new_from_slice(&cek)
            .map_err(|_| Error::invalid_input("invalid AES-128 key"))?
            .encrypt(
                &Nonce::from(iv),
                Payload {
                    msg: plaintext,
                    aad: protected.as_bytes(),
                },
            ),
        JweEncryption::A256GCM => Aes256Gcm::new_from_slice(&cek)
            .map_err(|_| Error::invalid_input("invalid AES-256 key"))?
            .encrypt(
                &Nonce::from(iv),
                Payload {
                    msg: plaintext,
                    aad: protected.as_bytes(),
                },
            ),
        _ => return Err(Error::configuration("unsupported response enc")),
    }
    .map_err(|_| Error::invalid_input("response encryption failed"))?;
    let split = authenticated
        .len()
        .checked_sub(16)
        .ok_or_else(|| Error::invalid_input("response authentication tag missing"))?;
    let (ciphertext, tag) = authenticated.split_at(split);
    Ok(format!(
        "{}.{}.{}.{}.{}",
        protected,
        "",
        b64u(&iv),
        b64u(ciphertext),
        b64u(tag)
    ))
}

/// Decrypt a credential/batch request the wallet sent as a JWE to our
/// advertised `credential_request_encryption` key (Final §8.2/§12.2.4):
/// same ECDH-ES + AES-GCM primitives as the response path, roles swapped.
pub fn decrypt_request(jwe: &str, our_key: &jose_rs::jwk::Jwk) -> Result<Vec<u8>> {
    decrypt_response(jwe, our_key)
}

/// The plain-text response is `{credential, c_nonce, c_nonce_expires_in,
/// (notification_id)}`; when the wallet requested encryption the whole
/// object is the JWE payload (OpenID4VCI ID1 §7.3).
pub fn decrypt_response(jwe: &str, recipient: &Jwk) -> Result<Vec<u8>> {
    // Test/support path: decrypt with the recipient's private key so
    // integration tests can read what the wallet would read. Kept here (not
    // only in tests) because the wallet-simulator contract lives beside the
    // encryption it must undo.
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(Error::invalid_input("JWE must have five parts"));
    }
    let header: JoseHeader = serde_json::from_slice(&b64u_decode(parts[0])?)
        .map_err(|e| Error::invalid_input(format!("JWE header: {e}")))?;
    let epk: Jwk = serde_json::from_value(
        header
            .extra
            .get("epk")
            .cloned()
            .ok_or_else(|| Error::invalid_input("JWE header has no epk"))?,
    )
    .map_err(|e| Error::invalid_input(format!("epk: {e}")))?;
    // The wallet-side support path: accept the key in signing form
    // (`alg: ES256`) and use it for what it is — an EC agreement key.
    let mut recipient = recipient.clone();
    recipient.alg = Some("ECDH-ES".to_owned());
    let own = jose_rs::jwk::agreement::agreement_key(&recipient)
        .map_err(|e| Error::invalid_input(format!("recipient key: {e}")))?;
    let peer = jose_rs::jwk::agreement::peer_key(&epk)
        .map_err(|e| Error::invalid_input(format!("epk: {e}")))?;
    let enc = JweEncryption::from_str(header.enc.as_deref().unwrap_or_default())
        .map_err(|_| Error::invalid_input("unsupported response enc"))?;
    let cek = own
        .derive_key(
            &peer,
            enc.as_str(),
            header.extra.get("apu").and_then(serde_json::Value::as_str),
            header.extra.get("apv").and_then(serde_json::Value::as_str),
            match enc {
                JweEncryption::A128GCM => 16,
                JweEncryption::A256GCM => 32,
                _ => return Err(Error::configuration("unsupported response enc")),
            },
        )
        .map_err(|e| Error::new(code::TRANSPORT, format!("key derivation: {e}")))?;
    let iv = b64u_decode(parts[2])?;
    let ciphertext = b64u_decode(parts[3])?;
    let tag = b64u_decode(parts[4])?;
    // Compact JWE carries ciphertext and tag as separate parts; aes-gcm
    // authenticates them concatenated (RFC 7516 §5.2/§5.3).
    let mut msg = ciphertext;
    msg.extend_from_slice(&tag);
    let nonce = Nonce::try_from(iv.as_slice())
        .map_err(|_| Error::invalid_input("invalid JWE nonce length"))?;
    let payload = Payload {
        msg: &msg,
        aad: parts[0].as_bytes(),
    };
    let plaintext = match enc {
        JweEncryption::A128GCM => Aes128Gcm::new_from_slice(&cek)
            .map_err(|_| Error::invalid_input("invalid AES-128 key"))?
            .decrypt(&nonce, payload),
        JweEncryption::A256GCM => Aes256Gcm::new_from_slice(&cek)
            .map_err(|_| Error::invalid_input("invalid AES-256 key"))?
            .decrypt(&nonce, payload),
        _ => return Err(Error::configuration("unsupported response enc")),
    }
    .map_err(|_| Error::invalid_input("response decryption failed"))?;
    Ok(plaintext)
}
