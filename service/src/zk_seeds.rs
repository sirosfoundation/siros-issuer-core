//! Seed providers (design §8.3 item 2, the `SeedProvider` capability):
//! generation and derivation of the secrets rulebooks need — with
//! **domain separation** as part of the contract (§8.3's
//! `derive(ref, info, inputs, bytes)`), backed by secret-manager refs for
//! rulebooks requiring cross-issuance continuity.
//!
//! The v1 provider is **file-backed**: the secret lives in a file the
//! deployment manages (0600, a mounted secret — never a value in config),
//! loaded once at startup. A missing, unreadable, or undersized file is a
//! **startup refusal**, fail-closed like every other secret this service
//! touches. Derivation happens in the core (`Opening::Hkdf`): the secret
//! becomes the HKDF key, `info` rides the message after the label —
//! one secret, infinitely many separated roles.
//!
//! `generate(scope) -> Seed` (the design's per-session/per-tenant random
//! seed) is the `random` opening vocabulary — already config; what this
//! module adds is the *held* secret a rulebook references by name.

use std::collections::BTreeMap;

use siros_issuer_core::{Error, Result};

/// The minimum provider secret length: HKDF keys under 32 bytes are
/// refused by the core's opening derivation; refuse them at load time
/// instead — a startup error beats an issuance-time one.
const MIN_SECRET_BYTES: usize = 32;

/// The loaded providers: name → secret (base64url). Built at startup
/// from `[zk.seeds.<name>]`; issuance-time lookups are by name only —
/// an unknown name is a fail-closed issuance refusal, never a default.
#[derive(Debug, Default, Clone)]
pub struct SeedProviders {
    secrets: BTreeMap<String, String>,
}

impl SeedProviders {
    /// Load every provider named in `[zk.seeds]` from its file. One
    /// unreadable or undersized secret refuses startup — a rulebook
    /// referencing it would mint credentials whose commitments no
    /// verifier reproduces.
    pub fn load(
        config: &std::collections::HashMap<String, crate::config::SeedProviderCfg>,
    ) -> Result<Self> {
        let mut secrets = BTreeMap::new();
        for (name, provider) in config {
            let bytes = std::fs::read(&provider.secret_path).map_err(|e| {
                Error::configuration(format!(
                    "seed provider {name:?}: reading {}: {e}",
                    provider.secret_path
                ))
            })?;
            if bytes.len() < MIN_SECRET_BYTES {
                return Err(Error::configuration(format!(
                    "seed provider {name:?}: secret is {} bytes, minimum {MIN_SECRET_BYTES}",
                    bytes.len()
                )));
            }
            // Warn on a secret file looser than owner-only: not a refusal
            // (filesystems vary; container mounts read as 0777), but the
            // operator should know the deployment left it open.
            if let Ok(metadata) = std::fs::metadata(&provider.secret_path) {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        "seed provider {name:?}: secret file {path} is mode {mode:o} — owner-only (0600) recommended",
                        path = provider.secret_path,
                    );
                }
            }
            secrets.insert(name.clone(), siros_issuer_core::sdjwt_issue::b64u(&bytes));
        }
        Ok(Self { secrets })
    }

    /// The named provider's secret, base64url (the core `Opening::Hkdf`
    /// shape). Unknown name = fail-closed refusal naming the provider.
    pub fn secret(&self, name: &str) -> Result<&str> {
        self.secrets.get(name).map(String::as_str).ok_or_else(|| {
            Error::configuration(format!(
                "no seed provider {name:?} is configured ([zk.seeds])"
            ))
        })
    }
}
