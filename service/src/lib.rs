//! siros-issuer-service library surface. The binary in `main.rs` and the
//! integration tests both build on this; deployment-only concerns live here,
//! never in the core.

pub mod api;
pub mod auth;
pub mod client_auth;
pub mod config;
pub mod dpop;
pub mod fetch;
#[cfg(feature = "mongo")]
pub mod mongo_store;
pub mod pdp;
pub mod pkcs11;
pub mod rate_limit;
pub mod status;
pub mod store;
pub mod vault;
pub mod wallet_attestation;
pub mod zk_load;
