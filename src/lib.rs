//! Sans-I/O digital credential issuance core for SIROS.
//!
//! The core owns protocol logic only: OpenID4VCI issuer metadata generation
//! from the TS 119 602 / TS11 catalog, the issuance session state machine,
//! trust-query construction for go-trust, and siros-status-service wire
//! types. Transport, storage, time and trust verdicts belong to the host
//! (see `service/`). Cryptographic verification of presentations is embedded
//! from `siros-verifier-core`, never re-implemented here.
//!
//! Error values carry stable machine-readable codes suitable for logs and
//! protocol error responses, and never include subject data.

pub mod catalog;
pub mod error;
pub mod mdoc_issue;
pub mod oid4vci;
pub mod response;
pub mod sdjwt_issue;
pub mod session;
pub mod signer;
pub mod status_client;
pub mod trust;
pub mod zk;

pub use error::{Error, Result};
