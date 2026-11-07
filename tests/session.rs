//! The session state machine (design §5.1). Source of truth: the state
//! machine in the design document, which both grants and both authorization
//! modes must share.

use siros_issuer_core::session::{transition, GrantKind, SessionEvent, SessionId, SessionState};

/// A session id is 128 bits of host entropy, hex-encoded; anything else is
/// refused rather than normalized (parse, don't validate).
#[test]
fn session_ids_reject_anything_but_32_lowercase_hex() {
    let id = SessionId::from_random([0x0f; 16]);
    assert_eq!(id.as_str().len(), 32);
    assert_eq!(id.as_str(), "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");

    assert!(SessionId::from_hex(id.as_str()).is_ok());
    for refused in [
        "",
        "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",   // 31 chars
        "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0", // 33 chars
        "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",  // uppercase
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ] {
        assert!(
            SessionId::from_hex(refused).is_err(),
            "{refused:?} must be refused"
        );
    }
}

/// The full pre-authorized path: offered → redeemed → issued → accepted.
#[test]
fn pre_authorized_grant_reaches_accepted() {
    let state = SessionState::Offered;
    let state = transition(state, SessionEvent::Redeemed).unwrap();
    assert_eq!(state, SessionState::Redeeming);
    let state = transition(state, SessionEvent::Issued).unwrap();
    assert_eq!(state, SessionState::Issued);
    let state = transition(state, SessionEvent::WalletAccepted).unwrap();
    assert_eq!(state, SessionState::Accepted);
    assert!(state.is_final());
}

/// The wallet-initiated path: PAR creates AwaitingAuthorization; only a
/// completed authorization (Mode A handoff or Mode B presentation) mints the
/// code. Neither grant may skip it.
#[test]
fn authorization_code_grant_requires_authorization_before_redemption() {
    let state = SessionState::AwaitingAuthorization;
    let state = transition(state, SessionEvent::Authorized).unwrap();
    assert_eq!(state, SessionState::Offered);
    let state = transition(state, SessionEvent::Redeemed).unwrap();
    let state = transition(state, SessionEvent::Issued).unwrap();
    assert_eq!(state, SessionState::Issued);

    assert_eq!(
        transition(SessionState::AwaitingAuthorization, SessionEvent::Redeemed)
            .unwrap_err()
            .code,
        "illegal_transition"
    );
}

/// Re-issuance: the wallet may request again after issuance — and after
/// a credential_accepted notification (OID4VCI §13.3; the suite's
/// additional-requests module).
#[test]
fn re_issuance_is_legal_from_issued_and_accepted() {
    for from in [SessionState::Issued, SessionState::Accepted] {
        assert_eq!(
            transition(from, SessionEvent::Issued).unwrap(),
            SessionState::Issued
        );
    }
    // Terminal failure/expiry states stay closed.
    for closed in [SessionState::Failed, SessionState::Expired] {
        assert!(transition(closed, SessionEvent::Issued).is_err());
    }
}

/// Deferred issuance: Redeeming → Pending → Issued, and re-deferral is
/// idempotent (the wallet polls; polls are not events, but a second
/// deferral must not fail the session).
#[test]
fn deferred_issuance_completes_exactly_once() {
    let state = transition(SessionState::Redeeming, SessionEvent::Deferred).unwrap();
    assert_eq!(state, SessionState::Pending);
    let state = transition(state, SessionEvent::Deferred).unwrap();
    assert_eq!(state, SessionState::Pending);
    let state = transition(state, SessionEvent::Issued).unwrap();
    assert_eq!(state, SessionState::Issued);

    // Re-issuance is legal (§13.3) — it does not fail the session; each
    // request mints a fresh credential and a fresh status-list index.
    assert_eq!(
        transition(state, SessionEvent::Issued).unwrap(),
        SessionState::Issued
    );
}

/// Expiry is legal while the offer/authorization is unredeemed and illegal
/// afterwards — an in-flight redemption must not be silently dropped.
#[test]
fn expiry_binds_only_to_unredeemed_states() {
    assert_eq!(
        transition(
            SessionState::AwaitingAuthorization,
            SessionEvent::TtlExpired
        )
        .unwrap(),
        SessionState::Expired
    );
    assert_eq!(
        transition(SessionState::Offered, SessionEvent::TtlExpired).unwrap(),
        SessionState::Expired
    );
    for in_flight in [
        SessionState::Redeeming,
        SessionState::Pending,
        SessionState::Issued,
    ] {
        assert_eq!(
            transition(in_flight, SessionEvent::TtlExpired)
                .unwrap_err()
                .code,
            "illegal_transition"
        );
    }
}

/// Notification events map per design §7.7: accepted → Accepted,
/// failure → Failed, deleted → Deleted. All are legal only from Issued.
#[test]
fn wallet_notifications_map_to_their_terminal_states() {
    use SessionEvent::*;
    for (event, expected) in [
        (WalletAccepted, SessionState::Accepted),
        (WalletFailed, SessionState::Failed),
        (WalletDeleted, SessionState::Deleted),
    ] {
        let state = transition(SessionState::Issued, event).unwrap();
        assert_eq!(state, expected);
        assert!(state.is_final());
    }
    assert!(transition(SessionState::Redeeming, WalletAccepted).is_err());
}

/// Any non-final state fails on a classified error; final states are closed.
#[test]
fn errors_close_every_non_final_state() {
    for state in [
        SessionState::AwaitingAuthorization,
        SessionState::Offered,
        SessionState::Redeeming,
        SessionState::Pending,
        SessionState::Issued,
    ] {
        assert_eq!(
            transition(state, SessionEvent::ErrorOccurred).unwrap(),
            SessionState::Failed
        );
    }
    for final_state in [
        SessionState::Accepted,
        SessionState::Failed,
        SessionState::Expired,
        SessionState::Deleted,
    ] {
        assert!(transition(final_state, SessionEvent::ErrorOccurred).is_err());
    }
}

/// Both grant kinds exist and round-trip through serde with snake_case wire
/// labels (the session store persists the discriminator).
#[test]
fn grant_kinds_have_snake_case_wire_labels() {
    assert_eq!(
        serde_json::to_string(&GrantKind::PreAuthorized).unwrap(),
        r#""pre_authorized""#
    );
    assert_eq!(
        serde_json::to_string(&GrantKind::AuthorizationCode).unwrap(),
        r#""authorization_code""#
    );
    assert_eq!(
        serde_json::to_string(&SessionState::AwaitingAuthorization).unwrap(),
        r#""awaiting_authorization""#
    );
}
