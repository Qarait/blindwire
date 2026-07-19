#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::commands::{
        default_relay_url, finalize_invite_attempt, reset_server_pin_at_path, ParsedInviteSummary,
    };
    use crate::error::AppError;
    use crate::state::{
        AppState, InviteAttemptError, RoomPhase, SessionOwnershipError, VerificationState,
    };
    use blindwire_core::invite::InvitePayload;

    #[test]
    fn release_default_uses_the_official_secure_relay() {
        #[cfg(not(debug_assertions))]
        assert_eq!(default_relay_url(), "wss://relay.blindwire.net");
        #[cfg(debug_assertions)]
        assert_eq!(default_relay_url(), "ws://127.0.0.1:8080");
    }

    // We can't easily mock Tauri's `State<'_, AppState>` or `AppHandle` in pure unit tests
    // without spinning up a mock Tauri app, but we can test the internal handlers and structs directly.

    #[test]
    fn test_frontend_payloads_contain_no_secret_material() {
        // Assert that the structs serialized to JS do not contain cryptographic keys.
        // We do this by checking the defined fields.
        let summary = ParsedInviteSummary {
            invite_handle: "uuid-1234".to_string(),
            room: "room123".to_string(),
            relay_label: "Official".to_string(),
            is_custom_relay: false,
            expires_at: 123456789,
        };

        // Serialize and verify it only contains the safe fields
        let serialized = serde_json::to_string(&summary).unwrap();
        assert!(serialized.contains("invite_handle"));
        assert!(
            !serialized.contains("token")
                && !serialized.contains("secret")
                && !serialized.contains("private_key")
        );
    }

    #[tokio::test]
    async fn test_parse_invite_handle_cannot_be_forged() {
        let state = AppState::new();

        // A forged JS handle
        let evil_handle = "forged-uuid-from-js".to_string();

        // Attempting to consume this handle must fail because Rust didn't issue it.
        let invite = state.consume_invite(&evil_handle);
        assert!(
            invite.is_none(),
            "Forged handle should not resolve to an invite"
        );
    }

    #[test]
    fn room_phase_and_generation_transition_together() {
        let state = AppState::new();
        let generation = state.begin_session().unwrap();
        let connecting = state.room_snapshot();
        assert_eq!(connecting.phase, RoomPhase::Connecting);
        assert_eq!(connecting.generation, generation);

        assert!(state.transition_room(generation, RoomPhase::Verifying));
        assert_eq!(state.room_snapshot().phase, RoomPhase::Verifying);
    }

    #[test]
    fn stale_room_transition_is_ignored_after_leave() {
        let state = AppState::new();
        let stale_generation = state.begin_session().unwrap();
        state.clear_session_state();
        let after_leave = state.room_snapshot();

        assert_eq!(after_leave.phase, RoomPhase::Idle);
        assert!(after_leave.generation > stale_generation);
        assert!(!state.transition_room(stale_generation, RoomPhase::Active));
        assert_eq!(state.room_snapshot(), after_leave);
    }

    #[test]
    fn only_one_session_attempt_can_own_the_runtime() {
        let state = AppState::new();
        let generation = state.begin_session().unwrap();

        assert_eq!(
            state.begin_session(),
            Err(SessionOwnershipError::AlreadyActive)
        );
        assert_eq!(state.active_generation(), Some(generation));
    }

    #[tokio::test]
    async fn stale_generation_cannot_replace_or_clear_current_sender() {
        let state = AppState::new();
        let stale_generation = state.begin_session().unwrap();
        let (stale_tx, _stale_rx) = tokio::sync::mpsc::channel(1);
        assert!(
            state
                .install_session_sender(stale_generation, stale_tx)
                .await
        );
        assert!(state.finish_session(stale_generation));

        let current_generation = state.begin_session().unwrap();
        let (current_tx, _current_rx) = tokio::sync::mpsc::channel(1);
        assert!(
            state
                .install_session_sender(current_generation, current_tx)
                .await
        );

        assert!(!state.clear_session_sender(stale_generation).await);
        assert_eq!(
            state.session_sender_generation().await,
            Some(current_generation)
        );
    }

    #[test]
    fn verification_requires_current_verifying_snapshot() {
        let state = AppState::new();
        let generation = state.begin_session().unwrap();

        assert!(state.confirm_peer_verified(generation).is_none());
        assert!(state
            .transition_room_with(
                generation,
                RoomPhase::Verifying,
                Some("room".to_string()),
                Some(VerificationState {
                    identicon_seed: "seed".to_string(),
                    emojis: vec!["one".to_string()],
                    verified: false,
                }),
                None,
            )
            .is_some());

        let confirmed = state
            .confirm_peer_verified(generation)
            .expect("current verifying state must be confirmable");
        assert_eq!(confirmed.phase, RoomPhase::Active);
        assert!(confirmed.peer_verified);
        assert!(confirmed.verification.unwrap().verified);
        assert!(state.confirm_peer_verified(generation).is_none());
    }

    #[test]
    fn room_snapshot_revision_is_monotonic() {
        let state = AppState::new();
        let generation = state.begin_session().unwrap();
        let connecting = state.room_snapshot();

        assert!(state.transition_room(generation, RoomPhase::Verifying));
        let verifying = state.room_snapshot();
        assert_eq!(verifying.generation, generation);
        assert!(verifying.revision > connecting.revision);
    }

    #[test]
    fn official_relay_pin_reset_is_forbidden() {
        let path =
            std::env::temp_dir().join(format!("blindwire-missing-{}.txt", uuid::Uuid::new_v4()));
        let error = reset_server_pin_at_path(path, "wss://relay.blindwire.net")
            .expect_err("the official relay must never use a mutable user pin");

        assert_eq!(error.code, "PIN_RESET_FORBIDDEN");
    }

    #[test]
    fn missing_custom_relay_pin_has_a_stable_error() {
        let path =
            std::env::temp_dir().join(format!("blindwire-missing-{}.txt", uuid::Uuid::new_v4()));
        let error = reset_server_pin_at_path(path, "wss://custom.example")
            .expect_err("resetting an unknown pin must not report success");

        assert_eq!(error.code, "PIN_NOT_FOUND");
    }

    fn test_invite() -> InvitePayload {
        InvitePayload {
            room: "cm9vbQ".to_string(),
            token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            exp: u64::MAX,
            relay_url: "wss://relay.blindwire.net".parse().unwrap(),
            relay_pin: None,
        }
    }

    #[test]
    fn invite_attempt_can_be_released_for_retry() {
        let state = AppState::new();
        let handle = state.store_invite(test_invite());
        let lease = state.begin_invite_attempt(&handle).unwrap();

        assert_eq!(
            state.begin_invite_attempt(&handle),
            Err(InviteAttemptError::InProgress)
        );
        state
            .release_invite_attempt(&handle, lease.generation)
            .unwrap();
        assert!(state.begin_invite_attempt(&handle).is_ok());
    }

    #[test]
    fn retryable_join_failure_releases_invite_attempt() {
        let state = AppState::new();
        let handle = state.store_invite(test_invite());
        let lease = state.begin_invite_attempt(&handle).unwrap();

        finalize_invite_attempt(lease, true).unwrap();
        assert!(state.begin_invite_attempt(&handle).is_ok());
    }

    #[test]
    fn fatal_join_failure_consumes_invite_attempt() {
        let state = AppState::new();
        let handle = state.store_invite(test_invite());
        let lease = state.begin_invite_attempt(&handle).unwrap();

        finalize_invite_attempt(lease, false).unwrap();
        assert_eq!(
            state.begin_invite_attempt(&handle),
            Err(InviteAttemptError::Missing)
        );
    }
    #[test]
    fn relay_reachability_failure_is_retryable() {
        let error = AppError::from(blindwire_transport::TransportError::ConnectionFailed(
            "network unavailable".to_string(),
        ));
        assert!(error.retryable);
    }

    #[test]
    fn tls_validation_failure_is_not_retryable() {
        let error = AppError::from(blindwire_transport::TransportError::TlsValidationFailed);
        assert_eq!(error.code, "RELAY_IDENTITY_INVALID");
        assert!(!error.retryable);
    }
    #[test]
    fn invite_attempt_is_permanently_consumed() {
        let state = AppState::new();
        let handle = state.store_invite(test_invite());
        let lease = state.begin_invite_attempt(&handle).unwrap();

        state
            .consume_invite_attempt(&handle, lease.generation)
            .unwrap();
        assert_eq!(
            state.begin_invite_attempt(&handle),
            Err(InviteAttemptError::Missing)
        );
    }
}
