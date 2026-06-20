use crate::error::AppError;
use crate::state::{
    transition_room_snapshot, AppState, InviteAttempt, InviteAttemptError, RoomPhase, RoomSnapshot,
    VerificationState,
};
use blindwire_core::invite::InvitePayload;
use blindwire_core::sas;
use blindwire_transport::{SecureSession, TransportConfig, TransportError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Emitter, State};
use uuid::Uuid;

// ────────────────────────────────────────────
// Response types (all safe to serialize to JS)
// ────────────────────────────────────────────

/// UI-safe invite summary returned by `parse_invite`.
/// Contains no keys or secrets — only display data + the opaque handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedInviteSummary {
    /// Opaque handle: JS returns this to `join_room`, cannot forge it.
    pub invite_handle: String,
    pub room: String,
    pub relay_label: String,
    pub is_custom_relay: bool,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomInfo {
    /// The canonical `blindwire://join?...` URI — use as both deep link and QR payload.
    pub invite_uri: String,
    pub qr_string: String,
    pub room_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAck {
    pub id: String,
    pub timestamp: u64,
}

pub enum SessionCmd {
    SendText(
        String,
        tokio::sync::oneshot::Sender<Result<MessageAck, AppError>>,
    ),
    Leave,
}

// ────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────

/// Derive a deterministic 32-byte session ID from the room string.
/// Both Initiator and Responder call this on the same `room` field → same ID.
fn session_id_from_room(room: &str) -> [u8; 32] {
    let hash = Sha256::digest(room.as_bytes());
    let mut id = [0u8; 32];
    id.copy_from_slice(&hash);
    id
}

/// Current Unix timestamp in milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(debug_assertions)]
pub(crate) fn default_relay_url() -> &'static str {
    "ws://127.0.0.1:8080"
}

#[cfg(not(debug_assertions))]
pub(crate) fn default_relay_url() -> &'static str {
    blindwire_core::invite::OFFICIAL_RELAY_URL
}

fn initiator_config(relay_url: String, session_id: [u8; 32]) -> TransportConfig {
    let config = TransportConfig::initiator(relay_url, session_id);
    #[cfg(debug_assertions)]
    return config.with_insecure_dev();
    #[cfg(not(debug_assertions))]
    config
}

/// Generate a cryptographically random base64url string of `n` bytes.
fn rand_base64url(n: usize) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    URL_SAFE_NO_PAD.encode(&buf)
}

pub(crate) fn finalize_invite_attempt(
    attempt: InviteAttempt,
    retryable: bool,
) -> Result<(), InviteAttemptError> {
    if retryable {
        attempt.release()
    } else {
        attempt.consume()
    }
}
/// Spawn the session task that multiplexes sending and receiving.
/// Returns the JoinHandle so callers can abort it on session replacement.
#[allow(clippy::too_many_arguments)]
fn spawn_session_task(
    mut session: SecureSession,
    mut rx: tokio::sync::mpsc::Receiver<SessionCmd>,
    app_handle: tauri::AppHandle,
    clear_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    my_generation: u64,
    current_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    session_tx_slot: std::sync::Arc<
        tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<SessionCmd>>>,
    >,
    room_snapshot: std::sync::Arc<std::sync::RwLock<RoomSnapshot>>,
    room: String,
    session_id: [u8; 32],
    invite_attempt: Option<InviteAttempt>,
) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let mut invite_attempt = invite_attempt;

        // Complete handshake first (blocks for initiator until responder joins)
        if let Err(e) = session.handshake().await {
            let err = AppError::from(e);
            if let Some(attempt) = invite_attempt.take() {
                let _ = finalize_invite_attempt(attempt, err.retryable);
            }
            let phase = if err.retryable {
                RoomPhase::Idle
            } else {
                RoomPhase::FatalError
            };
            if let Some(snapshot) = transition_room_snapshot(
                &room_snapshot,
                &current_generation,
                my_generation,
                phase,
                Some(room.clone()),
                None,
                Some(err),
            ) {
                emit_room_snapshot(&app_handle, &snapshot);
            }
            // Cleanup
            clear_flag.store(false, Ordering::SeqCst);
            let mut guard = session_tx_slot.lock().await;
            *guard = None;
            return;
        }

        if let Some(attempt) = invite_attempt.take() {
            let _ = finalize_invite_attempt(attempt, false);
        }

        let verification = build_verification_state(&session, &session_id);
        if let Some(snapshot) = transition_room_snapshot(
            &room_snapshot,
            &current_generation,
            my_generation,
            RoomPhase::Verifying,
            Some(room.clone()),
            Some(verification),
            None,
        ) {
            emit_room_snapshot(&app_handle, &snapshot);
        }

        loop {
            // Belt: exit if newer session started
            if current_generation.load(Ordering::SeqCst) != my_generation {
                break;
            }

            tokio::select! {
                Some(cmd) = rx.recv() => {
                    match cmd {
                        SessionCmd::SendText(text, ack_tx) => {
                            match session.send_text(&text).await {
                                Ok(_) => {
                                    let _ = ack_tx.send(Ok(MessageAck {
                                        id: Uuid::new_v4().to_string(),
                                        timestamp: now_ms(),
                                    }));
                                }
                                Err(e) => {
                                    let err = AppError::from(e);
                                    let _ = ack_tx.send(Err(err.clone()));
                                    if let Some(snapshot) = transition_room_snapshot(
                                        &room_snapshot,
                                        &current_generation,
                                        my_generation,
                                        RoomPhase::FatalError,
                                        Some(room.clone()),
                                        None,
                                        Some(err),
                                    ) {
                                        emit_room_snapshot(&app_handle, &snapshot);
                                    }
                                    break;
                                }
                            }
                        }
                        SessionCmd::Leave => {
                            session.burn();
                            break;
                        }
                    }
                }
                result = session.recv() => {
                    if current_generation.load(Ordering::SeqCst) != my_generation {
                        break;
                    }

                    match result {
                        Ok(msg) => {
                            #[derive(Serialize, Clone)]
                            struct MsgEvent { text: String, timestamp: u64 }
                            let text = String::from_utf8_lossy(msg.as_bytes()).to_string();
                            let _ = app_handle.emit("message_received", MsgEvent { text, timestamp: now_ms() });
                        }
                        Err(TransportError::SessionTerminated) | Err(TransportError::PeerDisconnected) => {
                            clear_flag.store(false, Ordering::SeqCst);
                            let mut guard = session_tx_slot.lock().await;
                            *guard = None;
                            if let Some(snapshot) = transition_room_snapshot(
                                &room_snapshot,
                                &current_generation,
                                my_generation,
                                RoomPhase::PeerDisconnected,
                                Some(room.clone()),
                                None,
                                None,
                            ) {
                                emit_room_snapshot(&app_handle, &snapshot);
                            }
                            break;
                        }
                        Err(e) => {
                            clear_flag.store(false, Ordering::SeqCst);
                            let mut guard = session_tx_slot.lock().await;
                            *guard = None;
                            let err: AppError = AppError::from(e);
                            if let Some(snapshot) = transition_room_snapshot(
                                &room_snapshot,
                                &current_generation,
                                my_generation,
                                RoomPhase::FatalError,
                                Some(room.clone()),
                                None,
                                Some(err),
                            ) {
                                emit_room_snapshot(&app_handle, &snapshot);
                            }
                            break;
                        }
                    }
                }
            }
        }
    })
}

/// Build the peer-verification details after a successful Noise handshake.
fn build_verification_state(session: &SecureSession, session_id: &[u8; 32]) -> VerificationState {
    let fingerprint_hex = session.fingerprint().unwrap_or_default();
    let mut shared_secret = [0u8; 32];
    if let Ok(bytes) = hex::decode(&fingerprint_hex) {
        let len = bytes.len().min(32);
        shared_secret[..len].copy_from_slice(&bytes[..len]);
    }

    VerificationState {
        identicon_seed: fingerprint_hex,
        emojis: sas::generate(&shared_secret, session_id),
        verified: false,
    }
}

fn emit_room_snapshot(app_handle: &tauri::AppHandle, snapshot: &RoomSnapshot) {
    let _ = app_handle.emit("room_state_changed", snapshot);
}

fn emit_room_error(
    state: &AppState,
    app_handle: &tauri::AppHandle,
    generation: u64,
    error: AppError,
) {
    let phase = if error.retryable {
        RoomPhase::Idle
    } else {
        RoomPhase::FatalError
    };
    if let Some(snapshot) = state.transition_room_with(generation, phase, None, None, Some(error)) {
        emit_room_snapshot(app_handle, &snapshot);
    }
}
// ────────────────────────────────────────────
// Tauri Commands
// ────────────────────────────────────────────

/// Parse a raw `blindwire://` URI or QR string.
/// Returns UI-safe summary + an opaque handle. The actual payload stays in Rust.
#[tauri::command]
pub async fn parse_invite(
    uri: String,
    state: State<'_, AppState>,
) -> Result<ParsedInviteSummary, AppError> {
    let payload = InvitePayload::parse(&uri).map_err(AppError::from)?;

    let is_custom_relay = payload.relay_pin.is_some();
    let relay_label = if is_custom_relay {
        payload
            .relay_url
            .host_str()
            .unwrap_or("Custom Server")
            .to_string()
    } else {
        "Official BlindWire Relay".to_string()
    };
    let expires_at = payload.exp;
    let room_id = payload.room.clone();

    let handle = state.store_invite(payload);

    Ok(ParsedInviteSummary {
        invite_handle: handle,
        room: room_id,
        relay_label,
        is_custom_relay,
        expires_at,
    })
}

/// Create a new room: mints a real invite URI and starts listening as Initiator.
/// Emits `verification_state_changed` once the responder joins and handshake completes.
#[tauri::command]
pub async fn create_room(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<RoomInfo, AppError> {
    // 1. Reject if already in a session
    if state.has_active_session() {
        return Err(AppError::new(
            "SESSION_ACTIVE",
            "Please leave the current room first.",
            false,
        ));
    }

    // 2. Increment generation, begin session
    let my_generation = state.begin_session();
    emit_room_snapshot(&app_handle, &state.room_snapshot());

    // 3. Mint a random room ID (16 bytes → 22-char base64url)
    let room_id = rand_base64url(16);
    let session_id = session_id_from_room(&room_id);

    // Allow overriding the dev relay URL via env var for testing
    let relay_url =
        std::env::var("BLINDWIRE_RELAY_URL").unwrap_or_else(|_| default_relay_url().to_string());

    // 4. Connect as Initiator and await server-minted token
    let config = initiator_config(relay_url.clone(), session_id);

    let connect_future = SecureSession::connect(config);
    let connect_result =
        tokio::time::timeout(std::time::Duration::from_secs(10), connect_future).await;

    let (session, server_token) = match connect_result {
        Ok(Ok(success)) => success,
        Ok(Err(e)) => {
            let error = AppError::from(e);
            emit_room_error(&state, &app_handle, my_generation, error.clone());
            return Err(error);
        }
        Err(_) => {
            let error = AppError::new(
                "RELAY_UNREACHABLE",
                "Timeout connecting to relay server.",
                true,
            );
            emit_room_error(&state, &app_handle, my_generation, error.clone());
            return Err(error);
        }
    };

    let token_raw = match server_token {
        Some(t) => t,
        None => {
            let error = AppError::new(
                "PROTOCOL_ERROR",
                "Server did not mint an invitation token.",
                false,
            );
            emit_room_error(&state, &app_handle, my_generation, error.clone());
            return Err(error);
        }
    };

    // Encode token for the URI
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let token_b64 = URL_SAFE_NO_PAD.encode(token_raw);

    // 5. Build the canonical invite URI
    // Expiry: 1 hour from now
    let exp = now_ms() + 3_600_000;
    let invite_uri =
        format!("blindwire://join?v=1&r={room_id}&t={token_b64}&e={exp}&u={relay_url}");

    let session_tx_slot = state.session_tx.clone();
    let pv_arc = state.peer_verified.clone();
    let gen_arc = state.session_generation.clone();
    let room_snapshot = state.room_snapshot.clone();
    let handle_slot = state.recv_loop_handle.clone();
    let sid = session_id;

    // 6. Spawn session task for background processing
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    {
        let mut guard = session_tx_slot.lock().await;
        *guard = Some(tx);
    }

    let handle = spawn_session_task(
        session,
        rx,
        app_handle,
        pv_arc,
        my_generation,
        gen_arc,
        session_tx_slot,
        room_snapshot,
        room_id.clone(),
        sid,
        None,
    );
    if let Ok(mut h) = handle_slot.lock() {
        *h = Some(handle);
    }

    Ok(RoomInfo {
        invite_uri: invite_uri.clone(),
        qr_string: invite_uri,
        room_id,
    })
}

/// Join a room using a valid opaque invite handle.
/// Emits `verification_state_changed` once the Noise handshake completes.
#[tauri::command]
pub async fn join_room(
    invite_handle: String,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<(), AppError> {
    if state.has_active_session() {
        return Err(AppError::new(
            "SESSION_ACTIVE",
            "Please leave the current room first.",
            false,
        ));
    }

    let invite_attempt = match state.begin_invite_attempt(&invite_handle) {
        Ok(attempt) => attempt,
        Err(InviteAttemptError::InProgress) => {
            return Err(AppError::new(
                "JOIN_IN_PROGRESS",
                "This invite is already being used to connect.",
                false,
            ));
        }
        Err(InviteAttemptError::Missing | InviteAttemptError::Stale) => {
            return Err(AppError::new(
                "INVITE_INVALID",
                "Invite handle is invalid, expired, or already used.",
                false,
            ));
        }
    };
    let invite = invite_attempt.payload.clone();

    if now_ms() > invite.exp.saturating_add(5 * 60 * 1000) {
        let _ = finalize_invite_attempt(invite_attempt, false);
        return Err(AppError::new(
            "INVITE_EXPIRED",
            "This invite link has expired.",
            false,
        ));
    }

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let decoded = match URL_SAFE_NO_PAD.decode(&invite.token) {
        Ok(decoded) => decoded,
        Err(_) => {
            let _ = finalize_invite_attempt(invite_attempt, false);
            return Err(AppError::new(
                "INVITE_INVALID",
                "Malformed token encoding.",
                false,
            ));
        }
    };
    if decoded.len() != 32 {
        let _ = finalize_invite_attempt(invite_attempt, false);
        return Err(AppError::new(
            "INVITE_INVALID",
            "Token has incorrect length.",
            false,
        ));
    }
    let mut token_bytes = [0u8; 32];
    token_bytes.copy_from_slice(&decoded);

    let session_id = session_id_from_room(&invite.room);
    let relay_url = invite.relay_url.to_string();
    let is_insecure = relay_url.starts_with("ws://");
    let mut config = TransportConfig::responder(relay_url, session_id, token_bytes);
    if is_insecure {
        config = config.with_insecure_dev();
    }

    if let Some(encoded_pin) = invite.relay_pin.as_deref() {
        let decoded_pin = match URL_SAFE_NO_PAD.decode(encoded_pin) {
            Ok(pin) => pin,
            Err(_) => {
                let _ = finalize_invite_attempt(invite_attempt, false);
                return Err(AppError::new(
                    "INVITE_INVALID",
                    "Malformed relay pin.",
                    false,
                ));
            }
        };
        let pin: [u8; 32] = match decoded_pin.try_into() {
            Ok(pin) => pin,
            Err(_) => {
                let _ = finalize_invite_attempt(invite_attempt, false);
                return Err(AppError::new(
                    "INVITE_INVALID",
                    "Malformed relay pin.",
                    false,
                ));
            }
        };
        config = config.with_server_pin(pin);
    }

    if let Ok(app_dir) = tauri::Manager::path(&app_handle).app_data_dir() {
        config = config.with_pins_path(app_dir.join("pins.txt"));
    }

    let my_generation = state.begin_session();
    emit_room_snapshot(&app_handle, &state.room_snapshot());
    let session_tx_slot = state.session_tx.clone();
    let pv_arc = state.peer_verified.clone();
    let gen_arc = state.session_generation.clone();
    let room_snapshot = state.room_snapshot.clone();
    let room = invite.room.clone();
    let handle_slot = state.recv_loop_handle.clone();

    tauri::async_runtime::spawn(async move {
        let session = match SecureSession::connect(config).await {
            Ok((session, _)) => session,
            Err(error) => {
                let error = AppError::from(error);
                let retryable = error.retryable;
                let _ = finalize_invite_attempt(invite_attempt, retryable);
                let phase = if retryable {
                    RoomPhase::Idle
                } else {
                    RoomPhase::FatalError
                };
                if let Some(snapshot) = transition_room_snapshot(
                    &room_snapshot,
                    &gen_arc,
                    my_generation,
                    phase,
                    Some(room.clone()),
                    None,
                    Some(error),
                ) {
                    emit_room_snapshot(&app_handle, &snapshot);
                }
                return;
            }
        };

        let (tx, rx) = tokio::sync::mpsc::channel(32);
        {
            let mut guard = session_tx_slot.lock().await;
            *guard = Some(tx);
        }

        let handle = spawn_session_task(
            session,
            rx,
            app_handle,
            pv_arc,
            my_generation,
            gen_arc,
            session_tx_slot,
            room_snapshot,
            room,
            session_id,
            Some(invite_attempt),
        );
        if let Ok(mut slot) = handle_slot.lock() {
            *slot = Some(handle);
        }
    });

    Ok(())
}
/// Get the current room state (for UI recovery after reload).
#[tauri::command]
pub async fn get_room_snapshot(state: State<'_, AppState>) -> Result<RoomSnapshot, AppError> {
    Ok(state.room_snapshot())
}

/// Mark the peer as verified (user confirmed the SAS match).
/// This gates `send_message` — chat is blocked until this is called.
#[tauri::command]
pub async fn confirm_peer_verified(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<(), AppError> {
    if !state.has_active_session() {
        return Err(AppError::new(
            "SESSION_NOT_ACTIVE",
            "No active session to verify.",
            false,
        ));
    }

    state.peer_verified.store(true, Ordering::SeqCst);
    let generation = state.session_generation.load(Ordering::SeqCst);
    let snapshot = state
        .transition_room_with(generation, RoomPhase::Active, None, None, None)
        .ok_or_else(|| {
            AppError::new("SESSION_NOT_ACTIVE", "No active session to verify.", false)
        })?;
    emit_room_snapshot(&app_handle, &snapshot);

    Ok(())
}

pub(crate) fn reset_server_pin_at_path(
    path: impl AsRef<std::path::Path>,
    relay: &str,
) -> Result<(), AppError> {
    match blindwire_transport::reset_server_pin(path, relay) {
        Ok(true) => Ok(()),
        Ok(false) => Err(AppError::new(
            "PIN_NOT_FOUND",
            "No stored pin exists for this custom relay.",
            false,
        )),
        Err(blindwire_transport::PinResetError::OfficialRelay) => Err(AppError::new(
            "PIN_RESET_FORBIDDEN",
            "The official relay's security pin cannot be reset.",
            false,
        )),
        Err(blindwire_transport::PinResetError::InvalidRelayUrl) => Err(AppError::new(
            "PIN_RESET_INVALID",
            "This custom relay address is invalid.",
            false,
        )),
        Err(blindwire_transport::PinResetError::Storage(_)) => Err(AppError::new(
            "PIN_STORE_FAILED",
            "The relay pin store could not be updated.",
            false,
        )),
    }
}

/// Reset the stored TOFU pin for a custom relay (used in Settings).
#[tauri::command]
pub async fn reset_server_pin(relay: String, app_handle: tauri::AppHandle) -> Result<(), AppError> {
    let app_dir = tauri::Manager::path(&app_handle)
        .app_data_dir()
        .map_err(|_| {
            AppError::new(
                "PIN_STORE_FAILED",
                "The relay pin store could not be opened.",
                false,
            )
        })?;
    reset_server_pin_at_path(app_dir.join("pins.txt"), &relay)
}

/// Send an encrypted message over the active session.
/// Blocked if the peer has not been verified.
#[tauri::command]
pub async fn send_message(
    text: String,
    state: State<'_, AppState>,
) -> Result<MessageAck, AppError> {
    // Block if not verified
    if !state.peer_verified.load(Ordering::SeqCst) {
        return Err(AppError::new(
            "SESSION_UNVERIFIED",
            "Cannot send messages before verifying the peer.",
            false,
        ));
    }

    let tx = {
        let guard = state.session_tx.lock().await;
        guard.clone()
    };

    let tx = tx.ok_or_else(|| AppError::new("SESSION_NOT_ACTIVE", "No active session.", false))?;

    let (oneshot_tx, oneshot_rx) = tokio::sync::oneshot::channel();
    tx.send(SessionCmd::SendText(text, oneshot_tx))
        .await
        .map_err(|_| AppError::new("SESSION_NOT_ACTIVE", "Session channel closed.", false))?;

    let result = oneshot_rx
        .await
        .map_err(|_| AppError::new("SESSION_NOT_ACTIVE", "Response channel dropped.", false))?;
    result
}

/// Leave the current room, burn the session, and reset state.
#[tauri::command]
pub async fn leave_room(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<(), AppError> {
    let tx = {
        let mut guard = state.session_tx.lock().await;
        guard.take()
    };

    if let Some(tx) = tx {
        let _ = tx.send(SessionCmd::Leave).await;
    }

    state.clear_session_state();
    emit_room_snapshot(&app_handle, &state.room_snapshot());

    Ok(())
}

/// Called by React once the frontend router has mounted and event listeners are registered.
/// Flushes any queued deep link that arrived before the UI was ready.
#[tauri::command]
pub async fn frontend_ready(
    app_handle: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    state.ui_ready.store(true, Ordering::SeqCst);

    let mut pending_lock = state.pending_deep_link.lock().await;
    if let Some(uri) = pending_lock.take() {
        let _ = app_handle.emit("blindwire-deep-link", uri);
    }

    Ok(())
}
