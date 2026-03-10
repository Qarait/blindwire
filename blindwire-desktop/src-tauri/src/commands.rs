use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{State, Emitter};
use uuid::Uuid;
use blindwire_core::invite::InvitePayload;
use blindwire_core::sas;
use blindwire_transport::{SecureSession, TransportConfig, TransportError};
use crate::error::AppError;
use crate::state::AppState;

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
pub struct RoomSnapshot {
    pub connected: bool,
    pub peer_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAck {
    pub id: String,
    pub timestamp: u64,
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

/// Generate a cryptographically random base64url string of `n` bytes.
fn rand_base64url(n: usize) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    URL_SAFE_NO_PAD.encode(&buf)
}

/// Spawn the receive loop for a live session.
/// Drives `message_received` events and terminates with `join_failed` on error.
fn spawn_recv_loop(
    session_slot: std::sync::Arc<tokio::sync::Mutex<Option<SecureSession>>>,
    app_handle: tauri::AppHandle,
    clear_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    tauri::async_runtime::spawn(async move {
        loop {
            // Lock, recv one message, unlock before emitting.
            let result = {
                let mut guard = session_slot.lock().await;
                match guard.as_mut() {
                    Some(s) => s.recv().await,
                    None => break, // Session was taken by leave_room
                }
            };

            match result {
                Ok(msg) => {
                    #[derive(Serialize, Clone)]
                    struct MsgEvent { text: String, timestamp: u64 }
                    let text = String::from_utf8_lossy(msg.as_bytes()).to_string();
                    let _ = app_handle.emit("message_received", MsgEvent { text, timestamp: now_ms() });
                }
                Err(TransportError::SessionTerminated) | Err(TransportError::PeerDisconnected) => {
                    clear_flag.store(false, Ordering::SeqCst);
                    {
                        let mut guard = session_slot.lock().await;
                        *guard = None;
                    }
                    let _ = app_handle.emit("room_state_changed", serde_json::json!({ "connected": false, "reason": "PEER_DISCONNECTED" }));
                    break;
                }
                Err(e) => {
                    clear_flag.store(false, Ordering::SeqCst);
                    {
                        let mut guard = session_slot.lock().await;
                        *guard = None;
                    }
                    let err: AppError = AppError::from(e);
                    let _ = app_handle.emit("join_failed", err);
                    break;
                }
            }
        }
    });
}

/// After a successful handshake, emit the real verification state.
/// Uses session.fingerprint() (16 hex chars) as the SAS shared_secret input,
/// and the session_id bytes as the salt — matching the core sas::generate() contract.
fn emit_verification_state(session: &SecureSession, session_id: &[u8; 32], app_handle: &tauri::AppHandle) {
    let fingerprint_hex = session.fingerprint().unwrap_or_default();

    // Decode the 16-char hex fingerprint into 8 bytes, zero-pad to [u8;32] for sas::generate.
    let mut shared_secret = [0u8; 32];
    if let Ok(bytes) = hex::decode(&fingerprint_hex) {
        let len = bytes.len().min(32);
        shared_secret[..len].copy_from_slice(&bytes[..len]);
    }

    let emojis = sas::generate(&shared_secret, session_id);

    #[derive(Serialize, Clone)]
    struct VerificationState {
        identicon_seed: String,
        emojis: Vec<String>,
        verified: bool,
    }

    let _ = app_handle.emit("verification_state_changed", VerificationState {
        identicon_seed: fingerprint_hex,
        emojis,
        verified: false,
    });
}

// ────────────────────────────────────────────
// Tauri Commands
// ────────────────────────────────────────────

/// Parse a raw `blindwire://` URI or QR string.
/// Returns UI-safe summary + an opaque handle. The actual payload stays in Rust.
#[tauri::command]
pub async fn parse_invite(
    uri: String,
    state: State<'_, AppState>
) -> Result<ParsedInviteSummary, AppError> {
    let payload = InvitePayload::parse(&uri).map_err(AppError::from)?;

    let is_custom_relay = payload.relay_pin.is_some();
    let relay_label = if is_custom_relay {
        payload.relay_url.host_str().unwrap_or("Custom Server").to_string()
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
    // Reject if already in a session
    if state.has_active_session() {
        return Err(AppError::new("SESSION_ACTIVE", "Please leave the current room first.", false));
    }

    // Mint a random room ID (16 bytes → 22-char base64url) and token
    let room_id = rand_base64url(16);
    let token = rand_base64url(24);
    // Expiry: 1 hour from now
    let exp = now_ms() + 3_600_000;

    // Build the canonical invite URI (same format as deep links + QR)
    let invite_uri = format!(
        "blindwire://join?v=1&r={}&t={}&e={}",
        room_id, token, exp
    );

    let session_id = session_id_from_room(&room_id);
    let relay_url = "ws://localhost:9001".to_string(); // dev: local server

    let config = TransportConfig::initiator(relay_url, session_id).with_insecure_dev();

    let session_slot = state.active_session.clone();
    let pv_arc = state.peer_verified.clone();
    let room_clone = room_id.clone();

    // Spawn connect + recv loop
    tauri::async_runtime::spawn(async move {
        let session = match SecureSession::connect(config).await {
            Ok(s) => s,
            Err(e) => {
                let err: AppError = AppError::from(e);
                let _ = app_handle.emit("join_failed", err);
                return;
            }
        };

        let sid = session_id_from_room(&room_clone);
        emit_verification_state(&session, &sid, &app_handle);

        {
            let mut guard = session_slot.lock().await;
            *guard = Some(session);
        }

        spawn_recv_loop(session_slot, app_handle, pv_arc);
    });

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
    // Reject if already in a session
    if state.has_active_session() {
        return Err(AppError::new("SESSION_ACTIVE", "Please leave the current room first.", false));
    }

    // Consume the Rust-side invite payload — JS cannot forge this
    let invite = state.consume_invite(&invite_handle)
        .ok_or_else(|| AppError::new("INVITE_INVALID", "Invite handle is invalid, expired, or already used.", false))?;

    let session_id = session_id_from_room(&invite.room);
    let relay_url = invite.relay_url.to_string();
    let room_clone = invite.room.clone();

    // For dev/local: if URL is ws:// allow insecure
    let is_insecure = relay_url.starts_with("ws://");
    let mut config = TransportConfig::responder(relay_url, session_id);
    if is_insecure {
        config = config.with_insecure_dev();
    }

    // Set pins path for TOFU persistence (app data dir)
    if let Ok(app_dir) = tauri::Manager::path(&app_handle).app_data_dir() {
        config = config.with_pins_path(app_dir.join("pins.txt"));
    }

    log::info!("Starting join flow for room: {}", invite.room);

    let session_slot = state.active_session.clone();
    let pv_arc = state.peer_verified.clone();

    tauri::async_runtime::spawn(async move {
        let session = match SecureSession::connect(config).await {
            Ok(s) => s,
            Err(e) => {
                let err: AppError = AppError::from(e);
                let _ = app_handle.emit("join_failed", err);
                return;
            }
        };

        emit_verification_state(&session, &session_id, &app_handle);

        {
            let mut guard = session_slot.lock().await;
            *guard = Some(session);
        }

        spawn_recv_loop(session_slot, app_handle, pv_arc);
    });

    Ok(())
}

/// Get the current room state (for UI recovery after reload).
#[tauri::command]
pub async fn get_room_snapshot(
    state: State<'_, AppState>
) -> Result<RoomSnapshot, AppError> {
    Ok(RoomSnapshot {
        connected: state.has_active_session(),
        peer_verified: state.peer_verified.load(Ordering::SeqCst),
    })
}

/// Mark the peer as verified (user confirmed the SAS match).
/// This gates `send_message` — chat is blocked until this is called.
#[tauri::command]
pub async fn confirm_peer_verified(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<(), AppError> {
    if !state.has_active_session() {
        return Err(AppError::new("SESSION_NOT_ACTIVE", "No active session to verify.", false));
    }

    state.peer_verified.store(true, Ordering::SeqCst);

    let _ = app_handle.emit("room_state_changed", serde_json::json!({
        "connected": true,
        "peer_verified": true
    }));

    Ok(())
}

/// Trust a new server identity after an observed pin change.
#[tauri::command]
pub async fn trust_new_server_identity(
    change_id: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    if !state.consume_identity_change(&change_id) {
        return Err(AppError::new("STALE_IDENTITY_CHANGE", "This identity prompt is no longer valid.", false));
    }
    Ok(())
}

/// Reset the stored TOFU pin for a relay (used in Settings).
#[tauri::command]
pub async fn reset_server_pin(
    relay: String,
    _state: State<'_, AppState>,
) -> Result<(), AppError> {
    log::info!("Pin reset requested for: {}", relay);
    // TODO: call DiskPinStore::remove(relay) — requires exposing that API
    Ok(())
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
        return Err(AppError::new("SESSION_UNVERIFIED", "Cannot send messages before verifying the peer.", false));
    }

    let mut guard = state.active_session.lock().await;
    let session = guard.as_mut()
        .ok_or_else(|| AppError::new("SESSION_NOT_ACTIVE", "No active session.", false))?;

    session.send_text(&text).await.map_err(|e| {
        AppError::from(e)
    })?;

    Ok(MessageAck {
        id: Uuid::new_v4().to_string(),
        timestamp: now_ms(),
    })
}

/// Leave the current room, burn the session, and reset state.
#[tauri::command]
pub async fn leave_room(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<(), AppError> {
    let session = {
        let mut guard = state.active_session.lock().await;
        guard.take()
    };

    if let Some(s) = session {
        s.burn();
    }

    state.clear_session_state();

    let _ = app_handle.emit("room_state_changed", serde_json::json!({ "connected": false }));

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
        log::info!("Dispatching queued deep link: {}", uri);
        let _ = app_handle.emit("blindwire-deep-link", uri);
    }

    Ok(())
}
