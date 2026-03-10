use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use blindwire_core::invite::InvitePayload;
use blindwire_transport::SecureSession;

/// App state injected into Tauri commands.
pub struct AppState {
    /// Opaque invite handles stored in memory to prevent JS from forging invites.
    pub parsed_invites: DashMap<String, InvitePayload>,

    /// Opaque identity change handles stored in memory.
    pub pending_identity_changes: DashMap<String, ()>,

    /// The live secure session.
    pub active_session: Arc<Mutex<Option<SecureSession>>>,

    /// True once the peer has been verified by the user (SAS confirmed).
    /// Wrapped in Arc so it can be cheaply cloned into background tasks.
    pub peer_verified: Arc<AtomicBool>,

    /// Stores a pending deep link URI that arrived before the UI was ready.
    pub pending_deep_link: Arc<Mutex<Option<String>>>,

    /// Flag set once the UI confirms it is ready to receive events.
    pub ui_ready: AtomicBool,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            parsed_invites: DashMap::new(),
            pending_identity_changes: DashMap::new(),
            active_session: Arc::new(Mutex::new(None)),
            peer_verified: Arc::new(AtomicBool::new(false)),
            pending_deep_link: Arc::new(Mutex::new(None)),
            ui_ready: AtomicBool::new(false),
        }
    }

    /// Stores an invite and returns the unguessable opaque handle (UUID v4) for JS.
    pub fn store_invite(&self, invite: InvitePayload) -> String {
        let handle = Uuid::new_v4().to_string();
        self.parsed_invites.insert(handle.clone(), invite);
        handle
    }

    /// Retrieves and removes (consumes) the invite associated with the opaque handle.
    pub fn consume_invite(&self, handle: &str) -> Option<InvitePayload> {
        self.parsed_invites.remove(handle).map(|(_, v)| v)
    }

    /// Stores an identity change requirement and returns the opaque handle.
    pub fn store_identity_change(&self) -> String {
        let handle = Uuid::new_v4().to_string();
        self.pending_identity_changes.insert(handle.clone(), ());
        handle
    }

    /// Verifies and removes a pending identity change.
    pub fn consume_identity_change(&self, handle: &str) -> bool {
        self.pending_identity_changes.remove(handle).is_some()
    }

    /// True if there is a live session that can send/receive.
    pub fn has_active_session(&self) -> bool {
        // Non-blocking check: try_lock. If locked, assume active.
        match self.active_session.try_lock() {
            Ok(guard) => guard.is_some(),
            Err(_) => true, // locked = recv loop is in it, so it's active
        }
    }

    /// Reset session state (called on leave or error).
    pub fn clear_session_state(&self) {
        self.peer_verified.store(false, Ordering::SeqCst);
    }
}
