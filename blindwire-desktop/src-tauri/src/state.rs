use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

    /// Monotonically increasing session generation counter.
    ///
    /// Incremented at the start of every create_room() or join_room().
    /// The recv loop captures the generation at spawn time and discards events
    /// from a different (stale) generation.
    pub session_generation: Arc<AtomicU64>,

    /// Handle to the current recv loop task.
    ///
    /// The new session start aborts this before spawning a replacement.
    pub recv_loop_handle: Arc<std::sync::Mutex<Option<tauri::async_runtime::JoinHandle<()>>>>,

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
            session_generation: Arc::new(AtomicU64::new(0)),
            recv_loop_handle: Arc::new(std::sync::Mutex::new(None)),
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

    /// Prepare for a new session:
    ///   1. Reset peer_verified to false.
    ///   2. Increment session_generation (stale loops will see a mismatch and exit).
    ///   3. Abort the old recv loop task if one exists.
    ///
    /// Returns the newly minted generation number — pass this into `spawn_recv_loop`.
    pub fn begin_session(&self) -> u64 {
        // 1. Reset verification gate
        self.peer_verified.store(false, Ordering::SeqCst);

        // 2. Increment generation — fetch_add returns the OLD value, so +1
        let new_gen = self.session_generation.fetch_add(1, Ordering::SeqCst) + 1;

        // 3. Abort previous recv loop
        if let Ok(mut handle_guard) = self.recv_loop_handle.lock() {
            if let Some(handle) = handle_guard.take() {
                handle.abort();
            }
        }

        new_gen
    }

    /// Reset session state on leave or transport error (mirrors begin_session without
    /// incrementing the generation — the loop will already be exiting or gone).
    pub fn clear_session_state(&self) {
        self.peer_verified.store(false, Ordering::SeqCst);
    }
}
