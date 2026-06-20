use crate::error::AppError;
use blindwire_core::invite::InvitePayload;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct InviteEntry {
    pub payload: InvitePayload,
    pub attempt_generation: Option<u64>,
}

#[derive(Debug)]
pub struct InviteAttempt {
    pub payload: InvitePayload,
    pub generation: u64,
    handle: String,
    store: Arc<DashMap<String, InviteEntry>>,
    finalized: bool,
}

impl PartialEq for InviteAttempt {
    fn eq(&self, other: &Self) -> bool {
        self.payload == other.payload && self.generation == other.generation
    }
}

impl Eq for InviteAttempt {}

impl InviteAttempt {
    pub fn release(mut self) -> Result<(), InviteAttemptError> {
        let result = release_invite_attempt_in(&self.store, &self.handle, self.generation);
        self.finalized = true;
        result
    }

    pub fn consume(mut self) -> Result<(), InviteAttemptError> {
        let result = consume_invite_attempt_in(&self.store, &self.handle, self.generation);
        self.finalized = true;
        result
    }
}

impl Drop for InviteAttempt {
    fn drop(&mut self) {
        if !self.finalized {
            let _ = release_invite_attempt_in(&self.store, &self.handle, self.generation);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteAttemptError {
    Missing,
    InProgress,
    Stale,
}

fn release_invite_attempt_in(
    store: &DashMap<String, InviteEntry>,
    handle: &str,
    generation: u64,
) -> Result<(), InviteAttemptError> {
    let mut entry = store.get_mut(handle).ok_or(InviteAttemptError::Missing)?;
    if entry.attempt_generation != Some(generation) {
        return Err(InviteAttemptError::Stale);
    }
    entry.attempt_generation = None;
    Ok(())
}

fn consume_invite_attempt_in(
    store: &DashMap<String, InviteEntry>,
    handle: &str,
    generation: u64,
) -> Result<(), InviteAttemptError> {
    match store.entry(handle.to_owned()) {
        Entry::Occupied(entry) if entry.get().attempt_generation == Some(generation) => {
            entry.remove();
            Ok(())
        }
        Entry::Occupied(_) => Err(InviteAttemptError::Stale),
        Entry::Vacant(_) => Err(InviteAttemptError::Missing),
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoomPhase {
    Idle,
    Connecting,
    Verifying,
    Active,
    PeerDisconnected,
    FatalError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationState {
    pub identicon_seed: String,
    pub emojis: Vec<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomSnapshot {
    pub phase: RoomPhase,
    pub generation: u64,
    pub peer_verified: bool,
    pub room: Option<String>,
    pub verification: Option<VerificationState>,
    pub error: Option<AppError>,
}

impl Default for RoomSnapshot {
    fn default() -> Self {
        Self {
            phase: RoomPhase::Idle,
            generation: 0,
            peer_verified: false,
            room: None,
            verification: None,
            error: None,
        }
    }
}
/// App state injected into Tauri commands.
pub struct AppState {
    /// Authoritative room lifecycle snapshot shared by commands and background tasks.
    pub room_snapshot: Arc<RwLock<RoomSnapshot>>,

    /// Opaque invite handles stored in memory to prevent JS from forging invites.
    pub parsed_invites: Arc<DashMap<String, InviteEntry>>,

    invite_attempt_generation: AtomicU64,
    /// The channel used to send commands to the active session task.
    pub session_tx: Arc<Mutex<Option<tokio::sync::mpsc::Sender<crate::commands::SessionCmd>>>>,

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

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            room_snapshot: Arc::new(RwLock::new(RoomSnapshot::default())),
            parsed_invites: Arc::new(DashMap::new()),
            invite_attempt_generation: AtomicU64::new(0),
            session_tx: Arc::new(Mutex::new(None)),
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
        self.parsed_invites.insert(
            handle.clone(),
            InviteEntry {
                payload: invite,
                attempt_generation: None,
            },
        );
        handle
    }

    /// Legacy one-shot consumption used only for invalid-handle checks.
    pub fn consume_invite(&self, handle: &str) -> Option<InvitePayload> {
        self.parsed_invites
            .remove(handle)
            .map(|(_, entry)| entry.payload)
    }

    /// Atomically lease an invite for one JOIN attempt.
    pub fn begin_invite_attempt(&self, handle: &str) -> Result<InviteAttempt, InviteAttemptError> {
        let mut entry = self
            .parsed_invites
            .get_mut(handle)
            .ok_or(InviteAttemptError::Missing)?;
        if entry.attempt_generation.is_some() {
            return Err(InviteAttemptError::InProgress);
        }

        let generation = self
            .invite_attempt_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        entry.attempt_generation = Some(generation);
        Ok(InviteAttempt {
            payload: entry.payload.clone(),
            generation,
            handle: handle.to_owned(),
            store: Arc::clone(&self.parsed_invites),
            finalized: false,
        })
    }

    /// Release a retryable JOIN attempt without returning a stale lease to circulation.
    pub fn release_invite_attempt(
        &self,
        handle: &str,
        generation: u64,
    ) -> Result<(), InviteAttemptError> {
        release_invite_attempt_in(&self.parsed_invites, handle, generation)
    }

    /// Permanently consume the invite only when the matching attempt still owns it.
    pub fn consume_invite_attempt(
        &self,
        handle: &str,
        generation: u64,
    ) -> Result<(), InviteAttemptError> {
        consume_invite_attempt_in(&self.parsed_invites, handle, generation)
    }

    /// True if there is a live session that can send/receive.
    pub fn has_active_session(&self) -> bool {
        // Non-blocking check: try_lock. If locked, assume active.
        match self.session_tx.try_lock() {
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

        if let Ok(mut snapshot) = self.room_snapshot.write() {
            *snapshot = RoomSnapshot {
                phase: RoomPhase::Connecting,
                generation: new_gen,
                peer_verified: false,
                room: None,
                verification: None,
                error: None,
            };
        }

        new_gen
    }

    /// Reset session state on leave or transport error (mirrors begin_session without
    /// incrementing the generation — the loop will already be exiting or gone).
    pub fn clear_session_state(&self) {
        self.peer_verified.store(false, Ordering::SeqCst);
        let generation = self.session_generation.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(mut snapshot) = self.room_snapshot.write() {
            *snapshot = RoomSnapshot {
                phase: RoomPhase::Idle,
                generation,
                peer_verified: false,
                room: None,
                verification: None,
                error: None,
            };
        }
    }

    pub fn room_snapshot(&self) -> RoomSnapshot {
        self.room_snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default()
    }

    pub fn transition_room(&self, generation: u64, phase: RoomPhase) -> bool {
        transition_room_snapshot(
            &self.room_snapshot,
            &self.session_generation,
            generation,
            phase,
            None,
            None,
            None,
        )
        .is_some()
    }

    pub fn transition_room_with(
        &self,
        generation: u64,
        phase: RoomPhase,
        room: Option<String>,
        verification: Option<VerificationState>,
        error: Option<AppError>,
    ) -> Option<RoomSnapshot> {
        transition_room_snapshot(
            &self.room_snapshot,
            &self.session_generation,
            generation,
            phase,
            room,
            verification,
            error,
        )
    }
}
pub fn transition_room_snapshot(
    room_snapshot: &Arc<RwLock<RoomSnapshot>>,
    current_generation: &Arc<AtomicU64>,
    generation: u64,
    phase: RoomPhase,
    room: Option<String>,
    verification: Option<VerificationState>,
    error: Option<AppError>,
) -> Option<RoomSnapshot> {
    if current_generation.load(Ordering::SeqCst) != generation {
        return None;
    }
    let mut snapshot = room_snapshot.write().ok()?;
    if snapshot.generation != generation {
        return None;
    }
    snapshot.phase = phase;
    snapshot.peer_verified = phase == RoomPhase::Active;
    if let Some(room) = room {
        snapshot.room = Some(room);
    }
    if let Some(verification) = verification {
        snapshot.verification = Some(verification);
    }
    snapshot.error = error;
    Some(snapshot.clone())
}
