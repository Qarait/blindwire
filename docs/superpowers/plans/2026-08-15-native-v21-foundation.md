# BlindWire Native Protocol 2.1 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`-`) syntax for tracking.

**Goal:** Restore the version-isolated signaling-v4 relay and implement the native Protocol 2.1 session, including authenticated recovery, ratcheting, terminal burn, and native end-to-end coverage.

**Architecture:** Keep the existing signaling-v3 implementation and `SecureSession` behavior intact. Add a strict v4 packet codec and room state machine on the server, a v4 WebSocket transport that exposes only control events and parsed opaque protocol frames, and a native `SecureSessionV21` that owns Noise, application, and recovery secrets. The browser application remains out of scope until this native slice is green.

**Tech Stack:** Rust 2021 workspace, Tokio, tokio-tungstenite, DashMap, SHA-256/HMAC/HKDF, existing `blindwire-core` Noise/frame/application/recovery APIs, Rust integration tests.

## Global Constraints

- Use `docs/superpowers/specs/2026-08-15-native-v21-foundation-design.md` as the normative design.
- Preserve signaling-v3 packet behavior and all existing v3 tests.
- Accept only binary signaling packets; malformed packets, wrong versions, wrong roles, wrong order, oversized frames, unauthorized capabilities, and duplicate terminal actions produce one sanitized error and terminate the offending connection.
- Relay frames are opaque to `blindwire-server`; the server may validate the outer length but must not parse or persist Noise/application payloads.
- Opaque relay payloads are 1 through 4096 bytes and use a two-byte big-endian length.
- The signaling-v4 wire version byte is exactly `0x04`.
- Room identifiers, tokens, capabilities, fingerprints, and contributions are 32-byte values; epochs are big-endian `u64`.
- Both roles must send `HANDSHAKE_COMPLETE` before the server emits `HANDSHAKE_CONFIRMED` or accepts recovery registration.
- Recovery proofs bind room, role, epoch, and fresh Noise fingerprint; successful recovery consumes the old continuity secret and installs the ratcheted replacement.
- Burn is terminal on both sides; no public API exposes secret buffers, recovery capabilities, raw continuity material, or relay plaintext.
- Every task ends with focused tests, formatting, and an intentional commit before the next task starts.

---

## File map

| Path | Responsibility |
| --- | --- |
| `blindwire-server/src/protocol.rs` | Strict v4 client/server packet enums, codecs, constants, and parser tests. |
| `blindwire-server/src/room.rs` | Versioned room lifecycle, token ownership, two-sided confirmation, recovery capabilities, epoch rotation, expiry, and burn. |
| `blindwire-server/src/lib.rs` | Preserve v3 orchestration while dispatching v4 connections to the new codec/room state. |
| `blindwire-server/tests/signaling_v4.rs` | WebSocket-level v4 lifecycle, ordering, queue, recovery, and burn tests. |
| `blindwire-transport/src/relay.rs` | Share the existing TLS/pinning WebSocket connector with v4 without changing v3 packet behavior. |
| `blindwire-transport/src/relay_v4.rs` | v4 join/resume/control packet serialization, strict server event parsing, opaque frame send/receive, and relay tests. |
| `blindwire-transport/src/session_v21.rs` | Native Protocol 2.1 handshake, SAS verification gate, application envelopes, recovery, ratcheting, and terminal state machine. |
| `blindwire-transport/src/lib.rs` | Export the v4 session API while retaining the existing v3 API. |
| `blindwire-transport/src/error.rs` | Add only the terminal/session errors required by the v4 relay and recovery state machine. |
| `blindwire-transport/tests/e2e_v21_test.rs` | Two native peers against an ephemeral local server covering initial handshake, text/ack, recovery, and burn. |

Historical files under `C:/tmp` may be consulted to recover intent, but the reviewed design and red tests are authoritative. Do not copy an artifact without reconciling it with the current core APIs and the v4 wire table.

## Task 1: Add the strict signaling-v4 packet codec

**Files:**
- Create: `blindwire-server/src/protocol.rs`
- Modify: `blindwire-server/src/lib.rs:1-10` to expose the module without moving v3 behavior yet
- Test: `blindwire-server/src/protocol.rs` unit tests

**Interfaces:**
- Produces `MAX_RELAY_FRAME: usize = 4096`.
- Produces `SignalingVersion::{V3,V4}` with `as_byte()`.
- Produces `Role::{Initiator,Responder}` with `as_byte()`, `other()`, and strict parsing.
- Produces `ClientPacket::{Join,Relay,Quit,HandshakeComplete,RegisterRecovery,Resume,Burn}`.
- Produces `ServerPacket::{Relay,PeerJoined,PeerQuit,Expired,Error,Token,HandshakeConfirmed,RecoveryRegistered,PeerResuming,ResumeReady,RoomBurned}`.
- `ClientPacket::parse_v4(data: &[u8]) -> Result<ClientPacket, ParseError>` accepts only the v4 layouts.
- `ClientPacket::encode(&self) -> Vec<u8>` emits canonical v4 bytes.
- `ServerPacket::parse(data: &[u8]) -> Result<ServerPacket, ParseError>` strictly validates server packets used by the client.
- `ServerPacket::encode(&self) -> Vec<u8>` emits canonical bytes.

- [ ] **Step 1: Write failing exact-layout tests**

Add tests for every canonical packet and assert the exact bytes. The join and resume tests must include the literal v4 byte:

~~~rust
#[test]
fn v4_join_and_resume_use_exact_lengths_and_version() {
    let room = [0x11; 32];
    let token = [0x22; 32];
    let join = ClientPacket::Join {
        role: Role::Responder,
        room,
        token: Some(token),
    };
    assert_eq!(join.encode().len(), 67);
    assert_eq!(join.encode()[..3], [0x00, b'r', 0x04]);

    let resume = ClientPacket::Resume {
        role: Role::Initiator,
        room,
        capability: [0x33; 32],
        epoch: 7,
    };
    assert_eq!(resume.encode().len(), 75);
    assert_eq!(resume.encode()[..3], [0x05, b'i', 0x04]);
}
~~~

Also cover relay lengths 1 and 4096, rejection of zero/4097/truncated/trailing payloads, exact one-byte controls, invalid role/version/opcode, invalid error lengths, and all server packet round trips.

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

~~~powershell
cargo test -p blindwire-server protocol -- --nocapture
~~~

Expected: FAIL because `blindwire_server::protocol` and its packet types do not exist.

- [ ] **Step 3: Implement the minimal codec**

Use fixed-size array copies after checking lengths. For `Relay`, preserve the complete encoded packet in the enum so the server can forward the opaque bytes without inspecting the frame. Reject every packet with extra bytes. Map unknown opcodes to `ParseError::Opcode`, known opcodes with invalid lengths to `ParseError::Format`, and a non-`0x04` version to `ParseError::Version`.

The public shape must include:

~~~rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientPacket {
    Join { role: Role, room: [u8; 32], token: Option<[u8; 32]> },
    Relay(Vec<u8>),
    Quit,
    HandshakeComplete,
    RegisterRecovery([u8; 32]),
    Resume { role: Role, room: [u8; 32], capability: [u8; 32], epoch: u64 },
    Burn,
}
~~~

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

~~~powershell
cargo test -p blindwire-server protocol -- --nocapture
cargo fmt --all -- --check
~~~

Expected: all codec tests pass and formatting is clean.

- [ ] **Step 5: Commit the codec**

~~~powershell
git add blindwire-server/src/protocol.rs blindwire-server/src/lib.rs
git commit -m "feat: add signaling v4 packet codec"
~~~

## Task 2: Implement the v4 room lifecycle state machine

**Files:**
- Create: `blindwire-server/src/room.rs`
- Modify: `blindwire-server/Cargo.toml` to add `subtle` if the current dependency graph does not already provide it directly
- Test: `blindwire-server/src/room.rs` unit tests

**Interfaces:**
- Produces `ROOM_TTL = Duration::from_secs(3600)` and `RECOVERY_TTL = Duration::from_secs(600)`.
- Produces `RoomError::{RoleTaken,Unauthorized,Expired,VersionMismatch,Burned}`.
- Produces `Room::new(id: [u8;32], version: SignalingVersion, created_at: Instant) -> Room`.
- Produces `Room::join_initial(&mut self, role: Role, token: Option<[u8;32]>, now: Instant) -> Result<Option<[u8;32]>, RoomError>`.
- Produces `Room::complete_handshake(&mut self, role: Role, now: Instant) -> Result<bool, RoomError>`, where `true` means this call caused two-sided confirmation.
- Produces `Room::register_recovery(&mut self, role: Role, capability: [u8;32], now: Instant) -> Result<(), RoomError>`.
- Produces `Room::begin_resume(&mut self, role: Role, capability: [u8;32], expected_epoch: u64, now: Instant) -> Result<u64, RoomError>`.
- Produces `Room::detach(&mut self, role: Role, now: Instant)`.
- Produces `Room::burn(&mut self, role: Role) -> Result<(), RoomError>`.
- Capability storage is `SHA-256(capability)` only; raw capability bytes are never retained.

- [ ] **Step 1: Write failing transition tests**

Test these transitions independently:

~~~rust
#[test]
fn only_the_tokened_responder_can_join_and_both_completions_confirm() {
    let now = Instant::now();
    let mut room = Room::new([0x41; 32], SignalingVersion::V4, now);
    let token = room.join_initial(Role::Initiator, None, now).unwrap().unwrap();
    assert!(room.join_initial(Role::Responder, Some([0; 32]), now).is_err());
    assert_eq!(room.join_initial(Role::Responder, Some(token), now).unwrap(), None);
    assert!(!room.complete_handshake(Role::Initiator, now).unwrap());
    assert!(room.complete_handshake(Role::Responder, now).unwrap());
    assert!(room.is_confirmed());
}

#[test]
fn resume_requires_hash_match_detachment_and_current_epoch_then_rotates_once() {
    let now = Instant::now();
    let mut room = confirmed_room(now);
    let capability = [0x52; 32];
    room.register_recovery(Role::Initiator, capability, now).unwrap();
    room.detach(Role::Initiator, now);
    let next = room.begin_resume(Role::Initiator, capability, 0, now).unwrap();
    assert_eq!(next, 1);
    assert!(room.begin_resume(Role::Initiator, capability, 0, now).is_err());
}
~~~

Add tests for role collision, wrong token, duplicate token reservation, unconfirmed registration, raw-capability non-retention, stale epoch, wrong capability, recovery-window expiry using an advanced `Instant`, room TTL expiry, burn tombstone behavior, and post-burn rejection.

- [ ] **Step 2: Run the room tests and verify they fail**

Run:

~~~powershell
cargo test -p blindwire-server room -- --nocapture
~~~

Expected: FAIL because `Room` is not defined.

- [ ] **Step 3: Implement the minimal room state**

Keep the lifecycle fields private: room id/version/creation time, token and reservation state, two occupied flags, two completion flags, confirmed flag, two capability hashes, two detached timestamps, epoch, and burned flag. Use constant-time comparison for token and capability hashes. `burn` clears all volatile secrets/state but retains the burned tombstone until the room entry is removed by server expiry.

- [ ] **Step 4: Run room tests and static checks**

Run:

~~~powershell
cargo test -p blindwire-server room -- --nocapture
cargo clippy -p blindwire-server --all-targets -- -D warnings
cargo fmt --all -- --check
~~~

Expected: all room tests pass with no Clippy or formatting findings.

- [ ] **Step 5: Commit room state**

~~~powershell
git add blindwire-server/src/room.rs blindwire-server/Cargo.toml
git commit -m "feat: add signaling v4 room lifecycle"
~~~

## Task 3: Route v4 connections through the server without changing v3

**Files:**
- Modify: `blindwire-server/src/lib.rs` in the connection dispatcher and new v4 orchestration helpers
- Create: `blindwire-server/tests/signaling_v4.rs`
- Modify: `blindwire-server/Cargo.toml` only if the v4 test harness needs a direct test dependency

**Interfaces:**
- Keep `pub async fn run_server(listener: TcpListener)` unchanged for existing callers.
- Add an internal `V4RoomState` containing `Room` plus per-role bounded `mpsc::Sender<Vec<u8>>` slots; it must not contain plaintext, Noise keys, continuity secrets, or resume proofs.
- The first binary WebSocket packet is inspected only for the version byte: `0x03` stays on the existing v3 path; `0x04` enters v4 parsing/orchestration.
- The v4 handler sends `ServerPacket` bytes and closes after one sanitized protocol error.

- [ ] **Step 1: Add red WebSocket lifecycle tests**

Start `run_server` on an ephemeral listener and use `tokio_tungstenite::connect_async`. Cover:

~~~rust
#[tokio::test]
async fn v4_join_token_peer_join_and_two_sided_confirmation() {
    let (url, server_task) = start_test_server().await;
    let (mut initiator, _) = connect_v4_initiator(&url, [0x61; 32]).await;
    let token = expect_token(&mut initiator).await;
    let mut responder = connect_v4_responder(&url, [0x61; 32], token).await;
    assert_eq!(next_binary(&mut initiator).await, vec![0x02]);
    assert_eq!(next_binary(&mut responder).await, vec![0x02]);

    send_binary(&mut initiator, vec![0x03]).await;
    send_binary(&mut responder, vec![0x03]).await;
    assert_eq!(next_binary(&mut initiator).await, vec![0x07]);
    assert_eq!(next_binary(&mut responder).await, vec![0x07]);
    server_task.abort();
}
~~~

Add tests for opaque relay byte preservation, queue capacity 32, wrong packet order, malformed packet termination, one-sided confirmation not being enough, token reuse/role collision, registration only after confirmation, recovery resume notifications, stale/wrong capabilities, expiry, and burn notifying the connected peer.

- [ ] **Step 2: Run the new integration tests and verify they fail**

Run:

~~~powershell
cargo test -p blindwire-server --test signaling_v4 -- --nocapture
~~~

Expected: FAIL because the current dispatcher rejects v4 or has no v4 room state.

- [ ] **Step 3: Refactor only the dispatch seam**

Move the existing v3 first-packet handling behind a helper that receives the already-read first packet. In `run_server`, read the first binary packet once, preserve the existing v3 behavior for version `0x03`, and call a new v4 handler for version `0x04`. Keep existing connection limits, IP accounting, TTL cleanup, and v3 packet constants unchanged.

- [ ] **Step 4: Implement v4 join and relay handling**

Create the v4 room map, create an initiator room on the first join, return `TOKEN`, require the exact token for the responder, send `PEER_JOINED` to both, and forward only the original validated `RELAY` bytes to the opposite sender. Reject relay traffic before both roles exist, after detachment, after burn, or after queue saturation with one error followed by connection termination.

- [ ] **Step 5: Implement v4 handshake, recovery, and burn controls**

For `HANDSHAKE_COMPLETE`, call `Room::complete_handshake`; emit `HANDSHAKE_CONFIRMED` to both only when the second role completes. For `REGISTER_RECOVERY`, store only the hash and emit `RECOVERY_REGISTERED` to the registering role. For `RESUME`, call `Room::begin_resume`; emit `PEER_RESUMING` to the currently connected peer and `RESUME_READY` with the new epoch to the resuming role. For `BURN`, clear the room state and send `ROOM_BURNED` to every connected role before closing.

- [ ] **Step 6: Run v3 and v4 integration tests**

Run:

~~~powershell
cargo test -p blindwire-server --test level3_integration -- --nocapture
cargo test -p blindwire-server --test signaling_v4 -- --nocapture
cargo test --workspace --all-targets
~~~

Expected: the existing v3 suite and all v4 tests pass.

- [ ] **Step 7: Commit server integration**

~~~powershell
git add blindwire-server/src/lib.rs blindwire-server/tests/signaling_v4.rs
git commit -m "feat: route signaling v4 rooms through the relay"
~~~

## Task 4: Add the native signaling-v4 relay transport

**Files:**
- Create: `blindwire-transport/src/relay_v4.rs`
- Modify: `blindwire-transport/src/relay.rs` to expose one shared `pub(crate)` WebSocket/TLS connector
- Modify: `blindwire-transport/src/lib.rs` to register the module
- Modify: `blindwire-transport/src/error.rs` for v4-specific terminal errors
- Test: `blindwire-transport/src/relay_v4.rs` unit tests

**Interfaces:**
- Produces `RelayEventV4::{Frame,PeerJoined,PeerQuit,Expired,Error,HandshakeConfirmed,RecoveryRegistered,PeerResuming,ResumeReady,RoomBurned}`.
- Produces `RelayTransportV4::connect_initial(config: &TransportConfig) -> Result<(RelayTransportV4, Option<[u8;32]>), TransportError>`.
- Produces `RelayTransportV4::connect_resume(config: &TransportConfig, capability: [u8;32], epoch: u64) -> Result<RelayTransportV4, TransportError>`.
- Produces `send_frame(&mut self, frame: Frame)`, `recv_event(&mut self)`, `send_handshake_complete(&mut self)`, `register_recovery(&mut self, capability: [u8;32])`, `burn(&mut self)`, and `close(&mut self)`.
- The existing v3 `RelayTransport` must continue to send the v3 join byte `0x03`; only the new type emits the v4 join/resume bytes.

- [ ] **Step 1: Write failing packet and event tests**

Test the v4 join bytes, resume bytes, relay length boundaries, exact server event parsing, malformed relay packets, unknown server opcodes, wrong event lengths, and preservation of a valid `Frame`:

~~~rust
#[test]
fn relay_event_parser_rejects_length_mismatch_without_parsing_payload() {
    let malformed = vec![0x01, 0x00, 0x05, 0x00, 0x04, 0xaa];
    assert!(parse_server_packet(&malformed).is_err());
}
~~~

- [ ] **Step 2: Run relay tests and verify they fail**

Run:

~~~powershell
cargo test -p blindwire-transport relay_v4 -- --nocapture
~~~

Expected: FAIL because `relay_v4` and its parser do not exist.

- [ ] **Step 3: Refactor the shared WebSocket connector**

Extract the current TLS roots, custom verifier, official-host handling, TOFU pin-store checks, and `connect_async_tls_with_config` call from `relay.rs` into a `pub(crate)` helper returning `WebSocketStream<MaybeTlsStream<TcpStream>>`. Keep all existing v3 join and event parsing in place and make its tests pass before adding v4 behavior.

- [ ] **Step 4: Implement v4 connect and event parsing**

Encode initial initiator join as `[0x00, b'i', 0x04, room]`, initial responder join as `[0x00, b'r', 0x04, room, token]`, and resume as `[0x05, role, 0x04, room, capability, epoch_be]`. Accept only the expected `TOKEN` or `PEER_JOINED` during initial connect. Convert server packets into `RelayEventV4`; parse relay length exactly, then call `Frame::parse` on the frame bytes. Any invalid event returns a terminal `TransportError`.

- [ ] **Step 5: Implement controls and close semantics**

Encode `HANDSHAKE_COMPLETE`, `REGISTER_RECOVERY`, and `BURN` as their one-command packets. `send_frame` must serialize `Frame::to_wire()` inside `[0x01, len_be, opaque_frame]`. `recv_event` must ignore only allowed asynchronous `PEER_JOINED` events where the session state permits it; it must not silently discard errors, burn, expiry, or unexpected recovery controls.

- [ ] **Step 6: Run focused transport checks**

Run:

~~~powershell
cargo test -p blindwire-transport relay_v4 -- --nocapture
cargo test -p blindwire-transport --lib
cargo clippy -p blindwire-transport --all-targets -- -D warnings
cargo fmt --all -- --check
~~~

Expected: all v3 and v4 transport tests pass.

- [ ] **Step 7: Commit the v4 relay transport**

~~~powershell
git add blindwire-transport/src/relay.rs blindwire-transport/src/relay_v4.rs blindwire-transport/src/lib.rs blindwire-transport/src/error.rs
git commit -m "feat: add native signaling v4 relay transport"
~~~

## Task 5: Implement the native Protocol 2.1 initial session

**Files:**
- Create: `blindwire-transport/src/session_v21.rs`
- Modify: `blindwire-transport/src/lib.rs` to register and re-export the v4 session types
- Modify: `blindwire-transport/src/error.rs` for verification, recovery, and invalid-envelope errors
- Test: `blindwire-transport/tests/e2e_v21_test.rs` initial-session tests

**Interfaces:**
- Produces `SessionEventV21::{VerificationReady,PeerVerified,TextReceived,MessageAcknowledged,Recovering,Recovered,PeerDisconnected,RoomBurned}`.
- Produces `SecureSessionV21::connect_initial(config: TransportConfig) -> Result<(SecureSessionV21, Option<[u8;32]>), TransportError>`.
- Produces `handshake(&mut self)`, `confirm_user_verified(&mut self)`, `send_text(&mut self, text: &str) -> Result<MessageId, TransportError>`, `recv_event(&mut self) -> Result<SessionEventV21, TransportError>`, and consuming `burn(self)`.
- Keeps Noise session, continuity secret, capability, pending message map, deduplicator, verification flags, and terminal flag private.
- Produces a `Debug` implementation that reports role/epoch/verification/terminal state only.

- [ ] **Step 1: Add a failing two-peer initial handshake test**

Create a local server fixture that starts `blindwire_server::run_server` on `127.0.0.1:0`. Connect the initiator, obtain its token, connect the responder, and assert that both sessions emit `VerificationReady` after `handshake()`. Use `tokio::join!` or two spawned tasks so neither peer blocks the other.

~~~rust
let (url, server_task) = start_test_server().await;
let (mut initiator, token) = SecureSessionV21::connect_initial(
    TransportConfig::initiator(&url, [0x61; 32]).with_insecure_dev()
).await.unwrap();
let (mut responder, responder_token) = SecureSessionV21::connect_initial(
    TransportConfig::responder(&url, [0x61; 32], token.unwrap()).with_insecure_dev()
).await.unwrap();
assert!(responder_token.is_none());
let (initiator_result, responder_result) = tokio::join!(
    initiator.handshake(),
    responder.handshake()
);
initiator_result.unwrap();
responder_result.unwrap();
assert_eq!(initiator.recv_event().await.unwrap(), SessionEventV21::VerificationReady);
assert_eq!(responder.recv_event().await.unwrap(), SessionEventV21::VerificationReady);
server_task.abort();
~~~

- [ ] **Step 2: Run the initial-session test and verify it fails**

Run:

~~~powershell
cargo test -p blindwire-transport --test e2e_v21_test initial_handshake -- --nocapture
~~~

Expected: FAIL because the v4 session module is absent.

- [ ] **Step 3: Implement initial Noise and relay confirmation**

Create a fresh `NoiseSession` for the configured role. The initiator sends the first handshake frame; both roles consume only `RelayEventV4::Frame` handshake frames until Noise is active; both send `HANDSHAKE_COMPLETE`; both wait for `HandshakeConfirmed`. Treat a peer disconnect, expiry, malformed frame, unexpected control, or cryptographic failure as terminal.

- [ ] **Step 4: Implement encrypted recovery contributions and readiness**

Generate one 32-byte local contribution with `blindwire_core::entropy::random_array`, send it in an encrypted `ApplicationEnvelope::RecoveryContribution`, receive exactly one peer contribution, order them initiator then responder, and call `derive_continuity_secret(&session_id, initiator, responder)`. Generate a fresh recovery capability, call `register_recovery`, and require `RecoveryRegistered` before exposing `VerificationReady`.

- [ ] **Step 5: Implement user verification and application flow**

`confirm_user_verified` sends one encrypted `UserVerified` envelope and sets the local flag. `send_text` must return `VerificationRequired` before both flags are true; after verification, encode/encrypt a `Text`, store the `MessageId` in the pending map, and return it. `recv_event` must:

1. mark the peer verified on `UserVerified`;
2. reject text/ack before both verification flags are true;
3. deduplicate text identifiers using `MessageDeduplicator`;
4. send an encrypted `Ack` for every accepted text envelope;
5. emit `TextReceived` only for the first observation;
6. remove pending IDs and emit `MessageAcknowledged`;
7. terminate on unexpected recovery envelopes, invalid application envelopes, decryption errors, and post-terminal input.

- [ ] **Step 6: Add initial flow and terminal tests**

Cover SAS readiness on both peers, both-sided verification gate, text/ack round trip, duplicate text delivery, malformed encrypted envelope, forged ciphertext, encrypted burn, server expiry, peer quit, and post-burn API calls. Assert that the public event values contain text and IDs only, never capabilities or continuity bytes.

- [ ] **Step 7: Run focused tests and commit**

Run:

~~~powershell
cargo test -p blindwire-transport --test e2e_v21_test -- --nocapture
cargo test -p blindwire-transport --lib
cargo clippy -p blindwire-transport --all-targets -- -D warnings
cargo fmt --all -- --check
~~~

Expected: all initial Protocol 2.1 tests pass.

~~~powershell
git add blindwire-transport/src/session_v21.rs blindwire-transport/src/lib.rs blindwire-transport/src/error.rs blindwire-transport/tests/e2e_v21_test.rs
git commit -m "feat: add native protocol 2.1 session"
~~~

## Task 6: Add authenticated native recovery and continuity ratcheting

**Files:**
- Modify: `blindwire-transport/src/relay_v4.rs` to support resume event sequencing
- Modify: `blindwire-transport/src/session_v21.rs` to add the snapshot/resume path
- Modify: `blindwire-transport/src/error.rs` for stale epoch, invalid proof, and unavailable recovery errors
- Modify: `blindwire-transport/tests/e2e_v21_test.rs` with recovery and adversarial cases

**Interfaces:**
- Produces non-cloneable `RecoverySnapshotV21` containing private continuity state, capability, epoch, verification state, pending messages, and deduplicator state.
- Produces `recovery_snapshot(&mut self) -> Result<RecoverySnapshotV21, TransportError>`; this consumes the active session's continuity/capability state and terminates the old Noise session.
- Produces `resume(config: TransportConfig, snapshot: RecoverySnapshotV21) -> Result<SecureSessionV21, TransportError>`.
- `resume` uses `RelayTransportV4::connect_resume`, creates fresh Noise keys, performs a fresh handshake and explicit relay confirmation, sends an encrypted `ResumeProof`, exchanges fresh recovery contributions, calls `ratchet_continuity_secret`, registers a fresh capability, and emits `Recovering` then `Recovered`.
- A successful resume consumes the previous continuity secret; the old snapshot cannot be reused.

- [ ] **Step 1: Add failing recovery tests**

Add a test that detaches one role after initial verification, snapshots it, reconnects with the snapshot, and verifies fresh recovery. Assert that old epoch/capability/proof reuse, wrong role, wrong room, wrong fingerprint, forged recovery ciphertext, duplicate contribution, and stale snapshot all terminate.

~~~rust
let snapshot = initiator.recovery_snapshot().unwrap();
let mut recovered = SecureSessionV21::resume(initiator_config, snapshot).await.unwrap();
assert_eq!(recovered.recv_event().await.unwrap(), SessionEventV21::Recovering);
assert_eq!(recovered.recv_event().await.unwrap(), SessionEventV21::Recovered);
~~~

The snapshot is consumed by the first `resume` call, so a second use is rejected by ownership rather than by a runtime clone. The test must also confirm that a separately captured stale snapshot/capability is rejected after the server epoch has advanced, that a successful ratchet changes the continuity-derived proof result, and that text remains gated until both users are verified in the fresh session.

- [ ] **Step 2: Run recovery tests and verify they fail**

Run:

~~~powershell
cargo test -p blindwire-transport --test e2e_v21_test recovery -- --nocapture
~~~

Expected: FAIL because `resume` is not implemented and the relay does not yet expose the complete resume event sequence.

- [ ] **Step 3: Implement resume relay sequencing**

When the server accepts a resume, wait for `PEER_RESUMING`/`RESUME_READY` in the role-specific order, perform a fresh Noise XX handshake over the same room, send `HANDSHAKE_COMPLETE`, and require a new two-sided `HANDSHAKE_CONFIRMED`. Never treat a resume control packet as an application frame.

- [ ] **Step 4: Implement role/epoch/fingerprint-bound proof verification**

After fresh Noise is active, obtain the fresh Noise fingerprint, compute the expected proof with `compute_resume_proof(&continuity, &session_id, role, epoch, &fingerprint)`, send it as an encrypted `ResumeProof`, and require the peer to verify the exact room/role/epoch/fingerprint transcript. Any mismatch calls the session's terminal failure path.

- [ ] **Step 5: Implement fresh contributions and consuming ratchet**

Exchange one fresh contribution per role over the authenticated fresh Noise channel. Order them initiator then responder and call:

~~~rust
let next = ratchet_continuity_secret(
    previous_continuity,
    &session_id,
    new_epoch,
    &initiator_contribution,
    &responder_contribution,
)?;
~~~

Replace the old secret only after all proof and contribution checks pass. Generate/register a fresh capability and update the epoch. Do not retain the old secret or capability in any field, event, log, or error.

- [ ] **Step 6: Verify recovery, ratchet, and terminal paths**

Run:

~~~powershell
cargo test -p blindwire-transport --test e2e_v21_test recovery -- --nocapture
cargo test -p blindwire-core --features worker-recovery-snapshot
cargo clippy -p blindwire-transport --all-targets -- -D warnings
cargo fmt --all -- --check
~~~

Expected: recovery and core vectors pass, stale/forged inputs terminate, and no warnings remain.

- [ ] **Step 7: Commit recovery**

~~~powershell
git add blindwire-transport/src/relay_v4.rs blindwire-transport/src/session_v21.rs blindwire-transport/src/error.rs blindwire-transport/tests/e2e_v21_test.rs
git commit -m "feat: add authenticated native session recovery"
~~~

## Task 7: Run the complete native foundation verification

**Files:**
- Modify: only files needed to correct failures found by the verification commands
- Test: all existing workspace tests plus the new v4/native suites

**Interfaces:**
- No new public API is introduced in this task.
- The final public surface must keep v3 types available and add only the reviewed v4/session-v21 types.

- [ ] **Step 1: Run the full workspace tests**

~~~powershell
cargo test --workspace --all-targets
~~~

Expected: every existing CLI, core, desktop, server, transport, and web-core host test passes, plus all v4/native tests.

- [ ] **Step 2: Run strict formatting and Clippy**

~~~powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
~~~

Expected: both commands exit successfully.

- [ ] **Step 3: Run the browser-core WASM gate with the known compatible ChromeDriver**

~~~powershell
$env:Path = "C:/tmp/chromedriver-win64-150.0.7871.129/chromedriver-win64;$env:Path"
wasm-pack test --headless --chrome blindwire-web-core
~~~

Expected: the existing nine browser-core tests pass. Firefox remains an environment gate only if the executable is still unavailable; record that limitation without weakening native verification.

- [ ] **Step 4: Inspect the final diff for secret leakage**

~~~powershell
git diff origin/codex/finish-beta-release-blockers...HEAD --stat
git diff origin/codex/finish-beta-release-blockers...HEAD -- blindwire-server blindwire-transport
rg -n "println!|debug!|info!|warn!|error!" blindwire-server/src blindwire-transport/src
git diff --check
~~~

Expected: relay/server code contains no plaintext or key logging; public events contain no secret arrays; diff check is clean.

- [ ] **Step 5: Commit any narrowly scoped verification correction**

If a verification correction is required, add only the failing test and its minimal fix, rerun the complete affected command, and commit it with a message that names the corrected invariant. Do not alter the v3 wire contract or expand scope into the browser application.

## Task 8: Finalize and hand off the native foundation

**Files:**
- Modify: `docs/superpowers/specs/2026-08-15-native-v21-foundation-design.md` only if implementation discovered a genuine normative correction
- Create: no new product code

- [ ] **Step 1: Confirm the acceptance checklist**

Confirm that `blindwire-server/src/protocol.rs`, `blindwire-server/src/room.rs`, `blindwire-transport/src/relay_v4.rs`, and `blindwire-transport/src/session_v21.rs` exist; v3 tests remain green; full tests, strict Clippy, and formatting pass; relay code never sees plaintext; and recovery consumes/ratchets continuity state.

- [ ] **Step 2: Inspect commit history and working tree**

~~~powershell
git log --oneline -8
git status -sb
~~~

Expected: the task commits are intentional, the working tree is clean, and the branch is ready to publish.

- [ ] **Step 3: Publish only after verification**

~~~powershell
git push -u origin codex/finish-beta-release-blockers
~~~

Expected: the remote branch contains the native foundation commits and no browser implementation has been included.

The next separate design/plan must cover the browser worker, WebSocket relay client, encrypted IndexedDB vault, controller/API boundary, invite/QR flow, UI, CSP/WASM integrity, and Firefox/browser matrix.
