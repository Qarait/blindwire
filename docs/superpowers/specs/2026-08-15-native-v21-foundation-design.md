# BlindWire Native Protocol 2.1 Foundation

## Status

Design approved in conversation. This slice restores the native signaling-v4
relay contract and Protocol 2.1 transport foundation. The browser application
is explicitly deferred until these contracts are implemented and verified.

## Context

The current pushed branch contains the shared Protocol 2.1 core primitives and
the narrow WebAssembly session machine. It does not contain the recovered
Task 4/5 native files:

- signaling-v4 server parsing and room state;
- the native signaling-v4 relay transport;
- the native Protocol 2.1 secure session;
- native recovery, burn, and interoperability tests.

Existing signaling v3 and the current desktop release behavior must remain
compatible and unchanged unless a test demonstrates a required shared-core
adjustment.

## Goals

1. Add a version-isolated signaling-v4 protocol and room state machine.
2. Add a native relay transport that forwards only opaque encrypted frames.
3. Add a native Protocol 2.1 session with the same security ordering as the
   restored WebAssembly session.
4. Authenticate recovery over a fresh Noise session, bind proofs to role,
   room, epoch, and fingerprint, and ratchet continuity secrets after
   recovery.
5. Make burn and all malformed or unauthenticated protocol input terminal.
6. Preserve all existing v3 behavior and pass the complete workspace gates.

## Non-goals

- No browser UI, worker bridge, IndexedDB vault, or production web bundle.
- No plaintext inspection or message persistence in the relay.
- No protocol-version negotiation that silently mixes v3 and v4 rooms.
- No new cryptographic primitive or replacement for the existing Noise/core
  implementation.
- No deployment changes in this slice.

## Architecture

### Versioned signaling server

Add blindwire-server/src/protocol.rs and blindwire-server/src/room.rs,
keeping the existing v3 behavior isolated from v4 code. The server library
owns connection orchestration while the protocol module owns exact packet
parsing/serialization and the room module owns lifecycle invariants.

The v4 relay accepts binary packets only. It stores volatile room metadata:
role ownership, token/capability hashes, queue state, recovery epoch, and
expiry. It never stores plaintext, Noise keys, continuity secrets, or resume
proofs.

### Signaling-v4 wire contract

All multi-byte integers are big-endian. Opaque encrypted frames have a
one-to-4096-byte payload and are length-prefixed.

Client packets:

| Packet | Layout |
| --- | --- |
| JOIN initiator | 00 69 04 ROOM[32] |
| JOIN responder | 00 72 04 ROOM[32] TOKEN[32] |
| RELAY | 01 LENGTH[2] OPAQUE_FRAME[LENGTH] |
| QUIT | 02 |
| HANDSHAKE_COMPLETE | 03 |
| REGISTER_RECOVERY | 04 CAPABILITY[32] |
| RESUME | 05 ROLE[1] 04 ROOM[32] CAPABILITY[32] EPOCH[8] |
| BURN | 06 |

Server packets:

| Packet | Layout |
| --- | --- |
| RELAY | 01 LENGTH[2] OPAQUE_FRAME[LENGTH] |
| PEER_JOINED | 02 |
| PEER_QUIT | 03 |
| EXPIRED | 04 |
| ERROR | 05 CODE[1] |
| TOKEN | 06 TOKEN[32] |
| HANDSHAKE_CONFIRMED | 07 |
| RECOVERY_REGISTERED | 08 |
| PEER_RESUMING | 09 EPOCH[8] |
| RESUME_READY | 0A EPOCH[8] |
| ROOM_BURNED | 0B |

Malformed packets, wrong versions, wrong roles, oversized frames, duplicate
terminal actions, and unauthorized capabilities produce one sanitized error
and terminate the offending connection.

### Room lifecycle

An initiator creates a room and receives a single-use responder token. The
responder must present that token. Both roles must send HANDSHAKE_COMPLETE;
one side alone never enables recovery. The room has a fixed lifetime and
recovery never extends it.

After confirmation, each role may register one fresh recovery capability. The
relay stores only a hash of each capability. A resume must match the room,
role, capability, current epoch, confirmation state, burn state, and recovery
window. An accepted resume increments the epoch exactly once and replaces only
the matching role connection.

Burn removes the room, capability hashes, queued data, and future join/resume
ability. A connected peer receives ROOM_BURNED.

### Native Protocol 2.1 transport

Add blindwire-transport/src/relay_v4.rs for signaling-v4 WebSocket
serialization and relay events. Add
blindwire-transport/src/session_v21.rs for the native session state machine.

The session owns Noise and all application secrets. The relay transport sees
only signaling control packets and opaque Protocol 2.1 frames. The session
exposes user-visible events, but never exposes secret buffers, recovery
capabilities, or raw continuity material.

The lifecycle is:

1. Establish the role-bound signaling connection.
2. Complete Noise XX.
3. Wait for the relay's explicit two-sided confirmation.
4. Exchange recovery contributions inside the encrypted channel.
5. Derive and display the SAS.
6. Require local and peer user verification before text or acknowledgements.
7. Encrypt text, deduplicate received IDs, and acknowledge accepted messages.
8. Authenticate recovery through fresh Noise, role-bound resume proofs, fresh
   contributions, and continuity ratcheting.
9. Treat encrypted burn, malformed input, cryptographic failure, and expiry as
   terminal.

### Recovery binding

Recovery proofs use the already-restored core functions and bind:

- room identifier;
- role;
- monotonically increasing epoch;
- fresh recovery Noise fingerprint;
- continuity secret.

The native transport must consume the old continuity state after a successful
ratchet. A stale proof, wrong role, wrong room, wrong epoch, wrong fingerprint,
forged ciphertext, or replayed contribution terminates the session.

## Testing strategy

Implement tests before production changes for each boundary:

1. Protocol-v4 exact lengths, round trips, version isolation, and malformed
   packet rejection.
2. Room lifecycle: token use, role ownership, both-sided confirmation,
   capability hashing, epoch rotation, expiry, concurrent resume rejection,
   and burn.
3. Native transport end-to-end handshake, SAS equality, two-sided verification,
   text/ack flow, deduplication, recovery, ratcheting, and terminal burn.
4. Adversarial inputs: forged capability, wrong-role capability, stale epoch,
   forged recovery ciphertext, oversized frame, wrong packet order, and
   post-terminal operations.
5. Existing workspace tests, strict formatting, and Clippy with warnings
   denied.

## Acceptance criteria

This foundation slice is accepted only when:

- blindwire-server/src/protocol.rs and blindwire-server/src/room.rs exist
  with v4 integration coverage;
- blindwire-transport/src/relay_v4.rs and
  blindwire-transport/src/session_v21.rs exist with native end-to-end
  coverage;
- signaling v3 tests remain green;
- the full workspace test suite passes;
- strict Clippy and formatting pass for changed crates;
- no test or public API exposes keys, continuity secrets, or plaintext to the
  relay;
- the changes are committed separately from the later browser application.

## Implementation order

1. Restore and normalize the v4 server protocol and room modules.
2. Add red server integration tests, then implement the smallest room and
   orchestration changes required to make them green.
3. Restore the native relay-v4 transport and its parser/event tests.
4. Add red Protocol 2.1 native lifecycle tests, then implement the session
   machine and recovery path.
5. Run full verification and commit this foundation slice.
6. Only after this slice is green, design and implement the browser worker,
   relay client, vault, controller, and UI.

## Risks and mitigations

- Recovered artifacts may be incomplete. Use the normative wire contract and
  tests as the authority; do not blindly concatenate patches.
- V3 regressions. Keep v4 modules isolated and run the existing v3 suite after
  every server change.
- Secret leakage through convenience APIs. Keep secret-bearing types private or
  consuming and test public event payloads explicitly.
- Recovery state divergence. Share the core recovery functions and require
  cross-role vectors plus a native two-peer recovery test.
