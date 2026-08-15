# Two-Sided Handshake Confirmation Design

**Status:** Approved

**Date:** 2026-07-19

## Goal

BlindWire must consume a responder invitation only after both peers have completed the same Noise XX connection attempt. The mechanism must remain invisible to ordinary users, preserve a usable retry path for interrupted handshakes, and expose no keys, SAS values, transcript hashes, plaintext, or stable identity data to the relay.

## User Experience

The normal flow remains unchanged:

1. The initiator creates a room and shares its invitation.
2. The responder opens the invitation and selects Connect.
3. Both applications establish Noise XX and confirm completion automatically.
4. Both applications display the SAS emojis.
5. Users compare the emojis and enter chat.

The completion exchange is internal and should normally add no perceptible delay. The SAS screen and message controls must never appear until the relay has confirmed that both role-bound connections acknowledged completion.

If a responder connection fails before confirmation while the initiator remains connected, the responder returns to an invitation-ready retry state with a clear retry action. The initiator discards the incomplete Noise state and waits for a fresh responder within the existing overall handshake deadline. Users do not need to recreate or repaste the invitation for that transient responder-side failure. If the initiator itself disconnects before confirmation, the room and invitation are burned and the initiator creates a new room; the old invitation must never outlive its owner.

If the connection fails after two-sided confirmation, the invitation remains consumed. BlindWire shows a disconnected room and requires a new room for a new conversation.

## Protocol Version

The signaling JOIN version byte changes from `0x02` to `0x03`. Version `0x03` is required because older clients do not send completion acknowledgments and older relays do not gate token consumption on them. A mixed-version connection fails immediately with `VERSION_MISMATCH`; it must not silently downgrade.

## Signaling Messages

Client-to-relay opcodes:

- `0x00 JOIN`
- `0x01 RELAY`
- `0x02 QUIT`
- `0x03 HANDSHAKE_COMPLETE`

Relay-to-client opcodes:

- `0x01 RELAY`
- `0x02 PEER_JOINED`
- `0x03 PEER_QUIT`
- `0x04 EXPIRED`
- `0x05 ERROR`
- `0x06 TOKEN`
- `0x07 HANDSHAKE_CONFIRMED`

`HANDSHAKE_COMPLETE` and `HANDSHAKE_CONFIRMED` are exactly one byte. They contain no payload and therefore disclose no SAS value, Noise transcript hash, key material, certificate fingerprint, room identifier, or application message.

## Client State Machine

Each client performs the following sequence:

1. Establish the WebSocket and complete JOIN.
2. Exchange the three Noise XX handshake messages.
3. Require the local core session to reach `SessionState::Active`.
4. Send one `HANDSHAKE_COMPLETE` packet on the role-bound WebSocket.
5. Wait for `HANDSHAKE_CONFIRMED` from the relay.
6. Only then expose the SAS and enter the desktop `verifying` phase.

Duplicate local completion sends are prohibited by client state. Duplicate packets received by the relay are idempotent and do not alter the result.

The entire peer wait, Noise exchange, completion exchange, and retry sequence is bounded by one 30-second deadline. A retry does not restart that deadline.

### Interrupted Attempts

Before `HANDSHAKE_CONFIRMED`:

- A responder-side transport interruption returns a retryable error while the invite remains unexpired and the initiator remains registered.
- The responder's Rust-side invite lease is released, allowing the same opaque handle to be tried again.
- The initiator remains joined to the room, creates a fresh initiator Noise session, and waits for a new responder.
- Any completion flags from the abandoned attempt are cleared.
- An initiator-side transport loss invalidates the room and invitation instead of permitting a new unauthenticated initiator to inherit them.

After `HANDSHAKE_CONFIRMED`:

- Both clients treat transport loss as a disconnected completed session.
- The invite lease and relay token remain consumed.
- Neither side attempts to reuse old Noise state or the old invite.

## Relay State Machine

The relay stores two completion flags in each reserved session:

- `initiator_complete`
- `responder_complete`

The relay accepts `HANDSHAKE_COMPLETE` only from the connection currently registered for that role and only while the responder token is `Reserved`. Receipt sets that role's flag. It does not parse Noise frames or infer completion from encrypted relay traffic.

When both flags are set, the relay atomically changes the token state from `Reserved` to `Consumed` and sends `HANDSHAKE_CONFIRMED` to both registered roles. Token consumption happens before either confirmation is queued, so a send failure cannot restore or duplicate the invitation.

If either role disconnects while the token is `Reserved`, the relay clears both completion flags. If the responder disconnected while the initiator remains registered, the token becomes `Available` for another responder. If the initiator disconnected, the relay removes the incomplete room and invalidates its token. If the token is already `Consumed`, disconnect cleanup never changes its state.

The relay remains unable to verify the internal cryptographic state of a modified client. It relies on official clients to send completion only after local Noise activation. This does not weaken confidentiality or peer authentication: a participant with a valid bearer invitation can always deny service, but one role-bound connection cannot acknowledge for the other role or derive the other peer's Noise keys.

## Desktop Concurrency Ownership

Only one create or join attempt may own the desktop session slot at a time, including while DNS, WebSocket, TLS, peer wait, Noise, or confirmation is pending.

An attempt acquires a generation-scoped owner before starting network work. Sender installation, snapshot transitions, invite release or consumption, task cleanup, and cancellation are conditional on that same owner generation. A stale task cannot replace or clear a newer session.

Peer verification is accepted only when the current authoritative snapshot is in `verifying`, belongs to the current generation, and contains verification data. Calling verification earlier fails closed.

Each room snapshot carries a monotonic revision in addition to its generation. React ignores a snapshot whose `(generation, revision)` is older than the latest applied snapshot, preventing a delayed initial query from regressing a newer event.

## Failure Policy

- Responder-side timeout, DNS failure, connection refusal, and transport loss before confirmation are retryable while the invite is valid and its initiator remains registered.
- Initiator loss invalidates the incomplete room; the initiator must create and share a new invitation.
- Certificate, hostname, SPKI, malformed protocol, version mismatch, invalid invite, expiry, and post-confirmation failures are not retryable with the same invitation.
- Fatal or post-confirmation cleanup clears the sender, verification flag, and sensitive in-memory message state only when owned by the failing generation.
- The server defaults to loopback binding and logs no room identifier or invitation-correlating value.

## Test Strategy

Tests must exercise production framing and public behavior rather than duplicated test-only packet formats.

Required coverage:

- A real initiator and responder complete Noise, send both acknowledgments, receive confirmation, disconnect, and cannot reuse the token.
- One acknowledgment never consumes the token or emits confirmation.
- A responder disconnect before confirmation clears both flags and permits a fresh responder.
- An initiator disconnect before confirmation invalidates the room and rejects the old invitation.
- A disconnect after confirmation never restores the token.
- Version `0x02` is rejected by a version `0x03` relay.
- Completion packets with payloads, completion before responder reservation, and completion from an unregistered role are rejected.
- Concurrent create/join commands permit exactly one global owner.
- Delayed stale connection success cannot install or clear a newer sender.
- Verification before the `verifying` phase is rejected.
- Older same-generation snapshot revisions are ignored by React.
- The live Tauri test harness starts the packaged frontend or its required Vite server explicitly and never tests a `chrome-error://` page.

The complete Rust, frontend, Playwright, audit, debug-build, and release-build gates must pass before publication. Release builds still require reviewed current and rotation SPKI pins, followed by an independent security audit before broad distribution.
