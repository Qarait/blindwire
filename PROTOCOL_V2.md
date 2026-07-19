# BlindWire Cryptographic Protocol v2.0

**Status:** Beta release specification
**Cryptographic protocol:** 2.0
**Signaling subprotocol:** 3 (`JOIN` literal `0x03`)
**Compatibility:** No backward compatibility or silent downgrade

This document describes the end-to-end protocol and its boundary with the blind relay. The complete signaling wire format is normative in `SIGNALING_SPEC.md`.

## 1. Security Principles

1. Security failures are explicit and terminal.
2. The relay routes opaque frames and never infers cryptographic progress from them.
3. Invitations are bearer capabilities for one responder connection attempt at a time.
4. SAS is exposed only after local Noise activation and two-sided relay confirmation.
5. Rooms and relay state are ephemeral and memory-only.

## 2. Cryptographic Session

BlindWire uses `Noise_XX_25519_ChaChaPoly_BLAKE2s` with initiator and responder roles. The three Noise XX messages establish an encrypted session without pre-existing user accounts or stable contact identifiers.

The core frame wire format is:

```text
[LENGTH:2, big endian][TYPE:1][PAYLOAD:N]
```

Core message types are:

| Type | Meaning |
|---|---|
| `0x01` | Noise handshake |
| `0x02` | Encrypted application data |
| `0x03` | Session termination |

Application plaintext is UTF-8, contains no NUL byte, and is limited to 4000 bytes. Authenticated encryption uses ChaCha20-Poly1305 through the Noise transport state.

## 3. Signaling v3 Compatibility Boundary

The project remains cryptographic protocol v2.0, but its relay signaling version is v3 because older clients do not acknowledge local Noise completion.

Initiator JOIN:

```text
[0x00]['i'][0x03][ROOM_ID:32]
```

Responder JOIN:

```text
[0x00]['r'][0x03][ROOM_ID:32][TOKEN:32]
```

A version other than literal `0x03` receives `ERROR(VERSION_MISMATCH)` and the connection closes. A v3 client never retries as v2.

## 4. Relay Blindness And Production Framing

The signaling relay envelope contains the complete core frame wire value:

```text
[RELAY:0x01][RELAY_LENGTH:2][CORE_LENGTH:2][TYPE:1][PAYLOAD:N]
```

The relay validates the outer packet length and bounded queue only. It does not read `CORE_LENGTH`, `TYPE`, Noise messages, ciphertext, SAS material, or application data. Clients validate both length prefixes and pass only the inner body to `blindwire-core`.

Relay traffic never advances invitation state. Sending three apparent handshake frames, replaying frames, or placing a handshake type byte at a chosen offset cannot consume a token.

## 5. Explicit Two-Sided Confirmation

Each official client follows this sequence:

1. JOIN the role-bound WebSocket.
2. Complete all three Noise XX messages.
3. Require the local core session to reach `Active`.
4. Send one-byte `HANDSHAKE_COMPLETE (0x03)`.
5. Wait for one-byte `HANDSHAKE_CONFIRMED (0x07)`.
6. Only then expose the SAS and verification workflow.

The relay stores one completion bit per role. It changes the invitation token from `Reserved` to `Consumed` only after both bits are true, and performs that state change before queueing either confirmation.

These packets attest only that each official client reports local completion. They do not let the relay authenticate or inspect Noise. A modified participant can still deny service, but one role-bound connection cannot acknowledge for the other role or derive the other peer's keys.

## 6. One Deadline And Interrupted Attempts

Peer wait, Noise XX, completion, confirmation, and any initiator retry share one 30-second deadline.

Before confirmation:

- Responder loss releases its reservation while the original initiator remains connected.
- Both relay completion flags are cleared.
- The initiator zeroizes the abandoned Noise state, creates a fresh initiator state, and waits for a replacement responder without restarting the deadline.
- Initiator loss deletes the incomplete room and invalidates the old invitation.

After confirmation, the invitation is permanently consumed. Neither role can reuse its token after a later disconnect.

## 7. SAS Verification

After confirmed Noise activation, each client derives the same short authentication string from the authenticated session state and displays its emoji representation. Users compare the SAS through an independent channel or in person before marking the peer verified.

The SAS is never sent to the relay. Relay confirmation is not a substitute for user SAS comparison; it only prevents the UI from presenting an attempt that the other role has not also completed.

## 8. TLS And Relay Identity

Production signaling uses `wss://`. The client validates the normal TLS certificate chain and proof-of-possession, then applies the configured SPKI policy:

- Official relay hosts use reviewed built-in pins with rotation support.
- A validated custom-relay invitation can supply an expected SPKI pin.
- TOFU, where explicitly selected, must persist the first accepted pin and reject later changes.

Plain `ws://` is accepted only for an explicitly enabled loopback debug connection.

## 9. Error Signaling

Relay errors are exactly two bytes:

```text
[ERROR:0x05][ERROR_CODE:1]
```

Notable terminal errors include malformed packets, unauthorized or consumed invitations, role conflicts, version mismatch, relay rate limits, expiry, and TLS or pin validation failure. No security error has an "accept anyway" path.

## 10. Operational Limits

- Relay room TTL: one hour.
- Maximum active connections per effective client IP: five.
- Maximum JOIN attempts per minute per effective client IP: ten.
- Maximum total active relay connections: 1000.
- Maximum per-peer relay queue: 32 packets.

The server defaults to loopback binding and requires explicit production exposure through reviewed TLS infrastructure.
