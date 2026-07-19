# BlindWire Signaling Protocol v3

**Status:** Beta release specification
**JOIN version byte:** `0x03`
**Compatibility:** No downgrade to signaling v2

## 1. Transport And Privacy

- Production clients use `wss://` and place no room metadata in the URL path.
- Plain `ws://` is permitted only for an explicitly enabled loopback debug connection.
- The relay defaults to `127.0.0.1:8080`; public exposure requires an explicit bind address and a TLS reverse proxy.
- The relay stores rooms, invitation tokens, and completion flags only in memory.
- Normal logs contain no room identifier, invitation token, SAS, key, transcript hash, or message content.

Every WebSocket binary message contains exactly one signaling packet. The first packet must be `JOIN`. Text packets are ignored; malformed or unauthorized binary packets terminate the offending connection.

## 2. JOIN

### Initiator

```text
[JOIN:0x00][ROLE:'i':1][VERSION:0x03][ROOM_ID:32]
```

The packet is exactly 35 bytes. A successful JOIN creates the in-memory room and returns:

```text
[TOKEN:0x06][TOKEN:32]
```

The token packet is exactly 33 bytes.

### Responder

```text
[JOIN:0x00][ROLE:'r':1][VERSION:0x03][ROOM_ID:32][TOKEN:32]
```

The packet is exactly 67 bytes. The responder is admitted only when the room has its original initiator, the token matches, and the token state is `Available`. The relay atomically reserves the token for that responder connection and sends one-byte `PEER_JOINED` packets to both roles.

A version other than `0x03` receives `ERROR(VERSION_MISMATCH)` and cannot downgrade.

## 3. RELAY Envelope

```text
[RELAY:0x01][LENGTH:2, big endian][FRAME_WIRE:LENGTH]
```

`FRAME_WIRE` is the complete `blindwire-core` frame, including its own two-byte length prefix:

```text
[FRAME_LENGTH:2, big endian][TYPE:1][PAYLOAD:N]
```

Relay validation is limited to the outer signaling length and packet bound. The relay does not inspect the inner type, Noise state, ciphertext, or application message. Clients strictly validate both length prefixes before parsing a core frame.

- `WS_LENGTH` must equal `3 + LENGTH`.
- `1 <= LENGTH <= 4096` at the relay boundary.
- One WebSocket binary packet maps to one relayed frame.
- The per-peer queue holds at most 32 packets.

## 4. Opcodes

### Client To Relay

| Opcode | Name | Exact format |
|---|---|---|
| `0x00` | `JOIN` | 35-byte initiator or 67-byte responder packet |
| `0x01` | `RELAY` | Header plus exactly `LENGTH` bytes |
| `0x02` | `QUIT` | One byte |
| `0x03` | `HANDSHAKE_COMPLETE` | One byte |

### Relay To Client

| Opcode | Name | Exact format |
|---|---|---|
| `0x01` | `RELAY` | Relayed packet unchanged |
| `0x02` | `PEER_JOINED` | One byte |
| `0x03` | `PEER_QUIT` | One byte |
| `0x04` | `EXPIRED` | One byte |
| `0x05` | `ERROR` | Exactly `[0x05][CODE]` |
| `0x06` | `TOKEN` | Exactly `[0x06][TOKEN:32]` |
| `0x07` | `HANDSHAKE_CONFIRMED` | One byte |

`HANDSHAKE_COMPLETE` and `HANDSHAKE_CONFIRMED` carry no payload. They disclose no Noise transcript, key, SAS value, certificate fingerprint, room identifier, token, or application data.

## 5. Two-Sided Completion

After its local Noise XX state reaches `Active`, each official client sends one `HANDSHAKE_COMPLETE` and waits for `HANDSHAKE_CONFIRMED`. A client must not expose SAS verification or active messaging before confirmation.

For a reserved room the relay stores:

- `initiator_complete`
- `responder_complete`

One completion only sets that role's flag. When both flags are set, the relay changes `Reserved` to `Consumed` before queueing a one-byte confirmation to each role. A queue or connection failure cannot restore the token. Duplicate completion packets from a currently registered role are idempotent and emit no additional confirmation.

Completion with payload bytes, before reservation, or from a connection that does not own its role is rejected.

## 6. Disconnect And Token Rules

- **Responder loss before confirmation:** clear both completion flags, change `Reserved` to `Available`, notify the initiator, and permit a fresh responder using the same token.
- **Initiator loss before confirmation:** notify any responder and remove the incomplete room. The old token is invalid.
- **Loss after confirmation:** never restore a `Consumed` token.
- **Duplicate role:** reject the new connection without replacing the existing role or minting a new token.

The client bounds peer wait, all Noise attempts, completion, confirmation, and initiator retry with one 30-second deadline. A responder retry does not restart that clock. The initiator creates a fresh Noise state before accepting a replacement responder.

## 7. Error Codes

All errors use `[ERROR:0x05][CODE:1]`.

| Code | Name |
|---|---|
| `0x01` | `ROLE_TAKEN` |
| `0x02` | `INVALID_FORMAT` |
| `0x03` | `UNKNOWN_OPCODE` |
| `0x04` | `UNAUTHORIZED` |
| `0x05` | `QUEUE_FULL` |
| `0x06` | `VERSION_MISMATCH` |
| `0x07` | `RATE_LIMIT_EXCEEDED` |
| `0x08` | `PIN_REQUIRED` |
| `0x09` | `EXPIRED` |

## 8. Operational Bounds

- Room TTL: one hour.
- Empty-room cleanup grace: five seconds.
- WebSocket upgrade timeout: ten seconds.
- JOIN timeout: ten seconds.
- Maximum active connections per effective client IP: five.
- Maximum JOIN attempts per effective client IP: ten per minute.
- Maximum total active connections: 1000.

