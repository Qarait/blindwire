# BlindWire Protocol State Machine v1.1.1 (FROZEN)

**Status**: FROZEN / Dissident-Grade

## Session States

| State | Description |
|-------|-------------|
| **CREATED** | Pre-transport initialization. |
| **CONNECTED** | WSS transport established, `JOIN` packet sent/received. |
| **HANDSHAKING** | Noise_XX (3-message) exchange via `RELAY`. |
| **ACTIVE** | Encrypted payload channel open. |
| **DISCONNECTED_GRACE** | Transport drop detected while ACTIVE. |
| **TERMINATED** | Volatile memory wiped. Session dead. |

## Transitions & Events

### Connection Handshake
1. Client connects via WSS.
2. Client sends `JOIN` packet (`0x00` Opcode).
3. Server registers role. If role is taken, Server sends `ERROR(ROLE_TAKEN)` and closes the *new* connection.
4. Clients proceed to Noise Handshake via `RELAY` packets (`0x01` Opcode).

### Reconnection Grace Semantics
Grace window keeps keys in RAM during reconnect; if reconnect fails by 5 seconds → terminate and zeroize. No cryptographic state is recovered beyond the 5-second window.

### Triggers for TERMINATED
- **Explicit Terminate**: `0x03` Frame received or `0x02` Opcode received.
- **Handshake Timeout**: 30 seconds from `CONNECTED`.
- **Idle Timeout**: 10 minutes from last message.
- **Session TTL**: 1 hour maximum duration (server enforced).
- **Validation Error**: Frame too large, Invalid UTF-8, Invalid Noise state.

## Zeroization Sequence
Upon entry to **TERMINATED**:
1. Zeroize `HandshakeState` (if any).
2. Zeroize `CipherState` (Send/Receive keys).
3. Zeroize `StaticKeypair`.
4. Zeroize any buffered Plaintext fragments.
5. Close transport socket.
