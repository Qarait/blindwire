# Signaling Server Specification v1.1.1 (FROZEN)

**Status**: FROZEN / Dissident-Grade
**Protocol Version**: 1.1.1

---

## 1. Connection & Privacy

### 1.1 Transport
- **URL**: `wss://<host>/`
- **Handshake**: Standard HTTP Upgrade. No metadata in path.

### 1.2 Access Control
- First message MUST be `JOIN`. 
- Any other message before `JOIN` results in **Immediate Kill** (Close WS + Delete Mapping).

---

## 2. Binary Signaling Envelope

Every WebSocket binary message maps to **exactly one** signaling packet.
No semantic parsing of Protocol Frames; validate length prefix only.

### 2.1 RELAY Packet Format
| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0      | 1B   | OP   | `0x01` (RELAY) |
| 1      | 2B   | LEN  | Length of Protocol Body |
| 3      | N B  | BODY | Protocol Frame (Exactly `LEN` bytes) |

**Validation**:
- `WS_LEN` MUST be exactly `3 + LEN`.
- `1 <= LEN <= 4096`.
- Violation = **Immediate Kill** of offending peer.

---

## 3. Opcodes (1 Byte)

### 3.1 Client → Server
- `0x00` (**JOIN**): `[Role: 1B] [ID: 32B]`. 
- `0x01` (**RELAY**): See section 2.1.
- `0x02` (**QUIT**): Cleanly disconnect and notify peer.

### 3.2 Server → Client
- `0x01` (**RELAY**): Relayed packet from peer.
- `0x02` (**PEER_JOINED**): Peer is connected.
- `0x03` (**PEER_QUIT**): Peer disconnected or was killed.
- `0x04` (**EXPIRED**): Session TTL reached.
- `0x05` (**ERROR**): `[Code: 1B]`.

---

## 4. Error Codes (1 Byte)
- `0x01`: **ROLE_TAKEN** (Duplicate JOIN for active role).
- `0x02`: **INVALID_FORMAT** (Bad length or framing).
- `0x03`: **UNKNOWN_OPCODE** (Opcode not supported).
- `0x04`: **UNAUTHORIZED** (Data sent before JOIN).
- `0x05`: **QUEUE_FULL** (Internal buffer overflow).

---

## 5. Policies & Guardrails

### 5.1 Duplicate JOIN Policy
If a client attempts to `JOIN` a role that is already occupied:
1. Server sends `ERROR(0x01)` to the **new** connection.
2. Server **closes** the new connection immediately.
3. Server **preserves** the existing mapping and peer connection.

### 5.2 Kill Policy (Immediate Death)
Upon `QUIT` or fatal protocol violation:
1. Close the offending WebSocket.
2. Delete the in-memory mapping for that role.
3. Send `PEER_QUIT` (`0x03`) to the other peer if connected.
4. Total Death: If both roles are empty for >5s, delete the `Session` object.

### 5.3 Bounded Queues
- **MAX_QUEUE_FRAMES**: 32.
- **Policy**: If the peer's relay queue is full, the server sends `ERROR(0x05)` and closes the sender's connection (Force-quit on backpressure).

### 5.4 Timeouts
- **Session TTL**: 10 minutes (Strict).
- **Idle Timeout**: 5 minutes of no activity.
- Safety nets for orphaned sessions. Ephemerality > Persistence.

