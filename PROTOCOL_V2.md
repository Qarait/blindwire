# BlindWire Protocol Specification v2.0 (FROZEN)

**Status**: FROZEN
**Protocol Version**: 2.0.0
**Compatibility**: None. No backward compatibility with v1.x. Version mismatch = Hard Fail.

This document defines the wire-breaking changes for BlindWire v2.0.

---

## 1. Guiding Principles for v2.0

1. **Failure Transparency**: Every security failure MUST be loud and terminal.
2. **Reduced Ambiguity**: No implicit versioning or opportunistic security.
3. **Abuse Resistance**: Built-in mechanisms to protect relays from flooding.

---

## 2. Explicit Deltas from v1.1.1

### 2.1 Versioned JOIN (Literal 0x02)
The `JOIN` packet format is modified to include a version identifier.
- **Offset 0**: `0x00` (JOIN Opcode)
- **Offset 1**: `0x69` ('i') or `0x72` ('r') (Role)
- **Offset 2**: `0x02` (Protocol Version Literal)
- **Offset 3**: `[ID: 32B]` (Session ID)

**Delta**: v1.1.1 expected `[OP:1][ROLE:1][ID:32]`. v2.0.0 expects `[OP:1][ROLE:1][VER:1][ID:32]`.
**Failure**: If a v2 server receives a non-`0x02` version byte, it emits `ERROR(VERSION_MISMATCH)` and kills the connection.

---

## 3. What Remains Unchanged

- **Noise Handshake**: Still Noise_XX_25519_ChaChaPoly_BLAKE2s.
- **Ephemerality**: No persistent storage on the relay.
- **Defense-in-Depth Zeroization**: Rigorous (but best-effort) burning of secrets and plaintext from memory to minimize the exposure window.
- **Relay Role**: The server remains blind to all encrypted payloads.

---

## 3.1 Wire Format Details

BlindWire v2.0 separates signaling metadata from cryptographic payloads.

### Signaling Layer (Unencrypted at Application Layer)
All packets sent to/from the relay start with a 1-byte **Opcode**.
- `[Opcode:1][Payload:N]`
- The relay server parses the Opcode to route data or enforce rate limits.
- **Note**: Signaling is unencrypted at the application layer (visible to the relay), but still inside TLS on the wire for non-local connections.

### Cryptographic Layer (End-to-End Ciphertext)
Encapsulated within the `RELAY (0x01)` opcode:
- `[RELAY:1][LENGTH:2][PAYLOAD:N]`
- **Payload** is parsed by the `blindwire-core` state machine:
  - **Handshake Phase**: RELAY payloads are Noise handshake messages. Parts of XX messages are encrypted after initial key exchange, but these are not post-handshake transport ciphertext.
  - **Transport Phase**: AEAD Ciphertext (ChaCha20-Poly1305).
  - **Overhead**: Each encrypted frame adds 16 bytes for the Poly1305 MAC.

---

## 4. TLS Pinning: A Failure Story

TLS Pinning in BlindWire is designed as a barrier against active network interception. It follows a "TOFU-and-Lock" model.

### 4.1 First Connection (TOFU)
1. On initial connection to a new relay, the client displays the relay's Certificate Fingerprint (SHA-256).
2. The user is prompted to verify this fingerprint out-of-band if possible.
3. Upon first successful `JOIN`, the client **locks** this fingerprint to the relay URL.

### 4.2 Subsequent Connections (The Lock)
1. Before sending a `JOIN` packet, the client verifies the current relay certificate against the stored pin.
2. **Terminal Failure**: If the hashes do not match:
   - The connection is closed immediately.
   - **NO** option is provided to "bypass" or "accept anyway".
   - The user is notified of a "Security Violation: Relay Identity Changed".
3. The only recovery is manual deletion of the pin (a high-intent administrative action).

---

## 5. Error Signaling (Fix D v2.1)

All errors use a single opcode with a sub-code byte:

```
[ERROR:0x05][ErrorCode:1]
```

### ErrorCode Table

| Code | Name | Description | Server Action |
|------|------|-------------|---------------|
| `0x01` | `ROLE_TAKEN` | Role already occupied in session | Close |
| `0x02` | `INVALID_FORMAT` | Malformed packet/frame | Close |
| `0x03` | `UNKNOWN_OPCODE` | Unknown relay opcode | Close |
| `0x04` | `UNAUTHORIZED` | (Reserved) | Close |
| `0x05` | `QUEUE_FULL` | Server backpressure | Close |
| `0x06` | `VERSION_MISMATCH` | Client/server v2 mismatch | Close |
| `0x07` | `RATE_LIMIT_EXCEEDED` | IP or global limits | Close |
| `0x08` | `PIN_REQUIRED` | (Future) | Close |

**Key Rule**: There are **no** dedicated opcodes for error conditions. All errors go through `ERROR(0x05)`.

---

## 6. Rekeying Decision

**Decision**: **OUT of Scope for v2.0**.

While Category A originally included rekeying, we have decided to exclude it from v2.0 to maintain protocol simplicity.
- **Reasoning**: A 1-hour session TTL provides sufficient rotation for dissident-grade security without the engineering surface of in-session renegotiation.
- **Recommendation**: To "rekey," clients should cleanly terminate and start a fresh session.

### Known Tradeoffs:
- **NAT Fairness**: Per-IP rate limiting (5 active conns/IP) may penalize users behind shared NATs (cafés, etc.). This is accepted in favor of protocol simplicity and basic abuse resistance.
- **Client UX**: `RATE_LIMIT_EXCEEDED` currently results in a terminal error with minimal retry logic. Human-readable polish is deferred.
- **Unauthenticated Control Frames**: Certain control opcodes (e.g., `TERMINATE`) are intentionally unauthenticated to preserve protocol simplicity and ephemerality. This permits denial-of-service (DoS) by active adversaries who know the `Session ID` and is an accepted limitation for v2.0.

---

## 7. Operational Hardening: Rate Limiting

The signaling server enforces strict per-IP connection limits:
1. **Connection Threshold**: Max 5 active connections per IP.
2. **Burst Threshold**: Max 10 `JOIN` attempts per minute per IP.
3. **Violation**: Server responds with `ERROR(0x07)` and drops the connection.

---

## 8. QR Sharing Specification

The QR code encodes a URI: `blindwire://relay_host:port/session_id/role`
- `role` is `i` or `r`.
- This URI contains **NO** cryptographic secrets (static keys or ephemeral keys).
- **Security Invariant (Non-Substitution)**: QR sharing is a transport convenience for session metadata only. It **does not replace** the mandatory out-of-band fingerprint verification.
- **Verification Requirement**: After the Noise handshake completes, users MUST still verify the displayed fingerprint (`SHA256(PubKeys)`) via a secondary secure channel.

---

## 9. Security Note: Unauthenticated Termination

In Protocol v2.0, the `TERMINATE (0x03)` frame is sent in plaintext.
- **Risk**: An attacker who knows the `Session ID` can forge a `TERMINATE` frame to force-close a session (DoS).
- **Mitigation**: Privacy is maintained (no keys leaked). Robustness against forgery is scheduled for v2.1 (Authenticated Termination).
