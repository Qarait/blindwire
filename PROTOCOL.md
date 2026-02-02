# BlindWire Protocol Specification v1.0 (FROZEN)

**Status**: FROZEN / Dissident-Grade
**Protocol Version**: 1.0.0

### Design Philosophy: One Strike
BlindWire enforces a "One Strike" security policy. Any protocol deviation, including malformed frames, incorrect message types for the current state, or failed decryption, is treated as a terminal event. There are no retries or error recovery mechanisms once a session has begun. Malfunction is indistinguishable from malice.

**Compatibility**: None. No version negotiation. No backward compatibility. Version mismatch or malformed frame = Hard Fail (Immediate zeroization and disconnect).


---

## 1. Transport & Security Invariants

### 1.1 Transport Layer
- **Mandatory**: WebSockets over TLS (`wss://`).
- **Development**: Unencrypted WebSockets (`ws://`) permitted ONLY for `localhost` with the explicit `--insecure-dev` flag.
- **TLS Termination**: Must occur at the server process or a trusted local proxy.

### 1.2 Cryptography
- **Pattern**: `Noise_XX_25519_ChaChaPoly_BLAKE2b`.
- **Key Scope**: Static keys are session-scoped. They are generated in volatile memory at session start and zeroized immediately on termination.
- **Rekeying**: Permitted but not required for v1.
- **Verification**: Initiator and Responder should compare fingerprints (32-byte hash) via an external secure channel.

---

## 2. Wire Framing

Every message on the wire is a **Frame**.

### 2.1 Frame Layout (Big-Endian)
| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0      | 2B   | LEN  | Length of Body (1-4097 bytes) |
| 2      | 1B   | TYPE | Message Type (0x01: Handshake, 0x02: Data, 0x03: Terminate) |
| 3      | N B  | DATA | Payload (Encrypted or Handshake bytes) |

### 2.2 Bounds
- **Max Frame Size**: 4096 bytes (Body) + 2 bytes (Length) = 4098 bytes total.
- **Max Plaintext**: 4000 bytes.
- **Minimum Body**: 1 byte (Type only).

---

## 3. Session State Machine

### 3.1 States
1. **CREATED**: Keypair generated, awaiting transport.
2. **CONNECTED**: WSS established, awaiting handshake start.
3. **HANDSHAKING**: 3-message `Noise_XX` exchange in progress.
4. **ACTIVE**: Transport keys derived. Secure messaging possible.
5. **DISCONNECTED_GRACE**: Transport lost during ACTIVE session.
6. **TERMINATED**: Final state. Memory zeroized.

### 3.2 Reconnection Grace Window
- **Semantics**: Grace window keeps keys in RAM during reconnect; if reconnect fails by 5 seconds → terminate and zeroize. No cryptographic continuity is guaranteed beyond this window.

---

## 4. Metadata & Identity
- **No Accounts**: No long-term identifiers.
- **No Headers**: No `User-Agent`, `Timestamp`, or `Subject` inside the encrypted payload.
- **UTF-8 Only**: Plaintext must be valid UTF-8. Non-UTF-8 or NUL bytes result in session termination.

---

## 5. Zeroization Points
Sensitive data must be wiped using `Zeroize` traits at these points:
1. **Post-Handshake**: Wipe `HandshakeState` immediately after `CipherState` derivation.
2. **Post-Send**: Wipe plaintext buffer after encryption completes.
3. **Post-Render**: Wipe decrypted plaintext after it is displayed.
4. **Any Error**: On any validation or transport error, transit to TERMINATED and zeroize.
5. **Termination**: Wipe static keypair, session keys, and any buffered fragments.

---

## 6. Threat Model & Boundaries

**Condition**: BlindWire is designed for secure communication between two trusted users on untrusted networks with an untrusted relay.

### 6.1 Protected Against
- **Network Adversary**: Passive snooping (TLS/Noise) and Active MITM (Noise_XX Fingerprint Verification).
- **Server Compromise**: The relay has no visibility into session keys or plaintext.
- **Forensics (Standard)**: Keys are never persisted to disk. Zeroization wipes RAM on session end.

### 6.2 NOT Protected Against (Out of Scope)
- **Compromised OS**: If the kernel or shell is compromised, BlindWire cannot protect you.
- **RAM Dumps**: Hostile OS processes can dump RAM before zeroization occurs.
- **Visual Capture**: Screenshots, screen recording, or physical observation of the display.
- **Keylogger**: OS-level keyboard hooks capturing input before it reaches the BlindWire process.

"If the OS is compromised, BlindWire cannot protect you."
