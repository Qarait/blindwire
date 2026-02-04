# BlindWire v1.0

Hardened, session-scoped secure messaging for untrusted environments.

BlindWire is a minimal, dissident-grade messaging protocol designed to minimize attack surface and enforce perfect forward secrecy through extreme session isolation. It is not a "chat app" with accounts; it is a point-to-point secure wire with a strictly enforced failure model.

## Core Philosophy

### Hard Failure
In BlindWire, failure is a first-class security citizen. Any protocol deviation, malformed frame, or validation error results in the immediate termination of the session and the zeroization of all cryptographic material in RAM. There is no recovery, no retry, and no fallback to insecure modes.

### Surface Area Compression
The signaling server (Relay) is binary-only. There is no JSON parsing, no database, and no long-term state. The server simply validates a 1:1 relay envelope and moves bytes. Minimal surface area is your primary defense against server compromise.

### MTU-Friendly Invariants
Message sizes are capped at 4000 bytes. This ensures that a complete encrypted frame (including AEAD overhead and signaling headers) fits within a single 4KB wire package. By enforcing this as a hard protocol invariant, we eliminate the complexity of fragmentation and reassembly bugs.

## Threat Model

BlindWire is designed to protect communication against a **Network Adversary** (passive snooping, active MITM) and a **Compromised Relay Server**.

### Out of Scope
The following risks are explicitly out of scope:
- **Compromised OS**: If your kernel, shell, or display manager is compromised, BlindWire cannot protect you.
- **Anonymity**: BlindWire provides encryption and forward secrecy; it is not an anonymity network like Tor. It does not provide advanced traffic masking/padding.
- **Metadata Protection**: While the relay is binary-only, standard metadata (IP addresses, timing, packet sizes) remains visible to the network and relay.
- **Persistence Resistance**: Zeroization handles RAM, but cannot protect against persistent OS-level forensic hooks or "cold boot" attacks on memory.

## Project Layout

| Component | Role | Description |
|-----------|------|-------------|
| `blindwire-cli` | Client | TUI-based messaging client. |
| `blindwire-server` | Relay | Binary signaling server (Relay). |
| `blindwire-core` | Protocol | Core state machine and framing logic. |
| `blindwire-transport` | Transport | Async secure transport wrapper. |

## Usage

### 1. Build
```powershell
cargo build --release
```

### 2. Run Signaling Server
```powershell
./blindwire-server
```

### 3. Initiate Session
```powershell
./blindwire-cli
```
The CLI will generate a volatile 32-byte Session ID. Share the Server Address and Session ID with your peer via an out-of-band secure channel.

### 4. Join Session
```powershell
./blindwire-cli --server <server_addr> --session <id>
```

**Security Warning**: Fingerprint verification is required. Both peers must verify that the displayed 32-byte session fingerprint matches exactly. If it does not, assume a Man-In-The-Middle (MITM) attack and burn the session immediately.
