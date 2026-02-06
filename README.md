# BlindWire v2.0

High-assurance encrypted messaging over WebSockets.

BlindWire is a minimal, secure messaging protocol designed to minimize attack surface and enforce perfect forward secrecy through extreme session isolation. It is not a "chat app" with accounts; it is a point-to-point secure wire with a strictly enforced failure model.

## Features (v2.0)

- **Noise_XX Handshake**: Curve25519, ChaChaPoly, BLAKE2s for mutual authentication and forward secrecy.
- **TLS Certificate Pinning**: TOFU-and-Lock model prevents MITM attacks at the transport layer.
- **Rate Limiting**: Per-IP connection limits and global server caps protect against abuse.
- **QR Session Sharing**: Scan-to-join via `blindwire://` URI scheme.
- **Hard Failure**: Any protocol deviation terminates the session immediately.
- **Memory Zeroization**: Best-effort burning of secrets and plaintext from RAM.

## Project Layout

| Component | Description |
|-----------|-------------|
| `blindwire-cli` | TUI-based messaging client with QR code display. |
| `blindwire-server` | Binary signaling relay (no JSON, no database). |
| `blindwire-core` | Protocol state machine, framing, Noise wrapper. |
| `blindwire-transport` | Async secure transport layer. |

## Installation

### From Release
Download pre-built binaries from [Releases](https://github.com/Qarait/blindwire/releases).

### From Source
```bash
cargo build --release
```

Binaries will be in `target/release/`.

## Usage

### Start the Relay Server
```bash
./blindwire-server
# Listening on 0.0.0.0:8080
```

### Initiate a Session (Peer A)
```bash
./blindwire-cli --server wss://your-relay.example.com:8080
```
A QR code will be displayed. Share it with your peer.

### Join a Session (Peer B)
```bash
# Option 1: Scan QR and use URI
./blindwire-cli --uri "blindwire://relay:8080/SESSION_ID/r"

# Option 2: Manual flags
./blindwire-cli --server wss://relay:8080 --session SESSION_ID --role r
```

### Fingerprint Verification
After the Noise handshake completes, both peers MUST verify the displayed fingerprint via a secondary secure channel (phone call, Signal, in-person). If fingerprints do not match, assume MITM and terminate immediately.

## Security Model

### Threat Model
BlindWire protects against:
- **Passive Network Adversary**: All application data is encrypted with ChaCha20-Poly1305.
- **Active MITM**: TLS pinning and fingerprint verification block interception.
- **Compromised Relay**: The server cannot read encrypted payloads. It sees only opaque binary frames.

### Out of Scope
- **Compromised Endpoint**: If your OS or terminal is compromised, BlindWire cannot protect you.
- **Anonymity**: This is not Tor. IP addresses are visible to the network and relay.
- **Metadata**: Timing, packet sizes, and connection patterns are not hidden.

### Known Limitations
- `TERMINATE` frames are unauthenticated (DoS possible if Session ID is leaked). Scheduled for v2.1.
- Zeroization is best-effort due to OS memory management constraints.

## Protocol Specification

See [PROTOCOL_V2.md](PROTOCOL_V2.md) for the frozen v2.0 wire format.

## License

MIT
