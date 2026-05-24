# BlindWire v2.0

BlindWire is a zero-account, ephemeral, relay-assisted end-to-end encrypted secure wire for short-lived communication with a strictly enforced failure model.

It uses an untrusted WebSocket relay for reachability, while message confidentiality is provided end-to-end by Noise_XX. The relay keeps only volatile routing state and cannot read message contents, but it can observe metadata such as IP addresses, timing, roles, session identifiers, and encrypted frame sizes.

BlindWire is not a general chat app, not an anonymity network, and not protection against compromised endpoints.

## Features (v2.0)

- **Noise_XX handshake**: X25519, ChaCha20-Poly1305, and BLAKE2s for forward-secret session establishment.
- **Fingerprint verification**: users must compare fingerprints out of band to detect active MITM.
- **TLS pinning**: TOFU-and-lock pinning detects relay certificate identity changes after first trust establishment.
- **Rate limiting**: per-IP and global server limits reduce relay abuse.
- **QR session sharing**: scan-to-join via `blindwire://` URI.
- **Hard failure**: protocol deviations terminate the session immediately.
- **Best-effort zeroization**: Rust-owned secrets are zeroized where possible; OS and endpoint compromise remain out of scope.

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

> **Note**: The QR contains no cryptographic keys, but the session ID is a join capability. Share it only with your intended peer via a secure channel.

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

BlindWire protects against:
- Passive network observers reading message contents.
- A compromised relay reading plaintext messages.
- Active interception attempts when users verify fingerprints out of band.

BlindWire does not protect against:
- Compromised endpoints.
- Malicious recipients.
- Screenshots or screen recording.
- Traffic analysis.
- Metadata exposure to the relay or network.
- Denial of service by the relay.

### Known Limitations
- `TERMINATE` frames are unauthenticated (DoS possible if Session ID is leaked). Scheduled for v2.1.
- Zeroization is best-effort due to OS memory management constraints.

## Protocol Specification

See [PROTOCOL_V2.md](PROTOCOL_V2.md) for the frozen v2.0 wire format.

## License

MIT
