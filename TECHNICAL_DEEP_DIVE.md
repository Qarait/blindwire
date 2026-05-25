# BlindWire: A Technical Deep Dive

BlindWire is a relay-assisted end-to-end encrypted messaging application designed under a strictly defined failure model. It assumes the network is hostile, the routing infrastructure is compromised, and endpoint persistence is an anti-feature.

Here is a comprehensive technical breakdown of its architecture, cryptographic protocols, and security invariants.

---

## 1. High-Level Architecture & Threat Model
BlindWire operates without user accounts, databases, or persistent identity keys. It bridges two endpoints (Initiator and Responder) across NATs/firewalls using a public, untrusted relay server.

*   **Threat Model**: Protects against passive eavesdropping and, strictly contingent upon correct out-of-band user verification, active MITM attacks at both the transport and application layers. It assumes the signaling relay is untrusted and potentially malicious.
*   **Out of Scope**: Endpoint compromise (e.g., malware on the OS, memory dumping by root) and traffic analysis (timing/packet size metadata).

## 2. The Cryptographic Engine (End-to-End Layer)
The core of BlindWire’s security relies on the **Noise Protocol Framework**.
*   **Pattern**: `Noise_XX_25519_ChaChaPoly_BLAKE2s`.
*   **Key Exchange**: The `XX` pattern executes a 3-message handshake, exchanging ephemeral X25519 public keys. This guarantees Perfect Forward Secrecy (PFS). However, because there are no persistent identity keys, the Noise_XX handshake alone does not authenticate human identity without SAS verification.
*   **SAS (Short Authentication String)**: To mitigate active MITM attacks during the initial unauthenticated X25519 key exchange, the client computes an SAS derived from the Noise handshake transcript hash. This hash is deterministically mapped to a 7-emoji sequence. The application state machine strictly blocks AEAD message transmission until both peers verify this SAS out-of-band. Cryptographic protection against active interception is exclusively dependent on this human verification step.
*   **Data Phase**: Once the handshake completes, transport ciphertext is encapsulated using AEAD ciphertext using ChaCha20-Poly1305.

## 3. The Signaling Server (`blindwire-server`)
The relay is a non-persistent volatile in-memory relay written as an asynchronous Rust (Tokio) binary that acts as a WebSocket router.
*   **Binary Envelope**: It does not parse JSON or HTTP after the initial WebSocket upgrade. It uses a minimal custom binary framing protocol (`[OPCODE:1][ROLE:1][VERSION:1][SESSION_ID:32]`).
*   **Content-Blind Relay**: The server cannot observe the Noise keys or the ChaCha20 plaintext. It merely routes the AEAD ciphertext payloads between the two WebSocket handles bound to a given `Session ID`.
*   **Token Binding & Access Control**: When an Initiator creates a room, the server mints a single-use token. The Responder must present this exact token in their `JOIN` packet. Once consumed, the token is invalidated. Concurrent race attempts to join are deterministically rejected.
*   **Hard Limits**: The server enforces strict constraints to prevent abuse:
    *   **Bounded Queues**: Internal MPSC channels are bounded. If a client is too slow, backpressure triggers a hard kill of the connection.
    *   **Rate Limiting**: Strict per-IP connection and burst limits.
    *   **TTL and Idle Timeout**: A hard 10-minute idle timeout between messages, and an absolute 1-hour Time-To-Live (TTL). Once either is reached, the session is evicted from the in-memory map and sockets are dropped.

## 4. Transport Security & TLS Pinning
While the Noise protocol protects the payload end-to-end, the transport layer to the relay (`wss://`) is protected by TLS with strict pinning to restrict arbitrary interception proxies.
*   **TOFU-and-Lock**: BlindWire uses a silent "Trust On First Use" model. On the first connection, the client extracts the **SPKI (Subject Public Key Info)** hash from the leaf certificate and silently pins it to the local disk. If the first connection is intercepted, the attacker's key may be pinned.
*   **Hard Failure Semantics**: On subsequent connections, if the SPKI hash does not match the pin, the Rust backend triggers an immediate connection kill. There is no bypass, no fallback, and no opportunistic security.
*   **Deployment Note (Let's Encrypt)**: Because clients use strict SPKI pinning, relay operators *must* reuse the certificate private key across renewals (e.g., using `--reuse-key` with Certbot or equivalent Caddy settings). If the underlying private key changes upon renewal, all existing clients will encounter a hard failure and be permanently locked out from that relay.

## 5. Client Implementation & Defense-in-Depth (`blindwire-desktop`)
The client is distributed as a **Tauri v2** application, combining a Rust core with a React frontend.
*   **IPC Boundary**: The React/TypeScript frontend acts as a view layer. All cryptographic state and network sockets reside in the Rust backend. However, the Tauri frontend can still receive plaintext for display, which inevitably enters the V8/WebKit garbage-collected memory heap.
*   **Best-Effort Zeroization**: BlindWire employs best-effort zeroization of Rust-owned key material and selected buffers. When a session is dropped, the `Drop` trait ensures that cryptographic keys, symmetric state, and specific plaintext buffers within the Rust core are explicitly overwritten with zeros in RAM before the memory is freed. However, Tauri/WebView displayed plaintext is outside this guarantee. Complete memory wiping across the entire OS or webview cannot be guaranteed.
*   **Reproducible Builds**: To allow users to verify that published binaries correspond exactly to the source code, the project enforces reproducible builds. This requires a pinned toolchain, locked dependencies, a deterministic compiler profile (e.g., `codegen-units = 1`, LTO), and published checksums alongside releases.
