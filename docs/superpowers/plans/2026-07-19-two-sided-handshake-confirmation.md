# BlindWire Two-Sided Handshake Confirmation Implementation Plan

> Execute this plan test-first. Each task is independently committed and reviewed before the next task begins.

**Goal:** Replace relay-side Noise-frame guessing with an explicit, two-sided completion acknowledgement, close desktop session races, fail closed on TOFU persistence errors, and make the release test gate reproducible.

**Architecture:** Signaling protocol v3 adds client `HANDSHAKE_COMPLETE` and server `HANDSHAKE_CONFIRMED` packets. The relay owns token state transitions but never parses encrypted Noise payloads. Clients do not expose SAS or an active session until both peers have completed Noise and the relay confirms the pair. Desktop state changes are generation-owned and monotonic. Pin persistence errors are explicit and fatal where TOFU is used.

**Stack:** Rust, Tokio, Axum WebSockets, rustls, Tauri 2, React/TypeScript, Playwright.

## Task 1: Add Signaling v3 and Two-Sided Relay Confirmation

**Files:**
- Modify: `blindwire-server/src/lib.rs`
- Modify: `blindwire-server/src/main.rs`
- Modify: `blindwire-server/tests/level3_integration.rs`
- Modify: `blindwire-transport/src/relay.rs`
- Modify: `blindwire-transport/src/session.rs`
- Modify: `blindwire-transport/tests/e2e_test.rs`
- Modify: `SIGNALING_SPEC.md`
- Modify: `PROTOCOL_V2.md`

1. Add failing integration tests using production `Frame::to_wire()` framing for:
   - JOIN version `0x03` succeeds and `0x02` is rejected.
   - One completion packet does not consume the invite or confirm either client.
   - Both completion packets atomically consume the invite and send confirmation to both clients.
   - Duplicate completion packets are idempotent.
   - A responder disconnect before confirmation releases the reservation while the initiator remains connected.
   - An initiator disconnect before confirmation removes the incomplete room.
   - Completion packets with payload bytes are rejected.
   - A confirmed invite can never be reused.
2. Run the focused server tests and confirm the new tests fail for the expected missing behavior.
3. Split direction-specific opcodes. Accept client `0x03 HANDSHAKE_COMPLETE`; emit server `0x07 HANDSHAKE_CONFIRMED`; require exact packet lengths.
4. Replace relay Noise-frame inspection with per-role completion flags. Transition `Reserved -> Consumed` before queueing confirmation to both clients.
5. Implement the approved disconnect rules and make the per-IP connection decrement/removal atomic through the DashMap entry API.
6. Change the production default bind address to loopback and remove room identifiers from normal logs.
7. Add transport methods for completion/confirmation. Wrap peer wait, Noise XX, completion, responder retry, and confirmation in one 30-second handshake deadline. Reset the initiator's Noise state after an unconfirmed responder disconnect.
8. Add a full `SecureSession` e2e test showing confirmation gates successful handshake and the used invite cannot reconnect.
9. Update signaling/protocol documentation, run formatting, Clippy, and focused server/transport tests.
10. Commit: `feat: require two-sided handshake confirmation`

## Task 2: Make Desktop Session Ownership Generation-Safe

**Files:**
- Modify: `blindwire-desktop/src-tauri/src/state.rs`
- Modify: `blindwire-desktop/src-tauri/src/commands.rs`
- Modify: `blindwire-desktop/src-tauri/src/error.rs`
- Modify: `blindwire-desktop/src/App.tsx`
- Modify: `blindwire-desktop/src/types.ts`
- Modify: desktop Rust and Playwright tests adjacent to these modules

1. Add failing Rust tests proving:
   - Only one create/join attempt can own the desktop session slot.
   - A stale generation cannot install or clear a newer generation's sender/task/snapshot.
   - Peer verification is rejected outside the current generation's `Verifying` phase.
   - Send failure and disconnect clear verification and communication state only for their owning generation.
2. Add failing frontend tests proving same-generation snapshots with older revisions are ignored.
3. Add a single atomic session owner keyed by generation. Acquire it before spawning connection work, track the entire connect/handshake/session task immediately, and release it only through generation-scoped cleanup.
4. Install and clear sender/task state conditionally on generation ownership. Do not let stale asynchronous work mutate current state.
5. Add a monotonically increasing `revision` to room snapshots. Reject snapshots older than the latest `(generation, revision)` in React.
6. Permit `confirm_peer_verified` only for the current owner in `Verifying` with SAS data present. Clear verification on all owning-generation failure paths.
7. Map a pre-confirmation responder disconnect to the retryable invite lease flow; keep confirmed invites terminal.
8. Run desktop Rust tests, TypeScript checks, and targeted Playwright tests.
9. Commit: `fix: serialize desktop session lifecycle`

## Task 3: Make TOFU Pin Persistence Fail Closed

**Files:**
- Modify: `blindwire-transport/src/pinning.rs`
- Modify: `blindwire-transport/src/relay.rs`
- Modify: `blindwire-transport/src/error.rs`
- Modify: `blindwire-transport/tests/pinning_integration.rs`
- Modify: CLI/desktop configuration call sites as required

1. Add failing tests for malformed pin files, duplicate host records, failed writes, and concurrent writers.
2. Change pin lookup from `Option` to `Result<Option<Pin>, PinStoreError>` so missing, malformed, and inaccessible storage are distinct.
3. Serialize read-modify-write operations, write through a unique same-directory temporary file, flush and `sync_all`, atomically replace the destination, and sync the parent directory where supported.
4. Propagate first-use save failures through certificate verification. Never complete a TOFU connection unless the accepted pin is durably stored.
5. Remove the temporary-directory fallback. Require an explicit persistent pin path whenever TOFU is selected; pinned invites and official pins remain independent of TOFU storage.
6. Keep reset/remove operations fail closed and covered by tests.
7. Run pinning tests, transport tests, formatting, and Clippy.
8. Commit: `fix: fail closed on pin persistence errors`

## Task 4: Repair the Desktop Release Test Harness

**Files:**
- Modify: `blindwire-desktop/package.json`
- Modify: `blindwire-desktop/playwright.config.ts`
- Modify: `blindwire-desktop/tests/helpers/tauri.ts`
- Modify: `blindwire-desktop/tests/security-gate.spec.ts`
- Modify/add focused Playwright tests as needed

1. Add a Playwright `webServer` that starts Vite on `127.0.0.1:1420` for the debug Tauri binary.
2. Add a deterministic pretest build step so `npm test` does not depend on undocumented manual compilation.
3. Stop logging relay URLs or environment details from the harness and remove shell-based process invocation where unnecessary.
4. Strengthen the security gate to exercise real user-visible invite/verification behavior. Decode a rendered QR asset and assert it contains the exact invite URI.
5. Run `npm ci`, `npm test`, `npm run build`, and `npm audit`.
6. Commit: `test: make desktop release gate reproducible`

## Task 5: Full Release Gate and Final Security Review

1. Run `cargo fmt --all -- --check`.
2. Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
3. Run `cargo test --workspace -- --test-threads=1`.
4. Run desktop `npm ci`, `npm test`, `npm run build`, and `npm audit`.
5. Build the Tauri desktop application in the release-gate configuration.
6. Review the entire branch against the approved design, concentrating on opcode parsing, token transitions, disconnect races, stale desktop tasks, and pin-store failure handling.
7. Fix every Critical or Important finding, rerun affected checks, and document any external deployment/signing work that cannot be completed locally.

## Definition of Done

- The relay never interprets Noise payloads.
- SAS is not shown until both clients receive relay confirmation.
- Before confirmation, responder loss is retryable and initiator loss invalidates the room.
- After confirmation, the invitation is permanently consumed.
- Concurrent or stale desktop tasks cannot overwrite active state.
- TOFU cannot silently degrade because storage is missing, corrupt, or unwritable.
- The complete local release gate passes from a clean checkout with documented commands.
