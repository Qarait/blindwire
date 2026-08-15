# BlindWire Browser Static SPA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone static `blindwire-web` SPA whose dedicated Worker owns the Protocol 2.1 WASM session, signaling-v4 WebSocket, encrypted IndexedDB recovery vault, and all secret-bearing state.

**Architecture:** Add `blindwire-web/` beside `blindwire-desktop/`. React talks only to a typed Worker controller. The Worker validates invites through a small WASM export, encodes signaling-v4 packets, drives `WebSession`, encrypts recovery payloads with Web Crypto before IndexedDB persistence, and emits redacted public events.

**Tech Stack:** Rust/WASM (`blindwire-web-core` + `wasm-bindgen`), TypeScript 5.8, React 19, Vite 8, Vitest, Playwright, `qrcode.react`, WebSocket, Web Crypto, and IndexedDB.

## Global Constraints

- `blindwire-web` must contain no `@tauri-apps/*` imports.
- React may receive the exact canonical one-time invite URI only for immediate text/QR sharing; it must never receive a separate token field, capabilities, room bytes, relay pins, snapshot bytes, ciphertext, or raw relay packets.
- Noise, SAS, continuity derivation, message encryption, authenticated recovery, ratcheting, and burn remain in Rust/WASM.
- Signaling-v4 uses version byte `0x04`, big-endian integers, binary packets only, and a 1..4096-byte opaque frame limit.
- Production browser relay connections use only `wss://relay.blindwire.net`; `ws://localhost` and `ws://127.0.0.1` are test/dev-only.
- IndexedDB stores only `{version, salt, iv, ciphertext}` for the recovery record; the passphrase is never persisted.
- PBKDF2-HMAC-SHA-256 uses exactly 600,000 iterations; AES-GCM uses a 32-byte key and a 12-byte IV.
- Burn and terminal authentication/protocol failures delete the recovery record and prevent in-place trust bypasses.
- Generated `blindwire-web/src/wasm/`, Vite `dist/`, Playwright reports, and test results are not committed.
- Every behavior change follows red-green-refactor: write one failing test, run it and observe the expected failure, implement the minimum behavior, run the test green, then refactor only while green.

---

### Task 1: Add the browser package and static build harness

**Files:**
- Create: `blindwire-web/package.json`
- Create: `blindwire-web/tsconfig.json`
- Create: `blindwire-web/vite.config.ts`
- Create: `blindwire-web/index.html`
- Create: `blindwire-web/src/main.tsx`
- Create: `blindwire-web/src/vite-env.d.ts`
- Create: `blindwire-web/scripts/build-wasm.mjs`
- Modify: `.gitignore`

**Interfaces:**
- Produces a Vite package with `npm run dev`, `npm run build`, `npm test`, and `npm run test:e2e` scripts.
- Produces an ignored `blindwire-web/src/wasm/` directory containing the `wasm-pack --target web` output consumed by `src/worker/wasm.ts`.

- [ ] **Step 1: Add the package manifest and TypeScript/Vite configuration**

Use this dependency split and script contract:

```json
{
  "name": "blindwire-web",
  "private": true,
  "version": "2.0.0-beta.3",
  "type": "module",
  "scripts": {
    "dev": "npm run wasm:dev && vite",
    "build": "tsc --noEmit && npm run wasm:release && vite build",
    "preview": "vite preview",
    "wasm:dev": "node scripts/build-wasm.mjs --dev",
    "wasm:release": "node scripts/build-wasm.mjs --release",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:e2e": "playwright test",
    "test:all": "npm test && npm run build && npm run test:e2e"
  }
}
```

Add React, React DOM, and `qrcode.react` as runtime dependencies. Add TypeScript, Vite, `@vitejs/plugin-react`, Vitest, jsdom, `fake-indexeddb`, Playwright, and the React/Node type packages as development dependencies. Use strict TypeScript, `moduleResolution: "Bundler"`, `noEmit: true`, and `src` as the root directory.

- [ ] **Step 2: Add the WASM build script**

Implement `scripts/build-wasm.mjs` so it resolves the repository root from `import.meta.url`, removes only the known generated directory `blindwire-web/src/wasm`, creates that directory, and invokes:

```text
wasm-pack build <repo>/blindwire-web-core --target web --out-dir <repo>/blindwire-web/src/wasm --dev|--release
```

Pass through the child process exit code and throw a clear error when `wasm-pack` is unavailable. Do not use a shell command string or a broad recursive path.

- [ ] **Step 3: Add CSP and a minimal entry point**

Put the production CSP from the spec in an `http-equiv="Content-Security-Policy"` meta tag in `index.html`. Include only the local `/src/main.tsx` module and the root mount element. `main.tsx` may render a minimal `<App />` shell until Task 9; it must not import Tauri.

Add a Vite `transformIndexHtml` dev-server hook that replaces only the served development HTML directive `connect-src 'self' wss:` with `connect-src 'self' ws: wss:`. The hook must run only when Vite supplies a dev server context; `vite build` must leave `dist/index.html` production-safe.

- [ ] **Step 4: Ignore generated browser artifacts and verify the harness**

Add these exact patterns to `.gitignore`:

```text
blindwire-web/src/wasm/
blindwire-web/dist/
blindwire-web/playwright-report/
blindwire-web/test-results/
```

Run `npm install` in `blindwire-web`, then run `npm run wasm:dev` and `npm run build`.

Expected: the generated WASM directory and `dist/` exist locally, both are ignored, and the Vite build exits 0 with no Tauri dependency.

- [ ] **Step 5: Commit the package harness**

```bash
git add .gitignore blindwire-web/package.json blindwire-web/package-lock.json blindwire-web/tsconfig.json blindwire-web/vite.config.ts blindwire-web/index.html blindwire-web/src/main.tsx blindwire-web/src/vite-env.d.ts blindwire-web/scripts/build-wasm.mjs
git commit -m "feat: scaffold browser static SPA"
```

### Task 2: Expose strict invite validation through the WASM boundary

**Files:**
- Modify: `blindwire-web-core/src/lib.rs`
- Modify: `blindwire-web-core/tests/web.rs`

**Interfaces:**
- Produces `parse_invite(uri: &str) -> Result<JsValue, JsValue>` exported by `blindwire-web-core`.
- Produces `copy_worker_snapshot_for_storage(&self, expires_at_ms: u64) -> Result<Vec<u8>, JsValue>` exported by `WebSession`; unlike the existing consuming snapshot method, it leaves the live session usable and is called only by the Worker.
- The returned object contains only `{ room, token, expires_at, relay_url, relay_pin, official_relay }` and is consumed only in the Worker.

- [ ] **Step 1: Write the failing WASM test**

Add a browser test that calls `parse_invite` with a valid official invite and deserializes the result:

```rust
#[wasm_bindgen_test]
fn parse_invite_returns_validated_worker_descriptor() {
    let exp = now_ms() + 3_600_000;
    let uri = format!(
        "blindwire://join?v=1&r=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&t=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&e={exp}"
    );
    let descriptor: InviteDescriptor = serde_wasm_bindgen::from_value(parse_invite(&uri).unwrap()).unwrap();
    assert_eq!(descriptor.relay_url, "wss://relay.blindwire.net/");
    assert!(descriptor.official_relay);
    assert_eq!(descriptor.relay_pin, None);
}
```

Add a second test asserting malformed/duplicate fields return a public `INVITE_INVALID` error object rather than a panic. Update the exported-method allowlist with `parse_invite` and `copy_worker_snapshot_for_storage`.

Add a test that creates an established session, calls `copy_worker_snapshot_for_storage`, then successfully calls `send_text` on the same session. This proves the browser checkpoint does not consume the active session.

- [ ] **Step 2: Run the focused test and verify red**

Run:

```bash
wasm-pack test --headless --chrome blindwire-web-core -- --test-threads=1
```

Expected: compilation/test failure because `parse_invite` and its descriptor do not exist.

- [ ] **Step 3: Implement the minimal Rust export**

Use `blindwire_core::invite::InvitePayload::parse`. Serialize the validated strings and a boolean indicating `relay.blindwire.net`. Map every `InviteError` to `{ code: "INVITE_INVALID", message: "The invite link is invalid or expired." }` so the Worker cannot expose parser internals or token data. Keep the export free of token logging. Factor the existing worker snapshot encoder so the consuming method takes the continuity secret, while `copy_worker_snapshot_for_storage` uses a temporary zeroized copy of the continuity bytes and leaves the session's `continuity`, pending IDs, and deduplicator intact.

- [ ] **Step 4: Run the focused test and verify green**

Run the same `wasm-pack test` command. Expected: the invite tests and existing web-core tests pass.

- [ ] **Step 5: Commit the WASM boundary**

```bash
git add blindwire-web-core/src/lib.rs blindwire-web-core/tests/web.rs
git commit -m "feat: expose validated browser invite parsing"
```

### Task 3: Implement Worker-only invite helpers

**Files:**
- Create: `blindwire-web/src/invite.ts`
- Create: `blindwire-web/tests/invite.test.ts`

**Interfaces:**
- Produces `base64UrlEncode(bytes: Uint8Array): string`.
- Produces `buildOfficialInviteUri(room: Uint8Array, token: Uint8Array, expiresAt: number): string`.
- Produces `toInvitePreview(descriptor: WasmInviteDescriptor): InvitePreview`.
- `invite.ts` is imported by Worker code only.

- [ ] **Step 1: Write failing invite helper tests**

```ts
it('builds the canonical official invite URI without padding', () => {
  const uri = buildOfficialInviteUri(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), 1890000000000);
  expect(uri).toBe('blindwire://join?v=1&r=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&t=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI&e=1890000000000&u=wss%3A%2F%2Frelay.blindwire.net');
});
```

Add tests for round-trip base64url conversion, truncated room preview labels, and rejection of non-32-byte room/token inputs.

- [ ] **Step 2: Run the focused Vitest file and verify red**

Run `npm test -- invite.test.ts`. Expected: failure because the module/functions do not exist.

- [ ] **Step 3: Implement the helpers**

Use `btoa`/`Uint8Array` conversion without `Buffer`, remove `=` padding, and use `URLSearchParams` only for the relay URL value. Keep the URI field order exactly `v`, `r`, `t`, `e`, `u`. The preview must expose only a truncated room label, relay label, custom/official boolean, and expiry.

- [ ] **Step 4: Run invite tests and the TypeScript checker**

Run `npm test -- invite.test.ts` and `npm run build`. Expected: focused tests pass and build reaches the generated-WASM import error only if Task 1's build hook was not run; run `npm run wasm:dev` before treating that as a failure.

- [ ] **Step 5: Commit invite helpers**

```bash
git add blindwire-web/src/invite.ts blindwire-web/tests/invite.test.ts
git commit -m "feat: add browser invite helpers"
```

### Task 4: Implement the signaling-v4 packet codec

**Files:**
- Create: `blindwire-web/src/worker/relay.ts`
- Create: `blindwire-web/tests/relay.test.ts`

**Interfaces:**
- Produces `encodeClientPacket(packet: ClientPacket): Uint8Array`.
- Produces `parseServerPacket(bytes: Uint8Array): ServerPacket`.
- Produces `RelayClient.connectInitial(url, role, room, token?): Promise<RelayClient>`.
- Produces `RelayClient.connectResume(url, role, room, capability, epoch): Promise<RelayClient>`.
- Produces `RelayClient.events(): AsyncIterable<RelayEvent>` and `sendFrame`, `sendHandshakeComplete`, `registerRecovery`, `burn`, `quit`, and `close` methods.

- [ ] **Step 1: Write exact-byte codec tests**

```ts
it('encodes a responder JOIN with v4 and a token', () => {
  const packet = encodeClientPacket({ type: 'join', role: 'responder', room: new Uint8Array(32).fill(0x11), token: new Uint8Array(32).fill(0x22) });
  expect([...packet.slice(0, 3)]).toEqual([0x00, 0x72, 0x04]);
  expect(packet).toHaveLength(67);
});

it('rejects a relay frame whose declared length is not exact', () => {
  expect(() => parseServerPacket(new Uint8Array([0x01, 0x00, 0x04, 0xaa]))).toThrow('INVALID_PACKET');
});
```

Cover every client/server opcode, u64 epoch encoding, 4096-byte acceptance, 4097-byte rejection, unknown opcodes, wrong versions, truncated controls, and non-binary message rejection in the WebSocket adapter.

- [ ] **Step 2: Run the codec tests and verify red**

Run `npm test -- relay.test.ts`. Expected: failure because the codec and relay types do not exist.

- [ ] **Step 3: Implement pure packet encoding/parsing**

Use `DataView` with big-endian writes/reads. Copy incoming bytes before storing them. Parse relay payloads as opaque `Uint8Array` without inspecting them. Return sanitized error codes only; never include packet bytes in an exception.

- [ ] **Step 4: Implement the WebSocket adapter**

Open `new WebSocket(url)`, set `binaryType = 'arraybuffer'`, reject text messages, and enqueue parsed server events. Enforce `wss://` outside a test-only localhost guard. Resolve initial connections only after TOKEN for initiators or PEER_JOINED for responders; resolve resume connections only after RESUME_READY. Reject close/error/timeouts with a retryability-coded `RelayError`.

- [ ] **Step 5: Run the relay tests and commit**

Run `npm test -- relay.test.ts`. Expected: all codec and adapter unit tests pass.

```bash
git add blindwire-web/src/worker/relay.ts blindwire-web/tests/relay.test.ts
git commit -m "feat: add browser signaling v4 relay client"
```

### Task 5: Implement the encrypted IndexedDB recovery vault

**Files:**
- Create: `blindwire-web/src/worker/vault.ts`
- Create: `blindwire-web/tests/vault.test.ts`

**Interfaces:**
- Produces `openVault(): Promise<RecoveryVault>`.
- `RecoveryVault.save(passphrase, payload): Promise<void>`.
- `RecoveryVault.load(passphrase, nowMs): Promise<RecoveryPayload>`.
- `RecoveryVault.hasRecord(): Promise<boolean>`.
- `RecoveryVault.clear(): Promise<void>`.
- The IndexedDB record type is exactly `{ version: 1, salt: ArrayBuffer, iv: ArrayBuffer, ciphertext: ArrayBuffer }`.

- [ ] **Step 1: Write failing vault tests**

Use `fake-indexeddb/auto` in the Vitest setup and assert behavior, not mock calls:

```ts
it('round-trips a payload while persisting ciphertext only', async () => {
  const vault = await openVault();
  await vault.save('correct horse battery staple', { snapshot: new Uint8Array([1, 2]), capability: new Uint8Array([3]), epoch: 4, relayUrl: 'wss://relay.blindwire.net', role: 'initiator' });
  const record = await readRawRecordForTest();
  expect(record).toEqual(expect.objectContaining({ version: 1, salt: expect.any(ArrayBuffer), iv: expect.any(ArrayBuffer), ciphertext: expect.any(ArrayBuffer) }));
  expect(JSON.stringify(record)).not.toContain('correct horse');
  await expect(vault.load('wrong passphrase', Date.now())).rejects.toMatchObject({ code: 'RECOVERY_UNLOCK_FAILED' });
  await expect(vault.load('correct horse battery staple', Date.now())).resolves.toMatchObject({ epoch: 4 });
});
```

Add tests for a fresh random salt/IV on each save, expiry rejection, unsupported version rejection, and clear/delete.

- [ ] **Step 2: Run vault tests and verify red**

Run `npm test -- vault.test.ts`. Expected: failure because the vault module does not exist.

- [ ] **Step 3: Implement PBKDF2/AES-GCM and IndexedDB storage**

Encode the payload as JSON with byte arrays converted to base64url. Derive a non-exportable AES-GCM key with Web Crypto using 600,000 PBKDF2 iterations, encrypt with a random 12-byte IV and optional associated data `blindwire/recovery/v1`, and store only the record fields. Map every decrypt/parse/expiry failure to the same generic public error. Keep database name `blindwire-recovery-v1`, object store `snapshots`, and fixed key `current`.

- [ ] **Step 4: Run vault tests and commit**

Run `npm test -- vault.test.ts` and verify all vault tests pass.

```bash
git add blindwire-web/src/worker/vault.ts blindwire-web/tests/vault.test.ts blindwire-web/tests/setup.ts
git commit -m "feat: add encrypted browser recovery vault"
```

### Task 6: Add public Worker types and the controller reducer

**Files:**
- Create: `blindwire-web/src/types.ts`
- Create: `blindwire-web/src/controller.ts`
- Create: `blindwire-web/tests/controller.test.ts`

**Interfaces:**
- `types.ts` exports the exact `WorkerCommand`, `WorkerEvent`, `RoomSnapshot`, `InvitePreview`, `PublicError`, and `RoomPhase` unions from the design spec.
- `InvitePreview` is `{ room_label: string; relay_label: string; official_relay: boolean; expires_at: number }`.
- `createController(worker: WorkerLike): Controller` returns `{ dispatch, handleEvent, subscribe, getSnapshot, terminate }`.
- `reduceSnapshot(snapshot, event): RoomSnapshot` is pure and exported for tests.

- [ ] **Step 1: Write failing reducer/controller tests**

```ts
it('ignores a stale terminal event after a newer idle generation', () => {
  const controller = createController(new RecordingWorker());
  controller.dispatch({ type: 'leave_room' });
  controller.workerMessage({ type: 'state', snapshot: idleSnapshot() });
  controller.workerMessage({ type: 'error', error: { code: 'OLD', message: 'old', retryable: false } });
  expect(controller.getSnapshot().phase).toBe('idle');
});

it('never projects worker-only fields into public state', () => {
  const publicState = reduceSnapshot(initialSnapshot(), { type: 'state', snapshot: activeSnapshot() });
  expect(JSON.stringify(publicState)).not.toContain('capability');
  expect(JSON.stringify(publicState)).not.toContain('ciphertext');
});
```

Cover subscribe/unsubscribe, command serialization, invite preview projection, verification, queued/received/acknowledged message events, recovery availability, and fatal error projection.

- [ ] **Step 2: Run controller tests and verify red**

Run `npm test -- controller.test.ts`. Expected: failure because the types, reducer, and controller do not exist.

- [ ] **Step 3: Implement types, reducer, and Worker wrapper**

Use a `WorkerLike` interface with `postMessage`, `addEventListener`, `removeEventListener`, and `terminate`. The controller must send commands without modifying their string values, accept only known event discriminants through `handleEvent`, and keep the last public snapshot immutable to subscribers. Add a test-only `RecordingWorker` implementing the same interface so command serialization is observed through real `postMessage` data.

- [ ] **Step 4: Run controller tests and commit**

Run `npm test -- controller.test.ts` and verify all controller tests pass.

```bash
git add blindwire-web/src/types.ts blindwire-web/src/controller.ts blindwire-web/tests/controller.test.ts
git commit -m "feat: add typed browser worker controller"
```

### Task 7: Drive initial create/join through the Worker and WASM

**Files:**
- Create: `blindwire-web/src/worker/wasm.ts`
- Create: `blindwire-web/src/worker/worker.ts`
- Create: `blindwire-web/tests/worker-lifecycle.test.ts`

**Interfaces:**
- `loadWasm(): Promise<WasmModule>` lazy-loads and initializes the generated web-target WASM exactly once.
- The Worker listens for `WorkerCommand` and posts only `WorkerEvent`.
- `WorkerRuntime` owns one `generation`, one `RelayClient`, one `WebSession`, and all binary/secret state.
- `tests/workerHarness.ts` exports `makeWorkerHarness()` and `makeWorkerHarnessAt(phase)`; each returns `{ command, flush, events, lastEvent, snapshot, relay, vault }` and drives the real `WorkerRuntime` with injected relay/WASM/vault dependencies.

- [ ] **Step 1: Write failing Worker lifecycle tests**

Use a real fake relay queue and a fake WASM session implementation behind a Worker-runtime dependency interface; assert public behavior rather than private method calls:

```ts
it('creates an official invite only after receiving the relay token', async () => {
  const harness = makeWorkerHarness();
  await harness.command({ type: 'create_room' });
  expect(harness.events()).toContainEqual(expect.objectContaining({ type: 'state', snapshot: expect.objectContaining({ phase: 'connecting' }) }));
  expect(harness.events()).not.toContainEqual(expect.objectContaining({ type: 'invite_ready' }));
  harness.relay.emit({ type: 'token', token: new Uint8Array(32).fill(7) });
  await harness.flush();
  expect(harness.lastEvent('invite_ready')).toEqual(expect.objectContaining({ uri: expect.stringContaining('blindwire://join?v=1') }));
});
```

Add tests for responder invite preview/confirmation, initiator waits for PEER_JOINED, only initiators call `start_handshake`, opaque WASM outbound frames become relay RELAY packets, malformed WASM public events become fatal, and public events contain no binary secret fields.

- [ ] **Step 2: Run Worker tests and verify red**

Run `npm test -- worker-lifecycle.test.ts`. Expected: failure because the WASM loader and Worker runtime do not exist.

- [ ] **Step 3: Implement the WASM adapter**

Import the generated `blindwire_web_core.js` module dynamically, await its default initializer, and type only the exported methods used by the Worker: `generate_random_32`, `parse_invite`, `WebSession.new`, `start_handshake`, `receive_frame`, `relay_handshake_confirmed`, `confirm_user_verified`, `send_text`, `burn`, `copy_worker_snapshot_for_storage`, `restore_worker_snapshot`, `begin_recovery`, and `accept_resume_proof`. Normalize each WASM call result into `{ events, message_id? }` and each error into a `PublicError` without serializing the full JS error.

- [ ] **Step 4: Implement initial lifecycle handling**

For create, generate a 32-byte room, connect initiator, wait for TOKEN, build the one-hour official invite, and keep the session in `invite_ready`. For join, call WASM `parse_invite`, reject non-official production relays, hold the descriptor only in Worker memory, emit `invite_preview`, and connect only after `confirm_join`.

After JOIN, route events as follows:

```text
PEER_JOINED -> initiator start_handshake
RELAY(frame) -> WebSession.receive_frame(frame)
WASM outbound(frame) -> relay.sendFrame(frame)
Noise complete -> relay.sendHandshakeComplete()
HANDSHAKE_CONFIRMED -> WebSession.relay_handshake_confirmed()
WASM verification -> register capability, emit verification_ready
confirm_verification -> WebSession.confirm_user_verified()
peer_verified + local_verified -> active
```

Use a generation-scoped async loop. On replacement, close the old relay and ignore its queued events. Map relay error codes to public, non-sensitive messages.

- [ ] **Step 5: Run Worker lifecycle tests and commit**

Run `npm test -- worker-lifecycle.test.ts`. Expected: all initial lifecycle tests pass.

```bash
git add blindwire-web/src/worker/wasm.ts blindwire-web/src/worker/worker.ts blindwire-web/tests/worker-lifecycle.test.ts
git commit -m "feat: drive browser sessions from a dedicated worker"
```

### Task 8: Add messaging, burn, disconnect, and recovery sequencing

**Files:**
- Modify: `blindwire-web/src/worker/worker.ts`
- Modify: `blindwire-web/src/worker/relay.ts`
- Modify: `blindwire-web/src/worker/vault.ts`
- Create: `blindwire-web/tests/worker-recovery.test.ts`

**Interfaces:**
- Extends the Worker runtime with `send_text`, `enable_recovery`, `resume_recovery`, `burn_room`, and `leave_room` behavior.
- Adds `RecoveryPayload` serialization private to `vault.ts`.

- [ ] **Step 1: Write failing messaging/terminal/recovery tests**

```ts
it('does not send text until both verification flags are true', async () => {
  const harness = makeWorkerHarnessAt('verifying');
  await harness.command({ type: 'send_text', text: 'blocked' });
  expect(harness.lastEvent('error')).toMatchObject({ error: { code: 'VERIFICATION_REQUIRED' } });
  harness.peerVerified();
  await harness.command({ type: 'send_text', text: 'allowed' });
  expect(harness.relay.sentFrames()).toHaveLength(1);
});

it('deletes the vault after a terminal burn', async () => {
  const harness = makeWorkerHarnessAt('active');
  await harness.command({ type: 'burn_room' });
  expect(await harness.vault.hasRecord()).toBe(false);
  expect(harness.snapshot().phase).toBe('burned');
});
```

Add recovery tests for checkpoint encryption before IndexedDB save, the live session remaining active after `enable_recovery`, authenticated resume from a later reload, buffering resume-proof frames until `HANDSHAKE_CONFIRMED`, `PeerResuming` causing the connected peer to call `begin_recovery`, new capability registration and refreshed encrypted checkpoint after `recovered`, wrong-passphrase generic error, stale epoch rejection, peer disconnect projection, and leave clearing the vault.

- [ ] **Step 2: Run the focused tests and verify red**

Run `npm test -- worker-recovery.test.ts`. Expected: failures for the missing Worker command handling and recovery sequence.

- [ ] **Step 3: Implement messaging and terminal state transitions**

On `send_text`, reject empty/NUL/over-4000-byte text before calling WASM; report `message_queued` from the returned message ID and echo the local timestamp. Convert WASM `text` and `acknowledgement` events into public message events. On `burn_room`, send the encrypted burn frame, signaling BURN, delete the vault, close the socket, and set `burned`. On `leave_room`, send QUIT, delete the vault, close, and set `idle`.

- [ ] **Step 4: Implement checkpoint and resume**

For `enable_recovery`, call `copy_worker_snapshot_for_storage`, build a private payload containing snapshot bytes, capability bytes, official relay URL, role, and current epoch, and save it with the passphrase while leaving the live session active. For `resume_recovery`, restore the snapshot, connect RESUME with the old capability/epoch, begin recovery at `epoch + 1`, hold any outbound resume proof until the relay sends HANDSHAKE_CONFIRMED, then flush it. On `recovered`, generate/register a fresh capability, create a new non-consuming snapshot at the new epoch, replace the encrypted vault record using the supplied passphrase, and emit `recovered` plus an active state. A connected peer that handles `PeerResuming` clears its old checkpoint after recovery because it does not retain the passphrase.

For `PeerResuming`, require exactly `currentEpoch + 1`, call `begin_recovery(epoch)`, buffer recovery outbound frames until handshake confirmation, and complete the same frame routing. Any invalid proof or stale epoch is fatal and deletes the vault.

- [ ] **Step 5: Run recovery tests and commit**

Run `npm test -- worker-recovery.test.ts` and then `npm test`. Expected: all browser unit tests pass.

```bash
git add blindwire-web/src/worker/worker.ts blindwire-web/src/worker/relay.ts blindwire-web/src/worker/vault.ts blindwire-web/tests/worker-recovery.test.ts
git commit -m "feat: add browser messaging and authenticated recovery"
```

### Task 9: Build the React UI against the public controller

**Files:**
- Modify: `blindwire-web/src/main.tsx`
- Create: `blindwire-web/src/App.tsx`
- Create: `blindwire-web/src/App.css`
- Create: `blindwire-web/src/components/HomeView.tsx`
- Create: `blindwire-web/src/components/InviteView.tsx`
- Create: `blindwire-web/src/components/JoinView.tsx`
- Create: `blindwire-web/src/components/VerificationView.tsx`
- Create: `blindwire-web/src/components/ChatView.tsx`
- Create: `blindwire-web/src/components/RecoveryView.tsx`
- Create: `blindwire-web/src/components/StatusView.tsx`
- Create: `blindwire-web/tests/ui.test.tsx`

**Interfaces:**
- Components consume only `RoomSnapshot`, `InvitePreview`, public message events, and controller callbacks.
- No component imports `worker.ts`, `relay.ts`, `vault.ts`, `wasm.ts`, `crypto`, `indexedDB`, or `WebSocket`.

- [ ] **Step 1: Write failing component tests**

```tsx
it('renders the exact invite URI in the read-only input and QR value', () => {
  render(<InviteView uri="blindwire://join?v=1&r=room&t=token&e=1890000000000&u=wss%3A%2F%2Frelay.blindwire.net" onCancel={vi.fn()} />);
  const input = screen.getByLabelText('Invite link');
  expect(input).toHaveValue('blindwire://join?v=1&r=room&t=token&e=1890000000000&u=wss%3A%2F%2Frelay.blindwire.net');
  expect(screen.getByTestId('invite-qr')).toHaveAttribute('data-qr-value', input.getAttribute('value'));
});

it('keeps chat send disabled before the active phase', () => {
  render(<ChatView phase="verifying" messages={[]} onSend={vi.fn()} />);
  expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled();
});
```

Add tests for home create/paste, join confirmation, explicit SAS confirmation, recovery passphrase entry, generic errors, burn/leave actions, and peer-disconnected read-only behavior.

- [ ] **Step 2: Run UI tests and verify red**

Run `npm test -- ui.test.tsx`. Expected: failure because the components do not exist.

- [ ] **Step 3: Implement the views and App state projection**

Render `HomeView`, `InviteView`, `JoinView`, `StatusView`, `VerificationView`, `ChatView`, and `RecoveryView` from the controller's public snapshot. Use `QRCodeSVG` with `value={uri}` and `data-qr-value={uri}`. Use system fonts only. The verification view must explain that both users compare the same seven emojis/numeric SAS and require a button click. The chat view must show queued/received/acknowledged messages without exposing IDs as secrets.

- [ ] **Step 4: Run UI tests and commit**

Run `npm test -- ui.test.tsx` and `npm run build`. Expected: all component tests pass and Vite emits a static bundle.

```bash
git add blindwire-web/src/main.tsx blindwire-web/src/App.tsx blindwire-web/src/App.css blindwire-web/src/components blindwire-web/tests/ui.test.tsx
git commit -m "feat: add browser room and chat UI"
```

### Task 10: Add browser E2E, CSP, and source security gates

**Files:**
- Create: `blindwire-web/playwright.config.ts`
- Create: `blindwire-web/tests/e2e/static-security.spec.ts`
- Create: `blindwire-web/tests/e2e/browser-room.spec.ts`
- Create: `blindwire-web/tests/e2e/recovery.spec.ts`
- Create: `blindwire-web/tests/e2e/helpers.ts`
- Create: `blindwire-web/tests/csp.test.ts`

**Interfaces:**
- Playwright runs Chromium and Firefox against the Vite preview server.
- The E2E helper starts the repository's v4 relay on an allowed local test address and supplies a test invite without weakening production source checks.

- [ ] **Step 1: Write security/CSP tests**

```ts
it('ships a restrictive CSP without remote code or insecure production WebSockets', async () => {
  const html = await readFile('dist/index.html', 'utf8');
  expect(html).toContain("default-src 'self'");
  expect(html).toContain("worker-src 'self'");
  expect(html).not.toContain("unsafe-inline");
  expect(html).not.toContain("unsafe-eval");
  expect(html).not.toContain('ws:');
});
```

Add a source scan asserting `blindwire-web/src` contains no `@tauri-apps`, no Google Fonts/imported remote URLs, no `console.log` of invite/message fields, and no browser secret API usage outside `src/worker/`. Assert against generated `dist/index.html` for CSP: it must not contain `ws:`, `unsafe-inline`, or `unsafe-eval`, while the dev-only Vite transform may contain the localhost test allowance.

- [ ] **Step 2: Run security tests and verify red**

Run `npm run build; npm test -- csp.test.ts`. Expected: failure until the final CSP and source rules are present.

- [ ] **Step 3: Add Playwright browser-room coverage**

The happy-path test must:

1. Open two browser contexts.
2. Create a room in context A and extract the rendered invite URI.
3. Paste it into context B and confirm join.
4. Assert both contexts reach verification and display equal SAS values.
5. Confirm verification on both sides.
6. Exchange a message in each direction and assert ACK/received rendering.
7. Burn from one side and assert both sides reach terminal burned/error UI.

Run the same test project in Chromium and Firefox. Never assert on raw relay frames, token values, or secret bytes.

- [ ] **Step 4: Add recovery E2E coverage**

After verification, enable recovery in context A with a passphrase, reload the page, resume the saved room with the same passphrase, assert recovery returns to active, and verify that a wrong passphrase yields only the generic unlock error. Inspect IndexedDB through the browser context and assert the record has version/salt/iv/ciphertext but no plaintext room, token, passphrase, or message body.

- [ ] **Step 5: Run the browser suite and commit**

Run `npm run test:all`. Expected: TypeScript, unit, build, Chromium, Firefox, and static security tests pass.

```bash
git add blindwire-web/playwright.config.ts blindwire-web/tests/e2e blindwire-web/tests/csp.test.ts
git commit -m "test: verify browser SPA security and room flows"
```

### Task 11: Run repository-wide verification and review for secret leakage

**Files:**
- Modify: `blindwire-web/README.md` if a package usage document is needed by the final build output.
- Modify: `docs/superpowers/specs/2026-08-15-browser-web-spa-design.md` only if verification finds a documented mismatch.

- [ ] **Step 1: Run fresh Rust and WASM verification**

```bash
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
wasm-pack test --headless --chrome blindwire-web-core
```

Expected: all commands exit 0.

- [ ] **Step 2: Run fresh browser verification**

```bash
Set-Location blindwire-web
npm test
npm run build
npm run test:e2e
```

Expected: Vitest, TypeScript/Vite build, Chromium, and Firefox exit 0.

- [ ] **Step 3: Review the diff and source boundaries**

Run:

```bash
git diff --check HEAD~10..HEAD
rg -n "token|capability|snapshot|ciphertext|relay_pin|WebSocket|indexedDB|crypto\.subtle" blindwire-web/src
git status --short --branch
```

Confirm secret-bearing matches are limited to Worker/vault/WASM adapter code, no React component imports a Worker-internal module, generated artifacts are ignored, and the working tree contains only intended changes.

- [ ] **Step 4: Commit any verification-only documentation update**

If and only if the final implementation requires a documented correction, update the spec and commit it with:

```bash
git add docs/superpowers/specs/2026-08-15-browser-web-spa-design.md blindwire-web/README.md
git commit -m "docs: finalize browser SPA verification notes"
```

- [ ] **Step 5: Report the exact verification evidence**

Record the test counts, build exit status, branch name, and commit range. Do not claim completion until the fresh commands above have been read and confirmed successful.
