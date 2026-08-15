# BlindWire Browser Static SPA

## Status

Design approved in conversation. This slice builds the browser-first website
as a standalone static single-page application beside the existing Tauri
desktop app. It consumes the completed Protocol 2.1 WebAssembly boundary and
does not replace or alter the desktop target.

## Context

The repository now contains:

- a version-isolated signaling-v4 relay contract;
- the native Protocol 2.1 session and recovery implementation;
- `blindwire-web-core`, a narrow WebAssembly session boundary with Noise,
  encrypted application frames, verification, burn, and recovery snapshots.

The remaining product surface is a real browser website. A browser cannot use
Tauri commands or native TLS certificate/SPKI APIs, so it needs its own Worker,
WebSocket relay client, encrypted IndexedDB vault, and React UI.

## Goals

1. Add a standalone `blindwire-web` Vite/React/TypeScript SPA.
2. Keep WebSocket, WASM, Web Crypto, IndexedDB, invite parsing, and all
   secret-bearing session state inside one dedicated Web Worker.
3. Implement signaling-v4 binary packet encoding/decoding in the Worker and
   forward only opaque Protocol 2.1 frames to the WASM session.
4. Support create-room, invite/QR join, two-sided SAS verification, encrypted
   text messaging, explicit burn, leave, and peer-disconnect states.
5. Support an explicit passphrase-protected recovery checkpoint stored as
   AES-GCM ciphertext in IndexedDB, followed by authenticated recovery over a
   fresh Noise session.
6. Produce a static `dist/` bundle with a restrictive CSP and no remote
   scripts, fonts, images, or runtime server requirement.
7. Test the Worker/controller boundary and browser UI in Chromium and Firefox.

## Non-goals

- No SSR, API server, backend session state, or user account system.
- No plaintext message or key persistence outside the live Worker memory.
- No crypto implementation in TypeScript; Noise, SAS, message encryption,
  recovery proofs, and continuity ratcheting remain in Rust/WASM.
- No Tauri imports or desktop command/event dependencies in `blindwire-web`.
- No browser attempt to emulate native SPKI pin verification.
- No custom production relay support until a browser-verifiable relay identity
  mechanism exists. Production browser invites use the official relay; local
  `ws://localhost` is permitted only in development/test builds.
- No service worker, push notifications, offline message queue, analytics, or
  remote feature flags.

## Architecture

The browser process is divided into two trust boundaries:

```text
React UI  <-- typed public events/commands -->  Dedicated Worker
                                                   |
                         +-------------------------+----------------------+
                         |                         |                      |
                   WebSession WASM          WebSocket v4          IndexedDB vault
                   Noise + protocol         opaque relay            ciphertext only
```

React renders public state and accepts user actions only. It never imports
WebSocket, WASM, IndexedDB, Web Crypto, or invite/token parsing code.

The Worker owns one session generation at a time. Every asynchronous relay
event is ignored after the generation is replaced or terminated. A malformed
relay packet, malformed WASM event, cryptographic failure, expiry, failed
invite validation, or terminal burn moves the generation to a fatal/terminal
state and clears recoverable state as required.

### Package layout

Create a new package at `blindwire-web/`:

- `src/main.tsx`: React entry point.
- `src/App.tsx`: public state projection and view selection.
- `src/App.css`: local/system-font responsive visual layer.
- `src/controller.ts`: typed Worker client and public state reducer.
- `src/types.ts`: public command, event, snapshot, invite-preview, and error
  types.
- `src/invite.ts`: Worker-only invite URI helpers and base64url conversion.
- `src/worker/worker.ts`: Worker command dispatcher and lifecycle owner.
- `src/worker/relay.ts`: WebSocket lifecycle and signaling-v4 packet codec.
- `src/worker/vault.ts`: PBKDF2/AES-GCM envelope and IndexedDB storage.
- `src/worker/wasm.ts`: lazy, single-instance `blindwire-web-core` loader.
- `src/components/`: Home, invite, join confirmation, verification, chat,
  recovery, connection, and terminal-error components.
- `tests/`: Vitest unit tests and Playwright browser tests.
- `scripts/build-wasm.mjs`: deterministic `wasm-pack` build into an ignored
  generated directory consumed by Vite.

The generated `src/wasm/` output is not committed. `npm run build` and the
browser test setup run the same WASM build step before TypeScript/Vite work.

## Worker API

The public boundary is intentionally small and serializable. Secrets and raw
binary relay packets are not members of these types.

```ts
export type WorkerCommand =
  | { type: 'create_room' }
  | { type: 'inspect_invite'; uri: string }
  | { type: 'confirm_join' }
  | { type: 'confirm_verification' }
  | { type: 'send_text'; text: string }
  | { type: 'enable_recovery'; passphrase: string }
  | { type: 'resume_recovery'; passphrase: string }
  | { type: 'burn_room' }
  | { type: 'leave_room' };

export type WorkerEvent =
  | { type: 'state'; snapshot: RoomSnapshot }
  | { type: 'invite_ready'; uri: string; expires_at: number }
  | { type: 'invite_preview'; preview: InvitePreview }
  | { type: 'verification_ready'; emojis: string[]; numeric: number[] }
  | { type: 'message_queued'; id: string; text: string; timestamp: number }
  | { type: 'message_received'; id: string; text: string; timestamp: number }
  | { type: 'message_acknowledged'; id: string }
  | { type: 'recovery_available' }
  | { type: 'recovered' }
  | { type: 'error'; error: PublicError };
```

`RoomSnapshot` contains only public display state:

```ts
type RoomPhase =
  | 'idle'
  | 'invite_ready'
  | 'connecting'
  | 'handshaking'
  | 'verifying'
  | 'active'
  | 'recovering'
  | 'peer_disconnected'
  | 'burned'
  | 'fatal_error';

type RoomSnapshot = {
  phase: RoomPhase;
  role: 'initiator' | 'responder' | null;
  room_label: string | null;
  relay_label: string | null;
  local_verified: boolean;
  peer_verified: boolean;
  recovery_available: boolean;
  error: PublicError | null;
};
```

`room_label` is a display-safe truncated identifier. The invite token,
capability, room bytes, relay pin, snapshot bytes, ciphertext, and raw relay
packets never cross this boundary.

## Session lifecycle

### Initial create/join

1. `create_room` asks WASM for 32 random room bytes and opens an initiator
   signaling-v4 WebSocket to the official relay.
2. The Worker sends `JOIN`, receives the one-time 32-byte relay token, builds a
   canonical one-hour `blindwire://join` URI, and emits `invite_ready`.
3. `inspect_invite` validates the full invite using the WASM/core invite
   contract and emits only an `InvitePreview`.
4. `confirm_join` opens the responder WebSocket and sends the validated token;
   the token is never put in React state.
5. The initiator waits for `PEER_JOINED`; the responder waits after its JOIN.
   The initiator starts Noise XX. The Worker forwards all resulting opaque
   frames through signaling-v4 `RELAY` packets.
6. Once Noise is complete, both roles send `HANDSHAKE_COMPLETE` and wait for
   the relay's `HANDSHAKE_CONFIRMED` packet before sending the encrypted
   recovery contribution.
7. The Worker registers one fresh 32-byte recovery capability with the relay,
   then waits for the WASM verification event.
8. React displays the emoji and numeric SAS. Each user must send
   `confirm_verification`; text remains blocked until both `local_verified` and
   `peer_verified` are true.

### Messaging and terminal actions

Text is passed to WASM only after a strict UTF-8/length check at the public
boundary. WASM encrypts it and returns an opaque frame plus message ID. The
Worker reports queued messages optimistically and reports acknowledgements
only when the encrypted ACK is accepted by WASM.

`burn_room` sends both the encrypted burn envelope and signaling-v4 `BURN`,
clears the recovery record, closes the socket, and leaves the Worker in the
irreversible `burned` state. `leave_room` sends `QUIT`, closes the socket,
clears the recovery record, and returns to `idle`.

### Recovery checkpoint

Recovery is explicit and user initiated. `enable_recovery` is available only
after both users verify the SAS:

1. WASM consumes the active session into its worker-only recovery snapshot.
2. The Worker combines that opaque snapshot with the relay URL, role, current
   epoch, and recovery capability into a vault payload.
3. Web Crypto derives an AES-GCM key from the supplied passphrase using a
   random 16-byte salt and PBKDF2-HMAC-SHA-256 with 600,000 iterations. A
   random 12-byte IV encrypts the payload.
4. IndexedDB stores only `{version, salt, iv, ciphertext}` under one fixed
   vault record. The passphrase and plaintext payload are not stored.
5. The Worker reconnects using the stored capability and current epoch,
   starts the fresh WASM recovery handshake, buffers any resume-proof frame
   until relay handshake confirmation, and then completes authenticated
   recovery and continuity ratcheting.
6. After successful immediate recovery, the Worker returns to `active` and
   marks recovery as available. The stored checkpoint is intentionally a
   point-in-time checkpoint; the user can replace it by enabling recovery
   again. A failed or stale checkpoint is deleted after a terminal auth/expiry
   failure.

On Worker startup, the presence of a vault record emits only
`recovery_available`. `resume_recovery` asks for the passphrase inside the
Worker, decrypts and validates the envelope, reconnects to the recorded
official relay, and completes the same authenticated recovery sequence. A bad
passphrase produces a generic public error and does not reveal whether any
part of the ciphertext was valid.

## Signaling-v4 browser relay

`src/worker/relay.ts` mirrors the exact v4 contract already implemented by the
Rust relay:

- client JOIN, RELAY, QUIT, HANDSHAKE_COMPLETE, REGISTER_RECOVERY, RESUME,
  and BURN packets;
- server RELAY, PEER_JOINED, PEER_QUIT, EXPIRED, ERROR, TOKEN,
  HANDSHAKE_CONFIRMED, RECOVERY_REGISTERED, PEER_RESUMING, RESUME_READY, and
  ROOM_BURNED packets;
- big-endian lengths and u64 epochs;
- a 1..4096-byte opaque frame limit;
- binary WebSocket messages only;
- unknown, truncated, oversized, wrong-version, wrong-role, or invalid-order
  packets become sanitized terminal errors.

The Worker treats WebSocket close/error/timeout before verification as
retryable only while the invite is still valid. After verification or during
authenticated recovery, unexpected transport or protocol failure is surfaced
as a disconnected/fatal state with no trust bypass.

## Invite handling

Invite parsing remains canonical and strict: `blindwire://join`, `v=1`,
base64url room/token fields, millisecond expiry, official relay identity, and
no unknown or duplicate query keys. A browser release accepts the official
`wss://relay.blindwire.net` relay. Development builds may accept
`ws://localhost` or `ws://127.0.0.1` only for local integration tests.

The QR renderer receives the exact canonical URI produced by the Worker and
renders it without adding metadata or a second encoding layer. The URI input
field is cleared when the user cancels or after a terminal failure.

## Static build and CSP

`blindwire-web` is built with Vite into `dist/` and can be hosted by any
static file server. It has no runtime server dependency. The build uses local
system fonts only and emits hashed JavaScript/CSS/WASM assets.

The shipped document includes an equivalent restrictive CSP:

```text
default-src 'self';
base-uri 'none';
object-src 'none';
frame-ancestors 'none';
script-src 'self';
worker-src 'self';
style-src 'self';
font-src 'self';
img-src 'self' data:;
connect-src 'self' wss:;
```

Production must not add `ws:` to `connect-src`, must not add `unsafe-inline`
or `unsafe-eval`, and must not load remote scripts/fonts/images. The app's
security test checks the generated HTML and source tree for these regressions.

## Testing strategy

Use TDD for every new behavior:

1. TypeScript invite helpers: canonical URI, strict fields, expiry, official
   relay, and rejection of malformed/duplicate/unsupported inputs.
2. Signaling codec: exact v4 packet bytes, round trips, length limits,
   malformed packet rejection, and sanitized error mapping.
3. Vault: passphrase encryption/decryption, wrong passphrase rejection,
   ciphertext-only IndexedDB records, expiry/version checks, and burn/delete.
4. Worker/controller: command serialization, generation replacement, lifecycle
   projection, public-event redaction, verification gating, and terminal
   cleanup.
5. React components: invite QR uses the exact URI, verification requires an
   explicit click, chat disables send until active, and terminal states provide
   no trust override.
6. Browser E2E: Chromium and Firefox create/join against a local v4 relay,
   complete matching SAS verification, exchange text/ACKs, burn a room, and
   resume from an encrypted vault checkpoint.
7. Existing `wasm-pack test --headless --chrome blindwire-web-core`, full Rust
   tests, formatting, Clippy, TypeScript build, and static CSP checks remain
   green.

## Acceptance criteria

This slice is accepted only when:

- `blindwire-web/` builds as a static SPA without Tauri imports;
- all relay and WASM interaction is Worker-owned;
- React receives no capability, token, room bytes, relay pin, snapshot,
  ciphertext, or raw relay packet;
- no plaintext recovery payload is persisted in IndexedDB;
- the browser UI completes the two-sided verification gate before chat;
- burn is irreversible and removes the vault record;
- Chromium and Firefox browser tests cover the happy path and terminal/error
  paths;
- generated WASM and build output are excluded from version control;
- existing desktop and Rust behavior remains green;
- the work is committed separately from the native foundation branch.

## Implementation order

1. Add the browser package, WASM build hook, TypeScript test harness, and CSP
   baseline.
2. Add red tests and implement invite helpers and the v4 relay codec.
3. Add red tests and implement the Web Crypto/IndexedDB vault.
4. Add red Worker/controller lifecycle tests, then connect relay, WASM, and
   recovery sequencing.
5. Add the React UI and component tests against the public controller only.
6. Add local-relay Chromium/Firefox E2E coverage and security-gate tests.
7. Run the complete repository verification suite, review the diff for secret
   leakage, and commit the browser slice.

## Future change points

The Worker API intentionally isolates likely future changes. A later slice can
replace the static host, add browser-verifiable custom relay identity, change
the vault KDF, or swap React without changing the Rust protocol or exposing
secrets to the UI. The checkpoint semantics can also become automatic if the
WASM boundary gains a safe non-consuming snapshot contract.
