# Security-Gated Beta Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the smallest BlindWire beta that preserves relay trust, peer-identity verification, invite safety, and deterministic room state.

**Architecture:** rustls performs ordinary WebPKI verification before BlindWire applies official, invite-supplied, or persisted SPKI pins. Desktop invite handles become leased resources so retryable failures release them while successful or fatal attempts consume them. The React UI exposes only the resulting security/session state and contains no trust override.

**Tech Stack:** Rust, rustls 0.23, Tokio, DashMap, Tauri 2, React/TypeScript, Playwright, npm.

**Commit policy:** Preserve the user's requested workflow: do not create intermediate commits. Make one reviewed commit only after the complete release gate passes.

---

## File map

- `blindwire-transport/src/pinning.rs`: standard WebPKI verification, SPKI policy, durable pin removal.
- `blindwire-transport/src/config.rs`: expected invite pin and pin-store configuration.
- `blindwire-transport/src/relay.rs`: construct the standard verifier and compose it with pin policy.
- `blindwire-transport/tests/pinning_test.rs`: public pin configuration/reset behavior.
- `blindwire-desktop/src-tauri/src/state.rs`: invite leasing and session-attempt serialization.
- `blindwire-desktop/src-tauri/src/commands.rs`: join lifecycle, pin reset, safe logging, room events.
- `blindwire-desktop/src-tauri/src/tests.rs`: invite lease and retry regression tests.
- `blindwire-desktop/src/App.tsx`: remove trust bypass, render QR, deterministic room/error behavior.
- `blindwire-desktop/src/App.css`: QR presentation only.
- `blindwire-desktop/src-tauri/tauri.conf.json`: restrictive CSP.
- `blindwire-desktop/tests/security_gates.spec.ts`: security UI and CSP gates.
- `blindwire-desktop/tests/reality_smoke_e2e.spec.ts`: room retry/disconnect behavior.
- `blindwire-desktop/package.json` and `package-lock.json`: QR dependency.
- Existing relay/deployment files: final `.net` consistency verification only.

### Task 1: Compose standard certificate verification with SPKI policy

**Files:**
- Modify: `blindwire-transport/src/pinning.rs`
- Modify: `blindwire-transport/src/relay.rs`
- Test: `blindwire-transport/src/pinning.rs`

- [ ] **Step 1: Add a failing test proving pin success cannot override WebPKI failure**

Create a test verifier that always returns `rustls::Error::InvalidCertificate(CertificateError::Expired)` and pass it to `BlindWireVerifier`. Assert that `verify_server_cert` returns `Expired` even when the fixture's SPKI equals the expected invite pin.

```rust
let expected = spki_sha256(&cert).unwrap();
let verifier = BlindWireVerifier::new(
    OFFICIAL_RELAY_HOST,
    store,
    Arc::new(RejectExpiredVerifier),
).with_expected_pin(Some(expected));
let error = verifier
    .verify_server_cert(&cert, &[], &server, &[], UnixTime::now())
    .unwrap_err();
assert!(matches!(
    error,
    rustls::Error::InvalidCertificate(rustls::CertificateError::Expired)
));
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `cargo test -p blindwire-transport pin_match_does_not_override_expired_certificate -- --nocapture`

Expected: compile failure because `BlindWireVerifier::new` does not accept a standard verifier, or assertion failure because WebPKI is not called.

- [ ] **Step 3: Delegate all certificate and signature checks to rustls WebPKI first**

Store `Arc<dyn ServerCertVerifier>` in `BlindWireVerifier`. At the beginning of `verify_server_cert`, call it with the original certificate chain, server name, OCSP response, and time. Delegate `verify_tls12_signature`, `verify_tls13_signature`, and `supported_verify_schemes` to the same verifier. Only after success compute and enforce the SPKI pin.

In `relay.rs`, construct the verifier with system-independent Mozilla roots:

```rust
let mut roots = rustls::RootCertStore::empty();
roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
let webpki = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
    .build()
    .map_err(|error| TransportError::ConnectionFailed(error.to_string()))?;
let verifier = BlindWireVerifier::new(OFFICIAL_RELAY_HOST, store, webpki)
    .with_expected_pin(config.expected_server_pin);
```

- [ ] **Step 4: Test official, invite-pin, TOFU, hostname, and expiry outcomes**

Run: `cargo test -p blindwire-transport pinning -- --nocapture`

Expected: PASS. Pin mismatch remains fatal; matching pins still fail when WebPKI rejects the chain, name, or validity period.

### Task 2: Implement durable, scoped pin reset

**Files:**
- Modify: `blindwire-transport/src/pinning.rs`
- Modify: `blindwire-transport/src/lib.rs`
- Modify: `blindwire-desktop/src-tauri/src/commands.rs`
- Test: `blindwire-transport/tests/pinning_test.rs`

- [ ] **Step 1: Write failing store tests**

Test that removing `custom.example` preserves `other.example`, survives reload, and returns `NotFound`/`false` when no pin exists. Test that `relay.blindwire.net` is rejected by the public reset function.

- [ ] **Step 2: Run the tests and confirm RED**

Run: `cargo test -p blindwire-transport reset_server_pin -- --nocapture`

Expected: compile failure because the reset API does not exist.

- [ ] **Step 3: Add atomic removal and a public reset API**

Implement `DiskPinStore::remove_pin` by parsing all valid rows, removing exactly the canonical hostname, writing a temporary file, and atomically renaming it. Export:

```rust
pub fn reset_server_pin(path: &Path, relay_url: &str) -> Result<bool, PinResetError>
```

Parse the URL, reject the official hostname, canonicalize the custom hostname, and remove only that key.

- [ ] **Step 4: Wire the Tauri command to app data**

Change `reset_server_pin` to accept `AppHandle`, resolve `app_data_dir()/pins.txt`, call the transport API, and return a stable `PIN_NOT_FOUND`, `PIN_RESET_FORBIDDEN`, or `PIN_STORE_FAILED` error. Never log the full relay URL.

- [ ] **Step 5: Verify reset behavior**

Run: `cargo test -p blindwire-transport reset_server_pin -- --nocapture`

Expected: PASS, including reload persistence and official-host rejection.

### Task 3: Lease invite handles and serialize JOIN attempts

**Files:**
- Modify: `blindwire-desktop/src-tauri/src/state.rs`
- Modify: `blindwire-desktop/src-tauri/src/commands.rs`
- Modify: `blindwire-desktop/src-tauri/src/tests.rs`

- [ ] **Step 1: Write failing invite lease tests**

Cover these transitions with real `AppState` methods:

```rust
let handle = state.store_invite(invite);
let lease = state.begin_invite_attempt(&handle).unwrap();
assert_eq!(state.begin_invite_attempt(&handle), Err(InviteAttemptError::InProgress));
state.release_invite_attempt(&handle, lease.generation).unwrap();
assert!(state.begin_invite_attempt(&handle).is_ok());
state.consume_invite_attempt(&handle, lease.generation).unwrap();
assert_eq!(state.begin_invite_attempt(&handle), Err(InviteAttemptError::Missing));
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `cargo test -p blindwire-desktop invite_attempt -- --nocapture`

Expected: compile failure because lease methods/types do not exist.

- [ ] **Step 3: Replace destructive lookup with a generation-checked lease**

Store `InviteEntry { payload, attempt_generation: Option<u64> }`. `begin_invite_attempt` atomically marks a free entry and returns a cloned payload plus generation. `release_invite_attempt` clears only the matching generation. `consume_invite_attempt` removes only the matching generation.

- [ ] **Step 4: Apply retry classification in `join_room`**

Acquire the lease before starting a session. On relay timeout, DNS/connectivity failure, or peer absence, release it and emit `join_failed` with `retryable: true`. On malformed invite, certificate/pin/identity failure, protocol failure, successful secure connection, or expiry, consume it. Always clear the active-attempt state on task exit.

- [ ] **Step 5: Verify retry and parallel-attempt behavior**

Run: `cargo test -p blindwire-desktop invite_attempt -- --nocapture`

Expected: PASS with one accepted concurrent attempt, retry after transient failure, and permanent consumption after fatal/success outcomes.

### Task 4: Remove trust bypasses and secret-bearing logs

**Files:**
- Modify: `blindwire-desktop/src-tauri/src/commands.rs`
- Modify: `blindwire-desktop/src-tauri/src/lib.rs`
- Modify: `blindwire-desktop/src-tauri/src/state.rs`
- Modify: `blindwire-desktop/src/App.tsx`
- Modify: `blindwire-desktop/tests/security_gates.spec.ts`

- [ ] **Step 1: Add failing static security gates**

Assert source and rendered UI contain no `Trust New Identity`, `trust_new_server_identity`, raw invite URI logging, room ID logging, relay URL logging, token logging, fingerprint logging, or message-content logging.

- [ ] **Step 2: Run the security gate and confirm RED**

Run: `cd blindwire-desktop && npm test -- security_gates.spec.ts`

Expected: FAIL on the trust button/command and diagnostic logs.

- [ ] **Step 3: Remove the bypass and sanitize logging**

Delete the Tauri command, registration, pending-identity-change state, and React button. The fatal identity-change screen offers only “Cancel” and, for custom relays, navigation to the separately confirmed pin-reset setting. Retain only coarse logs such as `session connection failed` without identifiers or error debug payloads.

- [ ] **Step 4: Re-run the security gate**

Run: `cd blindwire-desktop && npm test -- security_gates.spec.ts`

Expected: PASS.

### Task 5: Make room state deterministic

**Files:**
- Modify: `blindwire-desktop/src-tauri/src/commands.rs`
- Modify: `blindwire-desktop/src-tauri/src/state.rs`
- Modify: `blindwire-desktop/src/App.tsx`
- Test: `blindwire-desktop/tests/reality_smoke_e2e.spec.ts`

- [ ] **Step 1: Add failing state-transition tests**

Cover: connecting → verifying → active; retryable join failure → invite-ready; fatal join failure → home/error; peer disconnect → read-only disconnected; leave → home; stale generation event → ignored.

- [ ] **Step 2: Run the E2E test and confirm RED**

Run: `cd blindwire-desktop && npx playwright test tests/reality_smoke_e2e.spec.ts`

Expected: at least one transition fails or a stale/disconnected control remains enabled.

- [ ] **Step 3: Emit one authoritative room snapshot**

Extend `RoomSnapshot` with a serializable phase enum (`idle`, `connecting`, `verifying`, `active`, `peer_disconnected`, `fatal_error`). Update phase and generation together in Rust and emit the complete snapshot after each transition. React replaces local guesswork with the latest matching-generation snapshot.

- [ ] **Step 4: Verify all transitions**

Run: `cd blindwire-desktop && npx playwright test tests/reality_smoke_e2e.spec.ts`

Expected: PASS; send controls are enabled only in verified `active` state.

### Task 6: Add real QR rendering and restrictive CSP

**Files:**
- Modify: `blindwire-desktop/package.json`
- Modify: `blindwire-desktop/package-lock.json`
- Modify: `blindwire-desktop/src/App.tsx`
- Modify: `blindwire-desktop/src/App.css`
- Modify: `blindwire-desktop/src-tauri/tauri.conf.json`
- Modify: `blindwire-desktop/tests/security_gates.spec.ts`

- [ ] **Step 1: Add failing QR and CSP tests**

Assert the invite view contains an SVG/canvas QR whose encoded value equals `info.qr_string`. Assert Tauri CSP is non-null and contains `default-src 'self'`, `script-src 'self'`, `img-src 'self' data:`, and no wildcard source.

- [ ] **Step 2: Run tests and confirm RED**

Run: `cd blindwire-desktop && npx playwright test tests/security_gates.spec.ts`

Expected: FAIL because the QR is a text placeholder and CSP is null.

- [ ] **Step 3: Install and render the QR dependency**

Run: `cd blindwire-desktop && npm install qrcode.react`

Render `<QRCodeSVG value={info.qr_string} level="M" includeMargin />`. Do not encode any value other than the already validated invite URI.

- [ ] **Step 4: Configure CSP**

Set Tauri CSP to the minimum directives required by the packaged React/Tauri application. Start from:

```json
"csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src ipc: http://ipc.localhost"
```

If the packaged app requires an additional Tauri scheme, add only that exact scheme and document it in the test.

- [ ] **Step 5: Re-run QR/CSP tests**

Run: `cd blindwire-desktop && npx playwright test tests/security_gates.spec.ts`

Expected: PASS.

### Task 7: Run the complete release gate

**Files:**
- Review all modified files
- Do not modify: `release_notes.md`

- [ ] **Step 1: Rust quality gate**

Run:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Expected: all commands exit 0 with no warnings.

- [ ] **Step 2: Frontend quality/security gate**

Run:

```powershell
Set-Location blindwire-desktop
npm test
npx playwright test
npm audit
npm run build
```

Expected: tests/build pass. Audit has no unresolved high/critical production vulnerability; any lower finding is documented with reachability and mitigation.

- [ ] **Step 3: Tauri build gate**

Run the debug build, then set `BLINDWIRE_OFFICIAL_SPKI_PINS` to the reviewed current and rotation pins and run the release build. Expected: both builds pass; the release binary contains `wss://relay.blindwire.net` and rejects insecure WebSockets.

- [ ] **Step 4: Static release review**

Run:

```powershell
rg -n --hidden --glob '!target/**' --glob '!node_modules/**' "relay\.blindwire\.io|Trust New Identity|csp\": null|TODO: call DiskPinStore|token mint|exact relay URL"
git diff --check
git diff --stat
git status --short
```

Expected: no blocker patterns outside untouched historical/user-owned material; no whitespace errors; `release_notes.md` remains unmodified and untracked.

### Task 8: Publish the reviewed beta branch

**Files:** all reviewed blocker changes except `release_notes.md`

- [ ] **Step 1: Review and stage intentional files only**

Run `git diff`, then `git add` the reviewed source, tests, deployment files, spec, and plan. Do not stage `release_notes.md`.

- [ ] **Step 2: Create the single release-blocker commit**

Run: `git commit -m "fix: close beta release security blockers"`

Expected: commit succeeds with only intentional files.

- [ ] **Step 3: Push the existing branch**

Run: `git push -u origin codex/fix-beta-release-blockers`

Expected: push succeeds.

- [ ] **Step 4: Report external requirements**

Report the pushed commit, verification commands, production certificate/SPKI rotation-pin provisioning still required, and the recommendation for an independent security audit before broad distribution.
