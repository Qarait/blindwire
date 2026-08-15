# Relay Domain Correction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move BlindWire's official production relay from `relay.blindwire.net` to `relay.blindwire.tech` so the website and relay use the purchased domain.

**Architecture:** Keep the browser's fixed official relay policy, changing only the canonical hostname. Update browser fixtures and deployment templates together so invite validation, relay installation, and operational checks describe the same endpoint.

**Tech Stack:** React/Vite browser SPA, Vitest, Playwright, Bash, Nginx, Rust workspace CI.

## Global Constraints

- Website custom domain remains `blindwire.tech`.
- Official WebSocket endpoint is exactly `wss://relay.blindwire.tech`.
- Local development may continue using only `ws://localhost` or `ws://127.0.0.1` in development mode.
- Do not make the relay URL runtime-configurable in this change.
- Do not invent or commit a relay VPS IP address.

---

### Task 1: Add the hostname regression test

**Files:**
- Modify: `blindwire-web/tests/invite.test.ts`

**Interfaces:**
- Consumes: `buildOfficialInviteUri` and `buildInviteUri` from `blindwire-web/src/invite.ts`.
- Produces: a focused assertion that the purchased-domain relay is canonical and the legacy `.net` endpoint is rejected.

- [ ] **Step 1: Change expected official fixtures and add the legacy rejection assertion**

Update the existing invite URI and preview fixtures from `relay.blindwire.net` to `relay.blindwire.tech`, then add:

```ts
expect(() => buildInviteUri(room, token, expiresAt, 'wss://relay.blindwire.net')).toThrow('INVALID_INVITE_ARGUMENT');
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run from `blindwire-web`:

```bash
npm test -- tests/invite.test.ts
```

Expected: failure because the current production source still emits and accepts `relay.blindwire.net`.

- [ ] **Step 3: Commit the failing test**

```bash
git add blindwire-web/tests/invite.test.ts
git commit -m "test: require purchased relay domain"
```

### Task 2: Update browser relay policy and fixtures

**Files:**
- Modify: `blindwire-web/src/invite.ts`
- Modify: `blindwire-web/src/worker/worker.ts`
- Modify: `blindwire-web/tests/controller.test.ts`
- Modify: `blindwire-web/tests/ui.test.tsx`
- Modify: `blindwire-web/tests/vault.test.ts`
- Modify: `blindwire-web/tests/worker-lifecycle.test.ts`
- Modify: `blindwire-web/tests/invite.test.ts`

**Interfaces:**
- Consumes: the existing fixed official-relay validation boundary.
- Produces: `wss://relay.blindwire.tech` in official invites, previews, vault records, and worker connections.

- [ ] **Step 1: Replace the official hostname in source and fixtures**

Change the two source constants/allowlist comparisons and every browser test fixture to `relay.blindwire.tech`. Preserve the existing local-development exception and all other validation behavior.

- [ ] **Step 2: Run the focused tests and verify they pass**

Run:

```bash
npm test -- tests/invite.test.ts tests/controller.test.ts tests/ui.test.tsx tests/vault.test.ts tests/worker-lifecycle.test.ts
```

Expected: all focused tests pass, including the legacy-host rejection assertion.

- [ ] **Step 3: Commit the browser correction**

```bash
git add blindwire-web/src blindwire-web/tests
git commit -m "fix: use purchased domain for official relay"
```

### Task 3: Update relay deployment configuration and documentation

**Files:**
- Modify: `deploy/README.md`
- Modify: `deploy/scripts/install-relay.sh`
- Modify: `deploy/nginx/relay.blindwire.net.conf`
- Rename: `deploy/nginx/relay.blindwire.net.conf` to `deploy/nginx/relay.blindwire.tech.conf`

**Interfaces:**
- Consumes: the same canonical hostname `relay.blindwire.tech` used by the browser.
- Produces: an installer and Nginx configuration that request and serve TLS for `relay.blindwire.tech`.

- [ ] **Step 1: Replace the deployment hostname**

Change `DOMAIN`, Nginx `server_name`, certificate paths, health-check URLs, documentation examples, and config-file references from `.net` to `.tech`. Keep `--reuse-key`, SPKI pin output, localhost binding, and access-log restrictions unchanged.

- [ ] **Step 2: Validate shell and textual consistency**

Run:

```bash
rg -n "relay\\.blindwire\\.net" blindwire-web deploy README.md .github
shellcheck deploy/scripts/*.sh
```

Expected: no `.net` match in the scoped production files; ShellCheck passes where installed.

- [ ] **Step 3: Commit deployment updates**

```bash
git add deploy
git commit -m "fix: align relay deployment with tech domain"
```

### Task 4: Run full verification and publish

**Files:**
- No additional source files.

**Interfaces:**
- Consumes: the completed browser and deployment corrections.
- Produces: a clean branch, passing local verification, and a PR targeting `master`.

- [ ] **Step 1: Run browser verification**

From `blindwire-web`, run:

```bash
npm run test:all
npm run test:e2e:live
```

- [ ] **Step 2: Run Rust repository verification**

From the repository root, run:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
cargo audit
```

- [ ] **Step 3: Verify no stale production references remain**

```bash
rg -n "relay\\.blindwire\\.net" blindwire-web deploy README.md .github
git diff --check
git status --short --branch
```

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin codex/relay-domain-correction
gh pr create --base master --head codex/relay-domain-correction --title "fix: use purchased domain for relay" --body "Align browser relay policy and production deployment configuration with relay.blindwire.tech."
```

- [ ] **Step 5: Merge only after required CI is green**

Check `gh pr checks <number>` and merge with squash once Test Suite, Lint & Format, and Security Audit pass.
