# BlindWire Security-Gated Beta Design

## Goal

Release the smallest usable BlindWire beta without weakening its core promise: users must not be connected through an untrusted relay identity, bypass peer verification, or unknowingly reuse compromised session state.

## Mandatory pre-release scope

### Relay trust

- Delegate certificate-chain, hostname, signature, and validity-period checks to rustls's standard verifier before applying BlindWire SPKI pins.
- Enforce the official relay's compiled rotation pins after standard verification.
- Enforce custom-relay pins supplied by validated invites.
- Keep TOFU persistence fail-closed: a connection must fail if its first-use pin cannot be durably written.
- Implement explicit, durable custom-relay pin reset. The official relay pin set cannot be reset by the user.

### Identity and session safety

- Remove the UI path that trusts a changed identity and continues automatically.
- Require a fresh invite or explicit pin reset after a relay identity change.
- Preserve an invite handle after retryable connection failures, but consume it once a responder JOIN has been admitted or a non-retryable validation failure occurs.
- Serialize JOIN attempts so one invite handle cannot create parallel sessions.
- Remove logs containing relay URLs, room identifiers, tokens, fingerprints, message content, or other secret/correlation material.

### Minimum release UX

- Generate a real QR code containing only the validated invite URI.
- Apply a restrictive Tauri Content Security Policy permitting only packaged application resources needed by the beta.
- Keep room state consistent across connect, verification, peer disconnect, retryable failure, fatal security failure, and leave.
- Distinguish retryable network errors from fatal security errors in user-facing messages.

## Error-handling rules

- Certificate, pin, invite-integrity, Noise, and identity-change failures are fatal and never offer an in-place trust bypass.
- Timeouts and relay unavailability are retryable only while the invite remains valid and unused.
- Persistence failures are fatal because continuing would silently discard a security decision.
- Cleanup must clear active-session state and prevent stale background tasks from mutating a newer session.

## Verification gate

The beta is releasable only after all of the following pass from a clean invocation:

- Rust formatting and Clippy with warnings denied.
- All Rust unit and integration tests.
- Frontend unit/end-to-end tests.
- `npm audit` review with no unresolved release-blocking finding.
- Tauri debug and release builds, with the release build using `wss://relay.blindwire.net` and configured official SPKI pins.
- Manual diff review confirming `release_notes.md` was not modified and no secret-bearing logs or trust bypasses remain.

## Deferred until after beta

- Nonessential visual polish and broader UI redesign.
- Convenience workflows that do not affect trust or session correctness.
- General refactoring unrelated to the release blockers.
- Additional operational automation beyond the documented production certificate, key-rotation, and independent-audit requirements.

## Release handoff

After the verification gate passes, create one intentional commit containing the reviewed blocker fixes, push the existing branch, and report external work that cannot be completed in-repository—principally production certificate provisioning/pins and an independent security audit.
