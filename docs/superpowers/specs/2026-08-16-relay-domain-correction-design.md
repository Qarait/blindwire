# Relay Domain Correction Design

**Status:** Approved for implementation from the user's request to correct the relay hostname.

## Goal

Use the purchased `blindwire.tech` domain consistently: serve the SPA at `https://blindwire.tech` and the production WebSocket relay at `wss://relay.blindwire.tech`.

## Decision

Replace the pre-existing `relay.blindwire.net` hostname everywhere in the browser application, tests, relay installer, Nginx configuration, and deployment documentation. Keep the relay hostname fixed as an official endpoint so invite validation and the browser security boundary remain strict.

The alternative of making the relay URL runtime-configurable is rejected for this change because it would widen the accepted endpoint policy and add configuration surface before the first website launch.

## Components

- Browser runtime: official relay constant and invite validation use `wss://relay.blindwire.tech`.
- Browser tests: fixtures and assertions use the new official hostname; a regression test confirms the old hostname is rejected.
- Relay deployment: installer domain, Nginx server names/certificate paths, and operational documentation use `relay.blindwire.tech`.
- DNS handoff: Namecheap must contain an `A` record for `relay` pointing to the relay VPS. This change does not create or guess the VPS address.

## Security and compatibility

- `blindwire.tech` remains the static SPA custom domain.
- `relay.blindwire.tech` remains the only accepted non-local relay URL in production browser builds.
- Local development continues to permit only `ws://localhost` and `ws://127.0.0.1` when running in development mode.
- Existing invites containing `relay.blindwire.net` will be rejected after deployment because that endpoint is not the purchased official relay.

## Verification

- Focused invite tests fail before the source change and pass afterward.
- Browser unit, build, static E2E, and live E2E suites pass.
- Repository-wide Rust tests, formatting, clippy, and security audit remain passing.
- `rg` finds no production or deployment reference to `relay.blindwire.net`.
