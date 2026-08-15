import { describe, expect, it } from 'vitest';
import {
  WorkerRuntime,
  type RelayFactory,
  type WasmApi,
  type WasmSessionLike,
} from '../src/worker/worker';
import type { RelayEvent, RelayLike } from '../src/worker/relay';
import type { RecoveryVault } from '../src/worker/vault';
import type { WasmCallResult } from '../src/worker/wasm';
import type { WorkerCommand, WorkerEvent } from '../src/types';

const bytes = (value: number, length = 32) => new Uint8Array(length).fill(value);

class FakeRelay implements RelayLike {
  private readonly events: RelayEvent[] = [];
  private readonly waiters: Array<(event: RelayEvent) => void> = [];
  private initialToken: Uint8Array | null = null;
  readonly frames: Uint8Array[] = [];
  readonly controls: string[] = [];

  getInitialToken(): Uint8Array {
    if (!this.initialToken) throw new Error('RELAY_TOKEN_UNAVAILABLE');
    return this.initialToken.slice();
  }

  async nextEvent(): Promise<RelayEvent> {
    const event = this.events.shift();
    if (event) return event;
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  emit(event: RelayEvent): void {
    if (event.type === 'token') this.initialToken = event.token.slice();
    const waiter = this.waiters.shift();
    if (waiter) waiter(event);
    else this.events.push(event);
  }

  sendFrame(frame: Uint8Array): void { this.frames.push(frame.slice()); }
  sendHandshakeComplete(): void { this.controls.push('handshake_complete'); }
  registerRecovery(): void { this.controls.push('register_recovery'); }
  burn(): void { this.controls.push('burn'); }
  quit(): void { this.controls.push('quit'); }
  close(): void { this.controls.push('close'); }
}

class FakeSession implements WasmSessionLike {
  readonly calls: string[] = [];
  private complete = false;

  start_handshake(): WasmCallResult { this.calls.push('start_handshake'); return { events: [{ type: 'outbound', frame: bytes(1, 3) }] }; }
  receive_frame(): WasmCallResult { this.calls.push('receive_frame'); this.complete = true; return { events: [] }; }
  relay_handshake_confirmed(): WasmCallResult { this.calls.push('relay_handshake_confirmed'); return { events: [{ type: 'outbound', frame: bytes(2, 3) }] }; }
  confirm_user_verified(): WasmCallResult { this.calls.push('confirm_user_verified'); return { events: [{ type: 'outbound', frame: bytes(3, 3) }] }; }
  send_text(): WasmCallResult { this.calls.push('send_text'); return { events: [], message_id: bytes(4, 16) }; }
  copy_worker_snapshot_for_storage() { this.calls.push('copy_snapshot'); return bytes(5, 4); }
  begin_recovery(): WasmCallResult { this.calls.push('begin_recovery'); return { events: [] }; }
  accept_resume_proof(): WasmCallResult { this.calls.push('accept_resume_proof'); return { events: [] }; }
  burn(): WasmCallResult { this.calls.push('burn'); return { events: [{ type: 'outbound', frame: bytes(6, 3) }, { type: 'burned' }] }; }
  is_handshake_complete() { return this.complete; }
}

class FakeVault implements RecoveryVault {
  private saved = false;
  async save(): Promise<void> { this.saved = true; }
  async load(): Promise<never> { throw new Error('not used'); }
  async hasRecord(): Promise<boolean> { return this.saved; }
  async clear(): Promise<void> { this.saved = false; }
}

function makeHarness() {
  const relay = new FakeRelay();
  const session = new FakeSession();
  let connectResolve: ((value: FakeRelay) => void) | undefined;
  const relayFactory: RelayFactory = {
    connectInitial: async () => new Promise<FakeRelay>((resolve) => { connectResolve = resolve; }),
    connectResume: async () => relay,
  };
  const wasm: WasmApi = {
    generate_random_32: () => bytes(9),
    parse_invite: () => ({ room: '', token: '', expires_at: Date.now() + 100000, relay_url: 'wss://relay.blindwire.net', relay_pin: null, official_relay: true }),
    WebSession: class {
      constructor() { return session; }
      static restore_worker_snapshot() { return session; }
    } as unknown as WasmApi['WebSession'],
  };
  const events: WorkerEvent[] = [];
  const runtime = new WorkerRuntime({
    wasm,
    relayFactory,
    vault: new FakeVault(),
    now: () => 1_890_000_000_000,
    emit: (event) => events.push(event),
  });
  return {
    relay,
    session,
    events,
    command: async (command: WorkerCommand) => runtime.handle(command),
    resolveRelay: () => connectResolve?.(relay),
  };
}

describe('browser Worker lifecycle', () => {
  it('creates an official invite only after receiving the relay token', async () => {
    const harness = makeHarness();
    await harness.command({ type: 'create_room' });
    expect(harness.events).toContainEqual(expect.objectContaining({ type: 'state', snapshot: expect.objectContaining({ phase: 'connecting' }) }));
    expect(harness.events.some((event) => event.type === 'invite_ready')).toBe(false);

    harness.resolveRelay();
    await Promise.resolve();
    expect(harness.events.some((event) => event.type === 'invite_ready')).toBe(false);
    harness.relay.emit({ type: 'token', token: bytes(7) });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const invite = harness.events.find((event) => event.type === 'invite_ready');
    expect(invite, JSON.stringify(harness.events)).toEqual(expect.objectContaining({ uri: expect.stringContaining('blindwire://join?v=1') }));
    expect(JSON.stringify(harness.events)).not.toContain('capability');
  });

  it('waits for PEER_JOINED before the initiator starts Noise', async () => {
    const harness = makeHarness();
    await harness.command({ type: 'create_room' });
    harness.resolveRelay();
    harness.relay.emit({ type: 'token', token: bytes(7) });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(harness.session.calls).not.toContain('start_handshake');
    harness.relay.emit({ type: 'peer_joined' });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(harness.session.calls, JSON.stringify(harness.events)).toContain('start_handshake');
    expect(harness.relay.frames).toHaveLength(1);
  });
});
