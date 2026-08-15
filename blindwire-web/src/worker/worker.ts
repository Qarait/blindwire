import {
  base64UrlDecode,
  base64UrlEncode,
  buildOfficialInviteUri,
  toInvitePreview,
  type ValidatedInviteDescriptor,
} from '../invite';
import type { PublicError, RoomPhase, RoomSnapshot, WorkerCommand, WorkerEvent } from '../types';
import { openVault, type RecoveryVault } from './vault';
import {
  RelayClient,
  type RelayEvent,
  type RelayLike,
  type RelayRole,
} from './relay';
import { loadWasm, type WasmCallResult, type WasmEvent } from './wasm';

const OFFICIAL_RELAY_URL = 'wss://relay.blindwire.net';
const INVITE_LIFETIME_MS = 60 * 60 * 1000;
const RECOVERY_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

export type RelayFactory = {
  connectInitial(url: string, role: RelayRole, room: Uint8Array, token?: Uint8Array): Promise<RelayLike>;
  connectResume(url: string, role: RelayRole, room: Uint8Array, capability: Uint8Array, epoch: bigint): Promise<RelayLike>;
};

export type WasmSessionLike = import('./wasm').WasmSessionLike;
export type WasmApi = import('./wasm').WasmApi;

export type WorkerRuntimeDependencies = {
  wasm: WasmApi;
  relayFactory: RelayFactory;
  vault: RecoveryVault;
  now: () => number;
  emit: (event: WorkerEvent) => void;
};

export class WorkerRuntime {
  private generation = 0;
  private relay: RelayLike | null = null;
  private session: WasmSessionLike | null = null;
  private role: RelayRole | null = null;
  private room: Uint8Array | null = null;
  private relayUrl: string | null = null;
  private capability: Uint8Array | null = null;
  private epoch = 0n;
  private pendingRecoveryEpoch: bigint | null = null;
  private pendingInvite: ValidatedInviteDescriptor | null = null;
  private relayHandshakeSent = false;
  private initialHandshakeStarted = false;
  private recoveryAwaitingRelay = false;
  private localVerified = false;
  private peerVerified = false;
  private recoveryPassphrase: string | null = null;
  private snapshotExpiry = 0;
  private snapshot: RoomSnapshot = idleSnapshot();

  constructor(private readonly dependencies: WorkerRuntimeDependencies) {}

  handle(command: WorkerCommand): Promise<void> {
    return this.run(command).catch((error: unknown) => {
      this.handleCommandError(error);
    });
  }

  private async run(command: WorkerCommand): Promise<void> {
    switch (command.type) {
      case 'create_room':
        this.createRoom();
        return;
      case 'inspect_invite':
        await this.inspectInvite(command.uri);
        return;
      case 'confirm_join':
        this.confirmJoin();
        return;
      case 'confirm_verification':
        this.confirmVerification();
        return;
      case 'send_text':
        this.sendText(command.text);
        return;
      case 'enable_recovery':
        await this.enableRecovery(command.passphrase);
        return;
      case 'resume_recovery':
        await this.resumeRecovery(command.passphrase);
        return;
      case 'burn_room':
        this.burnRoom();
        return;
      case 'leave_room':
        this.leaveRoom();
        return;
    }
  }

  private createRoom(): void {
    this.replaceSession();
    const generation = this.generation;
    this.role = 'initiator';
    this.relayUrl = OFFICIAL_RELAY_URL;
    this.localVerified = false;
    this.peerVerified = false;
    this.setPhase('connecting');
    void this.connectInitiator(generation).catch((error: unknown) => this.handleAsyncError(generation, error));
  }

  private async connectInitiator(generation: number): Promise<void> {
    const room = this.dependencies.wasm.generate_random_32();
    this.room = room.slice();
    const relay = await this.dependencies.relayFactory.connectInitial(
      OFFICIAL_RELAY_URL,
      'initiator',
      room,
    );
    if (!this.isCurrent(generation)) {
      relay.close();
      return;
    }
    this.relay = relay;
    const token = await this.waitForInitialToken(relay);
    if (!this.isCurrent(generation)) return;
    this.session = new this.dependencies.wasm.WebSession(0x69, room);
    const expiresAt = this.dependencies.now() + INVITE_LIFETIME_MS;
    const descriptor: ValidatedInviteDescriptor = {
      room: base64UrlEncode(room),
      token: base64UrlEncode(token),
      expires_at: expiresAt,
      relay_url: OFFICIAL_RELAY_URL,
      relay_pin: null,
      official_relay: true,
    };
    this.pendingInvite = descriptor;
    this.emit({ type: 'invite_ready', uri: buildOfficialInviteUri(room, token, expiresAt), expires_at: expiresAt });
    this.setPhase('invite_ready');
    this.startRelayLoop(generation, relay);
  }

  private async waitForInitialToken(relay: RelayLike): Promise<Uint8Array> {
    try {
      return relay.getInitialToken();
    } catch {
      const event = await relay.nextEvent();
      if (event.type !== 'token') throw new Error('RELAY_TOKEN_UNAVAILABLE');
      return event.token.slice();
    }
  }

  private async inspectInvite(uri: string): Promise<void> {
    const descriptor = this.dependencies.wasm.parse_invite(uri);
    if (!descriptor.official_relay && !isLocalRelay(descriptor.relay_url)) {
      throw publicFailure('RELAY_UNTRUSTED', 'This browser build accepts the official relay only.', false);
    }
    this.pendingInvite = descriptor;
    this.emit({ type: 'invite_preview', preview: toInvitePreview(descriptor) });
  }

  private confirmJoin(): void {
    const descriptor = this.pendingInvite;
    if (!descriptor) {
      throw publicFailure('INVITE_REQUIRED', 'Paste a valid invite first.', false);
    }
    this.replaceSession();
    const generation = this.generation;
    this.role = 'responder';
    this.relayUrl = descriptor.relay_url;
    this.room = base64UrlDecode(descriptor.room);
    this.localVerified = false;
    this.peerVerified = false;
    this.setPhase('connecting');
    void this.connectResponder(generation, descriptor).catch((error: unknown) => this.handleAsyncError(generation, error));
  }

  private async connectResponder(generation: number, descriptor: ValidatedInviteDescriptor): Promise<void> {
    const room = this.room as Uint8Array;
    const relay = await this.dependencies.relayFactory.connectInitial(
      descriptor.relay_url,
      'responder',
      room,
      base64UrlDecode(descriptor.token),
    );
    if (!this.isCurrent(generation)) {
      relay.close();
      return;
    }
    this.relay = relay;
    this.session = new this.dependencies.wasm.WebSession(0x72, room, base64UrlDecode(descriptor.token));
    this.setPhase('handshaking');
    this.startRelayLoop(generation, relay);
  }

  private startRelayLoop(generation: number, relay: RelayLike): void {
    void this.relayLoop(generation, relay).catch((error: unknown) => this.handleAsyncError(generation, error));
  }

  private async relayLoop(generation: number, relay: RelayLike): Promise<void> {
    while (this.isCurrent(generation) && this.relay === relay) {
      const event = await relay.nextEvent();
      if (!this.isCurrent(generation) || this.relay !== relay) return;
      await this.handleRelayEvent(event, generation, relay);
    }
  }

  private async handleRelayEvent(event: RelayEvent, generation: number, relay: RelayLike): Promise<void> {
    const session = this.session;
    if (!session) throw new Error('SESSION_MISSING');
    switch (event.type) {
      case 'peer_joined':
        if (this.role === 'initiator' && !this.initialHandshakeStarted) {
          this.initialHandshakeStarted = true;
          this.setPhase('handshaking');
          await this.processResult(session.start_handshake(), generation, relay);
        }
        return;
      case 'relay':
        await this.processResult(
          this.recoveryAwaitingRelay && session.is_handshake_complete()
            ? session.accept_resume_proof(event.frame)
            : session.receive_frame(event.frame),
          generation,
          relay,
        );
        return;
      case 'handshake_confirmed':
        if (this.recoveryAwaitingRelay) {
          this.recoveryAwaitingRelay = false;
          this.flushBufferedFrames(relay);
        } else {
          await this.processResult(session.relay_handshake_confirmed(), generation, relay);
        }
        return;
      case 'peer_resuming':
        await this.handlePeerResuming(event.epoch, generation, relay);
        return;
      case 'peer_quit':
        this.setPhase('peer_disconnected');
        relay.close();
        return;
      case 'expired':
        throw publicFailure('INVITE_EXPIRED', 'This invite has expired.', false);
      case 'error':
        throw publicFailure(`RELAY_ERROR_${event.code}`, relayErrorMessage(event.code), true);
      case 'room_burned':
        await this.dependencies.vault.clear();
        this.replaceTransportOnly();
        this.setPhase('burned');
        return;
      case 'token':
      case 'recovery_registered':
      case 'resume_ready':
        return;
    }
  }

  private async processResult(result: WasmCallResult, generation: number, relay: RelayLike): Promise<void> {
    if (!result || !Array.isArray(result.events)) {
      throw new Error('WASM_RESULT_INVALID');
    }
    for (const event of result.events) {
      await this.processWasmEvent(event, generation, relay);
    }
    const session = this.session;
    if (session?.is_handshake_complete() && !this.relayHandshakeSent) {
      relay.sendHandshakeComplete();
      this.relayHandshakeSent = true;
    }
  }

  private async processWasmEvent(event: WasmEvent, generation: number, relay: RelayLike): Promise<void> {
    switch (event.type) {
      case 'outbound':
        if (!(event.frame instanceof Uint8Array)) throw new Error('WASM_FRAME_INVALID');
        if (this.recoveryAwaitingRelay && this.session?.is_handshake_complete()) {
          this.bufferedRecoveryFrames.push(event.frame.slice());
        } else {
          relay.sendFrame(event.frame);
        }
        return;
      case 'verification': {
        const capability = this.dependencies.wasm.generate_random_32();
        this.capability = capability.slice();
        relay.registerRecovery(capability);
        this.setPhase('verifying');
        this.emit({ type: 'verification_ready', emojis: [...event.emojis], numeric: [...event.numeric] });
        return;
      }
      case 'peer_verified':
        this.peerVerified = true;
        this.updateActiveState();
        return;
      case 'text':
        this.emit({ type: 'message_received', id: base64UrlEncode(event.id), text: event.text, timestamp: this.dependencies.now() });
        return;
      case 'acknowledgement':
        this.emit({ type: 'message_acknowledged', id: base64UrlEncode(event.id) });
        return;
      case 'recovering':
        this.setPhase('recovering');
        return;
      case 'recovered':
        this.recoveryAwaitingRelay = false;
        this.flushBufferedFrames(relay);
        if (this.pendingRecoveryEpoch !== null) this.epoch = this.pendingRecoveryEpoch;
        this.pendingRecoveryEpoch = null;
        this.capability?.fill(0);
        this.capability = this.dependencies.wasm.generate_random_32().slice();
        relay.registerRecovery(this.capability);
        this.setPhase('active');
        this.emit({ type: 'recovered' });
        await this.refreshRecoveryCheckpoint(generation, relay);
        return;
      case 'burned':
        await this.dependencies.vault.clear();
        this.replaceTransportOnly();
        this.setPhase('burned');
        return;
    }
  }

  private readonly bufferedRecoveryFrames: Uint8Array[] = [];

  private flushBufferedFrames(relay: RelayLike): void {
    while (this.bufferedRecoveryFrames.length > 0) {
      relay.sendFrame(this.bufferedRecoveryFrames.shift() as Uint8Array);
    }
  }

  private confirmVerification(): void {
    const session = this.session;
    const relay = this.relay;
    if (!session || !relay || this.snapshot.phase !== 'verifying') {
      throw publicFailure('VERIFICATION_REQUIRED', 'Compare the security words before confirming.', false);
    }
    this.localVerified = true;
    void this.processResult(session.confirm_user_verified(), this.generation, relay)
      .catch((error: unknown) => this.handleAsyncError(this.generation, error));
    this.updateActiveState();
  }

  private sendText(text: string): void {
    const session = this.session;
    const relay = this.relay;
    if (!session || !relay || this.snapshot.phase !== 'active' || !this.localVerified || !this.peerVerified) {
      throw publicFailure('VERIFICATION_REQUIRED', 'Both people must confirm the security words first.', false);
    }
    const encoded = new TextEncoder().encode(text);
    if (encoded.length === 0 || encoded.length > 4000 || text.includes('\0')) {
      throw publicFailure('MESSAGE_INVALID', 'Message must be 1–4000 bytes and contain no NUL characters.', false);
    }
    const result = session.send_text(text);
    void this.processResult(result, this.generation, relay)
      .then(() => {
        if (result.message_id) {
          this.emit({ type: 'message_queued', id: base64UrlEncode(result.message_id), text, timestamp: this.dependencies.now() });
        }
      })
      .catch((error: unknown) => this.handleAsyncError(this.generation, error));
  }

  private async enableRecovery(passphrase: string): Promise<void> {
    const session = this.session;
    if (!session || !this.relay || !this.capability || !this.role || !this.relayUrl || this.snapshot.phase !== 'active') {
      throw publicFailure('RECOVERY_UNAVAILABLE', 'Recovery is available after both people verify.', false);
    }
    if (!passphrase) throw publicFailure('RECOVERY_SAVE_FAILED', 'Enter a recovery passphrase.', false);
    const expiresAt = this.dependencies.now() + RECOVERY_LIFETIME_MS;
    const snapshot = session.copy_worker_snapshot_for_storage(BigInt(expiresAt));
    await this.dependencies.vault.save(passphrase, {
      snapshot,
      capability: this.capability.slice(),
      epoch: this.epoch,
      relay_url: this.relayUrl,
      role: this.role,
      expires_at: expiresAt,
    });
    this.snapshotExpiry = expiresAt;
    this.emit({ type: 'recovery_available' });
    this.snapshot = { ...this.snapshot, recovery_available: true };
    this.emit({ type: 'state', snapshot: this.snapshot });
  }

  private async resumeRecovery(passphrase: string): Promise<void> {
    if (!passphrase) throw publicFailure('RECOVERY_UNLOCK_FAILED', 'Unable to unlock recovery.', false);
    const payload = await this.dependencies.vault.load(passphrase, this.dependencies.now());
    this.replaceSession();
    const generation = this.generation;
    this.role = payload.role;
    this.relayUrl = payload.relay_url;
    this.room = extractRoomFromSnapshot(payload.snapshot);
    this.capability = payload.capability.slice();
    this.epoch = payload.epoch;
    this.pendingRecoveryEpoch = payload.epoch + 1n;
    this.recoveryPassphrase = passphrase;
    this.recoveryAwaitingRelay = true;
    this.relayHandshakeSent = false;
    this.localVerified = true;
    this.peerVerified = true;
    this.setPhase('recovering');
    this.session = this.dependencies.wasm.WebSession.restore_worker_snapshot(payload.snapshot, BigInt(this.dependencies.now()));
    const relay = await this.dependencies.relayFactory.connectResume(
      payload.relay_url,
      payload.role,
      this.room,
      payload.capability,
      payload.epoch,
    );
    if (!this.isCurrent(generation)) {
      relay.close();
      return;
    }
    this.relay = relay;
    await this.processResult(this.session.begin_recovery(payload.epoch + 1n), generation, relay);
    this.startRelayLoop(generation, relay);
  }

  private async handlePeerResuming(epoch: bigint, generation: number, relay: RelayLike): Promise<void> {
    const session = this.session;
    if (!session || epoch !== this.epoch + 1n) {
      throw publicFailure('RECOVERY_EPOCH_INVALID', 'The recovery attempt is no longer current.', false);
    }
    this.recoveryAwaitingRelay = true;
    this.pendingRecoveryEpoch = epoch;
    this.relayHandshakeSent = false;
    this.setPhase('recovering');
    await this.processResult(session.begin_recovery(epoch), generation, relay);
  }

  private async refreshRecoveryCheckpoint(generation: number, relay: RelayLike): Promise<void> {
    const session = this.session;
    if (!session || !this.recoveryPassphrase || !this.capability || !this.role || !this.relayUrl) return;
    const expiresAt = this.dependencies.now() + RECOVERY_LIFETIME_MS;
    const snapshot = session.copy_worker_snapshot_for_storage(BigInt(expiresAt));
    await this.dependencies.vault.save(this.recoveryPassphrase, {
      snapshot,
      capability: this.capability.slice(),
      epoch: this.epoch,
      relay_url: this.relayUrl,
      role: this.role,
      expires_at: expiresAt,
    });
    this.snapshotExpiry = expiresAt;
    this.emit({ type: 'recovery_available' });
    if (this.isCurrent(generation) && this.relay === relay) this.emit({ type: 'state', snapshot: { ...this.snapshot, recovery_available: true } });
  }

  private burnRoom(): void {
    const session = this.session;
    const relay = this.relay;
    if (!session || !relay) {
      throw publicFailure('ROOM_NOT_ACTIVE', 'There is no active room to burn.', false);
    }
    void this.processResult(session.burn(), this.generation, relay)
      .then(async () => {
        relay.burn();
        await this.dependencies.vault.clear();
        this.replaceTransportOnly();
        this.setPhase('burned');
      })
      .catch((error: unknown) => this.handleAsyncError(this.generation, error));
  }

  private leaveRoom(): void {
    const relay = this.relay;
    if (relay) {
      try { relay.quit(); } catch { /* terminal cleanup */ }
    }
    void this.dependencies.vault.clear().catch(() => undefined);
    this.replaceSession();
    this.pendingInvite = null;
    this.role = null;
    this.room = null;
    this.relayUrl = null;
    this.setPhase('idle');
  }

  private updateActiveState(): void {
    if (this.localVerified && this.peerVerified) this.setPhase('active');
  }

  private setPhase(phase: RoomPhase): void {
    this.snapshot = {
      ...this.snapshot,
      phase,
      role: this.role,
      room_label: this.room ? `${base64UrlEncode(this.room).slice(0, 8)}…` : null,
      relay_label: this.relayUrl ? safeHostname(this.relayUrl) : null,
      local_verified: this.localVerified,
      peer_verified: this.peerVerified,
      error: phase === 'fatal_error' ? this.snapshot.error : null,
    };
    this.emit({ type: 'state', snapshot: this.snapshot });
  }

  private replaceSession(): void {
    this.generation += 1;
    this.replaceTransportOnly();
    this.session?.free?.();
    this.session = null;
    this.capability?.fill(0);
    this.capability = null;
    this.room?.fill(0);
    this.room = null;
    this.relayHandshakeSent = false;
    this.initialHandshakeStarted = false;
    this.recoveryAwaitingRelay = false;
    this.pendingRecoveryEpoch = null;
    this.recoveryPassphrase = null;
    this.bufferedRecoveryFrames.length = 0;
  }

  private replaceTransportOnly(): void {
    this.relay?.close();
    this.relay = null;
  }

  private isCurrent(generation: number): boolean {
    return generation === this.generation;
  }

  private handleCommandError(error: unknown): void {
    const publicError = publicErrorFrom(error);
    this.emit({ type: 'error', error: publicError });
    if (publicError.retryable || publicError.code === 'VERIFICATION_REQUIRED' || publicError.code.startsWith('RECOVERY_') || publicError.code === 'INVITE_REQUIRED') return;
    this.snapshot = { ...this.snapshot, phase: 'fatal_error', error: publicError };
    this.emit({ type: 'state', snapshot: this.snapshot });
  }

  private handleAsyncError(generation: number, error: unknown): void {
    if (!this.isCurrent(generation)) return;
    this.handleCommandError(error);
  }

  private emit(event: WorkerEvent): void {
    this.dependencies.emit(event);
  }
}

export function installWorker(scope: { postMessage(event: WorkerEvent): void; onmessage: ((event: MessageEvent<WorkerCommand>) => void) | null }): void {
  let runtimePromise: Promise<WorkerRuntime> | undefined;
  scope.onmessage = (event) => {
    runtimePromise ??= Promise.all([loadWasm(), openVault()]).then(async ([wasm, vault]) => {
      const runtime = new WorkerRuntime({
        wasm,
        vault,
        relayFactory: {
          connectInitial: (url, role, room, token) => RelayClient.connectInitial(url, role, room, token),
          connectResume: (url, role, room, capability, epoch) => RelayClient.connectResume(url, role, room, capability, epoch),
        },
        now: () => Date.now(),
        emit: (workerEvent) => scope.postMessage(workerEvent),
      });
      if (await vault.hasRecord()) scope.postMessage({ type: 'recovery_available' });
      return runtime;
    });
    void runtimePromise.then((runtime) => runtime.handle(event.data));
  };
}

function idleSnapshot(): RoomSnapshot {
  return {
    phase: 'idle',
    role: null,
    room_label: null,
    relay_label: null,
    local_verified: false,
    peer_verified: false,
    recovery_available: false,
    error: null,
  };
}

function publicFailure(code: string, message: string, retryable: boolean): Error & { publicError: PublicError } {
  const error = new Error(message) as Error & { publicError: PublicError };
  error.publicError = { code, message, retryable };
  return error;
}

function publicErrorFrom(error: unknown): PublicError {
  if (isPublicError(error)) return error.publicError;
  if (error instanceof Error && /^RELAY_ERROR_\d+$/.test(error.message)) {
    const code = error.message;
    return { code, message: relayErrorMessage(Number(code.slice('RELAY_ERROR_'.length))), retryable: true };
  }
  if (error instanceof Error && error.message.startsWith('RELAY_')) {
    return { code: error.message, message: 'The relay connection was lost.', retryable: true };
  }
  if (error instanceof Error && error.message.startsWith('RECOVERY_')) {
    return { code: error.message, message: 'Unable to unlock or save the recovery checkpoint.', retryable: false };
  }
  if (error instanceof Error && error.message === 'WASM_RESULT_INVALID') {
    return { code: 'WASM_RESULT_INVALID', message: 'The session returned an invalid result.', retryable: false };
  }
  if (error && typeof error === 'object' && 'code' in error && typeof error.code === 'string') {
    return { code: error.code, message: 'The requested operation could not be completed.', retryable: false };
  }
  return { code: 'WORKER_ERROR', message: 'The room could not continue safely.', retryable: false };
}

function isPublicError(error: unknown): error is Error & { publicError: PublicError } {
  return error instanceof Error && 'publicError' in error;
}

function relayErrorMessage(code: number): string {
  if (code === 1) return 'The invite or room is invalid.';
  if (code === 2) return 'The invite has already been used.';
  if (code === 3) return 'The room is full or unavailable.';
  if (code === 4) return 'The room has expired.';
  return 'The relay rejected the connection.';
}

function isLocalRelay(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
  } catch {
    return false;
  }
}

function safeHostname(url: string): string | null {
  try { return new URL(url).hostname; } catch { return null; }
}

function extractRoomFromSnapshot(snapshot: Uint8Array): Uint8Array {
  if (snapshot.length < 42 || snapshot[0] !== 0x42 || snapshot[1] !== 0x57 || snapshot[2] !== 0x52 || snapshot[3] !== 0x53) {
    throw publicFailure('INVALID_SNAPSHOT', 'Unable to unlock recovery.', false);
  }
  return snapshot.slice(6, 38);
}
