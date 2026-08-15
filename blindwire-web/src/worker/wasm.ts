import type { ValidatedInviteDescriptor } from '../invite';

export type WasmEvent =
  | { type: 'outbound'; frame: Uint8Array }
  | { type: 'verification'; emojis: string[]; numeric: number[] }
  | { type: 'peer_verified' }
  | { type: 'text'; id: Uint8Array; text: string }
  | { type: 'acknowledgement'; id: Uint8Array }
  | { type: 'recovering' }
  | { type: 'recovered' }
  | { type: 'burned' };

export type WasmCallResult = {
  events: WasmEvent[];
  message_id?: Uint8Array;
};

export type WasmSessionLike = {
  start_handshake(): WasmCallResult;
  receive_frame(frame: Uint8Array): WasmCallResult;
  relay_handshake_confirmed(): WasmCallResult;
  confirm_user_verified(): WasmCallResult;
  send_text(text: string): WasmCallResult;
  copy_worker_snapshot_for_storage(expiresAtMs: bigint): Uint8Array;
  begin_recovery(epoch: bigint): WasmCallResult;
  accept_resume_proof(frame: Uint8Array): WasmCallResult;
  burn(): WasmCallResult;
  is_handshake_complete(): boolean;
  free?(): void;
};

export type WasmSessionConstructor = {
  new (role: number, room: Uint8Array, token?: Uint8Array | null): WasmSessionLike;
  restore_worker_snapshot(snapshot: Uint8Array, nowMs: bigint): WasmSessionLike;
};

export type WasmApi = {
  generate_random_32(): Uint8Array;
  parse_invite(uri: string): ValidatedInviteDescriptor;
  WebSession: WasmSessionConstructor;
};

let wasmPromise: Promise<WasmApi> | undefined;

export function loadWasm(): Promise<WasmApi> {
  wasmPromise ??= import('../wasm/blindwire_web_core.js').then(async (module) => {
    await module.default();
    return {
      generate_random_32: module.generate_random_32,
      parse_invite: module.parse_invite,
      WebSession: module.WebSession,
    } as unknown as WasmApi;
  });
  return wasmPromise;
}
