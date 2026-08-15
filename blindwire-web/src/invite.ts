export type ValidatedInviteDescriptor = {
  room: string;
  token: string;
  expires_at: number;
  relay_url: string;
  relay_pin: string | null;
  official_relay: boolean;
};

export type InvitePreview = {
  room_label: string;
  relay_label: string;
  official_relay: boolean;
  expires_at: number;
};

const INVITE_ARGUMENT_ERROR = 'INVALID_INVITE_ARGUMENT';

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
}

export function base64UrlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) {
    throw new Error(INVITE_ARGUMENT_ERROR);
  }

  const padded = value.replaceAll('-', '+').replaceAll('_', '/')
    + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function buildOfficialInviteUri(
  room: Uint8Array,
  token: Uint8Array,
  expiresAt: number,
): string {
  return buildInviteUri(room, token, expiresAt, 'wss://relay.blindwire.tech');
}

export function buildInviteUri(
  room: Uint8Array,
  token: Uint8Array,
  expiresAt: number,
  relayUrl: string,
): string {
  if (room.length !== 32 || token.length !== 32 || !Number.isSafeInteger(expiresAt) || expiresAt <= 0) {
    throw new Error(INVITE_ARGUMENT_ERROR);
  }
  const relay = new URL(relayUrl);
  const localDevelopmentRelay = (relay.hostname === 'localhost' || relay.hostname === '127.0.0.1')
    && relay.protocol === 'ws:'
    && import.meta.env?.DEV === true;
  if (relayUrl !== 'wss://relay.blindwire.tech' && !localDevelopmentRelay) {
    throw new Error(INVITE_ARGUMENT_ERROR);
  }

  const params = new URLSearchParams();
  params.set('v', '1');
  params.set('r', base64UrlEncode(room));
  params.set('t', base64UrlEncode(token));
  params.set('e', String(expiresAt));
  params.set('u', relayUrl);
  return `blindwire://join?${params.toString()}`;
}

export function toInvitePreview(descriptor: ValidatedInviteDescriptor): InvitePreview {
  const relay = new URL(descriptor.relay_url);
  return {
    room_label: `${descriptor.room.slice(0, 8)}…`,
    relay_label: relay.hostname,
    official_relay: descriptor.official_relay,
    expires_at: descriptor.expires_at,
  };
}
