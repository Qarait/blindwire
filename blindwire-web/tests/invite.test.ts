import {
  base64UrlDecode,
  base64UrlEncode,
  buildOfficialInviteUri,
  buildInviteUri,
  toInvitePreview,
} from '../src/invite';
import { describe, expect, it } from 'vitest';

describe('browser invite helpers', () => {
  it('builds the canonical official invite URI without padding', () => {
    const uri = buildOfficialInviteUri(
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      1_890_000_000_000,
    );

    expect(uri).toBe(
      'blindwire://join?v=1&r=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&t=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI&e=1890000000000&u=wss%3A%2F%2Frelay.blindwire.tech',
    );
  });

  it('round-trips arbitrary bytes through unpadded base64url', () => {
    const bytes = new Uint8Array([0, 1, 2, 125, 126, 127, 250, 251, 252, 253, 254, 255]);
    expect(base64UrlDecode(base64UrlEncode(bytes))).toEqual(bytes);
    expect(base64UrlEncode(bytes)).not.toContain('=');
  });

  it('projects only a safe preview from a validated descriptor', () => {
    const preview = toInvitePreview({
      room: 'A'.repeat(43),
      token: 'B'.repeat(43),
      expires_at: 1_890_000_000_000,
      relay_url: 'wss://relay.blindwire.tech/',
      relay_pin: null,
      official_relay: true,
    });

    expect(preview).toEqual({
      room_label: 'AAAAAAAA…',
      relay_label: 'relay.blindwire.tech',
      official_relay: true,
      expires_at: 1_890_000_000_000,
    });
    expect(JSON.stringify(preview)).not.toContain('BBBB');
  });

  it('rejects room and token values that are not 32 bytes', () => {
    expect(() => buildOfficialInviteUri(new Uint8Array(31), new Uint8Array(32), 1_890_000_000_000)).toThrow(
      'INVALID_INVITE_ARGUMENT',
    );
    expect(() => buildOfficialInviteUri(new Uint8Array(32), new Uint8Array(31), 1_890_000_000_000)).toThrow(
      'INVALID_INVITE_ARGUMENT',
    );
  });

  it('rejects the legacy relay hostname', () => {
    expect(() => buildInviteUri(
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      1_890_000_000_000,
      'wss://relay.blindwire.net',
    )).toThrow('INVALID_INVITE_ARGUMENT');
  });
});
