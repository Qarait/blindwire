import { describe, expect, it } from 'vitest';
import { encodeClientPacket, parseServerPacket, RelayClient } from '../src/worker/relay';

const bytes = (value: number, length: number) => new Uint8Array(length).fill(value);

class FakeWebSocket {
  static last: FakeWebSocket;
  binaryType = '';
  sent: ArrayBuffer[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;

  constructor(readonly url: string) {
    FakeWebSocket.last = this;
  }

  send(data: ArrayBuffer): void {
    this.sent.push(data);
  }

  close(): void {
    this.onclose?.();
  }

  open(): void {
    this.onopen?.();
  }

  receive(data: Uint8Array): void {
    this.onmessage?.({ data: data.slice().buffer });
  }
}

describe('signaling v4 packet codec', () => {
  it('encodes a responder JOIN with v4 and a token', () => {
    const packet = encodeClientPacket({
      type: 'join',
      role: 'responder',
      room: bytes(0x11, 32),
      token: bytes(0x22, 32),
    });

    expect([...packet.slice(0, 3)]).toEqual([0x00, 0x72, 0x04]);
    expect(packet).toHaveLength(67);
  });

  it('encodes and parses an opaque relay frame without changing its bytes', () => {
    const frame = new Uint8Array([0x00, 0xff, 0x10]);
    const encoded = encodeClientPacket({ type: 'relay', frame });
    expect([...encoded]).toEqual([0x01, 0x00, 0x03, 0x00, 0xff, 0x10]);
    expect(parseServerPacket(encoded)).toEqual({ type: 'relay', frame });
  });

  it('encodes and parses a big-endian recovery epoch', () => {
    const epoch = 0x0102030405060708n;
    const packet = encodeClientPacket({
      type: 'resume',
      role: 'initiator',
      room: bytes(0x11, 32),
      capability: bytes(0x22, 32),
      epoch,
    });
    expect([...packet.slice(-8)]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(parseServerPacket(new Uint8Array([0x0a, 0, 0, 0, 0, 0, 0, 0, 7]))).toEqual({
      type: 'resume_ready',
      epoch: 7n,
    });
  });

  it('accepts a maximum frame and rejects an oversized frame', () => {
    const maximum = encodeClientPacket({ type: 'relay', frame: bytes(0xaa, 4096) });
    expect(maximum).toHaveLength(4099);
    expect(parseServerPacket(maximum)).toEqual({ type: 'relay', frame: bytes(0xaa, 4096) });
    expect(() => encodeClientPacket({ type: 'relay', frame: bytes(0xaa, 4097) })).toThrow('INVALID_PACKET');
  });

  it('rejects a relay frame whose declared length is not exact', () => {
    expect(() => parseServerPacket(new Uint8Array([0x01, 0x00, 0x04, 0xaa]))).toThrow('INVALID_PACKET');
  });

  it('rejects unknown opcodes and malformed controls', () => {
    expect(() => parseServerPacket(new Uint8Array([0xff]))).toThrow('INVALID_PACKET');
    expect(() => parseServerPacket(new Uint8Array([0x07, 0x00]))).toThrow('INVALID_PACKET');
  });

  it('joins through a binary WebSocket and exposes subsequent parsed events', async () => {
    const connecting = RelayClient.connectInitial(
      'ws://localhost:9000',
      'initiator',
      bytes(0x11, 32),
      undefined,
      FakeWebSocket,
    );
    FakeWebSocket.last.open();
    FakeWebSocket.last.receive(new Uint8Array([0x06, ...bytes(0x22, 32)]));

    const relay = await connecting;
    expect([...new Uint8Array(FakeWebSocket.last.sent[0])]).toEqual([0x00, 0x69, 0x04, ...bytes(0x11, 32)]);
    relay.sendHandshakeComplete();
    expect([...new Uint8Array(FakeWebSocket.last.sent[1])]).toEqual([0x03]);

    const nextEvent = relay.nextEvent();
    FakeWebSocket.last.receive(new Uint8Array([0x02]));
    await expect(nextEvent).resolves.toEqual({ type: 'peer_joined' });
  });
});
