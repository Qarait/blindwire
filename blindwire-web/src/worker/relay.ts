export type RelayRole = 'initiator' | 'responder';

export type ClientPacket =
  | { type: 'join'; role: 'initiator'; room: Uint8Array }
  | { type: 'join'; role: 'responder'; room: Uint8Array; token: Uint8Array }
  | { type: 'relay'; frame: Uint8Array }
  | { type: 'quit' }
  | { type: 'handshake_complete' }
  | { type: 'register_recovery'; capability: Uint8Array }
  | { type: 'resume'; role: RelayRole; room: Uint8Array; capability: Uint8Array; epoch: bigint }
  | { type: 'burn' };

export type ServerPacket =
  | { type: 'relay'; frame: Uint8Array }
  | { type: 'peer_joined' }
  | { type: 'peer_quit' }
  | { type: 'expired' }
  | { type: 'error'; code: number }
  | { type: 'token'; token: Uint8Array }
  | { type: 'handshake_confirmed' }
  | { type: 'recovery_registered' }
  | { type: 'peer_resuming'; epoch: bigint }
  | { type: 'resume_ready'; epoch: bigint }
  | { type: 'room_burned' };

export type RelayEvent = ServerPacket;

export const MAX_RELAY_FRAME = 4096;
const V4 = 0x04;
const ERROR_CODES = new Set([1, 2, 3, 4, 5, 6, 7, 8, 9]);

function invalid(code = 'INVALID_PACKET'): never {
  throw new Error(code);
}

function requireFixed(value: Uint8Array, length: number): Uint8Array {
  if (value.length !== length) {
    invalid('INVALID_PACKET');
  }
  return value;
}

function roleByte(role: RelayRole): number {
  return role === 'initiator' ? 0x69 : 0x72;
}

function packetWithPrefix(length: number, opcode: number): Uint8Array {
  const packet = new Uint8Array(length);
  packet[0] = opcode;
  return packet;
}

export function encodeClientPacket(packet: ClientPacket): Uint8Array {
  switch (packet.type) {
    case 'join': {
      const room = requireFixed(packet.room, 32);
      const token = packet.role === 'responder' ? requireFixed(packet.token, 32) : undefined;
      const encoded = packetWithPrefix(token ? 67 : 35, 0x00);
      encoded[1] = roleByte(packet.role);
      encoded[2] = V4;
      encoded.set(room, 3);
      if (token) {
        encoded.set(token, 35);
      }
      return encoded;
    }
    case 'relay': {
      if (packet.frame.length < 1 || packet.frame.length > MAX_RELAY_FRAME) {
        invalid('INVALID_PACKET');
      }
      const encoded = packetWithPrefix(packet.frame.length + 3, 0x01);
      new DataView(encoded.buffer).setUint16(1, packet.frame.length, false);
      encoded.set(packet.frame, 3);
      return encoded;
    }
    case 'quit':
      return new Uint8Array([0x02]);
    case 'handshake_complete':
      return new Uint8Array([0x03]);
    case 'register_recovery': {
      const encoded = packetWithPrefix(33, 0x04);
      encoded.set(requireFixed(packet.capability, 32), 1);
      return encoded;
    }
    case 'resume': {
      const encoded = packetWithPrefix(75, 0x05);
      encoded[1] = roleByte(packet.role);
      encoded[2] = V4;
      encoded.set(requireFixed(packet.room, 32), 3);
      encoded.set(requireFixed(packet.capability, 32), 35);
      new DataView(encoded.buffer).setBigUint64(67, packet.epoch, false);
      return encoded;
    }
    case 'burn':
      return new Uint8Array([0x06]);
  }
}

function parseRelay(bytes: Uint8Array): ServerPacket {
  if (bytes.length < 3) {
    invalid();
  }
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(1, false);
  if (length < 1 || length > MAX_RELAY_FRAME || length + 3 !== bytes.length) {
    invalid();
  }
  return { type: 'relay', frame: bytes.slice(3) };
}

function exact(bytes: Uint8Array, length: number): void {
  if (bytes.length !== length) {
    invalid();
  }
}

export function parseServerPacket(input: Uint8Array): ServerPacket {
  const bytes = input.slice();
  const opcode = bytes[0];
  switch (opcode) {
    case 0x01:
      return parseRelay(bytes);
    case 0x02:
      exact(bytes, 1);
      return { type: 'peer_joined' };
    case 0x03:
      exact(bytes, 1);
      return { type: 'peer_quit' };
    case 0x04:
      exact(bytes, 1);
      return { type: 'expired' };
    case 0x05:
      exact(bytes, 2);
      if (!ERROR_CODES.has(bytes[1])) {
        invalid();
      }
      return { type: 'error', code: bytes[1] };
    case 0x06:
      exact(bytes, 33);
      return { type: 'token', token: bytes.slice(1) };
    case 0x07:
      exact(bytes, 1);
      return { type: 'handshake_confirmed' };
    case 0x08:
      exact(bytes, 1);
      return { type: 'recovery_registered' };
    case 0x09:
      exact(bytes, 9);
      return { type: 'peer_resuming', epoch: new DataView(bytes.buffer).getBigUint64(1, false) };
    case 0x0a:
      exact(bytes, 9);
      return { type: 'resume_ready', epoch: new DataView(bytes.buffer).getBigUint64(1, false) };
    case 0x0b:
      exact(bytes, 1);
      return { type: 'room_burned' };
    default:
      invalid();
  }
}

export type WebSocketLike = {
  binaryType: string;
  onopen: (() => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror: (() => void) | null;
  onclose: (() => void) | null;
  send(data: ArrayBuffer): void;
  close(): void;
};

export type WebSocketConstructor = new (url: string) => WebSocketLike;

type EventWaiter = {
  resolve: (event: RelayEvent) => void;
  reject: (error: Error) => void;
};

function defaultWebSocketConstructor(): WebSocketConstructor {
  return WebSocket as unknown as WebSocketConstructor;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export class RelayClient {
  private readonly queue: RelayEvent[] = [];
  private readonly waiters: EventWaiter[] = [];
  private opened = false;
  private closed = false;

  private constructor(private readonly socket: WebSocketLike) {
    socket.binaryType = 'arraybuffer';
    socket.onopen = () => {
      this.opened = true;
    };
    socket.onmessage = (event) => {
      void this.receiveMessage(event.data);
    };
    socket.onerror = () => {
      this.fail(new Error('RELAY_UNREACHABLE'));
    };
    socket.onclose = () => {
      this.closed = true;
      this.fail(new Error('RELAY_DISCONNECTED'));
    };
  }

  static async connectInitial(
    url: string,
    role: RelayRole,
    room: Uint8Array,
    token?: Uint8Array,
    socketConstructor: WebSocketConstructor = defaultWebSocketConstructor(),
  ): Promise<RelayClient> {
    if (!isAllowedRelayUrl(url)) {
      invalid('RELAY_URL_INVALID');
    }
    if (role === 'responder' && !token) {
      invalid('INVALID_PACKET');
    }
    const client = new RelayClient(new socketConstructor(url));
    await client.waitUntilOpen();
    client.sendRaw(encodeClientPacket(
      role === 'initiator'
        ? { type: 'join', role, room }
        : { type: 'join', role, room, token: token as Uint8Array },
    ));

    const expected = role === 'initiator' ? 'token' : 'peer_joined';
    while (true) {
      const event = await client.nextEvent();
      if (event.type === expected) {
        return client;
      }
      if (event.type === 'error') {
        throw new Error(`RELAY_ERROR_${event.code}`);
      }
    }
  }

  static async connectResume(
    url: string,
    role: RelayRole,
    room: Uint8Array,
    capability: Uint8Array,
    epoch: bigint,
    socketConstructor: WebSocketConstructor = defaultWebSocketConstructor(),
  ): Promise<RelayClient> {
    if (!isAllowedRelayUrl(url)) {
      invalid('RELAY_URL_INVALID');
    }
    const client = new RelayClient(new socketConstructor(url));
    await client.waitUntilOpen();
    client.sendRaw(encodeClientPacket({ type: 'resume', role, room, capability, epoch }));
    while (true) {
      const event = await client.nextEvent();
      if (event.type === 'resume_ready') {
        return client;
      }
      if (event.type === 'error') {
        throw new Error(`RELAY_ERROR_${event.code}`);
      }
    }
  }

  async *events(): AsyncIterable<RelayEvent> {
    while (!this.closed) {
      yield await this.nextEvent();
    }
  }

  nextEvent(): Promise<RelayEvent> {
    const event = this.queue.shift();
    if (event) {
      return Promise.resolve(event);
    }
    if (this.closed) {
      return Promise.reject(new Error('RELAY_DISCONNECTED'));
    }
    return new Promise<RelayEvent>((resolve, reject) => {
      this.waiters.push({ resolve, reject });
    });
  }

  sendFrame(frame: Uint8Array): void {
    this.sendRaw(encodeClientPacket({ type: 'relay', frame }));
  }

  sendHandshakeComplete(): void {
    this.sendRaw(encodeClientPacket({ type: 'handshake_complete' }));
  }

  registerRecovery(capability: Uint8Array): void {
    this.sendRaw(encodeClientPacket({ type: 'register_recovery', capability }));
  }

  burn(): void {
    this.sendRaw(encodeClientPacket({ type: 'burn' }));
  }

  quit(): void {
    this.sendRaw(encodeClientPacket({ type: 'quit' }));
  }

  close(): void {
    if (!this.closed) {
      this.closed = true;
      this.socket.close();
      this.fail(new Error('RELAY_DISCONNECTED'));
    }
  }

  private waitUntilOpen(): Promise<void> {
    if (this.opened) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const originalOpen = this.socket.onopen;
      const originalError = this.socket.onerror;
      this.socket.onopen = () => {
        originalOpen?.();
        resolve();
      };
      this.socket.onerror = () => {
        originalError?.();
        reject(new Error('RELAY_UNREACHABLE'));
      };
    });
  }

  private sendRaw(packet: Uint8Array): void {
    if (this.closed || !this.opened) {
      throw new Error('RELAY_NOT_OPEN');
    }
    this.socket.send(asArrayBuffer(packet));
  }

  private async receiveMessage(data: unknown): Promise<void> {
    try {
      if (typeof data === 'string') {
        invalid('INVALID_PACKET');
      }
      let bytes: Uint8Array;
      if (data instanceof ArrayBuffer) {
        bytes = new Uint8Array(data);
      } else if (ArrayBuffer.isView(data)) {
        bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      } else if (data instanceof Blob) {
        bytes = new Uint8Array(await data.arrayBuffer());
      } else {
        invalid('INVALID_PACKET');
      }
      this.enqueue(parseServerPacket(bytes));
    } catch (error) {
      this.fail(error instanceof Error ? error : new Error('INVALID_PACKET'));
    }
  }

  private enqueue(event: RelayEvent): void {
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter.resolve(event);
    } else {
      this.queue.push(event);
    }
  }

  private fail(error: Error): void {
    while (this.waiters.length > 0) {
      this.waiters.shift()?.reject(error);
    }
  }
}

function isAllowedRelayUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const local = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    return parsed.protocol === 'wss:' || (import.meta.env?.DEV === true && local && parsed.protocol === 'ws:');
  } catch {
    return false;
  }
}
