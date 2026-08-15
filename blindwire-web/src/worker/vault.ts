import { base64UrlDecode, base64UrlEncode } from '../invite';

export type RecoveryRole = 'initiator' | 'responder';

export type RecoveryPayload = {
  snapshot: Uint8Array;
  capability: Uint8Array;
  epoch: bigint;
  relay_url: string;
  role: RecoveryRole;
  expires_at: number;
};

export class VaultError extends Error {
  constructor(readonly code: 'RECOVERY_NOT_FOUND' | 'RECOVERY_UNLOCK_FAILED' | 'RECOVERY_EXPIRED' | 'RECOVERY_SAVE_FAILED') {
    super(code);
    this.name = 'VaultError';
  }
}

type VaultRecord = {
  version: 1;
  salt: ArrayBuffer;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
};

type SerializedPayload = {
  snapshot: string;
  capability: string;
  epoch: string;
  relay_url: string;
  role: RecoveryRole;
  expires_at: number;
};

const DATABASE_NAME = 'blindwire-recovery-v1';
const STORE_NAME = 'snapshots';
const RECORD_KEY = 'current';
const DATABASE_VERSION = 1;
const KDF_ITERATIONS = 600_000;
const ASSOCIATED_DATA = new TextEncoder().encode('blindwire/recovery/v1');

export type RecoveryVault = {
  save(passphrase: string, payload: RecoveryPayload): Promise<void>;
  load(passphrase: string, nowMs: number): Promise<RecoveryPayload>;
  hasRecord(): Promise<boolean>;
  clear(): Promise<void>;
};

export async function openVault(): Promise<RecoveryVault> {
  const database = await openDatabase();
  return {
    save: (passphrase, payload) => save(database, passphrase, payload),
    load: (passphrase, nowMs) => load(database, passphrase, nowMs),
    hasRecord: () => hasRecord(database),
    clear: () => clear(database),
  };
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new VaultError('RECOVERY_SAVE_FAILED'));
  });
}

async function save(database: IDBDatabase, passphrase: string, payload: RecoveryPayload): Promise<void> {
  if (!passphrase) {
    throw new VaultError('RECOVERY_SAVE_FAILED');
  }
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt, ['encrypt']);
    const serialized: SerializedPayload = {
      snapshot: base64UrlEncode(payload.snapshot),
      capability: base64UrlEncode(payload.capability),
      epoch: payload.epoch.toString(),
      relay_url: payload.relay_url,
      role: payload.role,
      expires_at: payload.expires_at,
    };
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: ASSOCIATED_DATA },
      key,
      new TextEncoder().encode(JSON.stringify(serialized)),
    );
    const record: VaultRecord = {
      version: 1,
      salt: salt.buffer.slice(0),
      iv: iv.buffer.slice(0),
      ciphertext,
    };
    await putRecord(database, record);
  } catch {
    throw new VaultError('RECOVERY_SAVE_FAILED');
  }
}

async function load(database: IDBDatabase, passphrase: string, nowMs: number): Promise<RecoveryPayload> {
  const record = await getRecord(database);
  if (!record) {
    throw new VaultError('RECOVERY_NOT_FOUND');
  }
  if (record.version !== 1) {
    throw new VaultError('RECOVERY_UNLOCK_FAILED');
  }

  try {
    const key = await deriveKey(passphrase, new Uint8Array(record.salt), ['decrypt']);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(record.iv), additionalData: ASSOCIATED_DATA },
      key,
      record.ciphertext,
    );
    const serialized = JSON.parse(new TextDecoder().decode(plaintext)) as SerializedPayload;
    if (!Number.isSafeInteger(serialized.expires_at) || nowMs > serialized.expires_at) {
      throw new VaultError('RECOVERY_EXPIRED');
    }
    if (serialized.role !== 'initiator' && serialized.role !== 'responder') {
      throw new VaultError('RECOVERY_UNLOCK_FAILED');
    }
    return {
      snapshot: base64UrlDecode(serialized.snapshot),
      capability: base64UrlDecode(serialized.capability),
      epoch: BigInt(serialized.epoch),
      relay_url: serialized.relay_url,
      role: serialized.role,
      expires_at: serialized.expires_at,
    };
  } catch (error) {
    if (error instanceof VaultError) {
      throw error;
    }
    throw new VaultError('RECOVERY_UNLOCK_FAILED');
  }
}

async function hasRecord(database: IDBDatabase): Promise<boolean> {
  return (await getRecord(database)) !== undefined;
}

async function clear(database: IDBDatabase): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, 'readwrite');
    transaction.objectStore(STORE_NAME).delete(RECORD_KEY);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new VaultError('RECOVERY_SAVE_FAILED'));
    transaction.onabort = () => reject(transaction.error ?? new VaultError('RECOVERY_SAVE_FAILED'));
  });
}

function getRecord(database: IDBDatabase): Promise<VaultRecord | undefined> {
  return new Promise((resolve, reject) => {
    const request = database.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get(RECORD_KEY);
    request.onsuccess = () => resolve(request.result as VaultRecord | undefined);
    request.onerror = () => reject(request.error ?? new VaultError('RECOVERY_UNLOCK_FAILED'));
  });
}

function putRecord(database: IDBDatabase, record: VaultRecord): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, 'readwrite');
    transaction.objectStore(STORE_NAME).put(record, RECORD_KEY);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new VaultError('RECOVERY_SAVE_FAILED'));
    transaction.onabort = () => reject(transaction.error ?? new VaultError('RECOVERY_SAVE_FAILED'));
  });
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: KDF_ITERATIONS, hash: 'SHA-256' },
    passphraseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}
