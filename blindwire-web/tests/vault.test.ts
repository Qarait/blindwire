import { beforeEach, describe, expect, it } from 'vitest';
import { openVault, type RecoveryPayload } from '../src/worker/vault';

const payload: RecoveryPayload = {
  snapshot: new Uint8Array([1, 2, 3]),
  capability: new Uint8Array([4, 5, 6]),
  epoch: 4n,
  relay_url: 'wss://relay.blindwire.net',
  role: 'initiator',
  expires_at: 1_900_000_000_000,
};

async function readRawRecord(): Promise<Record<string, unknown>> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('blindwire-recovery-v1');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return new Promise((resolve, reject) => {
    const request = database.transaction('snapshots', 'readonly').objectStore('snapshots').get('current');
    request.onsuccess = () => resolve(request.result as Record<string, unknown>);
    request.onerror = () => reject(request.error);
  });
}

describe('encrypted recovery vault', () => {
  beforeEach(async () => {
    await (await openVault()).clear();
  });

  it('round-trips a payload while persisting ciphertext only', async () => {
    const vault = await openVault();
    await vault.save('correct horse battery staple', payload);
    const record = await readRawRecord();

    expect(record).toEqual(expect.objectContaining({
      version: 1,
    }));
    expect(record.salt).toHaveProperty('byteLength', 16);
    expect(record.iv).toHaveProperty('byteLength', 12);
    expect(record.ciphertext).toHaveProperty('byteLength');
    expect(JSON.stringify(record)).not.toContain('correct horse');
    expect(new TextDecoder().decode(record.ciphertext as ArrayBuffer)).not.toContain('relay.blindwire.net');
    await expect(vault.load('wrong passphrase', 1_800_000_000_000)).rejects.toMatchObject({ code: 'RECOVERY_UNLOCK_FAILED' });
    await expect(vault.load('correct horse battery staple', 1_800_000_000_000)).resolves.toMatchObject({ epoch: 4n });
  });

  it('uses a fresh salt and IV when replacing a checkpoint', async () => {
    const vault = await openVault();
    await vault.save('passphrase', payload);
    const first = await readRawRecord();
    await vault.save('passphrase', { ...payload, epoch: 5n });
    const second = await readRawRecord();

    expect([...new Uint8Array(first.salt as ArrayBuffer)]).not.toEqual([...new Uint8Array(second.salt as ArrayBuffer)]);
    expect([...new Uint8Array(first.iv as ArrayBuffer)]).not.toEqual([...new Uint8Array(second.iv as ArrayBuffer)]);
  });

  it('rejects expired records and clears the record', async () => {
    const vault = await openVault();
    await vault.save('passphrase', { ...payload, expires_at: 100 });
    await expect(vault.load('passphrase', 101)).rejects.toMatchObject({ code: 'RECOVERY_EXPIRED' });
    expect(await vault.hasRecord()).toBe(true);
    await vault.clear();
    expect(await vault.hasRecord()).toBe(false);
  });
});
