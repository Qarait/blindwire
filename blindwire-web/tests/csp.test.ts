import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const packageDirectory = resolve(import.meta.dirname, '..');
const sourceDirectory = resolve(packageDirectory, 'src');

async function sourceFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory() && entry.name !== 'wasm') files.push(...await sourceFiles(path));
    if (entry.isFile() && /\.(ts|tsx|css)$/u.test(entry.name)) files.push(path);
  }
  return files;
}

describe('static browser security boundary', () => {
  it('ships a restrictive production CSP', async () => {
    const html = await readFile(resolve(packageDirectory, 'dist', 'index.html'), 'utf8');
    expect(html).toContain("default-src 'self'");
    expect(html).toContain("worker-src 'self'");
    expect(html).toContain("connect-src 'self' wss:");
    expect(html).not.toContain('ws:');
    expect(html).not.toContain('unsafe-inline');
    expect(html).not.toContain('unsafe-eval');
  });

  it('keeps browser secrets and native APIs inside the worker boundary', async () => {
    const files = await sourceFiles(sourceDirectory);
    const source = await Promise.all(files.map(async (file) => [file, await readFile(file, 'utf8')] as const));
    for (const [file, contents] of source) {
      expect(contents).not.toContain('@tauri-apps');
      expect(contents).not.toContain('console.log');
      if (!file.startsWith(resolve(sourceDirectory, 'worker'))) {
        expect(contents).not.toMatch(/\bWebSocket\b|indexedDB|crypto\.subtle/u);
      }
    }
  });
});
