import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const scriptDirectory = fileURLToPath(new URL('.', import.meta.url));
const packageDirectory = resolve(scriptDirectory, '..');
const repositoryDirectory = resolve(packageDirectory, '..');
const outputDirectory = resolve(packageDirectory, 'src', 'wasm');
const coreDirectory = resolve(repositoryDirectory, 'blindwire-web-core');

const mode = process.argv[2];
if (mode !== '--dev' && mode !== '--release') {
  throw new Error('Usage: node scripts/build-wasm.mjs --dev|--release');
}

if (existsSync(outputDirectory)) {
  rmSync(outputDirectory, { recursive: true, force: true });
}
mkdirSync(outputDirectory, { recursive: true });

const result = spawnSync(
  'wasm-pack',
  [
    'build',
    coreDirectory,
    '--target',
    'web',
    '--mode',
    'no-install',
    '--out-dir',
    outputDirectory,
    mode,
  ],
  { cwd: repositoryDirectory, stdio: 'inherit', shell: false },
);

if (result.error) {
  throw new Error(`Unable to run wasm-pack: ${result.error.message}`);
}
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
