import { spawn, spawnSync, ChildProcess } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const workspaceRoot = path.resolve(__dirname, '..', '..');

export async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as net.AddressInfo;
      const port = addr.port;
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

function cargoMetadata(root: string) {
  const r = spawnSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], {
    cwd: root,
    encoding: 'utf8',
  });
  if (r.status !== 0) throw new Error(r.stderr || r.stdout);
  return JSON.parse(r.stdout);
}

export function resolveBin(bin: string) {
  const meta = cargoMetadata(workspaceRoot);
  const exe = process.platform === 'win32' ? `${bin}.exe` : bin;
  const full = path.join(meta.target_directory, 'debug', exe);
  if (!fs.existsSync(full)) throw new Error(`Missing binary: ${full}`);
  return full;
}

export async function startRelay(port?: number, testTtl?: string): Promise<{ process: ChildProcess, url: string, port: number }> {
    const actualPort = port || await getFreePort();
    const env = { ...process.env, BLINDWIRE_BIND_ADDR: `127.0.0.1:${actualPort}` };
    if (testTtl) {
        env['BLINDWIRE_TEST_TTL'] = testTtl;
    }
    const serverProcess = spawn(resolveBin('blindwire-server'), [], {
        cwd: workspaceRoot,
        env,
        stdio: 'ignore',
    });

    await waitForSocket('127.0.0.1', actualPort, 5000);
    const url = `ws://127.0.0.1:${actualPort}`;

    return { process: serverProcess, url, port: actualPort };
}

async function waitForSocket(host: string, port: number, timeoutMs: number): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise<void>((resolve, reject) => {
        const sock = new net.Socket();
        sock.setTimeout(500);
        sock.connect(port, host, () => {
          sock.destroy();
          resolve();
        });
        sock.on('error', reject);
        sock.on('timeout', () => {
            sock.destroy();
            reject(new Error("socket timeout"));
        });
      });
      return;
    } catch (e) {
      await new Promise(r => setTimeout(r, 200));
    }
  }
  throw new Error(`Timeout waiting for TCP port ${port}`);
}

export interface DesktopOptions {
    debugPort: number;
    userDataDir?: string;
    relayUrl?: string;
    testTtl?: string;
}

export function launchDesktop(opts: DesktopOptions): ChildProcess {
    const env = { ...process.env };
    env['BLINDWIRE_ALLOW_REMOTE_DEBUG'] = '1';
    env['WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS'] = `--remote-debugging-port=${opts.debugPort}`;
    
    if (opts.userDataDir) {
        env['WEBVIEW2_USER_DATA_FOLDER'] = opts.userDataDir;
    }
    if (opts.relayUrl) {
        env['BLINDWIRE_RELAY_URL'] = opts.relayUrl;
    }
    if (opts.testTtl) {
        env['BLINDWIRE_TEST_TTL'] = opts.testTtl;
    }

    const appProcess = spawn(resolveBin('blindwire-desktop'), [], {
        env,
        cwd: __dirname, 
        detached: false
    });

    appProcess.stdout?.on('data', d => console.log(`[APP] ${d}`));
    appProcess.stderr?.on('data', d => console.log(`[APP-ERR] ${d}`));

    return appProcess;
}

export function killProcess(proc: ChildProcess) {
    if (!proc) return;
    if (process.platform === 'win32' && proc.pid) {
        try {
            spawnSync('taskkill', ['/pid', proc.pid.toString(), '/f', '/t']);
        } catch (e) {}
    }
    try { proc.kill(); } catch (e) {}
}

export async function waitForCDP(port: number, appProcess: ChildProcess, timeoutMs = 20000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (appProcess.exitCode !== null || appProcess.killed) {
      throw new Error(`App exited prematurely with code ${appProcess.exitCode}`);
    }
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) {
        return;
      }
    } catch (e) {
      // ignore
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(`Timeout waiting for CDP on port ${port}`);
}

export async function waitForAppPage(context: any, timeoutMs = 15000) {
  const start = Date.now();

  while (Date.now() - start < timeoutMs) {
    const pages = context.pages();
    for (const p of pages) {
      const url = p.url();
      const isPackagedApp = url.includes('tauri.localhost');
      const isDebugApp = url.startsWith('http://localhost:1420/') ||
        url.startsWith('http://127.0.0.1:1420/');
      if (url && !url.includes('about:blank') && (isPackagedApp || isDebugApp)) {
        return p;
      }
    }
    await new Promise(r => setTimeout(r, 200));
  }

  const urls = context.pages().map((p: any) => p.url());
  throw new Error(`App page not found. Current pages: ${JSON.stringify(urls)}`);
}
