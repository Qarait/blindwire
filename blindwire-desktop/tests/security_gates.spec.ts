import { test, expect, chromium } from '@playwright/test';
import type { Locator } from '@playwright/test';
import jsQR from 'jsqr';
import { PNG } from 'pngjs';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';

import { startRelay, getFreePort, resolveBin, launchDesktop, waitForCDP, waitForAppPage, killProcess } from './harness';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const workspaceRoot = path.resolve(__dirname, '..', '..');

const readWorkspaceSource = (relativePath: string) =>
  fs.readFileSync(path.join(workspaceRoot, relativePath), 'utf8');

const decodeQr = async (locator: Locator): Promise<string> => {
  const png = PNG.sync.read(await locator.screenshot());
  const pixels = new Uint8ClampedArray(
    png.data.buffer,
    png.data.byteOffset,
    png.data.byteLength,
  );
  const decoded = jsQR(pixels, png.width, png.height);
  if (!decoded) throw new Error('Rendered invite QR code could not be decoded');
  return decoded.data;
};

test('static release sources contain no trust bypass or sensitive logging', () => {
  const appSource = readWorkspaceSource('blindwire-desktop/src/App.tsx');
  const commandSource = readWorkspaceSource('blindwire-desktop/src-tauri/src/commands.rs');
  const stateSource = readWorkspaceSource('blindwire-desktop/src-tauri/src/state.rs');
  const libSource = readWorkspaceSource('blindwire-desktop/src-tauri/src/lib.rs');
  const tauriConfig = JSON.parse(
    readWorkspaceSource('blindwire-desktop/src-tauri/tauri.conf.json'),
  );
  const releaseSources = [appSource, commandSource, stateSource, libSource].join('\n');

  expect(releaseSources).not.toContain('Trust New Identity');
  expect(releaseSources).not.toContain('trust_new_server_identity');
  expect(releaseSources).not.toContain('pending_identity_changes');
  expect(appSource).not.toMatch(/console\.(?:log|debug|info|warn|error)/);
  expect(commandSource).not.toMatch(/log::(?:trace|debug|info|warn|error)!/);

  expect(appSource).toContain('<QRCodeSVG');
  expect(appSource).toContain('value={view.info.qr_string}');
  expect(appSource).not.toContain('qr_string.slice(');

  const csp = tauriConfig.app.security.csp;
  expect(typeof csp).toBe('string');
  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("script-src 'self'");
  expect(csp).toContain("img-src 'self' data:");
  expect(csp).not.toContain('*');
});
const runResponder = (exe: string, uri: string, relayUrl?: string) => {
    return new Promise<{code: number | null, output: string}>((resolve) => {
      const env = { ...process.env, RUST_LOG: 'info' };
      if (relayUrl) env['BLINDWIRE_RELAY_URL'] = relayUrl;

      const responder = spawn(exe, [uri], {
        cwd: workspaceRoot,
        env
      });
      
      let output = '';
      responder.stdout.on('data', d => output += d.toString());
      responder.stderr.on('data', d => output += d.toString());
      
      responder.on('close', code => {
        console.log(`[RESPONDER] Exited with code ${code}`);
        resolve({ code, output });
      });
    });
};

test.describe.configure({ mode: 'serial' });

test.describe('Phase 7: Deep Hardening Security Gates', () => {

  test('Concurrent Race Rejection (Only One Join Wins)', async () => {
    const { process: server, url: relayUrl } = await startRelay();
    const debugPort = await getFreePort();
    const userDataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'bw-race-'));
    const appProcess = launchDesktop({ debugPort, userDataDir, relayUrl });

    try {
        console.log('[TEST] Waiting for CDP...');
        await waitForCDP(debugPort, appProcess);
        console.log('[TEST] Connecting over CDP...');
        const browser = await chromium.connectOverCDP(`http://127.0.0.1:${debugPort}`);
        console.log('[TEST] Connected to CDP. Getting default context...');
        const defaultContext = browser.contexts()[0];
        console.log('[TEST] Got default context. Getting page...');
        
        const page = await waitForAppPage(defaultContext);
        await page.waitForLoadState('domcontentloaded');

        page.on('pageerror', (err: any) => console.log(`[PAGE-ERR] ${err.message}`));
        page.on('console', (msg: any) => console.log(`[PAGE-CONSOLE] ${msg.text()}`));
        console.log(`[TEST] Current Page URL: ${page.url()}`);


        console.log('[TEST] Page found, waiting for UI selector...');
        try {
            await page.waitForSelector('button:has-text("Create Secure Room")', { timeout: 10000 });
        } catch (e) {
            console.log('[TEST-ERR] Timeout waiting for button. Page content:');
            console.log(await page.content());
            throw e;
        }
        console.log('[TEST] UI is ready.');
        const createRoom = page.getByRole('button', { name: 'Create Secure Room' });
        await expect(createRoom).toBeEnabled();
        await createRoom.evaluate(button => (button as HTMLButtonElement).click());
        console.log('[TEST] Create Room command submitted.');
        await page.waitForSelector('#invite-link-input', { timeout: 15000 });
        
        await page.waitForTimeout(500); // let UI settle
        
        const inviteUri = (await page.inputValue('#invite-link-input')).trim();

        expect(await decodeQr(page.locator('.qr-container svg'))).toBe(inviteUri);
        console.log('[TEST] Racing two responders for the generated invitation...');
        
        const p1 = runResponder(resolveBin('smoke-responder'), inviteUri, relayUrl);
        const p2 = runResponder(resolveBin('smoke-responder'), inviteUri, relayUrl);

        console.log('[TEST] Waiting for Verifying screen...');
        await page.waitForSelector('button:has-text("Matches (Verified)")', { timeout: 15000 });
        
        await page.waitForTimeout(500); // let verification UI settle
        
        console.log('[TEST] Clicking Matches (Verified)...');
        await page.click('button:has-text("Matches (Verified)")');

        console.log('[TEST] Waiting for Chat input...');
        await page.waitForSelector('#chat-input', { timeout: 10000 });
        
        await page.waitForTimeout(500); // let chat UI settle
        
        console.log('[TEST] Sending mock message...');
        await page.fill('#chat-input', 'Hello from Initiator! This is a secure end-to-end P2P connection.');
        await page.click('#chat-send');

        await page.waitForTimeout(500); // let message bubble render

        console.log('[TEST] Waiting for responders to exit...');
        const [res1, res2] = await Promise.all([p1, p2]);

        const successCount = (res1.code === 0 ? 1 : 0) + (res2.code === 0 ? 1 : 0);
        const failureCount = (res1.code !== 0 ? 1 : 0) + (res2.code !== 0 ? 1 : 0);

        console.log(`[TEST] Race result: success=${successCount}, failure=${failureCount}`);
        expect(successCount).toBe(1);
        expect(failureCount).toBe(1);
        const failedRes = res1.code !== 0 ? res1 : res2;
        // A loser rejected during reservation sees RoleTaken (1); after atomic
        // token consumption it sees the deliberately non-disclosing Unauthorized (4).
        expect(failedRes.output).toMatch(/UnexpectedResponse\((1|4)\)/);

        await browser.close();
    } finally {
        killProcess(appProcess);
        killProcess(server);
        await new Promise(r => setTimeout(r, 1000));
        await fsp.rm(userDataDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  test('Server-Side Expiry Rejection', async () => {
    const { process: server, url: relayUrl } = await startRelay(undefined, '1');
    const debugPort = await getFreePort();
    const userDataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'bw-expiry-'));

    const appProcess = launchDesktop({ debugPort, userDataDir, relayUrl, testTtl: '1' });

    try {
        await waitForCDP(debugPort, appProcess);
        const browser = await chromium.connectOverCDP(`http://127.0.0.1:${debugPort}`);
        const defaultContext = browser.contexts()[0];
        
        const page = await waitForAppPage(defaultContext);
        await page.waitForLoadState('domcontentloaded');
        page.on('pageerror', (err: any) => console.log(`[PAGE-ERR] ${err.message}`));
        page.on('console', (msg: any) => console.log(`[PAGE-CONSOLE] ${msg.text()}`));

        await expect(page.locator('h1:has-text("BlindWire")')).toBeVisible({ timeout: 10000 });
        await page.waitForTimeout(1000);

        await page.waitForSelector('button:has-text("Create Secure Room")');
        await page.click('button:has-text("Create Secure Room")');
        await page.waitForSelector('#invite-link-input');
        const inviteUri = (await page.inputValue('#invite-link-input')).trim();

        console.log('[TEST] Waiting for 4s for server-side expiry...');
        await new Promise(resolve => setTimeout(resolve, 4000));

        const res = await runResponder(resolveBin('smoke-responder'), inviteUri, relayUrl);
        expect(res.code).not.toBe(0);
        expect(res.output.includes('UnexpectedResponse(9)') || res.output.includes('UnexpectedResponse(4)')).toBe(true);

        await browser.close();
    } finally {
        killProcess(appProcess);
        killProcess(server);
        await new Promise(r => setTimeout(r, 1000));
        await fsp.rm(userDataDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  test('Room/Token Binding Mismatch', async () => {
    const { process: server, url: relayUrl } = await startRelay();
    const debugPort = await getFreePort();
    const userDataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'bw-mismatch-'));

    const appProcess = launchDesktop({ debugPort, userDataDir, relayUrl });

    try {
        await waitForCDP(debugPort, appProcess);
        const browser = await chromium.connectOverCDP(`http://127.0.0.1:${debugPort}`);
        const defaultContext = browser.contexts()[0];
        
        let page = await waitForAppPage(defaultContext);
        await page.waitForLoadState('domcontentloaded');
        page.on('pageerror', (err: any) => console.log(`[PAGE-ERR] ${err.message}`));
        page.on('console', (msg: any) => console.log(`[PAGE-CONSOLE] ${msg.text()}`));

        await expect(page.locator('h1:has-text("BlindWire")')).toBeVisible({ timeout: 10000 });
        await page.waitForTimeout(1000);

        await page.click('button:has-text("Create Secure Room")');
        await page.waitForSelector('#invite-link-input');
        const uriA = (await page.inputValue('#invite-link-input')).trim();
        const tokenA = uriA.match(/t=([A-Za-z0-9_-]+)/)?.[1];

        console.log('[TEST] Canceling first invite session...');
        await page.click('button:has-text("Cancel")');

        await page.reload();
        await expect(page.locator('h1:has-text("BlindWire")')).toBeVisible({ timeout: 10000 });
        await page.waitForTimeout(1000);
        await page.click('button:has-text("Create Secure Room")');
        await page.waitForSelector('#invite-link-input');
        const uriB = (await page.inputValue('#invite-link-input')).trim();

        const mismatchUri = uriB.replace(/t=[A-Za-z0-9_-]+/, `t=${tokenA}`);

        const res = await runResponder(resolveBin('smoke-responder'), mismatchUri, relayUrl);
        expect(res.code).not.toBe(0);
        expect(res.output).toContain('UnexpectedResponse(4)');

        await browser.close();
    } finally {
        killProcess(appProcess);
        killProcess(server);
        await new Promise(r => setTimeout(r, 1000));
        await fsp.rm(userDataDir, { recursive: true, force: true }).catch(() => {});
    }
  });
});
