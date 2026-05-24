import { test, expect, chromium, Browser, Page } from '@playwright/test';
import { spawn, ChildProcess } from 'child_process';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import net from 'net';

let childProcess: ChildProcess;
let browser: Browser;
let page: Page;
let debugPort: number;
let userDataDir: string;

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('failed to get free port'));
        return;
      }
      const port = addr.port;
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

async function waitForCdp(port: number, timeoutMs = 15000): Promise<Browser> {
  const start = Date.now();
  let lastErr: unknown;
  while (Date.now() - start < timeoutMs) {
    try {
      return await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
    } catch (e) {
      lastErr = e;
      await new Promise(r => setTimeout(r, 250));
    }
  }
  throw new Error(`CDP not available on port ${port}: ${String(lastErr)}`);
}

test.beforeEach(async () => {
  debugPort = await getFreePort();
  userDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'blindwire-smoke-'));

  const exePath = path.resolve('../target/debug/blindwire-desktop.exe');

  childProcess = spawn(exePath, [], {
    env: {
      ...process.env,
      BLINDWIRE_ALLOW_REMOTE_DEBUG: '1',
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${debugPort}`,
      WEBVIEW2_USER_DATA_FOLDER: userDataDir,
      BLINDWIRE_RUN_ID: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    },
    detached: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  childProcess.stdout?.on('data', (d: any) => process.stdout.write(`[DESKTOP stdout] ${d}`));
  childProcess.stderr?.on('data', (d: any) => process.stderr.write(`[DESKTOP stderr] ${d}`));

  browser = await waitForCdp(debugPort);

  const ctx = browser.contexts()[0];
  
  // Wait for Tauri to load the window
  for (let i = 0; i < 50; i++) {
    const pages = ctx.pages();
    const target = pages.find(p => !p.url().includes('about:blank') && p.url() !== '');
    if (target) {
      page = target;
      break;
    }
    await new Promise(r => setTimeout(r, 100));
  }
  if (!page) {
    page = ctx.pages()[0];
  }

  page.on('console', msg => process.stdout.write(`[BROWSER CONSOLE] ${msg.text()}\n`));
  page.on('pageerror', error => process.stdout.write(`[BROWSER ERROR] ${error.message}\n`));

  await page.waitForLoadState('domcontentloaded');
});

test.afterEach(async () => {
  try { await browser?.close(); } catch {}

  if (childProcess?.pid) {
    // Windows-safe hard cleanup
    spawn('taskkill', ['/PID', String(childProcess.pid), '/T', '/F'], { stdio: 'ignore' });
  }

  try { await fs.rm(userDataDir, { recursive: true, force: true }); } catch {}
});

test('Reality Smoke: App (A) <-> Headless Responder (B)', async () => {
    test.setTimeout(60000); // 60s for full handshake and message round-trip

    // 1. App starts at Home
    console.log(`[SMOKE] Current URL: ${page.url()}`);
    const bodyText = await page.textContent('body');
    console.log(`[SMOKE] Body content snippet: ${bodyText?.slice(0, 100)}`);
    await expect(page.locator('h1')).toContainText('BlindWire');

    // 2. Click Create Room
    console.log(`[SMOKE] Emitting test ping to verify console wire...`);
    await page.evaluate(() => console.log("Ping from Playwright evaluate"));
    console.log(`[SMOKE] Waiting 1s for React to settle...`);
    await page.waitForTimeout(1000);
    console.log(`[SMOKE] Clicking Create Secure Room`);
    await page.locator('button:has-text("Create Secure Room")').click({ force: true });
    console.log(`[SMOKE] Click executed`);

    // 3. App reaches INVITE_QR screen
    try {
        await expect(page.locator('h1:has-text("Invite Peer")')).toBeVisible({ timeout: 10000 });
    } catch (e) {
        console.log(`[SMOKE] Failed waiting for Invite Peer. Body text: ${await page.textContent('body')}`);
        throw e;
    }

    // 4. Extract Invite URI
    const inviteUri = await page.locator('#invite-link-input').inputValue();
    console.log(`[SMOKE] Extracted URI: ${inviteUri}`);
    expect(inviteUri).toContain('blindwire://join');

    // 5. Spawn Headless Responder (Instance B)
    const responderPath = path.resolve('../target/debug/smoke-responder.exe');
    console.log(`[SMOKE] Spawning responder: ${responderPath}`);

    const responder = spawn(responderPath, [inviteUri, '--expect-msg', 'Reality Check'], {
        env: { ...process.env }
    });

    let responderSas = '';
    let responderPassed = false;

    responder.stdout.on('data', (data) => {
        const chunk = data.toString();
        process.stdout.write(`[RESPONDER] ${chunk}`);

        const lines = chunk.split('\n');
        for (const line of lines) {
            // Capture SAS: "[SMOKE] SAS (verify this matches instance A): emoji1 emoji2 ..."
            if (line.includes('SAS (verify this matches instance A):')) {
                responderSas = line.split(':').pop().trim();
                console.log(`[SMOKE] Captured Responder SAS: ${responderSas}`);
            }
            if (line.includes('[SMOKE] PASS')) {
                responderPassed = true;
            }
        }
    });

    responder.stderr.on('data', (data) => {
        process.stderr.write(`[RESPONDER ERR] ${data}`);
    });

    // 6. Wait for Instance A to reach Verifying screen
    await expect(page.locator('h1:has-text("Verify Peer")')).toBeVisible({ timeout: 15000 });

    // 7. Extract SAS from Instance A
    const emojiLocators = page.locator('.sas-emoji');
    const emojiCount = await emojiLocators.count();
    let appSasEmojis = [];
    for (let i = 0; i < emojiCount; i++) {
        appSasEmojis.push(await emojiLocators.nth(i).textContent());
    }
    const appSas = appSasEmojis.join(' ');
    console.log(`[SMOKE] Captured App SAS: ${appSas}`);

    // 8. Assert SAS Match
    // Note: We might need to wait a bit for responderSas to be populated if handshake is fast
    for (let i = 0; i < 10; i++) {
        if (responderSas) break;
        await new Promise(r => setTimeout(r, 500));
    }
    expect(appSas).toBe(responderSas);
    console.log(`[SMOKE] SAS MATCH VERIFIED ✓`);

    // 9. Confirm verification in App (A)
    await page.locator('button:has-text("Matches (Verified)")').click();

    // 10. App reaches Chat
    await expect(page.locator('.chat-messages')).toBeVisible({ timeout: 10000 });

    // 11. Send message from A -> B
    const chatInput = page.locator('input[placeholder="Send an encrypted message..."]');
    await chatInput.fill('Reality Check');
    await page.locator('button:has-text("Send")').click();
    console.log(`[SMOKE] Message sent from A: 'Reality Check'`);

    // 12. Verify A's message appears in its own UI (allow some time for disconnect event to fire)
    await expect(page.locator('.message-bubble.me .message-content')).toHaveText('Reality Check', { timeout: 5000 });

    // 13. Verify A receives the echo from B: "echo: Reality Check"
    try {
        await expect(page.locator('.message-bubble.peer .message-content'))
            .toHaveText('echo: Reality Check', { timeout: 10000 });
        console.log(`[SMOKE] Echo received in A: 'echo: Reality Check' ✓`);
    } catch (e) {
        console.log(`[SMOKE] Failed waiting for echo. Body text: ${await page.textContent('body')}`);
        throw e;
    }

    // 14. Verify Responder (B) finished successfully
    for (let i = 0; i < 20; i++) {
        if (responderPassed) break;
        await new Promise(r => setTimeout(r, 500));
    }
    expect(responderPassed).toBe(true);
    console.log(`[SMOKE] Responder B passed ✓`);

    // 14.5 Verify Peer Disconnected UI in App (A)
    await expect(page.locator('#chat-input')).toBeDisabled({ timeout: 5000 });
    await expect(page.locator('#chat-input')).toHaveAttribute('placeholder', 'Peer disconnected');
    console.log(`[SMOKE] UI Disconnect Gate verified ✓`);

    // 14. Leave room cleanly in App (A)
    await page.locator('button:has-text("Leave")').click();
    await expect(page.locator('h1:has-text("BlindWire")')).toBeVisible();
    console.log(`[SMOKE] E2E FULL PASS ✓`);
});

test('Step 5: Fresh Session Hygiene (SAS Uniqueness)', async () => {
    test.setTimeout(60000);

    const runSession = async () => {
        console.log(`[SMOKE] runSession URL: ${page.url()}`);
        console.log(`[SMOKE] Waiting 1s for React settle...`);
        await page.waitForTimeout(1000);
        await page.locator('button:has-text("Create Secure Room")').click({ force: true });
        try {
            await expect(page.locator('h1:has-text("Invite Peer")')).toBeVisible({ timeout: 10000 });
        } catch (e) {
            console.log(`[SMOKE] runSession failed to reach Invite Peer. DOM: ${await page.textContent('body')}`);
            throw e;
        }
        const inviteUri = await page.locator('#invite-link-input').inputValue();

        const responder = spawn(path.resolve('../target/debug/smoke-responder.exe'), [inviteUri], {
            env: { ...process.env }
        });

        let capturedSas = '';
        responder.stdout.on('data', (data) => {
            const chunk = data.toString();
            if (chunk.includes('SAS (verify this matches instance A):')) {
                capturedSas = chunk.split(':').pop().trim();
            }
        });

        await expect(page.locator('h1:has-text("Verify Peer")')).toBeVisible({ timeout: 15000 });
        const emojiLocators = page.locator('.sas-emoji');
        const appSas = (await emojiLocators.allTextContents()).join(' ');

        await page.locator('button:has-text("Matches (Verified)")').click();
        await expect(page.locator('.chat-messages')).toBeVisible();
        
        await page.locator('button:has-text("Leave")').click();
        await expect(page.locator('h1:has-text("BlindWire")')).toBeVisible();

        return appSas;
    };

    console.log(`[SMOKE] Starting Session 1...`);
    const sas1 = await runSession();
    console.log(`[SMOKE] Session 1 SAS: ${sas1}`);

    console.log(`[SMOKE] Starting Session 2...`);
    // Verify messages are cleared before starting session 2
    const messageCount = await page.locator('.message-bubble').count();
    expect(messageCount).toBe(0);

    const sas2 = await runSession();
    console.log(`[SMOKE] Session 2 SAS: ${sas2}`);

    expect(sas1).not.toBe(sas2);
    console.log(`[SMOKE] SAS UNIQUENESS VERIFIED ✓`);
    console.log(`[SMOKE] FRESH SESSION HYGIENE PASS ✓`);
});
