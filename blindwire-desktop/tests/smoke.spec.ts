import { test, expect, chromium } from '@playwright/test';
import { spawn } from 'child_process';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { launchDesktop, waitForCDP, waitForAppPage } from './harness';

let childProcess: any;
let browser: any;
let page: any;

test.beforeAll(async () => {
    if (process.env.BLINDWIRE_ALLOW_REMOTE_DEBUG !== '1') {
        throw new Error(
            'BLINDWIRE_ALLOW_REMOTE_DEBUG=1 must be set to run packaged smoke tests.\n' +
            'Never set this in production launch scripts or installed app shortcuts.'
        );
    }

    const debugPort = 9222;
    const userDataDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'bw-smoke-'));
    childProcess = launchDesktop({ debugPort, userDataDir });

    await waitForCDP(debugPort, childProcess);

    browser = await chromium.connectOverCDP(`http://localhost:${debugPort}`);
    const defaultContext = browser.contexts()[0];
    
    page = await waitForAppPage(defaultContext);
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);
});

test.afterAll(async () => {
    if (browser) await browser.close();
    if (childProcess) {
        childProcess.kill();
        // Windows usually needs tree-kill or forcefully killing the exe
        try { spawn('taskkill', ['/pid', childProcess.pid.toString(), '/f', '/t']); } catch (e) { }
    }
});

test('packaged app smoke test: valid join loop', async () => {
    page.on('pageerror', (err: any) => console.log(`[PAGE-ERR] ${err.message}`));
    page.on('console', (msg: any) => console.log(`[PAGE-CONSOLE] ${msg.text()}`));

    // 1. App lands in Home
    await expect(page.locator('h1:has-text("BlindWire")')).toBeVisible();

    // 2. Inject a valid mock invite link.
    //    Token must be 43 chars of base64url (decodes to 32 bytes) to pass Rust validation.
    //    Relay defaults to wss://relay.blindwire.net (official), so no relay needed for parse.
    const fakeToken = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // 43 chars, decodes to 32 zero-bytes
    const input = page.locator('input[placeholder="Paste blindwire:// link"]');
    await input.fill(`blindwire://join?v=1&r=testroom&t=${fakeToken}&e=9999999999999`);
    await page.locator('button:has-text("Go")').click();

    // 3. App lands in Confirm Join
    await page.waitForFunction(() => {
        const h1 = document.querySelector('h1');
        return h1 && h1.textContent !== 'BlindWire';
    }, { timeout: 5000 });

    const h1Text = await page.locator('h1').textContent();
    if (h1Text === 'Connection Error') {
        const pText = await page.locator('.glass-card p').textContent();
        console.error("DEBUG PARSE ERROR:", pText);
    }
    await expect(page.locator('h1')).toHaveText('Join Room');

    // 4. Verify the Confirm Join screen shows expected room and relay info
    await expect(page.locator('text=testroom')).toBeVisible();
    await expect(page.locator('text=Official BlindWire Relay')).toBeVisible();

    // 5. Cancel back to Home (don't connect — no relay is running)
    await page.locator('button:has-text("Cancel")').click();

    // 6. Back to home
    await expect(page.locator('h1:has-text("BlindWire")')).toBeVisible();
});


test('packaged app smoke test: negative join loop', async () => {
    // 1. Launch app -> Inject invalid/expired invite
    const input = page.locator('input[placeholder="Paste blindwire:// link"]');
    // e=1000000000 triggers ExpiredToken (10 digits)
    await input.fill('blindwire://join?v=1&r=testroom&t=testtoken1234567&e=1000000000');
    await page.locator('button:has-text("Go")').click();

    // 2. App shows safe error state
    await expect(page.locator('h1:has-text("Connection Error")')).toBeVisible();
    await expect(page.locator('text=This invite link has expired.')).toBeVisible();

    // 3. Clear back to home, ensuring no chat state is entered
    await page.locator('button:has-text("Back")').click();
    await expect(page.locator('h1:has-text("BlindWire")')).toBeVisible();
});
