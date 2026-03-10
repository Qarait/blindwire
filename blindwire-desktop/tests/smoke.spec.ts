import { test, expect, chromium } from '@playwright/test';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';

let childProcess: any;
let browser: any;
let page: any;

test.beforeAll(async () => {
    // SECURITY GUARDRAIL:
    // CDP remote-debugging (port 9222) is a powerful automation hook that must NEVER be
    // enabled in production/normal builds. It exposes the entire WebView2 context to
    // any local process that can connect.
    //
    // This harness enables it via the WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS env var,
    // which only affects the child process spawned here, never the installed binary.
    //
    // Allowed contexts: debug builds, CI smoke runs, explicit test invocation.
    // Enforcement: this test will hard-abort unless BLINDWIRE_ALLOW_REMOTE_DEBUG=1 is set.
    if (process.env.BLINDWIRE_ALLOW_REMOTE_DEBUG !== '1') {
        throw new Error(
            'BLINDWIRE_ALLOW_REMOTE_DEBUG=1 must be set to run packaged smoke tests.\n' +
            'Never set this in production launch scripts or installed app shortcuts.'
        );
    }

    const exePath = path.resolve('../target/debug/blindwire-desktop.exe');

    if (!fs.existsSync(exePath)) {
        throw new Error(`Executable not found at ${exePath}. Did you run 'npx tauri build --debug'?`);
    }

    // Launch the app with CDP enabled ONLY for this child process.
    // The env var is NOT baked into the binary — it is injected here by the test harness.
    childProcess = spawn(exePath, [], {
        env: { ...process.env, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: '--remote-debugging-port=9222' },
        detached: true,
    });

    // Wait 3 seconds for the WebView2 process and WebSocket to initialize
    await new Promise(r => setTimeout(r, 4000));

    // Connect playwright to WebView2
    browser = await chromium.connectOverCDP('http://localhost:9222');
    const defaultContext = browser.contexts()[0];
    page = defaultContext.pages()[0];
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
    // 1. App lands in Home
    await expect(page.locator('h1:has-text("BlindWire")')).toBeVisible();

    // 2. Inject a valid mock invite link
    const input = page.locator('input[placeholder="Paste blindwire:// link"]');
    await input.fill('blindwire://join?v=1&r=testroom&t=testtoken1234567&e=9999999999999');
    await page.locator('button:has-text("Go")').click();

    // 3. App lands in Confirm Join
    const h1Text = await page.locator('h1').textContent();
    if (h1Text === 'Connection Error') {
        const pText = await page.locator('.glass-card p').textContent();
        console.error("DEBUG URL ERROR:", pText);
    }
    await expect(page.locator('h1')).toHaveText('Join Room');

    // 4. Approve join
    await page.locator('button:has-text("Connect")').click();

    // 5. App reaches Connecting
    await expect(page.locator('text=Establishing secure connection...')).toBeVisible();

    // 6. App reaches Verifying with identicon + 7-emoji SAS visible
    await expect(page.locator('h1:has-text("Verify Peer")')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.sas-grid')).toBeVisible();

    // 7. Confirm verification
    await page.locator('button:has-text("Matches (Verified)")').click();

    // 8. App reaches Chat
    await expect(page.locator('text=Connected to room room123')).toBeVisible();

    // 9. Send one mock message
    const chatInput = page.locator('input[placeholder="Send an encrypted message..."]');
    await chatInput.fill('Hello world');
    await page.locator('button:has-text("Send")').click();

    // 10. Leave room cleanly
    await page.locator('button:has-text("Leave")').click();

    // Back to home
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
