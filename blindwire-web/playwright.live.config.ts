import { defineConfig, devices } from '@playwright/test';

const windows = process.platform === 'win32';
const relayCommand = windows
  ? 'set BLINDWIRE_BIND_ADDR=127.0.0.1:8780&& cargo run -p blindwire-server'
  : 'BLINDWIRE_BIND_ADDR=127.0.0.1:8780 cargo run -p blindwire-server';
const devCommand = windows
  ? 'set VITE_RELAY_URL=ws://127.0.0.1:8780&& npm run dev -- --host 127.0.0.1 --port 4175'
  : 'VITE_RELAY_URL=ws://127.0.0.1:8780 npm run dev -- --host 127.0.0.1 --port 4175';

export default defineConfig({
  testDir: './tests/e2e',
  testMatch: /live-room\.spec\.ts/,
  timeout: 120_000,
  use: {
    baseURL: 'http://127.0.0.1:4175',
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      command: relayCommand,
      cwd: '..',
      port: 8780,
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: devCommand,
      cwd: '.',
      url: 'http://127.0.0.1:4175',
      reuseExistingServer: false,
      timeout: 120_000,
    },
  ],
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
  ],
});
