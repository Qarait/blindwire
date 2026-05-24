import { defineConfig } from '@playwright/test';

export default defineConfig({
    testDir: './tests',
    fullyParallel: false, // Must be sequential to bind to port 9222
    workers: 1,
    retries: 0,
    timeout: 120000, // 120s timeout for tests
});
