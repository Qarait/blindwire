import { expect, test } from '@playwright/test';

test('loads the static BlindWire home screen without remote dependencies', async ({ page }) => {
  const response = await page.goto('/');
  expect(response?.status()).toBe(200);
  await expect(page.getByText('BlindWire', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: /Create a private room/i })).toBeVisible();
  const csp = await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute('content');
  expect(csp).toContain("connect-src 'self' wss:");
  expect(csp).not.toContain('ws:');
  expect(csp).not.toContain('unsafe-inline');
});

test('keeps the join surface inside the public UI boundary', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Invite link').fill('blindwire://join?invalid');
  await expect(page.getByRole('button', { name: 'Inspect invite' })).toBeEnabled();
  await expect(page.locator('body')).not.toContainText('capability');
});
