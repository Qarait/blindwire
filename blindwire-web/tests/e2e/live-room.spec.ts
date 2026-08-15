import { expect, test } from '@playwright/test';

test('two browser peers create, verify, message, and burn a room', async ({ browser }) => {
  const initiatorContext = await browser.newContext();
  const responderContext = await browser.newContext();
  const initiator = await initiatorContext.newPage();
  const responder = await responderContext.newPage();

  try {
    await initiator.goto('/');
    await expect(initiator.getByRole('heading', { name: 'Have an invite?' })).toBeVisible();
    await initiator.getByRole('button', { name: /Create a private room/i }).click();
    await expect(initiator.getByRole('heading', { name: 'Share this one-time invite' })).toBeVisible({ timeout: 30_000 });
    const invite = initiator.getByLabel('Invite link');
    const inviteUri = await invite.inputValue();

    await responder.goto('/');
    await expect(responder.getByRole('heading', { name: 'Have an invite?' })).toBeVisible();
    const responderInvite = responder.getByLabel('Invite link');
    await responderInvite.fill(inviteUri);
    const inspect = responder.getByRole('button', { name: 'Inspect invite' });
    await expect(inspect).toBeEnabled({ timeout: 5_000 });
    await inspect.click({ timeout: 5_000 });
    await expect(responder.getByRole('heading', { name: 'Ready to connect?' })).toBeVisible();
    await expect(responder.getByText('Local development relay')).toBeVisible();
    await responder.getByRole('button', { name: 'Join room' }).click();

    const initiatorSas = initiator.locator('[aria-label="Security emojis"]');
    const responderSas = responder.locator('[aria-label="Security emojis"]');
    await expect.poll(async () => `${await initiator.locator('main').textContent({ timeout: 1_000 }) ?? ''}\n---\n${await responder.locator('main').textContent({ timeout: 1_000 }) ?? ''}`, { timeout: 30_000, intervals: [500, 1_000, 2_000] }).toContain('Compare your security words');
    await expect(initiatorSas).toBeVisible({ timeout: 30_000 });
    await expect(responderSas).toBeVisible({ timeout: 30_000 });
    await expect(initiatorSas).toHaveText(await responderSas.innerText());
    await expect(initiator.locator('[aria-label="Security numbers"]')).toHaveText(await responder.locator('[aria-label="Security numbers"]').innerText());

    await initiator.getByRole('button', { name: 'I verified the match' }).click();
    await responder.getByRole('button', { name: 'I verified the match' }).click();
    await expect(initiator.getByRole('heading', { name: 'Messages' })).toBeVisible();
    await expect(responder.getByRole('heading', { name: 'Messages' })).toBeVisible();

    await initiator.getByRole('textbox', { name: 'Message' }).fill('hello from A');
    await initiator.getByRole('button', { name: 'Send' }).click();
    await expect(responder.getByText('hello from A')).toBeVisible();
    await responder.getByRole('textbox', { name: 'Message' }).fill('hello from B');
    await responder.getByRole('button', { name: 'Send' }).click();
    await expect(initiator.getByText('hello from B')).toBeVisible();

    await initiator.getByRole('button', { name: 'Burn room' }).click();
    await expect(initiator.getByRole('heading', { name: 'Room burned' })).toBeVisible();
    await expect(responder.getByRole('heading', { name: 'Room burned' })).toBeVisible();
  } finally {
    await responderContext.close();
    await initiatorContext.close();
  }
});
