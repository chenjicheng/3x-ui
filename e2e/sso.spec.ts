import { test, expect } from '@playwright/test';

const BASE = 'http://localhost:2053';

test.describe('SSO login', () => {
  test('login page renders SSO button', async ({ page }) => {
    await page.goto(BASE + '/');
    // Vue fetches /getTwoFactorEnable before showing the form
    await expect(page.locator('.x-sso-btn')).toBeVisible({ timeout: 15_000 });
  });

  test('SSO login flow completes and lands on panel', async ({ page }) => {
    await page.goto(BASE + '/');
    await page.waitForSelector('.x-sso-btn', { timeout: 15_000 });

    // Click SSO → mock OIDC auto-redirects with code → callback → panel
    await Promise.all([
      page.waitForURL(`${BASE}/panel/**`, { timeout: 20_000 }),
      page.click('.x-sso-btn'),
    ]);

    await expect(page).toHaveURL(/\/panel\//);
  });
});
