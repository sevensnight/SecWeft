import { expect, test } from '@playwright/test';

test('renders the P0 control-plane shell', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '综合态势' })).toBeVisible();
  await expect(page.getByText('P0 企业化迁移')).toBeVisible();
});
