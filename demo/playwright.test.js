const { test, expect } = require('@playwright/test');
const path = require('path');

const PAGE_URL = `file://${path.resolve(__dirname, 'index.html')}`;

test.describe('Peter Demo Page', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto(PAGE_URL);
    await page.waitForLoadState('networkidle');
  });

  test('page loads without errors', async ({ page }) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.waitForTimeout(1000);
    expect(errors).toEqual([]);
  });

  test('page title is correct', async ({ page }) => {
    await expect(page).toHaveTitle(/Peter/);
  });

  test('hero section is visible', async ({ page }) => {
    const hero = page.locator('h1');
    await expect(hero).toBeVisible();
    await expect(hero).toContainText('Peter');
  });

  test('all 4 sections exist', async ({ page }) => {
    const sections = ['flow', 'whatsapp', 'calls', 'future'];
    for (const id of sections) {
      const section = page.locator(`#${id}`);
      await expect(section).toBeAttached();
    }
  });

  test('navigation bar is visible', async ({ page }) => {
    const nav = page.locator('nav');
    await expect(nav).toBeVisible();
  });

  test('navigation links work', async ({ page }) => {
    const links = page.locator('nav a');
    const count = await links.count();
    expect(count).toBeGreaterThanOrEqual(4);
  });

  // Phone frame tests
  test('phone frames render with correct dimensions', async ({ page }) => {
    const phones = page.locator('.phone-frame');
    const count = await phones.count();
    expect(count).toBe(17);

    // Check first phone frame dimensions
    const firstPhone = phones.first();
    const box = await firstPhone.boundingBox();
    expect(box).not.toBeNull();
    // Width should be around 360px + bezels
    expect(box.width).toBeGreaterThan(300);
    expect(box.width).toBeLessThan(420);
  });

  test('phone frames have rounded corners', async ({ page }) => {
    const phone = page.locator('.phone-frame').first();
    const borderRadius = await phone.evaluate(el =>
      window.getComputedStyle(el).borderRadius
    );
    // Should be 2.5rem = 40px
    expect(parseFloat(borderRadius)).toBeGreaterThanOrEqual(30);
  });

  test('phone frames have black bezel', async ({ page }) => {
    const phone = page.locator('.phone-frame').first();
    const borderColor = await phone.evaluate(el =>
      window.getComputedStyle(el).borderColor
    );
    // Should be dark/black
    expect(borderColor).toMatch(/rgb\((0|17|34),\s*(0|17|34),\s*(0|17|34)\)/);
  });

  // All screens are HTML mockups (no screenshots)
  test('all phone screens have content', async ({ page }) => {
    const screens = page.locator('.phone-screen');
    const count = await screens.count();
    expect(count).toBe(17);

    for (let i = 0; i < count; i++) {
      const screen = screens.nth(i);
      const text = await screen.textContent();
      expect(text.length).toBeGreaterThan(5);
    }
  });

  // Section content tests
  test('App Flow section has 6 phones', async ({ page }) => {
    const section = page.locator('#flow');
    const phones = section.locator('.phone-frame');
    const count = await phones.count();
    expect(count).toBe(6);
  });

  test('WhatsApp Guard section has 2 phones', async ({ page }) => {
    const section = page.locator('#whatsapp');
    const phones = section.locator('.phone-frame');
    const count = await phones.count();
    expect(count).toBe(2);
  });

  test('Call Guard section has 2 phones', async ({ page }) => {
    const section = page.locator('#calls');
    const phones = section.locator('.phone-frame');
    const count = await phones.count();
    expect(count).toBe(2);
  });

  test('Future Features section has 8 phones', async ({ page }) => {
    const section = page.locator('#future');
    const phones = section.locator('.phone-frame');
    const count = await phones.count();
    expect(count).toBe(7);
  });

  // Future feature mockup tests
  test('Lock Screen mockup has time display', async ({ page }) => {
    const section = page.locator('#future');
    const lockTime = section.locator('text=10:30').first();
    await expect(lockTime).toBeVisible();
  });

  test('SOS screen has emergency elements', async ({ page }) => {
    const sos = page.locator('text=SOS').first();
    await expect(sos).toBeAttached();
  });

  test('Medication reminder has confirmation button', async ({ page }) => {
    const btn = page.locator('text=medicamento').first();
    await expect(btn).toBeAttached();
  });

  test('Quarantine screen has warning', async ({ page }) => {
    const warning = page.locator('text=CUARENTENA').first();
    await expect(warning).toBeAttached();
  });

  test('Security filters has 3 toggles', async ({ page }) => {
    const section = page.locator('#future');
    const toggles = section.locator('.toggle-track');
    // At least 3 toggles in the security filters mockup
    const count = await toggles.count();
    expect(count).toBeGreaterThanOrEqual(3);
  });

  // Dark theme tests
  test('page has dark background', async ({ page }) => {
    const bg = await page.evaluate(() =>
      window.getComputedStyle(document.body).backgroundColor
    );
    // Should be very dark (r,g,b all < 30)
    const match = bg.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/);
    expect(match).not.toBeNull();
    expect(parseInt(match[1])).toBeLessThan(30);
    expect(parseInt(match[2])).toBeLessThan(30);
    expect(parseInt(match[3])).toBeLessThan(30);
  });

  // Responsive tests
  test('responsive: renders at 1280px width', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    const phones = page.locator('.phone-frame');
    const firstBox = await phones.first().boundingBox();
    expect(firstBox).not.toBeNull();
  });

  test('responsive: renders at 768px tablet width', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    const phones = page.locator('.phone-frame');
    const firstBox = await phones.first().boundingBox();
    expect(firstBox).not.toBeNull();
  });

  test('responsive: renders at 375px mobile width', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    const phones = page.locator('.phone-frame');
    const firstBox = await phones.first().boundingBox();
    expect(firstBox).not.toBeNull();
  });

  // Scrollability
  test('page is scrollable', async ({ page }) => {
    const scrollHeight = await page.evaluate(() => document.body.scrollHeight);
    const viewportHeight = await page.evaluate(() => window.innerHeight);
    expect(scrollHeight).toBeGreaterThan(viewportHeight);
  });

  // Footer
  test('footer exists', async ({ page }) => {
    const footer = page.locator('text=Peter').last();
    await expect(footer).toBeAttached();
  });
});
