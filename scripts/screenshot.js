// Playwright screenshot script for pam-pocketid
// Usage: node scripts/screenshot.js
// Opens a browser for passkey auth, then captures all pages in dark+light.

const { chromium } = require('/Users/rinseaid/.npm/_npx/e41f203b7505f1fb/node_modules/playwright');
const path = require('path');

const BASE_URL = 'https://pam.rinseaid.org';
const OUT_DIR = path.join(__dirname, '..', 'screenshots');

// Map real values → generic placeholders (serializable for page.evaluate)
const REPLACEMENTS = [
  [{ source: '\\brinseaid\\b', flags: 'g' }, 'alice'],
  [{ source: '\\bpvemsa2\\b', flags: 'gi' }, 'db-prod-1'],
  [{ source: '\\bplex\\b', flags: 'gi' }, 'media-srv'],
  [{ source: '\\bdocker\\b', flags: 'gi' }, 'app-srv'],
  [{ source: '\\b[A-Z0-9]{6}-[A-Z0-9]{6}\\b', flags: 'g' }, 'ABCDEF-123456'],
  [{ source: '\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b', flags: 'g' }, '10.0.0.1'],
];

async function anonymize(page) {
  await page.evaluate((replacements) => {
    function replaceInText(node) {
      if (node.nodeType === Node.TEXT_NODE) {
        let t = node.textContent;
        for (const [pattern, sub] of replacements) {
          t = t.replace(new RegExp(pattern.source, pattern.flags), sub);
        }
        node.textContent = t;
      } else if (node.nodeType === Node.ELEMENT_NODE &&
                 !['SCRIPT','STYLE','INPUT','TEXTAREA'].includes(node.tagName)) {
        node.childNodes.forEach(replaceInText);
      }
    }
    replaceInText(document.body);

    // Blur avatar images
    document.querySelectorAll('img').forEach(img => {
      if (img.src && (img.src.includes('gravatar') || img.src.includes('avatar') ||
                      img.src.includes('pocket') || img.naturalWidth < 64)) {
        img.style.filter = 'blur(8px)';
      }
    });
  }, REPLACEMENTS);
}

async function setTheme(page, theme) {
  const current = page.url();
  await page.goto(`${BASE_URL}/theme?set=${theme}&from=${encodeURIComponent(current.replace(BASE_URL, '') || '/')}`,
    { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(500);
}

async function capture(page, url, name, theme) {
  await setTheme(page, theme);
  await page.goto(`${BASE_URL}${url}`, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(800);
  await anonymize(page);
  const suffix = theme === 'light' ? '-light' : '';
  const file = path.join(OUT_DIR, `${name}${suffix}.png`);
  await page.screenshot({ path: file, fullPage: false });
  console.log(`  saved ${path.basename(file)}`);
}

async function captureBoth(page, url, name) {
  await capture(page, url, name, 'dark');
  await capture(page, url, name, 'light');
}

(async () => {
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();

  await page.goto(BASE_URL, { waitUntil: 'domcontentloaded' });

  if (!page.url().startsWith(BASE_URL)) {
    console.log('\nPlease complete passkey authentication in the browser window...');
    await page.waitForURL(`${BASE_URL}/**`, { timeout: 120000 });
    console.log('Authenticated. Taking screenshots...\n');
  } else {
    console.log('Session active. Taking screenshots...\n');
  }

  console.log('Sessions...');
  await captureBoth(page, '/', 'sessions');

  console.log('History...');
  await captureBoth(page, '/history', 'history');

  console.log('Hosts...');
  await captureBoth(page, '/hosts', 'hosts');

  console.log('Info...');
  await captureBoth(page, '/info', 'info');

  console.log('Admin history...');
  await setTheme(page, 'dark');
  await page.goto(`${BASE_URL}/admin/history`, { waitUntil: 'domcontentloaded' });
  if (page.url().includes('/admin')) {
    await page.waitForTimeout(800);
    await anonymize(page);
    await page.screenshot({ path: path.join(OUT_DIR, 'admin-history.png'), fullPage: false });
    console.log('  saved admin-history.png');

    await setTheme(page, 'light');
    await page.goto(`${BASE_URL}/admin/history`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(800);
    await anonymize(page);
    await page.screenshot({ path: path.join(OUT_DIR, 'admin-history-light.png'), fullPage: false });
    console.log('  saved admin-history-light.png');
  }

  console.log('Admin users...');
  await setTheme(page, 'dark');
  await page.goto(`${BASE_URL}/admin/users`, { waitUntil: 'domcontentloaded' });
  if (page.url().includes('/admin')) {
    await page.waitForTimeout(800);
    await anonymize(page);
    await page.screenshot({ path: path.join(OUT_DIR, 'admin-users.png'), fullPage: false });
    console.log('  saved admin-users.png');

    await setTheme(page, 'light');
    await page.goto(`${BASE_URL}/admin/users`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(800);
    await anonymize(page);
    await page.screenshot({ path: path.join(OUT_DIR, 'admin-users-light.png'), fullPage: false });
    console.log('  saved admin-users-light.png');
  }

  await browser.close();
  console.log('\nDone.');
})();
