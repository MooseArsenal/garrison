// Capture README screenshots by driving the built app in headless Chrome.
// Usage: serve the app on :5183 (npx vite preview --port 5183), then
//   node scripts/capture.mjs
import puppeteer from 'puppeteer-core';
import { setTimeout as sleep } from 'node:timers/promises';

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const BASE = 'http://localhost:5183';
const OUT = 'docs/screenshots';

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: 'new',
  args: ['--no-sandbox', '--hide-scrollbars', '--force-color-profile=srgb'],
});
const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 2 });

async function shot(name, opts = {}) { await sleep(500); await page.screenshot({ path: `${OUT}/${name}.png`, ...opts }); console.log('captured', name); }
async function tool(label) {
  await page.evaluate((l) => { const b = [...document.querySelectorAll('.rail button')].find((x) => x.querySelector('.lbl')?.textContent === l); b?.click(); }, label);
  await sleep(400);
}
async function clickText(sel, text) {
  await page.evaluate((s, t) => { const el = [...document.querySelectorAll(s)].find((x) => x.textContent?.includes(t)); el?.click(); }, sel, text);
  await sleep(400);
}
function setInput(selector, value) {
  return page.evaluate((sel, val) => {
    const el = document.querySelector(sel); if (!el) return;
    const proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, val);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }, selector, value);
}
// deep-link straight into a scenario's briefing, then Start the clock
async function openScenario(id) {
  await page.goto(`${BASE}#play=${id}`, { waitUntil: 'networkidle2' });
  await sleep(400);
  await clickText('button', 'Start the clock');
  await sleep(500);
}

// 1) HOME — the shift queue as a new analyst sees it (Service Desk I, SOC/CIRT
// locked). Deep-links below still open any scenario for the tool screenshots.
await page.goto(BASE, { waitUntil: 'networkidle2' });
await sleep(700);
await shot('home');

// 2) BRIEFING — a ticket arrives
await page.goto(`${BASE}#play=sd1-01`, { waitUntil: 'networkidle2' });
await sleep(600);
await shot('briefing');

// 3) DIRECTORY (Okta/AD) — sign-in System Log
await openScenario('sd1-01');
await tool('Okta / AD');
await setInput('.searchbar input', 'jmorales');
await sleep(400);
await clickText('.list-item .t', 'Jenna Morales');
await sleep(300);
await clickText('.tabs button', 'System Log');
await sleep(400);
await shot('directory');

// 3b) DOCUMENTATION — guided work-notes fields (right panel)
await fillDoc([
  'AP user locked out before payroll; verified, unlocked and reset — root cause was a saved password on her phone.',
  'Employee ID E10105 + callback to the number on record.',
  'Old password cached in the iPhone mail app kept locking the account.',
  'Unlocked account; reset password (must change); had her update the saved password on her phone.',
]);
await page.evaluate(() => { const el = document.querySelector('.work'); if (el) el.scrollTop = 0; });
await sleep(200);
await page.screenshot({ path: `${OUT}/documentation.png`, clip: { x: 1440 - 380, y: 52, width: 380, height: 848 } });
console.log('captured documentation');
async function fillDoc(vals) {
  await page.evaluate((vals) => {
    const set = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
    const tas = [...document.querySelectorAll('.docfield textarea')];
    vals.forEach((v, i) => { if (tas[i]) { set.call(tas[i], v); tas[i].dispatchEvent(new Event('input', { bubbles: true })); } });
  }, vals);
  await sleep(300);
}

// 4) SPLUNK — SPL search with stats
await openScenario('soc1-04');
await tool('Splunk');
await setInput('.spl-input', 'index=proxy | stats count by domain | sort -count');
await page.evaluate(() => { const b = [...document.querySelectorAll('.spl-bar button')].find((x) => x.textContent.includes('Search')); b?.click(); });
await sleep(600);
await shot('splunk');

// 5) FALCON — process tree
await tool('CrowdStrike Falcon');
await sleep(400);
await page.evaluate(() => { const r = document.querySelector('table.data tbody tr'); r?.click(); });
await sleep(700);
await shot('falcon');

await browser.close();
console.log('done');
