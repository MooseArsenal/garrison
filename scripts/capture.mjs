// Capture README screenshots by driving the built app in headless Chrome.
// Usage: node scripts/capture.mjs   (serve the app on :5183 first)
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

async function shot(name, opts = {}) {
  await sleep(500);
  await page.screenshot({ path: `${OUT}/${name}.png`, ...opts });
  console.log('captured', name);
}
// click a rail tool by its tooltip label
async function tool(label) {
  await page.evaluate((l) => {
    const b = [...document.querySelectorAll('.rail button')].find((x) => x.querySelector('.lbl')?.textContent === l);
    b?.click();
  }, label);
  await sleep(400);
}
async function clickText(sel, text) {
  await page.evaluate((s, t) => {
    const el = [...document.querySelectorAll(s)].find((x) => x.textContent?.includes(t));
    el?.click();
  }, sel, text);
  await sleep(400);
}
function setInput(selector, value) {
  return page.evaluate((sel, val) => {
    const el = document.querySelector(sel);
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(el, val); el.dispatchEvent(new Event('input', { bubbles: true }));
  }, selector, value);
}

// ---- unlock all tiers so every screen is reachable ----
await page.goto(BASE, { waitUntil: 'networkidle2' });
await page.evaluate(() => localStorage.setItem('garrison.settings.v1', JSON.stringify({ unlockAll: true, hintsEnabled: true, playerName: 'Analyst' })));

// 1) HOME — the tier ladder
await page.goto(BASE, { waitUntil: 'networkidle2' });
await sleep(700);
await shot('home');

// 2) BRIEFING — open the SD1 lockout scenario
await clickText('.scen-card .title', 'Locked out before a deadline');
await sleep(500);
await shot('briefing');

// 3) DIRECTORY (Okta/AD) — start, open directory, show a user's System Log
await clickText('button', 'Start the clock');
await sleep(500);
await tool('Okta / AD');
await setInput('.searchbar input', 'jmorales');
await sleep(400);
await clickText('.list-item .t', 'Jenna Morales');
await sleep(300);
await clickText('.tabs button', 'System Log');
await sleep(400);
await shot('directory');

// 4) SPLUNK — go to a SOC scenario with rich logs
await page.goto(BASE, { waitUntil: 'networkidle2' });
await sleep(500);
await clickText('.scen-card .title', 'malicious document spawned PowerShell');
await sleep(400);
await clickText('button', 'Start the clock');
await sleep(500);
await tool('Splunk');
await setInput('.spl-input', 'index=proxy | stats count by domain | sort -count');
await page.evaluate(() => { const b = [...document.querySelectorAll('.spl-bar button')].find((x) => x.textContent.includes('Search')); b.click(); });
await sleep(600);
await shot('splunk');

// 5) FALCON — process tree on the alerting host
await tool('CrowdStrike Falcon');
await sleep(400);
await page.evaluate(() => { const r = document.querySelector('table.data tbody tr'); r?.click(); });
await sleep(700);
await shot('falcon');

await browser.close();
console.log('done');
