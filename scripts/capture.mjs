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

// 7) REPORT CARD — seed a sample training history, then capture the report
await page.goto(BASE, { waitUntil: 'networkidle2' });
await page.evaluate(() => {
  const s = (t, i, se, c, d, pr, e) => ({ technical: t, investigation: i, security: se, communication: c, documentation: d, process: pr, efficiency: e });
  const now = Date.now(); const iso = (da) => new Date(now - da * 86400000).toISOString();
  const scen = {
    'sd1-01': { scenarioId: 'sd1-01', best: 96, attempts: 2, passed: true, lastPlayed: iso(6) },
    'sd1-02': { scenarioId: 'sd1-02', best: 88, attempts: 1, passed: true, lastPlayed: iso(6) },
    'sd1-04': { scenarioId: 'sd1-04', best: 79, attempts: 2, passed: true, lastPlayed: iso(5) },
    'sd1-06': { scenarioId: 'sd1-06', best: 91, attempts: 1, passed: true, lastPlayed: iso(5) },
    'sd1-12': { scenarioId: 'sd1-12', best: 84, attempts: 1, passed: true, lastPlayed: iso(4) },
    'sd2-01': { scenarioId: 'sd2-01', best: 90, attempts: 1, passed: true, lastPlayed: iso(3) },
    'sd2-04': { scenarioId: 'sd2-04', best: 72, attempts: 3, passed: true, lastPlayed: iso(3) },
    'soc1-01': { scenarioId: 'soc1-01', best: 91, attempts: 1, passed: true, lastPlayed: iso(2) },
    'soc1-04': { scenarioId: 'soc1-04', best: 68, attempts: 2, passed: false, lastPlayed: iso(1) },
    'soc2-02': { scenarioId: 'soc2-02', best: 74, attempts: 1, passed: true, lastPlayed: iso(1) },
  };
  const history = [
    { scenarioId: 'sd1-01', score: 82, at: iso(6), skills: s(90, 70, 80, 80, 80, 90, 80) },
    { scenarioId: 'sd1-01', score: 96, at: iso(6), skills: s(100, 80, 100, 100, 100, 100, 100) },
    { scenarioId: 'sd1-02', score: 88, at: iso(6), skills: s(90, 85, 90, 90, 80, 90, 90) },
    { scenarioId: 'sd1-04', score: 71, at: iso(5), skills: s(80, 60, 70, 75, 70, 70, 80) },
    { scenarioId: 'sd1-04', score: 79, at: iso(5), skills: s(85, 70, 75, 80, 80, 80, 80) },
    { scenarioId: 'sd1-06', score: 91, at: iso(5), skills: s(95, 80, 90, 90, 90, 95, 90) },
    { scenarioId: 'sd1-12', score: 84, at: iso(4), skills: s(80, 75, 95, 85, 80, 90, 80) },
    { scenarioId: 'sd2-01', score: 90, at: iso(3), skills: s(95, 85, 85, 90, 90, 90, 90) },
    { scenarioId: 'sd2-04', score: 72, at: iso(3), skills: s(78, 65, 72, 75, 70, 72, 78) },
    { scenarioId: 'soc1-01', score: 91, at: iso(2), skills: s(90, 88, 92, 90, 92, 92, 90) },
    { scenarioId: 'soc1-04', score: 68, at: iso(1), skills: s(75, 60, 65, 70, 66, 68, 72) },
    { scenarioId: 'soc2-02', score: 74, at: iso(1), skills: s(80, 68, 72, 75, 70, 74, 78) },
  ];
  localStorage.setItem('garrison.progress.v1', JSON.stringify({ scenarios: scen, history }));
  localStorage.setItem('garrison.settings.v1', JSON.stringify({ unlockAll: true, hintsEnabled: true, playerName: 'Shamus Johnson' }));
});
await page.goto(`${BASE}#report`, { waitUntil: 'networkidle2' });
await sleep(800);
await page.screenshot({ path: `${OUT}/report.png`, fullPage: true });
console.log('captured report');

await browser.close();
console.log('done');
