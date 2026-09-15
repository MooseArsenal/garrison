// A small but real Search Processing Language (SPL) engine over the world's log
// events, so the SIEM tool behaves like Splunk: an implicit search filter
// followed by piped commands. Supports the subset a SOC analyst actually uses
// day to day. The goal is that queries a trainee writes here would run in real
// Splunk with the same intent.
//
// Supported:
//   <terms> key=value key!=value key>n key<n key=*wild*   (implicit search)
//   | search ...            (same as implicit)
//   | where field=value | where field>n | where field="x"
//   | stats count [by f1,f2] | stats count(field) | stats dc(field) by f
//   | table f1 f2 ...
//   | fields f1 f2
//   | rename a as b
//   | sort [-]field | sort num
//   | head N | tail N
//   | dedup field
//   | top field [limit=N]
//   | eval is not supported (kept out on purpose); use where.

import type { LogEvent } from './types';

export interface SplRow { [k: string]: string | number | undefined; }

export interface SplResult {
  kind: 'events' | 'table';
  columns: string[];        // for table/stats/top
  rows: SplRow[];
  eventCount: number;       // rows after the search stage (before aggregation)
  error?: string;
}

// Map a LogEvent into a flat field bag with Splunk-ish names.
export function eventToRow(e: LogEvent): SplRow {
  const row: SplRow = {
    _time: e.time,
    index: e.source,
    sourcetype: e.source,
    source: e.source,
    host: e.host,
    user: e.user,
    src_ip: e.srcIp,
    dest_ip: e.dstIp,
    dest_port: e.dstPort,
    domain: e.domain,
    url: e.url,
    action: e.action,
    process: e.process,
    _raw: e.message,
    message: e.message,
  };
  if (e.fields) for (const [k, v] of Object.entries(e.fields)) row[k] = v;
  // drop undefined
  for (const k of Object.keys(row)) if (row[k] === undefined) delete row[k];
  return row;
}

const FIELD_ALIASES: Record<string, string> = {
  ip: 'src_ip', srcip: 'src_ip', source_ip: 'src_ip', dst: 'dest_ip', dstip: 'dest_ip',
  destination_ip: 'dest_ip', port: 'dest_port', dstport: 'dest_port', username: 'user',
  account: 'user', computer: 'host', hostname: 'host', dvc: 'host', app: 'app', signature: 'message',
};
function canon(field: string): string {
  const f = field.toLowerCase();
  return FIELD_ALIASES[f] ?? f;
}

function wildToRe(v: string): RegExp {
  const esc = v.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp('^' + esc + '$', 'i');
}

interface Term { neg: boolean; field?: string; op: string; value: string; }

function tokenize(s: string): string[] {
  const out: string[] = [];
  const re = /"[^"]*"|\S+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out.push(m[0]);
  return out;
}

function parseSearchTerms(text: string): Term[] {
  const terms: Term[] = [];
  for (const tokRaw of tokenize(text)) {
    let tok = tokRaw;
    let neg = false;
    if (tok.toUpperCase() === 'AND' || tok.toUpperCase() === 'OR') continue;
    if (tok.startsWith('NOT')) { neg = true; tok = tok.slice(3); if (!tok) continue; }
    const m = tok.match(/^([A-Za-z0-9_]+)\s*(!=|>=|<=|=|>|<)\s*(.*)$/);
    if (m) {
      const value = m[3].replace(/^"|"$/g, '');
      terms.push({ neg, field: canon(m[1]), op: m[2], value });
    } else {
      terms.push({ neg, op: 'term', value: tok.replace(/^"|"$/g, '') });
    }
  }
  return terms;
}

function matchTerm(row: SplRow, t: Term): boolean {
  if (t.op === 'term') {
    const hay = JSON.stringify(row).toLowerCase();
    const hit = t.value.includes('*') ? wildToRe(t.value).test(hay) || hay.includes(t.value.replace(/\*/g, '').toLowerCase()) : hay.includes(t.value.toLowerCase());
    return t.neg ? !hit : hit;
  }
  const raw = row[t.field!];
  const cell = raw === undefined ? '' : String(raw);
  let hit: boolean;
  const numA = Number(cell); const numB = Number(t.value);
  const bothNum = !Number.isNaN(numA) && !Number.isNaN(numB) && cell !== '';
  switch (t.op) {
    case '=': hit = t.value.includes('*') ? wildToRe(t.value).test(cell) : cell.toLowerCase() === t.value.toLowerCase(); break;
    case '!=': hit = !(t.value.includes('*') ? wildToRe(t.value).test(cell) : cell.toLowerCase() === t.value.toLowerCase()); break;
    case '>': hit = bothNum ? numA > numB : cell > t.value; break;
    case '<': hit = bothNum ? numA < numB : cell < t.value; break;
    case '>=': hit = bothNum ? numA >= numB : cell >= t.value; break;
    case '<=': hit = bothNum ? numA <= numB : cell <= t.value; break;
    default: hit = false;
  }
  return t.neg ? !hit : hit;
}

function applySearch(rows: SplRow[], text: string): SplRow[] {
  const terms = parseSearchTerms(text);
  if (!terms.length) return rows;
  return rows.filter((r) => terms.every((t) => matchTerm(r, t)));
}

export function runSpl(events: LogEvent[], query: string): SplResult {
  const q = query.trim();
  let rows = events.map(eventToRow).sort((a, b) => String(b._time).localeCompare(String(a._time)));
  if (!q) return { kind: 'events', columns: [], rows, eventCount: rows.length };

  const stages = q.split('|').map((s) => s.trim());
  // first stage is the implicit search unless it starts with a command
  let firstIsCmd = /^(search|where|stats|table|fields|rename|sort|head|tail|dedup|top|rare)\b/i.test(stages[0]);
  let searchText = firstIsCmd ? '' : stages.shift() ?? '';
  rows = applySearch(rows, searchText);
  const eventCount = rows.length;
  let result: SplResult = { kind: 'events', columns: [], rows, eventCount };

  try {
    for (const stage of stages) {
      const [cmd, ...rest] = stage.split(/\s+/);
      const arg = stage.slice(cmd.length).trim();
      switch (cmd.toLowerCase()) {
        case 'search': result.rows = applySearch(result.rows, arg); result.eventCount = result.rows.length; break;
        case 'where': result.rows = applySearch(result.rows, arg); break;
        case 'head': result.rows = result.rows.slice(0, Number(rest[0] || 10)); break;
        case 'tail': result.rows = result.rows.slice(-Number(rest[0] || 10)); break;
        case 'dedup': { const f = canon(rest[0] || ''); const seen = new Set(); result.rows = result.rows.filter((r) => { const k = String(r[f]); if (seen.has(k)) return false; seen.add(k); return true; }); break; }
        case 'fields': case 'table': {
          const cols = arg.split(/[\s,]+/).map(canon).filter(Boolean);
          result = { kind: 'table', columns: cols, rows: result.rows.map((r) => Object.fromEntries(cols.map((c) => [c, r[c]]))), eventCount: result.eventCount };
          break;
        }
        case 'rename': { const m = arg.match(/(\S+)\s+as\s+(\S+)/i); if (m) { const from = canon(m[1]), to = m[2]; result.rows = result.rows.map((r) => { const { [from]: v, ...rest2 } = r; return { ...rest2, [to]: v }; }); if (result.columns.length) result.columns = result.columns.map((c) => c === from ? to : c); } break; }
        case 'sort': { let f = arg; let desc = false; if (f.startsWith('-')) { desc = true; f = f.slice(1); } f = canon(f.replace(/^num\(|\)$/g, '').trim()); result.rows = [...result.rows].sort((a, b) => { const av = a[f], bv = b[f]; const na = Number(av), nb = Number(bv); const cmp = (!Number.isNaN(na) && !Number.isNaN(nb)) ? na - nb : String(av).localeCompare(String(bv)); return desc ? -cmp : cmp; }); break; }
        case 'stats': result = doStats(result.rows, arg, result.eventCount); break;
        case 'top': case 'rare': result = doTop(result.rows, arg, cmd.toLowerCase() === 'rare', result.eventCount); break;
        default: return { ...result, error: `Unknown command: ${cmd}` };
      }
    }
  } catch (e) {
    return { ...result, error: 'Query error: ' + (e as Error).message };
  }
  return result;
}

function doStats(rows: SplRow[], arg: string, eventCount: number): SplResult {
  // supports: count | count(field) | dc(field) | values(field)  [by f1,f2]
  const byMatch = arg.match(/\bby\b\s+(.+)$/i);
  const byFields = byMatch ? byMatch[1].split(/[\s,]+/).map(canon).filter(Boolean) : [];
  const aggPart = (byMatch ? arg.slice(0, byMatch.index) : arg).trim();
  const aggs = aggPart.split(/[\s,]+(?![^()]*\))/).filter(Boolean);
  const groups = new Map<string, { key: SplRow; items: SplRow[] }>();
  for (const r of rows) {
    const key = byFields.map((f) => String(r[f] ?? '')).join('');
    if (!groups.has(key)) groups.set(key, { key: Object.fromEntries(byFields.map((f) => [f, r[f]])), items: [] });
    groups.get(key)!.items.push(r);
  }
  const columns = [...byFields];
  const outRows: SplRow[] = [];
  for (const g of groups.values()) {
    const row: SplRow = { ...g.key };
    for (const a of (aggs.length ? aggs : ['count'])) {
      const m = a.match(/^(\w+)\(([^)]*)\)$/);
      if (a.toLowerCase() === 'count') { row['count'] = g.items.length; if (!columns.includes('count')) columns.push('count'); }
      else if (m) {
        const fn = m[1].toLowerCase(); const f = canon(m[2]); const colName = `${fn}(${m[2]})`;
        if (fn === 'count') row[colName] = g.items.filter((x) => x[f] !== undefined).length;
        else if (fn === 'dc') row[colName] = new Set(g.items.map((x) => x[f])).size;
        else if (fn === 'values') row[colName] = [...new Set(g.items.map((x) => String(x[f] ?? '')))].filter(Boolean).join(', ');
        else if (fn === 'sum') row[colName] = g.items.reduce((s, x) => s + (Number(x[f]) || 0), 0);
        else row[colName] = g.items.length;
        if (!columns.includes(colName)) columns.push(colName);
      }
    }
    outRows.push(row);
  }
  outRows.sort((a, b) => Number(b['count'] ?? 0) - Number(a['count'] ?? 0));
  return { kind: 'table', columns, rows: outRows, eventCount };
}

function doTop(rows: SplRow[], arg: string, rare: boolean, eventCount: number): SplResult {
  const limMatch = arg.match(/limit=(\d+)/i);
  const limit = limMatch ? Number(limMatch[1]) : 10;
  const field = canon(arg.replace(/limit=\d+/i, '').trim().split(/[\s,]+/)[0]);
  const counts = new Map<string, number>();
  for (const r of rows) { const k = String(r[field] ?? ''); counts.set(k, (counts.get(k) ?? 0) + 1); }
  let entries = [...counts.entries()].map(([k, c]) => ({ [field]: k, count: c, percent: rows.length ? Math.round((c / rows.length) * 1000) / 10 : 0 } as SplRow));
  entries.sort((a, b) => (rare ? 1 : -1) * (Number(b.count) - Number(a.count)));
  return { kind: 'table', columns: [field, 'count', 'percent'], rows: entries.slice(0, limit), eventCount };
}

// Example queries shown to the trainee.
export const SPL_EXAMPLES: string[] = [
  'index=auth user=sturner',
  'index=firewall dest_ip=45.146.164.90',
  'index=proxy | stats count by domain',
  '"powershell" OR "cmd.exe" | table _time host user message',
  'index=cloud action=signin | top user',
  'src_ip=185.220.101.47 | stats count by index',
];
