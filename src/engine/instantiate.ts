// Per-attempt scenario instantiation with optional token randomization.
// A scenario opts in with `tokens`: each token's literal (e.g. a C2 IP) is
// replaced by a freshly generated value everywhere it appears — the seeded
// world, the intake text, the grading matchers, replies, hints and rubric — so
// the correct decision is unchanged but memorizable indicators rotate.

import type {
  ActionMatcher, Closure, ContactQuestion, Evidence, ForbiddenAction, NoteRule,
  ReplyChoice, RequiredAction, Scenario, TicketIntake, IncidentIntake, World,
} from './types';
import { buildWorld, cloneWorld } from './world';

const BASE = buildWorld();

// ---- seeded RNG + value generators -------------------------------------
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const pick = <T,>(r: () => number, arr: T[]): T => arr[Math.floor(r() * arr.length)];
const int = (r: () => number, lo: number, hi: number): number => lo + Math.floor(r() * (hi - lo + 1));

// Realistic malicious-looking source octets (avoid internal 10./192.168./198.51.100 test ranges).
const BAD_PREFIXES = ['45.146.164', '185.220.101', '141.98.11', '193.32.162', '92.63.197', '5.188.206', '77.83.36', '194.26.135', '171.25.193', '89.248.165'];
export function randIp(r: () => number): string { return `${pick(r, BAD_PREFIXES)}.${int(r, 3, 250)}`; }
export function randHash(r: () => number): string {
  const hex = '0123456789abcdef'; let s = ''; for (let i = 0; i < 12; i++) s += hex[Math.floor(r() * 16)]; return s;
}
const D_WORDS = ['secure', 'verify', 'account', 'update', 'login', 'cloud', 'portal', 'mail', 'docs', 'cdn', 'app', 'auth', 'files', 'drive', 'support'];
const D_TLDS = ['top', 'xyz', 'app', 'live', 'online', 'site', 'click', 'shop', 'cc', 'info'];
export function randDomain(r: () => number): string { return `${pick(r, D_WORDS)}-${pick(r, D_WORDS)}.${pick(r, D_TLDS)}`; }
export function randExe(r: () => number): string { return `${pick(r, ['svc', 'sys', 'net', 'win', 'host', 'update', 'run', 'task'])}${pick(r, ['host', 'mgr', 'svc', 'upd', 'agent', 'proc'])}.exe`; }

// ---- string / regex substitution ---------------------------------------
function escapeRegex(s: string): string { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

interface Sub { from: string; to: string; }

function plainReplacer(map: Sub[]): (s: string) => string {
  if (!map.length) return (s) => s;
  const sorted = [...map].sort((a, b) => b.from.length - a.from.length);
  const dict = Object.fromEntries(sorted.map((m) => [m.from, m.to]));
  const re = new RegExp(sorted.map((m) => escapeRegex(m.from)).join('|'), 'g');
  return (s) => s.replace(re, (x) => dict[x] ?? x);
}
function regexSourceReplacer(map: Sub[]): (src: string) => string {
  if (!map.length) return (s) => s;
  // In a regex source, our literals appear regex-escaped (e.g. "45\.146\.164\.90").
  const sorted = [...map].sort((a, b) => b.from.length - a.from.length);
  const dict = Object.fromEntries(sorted.map((m) => [escapeRegex(m.from), escapeRegex(m.to)]));
  const outer = new RegExp(sorted.map((m) => escapeRegex(escapeRegex(m.from))).join('|'), 'g');
  return (src) => src.replace(outer, (x) => dict[x] ?? x);
}

function transformMatcher(m: ActionMatcher, ps: (s: string) => string, rs: (s: string) => string): ActionMatcher {
  const t = (v: string | RegExp | undefined): string | RegExp | undefined =>
    v === undefined ? undefined : v instanceof RegExp ? new RegExp(rs(v.source), v.flags) : ps(v);
  return {
    tool: m.tool, action: m.action,
    target: t(m.target),
    params: m.params ? Object.fromEntries(Object.entries(m.params).map(([k, v]) => [k, t(v) as string | RegExp])) : undefined,
  };
}
function transformMatch(m: ActionMatcher | ActionMatcher[], ps: (s: string) => string, rs: (s: string) => string): ActionMatcher | ActionMatcher[] {
  return Array.isArray(m) ? m.map((x) => transformMatcher(x, ps, rs)) : transformMatcher(m, ps, rs);
}

// ---- world (data only) round-trip replace ------------------------------
function transformWorld(world: World, map: Sub[]): World {
  if (!map.length) return world;
  const ps = plainReplacer(map);
  return JSON.parse(ps(JSON.stringify(world))) as World;
}

// ---- scenario transform ------------------------------------------------
function transformScenario(base: Scenario, map: Sub[]): Scenario {
  const ps = plainReplacer(map);
  const rs = regexSourceReplacer(map);
  const ev = (e: Evidence): Evidence => ({ ...e, label: ps(e.label), hint: e.hint ? ps(e.hint) : undefined, match: transformMatch(e.match, ps, rs) });
  const rq = (r: RequiredAction): RequiredAction => ({ ...r, label: ps(r.label), match: transformMatch(r.match, ps, rs) });
  const fb = (f: ForbiddenAction): ForbiddenAction => ({ ...f, label: ps(f.label), why: ps(f.why), match: transformMatch(f.match, ps, rs) });
  const rep = (r: ReplyChoice): ReplyChoice => ({ ...r, text: ps(r.text), feedback: ps(r.feedback) });
  const cq = (c: ContactQuestion): ContactQuestion => ({ ...c, question: ps(c.question), answer: ps(c.answer) });
  const nr = (n: NoteRule): NoteRule => ({ label: ps(n.label), pattern: new RegExp(rs(n.pattern.source), n.pattern.flags) });
  const closure: Closure = { ...base.closure, reportFields: base.closure.reportFields?.map(nr) };

  let intake = base.intake;
  if (intake.kind === 'ticket') intake = { ...intake, subject: ps(intake.subject), body: ps(intake.body) } as TicketIntake;
  else if (intake.kind === 'incident') intake = { ...intake, title: ps(intake.title), summary: ps(intake.summary) } as IncidentIntake;

  return {
    ...base,
    intake,
    objective: ps(base.objective),
    evidence: base.evidence.map(ev),
    required: base.required.map(rq),
    forbidden: base.forbidden.map(fb),
    replies: base.replies.map(rep),
    contact: base.contact?.map(cq),
    notesRubric: base.notesRubric.map(nr),
    closure,
    hints: base.hints.map(ps),
    debrief: ps(base.debrief),
    categoryAccept: base.categoryAccept, // categories aren't tokenized
  };
}

/** Build a fresh world + (possibly randomized) scenario for one attempt. */
export function instantiate(base: Scenario, seed?: number): { scenario: Scenario; world: World } {
  const world = cloneWorld(BASE);
  base.setup(world);
  const toks = base.tokens ?? [];
  if (!toks.length) return { scenario: base, world };
  const rand = mulberry32(seed ?? ((Math.random() * 2 ** 32) >>> 0));
  const seen = new Set<string>();
  const map: Sub[] = [];
  for (const t of toks) {
    let to = t.gen(rand); let tries = 0;
    while ((to === t.from || seen.has(to)) && tries++ < 8) to = t.gen(rand);
    seen.add(to);
    map.push({ from: t.from, to });
  }
  return { scenario: transformScenario(base, map), world: transformWorld(world, map) };
}
