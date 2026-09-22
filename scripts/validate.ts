/* Scenario validator. For each scenario it:
 *   1. runs static structural checks,
 *   2. synthesizes the "ideal analyst" action log + closure from the scenario's
 *      own matchers and grades it — this must PASS with a high score,
 *   3. grades an empty run — this must NOT pass.
 * If a scenario can't be completed via its declared actions, or grades wrong,
 * it fails here instead of teaching the trainee something false.
 *
 * Run: npx tsx scripts/validate.ts
 */
import type { Action, ActionMatcher, Scenario, Skill, TicketState } from '../src/engine/types';
import { SKILLS } from '../src/engine/types';
import { buildWorld, cloneWorld } from '../src/engine/world';
import { grade } from '../src/engine/grading';
import { initialTicket } from '../src/engine/session';
import { ALL_SCENARIOS } from '../src/scenarios';
import { LEARNING_PATHS } from '../src/engine/paths';

const BASE = buildWorld();

// ---- turn a RegExp (our simple patterns) into a string that matches it ----
function splitTopAlt(src: string): string[] {
  const parts: string[] = []; let depth = 0; let cur = '';
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') { cur += c + (src[i + 1] ?? ''); i++; continue; }
    if (c === '[' || c === '(') depth++;
    if (c === ']' || c === ')') depth--;
    if (c === '|' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += c;
  }
  parts.push(cur);
  return parts;
}
function sampleFromSource(src0: string): string {
  const src = src0.replace(/^\^/, '').replace(/\$$/, '');
  return walk(splitTopAlt(src)[0]);
}
function walk(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\') {
      const n = s[i + 1]; i++;
      out += n === 'd' ? '5' : n === 'w' ? 'x' : n === 's' ? ' ' : (n ?? '');
      if ('*+?'.includes(s[i + 1])) i++;
      continue;
    }
    if (c === '(') {
      let depth = 1; let j = i + 1;
      for (; j < s.length && depth; j++) { if (s[j] === '\\') { j++; continue; } if (s[j] === '(') depth++; else if (s[j] === ')') depth--; }
      const inner = s.slice(i + 1, j - 1).replace(/^\?:/, '').replace(/^\?[=!]/, '');
      i = j - 1; // now at ')'
      if ('*+?'.includes(s[i + 1])) i++;
      out += walk(splitTopAlt(inner)[0]);
      continue;
    }
    if (c === ')') continue;
    if (c === '[') {
      const end = s.indexOf(']', i);
      let cls = s.slice(i + 1, end).replace('^', '');
      let ch = cls[0] === '\\' ? cls[1] : cls[0];
      out += ch === 'd' ? '5' : ch === 'w' ? 'x' : (ch ?? 'a');
      i = end;
      if ('*+?'.includes(s[i + 1])) i++;
      continue;
    }
    if (c === '.') { out += 'x'; if ('*+?'.includes(s[i + 1])) i++; continue; }
    if ('*+?'.includes(c)) continue;
    out += c;
  }
  return out;
}
function matchTarget(m: ActionMatcher): string | undefined {
  if (m.target === undefined) return undefined;
  return m.target instanceof RegExp ? sampleFromSource(m.target.source) : m.target;
}
function matchParams(m: ActionMatcher): Record<string, string> | undefined {
  if (!m.params) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(m.params)) out[k] = v instanceof RegExp ? sampleFromSource(v.source) : v;
  return out;
}
function firstMatcher(m: ActionMatcher | ActionMatcher[]): ActionMatcher {
  return Array.isArray(m) ? m[0] : m;
}
function toAction(m: ActionMatcher | ActionMatcher[]): Action {
  const mm = firstMatcher(m);
  return { t: 0, tool: mm.tool, action: mm.action, target: matchTarget(mm), params: matchParams(mm), label: 'sim' };
}

// A notes string that satisfies every rubric regex (concatenate a sample per rule).
function notesFor(s: Scenario): string {
  const parts = s.notesRubric.map((r) => sampleFromSource(r.pattern.source));
  let notes = 'Investigation summary. ' + parts.join('. ') + '.';
  while (notes.length < 130) notes += ' Additional detail for documentation completeness.';
  return notes;
}
function reportFor(s: Scenario): string {
  if (!s.closure.reportFields?.length) return '';
  const parts = s.closure.reportFields.map((r) => sampleFromSource(r.pattern.source));
  let rep = 'Incident report. ' + parts.join('. ') + '.';
  while (rep.length < 130) rep += ' Follow-up owner assigned.';
  return rep;
}

function orderedRequired(s: Scenario): typeof s.required {
  // topological-ish: place 'after' deps earlier, 'before' later
  const items = [...s.required];
  items.sort((a, b) => {
    if (a.before === b.id || b.after === a.id) return -1;
    if (b.before === a.id || a.after === b.id) return 1;
    return 0;
  });
  return items;
}

function perfectRun(s: Scenario): { actions: Action[]; ticket: TicketState } {
  const actions: Action[] = [];
  // contact: ask verify + clarify + red-flag-avoided (skip irrelevant & red_flag)
  const askedQuestions: string[] = [];
  for (const q of s.contact ?? []) {
    if (q.purpose === 'irrelevant' || q.purpose === 'red_flag') continue;
    askedQuestions.push(q.id);
    actions.push({ t: 0, tool: 'ticket', action: 'contact', target: q.id, params: { purpose: q.purpose ?? 'clarify' }, label: 'sim' });
  }
  // evidence
  for (const e of s.evidence) actions.push(toAction(e.match));
  // required, ordered
  for (const r of orderedRequired(s)) actions.push(toAction(r.match));
  // reply = best
  const best = s.replies.find((r) => r.best) ?? s.replies[0];
  if (best) actions.push({ t: 0, tool: 'ticket', action: 'reply', target: best.id, label: 'sim' });

  const ticket: TicketState = {
    ...initialTicket(s),
    priority: s.priorityExpected,
    notes: notesFor(s),
    replyId: best?.id,
    disposition: s.closure.disposition,
    escalateTo: s.closure.escalateTo,
    category: s.closure.category,
    resolutionCode: s.closure.resolutionCode,
    classification: s.closure.classification,
    severity: s.closure.severity,
    notifications: [...(s.closure.notifications ?? [])],
    report: reportFor(s),
    verified: true,
    askedQuestions,
  };
  return { actions, ticket };
}

// -------------------- run --------------------
let failures = 0;
const seen = new Set<string>();
const kbIds = new Set(BASE.kb.map((k) => k.id));

for (const s of ALL_SCENARIOS) {
  const problems: string[] = [];

  if (seen.has(s.id)) problems.push('duplicate id');
  seen.add(s.id);

  // structural
  const bests = s.replies.filter((r) => r.best);
  if (s.replies.length && bests.length !== 1) problems.push(`expected exactly 1 best reply, got ${bests.length}`);
  if (!s.notesRubric.length) problems.push('empty notesRubric');
  if (!s.categoryAccept.length) problems.push('empty categoryAccept');
  if (!s.hints.length) problems.push('no hints');
  if (!s.debrief) problems.push('no debrief');
  if (!s.evidence.length) problems.push('no evidence items');
  if (!s.required.length) problems.push('no required actions');
  // category self-consistency
  if (!s.categoryAccept.some((c) => s.closure.category.toLowerCase().includes(c.toLowerCase())))
    problems.push(`closure.category "${s.closure.category}" matches none of categoryAccept`);
  const rcAccept = s.resolutionCodeAccept ?? [s.closure.resolutionCode];
  if (!rcAccept.some((c) => s.closure.resolutionCode.toLowerCase().includes(c.toLowerCase())))
    problems.push('closure.resolutionCode matches none of resolutionCodeAccept');
  // KB references exist
  for (const e of s.evidence) for (const m of (Array.isArray(e.match) ? e.match : [e.match])) {
    if (m.tool === 'kb' && m.action === 'read' && typeof m.target === 'string' && !kbIds.has(m.target))
      problems.push(`evidence references missing KB ${m.target}`);
  }
  // reply score skills valid
  for (const r of s.replies) for (const k of Object.keys(r.scores)) if (!SKILLS.includes(k as Skill)) problems.push(`reply ${r.id} bad skill ${k}`);

  // setup runs
  let world;
  try { world = cloneWorld(BASE); s.setup(world); } catch (e) { problems.push('setup threw: ' + (e as Error).message); world = cloneWorld(BASE); }

  // intake refs
  if (s.intake.kind === 'ticket') {
    if (!world.users.find((u) => u.id === s.intake.requester)) problems.push(`intake.requester ${s.intake.requester} not found`);
    if (s.intake.affectedHost && !world.hosts.find((h) => h.id === s.intake.affectedHost)) problems.push(`affectedHost ${s.intake.affectedHost} not found`);
  }
  if (s.intake.kind === 'alert' && !world.alerts.find((a) => a.id === s.intake.alertId)) problems.push(`alert ${s.intake.alertId} not created in setup`);

  // perfect-run grade
  try {
    const { actions, ticket } = perfectRun(s);
    const g = grade(s, world, actions, ticket, Math.max(1, s.estMinutes * 30));
    if (!g.passed) problems.push(`PERFECT RUN FAILS (overall ${g.overall})`);
    else if (g.overall < 85) problems.push(`perfect run low score ${g.overall}`);
    // report which skills dragged it down when failing
    if (g.overall < 85) {
      const low = g.skills.filter((x) => x.score < 80).map((x) => `${x.skill}:${x.score}`);
      if (low.length) problems.push('  low skills: ' + low.join(', '));
      for (const x of g.skills) for (const d of x.details) if (!d.ok) problems.push(`   ✕ [${x.skill}] ${d.text}${d.sub ? ' — ' + d.sub : ''}`);
    }
  } catch (e) { problems.push('grade() threw on perfect run: ' + (e as Error).message + '\n' + (e as Error).stack); }

  // empty run should not pass
  try {
    const emptyTicket = initialTicket(s);
    const g0 = grade(s, cloneWorld(world), [], emptyTicket, 999999);
    if (g0.passed) problems.push(`EMPTY RUN PASSES (overall ${g0.overall}) — scenario is too easy / mis-wired`);
  } catch { /* ignore */ }

  if (problems.length) {
    failures++;
    console.log(`\n✗ ${s.id} (${s.tier}) — ${s.title}`);
    for (const p of problems) console.log('   ' + p);
  }
}

// ---- learning-path references ----
let pathProblems = 0;
for (const p of LEARNING_PATHS) {
  p.steps.forEach((step, i) => {
    if (step.kind === 'lesson') {
      if (!step.kb || !kbIds.has(step.kb)) { console.log(`\n✗ path ${p.id}#${i}: missing KB ${step.kb}`); pathProblems++; }
    } else if (!step.scenarioId || !ALL_SCENARIOS.some((s) => s.id === step.scenarioId)) {
      console.log(`\n✗ path ${p.id}#${i}: missing scenario ${step.scenarioId}`); pathProblems++;
    }
  });
}

console.log(`\n${'='.repeat(60)}`);
console.log(`${ALL_SCENARIOS.length} scenarios checked, ${failures} with problems.`);
console.log(`${LEARNING_PATHS.length} learning paths checked, ${pathProblems} bad references.`);
process.exit(failures || pathProblems ? 1 : 0);
