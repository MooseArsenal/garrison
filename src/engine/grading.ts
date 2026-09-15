import type {
  Action, ActionMatcher, Evidence, ForbiddenAction, GradeResult, RequiredAction, Scenario, Skill, SkillResult, TicketState, World,
} from './types';
import { SKILLS } from './types';

function matchOne(a: Action, m: ActionMatcher): boolean {
  if (a.tool !== m.tool || a.action !== m.action) return false;
  if (m.target !== undefined) {
    const t = a.target ?? '';
    if (m.target instanceof RegExp) { if (!m.target.test(t)) return false; }
    else if (t.toLowerCase() !== m.target.toLowerCase()) return false;
  }
  if (m.params) {
    for (const [k, v] of Object.entries(m.params)) {
      const av = a.params?.[k] ?? '';
      if (v instanceof RegExp) { if (!v.test(av)) return false; }
      else if (av.toLowerCase() !== v.toLowerCase()) return false;
    }
  }
  return true;
}

export function matches(a: Action, m: ActionMatcher | ActionMatcher[]): boolean {
  return Array.isArray(m) ? m.some((x) => matchOne(a, x)) : matchOne(a, m);
}

/** Index of first matching action, or -1. */
function firstIndex(actions: Action[], m: ActionMatcher | ActionMatcher[]): number {
  return actions.findIndex((a) => matches(a, m));
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

const DEFAULT_WEIGHTS: Record<Skill, number> = {
  technical: 25, investigation: 20, security: 15, communication: 10, documentation: 10, process: 15, efficiency: 5,
};

export function grade(s: Scenario, world: World, actions: Action[], ticket: TicketState, elapsedSec: number): GradeResult {
  const results: Record<Skill, SkillResult> = Object.fromEntries(
    SKILLS.map((k) => [k, { skill: k, score: 100, details: [] as SkillResult['details'] }]),
  ) as unknown as Record<Skill, SkillResult>;

  // ---------------- Required actions (technical unless skill overridden) ------
  const reqIndex = new Map<string, number>();
  for (const r of s.required) reqIndex.set(r.id, firstIndex(actions, r.match));
  const missedRequired: RequiredAction[] = [];
  const bySkill = new Map<Skill, { got: number; total: number }>();
  for (const r of s.required) {
    const sk = r.skill ?? 'technical';
    const w = r.weight ?? 1;
    const acc = bySkill.get(sk) ?? { got: 0, total: 0 };
    acc.total += w;
    const idx = reqIndex.get(r.id) ?? -1;
    let ok = idx >= 0;
    let sub: string | undefined;
    if (ok && r.after) {
      const other = reqIndex.get(r.after) ?? -1;
      if (other < 0 || other > idx) { ok = false; sub = `Done, but out of order: it must come AFTER "${s.required.find((x) => x.id === r.after)?.label}".`; }
    }
    if (ok && r.before) {
      const other = reqIndex.get(r.before) ?? -1;
      if (other >= 0 && other < idx) { ok = false; sub = `Done, but out of order: it must come BEFORE "${s.required.find((x) => x.id === r.before)?.label}".`; }
    }
    if (ok) acc.got += w; else missedRequired.push(r);
    bySkill.set(sk, acc);
    results[sk].details.push({ ok, text: r.label, sub });
  }
  for (const [sk, acc] of bySkill) {
    if (acc.total > 0) results[sk].score = clamp((acc.got / acc.total) * 100);
  }
  if (!bySkill.has('technical')) results.technical.score = 100;

  // ---------------- Evidence (investigation) ---------------------------------
  const missedEvidence: Evidence[] = [];
  let evGot = 0; let evTotal = 0;
  for (const e of s.evidence) {
    const w = e.weight ?? 1;
    evTotal += w;
    const ok = firstIndex(actions, e.match) >= 0;
    if (ok) evGot += w; else missedEvidence.push(e);
    results.investigation.details.push({ ok, text: e.label, sub: ok ? undefined : e.hint });
  }
  // Clarifying questions count as investigation evidence.
  if (s.contact) {
    const useful = s.contact.filter((q) => q.purpose === 'clarify');
    for (const q of useful) {
      evTotal += 0.5;
      const ok = ticket.askedQuestions.includes(q.id);
      if (ok) evGot += 0.5;
      results.investigation.details.push({ ok, text: `Asked: "${q.question}"` });
    }
    // Irrelevant questions waste time (efficiency).
    const irrelevant = s.contact.filter((q) => q.purpose === 'irrelevant' && ticket.askedQuestions.includes(q.id));
    for (const q of irrelevant) {
      results.efficiency.details.push({ ok: false, text: `Asked an unhelpful question: "${q.question}"` });
    }
    // Red-flag questions are the social-engineering bait; taking it shows poor security instinct.
    const redFlags = s.contact.filter((q) => q.purpose === 'red_flag' && ticket.askedQuestions.includes(q.id));
    for (const q of redFlags) {
      results.security.score = clamp(results.security.score - 20);
      results.security.details.push({ ok: false, text: `Took the bait: "${q.question}"`, sub: 'This plays into a likely social-engineering or unsafe request. Recognize and refuse these.' });
    }
  }
  if (evTotal > 0) results.investigation.score = clamp((evGot / evTotal) * 100);

  // `verify_gate` is a virtual gate satisfied by asking any identity-verification
  // contact question (they are emitted into the action log as ticket/contact).
  const verifyGateIdx = firstIndex(actions, { tool: 'ticket', action: 'contact', params: { purpose: 'verify' } });

  // ---------------- Forbidden actions ----------------------------------------
  const forbiddenHits: { label: string; why: string }[] = [];
  for (const f of s.forbidden) {
    const idx = firstIndex(actions, f.match);
    if (idx < 0) continue;
    if (f.unlessAfter) {
      const gate = f.unlessAfter === 'verify_gate' ? verifyGateIdx : (reqIndex.get(f.unlessAfter) ?? -1);
      if (gate >= 0 && gate < idx) continue; // done after the gate: allowed
    }
    const sk = f.skill ?? 'security';
    const pen = (f.penalty ?? 0.5) * 100;
    results[sk].score = clamp(results[sk].score - pen);
    results[sk].details.push({ ok: false, text: f.label, sub: f.why });
    forbiddenHits.push({ label: f.label, why: f.why });
  }

  // ---------------- Identity verification (security/process) -----------------
  if (s.contact?.some((q) => q.purpose === 'verify')) {
    const verifyQs = s.contact.filter((q) => q.purpose === 'verify');
    const asked = verifyQs.filter((q) => ticket.askedQuestions.includes(q.id)).length;
    const ok = asked >= Math.min(2, verifyQs.length);
    if (!ok) results.security.score = clamp(results.security.score - 35);
    results.security.details.push({ ok, text: ok ? 'Verified the caller with two factors (KB-0001)' : 'Did not verify the caller with two factors before acting (KB-0001)' });
  }

  // ---------------- Reply choice (communication + others) --------------------
  if (s.replies.length) {
    const r = s.replies.find((x) => x.id === ticket.replyId);
    if (!r) {
      results.communication.score = clamp(results.communication.score - 60);
      results.communication.details.push({ ok: false, text: 'No reply was sent to the requester / stakeholder.' });
    } else {
      for (const [sk, v] of Object.entries(r.scores) as [Skill, number][]) {
        if (sk === 'communication') results.communication.score = clamp(v * 100);
        else results[sk].score = clamp(results[sk].score - (1 - v) * 30);
      }
      if (r.scores.communication === undefined) results.communication.score = clamp(r.best ? 100 : 60);
      results.communication.details.push({ ok: !!r.best || (r.scores.communication ?? 0) >= 0.8, text: `Reply chosen: "${r.text.slice(0, 90)}${r.text.length > 90 ? '…' : ''}"`, sub: r.feedback });
    }
  }

  // ---------------- Documentation --------------------------------------------
  const notes = ticket.notes.trim();
  if (s.notesRubric.length) {
    let got = 0;
    for (const rule of s.notesRubric) {
      const ok = rule.pattern.test(notes);
      if (ok) got++;
      results.documentation.details.push({ ok, text: `Work notes mention: ${rule.label}` });
    }
    let docScore = (got / s.notesRubric.length) * 80;
    if (notes.length >= 120) docScore += 10; else results.documentation.details.push({ ok: false, text: 'Work notes are very short (<120 chars).' });
    const catOk = s.categoryAccept.some((c) => ticket.category.toLowerCase().includes(c.toLowerCase()));
    if (catOk) docScore += 5;
    results.documentation.details.push({ ok: catOk, text: `Category set correctly (${s.closure.category})` });
    const rcOk = (s.resolutionCodeAccept ?? [s.closure.resolutionCode]).some((c) => ticket.resolutionCode.toLowerCase().includes(c.toLowerCase()));
    if (rcOk) docScore += 5;
    results.documentation.details.push({ ok: rcOk, text: `Resolution code set correctly (${s.closure.resolutionCode})` });
    results.documentation.score = clamp(docScore);
  }
  if (s.closure.reportFields?.length) {
    let got = 0;
    for (const rule of s.closure.reportFields) {
      const ok = rule.pattern.test(ticket.report);
      if (ok) got++;
      results.documentation.details.push({ ok, text: `Incident report covers: ${rule.label}` });
    }
    results.documentation.score = clamp((results.documentation.score + (got / s.closure.reportFields.length) * 100) / 2);
  }

  // ---------------- Process: priority, disposition, escalation, classification
  let proc = 100;
  const prOk = ticket.priority === s.priorityExpected;
  if (!prOk) proc -= 20;
  results.process.details.push({ ok: prOk, text: `Priority set to ${s.priorityExpected} (you set ${ticket.priority})` });
  const dispOk = ticket.disposition === s.closure.disposition;
  if (!dispOk) proc -= 40;
  results.process.details.push({ ok: dispOk, text: `Disposition: ${s.closure.disposition}${s.closure.escalateTo ? ' to ' + s.closure.escalateTo : ''} (you chose ${ticket.disposition}${ticket.escalateTo ? ' to ' + ticket.escalateTo : ''})` });
  if (dispOk && s.closure.disposition === 'escalate' && s.closure.escalateTo) {
    const escOk = ticket.escalateTo === s.closure.escalateTo;
    if (!escOk) proc -= 25;
    results.process.details.push({ ok: escOk, text: `Escalated to the right team (${s.closure.escalateTo})` });
  }
  if (s.closure.classification) {
    const ok = ticket.classification === s.closure.classification;
    if (!ok) proc -= 30;
    results.process.details.push({ ok, text: `Classification: ${s.closure.classification.replace(/_/g, ' ')} (you chose ${ticket.classification?.replace(/_/g, ' ') ?? 'nothing'})` });
  }
  if (s.closure.severity) {
    const ok = ticket.severity === s.closure.severity;
    if (!ok) proc -= 15;
    results.process.details.push({ ok, text: `Severity: ${s.closure.severity} (you chose ${ticket.severity ?? 'nothing'})` });
  }
  if (s.closure.notifications?.length) {
    let got = 0;
    for (const n of s.closure.notifications) {
      const ok = ticket.notifications.includes(n);
      if (ok) got++;
      results.process.details.push({ ok, text: `Notified: ${n}` });
    }
    proc -= Math.round((1 - got / s.closure.notifications.length) * 30);
    for (const n of s.closure.notificationsForbidden ?? []) {
      if (ticket.notifications.includes(n)) {
        proc -= 15;
        results.process.details.push({ ok: false, text: `Notified ${n}: premature or wrong audience (KB-0017)` });
      }
    }
  }
  results.process.score = clamp(proc);

  // ---------------- Efficiency ------------------------------------------------
  const budget = s.estMinutes * 60;
  let eff = 100;
  if (elapsedSec > budget * 1.5) eff -= 30; else if (elapsedSec > budget) eff -= 15;
  results.efficiency.details.push({ ok: elapsedSec <= budget, text: `Time: ${Math.round(elapsedSec / 60)} min (target ${s.estMinutes} min)` });
  const relevant = new Set<number>();
  const allMatchers = [...s.evidence.map((e) => e.match), ...s.required.map((r) => r.match)];
  actions.forEach((a, i) => { if (allMatchers.some((m) => matches(a, m))) relevant.add(i); });
  const noise = actions.filter((a, i) => !relevant.has(i) && !['ticket', 'kb'].includes(a.tool)).length;
  const noiseRatio = actions.length ? noise / actions.length : 0;
  if (noiseRatio > 0.75 && actions.length > 12) eff -= 20; else if (noiseRatio > 0.5 && actions.length > 12) eff -= 10;
  results.efficiency.details.push({ ok: noiseRatio <= 0.5 || actions.length <= 12, text: `${actions.length} actions, ${noise} not tied to the case` });
  eff -= Math.min(20, results.efficiency.details.filter((d) => !d.ok && d.text.startsWith('Asked an unhelpful')).length * 5);
  results.efficiency.score = clamp(eff);

  // ---------------- Overall ---------------------------------------------------
  const weights = { ...DEFAULT_WEIGHTS, ...(s.weights ?? {}) };
  let total = 0; let wsum = 0;
  for (const k of SKILLS) { total += results[k].score * weights[k]; wsum += weights[k]; }
  let overall = clamp(total / wsum);
  // hard failure: taking a forbidden security action or wrong disposition caps the score
  if (forbiddenHits.length) overall = Math.min(overall, 69);
  if (!dispOk) overall = Math.min(overall, 74);
  return {
    overall,
    skills: SKILLS.map((k) => results[k]),
    elapsedSec,
    actionCount: actions.length,
    passed: overall >= 70,
    forbiddenHits,
    missedEvidence,
    missedRequired,
  };
}
