import React, { useMemo, useState } from 'react';
import { TIER_LABELS, TIER_ORDER, type Tier } from '../engine/types';
import { SCENARIOS_BY_TIER, getScenario } from '../scenarios';
import { LEARNING_PATHS, getPath } from '../engine/paths';
import { type Assignment, type Receipt, assignmentLink, decodeReceipt } from '../engine/assignments';
import { Tabs, useToast, scoreColor } from './common';

export function Teacher({ onExit }: { onExit: () => void }) {
  const [tab, setTab] = useState<'build' | 'gradebook'>('build');
  return (
    <div className="home">
      <div className="brandbar">
        <div className="brand"><div className="logo">🎓</div><div><h1>Teacher console</h1><div className="sub">Build an assignment link · grade returned receipts</div></div></div>
        <button className="btn ghost sm" onClick={onExit}>← Menu</button>
      </div>
      <Tabs tabs={[{ id: 'build', label: 'Build assignment' }, { id: 'gradebook', label: 'Gradebook' }]} active={tab} onChange={setTab} />
      {tab === 'build' ? <Builder /> : <Gradebook />}
    </div>
  );
}

function Builder() {
  const toast = useToast();
  const [title, setTitle] = useState('');
  const [from, setFrom] = useState('');
  const [note, setNote] = useState('');
  const [pass, setPass] = useState(70);
  const [pathId, setPathId] = useState('');
  const [picked, setPicked] = useState<string[]>([]);
  const [tier, setTier] = useState<Tier>('sd1');
  const [link, setLink] = useState('');

  function usePath(id: string) {
    setPathId(id);
    const p = getPath(id);
    if (p) {
      const cases = p.steps.filter((s) => s.kind === 'case' && s.scenarioId).map((s) => s.scenarioId!) as string[];
      setPicked(cases);
      if (!title) setTitle(p.title);
    }
  }
  function toggle(id: string) {
    setPicked((cur) => cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]);
    setPathId('');
  }
  function build() {
    if (!title.trim() || picked.length === 0) { toast('Add a title and at least one case', 'bad'); return; }
    const a: Assignment = { v: 1, title: title.trim(), from: from.trim(), note: note.trim() || undefined, pass, items: picked, pathId: pathId || undefined, created: new Date().toISOString() };
    const url = assignmentLink(a);
    setLink(url);
    navigator.clipboard?.writeText(url).then(() => toast('Assignment link copied', 'good'), () => toast('Link ready below — copy it', 'info'));
  }

  return (
    <div className="two-col" style={{ gridTemplateColumns: '1fr 1fr', alignItems: 'start' }}>
      <div>
        <div className="card">
          <h4>Assignment details</h4>
          <label className="field">Title</label>
          <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Week 3 — SOC triage" style={{ width: '100%' }} />
          <label className="field">Your name (instructor)</label>
          <input value={from} onChange={(e) => setFrom(e.target.value)} placeholder="e.g. Prof. Vance" style={{ width: '100%' }} />
          <label className="field">Instructions / due date</label>
          <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} placeholder="Work each case to at least the pass mark. Due Friday." style={{ width: '100%' }} />
          <label className="field">Pass mark</label>
          <input type="number" min={0} max={100} value={pass} onChange={(e) => setPass(Math.max(0, Math.min(100, Number(e.target.value))))} style={{ width: 100 }} />
        </div>

        <div className="card">
          <h4>Start from a learning path (optional)</h4>
          <select value={pathId} onChange={(e) => e.target.value ? usePath(e.target.value) : setPathId('')} style={{ width: '100%' }}>
            <option value="">— hand-pick cases below —</option>
            {LEARNING_PATHS.map((p) => <option key={p.id} value={p.id}>{TIER_LABELS[p.tier]} · {p.title}</option>)}
          </select>
          <div className="tiny dim mt">Picking a path loads its cases (students are pointed to its lessons first).</div>
        </div>

        <div className="card">
          <h4>Selected cases ({picked.length})</h4>
          {picked.length === 0 ? <div className="small dim">None yet — pick from the list.</div> : (
            <div className="pill-row">
              {picked.map((id) => <span key={id} className="chip" style={{ cursor: 'pointer' }} onClick={() => toggle(id)}>{getScenario(id)?.title ?? id} ✕</span>)}
            </div>
          )}
          <button className="btn primary mt" style={{ width: '100%' }} onClick={build}>Copy assignment link</button>
          {link && <><label className="field">Shareable link</label><input readOnly value={link} onFocus={(e) => e.currentTarget.select()} style={{ width: '100%', fontFamily: 'var(--mono)', fontSize: 11 }} /></>}
        </div>
      </div>

      <div>
        <div className="card">
          <h4>Add cases</h4>
          <Tabs tabs={TIER_ORDER.map((t) => ({ id: t, label: TIER_LABELS[t].replace(' Analyst', '').replace(' Member', '') }))} active={tier} onChange={(t) => setTier(t as Tier)} />
          <div style={{ maxHeight: '52vh', overflowY: 'auto' }}>
            {SCENARIOS_BY_TIER[tier].map((s) => (
              <label key={s.id} className="flex" style={{ gap: 9, padding: '5px 2px', fontSize: 12.5, alignItems: 'flex-start' }}>
                <input type="checkbox" style={{ width: 'auto', marginTop: 2 }} checked={picked.includes(s.id)} onChange={() => toggle(s.id)} />
                <span><strong>{s.title}</strong> <span className="dim">· {s.category}</span></span>
              </label>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Gradebook() {
  const [raw, setRaw] = useState('');
  const decoded = useMemo(() => {
    return raw.split(/\s+/).map((c) => c.trim()).filter(Boolean).map((c) => decodeReceipt(c)).filter((r): r is Receipt => !!r);
  }, [raw]);
  const bad = raw.trim() ? raw.split(/\s+/).filter(Boolean).length - decoded.length : 0;

  return (
    <div>
      <div className="card">
        <h4>Paste submission receipts</h4>
        <div className="small dim mb">Paste one or more receipt codes (whitespace or newline separated) from your students.</div>
        <textarea value={raw} onChange={(e) => setRaw(e.target.value)} rows={5} placeholder="eyJ2Ijox... (one per student)" style={{ width: '100%', fontFamily: 'var(--mono)', fontSize: 11 }} />
        {bad > 0 && <div className="small" style={{ color: 'var(--amber)' }}>{bad} code(s) couldn’t be read.</div>}
      </div>

      {decoded.length > 0 && (
        <div className="card">
          <h4>Results ({decoded.length})</h4>
          <table className="data">
            <thead><tr><th>Student</th><th>Assignment</th><th>Passed</th><th>Avg score</th><th>Submitted</th></tr></thead>
            <tbody>
              {decoded.map((r, i) => {
                const passed = r.results.filter((x) => x.passed).length;
                const avg = r.results.length ? Math.round(r.results.reduce((a, x) => a + x.score, 0) / r.results.length) : 0;
                const full = passed === r.results.length;
                return (
                  <tr key={i}>
                    <td><strong>{r.by}</strong></td>
                    <td className="dim">{r.a}</td>
                    <td style={{ color: full ? 'var(--green)' : 'var(--amber)' }}>{passed}/{r.results.length}</td>
                    <td className="mono" style={{ color: scoreColor(avg) }}>{avg}</td>
                    <td className="dim nowrap">{new Date(r.at).toLocaleDateString()}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <details style={{ marginTop: 10 }}>
            <summary className="small dim" style={{ cursor: 'pointer' }}>Per-case detail</summary>
            {decoded.map((r, i) => (
              <div key={i} className="mt">
                <div className="small"><strong>{r.by}</strong> — {r.a}</div>
                <table className="data"><thead><tr><th>Case</th><th>Score</th><th>Pass</th><th>Attempts</th></tr></thead>
                  <tbody>{r.results.map((x, j) => (
                    <tr key={j}><td>{getScenario(x.id)?.title ?? x.id}</td><td className="mono" style={{ color: scoreColor(x.score) }}>{x.score}</td><td style={{ color: x.passed ? 'var(--green)' : 'var(--amber)' }}>{x.passed ? '✓' : '—'}</td><td className="mono">{x.attempts}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            ))}
          </details>
          <div className="tiny dim mt">Receipts are self-reported (practice-grade), not verified credentials.</div>
        </div>
      )}
    </div>
  );
}
