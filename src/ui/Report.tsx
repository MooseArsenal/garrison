import React, { useMemo, useState } from 'react';
import { SKILLS, SKILL_LABELS, TIER_LABELS, TIER_ORDER, type Skill, type Tier } from '../engine/types';
import { SCENARIOS_BY_TIER, ALL_SCENARIOS, getScenario } from '../scenarios';
import { loadProgress, loadSettings } from '../engine/progress';
import { scoreColor } from './common';

function fmtDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

export function Report({ onExit }: { onExit: () => void }) {
  const progress = useMemo(() => loadProgress(), []);
  const settings = useMemo(() => loadSettings(), []);
  const [name, setName] = useState(settings.playerName || 'Analyst');

  const data = useMemo(() => {
    const scen = progress.scenarios;
    const hist = progress.history;
    const cleared = Object.values(scen).filter((s) => s.passed).length;
    const attempts = hist.length;
    const avg = attempts ? Math.round(hist.reduce((a, h) => a + h.score, 0) / attempts) : 0;

    const perTier = TIER_ORDER.map((t: Tier) => {
      const list = SCENARIOS_BY_TIER[t];
      const passed = list.filter((s) => scen[s.id]?.passed).length;
      const bests = list.map((s) => scen[s.id]?.best).filter((x): x is number => typeof x === 'number');
      const tierAvg = bests.length ? Math.round(bests.reduce((a, b) => a + b, 0) / bests.length) : null;
      return { tier: t, passed, total: list.length, avg: tierAvg };
    });

    // per-skill average across all graded attempts
    const skillAvg = {} as Record<Skill, number | null>;
    for (const k of SKILLS) {
      const vals = hist.map((h) => h.skills[k]).filter((x): x is number => typeof x === 'number');
      skillAvg[k] = vals.length ? Math.round(vals.reduce((a, b) => a + b, 0) / vals.length) : null;
    }
    const rankedSkills = SKILLS.filter((k) => skillAvg[k] != null).sort((a, b) => (skillAvg[b]! - skillAvg[a]!));
    const strengths = rankedSkills.slice(0, 3);
    const focus = rankedSkills.slice(-3).reverse();

    const recent = [...hist].reverse().slice(0, 12).map((h) => ({
      ...h, title: getScenario(h.scenarioId)?.title ?? h.scenarioId, tier: getScenario(h.scenarioId)?.tier as Tier | undefined,
    }));
    const firstAt = hist.length ? hist.map((h) => h.at).sort()[0] : null;
    return { cleared, total: ALL_SCENARIOS.length, attempts, avg, perTier, skillAvg, strengths, focus, recent, firstAt, hasData: attempts > 0 };
  }, [progress]);

  return (
    <div className="report">
      <div className="report-actions">
        <button className="btn ghost sm" onClick={onExit}>← Menu</button>
        <button className="btn primary sm" onClick={() => window.print()}>🖨 Save as PDF / Print</button>
      </div>

      <div className="report-sheet">
        <div className="report-head">
          <div className="flex" style={{ gap: 12 }}>
            <div className="logo" style={{ width: 44, height: 44 }}>🛡️</div>
            <div>
              <h1 style={{ fontSize: 22 }}>Garrison — Training Report</h1>
              <div className="small dim">IT &amp; Security Operations · Service Desk → SOC → CIRT</div>
            </div>
          </div>
          <div className="report-name">
            <label className="tiny dim">Analyst</label>
            <input value={name} onChange={(e) => setName(e.target.value)} className="report-name-input" />
            <div className="tiny dim">{data.firstAt ? `Training since ${fmtDate(data.firstAt)}` : 'No attempts yet'} · Generated {fmtDate(new Date().toISOString())}</div>
          </div>
        </div>

        {!data.hasData ? (
          <div className="empty">No attempts recorded yet. Work a few cases from the queue, then come back for your report.</div>
        ) : (
          <>
            <div className="report-kpis">
              <div className="rkpi"><div className="rk-n">{data.cleared}/{data.total}</div><div className="rk-l">Cases cleared</div></div>
              <div className="rkpi"><div className="rk-n">{data.attempts}</div><div className="rk-l">Total attempts</div></div>
              <div className="rkpi"><div className="rk-n" style={{ color: scoreColor(data.avg) }}>{data.avg}</div><div className="rk-l">Average score</div></div>
              <div className="rkpi"><div className="rk-n">{Math.round((data.cleared / data.total) * 100)}%</div><div className="rk-l">Ladder complete</div></div>
            </div>

            <div className="report-cols">
              <div>
                <h3 className="report-h">Skill profile</h3>
                <Radar skillAvg={data.skillAvg} />
              </div>
              <div>
                <h3 className="report-h">By skill</h3>
                {SKILLS.map((k) => (
                  <div key={k} className="skill-bar">
                    <div className="top"><span>{SKILL_LABELS[k]}</span><span style={{ color: data.skillAvg[k] == null ? 'var(--text-faint)' : scoreColor(data.skillAvg[k]!), fontWeight: 700 }}>{data.skillAvg[k] ?? '—'}</span></div>
                    <div className="track"><span style={{ width: `${data.skillAvg[k] ?? 0}%`, background: data.skillAvg[k] == null ? 'var(--border)' : scoreColor(data.skillAvg[k]!) }} /></div>
                  </div>
                ))}
              </div>
            </div>

            <div className="report-cols">
              <div className="card">
                <h4 style={{ color: 'var(--green)' }}>Strengths</h4>
                {data.strengths.length ? data.strengths.map((k) => <div key={k} className="small">✓ {SKILL_LABELS[k]} <span className="dim">({data.skillAvg[k]})</span></div>) : <div className="small dim">Not enough data yet.</div>}
              </div>
              <div className="card">
                <h4 style={{ color: 'var(--amber)' }}>Focus areas</h4>
                {data.focus.length ? data.focus.map((k) => <div key={k} className="small">→ {SKILL_LABELS[k]} <span className="dim">({data.skillAvg[k]})</span></div>) : <div className="small dim">Not enough data yet.</div>}
              </div>
            </div>

            <h3 className="report-h">Progress by tier</h3>
            <table className="data report-table">
              <thead><tr><th>Tier</th><th>Cleared</th><th>Avg (best)</th><th></th></tr></thead>
              <tbody>
                {data.perTier.map((r) => (
                  <tr key={r.tier}>
                    <td>{TIER_LABELS[r.tier]}</td>
                    <td className="mono">{r.passed}/{r.total}</td>
                    <td className="mono" style={{ color: r.avg == null ? 'var(--text-faint)' : scoreColor(r.avg) }}>{r.avg ?? '—'}</td>
                    <td style={{ width: 160 }}><div className="track" style={{ height: 7 }}><span style={{ display: 'block', height: '100%', width: `${Math.round((r.passed / r.total) * 100)}%`, background: 'linear-gradient(90deg, var(--brass), var(--green))', borderRadius: 5 }} /></div></td>
                  </tr>
                ))}
              </tbody>
            </table>

            <h3 className="report-h">Recent activity</h3>
            <table className="data report-table">
              <thead><tr><th>Case</th><th>Tier</th><th>Score</th><th>When</th></tr></thead>
              <tbody>
                {data.recent.map((h, i) => (
                  <tr key={i}>
                    <td>{h.title}</td>
                    <td className="dim">{h.tier ? TIER_LABELS[h.tier] : '—'}</td>
                    <td className="mono" style={{ color: scoreColor(h.score) }}>{h.score}</td>
                    <td className="dim nowrap">{fmtDate(h.at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="report-foot small dim">
              Self-reported practice record from Garrison, a hands-on IT &amp; security operations training simulator. Scores reflect decisions taken across {data.attempts} simulated case attempt{data.attempts === 1 ? '' : 's'} spanning help desk, SOC, and incident response.
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function Radar({ skillAvg }: { skillAvg: Record<Skill, number | null> }) {
  const size = 260, cx = size / 2, cy = size / 2, R = 96;
  const n = SKILLS.length;
  const pt = (i: number, r: number) => {
    const ang = -Math.PI / 2 + (i * 2 * Math.PI) / n;
    return [cx + Math.cos(ang) * r, cy + Math.sin(ang) * r];
  };
  const rings = [0.25, 0.5, 0.75, 1];
  const dataPts = SKILLS.map((k, i) => pt(i, ((skillAvg[k] ?? 0) / 100) * R));
  const poly = dataPts.map((p) => p.join(',')).join(' ');
  return (
    <svg viewBox={`0 0 ${size} ${size}`} className="radar" role="img" aria-label="Skill radar">
      {rings.map((rr, ri) => (
        <polygon key={ri} points={SKILLS.map((_, i) => pt(i, R * rr).join(',')).join(' ')} fill="none" stroke="var(--border)" strokeWidth={1} />
      ))}
      {SKILLS.map((_, i) => { const [x, y] = pt(i, R); return <line key={i} x1={cx} y1={cy} x2={x} y2={y} stroke="var(--border)" strokeWidth={1} />; })}
      <polygon points={poly} fill="rgba(176,71,44,.22)" stroke="var(--accent)" strokeWidth={2} />
      {dataPts.map((p, i) => <circle key={i} cx={p[0]} cy={p[1]} r={2.5} fill="var(--accent)" />)}
      {SKILLS.map((k, i) => {
        const [x, y] = pt(i, R + 14);
        return <text key={k} x={x} y={y} fontSize={9} fill="var(--text-dim)" textAnchor={x < cx - 5 ? 'end' : x > cx + 5 ? 'start' : 'middle'} dominantBaseline="middle">{SKILL_LABELS[k].split(' ')[0]}</text>;
      })}
    </svg>
  );
}
