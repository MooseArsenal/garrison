import React, { useMemo, useRef, useState } from 'react';
import type { GradeResult } from '../engine/types';
import { getScenario } from '../scenarios';
import { Play } from './Play';
import { scoreColor } from './common';

interface ShiftResult { id: string; title: string; score: number; passed: boolean; }

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}

export function Shift({ scope, label, onExit }: { scope: string[]; label: string; onExit: () => void }) {
  const [order, setOrder] = useState<string[]>(() => shuffle(scope));
  const [pos, setPos] = useState(0);
  const [results, setResults] = useState<ShiftResult[]>([]);
  const [phase, setPhase] = useState<'play' | 'summary'>('play');
  const startedAt = useRef<number>(Date.now());

  const currentId = order[pos];
  const avg = results.length ? Math.round(results.reduce((a, r) => a + r.score, 0) / results.length) : null;
  const streak = useMemo(() => {
    let s = 0; for (let i = results.length - 1; i >= 0; i--) { if (results[i].passed) s++; else break; } return s;
  }, [results]);

  function record(r: GradeResult): ShiftResult[] {
    const sc = getScenario(currentId);
    const rec: ShiftResult = { id: currentId, title: sc?.title ?? currentId, score: r.overall, passed: r.passed };
    const next = [...results, rec];
    setResults(next);
    return next;
  }
  function advance() {
    let np = pos + 1; let ord = order;
    if (np >= order.length) { ord = shuffle(scope); setOrder(ord); np = 0; }
    setPos(np);
  }

  if (phase === 'summary') {
    return <ShiftSummary label={label} results={results} durationSec={Math.floor((Date.now() - startedAt.current) / 1000)}
      onNewShift={() => { setOrder(shuffle(scope)); setPos(0); setResults([]); startedAt.current = Date.now(); setPhase('play'); }}
      onExit={onExit} />;
  }

  return (
    <Play
      key={`${currentId}@${pos}`}
      scenarioId={currentId}
      onExit={() => (results.length ? setPhase('summary') : onExit())}
      shift={{ caseNum: results.length + 1, avg, streak, label }}
      onNext={(r) => { record(r); advance(); }}
      onEndShift={(r) => { record(r); setPhase('summary'); }}
    />
  );
}

function ShiftSummary({ label, results, durationSec, onNewShift, onExit }: {
  label: string; results: ShiftResult[]; durationSec: number; onNewShift: () => void; onExit: () => void;
}) {
  const n = results.length;
  const avg = n ? Math.round(results.reduce((a, r) => a + r.score, 0) / n) : 0;
  const passed = results.filter((r) => r.passed).length;
  const best = n ? Math.max(...results.map((r) => r.score)) : 0;
  let bestStreak = 0, cur = 0;
  for (const r of results) { if (r.passed) { cur++; bestStreak = Math.max(bestStreak, cur); } else cur = 0; }
  const mins = Math.floor(durationSec / 60), secs = durationSec % 60;

  return (
    <div className="debrief">
      <div className="flex" style={{ justifyContent: 'space-between', marginBottom: 18 }}>
        <button className="btn ghost sm" onClick={onExit}>← Menu</button>
        <button className="btn primary sm" onClick={onNewShift}>▶ New shift</button>
      </div>
      <div className="score-hero">
        <div>
          <div className="verdict-big pass">🎧 Shift complete</div>
          <div className="dim">{label} · {mins}m {secs}s on the clock</div>
        </div>
      </div>
      <div className="report-kpis" style={{ marginBottom: 22 }}>
        <div className="rkpi"><div className="rk-n">{n}</div><div className="rk-l">Cases handled</div></div>
        <div className="rkpi"><div className="rk-n" style={{ color: scoreColor(avg) }}>{avg}</div><div className="rk-l">Average score</div></div>
        <div className="rkpi"><div className="rk-n">{n ? Math.round((passed / n) * 100) : 0}%</div><div className="rk-l">Passed ({passed}/{n})</div></div>
        <div className="rkpi"><div className="rk-n">🔥 {bestStreak}</div><div className="rk-l">Best streak</div></div>
      </div>
      <h3 className="report-h">Cases this shift</h3>
      <table className="data report-table">
        <thead><tr><th>#</th><th>Case</th><th>Score</th><th>Result</th></tr></thead>
        <tbody>
          {results.map((r, i) => (
            <tr key={i}>
              <td className="dim">{i + 1}</td>
              <td>{r.title}</td>
              <td className="mono" style={{ color: scoreColor(r.score) }}>{r.score}</td>
              <td style={{ color: r.passed ? 'var(--green)' : 'var(--amber)' }}>{r.passed ? '✓ passed' : 'retry'}</td>
            </tr>
          ))}
          {n === 0 && <tr><td colSpan={4} className="dim">No cases completed.</td></tr>}
        </tbody>
      </table>
      <div className="flex" style={{ justifyContent: 'center', gap: 12, marginTop: 20 }}>
        <button className="btn" onClick={onExit}>Back to menu</button>
        <button className="btn primary" onClick={onNewShift}>▶ Start another shift</button>
      </div>
    </div>
  );
}
