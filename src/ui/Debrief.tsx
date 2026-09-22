import React from 'react';
import { useSession } from '../engine/session';
import { SKILL_LABELS, type GradeResult } from '../engine/types';
import { scoreColor } from './common';

export function Debrief({ result, onExit, onRetry, shift, onNext, onEndShift }: {
  result: GradeResult; onExit: () => void; onRetry: () => void;
  shift?: { caseNum: number; avg: number | null; streak: number; label: string };
  onNext?: () => void; onEndShift?: () => void;
}) {
  const { scenario: s, ticket } = useSession();
  const r = result;
  const chosenReply = s.replies.find((x) => x.id === ticket.replyId);
  const bestReply = s.replies.find((x) => x.best);
  const ring = `conic-gradient(${scoreColor(r.overall)} ${r.overall * 3.6}deg, var(--ground-2) 0deg)`;

  return (
    <div className="debrief">
      <div className="flex" style={{ justifyContent: 'space-between', marginBottom: 18 }}>
        {shift ? <button className="btn ghost sm" onClick={onEndShift}>■ End shift</button> : <button className="btn ghost sm" onClick={onExit}>← Menu</button>}
        <div className="flex" style={{ gap: 8 }}>
          <button className="btn sm" onClick={onRetry}>↻ Retry</button>
          {shift && onNext && <button className="btn primary sm" onClick={onNext}>Next case →</button>}
        </div>
      </div>
      {shift && (
        <div className="card" style={{ background: 'var(--surface-2)', borderColor: 'var(--brass)' }}>
          <div className="flex wrap" style={{ justifyContent: 'space-between' }}>
            <strong>🎧 {shift.label} shift</strong>
            <span className="small dim">case {shift.caseNum}{shift.avg != null ? ` · running avg ${shift.avg}` : ''}{shift.streak > 0 ? ` · 🔥 ${shift.streak} in a row` : ''}</span>
          </div>
        </div>
      )}

      <div className="score-hero">
        <div className="ring" style={{ background: ring, borderRadius: '50%' }}>
          <div className="ring" style={{ position: 'absolute', inset: 10, background: 'var(--bg-2)', borderRadius: '50%' }} />
          <div className="num">{r.overall}<small>/100</small></div>
        </div>
        <div>
          <div className={`verdict-big ${r.passed ? 'pass' : 'fail'}`}>{r.passed ? '✓ Passed' : 'Not yet — retry'}</div>
          <div className="dim">{s.title}</div>
          <div className="flex wrap mt small dim">
            <span>⏱ {Math.floor(r.elapsedSec / 60)}m {r.elapsedSec % 60}s</span>
            <span>· {r.actionCount} actions</span>
            {r.forbiddenHits.length > 0 && <span style={{ color: 'var(--red)' }}>· {r.forbiddenHits.length} costly mistake{r.forbiddenHits.length > 1 ? 's' : ''}</span>}
          </div>
        </div>
      </div>

      {r.forbiddenHits.length > 0 && (
        <div className="card" style={{ borderColor: '#C79A93' }}>
          <h4 style={{ color: 'var(--red)' }}>What hurt you most</h4>
          {r.forbiddenHits.map((f, i) => (
            <div key={i} className="mb"><strong>{f.label}</strong><div className="small dim">{f.why}</div></div>
          ))}
        </div>
      )}

      <div className="two-col">
        <div>
          <h3 className="mb">Skills</h3>
          {r.skills.map((sk) => (
            <div key={sk.skill} className="skill-bar">
              <div className="top"><span>{SKILL_LABELS[sk.skill]}</span><span style={{ color: scoreColor(sk.score), fontWeight: 700 }}>{sk.score}</span></div>
              <div className="track"><span style={{ width: `${sk.score}%`, background: scoreColor(sk.score) }} /></div>
            </div>
          ))}
        </div>
        <div>
          <h3 className="mb">Your reply</h3>
          {chosenReply ? (
            <div className="card">
              <div className="small">{chosenReply.text}</div>
              <hr className="sep" />
              <div className="small" style={{ color: chosenReply.best ? 'var(--green)' : 'var(--amber)' }}>{chosenReply.feedback}</div>
              {!chosenReply.best && bestReply && (
                <>
                  <div className="small dim mt"><strong>Stronger reply:</strong></div>
                  <div className="small dim" style={{ marginTop: 4 }}>{bestReply.text}</div>
                </>
              )}
            </div>
          ) : <div className="card dim small">You didn't send a reply. Communication is part of the job — always close the loop with the requester or stakeholder.</div>}
        </div>
      </div>

      <h3 className="mt mb">Breakdown</h3>
      {r.skills.filter((sk) => sk.details.length > 0).map((sk) => (
        <div key={sk.skill} className="card">
          <h4>{SKILL_LABELS[sk.skill]} <span className="dim" style={{ fontWeight: 400 }}>· {sk.score}</span></h4>
          <ul className="detail-list">
            {sk.details.map((d, i) => (
              <li key={i}>
                <span className={`ic ${d.ok ? 'ok' : 'no'}`}>{d.ok ? '✓' : '✕'}</span>
                <span>{d.text}{d.sub && <span className="sub">{d.sub}</span>}</span>
              </li>
            ))}
          </ul>
        </div>
      ))}

      <div className="card" style={{ background: 'var(--wash-info)', borderColor: '#B9CDCE' }}>
        <h4>Debrief</h4>
        <div className="small" style={{ lineHeight: 1.65 }}>{s.debrief}</div>
        <hr className="sep" />
        <div className="small dim"><strong>Key SOPs for this scenario:</strong> open the Knowledge Base and review the articles referenced above.</div>
      </div>

      <div className="flex" style={{ justifyContent: 'center', gap: 12, marginTop: 20 }}>
        {shift ? (
          <>
            <button className="btn" onClick={onEndShift}>End shift &amp; see summary</button>
            <button className="btn" onClick={onRetry}>Retry this case</button>
            {onNext && <button className="btn primary" onClick={onNext}>Next case →</button>}
          </>
        ) : (
          <>
            <button className="btn" onClick={onExit}>Back to menu</button>
            <button className="btn primary" onClick={onRetry}>Retry scenario</button>
          </>
        )}
      </div>
    </div>
  );
}
