import React from 'react';
import { useSession } from '../engine/session';
import { TIER_LABELS } from '../engine/types';
import { userName, fmt } from '../engine/world';
import { Diff, Pri, Sev } from './common';

export function Briefing({ onStart, onExit }: { onStart: () => void; onExit: () => void }) {
  const { scenario: s, world } = useSession();
  const intake = s.intake;
  return (
    <div className="home">
      <div className="brandbar">
        <button className="btn ghost sm" onClick={onExit}>← Menu</button>
        <span className="chip">{TIER_LABELS[s.tier]}</span>
      </div>
      <div className="brief">
        <div className="flex wrap" style={{ gap: 10 }}>
          <span className="chip">{s.category}</span>
          <Diff n={s.difficulty} />
          <span className="small dim">~{s.estMinutes} min</span>
        </div>
        <h1 style={{ fontSize: 26, margin: '12px 0 4px' }}>{s.title}</h1>
        <div className="obj"><strong>Objective.</strong> {s.objective}</div>

        {intake.kind === 'ticket' && (
          <div className="card">
            <div className="ticket-head">
              <span className="mono dim">{intake.number}</span>
              <Pri p={intake.priority} />
              <span className="chip">{intake.channel}</span>
              <span className="small dim">opened {fmt(intake.openedAt)}</span>
            </div>
            <h3 style={{ margin: '6px 0' }}>{intake.subject}</h3>
            <div className="small dim">From: {userName(world, intake.requester)} · {world.users.find((u) => u.id === intake.requester)?.title}</div>
            <div className="ticket-body">{intake.body}</div>
            {intake.affectedHost && <div className="small dim">Affected host: <span className="mono">{intake.affectedHost}</span></div>}
          </div>
        )}

        {intake.kind === 'alert' && (() => {
          const a = world.alerts.find((x) => x.id === intake.alertId)!;
          return (
            <div className="card">
              <div className="ticket-head">
                <span className="mono dim">{a.id}</span>
                <Sev s={a.severity} />
                <span className="chip">source: {a.source}</span>
                <span className="small dim">{fmt(a.time)}</span>
              </div>
              <h3 style={{ margin: '6px 0' }}>{a.title}</h3>
              <div className="ticket-body">{a.description}</div>
              <div className="flex wrap small">
                {a.host && <span className="chip">host: {a.host}</span>}
                {a.user && <span className="chip">user: {a.user}</span>}
                {a.mitre?.map((m) => <span key={m} className="tag">{m}</span>)}
              </div>
            </div>
          );
        })()}

        {intake.kind === 'incident' && (
          <div className="card">
            <div className="ticket-head">
              <span className="mono dim">{intake.number}</span>
              <span className={`sev ${intake.severity === 'SEV1' ? 'critical' : intake.severity === 'SEV2' ? 'high' : 'medium'}`}>{intake.severity}</span>
              <span className="small dim">declared by {userName(world, intake.declaredBy)} · {fmt(intake.openedAt)}</span>
            </div>
            <h3 style={{ margin: '6px 0' }}>{intake.title}</h3>
            <div className="ticket-body">{intake.summary}</div>
          </div>
        )}

        <div className="card" style={{ background: 'var(--bg-2)' }}>
          <div className="small dim">You are working as a <strong style={{ color: 'var(--text)' }}>{TIER_LABELS[s.tier]}</strong> at Kestrel Dynamics. Use the tools on the left to investigate, then fill in the work panel on the right and submit. You are graded on what you check, what you do, the order you do it in, and how you close it — just like a real desk.</div>
        </div>

        <div className="flex" style={{ justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
          <button className="btn ghost" onClick={onExit}>Cancel</button>
          <button className="btn primary" onClick={onStart}>Start the clock →</button>
        </div>
      </div>
    </div>
  );
}
