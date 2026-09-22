import React, { useState } from 'react';
import { TIER_LABELS } from '../engine/types';
import { getScenario } from '../scenarios';
import { loadProgress, loadSettings } from '../engine/progress';
import { type Assignment as Asg, type Receipt, encodeReceipt } from '../engine/assignments';
import { getPath } from '../engine/paths';
import { Play } from './Play';
import { Modal, useToast, scoreColor } from './common';

export function AssignmentView({ assignment, onExit }: { assignment: Asg; onExit: () => void }) {
  const [progress, setProgress] = useState(loadProgress());
  const [playing, setPlaying] = useState<string | null>(null);
  const [showReceipt, setShowReceipt] = useState(false);

  if (playing) {
    return <Play key={playing} scenarioId={playing} onExit={() => { setProgress(loadProgress()); setPlaying(null); }} onReplay={() => {}} />;
  }

  const items = assignment.items.map((id) => {
    const sc = getScenario(id);
    const p = progress.scenarios[id];
    const met = (p?.best ?? 0) >= assignment.pass;
    return { id, sc, best: p?.best, attempts: p?.attempts ?? 0, met };
  });
  const met = items.filter((i) => i.met).length;
  const path = assignment.pathId ? getPath(assignment.pathId) : null;

  return (
    <div className="home">
      <div className="brandbar">
        <div className="brand"><div className="logo">📋</div><div><h1>Assignment</h1><div className="sub">from {assignment.from || 'your instructor'}</div></div></div>
        <button className="btn ghost sm" onClick={onExit}>Garrison home →</button>
      </div>

      <div className="brief">
        <div className="card">
          <div className="flex wrap" style={{ justifyContent: 'space-between' }}>
            <h2 style={{ fontSize: 20 }}>{assignment.title}</h2>
            <span className="chip">pass mark {assignment.pass}</span>
          </div>
          {assignment.note && <div className="ticket-body" style={{ marginBottom: 0 }}>{assignment.note}</div>}
          {path && <div className="small dim mt">Recommended reading first: the <strong>{path.title}</strong> learning path.</div>}
          <div className="small dim mt">{met}/{items.length} cases at or above the pass mark. Work each case, then generate your submission receipt to send back.</div>
          <div className="tier-progress mt"><div className="bar" style={{ width: 240 }}><span style={{ width: `${Math.round((met / items.length) * 100)}%` }} /></div></div>
        </div>

        <div className="path-steps">
          {items.map((it, idx) => (
            <div key={it.id} className={`path-step ${it.met ? 'done' : 'available'}`}>
              <div className="ps-marker">{it.met ? '✓' : idx + 1}</div>
              <div className="ps-body">
                <div className="ps-kind">{it.sc ? TIER_LABELS[it.sc.tier] : 'Case'}{it.sc ? ` · ${it.sc.category}` : ''}</div>
                <div className="ps-title">{it.sc?.title ?? it.id}</div>
                <div className="ps-blurb">{it.best != null ? `best ${it.best} · ${it.attempts} attempt${it.attempts === 1 ? '' : 's'}` : 'not started'}</div>
              </div>
              <div className="ps-action">
                <button className={`btn sm ${it.met ? '' : 'primary'}`} onClick={() => setPlaying(it.id)}>{it.best != null ? 'Rework' : 'Work case →'}</button>
              </div>
            </div>
          ))}
        </div>

        <div className="flex" style={{ justifyContent: 'center', marginTop: 20 }}>
          <button className="btn primary" onClick={() => setShowReceipt(true)}>Generate submission receipt</button>
        </div>
        <div className="tiny dim" style={{ textAlign: 'center', marginTop: 8 }}>Self-reported practice record. Your progress stays in this browser; the receipt is what you send your instructor.</div>
      </div>

      {showReceipt && <ReceiptModal assignment={assignment} items={items} onClose={() => setShowReceipt(false)} />}
    </div>
  );
}

function ReceiptModal({ assignment, items, onClose }: {
  assignment: Asg; items: { id: string; best?: number; attempts: number; met: boolean }[]; onClose: () => void;
}) {
  const toast = useToast();
  const [name, setName] = useState(loadSettings().playerName || '');
  const receipt: Receipt = {
    v: 1, a: assignment.title, by: name || 'Anonymous', at: new Date().toISOString(), pass: assignment.pass,
    results: items.map((i) => ({ id: i.id, score: i.best ?? 0, passed: i.met, attempts: i.attempts })),
  };
  const code = encodeReceipt(receipt);
  const met = items.filter((i) => i.met).length;

  return (
    <Modal title="Submission receipt" onClose={onClose} wide
      footer={<>
        <button className="btn ghost" onClick={onClose}>Close</button>
        <button className="btn primary" onClick={() => { navigator.clipboard?.writeText(code).then(() => toast('Receipt copied', 'good'), () => toast('Copy failed — select the text', 'bad')); }}>Copy receipt code</button>
      </>}>
      <label className="field">Your name (on the receipt)</label>
      <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Sam Rivera" style={{ width: '100%' }} />
      <div className="small dim mt">You met the pass mark on <strong>{met}/{items.length}</strong> cases. Send this code to your instructor (paste into email/Classroom/Teams). They decode it in the Garrison gradebook.</div>
      <textarea readOnly value={code} rows={5} style={{ width: '100%', marginTop: 10, fontFamily: 'var(--mono)', fontSize: 11 }} onFocus={(e) => e.currentTarget.select()} />
      <div className="tiny dim mt">This is a self-reported practice record, not a verified credential.</div>
    </Modal>
  );
}
