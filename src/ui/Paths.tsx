import React, { useState } from 'react';
import { TIER_LABELS, TIER_ORDER, type Tier } from '../engine/types';
import { LEARNING_PATHS, KB_CHECKS, getPath, type LearningPath, type PathStep } from '../engine/paths';
import { KB } from '../engine/world';
import { getScenario } from '../scenarios';
import { loadProgress, markLesson, type ProgressStore } from '../engine/progress';
import { Modal } from './common';

interface StepStatus { done: boolean; available: boolean; }

function statusFor(path: LearningPath, progress: ProgressStore): StepStatus[] {
  const out: StepStatus[] = [];
  let prevDone = true;
  path.steps.forEach((step, idx) => {
    const done = step.kind === 'lesson'
      ? !!progress.lessons?.[`${path.id}#${idx}`]
      : !!(step.scenarioId && progress.scenarios[step.scenarioId]?.passed);
    out.push({ done, available: prevDone });
    prevDone = prevDone && done;
  });
  return out;
}
function pathDone(path: LearningPath, progress: ProgressStore): number {
  return statusFor(path, progress).filter((s) => s.done).length;
}

export function Paths({ onPlay, onExit }: { onPlay: (id: string) => void; onExit: () => void }) {
  const [progress, setProgress] = useState(loadProgress());
  const [openId, setOpenId] = useState<string | null>(null);
  const path = openId ? getPath(openId) : null;

  if (path) return <PathDetail path={path} progress={progress} onBack={() => { setProgress(loadProgress()); setOpenId(null); }}
    onPlay={onPlay} onProgress={() => setProgress(loadProgress())} />;

  return (
    <div className="home">
      <div className="brandbar">
        <div className="brand"><div className="logo">📚</div><div><h1>Learning paths</h1><div className="sub">Guided curricula — read the playbook, then work the cases</div></div></div>
        <button className="btn ghost sm" onClick={onExit}>← Menu</button>
      </div>
      {TIER_ORDER.map((tier: Tier) => {
        const paths = LEARNING_PATHS.filter((p) => p.tier === tier);
        if (!paths.length) return null;
        return (
          <div key={tier} style={{ marginBottom: 22 }}>
            <h3 className="report-h" style={{ marginBottom: 10 }}>{TIER_LABELS[tier]}</h3>
            <div className="scen-grid" style={{ padding: 0 }}>
              {paths.map((p) => {
                const done = pathDone(p, progress); const total = p.steps.length;
                const pct = Math.round((done / total) * 100);
                return (
                  <button key={p.id} className="scen-card" onClick={() => setOpenId(p.id)}>
                    <div className="row1"><span className="cat">{done === total ? '✓ complete' : `${done}/${total} steps`}</span></div>
                    <div className="title">{p.title}</div>
                    <div className="obj">{p.summary}</div>
                    <div className="tier-progress" style={{ marginTop: 4 }}><div className="bar"><span style={{ width: `${pct}%` }} /></div></div>
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function PathDetail({ path, progress, onBack, onPlay, onProgress }: {
  path: LearningPath; progress: ProgressStore; onBack: () => void; onPlay: (id: string) => void; onProgress: () => void;
}) {
  const [lessonIdx, setLessonIdx] = useState<number | null>(null);
  const status = statusFor(path, progress);
  const done = status.filter((s) => s.done).length;

  return (
    <div className="home">
      <div className="brandbar">
        <button className="btn ghost sm" onClick={onBack}>← All paths</button>
        <span className="chip">{TIER_LABELS[path.tier]}</span>
      </div>
      <div className="brief">
        <h1 style={{ fontSize: 24, marginBottom: 4 }}>{path.title}</h1>
        <div className="dim mb">{path.summary}</div>
        <div className="tier-progress mb"><div className="bar" style={{ width: 220 }}><span style={{ width: `${Math.round((done / path.steps.length) * 100)}%` }} /></div><span className="small dim">{done}/{path.steps.length} complete</span></div>

        <div className="path-steps">
          {path.steps.map((step, idx) => {
            const st = status[idx];
            const sc = step.kind === 'case' && step.scenarioId ? getScenario(step.scenarioId) : null;
            const art = step.kind === 'lesson' && step.kb ? KB.find((a) => a.id === step.kb) : null;
            const title = step.kind === 'lesson' ? (art?.title ?? step.kb ?? 'Lesson') : (sc?.title ?? step.scenarioId ?? 'Case');
            return (
              <div key={idx} className={`path-step ${st.done ? 'done' : st.available ? 'available' : 'locked'}`}>
                <div className="ps-marker">{st.done ? '✓' : st.available ? (step.kind === 'lesson' ? '📖' : '🎯') : '🔒'}</div>
                <div className="ps-body">
                  <div className="ps-kind">{step.kind === 'lesson' ? 'Lesson' : 'Case'}{art ? ` · ${art.id}` : sc ? ` · ${TIER_LABELS[sc.tier]}` : ''}</div>
                  <div className="ps-title">{title}</div>
                  {step.blurb && <div className="ps-blurb">{step.blurb}</div>}
                </div>
                <div className="ps-action">
                  {!st.available ? <span className="tiny dim">locked</span>
                    : step.kind === 'lesson'
                      ? <button className={`btn sm ${st.done ? '' : 'primary'}`} onClick={() => setLessonIdx(idx)}>{st.done ? 'Review' : 'Read lesson'}</button>
                      : <button className={`btn sm ${st.done ? '' : 'primary'}`} onClick={() => step.scenarioId && onPlay(step.scenarioId)}>{st.done ? 'Replay' : 'Work case →'}</button>}
                </div>
              </div>
            );
          })}
        </div>
        {done === path.steps.length && <div className="card mt" style={{ background: 'var(--wash-low)', borderColor: '#A6C2B0' }}><strong>✓ Path complete.</strong> Nicely done — every lesson read and every case cleared.</div>}
      </div>

      {lessonIdx != null && (
        <LessonModal path={path} idx={lessonIdx} onClose={() => setLessonIdx(null)}
          onComplete={() => { markLesson(`${path.id}#${lessonIdx}`); onProgress(); setLessonIdx(null); }} />
      )}
    </div>
  );
}

function LessonModal({ path, idx, onClose, onComplete }: { path: LearningPath; idx: number; onClose: () => void; onComplete: () => void }) {
  const step = path.steps[idx];
  const art = step.kb ? KB.find((a) => a.id === step.kb) : null;
  const check = step.kb ? KB_CHECKS[step.kb] : undefined;
  const [picked, setPicked] = useState<number | null>(null);
  const answered = picked != null;

  return (
    <Modal title={art?.title ?? 'Lesson'} onClose={onClose} wide
      footer={<>
        <button className="btn ghost" onClick={onClose}>Close</button>
        <button className="btn primary" disabled={!!check && !answered} onClick={onComplete}>
          {check && !answered ? 'Answer the check to continue' : 'Mark complete ✓'}
        </button>
      </>}>
      <div className="pill-row mb">{art?.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>
      <div style={{ whiteSpace: 'pre-wrap', fontSize: 13.5, lineHeight: 1.6, maxHeight: '40vh', overflowY: 'auto', paddingRight: 8 }}>{art?.body}</div>
      {check && (
        <div className="card mt" style={{ background: 'var(--surface-2)' }}>
          <h4>Knowledge check</h4>
          <div className="small mb">{check.q}</div>
          {check.options.map((o, i) => {
            const cls = !answered ? '' : i === check.answer ? 'check-correct' : i === picked ? 'check-wrong' : '';
            return <button key={i} className={`reply-opt ${cls}`} disabled={answered} onClick={() => setPicked(i)}>{o}</button>;
          })}
          {answered && (
            <div className="small mt" style={{ color: picked === check.answer ? 'var(--green)' : 'var(--amber)' }}>
              {picked === check.answer ? '✓ Correct. ' : '✗ Not quite. '}{check.explain}
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
