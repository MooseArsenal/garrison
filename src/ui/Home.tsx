import React, { useMemo, useState } from 'react';
import { TIER_LABELS, TIER_ORDER, type Tier } from '../engine/types';
import { SCENARIOS_BY_TIER, SCENARIO_IDS_BY_TIER, ALL_SCENARIOS } from '../scenarios';
import { loadProgress, loadSettings, saveSettings, resetProgress, tierUnlocked, type Settings } from '../engine/progress';
import { Diff, Modal, Pri, Sev, useToast } from './common';
import { inboxMeta, arrivedAgo } from './inbox';

const TIER_DESC: Record<Tier, string> = {
  sd1: 'Front line. Password resets, hardware, printers, phishing triage. Verify, fix, or escalate cleanly.',
  sd2: 'Deeper desktop and network. Cached credentials, malware boundaries, access control, Kerberos.',
  soc1: 'Alert triage. Classify true/false/benign, run playbooks, contain a single endpoint or account.',
  soc2: 'Investigation and hunting. BEC, cross-estate scoping, insider cases, server-level containment.',
  cirt: 'Incident command. Ransomware, domain compromise, third-party breaches, lifecycle and notifications.',
};

const QUEUE_SIZE = 5;

export function Home({ onPlay, onReport, onLearn, onStartShift }: { onPlay: (id: string) => void; onReport: () => void; onLearn: () => void; onStartShift: (scope: string[], label: string) => void }) {
  const [progress, setProgress] = useState(loadProgress());
  const [settings, setSettings] = useState<Settings>(loadSettings());
  const [showSettings, setShowSettings] = useState(false);
  const [showDone, setShowDone] = useState(false);
  const toast = useToast();

  const unlocked = useMemo(
    () => Object.fromEntries(TIER_ORDER.map((t) => [t, tierUnlocked(t, SCENARIO_IDS_BY_TIER, progress, settings)])) as Record<Tier, boolean>,
    [progress, settings],
  );

  const [tier, setTier] = useState<Tier>(() => {
    // open on the highest unlocked tier that still has unworked items
    for (let i = TIER_ORDER.length - 1; i >= 0; i--) {
      const t = TIER_ORDER[i];
      if (tierUnlocked(t, SCENARIO_IDS_BY_TIER, progress, settings) && SCENARIOS_BY_TIER[t].some((s) => !progress.scenarios[s.id]?.passed)) return t;
    }
    return 'sd1';
  });

  const stats = useMemo(() => {
    const attempted = Object.keys(progress.scenarios).length;
    const passed = Object.values(progress.scenarios).filter((s) => s.passed).length;
    const avg = progress.history.length ? Math.round(progress.history.reduce((a, h) => a + h.score, 0) / progress.history.length) : 0;
    return { attempted, passed, total: ALL_SCENARIOS.length, avg };
  }, [progress]);

  const scenarios = SCENARIOS_BY_TIER[tier];
  const unpassed = scenarios.filter((s) => !progress.scenarios[s.id]?.passed)
    .sort((a, b) => a.difficulty - b.difficulty || a.id.localeCompare(b.id));
  const done = scenarios.filter((s) => progress.scenarios[s.id]?.passed);
  const queue = unpassed.slice(0, QUEUE_SIZE);
  const waiting = unpassed.length - queue.length;
  const isUnlocked = unlocked[tier];

  function updateSettings(patch: Partial<Settings>) {
    const next = { ...settings, ...patch };
    setSettings(next); saveSettings(next);
  }

  return (
    <div className="home">
      <div className="brandbar">
        <div className="brand">
          <div className="logo">🛡️</div>
          <div>
            <h1>Garrison</h1>
            <div className="sub">Shift console · Service Desk → SOC → CIRT</div>
          </div>
        </div>
        <div className="flex" style={{ gap: 8 }}>
          <button className="btn ghost sm" onClick={onLearn}>📚 Learn</button>
          <button className="btn ghost sm" onClick={onReport}>📊 Report card</button>
          <button className="btn ghost sm" onClick={() => setShowSettings(true)}>⚙ Settings</button>
        </div>
      </div>

      <div className="stat-row">
        <div className="stat"><div className="n">{stats.passed}/{stats.total}</div><div className="l">Cases cleared</div></div>
        <div className="stat"><div className="n">{stats.attempted}</div><div className="l">Attempted</div></div>
        <div className="stat"><div className="n">{stats.avg || '—'}</div><div className="l">Avg score</div></div>
        <div className="stat"><div className="n">{progress.history.length}</div><div className="l">Total attempts</div></div>
      </div>

      {/* tier selector */}
      <div className="tier-tabs">
        {TIER_ORDER.map((t, i) => {
          const u = unlocked[t];
          const passed = SCENARIOS_BY_TIER[t].filter((s) => progress.scenarios[s.id]?.passed).length;
          const total = SCENARIOS_BY_TIER[t].length;
          return (
            <button key={t} className={`tier-tab ${tier === t ? 'active' : ''}`} disabled={!u} onClick={() => setTier(t)} title={u ? '' : `Pass 75% of ${TIER_LABELS[TIER_ORDER[i - 1]]} to unlock`}>
              <span className="tt-num">{u ? i + 1 : '🔒'}</span>
              <span className="tt-body">
                <span className="tt-name">{TIER_LABELS[t]}</span>
                <span className="tt-meta">{u ? `${passed}/${total} cleared` : 'locked'}</span>
              </span>
            </button>
          );
        })}
      </div>

      {/* queue */}
      <div className="queue">
        <div className="queue-head">
          <div>
            <h2>Your queue — {TIER_LABELS[tier]}</h2>
            <div className="small dim">{TIER_DESC[tier]}</div>
          </div>
          <div className="flex" style={{ gap: 14 }}>
            {isUnlocked && (
              <button className="btn sm" title="Work a continuous stream of cases from this tier" onClick={() => onStartShift(scenarios.map((s) => s.id), TIER_LABELS[tier])}>▶ Start shift</button>
            )}
            <div className="queue-count">
              <span className="qn">{unpassed.length}</span>
              <span className="ql">in queue</span>
            </div>
          </div>
        </div>

        {!isUnlocked && <div className="empty">🔒 Clear 75% of the previous tier to unlock this queue. (Or turn on practice mode in Settings.)</div>}

        {isUnlocked && queue.length === 0 && (
          <div className="empty">✓ Queue clear for this tier. {done.length > 0 ? 'Review completed cases below to keep sharp, or advance to the next tier.' : ''}</div>
        )}

        {isUnlocked && queue.map((s) => {
          const m = inboxMeta(s);
          const p = progress.scenarios[s.id];
          return (
            <button key={s.id} className="qrow" onClick={() => onPlay(s.id)}>
              <span className="qrow-ic" title={m.channel}>{m.icon}</span>
              <span className="qrow-main">
                <span className="qrow-top">
                  <span className="qrow-chan">{m.channel}</span>
                  <span className="qrow-from">{m.from}{m.fromSub ? <span className="dim"> · {m.fromSub}</span> : ''}</span>
                  <span className="qrow-time">{arrivedAgo(s.id)}</span>
                </span>
                <span className="qrow-subj">{!p && <span className="unread" />}{m.subject}</span>
                <span className="qrow-prev">{m.preview}</span>
              </span>
              <span className="qrow-side">
                {m.tagKind === 'pri' ? <Pri p={m.tag} /> : m.tag.startsWith('SEV') ? <span className={`sev ${m.tag === 'SEV1' ? 'critical' : m.tag === 'SEV2' ? 'high' : 'medium'}`}>{m.tag}</span> : <Sev s={m.tag} />}
                <span className="qrow-cat">{s.category}</span>
                <span className="qrow-diff"><Diff n={s.difficulty} /></span>
                {p && !p.passed && <span className="qrow-attempt">retry · best {p.best}</span>}
              </span>
            </button>
          );
        })}

        {isUnlocked && waiting > 0 && (
          <div className="queue-more">{waiting} more waiting — clear cases at the top of your queue to pull the next.</div>
        )}

        {isUnlocked && done.length > 0 && (
          <div className="queue-done">
            <button className="done-toggle" onClick={() => setShowDone((v) => !v)}>
              {showDone ? '▾' : '▸'} Completed ({done.length}) — replay for practice
            </button>
            {showDone && (
              <div className="done-grid">
                {done.map((s) => {
                  const m = inboxMeta(s);
                  const p = progress.scenarios[s.id]!;
                  return (
                    <button key={s.id} className="done-item" onClick={() => onPlay(s.id)}>
                      <span className="done-ic">{m.icon}</span>
                      <span className="grow"><span className="done-t">{s.title}</span><span className="done-s dim">{s.category}</span></span>
                      <span className="best pass">{p.best}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {showSettings && (
        <Modal title="Settings" onClose={() => setShowSettings(false)}
          footer={<button className="btn" onClick={() => setShowSettings(false)}>Done</button>}>
          <label className="flex" style={{ gap: 10, marginBottom: 14 }}>
            <input type="checkbox" style={{ width: 'auto' }} checked={settings.hintsEnabled} onChange={(e) => updateSettings({ hintsEnabled: e.target.checked })} />
            <span>Show hints during scenarios</span>
          </label>
          <label className="flex" style={{ gap: 10, marginBottom: 14 }}>
            <input type="checkbox" style={{ width: 'auto' }} checked={settings.unlockAll} onChange={(e) => updateSettings({ unlockAll: e.target.checked })} />
            <span>Practice mode — unlock all tiers</span>
          </label>
          <hr className="sep" />
          <button className="btn danger sm" onClick={() => {
            if (confirm('Reset all progress and scores? This cannot be undone.')) {
              resetProgress(); setProgress(loadProgress()); toast('Progress reset', 'info');
            }
          }}>Reset all progress</button>
        </Modal>
      )}
    </div>
  );
}
