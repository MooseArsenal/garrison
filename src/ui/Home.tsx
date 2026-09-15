import React, { useMemo, useState } from 'react';
import { TIER_LABELS, TIER_ORDER, type Tier } from '../engine/types';
import { SCENARIOS_BY_TIER, SCENARIO_IDS_BY_TIER, ALL_SCENARIOS } from '../scenarios';
import { loadProgress, loadSettings, saveSettings, resetProgress, tierUnlocked, type Settings } from '../engine/progress';
import { Diff, Modal, Pri, useToast } from './common';

const TIER_DESC: Record<Tier, string> = {
  sd1: 'Front line. Password resets, hardware, printers, phishing triage. Verify, fix, or escalate cleanly.',
  sd2: 'Deeper desktop and network. Cached credentials, malware cleanup boundaries, access control, Kerberos.',
  soc1: 'Alert triage. Classify true/false/benign, run playbooks, contain a single endpoint or account.',
  soc2: 'Investigation and hunting. BEC, cross-estate scoping, insider cases, server-level containment.',
  cirt: 'Incident command. Ransomware, domain compromise, third-party breaches, lifecycle and notifications.',
};

export function Home({ onPlay }: { onPlay: (id: string) => void }) {
  const [progress, setProgress] = useState(loadProgress());
  const [settings, setSettings] = useState<Settings>(loadSettings());
  const [showSettings, setShowSettings] = useState(false);
  const toast = useToast();

  const stats = useMemo(() => {
    const attempted = Object.keys(progress.scenarios).length;
    const passed = Object.values(progress.scenarios).filter((s) => s.passed).length;
    const avg = progress.history.length
      ? Math.round(progress.history.reduce((a, h) => a + h.score, 0) / progress.history.length)
      : 0;
    return { attempted, passed, total: ALL_SCENARIOS.length, avg };
  }, [progress]);

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
            <div className="sub">IT &amp; Security Operations Trainer · Service Desk → SOC → CIRT</div>
          </div>
        </div>
        <button className="btn ghost sm" onClick={() => setShowSettings(true)}>⚙ Settings</button>
      </div>

      <div className="stat-row">
        <div className="stat"><div className="n">{stats.passed}/{stats.total}</div><div className="l">Scenarios passed</div></div>
        <div className="stat"><div className="n">{stats.attempted}</div><div className="l">Attempted</div></div>
        <div className="stat"><div className="n">{stats.avg || '—'}</div><div className="l">Avg score</div></div>
        <div className="stat"><div className="n">{progress.history.length}</div><div className="l">Total attempts</div></div>
      </div>

      <div className="ladder">
        {TIER_ORDER.map((tier, i) => {
          const scenarios = SCENARIOS_BY_TIER[tier];
          const unlocked = tierUnlocked(tier, SCENARIO_IDS_BY_TIER, progress, settings);
          const passed = scenarios.filter((s) => progress.scenarios[s.id]?.passed).length;
          const pct = Math.round((passed / scenarios.length) * 100);
          return (
            <div className="tier-card" key={tier}>
              <div className="tier-head">
                <div className="num">{i + 1}</div>
                <div className="tt">
                  <div className="name">{TIER_LABELS[tier]}</div>
                  <div className="desc">{TIER_DESC[tier]}</div>
                </div>
                {unlocked ? (
                  <div className="tier-progress">
                    <div className="bar"><span style={{ width: `${pct}%` }} /></div>
                    <span className="small dim nowrap">{passed}/{scenarios.length}</span>
                  </div>
                ) : (
                  <div className="tier-locked">🔒 Pass 75% of {TIER_LABELS[TIER_ORDER[i - 1]]}</div>
                )}
              </div>
              <div className="scen-grid">
                {scenarios.map((s) => {
                  const p = progress.scenarios[s.id];
                  return (
                    <button key={s.id} className={`scen-card ${unlocked ? '' : 'locked'}`} disabled={!unlocked}
                      onClick={() => onPlay(s.id)}>
                      <div className="row1">
                        <span className="cat">{s.category}</span>
                        {p && <span className={`best ${p.passed ? 'pass' : 'fail'}`}>{p.best}</span>}
                      </div>
                      <div className="title">{s.title}</div>
                      <div className="obj">{s.objective}</div>
                      <div className="meta">
                        <Diff n={s.difficulty} />
                        <span>~{s.estMinutes} min</span>
                        {p ? <span className="dim">· {p.attempts} attempt{p.attempts > 1 ? 's' : ''}</span> : <span className="dim">· new</span>}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
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
            <span>Unlock all tiers (practice mode)</span>
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
