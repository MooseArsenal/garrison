import React, { useMemo, useRef, useState, useEffect, useCallback } from 'react';
import { TIER_LABELS, type Action, type GradeResult, type TicketState, type World } from '../engine/types';
import { getScenario } from '../scenarios';
import { buildWorld, cloneWorld } from '../engine/world';
import { grade } from '../engine/grading';
import { SessionContext, initialTicket, TIER_TOOLS, TOOL_META, type Session } from '../engine/session';
import { recordResult } from '../engine/progress';
import { Modal, useToast, Diff } from './common';
import { Briefing } from './Briefing';
import { Debrief } from './Debrief';
import { WorkPanel } from './WorkPanel';
import { TOOL_COMPONENTS } from './tools';

const BASE = buildWorld();

export function Play({ scenarioId, onExit }: { scenarioId: string; onExit: () => void; onReplay: (id: string) => void }) {
  const scenario = getScenario(scenarioId)!;
  const toast = useToast();
  const worldRef = useRef<World | null>(null);
  if (!worldRef.current) {
    const w = cloneWorld(BASE);
    scenario.setup(w);
    worldRef.current = w;
  }
  const actionsRef = useRef<Action[]>([]);
  const uiRef = useRef<Record<string, unknown>>({});
  const startRef = useRef<number>(Date.now());
  const [version, setVersion] = useState(0);
  const [ticket, setTicketState] = useState<TicketState>(() => initialTicket(scenario));
  const [notices, setNotices] = useState<{ t: number; text: string }[]>([]);
  const [phase, setPhase] = useState<'brief' | 'work' | 'debrief'>('brief');
  const [activeTool, setActiveTool] = useState<string>('queue');
  const [result, setResult] = useState<GradeResult | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const firedTimers = useRef<Set<number>>(new Set());

  const tools = useMemo(() => {
    const base = TIER_TOOLS[scenario.tier] ?? [];
    const extra = scenario.tools ?? [];
    return Array.from(new Set([...base, ...extra]));
  }, [scenario]);

  const touch = useCallback(() => setVersion((v) => v + 1), []);

  const act = useCallback<Session['act']>((a, effect) => {
    const action: Action = { ...a, t: Date.now() - startRef.current };
    actionsRef.current.push(action);
    if (effect) effect(worldRef.current!);
    setVersion((v) => v + 1);
  }, []);

  const setTicket = useCallback((patch: Partial<TicketState>) => {
    setTicketState((t) => ({ ...t, ...patch }));
  }, []);

  // timer + scenario timeline
  useEffect(() => {
    if (phase !== 'work') return;
    const iv = setInterval(() => {
      const secs = Math.floor((Date.now() - startRef.current) / 1000);
      setElapsed(secs);
      for (const ev of scenario.timeline ?? []) {
        if (secs >= ev.atSec && !firedTimers.current.has(ev.atSec)) {
          firedTimers.current.add(ev.atSec);
          ev.event(worldRef.current!);
          setVersion((v) => v + 1);
          if (ev.notice) { setNotices((n) => [...n, { t: secs, text: ev.notice! }]); toast(ev.notice!, 'info'); }
        }
      }
    }, 1000);
    return () => clearInterval(iv);
  }, [phase, scenario, toast]);

  const session: Session = {
    scenario, world: worldRef.current!, actions: actionsRef.current, ticket,
    startedAt: startRef.current, version, notices, act, setTicket, touch, ui: uiRef.current,
  };

  function beginWork() {
    startRef.current = Date.now();
    // record the intake open
    act({ tool: 'ticket', action: 'open', target: scenario.intake.kind === 'ticket' ? scenario.intake.number : scenario.intake.kind === 'incident' ? scenario.intake.number : scenario.intake.alertId, label: 'Opened the case' });
    setPhase('work');
  }

  function submit() {
    const elapsedSec = Math.floor((Date.now() - startRef.current) / 1000);
    const r = grade(scenario, worldRef.current!, actionsRef.current, ticket, elapsedSec);
    setResult(r);
    const skills = Object.fromEntries(r.skills.map((s) => [s.skill, s.score]));
    recordResult(scenario.id, r.overall, skills);
    setPhase('debrief');
  }

  if (phase === 'brief') {
    return (
      <SessionContext.Provider value={session}>
        <Briefing onStart={beginWork} onExit={onExit} />
      </SessionContext.Provider>
    );
  }

  if (phase === 'debrief' && result) {
    return (
      <SessionContext.Provider value={session}>
        <Debrief result={result} onExit={onExit} onRetry={() => window.location.reload()} />
      </SessionContext.Provider>
    );
  }

  const ToolComp = TOOL_COMPONENTS[activeTool] ?? (() => <div className="empty">Tool not available.</div>);
  const mm = String(Math.floor(elapsed / 60)).padStart(2, '0');
  const ss = String(elapsed % 60).padStart(2, '0');

  return (
    <SessionContext.Provider value={session}>
      <div className="play">
        <div className="topbar">
          <button className="btn ghost home-btn" title="Exit to menu" onClick={() => { if (confirm('Exit without submitting? Progress on this scenario is lost.')) onExit(); }}>←</button>
          <div className="tt">{scenario.title}<small>{TIER_LABELS[scenario.tier]}</small></div>
          <div className="spacer" />
          <span className="timer">⏱ {mm}:{ss}</span>
        </div>

        <div className="rail">
          {tools.map((id) => {
            const meta = TOOL_META[id];
            if (!meta) return null;
            const alertDot = id === 'queue' && ticket.disposition === 'pending';
            return (
              <button key={id} className={activeTool === id ? 'active' : ''} onClick={() => setActiveTool(id)}>
                {meta.icon}
                <span className="lbl">{meta.label}</span>
                {alertDot && <span className="dot" />}
              </button>
            );
          })}
        </div>

        <div className="main">
          <div className="tool" key={activeTool}>
            <h2 className="tool-title">{TOOL_META[activeTool]?.icon} {TOOL_META[activeTool]?.label}</h2>
            <div className="tool-blurb">{TOOL_META[activeTool]?.blurb}</div>
            <ToolComp />
          </div>
        </div>

        <WorkPanel onSubmit={submit} goToQueue={() => setActiveTool('queue')} />
      </div>
    </SessionContext.Provider>
  );
}
