import React, { useEffect, useState } from 'react';
import { ToastProvider } from './common';
import { Home } from './Home';
import { Play } from './Play';
import { Report } from './Report';
import { Shift } from './Shift';
import { Paths } from './Paths';
import { Teacher } from './Teacher';
import { AssignmentView } from './Assignment';
import { decodeAssignment, type Assignment } from '../engine/assignments';
import { getScenario } from '../scenarios';

type Route = { name: 'home' } | { name: 'play'; scenarioId: string } | { name: 'report' } | { name: 'learn' } | { name: 'teacher' } | { name: 'assign'; assignment: Assignment } | { name: 'shift'; scope: string[]; label: string };

function routeFromHash(): Route {
  const h = typeof location !== 'undefined' ? location.hash : '';
  if (h === '#report') return { name: 'report' };
  if (h === '#learn') return { name: 'learn' };
  if (h === '#teach') return { name: 'teacher' };
  if (h.startsWith('#assign=')) { const a = decodeAssignment(h.slice('#assign='.length)); if (a) return { name: 'assign', assignment: a }; }
  const m = h.match(/#play=([\w-]+)/);
  if (m && getScenario(m[1])) return { name: 'play', scenarioId: m[1] };
  return { name: 'home' };
}

export function App() {
  const [route, setRoute] = useState<Route>(routeFromHash);
  useEffect(() => {
    const onHash = () => setRoute(routeFromHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  function go(r: Route) {
    if (r.name === 'home' && location.hash) location.hash = '';
    setRoute(r);
  }
  return (
    <ToastProvider>
      {route.name === 'home' && <Home onPlay={(id) => go({ name: 'play', scenarioId: id })} onReport={() => go({ name: 'report' })} onLearn={() => go({ name: 'learn' })} onTeach={() => go({ name: 'teacher' })} onStartShift={(scope, label) => go({ name: 'shift', scope, label })} />}
      {route.name === 'report' && <Report onExit={() => go({ name: 'home' })} />}
      {route.name === 'learn' && <Paths onPlay={(id) => go({ name: 'play', scenarioId: id })} onExit={() => go({ name: 'home' })} />}
      {route.name === 'teacher' && <Teacher onExit={() => go({ name: 'home' })} />}
      {route.name === 'assign' && <AssignmentView assignment={route.assignment} onExit={() => go({ name: 'home' })} />}
      {route.name === 'shift' && <Shift scope={route.scope} label={route.label} onExit={() => go({ name: 'home' })} />}
      {route.name === 'play' && <Play scenarioId={route.scenarioId} onExit={() => go({ name: 'home' })} onReplay={() => go({ name: 'home' })} />}
    </ToastProvider>
  );
}
