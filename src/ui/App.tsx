import React, { useEffect, useState } from 'react';
import { ToastProvider } from './common';
import { Home } from './Home';
import { Play } from './Play';
import { Report } from './Report';
import { getScenario } from '../scenarios';

type Route = { name: 'home' } | { name: 'play'; scenarioId: string } | { name: 'report' };

function routeFromHash(): Route {
  if (typeof location !== 'undefined' && location.hash === '#report') return { name: 'report' };
  const m = typeof location !== 'undefined' ? location.hash.match(/#play=([\w-]+)/) : null;
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
      {route.name === 'home' && <Home onPlay={(id) => go({ name: 'play', scenarioId: id })} onReport={() => go({ name: 'report' })} />}
      {route.name === 'report' && <Report onExit={() => go({ name: 'home' })} />}
      {route.name === 'play' && <Play scenarioId={route.scenarioId} onExit={() => go({ name: 'home' })} onReplay={() => go({ name: 'home' })} />}
    </ToastProvider>
  );
}
