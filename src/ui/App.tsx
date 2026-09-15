import React, { useState } from 'react';
import { ToastProvider } from './common';
import { Home } from './Home';
import { Play } from './Play';

type Route = { name: 'home' } | { name: 'play'; scenarioId: string };

export function App() {
  const [route, setRoute] = useState<Route>({ name: 'home' });
  return (
    <ToastProvider>
      {route.name === 'home'
        ? <Home onPlay={(id) => setRoute({ name: 'play', scenarioId: id })} />
        : <Play scenarioId={route.scenarioId} onExit={() => setRoute({ name: 'home' })}
            onReplay={(id) => setRoute({ name: 'home' })} />}
    </ToastProvider>
  );
}
