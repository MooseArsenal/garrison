import React, { useState } from 'react';
import { useSession } from '../../engine/session';

export function Kb() {
  const { world, act } = useSession();
  const [q, setQ] = useState('');
  const [openId, setOpenId] = useState<string | null>(null);
  const list = world.kb.filter((a) => {
    if (!q) return true;
    const hay = (a.title + ' ' + a.tags.join(' ') + ' ' + a.body).toLowerCase();
    return q.toLowerCase().split(/\s+/).every((t) => hay.includes(t));
  });
  const open = openId ? world.kb.find((a) => a.id === openId) : null;

  if (open) {
    return (
      <div>
        <button className="btn ghost sm mb" onClick={() => setOpenId(null)}>← All articles</button>
        <div className="card">
          <div className="small dim mono">{open.id}</div>
          <h3 style={{ margin: '4px 0 10px' }}>{open.title}</h3>
          <div className="pill-row mb">{open.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>
          <div style={{ whiteSpace: 'pre-wrap', fontSize: 13.5, lineHeight: 1.6 }}>{open.body}</div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="searchbar">
        <input value={q} onChange={(e) => { setQ(e.target.value); if (e.target.value) act({ tool: 'kb', action: 'search', params: { q: e.target.value }, label: `KB search "${e.target.value}"` }); }} placeholder="Search SOPs and guides (e.g. verification, phishing, dhcp)…" autoFocus />
      </div>
      {list.map((a) => (
        <button key={a.id} className="list-item" style={{ width: '100%', textAlign: 'left' }}
          onClick={() => { setOpenId(a.id); act({ tool: 'kb', action: 'read', target: a.id, label: `Read ${a.id}: ${a.title}` }); }}>
          <div className="grow">
            <div className="t">{a.title}</div>
            <div className="s mono">{a.id} · {a.tags.slice(0, 5).join(', ')}</div>
          </div>
          <span className="dim">›</span>
        </button>
      ))}
      {list.length === 0 && <div className="empty">No articles match “{q}”.</div>}
    </div>
  );
}
