import React, { useState } from 'react';
import { useSession } from '../../engine/session';
import { useToast } from '../common';

type Where = 'firewall' | 'proxy' | 'email' | 'dns';

export function Perimeter() {
  const { world, act } = useSession();
  const toast = useToast();
  const [ind, setInd] = useState('');
  const [where, setWhere] = useState<Where>('firewall');

  function block() {
    const i = ind.trim();
    if (!i) return;
    act({ tool: 'perimeter', action: 'block', target: i, params: { where }, label: `Blocked ${i} at ${where}` }, (w) => {
      w.blocklist.push({ indicator: i, where, by: 'you' });
    });
    toast(`Blocked ${i} at the ${where}`, 'good');
    setInd('');
  }

  return (
    <div>
      <div className="card">
        <h4>Block an indicator</h4>
        <div className="small dim mb">Block a confirmed-malicious IP, domain, URL or sender at the right control point.</div>
        <div className="field-row">
          <input value={ind} onChange={(e) => setInd(e.target.value)} placeholder="IP, domain, URL or sender…" onKeyDown={(e) => { if (e.key === 'Enter') block(); }} />
          <select value={where} onChange={(e) => setWhere(e.target.value as Where)} style={{ maxWidth: 130 }}>
            <option value="firewall">Firewall</option><option value="proxy">Proxy</option><option value="email">Mail gateway</option><option value="dns">DNS sinkhole</option>
          </select>
          <button className="btn" onClick={block}>Block</button>
        </div>
      </div>

      <div className="card">
        <h4>Current firewall rules</h4>
        <table className="data"><thead><tr><th>ID</th><th>Action</th><th>Src</th><th>Dst</th><th>Port</th><th>Comment</th></tr></thead>
          <tbody>{world.firewall.map((r) => <tr key={r.id}><td className="mono">{r.id}</td><td style={{ color: r.action === 'deny' ? 'var(--red)' : 'var(--green)' }}>{r.action}</td><td className="mono tiny">{r.src}</td><td className="mono tiny">{r.dst}</td><td className="mono">{r.port}</td><td className="dim tiny">{r.comment}</td></tr>)}</tbody>
        </table>
      </div>

      {world.blocklist.length > 0 && (
        <div className="card">
          <h4>Blocks you've added</h4>
          <table className="data"><thead><tr><th>Indicator</th><th>Where</th></tr></thead>
            <tbody>{world.blocklist.map((b, i) => <tr key={i}><td className="mono">{b.indicator}</td><td>{b.where}</td></tr>)}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}
