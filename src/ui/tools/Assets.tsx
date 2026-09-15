import React from 'react';
import { useSession, usePersisted } from '../../engine/session';
import type { Asset } from '../../engine/types';
import { useToast } from '../common';

export function Assets() {
  const { world, act } = useSession();
  const toast = useToast();
  const [q, setQ] = usePersisted('asset.q', '');
  const [sel, setSel] = usePersisted<string | null>('asset.sel', null);
  const a = sel ? world.assets.find((x) => x.tag === sel) : null;
  const list = world.assets.filter((x) => !q || (x.tag + ' ' + x.model + ' ' + x.serial + ' ' + (x.assignedTo ?? '') + ' ' + (x.hostname ?? '') + ' ' + x.type + ' ' + x.status).toLowerCase().includes(q.toLowerCase()));

  function doAct(action: string, label: string, params?: Record<string, string>, effect?: (x: Asset) => void) {
    act({ tool: 'assets', action, target: a!.tag, params, label }, (w) => { const x = w.assets.find((y) => y.tag === a!.tag); if (x && effect) effect(x); });
    toast(label, 'good');
  }

  if (a) {
    return (
      <div>
        <button className="btn ghost sm mb" onClick={() => setSel(null)}>← All assets</button>
        <dl className="kv card">
          <dt>Tag</dt><dd className="mono">{a.tag}</dd><dt>Type</dt><dd>{a.type}</dd><dt>Model</dt><dd>{a.model}</dd>
          <dt>Serial</dt><dd className="mono">{a.serial}</dd><dt>Assigned to</dt><dd>{a.assignedTo ?? '—'}</dd><dt>Hostname</dt><dd className="mono">{a.hostname ?? '—'}</dd>
          <dt>Status</dt><dd>{a.status}</dd><dt>Location</dt><dd>{a.location}</dd>
          <dt>Purchased</dt><dd>{a.purchaseDate.slice(0, 10)}</dd>
          <dt>Warranty ends</dt><dd style={new Date(a.warrantyEnd) < new Date(world.now) ? { color: 'var(--amber)' } : { color: 'var(--green)' }}>{a.warrantyEnd.slice(0, 10)} {new Date(a.warrantyEnd) < new Date(world.now) ? '(out of warranty)' : '(in warranty)'}</dd>
          {a.notes && <><dt>Notes</dt><dd>{a.notes}</dd></>}
        </dl>
        <div className="card">
          <h4>Actions</h4>
          <div className="pill-row">
            <select onChange={(e) => { if (e.target.value) doAct('set_status', `Set ${a.tag} status: ${e.target.value}`, { status: e.target.value }, (x) => { x.status = e.target.value as Asset['status']; }); }} defaultValue="">
              <option value="" disabled>Set status…</option>
              {['deployed', 'in stock', 'repair', 'retired', 'lost/stolen'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <button className="btn sm" onClick={() => doAct('dispatch_vendor', `Dispatched vendor for ${a.tag}`)}>Dispatch vendor</button>
            <button className="btn sm" onClick={() => { const u = prompt('Assign to user id:'); if (u) doAct('assign', `Assigned ${a.tag} to ${u}`, { user: u }, (x) => { x.assignedTo = u; x.status = 'deployed'; }); }}>Assign</button>
            <button className="btn sm" onClick={() => doAct('unassign', `Unassigned ${a.tag}`, undefined, (x) => { x.assignedTo = undefined; })}>Unassign</button>
            <button className="btn sm" onClick={() => { const u = prompt('Ship to user id:'); if (u) doAct('ship', `Shipped ${a.tag} to ${u} (return label included)`, { user: u }); }}>Ship</button>
            <button className="btn sm danger" onClick={() => doAct('remote_wipe', `Remote-wiped ${a.tag}`)}>Remote wipe</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="searchbar"><input value={q} onChange={(e) => { setQ(e.target.value); if (e.target.value) act({ tool: 'assets', action: 'search', params: { q: e.target.value }, label: `Asset search "${e.target.value}"` }); }} placeholder="Search assets (tag, serial, owner, hostname, 'in stock')…" autoFocus /></div>
      <table className="data">
        <thead><tr><th>Tag</th><th>Type</th><th>Model</th><th>Assigned</th><th>Status</th><th>Location</th></tr></thead>
        <tbody>
          {list.map((x) => (
            <tr key={x.tag} className="clickable" onClick={() => { setSel(x.tag); act({ tool: 'assets', action: 'view', target: x.tag, label: `Viewed asset ${x.tag}` }); }}>
              <td className="mono">{x.tag}</td><td className="dim">{x.type}</td><td>{x.model}</td><td>{x.assignedTo ?? '—'}</td>
              <td style={x.status === 'in stock' ? { color: 'var(--green)' } : x.status === 'lost/stolen' ? { color: 'var(--red)' } : undefined}>{x.status}</td><td className="dim">{x.location}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
