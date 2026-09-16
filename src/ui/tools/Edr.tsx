import React from 'react';
import { useSession, usePersisted } from '../../engine/session';
import { fmt } from '../../engine/world';
import type { Host, Proc } from '../../engine/types';
import { useToast } from '../common';
import { suspiciousProc, interestingProc } from '../procHeuristics';

export function Edr() {
  const { world, act } = useSession();
  const toast = useToast();
  const [sel, setSel] = usePersisted<string | null>('edr.sel', null);
  const [tab, setTab] = usePersisted<'tree' | 'net' | 'alerts'>('edr.tab', 'tree');
  const host = sel ? world.hosts.find((h) => h.id === sel) : null;

  const alerts = world.alerts;

  function doAct(action: string, label: string, params?: Record<string, string>, effect?: (h: Host) => void, kind: 'good' | 'bad' = 'good') {
    act({ tool: 'edr', action, target: host!.id, params, label }, (w) => { const h = w.hosts.find((x) => x.id === host!.id); if (h && effect) effect(h); });
    toast(label, kind === 'bad' ? 'bad' : 'good');
  }

  if (!host) {
    return (
      <div>
        <div className="card">
          <h4>Detections</h4>
          {alerts.length === 0 ? <div className="dim small">No Falcon detections.</div> : (
            <table className="data"><thead><tr><th>ID</th><th>Sev</th><th>Title</th><th>Host</th></tr></thead>
              <tbody>{alerts.map((a) => (
                <tr key={a.id} className="clickable" onClick={() => { if (a.host) { setSel(a.host); act({ tool: 'edr', action: 'view_alerts', label: `Reviewed alert ${a.id}` }); } }}>
                  <td className="mono">{a.id}</td><td><span className={`sev ${a.severity}`}>{a.severity}</span></td><td>{a.title}</td><td className="mono">{a.host ?? '—'}</td></tr>
              ))}</tbody>
            </table>
          )}
        </div>
        <h4 className="mt mb">Host management</h4>
        <table className="data">
          <thead><tr><th>Host</th><th>Owner</th><th>Sensor</th><th>Contained</th></tr></thead>
          <tbody>
            {world.hosts.map((h) => (
              <tr key={h.id} className="clickable" onClick={() => { setSel(h.id); setTab('tree'); act({ tool: 'edr', action: 'view_host', target: h.id, label: `Opened ${h.id} in EDR` }); }}>
                <td className="mono">{h.id}</td><td>{h.owner ?? '—'}</td>
                <td style={{ color: h.edrAgent === 'healthy' ? 'var(--green)' : 'var(--red)' }}>{h.edrAgent}</td><td>{h.isolated ? 'yes' : 'no'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  const conns = (host as unknown as { _connections?: { proto: string; local: string; remote: string; state: string; pid: number }[] })._connections ?? [];

  return (
    <div>
      <div className="between mb">
        <div className="flex"><button className="btn ghost sm" onClick={() => setSel(null)}>← Falcon</button><span className="mono" style={{ fontWeight: 600 }}>{host.id}</span>
          <span className="small" style={{ color: host.edrAgent === 'healthy' ? 'var(--green)' : 'var(--red)' }}>sensor {host.edrAgent}</span>
          {host.isolated && <span className="chip" style={{ color: 'var(--red)' }}>network contained</span>}</div>
        <div className="pill-row">
          {!host.isolated ? <button className="btn sm danger" onClick={() => doAct('isolate', `Network-contained ${host.id}`, undefined, (h) => { h.isolated = true; }, 'bad')}>Network Contain</button>
            : <button className="btn sm" onClick={() => doAct('release', `Lifted containment on ${host.id}`, undefined, (h) => { h.isolated = false; })}>Lift Containment</button>}
          <button className="btn sm" onClick={() => doAct('collect_triage', `Collected triage package (RTR) from ${host.id}`)}>Collect triage (RTR)</button>
          <button className="btn sm" onClick={() => doAct('scan', `Ran on-demand scan on ${host.id}`)}>Run scan</button>
        </div>
      </div>
      <div className="tabs">
        <button className={tab === 'tree' ? 'active' : ''} onClick={() => setTab('tree')}>Process tree</button>
        <button className={tab === 'net' ? 'active' : ''} onClick={() => setTab('net')}>Network</button>
      </div>
      {tab === 'tree' && <ProcTree host={host} onView={() => act({ tool: 'edr', action: 'view_tree', target: host.id, label: `Viewed process tree on ${host.id}` })}
        onKill={(name, pid) => doAct('kill_process', `Killed ${name} (PID ${pid})`, { name }, (h) => { h.processes = h.processes.filter((p) => p.pid !== pid && p.parentPid !== pid); })} />}
      {tab === 'net' && (
        <table className="data"><thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th><th>PID</th></tr></thead>
          <tbody>{conns.length === 0 ? <tr><td colSpan={5} className="dim">No flagged connections. Use SIEM for full flow logs.</td></tr> :
            conns.map((c, i) => <tr key={i} className="bad"><td>{c.proto}</td><td className="mono tiny">{c.local}</td><td className="mono tiny">{c.remote}</td><td>{c.state}</td><td className="mono">{c.pid}</td></tr>)}</tbody>
        </table>
      )}
    </div>
  );
}

function ProcTree({ host, onView, onKill }: { host: Host; onView: () => void; onKill: (name: string, pid: number) => void }) {
  React.useEffect(onView, [host.id]);
  const byParent = new Map<number | undefined, Proc[]>();
  for (const p of host.processes) {
    const k = p.parentPid;
    if (!byParent.has(k)) byParent.set(k, []);
    byParent.get(k)!.push(p);
  }
  const roots = host.processes.filter((p) => !p.parentPid || !host.processes.some((x) => x.pid === p.parentPid));
  // Only show interesting roots: LOLBins/Office anchors and anything suspicious, to keep the tree readable
  const interesting = interestingProc;
  const anyInteresting = host.processes.some(interesting);

  function render(p: Proc, depth: number): React.ReactNode {
    const kids = byParent.get(p.pid) ?? [];
    const susp = suspiciousProc(p);
    return (
      <div key={p.pid}>
        <div className={`node ${susp ? 'susp' : ''} between`} style={{ paddingRight: 6 }}>
          <span><strong>{p.name}</strong> <span className="dim">({p.pid})</span> {p.signed === false && <span className="tag" style={{ color: 'var(--red)' }}>unsigned</span>}
            {p.cmdline && <div className="tiny dim" style={{ marginLeft: 14 }}>{p.cmdline}</div>}
            {p.path && !p.cmdline && <div className="tiny dim" style={{ marginLeft: 14 }}>{p.path}</div>}
            {p.hash && <div className="tiny mono" style={{ marginLeft: 14 }}>hash {p.hash}</div>}
          </span>
          <button className="btn sm danger" onClick={() => onKill(p.name, p.pid)}>Kill</button>
        </div>
        {kids.length > 0 && <div className="kids">{kids.map((k) => render(k, depth + 1))}</div>}
      </div>
    );
  }

  const show = anyInteresting
    ? host.processes.filter((p) => interesting(p) && !(p.parentPid != null && host.processes.some((x) => x.pid === p.parentPid && interesting(x))))
    : roots;
  return (
    <div className="tree">
      <div className="small dim mb">{anyInteresting ? 'Suspicious / user-launched processes and their children:' : 'Root processes (nothing flagged):'}</div>
      {show.map((p) => render(p, 0))}
    </div>
  );
}
