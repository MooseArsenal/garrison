import React from 'react';
import { useSession, usePersisted } from '../../engine/session';
import { fmt } from '../../engine/world';
import type { Server } from '../../engine/types';
import { useToast } from '../common';

export function ServerRoom() {
  const { world, act } = useSession();
  const toast = useToast();
  const [sel, setSel] = usePersisted<string | null>('srv.sel', null);
  const [tab, setTab] = usePersisted<string>('srv.tab', 'overview');
  const srv = sel ? world.servers.find((s) => s.id === sel) : null;

  function doAct(action: string, label: string, params?: Record<string, string>, effect?: (s: Server) => void) {
    act({ tool: 'server', action, target: srv!.id, params, label }, (w) => { const s = w.servers.find((x) => x.id === srv!.id); if (s && effect) effect(s); });
    toast(label, 'good');
  }

  if (!srv) {
    return (
      <table className="data">
        <thead><tr><th>Server</th><th>Role</th><th>IP</th><th>Status</th><th>OS</th></tr></thead>
        <tbody>
          {world.servers.map((s) => (
            <tr key={s.id} className={`clickable ${s.status === 'offline' ? 'bad' : s.status === 'degraded' ? 'warn' : ''}`}
              onClick={() => { setSel(s.id); setTab('overview'); act({ tool: 'server', action: 'view', target: s.id, label: `Viewed ${s.id}` }); }}>
              <td className="mono">{s.id}</td><td>{s.role}</td><td className="mono">{s.ip}</td>
              <td style={{ color: s.status === 'online' ? 'var(--green)' : s.status === 'degraded' ? 'var(--amber)' : 'var(--red)' }}>{s.status}</td><td className="dim">{s.os}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview' }, { id: 'services', label: 'Services' },
    ...(srv.dhcpScopes ? [{ id: 'dhcp', label: 'DHCP' }] : []),
    ...(srv.dnsRecords ? [{ id: 'dns', label: 'DNS' }] : []),
    ...(srv.printQueues ? [{ id: 'print', label: 'Print Queues' }] : []),
    ...(srv.shares ? [{ id: 'shares', label: 'Shares' }] : []),
    ...(srv.backups ? [{ id: 'backups', label: 'Backups' }] : []),
    ...(srv.processes ? [{ id: 'procs', label: 'Processes' }] : []),
  ];

  return (
    <div>
      <div className="flex mb"><button className="btn ghost sm" onClick={() => setSel(null)}>← Servers</button><span className="mono" style={{ fontWeight: 600 }}>{srv.id}</span><span className="small dim">{srv.role}</span></div>
      <div className="tabs">{tabs.map((t) => <button key={t.id} className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>{t.label}</button>)}</div>

      {tab === 'overview' && (
        <dl className="kv card">
          <dt>Status</dt><dd>{srv.status}</dd><dt>IP</dt><dd className="mono">{srv.ip}</dd><dt>OS</dt><dd>{srv.os}</dd>
          <dt>CPU / Mem</dt><dd>{srv.cpu}% / {srv.mem}%</dd><dt>Uptime</dt><dd>{Math.floor(srv.uptimeHours / 24)}d {srv.uptimeHours % 24}h</dd>
          <dt>Disks</dt><dd>{srv.disk.map((d) => `${d.drive} ${d.used}/${d.size}GB`).join(' · ')}</dd>
          {srv.notes && <><dt>Notes</dt><dd style={{ color: 'var(--amber)' }}>{srv.notes}</dd></>}
        </dl>
      )}
      {tab === 'services' && (
        <table className="data"><thead><tr><th>Service</th><th>Status</th><th></th></tr></thead>
          <tbody>{srv.services.map((s) => (
            <tr key={s.name} className={s.suspicious ? 'bad' : ''}><td>{s.displayName} <span className="tiny dim mono">{s.name}</span></td>
              <td style={{ color: s.status === 'running' ? 'var(--green)' : 'var(--red)' }}>{s.status}</td>
              <td className="pill-row">
                {s.status === 'running' ? <button className="btn sm" onClick={() => doAct('restart_service', `Restarted ${s.displayName} on ${srv.id}`, { service: s.name })}>Restart</button> : <button className="btn sm" onClick={() => doAct('start_service', `Started ${s.displayName}`, { service: s.name }, (x) => { x.services.find((y) => y.name === s.name)!.status = 'running'; })}>Start</button>}
                {s.status === 'running' && <button className="btn sm" onClick={() => doAct('stop_service', `Stopped ${s.displayName}`, { service: s.name }, (x) => { x.services.find((y) => y.name === s.name)!.status = 'stopped'; })}>Stop</button>}
              </td></tr>
          ))}</tbody>
        </table>
      )}
      {tab === 'dhcp' && (
        <table className="data"><thead><tr><th>Scope</th><th>Range</th><th>Used</th><th>Lease</th><th>Status</th><th></th></tr></thead>
          <tbody>{srv.dhcpScopes!.map((sc) => (
            <tr key={sc.name} className={sc.status === 'exhausted' ? 'bad' : ''}>
              <td>{sc.name}</td><td className="mono tiny">{sc.range}</td><td className="mono">{sc.used}/{sc.total}{sc.used >= sc.total ? ' (FULL)' : ''}</td><td className="dim">{sc.leaseHours}h</td>
              <td style={{ color: sc.status === 'active' ? 'var(--green)' : 'var(--red)' }}>{sc.status}</td>
              <td className="pill-row">
                <button className="btn sm" onClick={() => doAct('extend_scope', `Extended scope ${sc.name}`, { scope: sc.name }, (x) => { const s2 = x.dhcpScopes!.find((y) => y.name === sc.name)!; s2.total += 100; s2.status = 'active'; })}>Extend</button>
                <button className="btn sm" onClick={() => doAct('reduce_lease', `Reduced lease time on ${sc.name}`, { scope: sc.name })}>Reduce lease</button>
              </td></tr>
          ))}</tbody>
        </table>
      )}
      {tab === 'dns' && (
        <table className="data"><thead><tr><th>Name</th><th>Type</th><th>Value</th></tr></thead>
          <tbody>{srv.dnsRecords!.map((r, i) => <tr key={i}><td className="mono">{r.name}</td><td>{r.type}</td><td className="mono">{r.value}</td></tr>)}</tbody>
        </table>
      )}
      {tab === 'print' && (
        <table className="data"><thead><tr><th>Queue</th><th>Location</th><th>Status</th><th>Jobs</th><th></th></tr></thead>
          <tbody>{srv.printQueues!.map((p) => (
            <tr key={p.name} className={p.status === 'error' || p.status === 'offline' ? 'bad' : p.status === 'paused' ? 'warn' : ''}>
              <td>{p.name}</td><td className="dim">{p.location}</td><td>{p.status}{p.error ? ` — ${p.error}` : ''}</td><td className="mono">{p.jobs}</td>
              <td className="pill-row">
                {p.status === 'paused' && <button className="btn sm" onClick={() => doAct('resume_queue', `Resumed ${p.name}`, { queue: p.name }, (x) => { x.printQueues!.find((y) => y.name === p.name)!.status = 'ready'; })}>Resume</button>}
                {p.jobs > 0 && <button className="btn sm" onClick={() => doAct('clear_queue', `Cleared ${p.name} queue`, { queue: p.name }, (x) => { x.printQueues!.find((y) => y.name === p.name)!.jobs = 0; })}>Clear jobs</button>}
              </td></tr>
          ))}</tbody>
        </table>
      )}
      {tab === 'shares' && (
        <table className="data"><thead><tr><th>Share</th><th>Path</th><th>NTFS groups</th><th>Status</th></tr></thead>
          <tbody>{srv.shares!.map((s) => <tr key={s.name}><td>{s.name}</td><td className="mono tiny">{s.path}</td><td>{s.ntfsGroups.join(', ')}</td><td style={{ color: s.status === 'ok' ? 'var(--green)' : 'var(--red)' }}>{s.status}</td></tr>)}</tbody>
        </table>
      )}
      {tab === 'backups' && (
        <table className="data"><thead><tr><th>Job</th><th>Last run</th><th>Status</th><th>Restore pts</th><th></th></tr></thead>
          <tbody>{srv.backups!.map((b) => (
            <tr key={b.job} className={b.status === 'failed' ? 'bad' : b.status === 'warning' ? 'warn' : ''}>
              <td>{b.job}</td><td className="mono nowrap">{fmt(b.lastRun)}</td><td style={{ color: b.status === 'success' ? 'var(--green)' : b.status === 'failed' ? 'var(--red)' : 'var(--amber)' }}>{b.status}</td><td className="mono">{b.restorePoints}</td>
              <td><button className="btn sm" onClick={() => doAct('restore', `Restored from ${b.job}`, { job: b.job })}>Restore</button></td></tr>
          ))}</tbody>
        </table>
      )}
      {tab === 'procs' && (
        <table className="data"><thead><tr><th>Name</th><th>PID</th><th>User</th><th>Path / cmd</th><th></th></tr></thead>
          <tbody>{srv.processes!.map((p) => (
            <tr key={p.pid} className={p.signed === false ? 'bad' : ''}><td>{p.name}</td><td className="mono">{p.pid}</td><td className="dim">{p.user.replace('KESTREL\\', '')}</td><td className="mono tiny">{p.cmdline ?? p.path}</td>
              <td><button className="btn sm danger" onClick={() => doAct('end_process', `Killed ${p.name} on ${srv.id}`, { name: p.name }, (x) => { x.processes = x.processes!.filter((y) => y.pid !== p.pid); })}>End</button></td></tr>
          ))}</tbody>
        </table>
      )}
    </div>
  );
}
