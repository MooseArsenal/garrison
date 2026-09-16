import React, { useState, useRef, useEffect } from 'react';
import { useSession, usePersisted } from '../../engine/session';
import { fmt } from '../../engine/world';
import type { Host } from '../../engine/types';
import { runCommand } from '../../engine/terminal';
import { useToast } from '../common';
import { suspiciousProc } from '../procHeuristics';

type RTab = 'tasks' | 'services' | 'events' | 'devices' | 'network' | 'sched' | 'programs' | 'ext' | 'files' | 'terminal';

export function RemoteDesktop() {
  const { world, act, version } = useSession();
  const toast = useToast();
  const [hostId, setHostId] = usePersisted<string | null>('rdp.host', null);
  const [tab, setTab] = usePersisted<RTab>('rdp.tab', 'tasks');
  const [q, setQ] = usePersisted('rdp.q', '');
  const host = hostId ? world.hosts.find((h) => h.id === hostId) : null;

  if (!host) {
    const list = world.hosts.filter((h) => !q || (h.id + ' ' + (h.owner ?? '') + ' ' + h.ip).toLowerCase().includes(q.toLowerCase()));
    return (
      <div>
        <div className="searchbar"><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find a host (hostname, owner, IP)…" autoFocus /></div>
        <table className="data">
          <thead><tr><th>Host</th><th>Owner</th><th>Type</th><th>IP</th><th>Site</th><th>EDR</th><th></th></tr></thead>
          <tbody>
            {list.map((h) => (
              <tr key={h.id} className="clickable" onClick={() => { setHostId(h.id); setTab('tasks'); act({ tool: 'rdp', action: 'connect', target: h.id, label: `Connected to ${h.id}` }); }}>
                <td className="mono">{h.id}</td><td>{h.owner ?? '—'}</td><td className="dim">{h.kind}</td><td className="mono">{h.ip}</td><td className="dim">{h.site}</td>
                <td style={{ color: h.edrAgent === 'healthy' ? 'var(--green)' : 'var(--amber)' }}>{h.edrAgent}{h.isolated ? ' · isolated' : ''}</td>
                <td className="dim">connect ›</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  const tabs: { id: RTab; label: string }[] = [
    { id: 'tasks', label: 'Task Manager' }, { id: 'services', label: 'Services' }, { id: 'events', label: 'Event Viewer' },
    { id: 'devices', label: 'Device Mgr' }, { id: 'network', label: 'Network' }, { id: 'sched', label: 'Scheduled Tasks' },
    { id: 'programs', label: 'Programs' }, { id: 'ext', label: 'Extensions' }, { id: 'files', label: 'Files' }, { id: 'terminal', label: 'Terminal' },
  ];

  return (
    <div>
      <div className="between mb">
        <div className="flex">
          <button className="btn ghost sm" onClick={() => setHostId(null)}>← Hosts</button>
          <span className="mono" style={{ fontWeight: 600 }}>{host.id}</span>
          <span className="small dim">{host.owner ? `${host.owner} · ` : ''}{host.os} · {host.ip}</span>
          {host.isolated && <span className="chip" style={{ color: 'var(--red)' }}>isolated</span>}
        </div>
      </div>
      <div className="tabs">
        {tabs.map((t) => <button key={t.id} className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>{t.label}</button>)}
      </div>
      {tab === 'tasks' && <TaskManager host={host} onView={() => act({ tool: 'rdp', action: 'view_processes', target: host.id, label: `Viewed processes on ${host.id}` })} onKill={(name, pid) => { act({ tool: 'rdp', action: 'end_process', target: host.id, params: { name, pid: String(pid) }, label: `Ended ${name} (PID ${pid})` }, (w) => { const h = w.hosts.find((x) => x.id === host.id)!; h.processes = h.processes.filter((p) => p.pid !== pid && p.parentPid !== pid); }); toast(`Ended ${name}`, 'good'); }} />}
      {tab === 'services' && <ServicesTab host={host} />}
      {tab === 'events' && <EventsTab host={host} />}
      {tab === 'devices' && <DevicesTab host={host} />}
      {tab === 'network' && <NetworkTab host={host} />}
      {tab === 'sched' && <SchedTab host={host} />}
      {tab === 'programs' && <ProgramsTab host={host} />}
      {tab === 'ext' && <ExtTab host={host} />}
      {tab === 'files' && <FilesTab host={host} />}
      {tab === 'terminal' && <Terminal host={host} />}
    </div>
  );
}

function useHostAct(hostId: string) {
  const { act } = useSession();
  const toast = useToast();
  return (action: string, label: string, params?: Record<string, string>, effect?: (h: Host) => void, kind: 'good' | 'info' = 'good') => {
    act({ tool: 'rdp', action, target: hostId, params, label }, (w) => { const h = w.hosts.find((x) => x.id === hostId); if (h && effect) effect(h); });
    toast(label, kind);
  };
}

function TaskManager({ host, onView, onKill }: { host: Host; onView: () => void; onKill: (name: string, pid: number) => void }) {
  useEffect(onView, [host.id]);
  const sorted = [...host.processes].sort((a, b) => b.cpu - a.cpu);
  const susp = (p: Host['processes'][number]) => suspiciousProc(p);
  return (
    <table className="data">
      <thead><tr><th>Name</th><th>PID</th><th>User</th><th>CPU%</th><th>Mem MB</th><th>Path / command line</th><th></th></tr></thead>
      <tbody>
        {sorted.map((p) => (
          <tr key={p.pid} className={susp(p) ? 'bad' : ''}>
            <td>{p.name}{p.signed === false && <span className="tag" style={{ marginLeft: 6, color: 'var(--red)' }}>unsigned</span>}</td>
            <td className="mono">{p.pid}</td><td className="dim">{p.user.replace('KESTREL\\', '')}</td><td className="mono">{p.cpu.toFixed(1)}</td><td className="mono">{p.mem}</td>
            <td className="mono tiny">{p.cmdline ?? p.path}{p.parentPid ? ` (parent ${p.parentPid})` : ''}</td>
            <td><button className="btn sm danger" onClick={() => onKill(p.name, p.pid)}>End</button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ServicesTab({ host }: { host: Host }) {
  const doAct = useHostAct(host.id);
  useEffect(() => { doAct('view_services', `Viewed services on ${host.id}`, undefined, undefined, 'info'); }, [host.id]);
  return (
    <table className="data">
      <thead><tr><th>Service</th><th>Status</th><th>Start</th><th></th></tr></thead>
      <tbody>
        {host.services.map((s) => (
          <tr key={s.name} className={s.suspicious ? 'bad' : ''}>
            <td>{s.displayName}<div className="tiny dim mono">{s.name}{s.path ? ` · ${s.path}` : ''}</div></td>
            <td style={{ color: s.status === 'running' ? 'var(--green)' : s.status === 'failed' ? 'var(--red)' : 'var(--text-dim)' }}>{s.status}</td>
            <td className="dim">{s.startType}</td>
            <td className="pill-row">
              {s.status !== 'running' && <button className="btn sm" onClick={() => doAct('start_service', `Started ${s.displayName}`, { service: s.name }, (h) => { const x = h.services.find((y) => y.name === s.name)!; x.status = 'running'; })}>Start</button>}
              {s.status === 'running' && <button className="btn sm" onClick={() => doAct('restart_service', `Restarted ${s.displayName}`, { service: s.name })}>Restart</button>}
              {s.status === 'running' && <button className="btn sm" onClick={() => doAct('stop_service', `Stopped ${s.displayName}`, { service: s.name }, (h) => { const x = h.services.find((y) => y.name === s.name)!; x.status = 'stopped'; })}>Stop</button>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function EventsTab({ host }: { host: Host }) {
  const doAct = useHostAct(host.id);
  const [log, setLog] = useState<'System' | 'Application' | 'Security' | 'Sysmon'>('System');
  useEffect(() => { doAct('view_events', `Viewed ${log} log on ${host.id}`, { log }, undefined, 'info'); }, [host.id, log]);
  const events = host.events.filter((e) => e.log === log);
  return (
    <div>
      <div className="tabs">
        {(['System', 'Application', 'Security', 'Sysmon'] as const).map((l) => <button key={l} className={log === l ? 'active' : ''} onClick={() => setLog(l)}>{l}</button>)}
      </div>
      <table className="data">
        <thead><tr><th>Level</th><th>Time</th><th>Event ID</th><th>Source</th><th>Message</th></tr></thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={i} className={e.level === 'Error' || e.level === 'Critical' || e.level === 'Audit Failure' ? 'bad' : e.level === 'Warning' ? 'warn' : ''}>
              <td className="nowrap">{e.level}</td><td className="mono nowrap">{fmt(e.time)}</td><td className="mono">{e.id}</td><td className="dim">{e.source}</td><td className="tiny">{e.message}</td>
            </tr>
          ))}
          {events.length === 0 && <tr><td colSpan={5} className="dim">No events in this log.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function DevicesTab({ host }: { host: Host }) {
  const doAct = useHostAct(host.id);
  useEffect(() => { doAct('view_devices', `Viewed Device Manager on ${host.id}`, undefined, undefined, 'info'); }, [host.id]);
  return (
    <table className="data">
      <thead><tr><th>Device</th><th>Class</th><th>Status</th><th>Driver</th><th></th></tr></thead>
      <tbody>
        {host.devices.map((d, i) => (
          <tr key={i} className={d.status !== 'ok' ? 'bad' : ''}>
            <td>{d.name}{d.error && <div className="tiny" style={{ color: 'var(--red)' }}>{d.error}</div>}</td>
            <td className="dim">{d.class}</td><td style={{ color: d.status === 'ok' ? 'var(--green)' : 'var(--red)' }}>{d.status}</td>
            <td className="mono tiny">{d.driver}{d.driverDate ? ` (${d.driverDate.slice(0, 10)})` : ''}</td>
            <td className="pill-row">
              {d.status !== 'ok' && <>
                <button className="btn sm" onClick={() => doAct('update_driver', `Updated driver for ${d.name}`, { device: d.name })}>Update driver</button>
                <button className="btn sm" onClick={() => doAct('rollback_driver', `Rolled back driver for ${d.name}`, { device: d.name })}>Roll back</button>
                {d.status === 'disabled' && <button className="btn sm" onClick={() => doAct('enable_device', `Enabled ${d.name}`, { device: d.name }, (h) => { const x = h.devices.find((y) => y.name === d.name)!; x.status = 'ok'; })}>Enable</button>}
              </>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function NetworkTab({ host }: { host: Host }) {
  const doAct = useHostAct(host.id);
  useEffect(() => { doAct('view_network', `Viewed network config on ${host.id}`, undefined, undefined, 'info'); }, [host.id]);
  const n = host.network;
  return (
    <div>
      <dl className="kv card">
        <dt>Adapter</dt><dd>{n.adapter} <span style={{ color: n.adapterStatus === 'up' ? 'var(--green)' : 'var(--red)' }}>({n.adapterStatus})</span></dd>
        <dt>DHCP</dt><dd>{n.dhcp ? 'Enabled' : 'Static'}</dd>
        <dt>IPv4</dt><dd className="mono" style={n.ip.startsWith('169.254') ? { color: 'var(--red)' } : undefined}>{n.ip}{n.ip.startsWith('169.254') ? ' (APIPA — no DHCP lease)' : ''}</dd>
        <dt>Subnet mask</dt><dd className="mono">{n.mask}</dd>
        <dt>Gateway</dt><dd className="mono">{n.gateway || '—'}</dd>
        <dt>DNS servers</dt><dd className="mono">{n.dns.join(', ')}</dd>
        {n.ssid && <><dt>Wi-Fi SSID</dt><dd>{n.ssid}</dd></>}
        {n.vpn && n.vpn !== 'n/a' && <><dt>VPN</dt><dd>{n.vpn}</dd></>}
      </dl>
      <div className="pill-row">
        <button className="btn sm" onClick={() => doAct('set_dhcp', `Set adapter to DHCP on ${host.id}`, undefined, (h) => { h.network.dhcp = true; })}>Set DHCP</button>
        <span className="small dim">For deeper diagnosis use the Terminal tab (ipconfig, ping, nslookup…).</span>
      </div>
    </div>
  );
}

function SchedTab({ host }: { host: Host }) {
  const doAct = useHostAct(host.id);
  useEffect(() => { doAct('view_tasks', `Viewed scheduled tasks on ${host.id}`, undefined, undefined, 'info'); }, [host.id]);
  return (
    <table className="data">
      <thead><tr><th>Task</th><th>Trigger</th><th>Action</th><th>Author</th><th></th></tr></thead>
      <tbody>
        {host.scheduledTasks.map((t, i) => (
          <tr key={i} className={t.suspicious ? 'bad' : ''}>
            <td>{t.name}</td><td className="dim">{t.trigger}</td><td className="mono tiny">{t.action}</td><td className="dim mono">{t.author}</td>
            <td><button className="btn sm danger" onClick={() => doAct('delete_task', `Deleted task ${t.name}`, { task: t.name }, (h) => { h.scheduledTasks = h.scheduledTasks.filter((x) => x.name !== t.name); })}>Delete</button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ProgramsTab({ host }: { host: Host }) {
  const doAct = useHostAct(host.id);
  useEffect(() => { doAct('view_programs', `Viewed installed programs on ${host.id}`, undefined, undefined, 'info'); }, [host.id]);
  return (
    <table className="data">
      <thead><tr><th>Program</th><th>Version</th><th>Publisher</th><th>Installed</th><th></th></tr></thead>
      <tbody>
        {host.programs.map((p, i) => (
          <tr key={i} className={p.suspicious ? 'bad' : ''}>
            <td>{p.name}</td><td className="mono dim">{p.version}</td><td className="dim">{p.publisher}</td><td className="dim">{p.installedOn.slice(0, 10)}</td>
            <td><button className="btn sm danger" onClick={() => doAct('uninstall', `Uninstalled ${p.name}`, { program: p.name }, (h) => { h.programs = h.programs.filter((x) => x.name !== p.name); })}>Uninstall</button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ExtTab({ host }: { host: Host }) {
  const doAct = useHostAct(host.id);
  useEffect(() => { doAct('view_browser_extensions', `Viewed browser extensions on ${host.id}`, undefined, undefined, 'info'); }, [host.id]);
  const exts = (host as unknown as { _extensions?: { name: string; id: string; suspicious?: boolean }[] })._extensions ?? [];
  return (
    <table className="data">
      <thead><tr><th>Extension</th><th>ID</th><th></th></tr></thead>
      <tbody>
        {exts.map((e, i) => (
          <tr key={i} className={e.suspicious ? 'bad' : ''}>
            <td>{e.name}</td><td className="mono tiny dim">{e.id}</td>
            <td><button className="btn sm danger" onClick={() => doAct('remove_extension', `Removed extension ${e.name}`, { name: e.name }, (h) => { const arr = (h as unknown as { _extensions?: { name: string }[] })._extensions; if (arr) (h as unknown as { _extensions: unknown[] })._extensions = arr.filter((x) => x.name !== e.name); })}>Remove</button></td>
          </tr>
        ))}
        {exts.length === 0 && <tr><td colSpan={3} className="dim">No browser extensions inventoried on this host.</td></tr>}
      </tbody>
    </table>
  );
}

function FilesTab({ host }: { host: Host }) {
  const doAct = useHostAct(host.id);
  useEffect(() => { doAct('view_files', `Reviewed files of interest on ${host.id}`, undefined, undefined, 'info'); }, [host.id]);
  return (
    <table className="data">
      <thead><tr><th>Path</th><th>Modified</th><th>Signed</th><th>Hash</th><th></th></tr></thead>
      <tbody>
        {host.files.map((f, i) => (
          <tr key={i} className={f.suspicious ? 'bad' : ''}>
            <td className="mono tiny">{f.path}</td><td className="dim nowrap">{fmt(f.modified)}</td>
            <td style={{ color: f.signed === false ? 'var(--red)' : undefined }}>{f.signed === false ? 'no' : f.signed ? 'yes' : '—'}</td>
            <td className="mono tiny">{f.hash ?? '—'}</td>
            <td>{f.suspicious && <button className="btn sm danger" onClick={() => doAct('quarantine_file', `Quarantined ${f.path.split('\\').pop()}`, { path: f.path })}>Quarantine</button>}</td>
          </tr>
        ))}
        {host.files.length === 0 && <tr><td colSpan={5} className="dim">Nothing flagged.</td></tr>}
      </tbody>
    </table>
  );
}

function Terminal({ host }: { host: Host }) {
  const { world, act } = useSession();
  const [lines, setLines] = useState<{ cmd?: string; out: string }[]>([{ out: `Windows PowerShell (remote session: ${host.id})\nType 'help' for supported commands.\n` }]);
  const [input, setInput] = useState('');
  const [hist, setHist] = useState<string[]>([]);
  const [hi, setHi] = useState(-1);
  const outRef = useRef<HTMLDivElement>(null);
  useEffect(() => { outRef.current?.scrollTo(0, outRef.current.scrollHeight); }, [lines]);

  function submit() {
    const cmd = input.trim();
    if (!cmd) return;
    const res = runCommand(world, host, cmd);
    if (res.output === ' CLEAR') { setLines([]); }
    else setLines((l) => [...l, { cmd, out: res.output }]);
    if (res.action !== 'noop' && res.action !== 'cls') {
      act({ tool: 'terminal', action: res.action, target: host.id, params: { cmd, arg: cmd.split(/\s+/).slice(1).join(' ') }, label: `${host.id}> ${cmd}` });
    }
    setHist((h) => [...h, cmd]); setHi(-1); setInput('');
  }

  return (
    <div className="terminal">
      <div className="out" ref={outRef}>
        {lines.map((l, i) => (
          <div key={i}>{l.cmd && <div className="cmd">{l.cmd}</div>}{l.out}</div>
        ))}
      </div>
      <div className="in">
        <span>{host.id.toLowerCase()}&gt;</span>
        <input value={input} autoFocus onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') submit();
            else if (e.key === 'ArrowUp') { const ni = Math.min(hist.length - 1, hi + 1); if (hist.length) { setHi(ni); setInput(hist[hist.length - 1 - ni] ?? ''); } e.preventDefault(); }
            else if (e.key === 'ArrowDown') { const ni = Math.max(-1, hi - 1); setHi(ni); setInput(ni < 0 ? '' : hist[hist.length - 1 - ni] ?? ''); e.preventDefault(); }
          }} />
      </div>
    </div>
  );
}
