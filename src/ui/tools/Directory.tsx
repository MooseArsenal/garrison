import React, { useState } from 'react';
import { useSession, usePersisted } from '../../engine/session';
import { fmt, userName } from '../../engine/world';
import type { DirUser } from '../../engine/types';
import { useToast } from '../common';

export function Directory() {
  const { world, act } = useSession();
  const toast = useToast();
  const [q, setQ] = usePersisted('dir.q', '');
  const [sel, setSel] = usePersisted<string | null>('dir.sel', null);
  const [tab, setTab] = usePersisted<'info' | 'signins' | 'groups'>('dir.tab', 'info');
  const [groupView, setGroupView] = usePersisted<string | null>('dir.group', null);

  const results = world.users.filter((u) => {
    if (!q) return false;
    const hay = (u.displayName + ' ' + u.id + ' ' + u.title + ' ' + u.department + ' ' + u.employeeId + ' ' + u.email).toLowerCase();
    return hay.includes(q.toLowerCase());
  });
  const u = sel ? world.users.find((x) => x.id === sel) : null;

  function doAction(action: string, label: string, params?: Record<string, string>, effect?: () => void) {
    act({ tool: 'directory', action, target: u!.id, params, label }, () => effect?.());
    toast(label, 'good');
  }

  if (groupView) {
    const g = world.groups.find((x) => x.id === groupView || x.name === groupView);
    return (
      <div>
        <button className="btn ghost sm mb" onClick={() => setGroupView(null)}>← Back</button>
        {g && (
          <div className="card">
            <div className="between"><h3>{g.name}</h3>{g.sensitive && <span className="chip" style={{ color: 'var(--amber)' }}>sensitive</span>}</div>
            <div className="small dim mb">{g.description}</div>
            <table className="data"><thead><tr><th>Member</th><th>Title</th><th>Dept</th></tr></thead>
              <tbody>{g.members.map((m) => { const mu = world.users.find((x) => x.id === m); return <tr key={m}><td>{mu?.displayName ?? m}</td><td className="dim">{mu?.title}</td><td className="dim">{mu?.department}</td></tr>; })}</tbody>
            </table>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="two-col" style={{ gridTemplateColumns: '300px 1fr', alignItems: 'start' }}>
      <div>
        <div className="searchbar"><input value={q} onChange={(e) => { setQ(e.target.value); if (e.target.value) act({ tool: 'directory', action: 'search', params: { q: e.target.value }, label: `Directory search "${e.target.value}"` }); }} placeholder="Search users…" autoFocus /></div>
        {results.map((r) => (
          <button key={r.id} className={`list-item ${sel === r.id ? '' : ''}`} style={{ width: '100%', textAlign: 'left', borderColor: sel === r.id ? 'var(--accent)' : undefined }}
            onClick={() => { setSel(r.id); setTab('info'); act({ tool: 'directory', action: 'view', target: r.id, label: `Viewed ${r.displayName}` }); }}>
            <div className="grow"><div className="t">{r.displayName} {r.lockedOut && <span className="tag" style={{ color: 'var(--red)' }}>locked</span>} {!r.enabled && <span className="tag">disabled</span>}</div><div className="s mono">{r.id} · {r.title}</div></div>
          </button>
        ))}
        {q && results.length === 0 && <div className="empty">No users match.</div>}
        {!q && <div className="empty">Search by name, username, employee ID…</div>}
      </div>

      <div>
        {!u && <div className="empty">Select a user to view their account.</div>}
        {u && (
          <div>
            <div className="between mb">
              <div><h3>{u.displayName}</h3><div className="small dim">{u.title} · {u.department}</div></div>
              <div className="flex wrap">
                {u.privileged && <span className="chip" style={{ color: 'var(--amber)' }}>privileged</span>}
                {u.lockedOut && <span className="chip" style={{ color: 'var(--red)' }}>locked out</span>}
                {!u.enabled && <span className="chip">disabled</span>}
              </div>
            </div>
            <div className="tabs">
              <button className={tab === 'info' ? 'active' : ''} onClick={() => setTab('info')}>Account</button>
              <button className={tab === 'signins' ? 'active' : ''} onClick={() => { setTab('signins'); act({ tool: 'directory', action: 'view_signins', target: u.id, label: `Reviewed ${u.displayName}'s System Log` }); }}>System Log ({u.recentSignIns.length})</button>
              <button className={tab === 'groups' ? 'active' : ''} onClick={() => setTab('groups')}>Groups ({u.groups.length})</button>
            </div>

            {tab === 'info' && (
              <>
                <dl className="kv card">
                  <dt>Username</dt><dd className="mono">{u.id}</dd>
                  <dt>Email</dt><dd className="mono">{u.email}</dd>
                  <dt>Employee ID</dt><dd className="mono">{u.employeeId}</dd>
                  <dt>Phone</dt><dd className="mono">{u.phone || '—'}</dd>
                  <dt>Manager</dt><dd>{userName(world, u.manager) || '—'}</dd>
                  <dt>Location</dt><dd>{u.location}</dd>
                  <dt>Enabled</dt><dd>{u.enabled ? 'Yes' : 'No'}</dd>
                  <dt>Locked out</dt><dd style={u.lockedOut ? { color: 'var(--red)' } : undefined}>{u.lockedOut ? `Yes (bad pwd count ${u.badPwdCount})` : 'No'}</dd>
                  <dt>Password last set</dt><dd>{fmt(u.passwordLastSet)}{u.passwordExpired ? ' (EXPIRED)' : ''}{u.passwordNeverExpires ? ' (never expires)' : ''}</dd>
                  <dt>MFA enrolled</dt><dd>{u.mfaEnrolled ? 'Yes' : 'No'}</dd>
                  <dt>Last logon</dt><dd>{fmt(u.lastLogon)}</dd>
                  {u.hireDate && <><dt>Hire date</dt><dd>{u.hireDate}</dd></>}
                  {u.notes && <><dt>Notes</dt><dd style={{ color: 'var(--amber)' }}>{u.notes}</dd></>}
                </dl>
                <div className="card">
                  <h4>Actions</h4>
                  <div className="pill-row">
                    <button className="btn sm" disabled={!u.lockedOut} onClick={() => doAction('unlock', `Unlocked ${u.displayName}`, undefined, () => { u.lockedOut = false; u.badPwdCount = 0; })}>Unlock</button>
                    <button className="btn sm" onClick={() => doAction('reset_password', `Reset password (must change) for ${u.displayName}`, { mustChange: 'true' }, () => { u.passwordExpired = false; })}>Reset password</button>
                    <button className="btn sm" onClick={() => doAction('revoke_sessions', `Cleared Okta sessions for ${u.displayName}`)}>Clear sessions (Okta)</button>
                    <button className="btn sm" onClick={() => doAction('reset_mfa', `Reset MFA factors for ${u.displayName}`)}>Reset MFA factors</button>
                    {u.enabled
                      ? <button className="btn sm danger" onClick={() => doAction('disable', `Deactivated ${u.displayName}`, undefined, () => { u.enabled = false; })}>Deactivate account</button>
                      : <button className="btn sm" onClick={() => doAction('enable', `Reactivated ${u.displayName}`, undefined, () => { u.enabled = true; })}>Reactivate account</button>}
                  </div>
                  <hr className="sep" />
                  <NameChange u={u} onAct={(action, label, params) => act({ tool: 'directory', action, target: u.id, params, label })} />
                </div>
              </>
            )}

            {tab === 'signins' && (
              <table className="data">
                <thead><tr><th>Time</th><th>Result</th><th>App</th><th>IP</th><th>Location</th><th>Device</th><th>MFA</th></tr></thead>
                <tbody>
                  {u.recentSignIns.map((si, i) => (
                    <tr key={i} className={si.result === 'failure' ? 'warn' : si.mfa === 'fatigue-approved' || (si.location && !si.location.includes('US')) ? 'bad' : ''}>
                      <td className="mono nowrap">{fmt(si.time)}</td>
                      <td style={{ color: si.result === 'success' ? 'var(--green)' : 'var(--red)' }}>{si.result}{si.reason ? ` (${si.reason})` : ''}</td>
                      <td>{si.app}</td><td className="mono">{si.ip}</td><td>{si.location}</td><td className="dim">{si.device ?? '—'}</td>
                      <td className={si.mfa === 'fatigue-approved' ? '' : ''} style={si.mfa === 'fatigue-approved' ? { color: 'var(--red)' } : undefined}>{si.mfa ?? '—'}</td>
                    </tr>
                  ))}
                  {u.recentSignIns.length === 0 && <tr><td colSpan={7} className="dim">No recent sign-ins recorded.</td></tr>}
                </tbody>
              </table>
            )}

            {tab === 'groups' && (
              <div className="pill-row">
                {u.groups.map((g) => {
                  const gd = world.groups.find((x) => x.name === g);
                  return <button key={g} className="chip" style={gd?.sensitive ? { color: 'var(--amber)', cursor: 'pointer' } : { cursor: 'pointer' }}
                    onClick={() => { setGroupView(g); act({ tool: 'directory', action: 'view_group', target: g, label: `Viewed group ${g}` }); }}>{g}</button>;
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function NameChange({ u, onAct }: { u: DirUser; onAct: (action: string, label: string, params?: Record<string, string>) => void }) {
  const [name, setName] = useState('');
  const [alias, setAlias] = useState('');
  const toast = useToast();
  return (
    <div>
      <h4>Name / alias</h4>
      <div className="field-row mb">
        <input placeholder="New display name" value={name} onChange={(e) => setName(e.target.value)} />
        <button className="btn sm" disabled={!name} onClick={() => { u.displayName = name; onAct('set_display_name', `Set display name to ${name}`, { name }); toast('Display name updated', 'good'); }}>Set</button>
      </div>
      <div className="field-row">
        <input placeholder="New email alias" value={alias} onChange={(e) => setAlias(e.target.value)} />
        <button className="btn sm" disabled={!alias} onClick={() => { onAct('add_alias', `Added alias ${alias}`, { alias }); toast('Alias added (old address kept)', 'good'); }}>Add alias</button>
      </div>
    </div>
  );
}
