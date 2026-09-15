import React, { useState } from 'react';
import { useSession } from '../../engine/session';
import { useToast } from '../common';

const PHASES = ['Identification', 'Containment', 'Eradication', 'Recovery', 'Lessons Learned'];

export function Incident() {
  const { world, act } = useSession();
  const toast = useToast();
  const [phase, setPhase] = useState('Identification');
  const [ioc, setIoc] = useState('');
  const [scope, setScope] = useState('');
  const [tl, setTl] = useState('');
  const [target, setTarget] = useState('');
  const [iocs, setIocs] = useState<string[]>([]);
  const [scopes, setScopes] = useState<string[]>([]);

  function a(action: string, label: string, params?: Record<string, string>, effect?: () => void, kind: 'good' | 'bad' = 'good') {
    act({ tool: 'incident', action, target, params, label }, () => effect?.());
    toast(label, kind === 'bad' ? 'bad' : 'good');
  }

  return (
    <div>
      <div className="card">
        <h4>Response phase</h4>
        <div className="pill-row">
          {PHASES.map((p) => (
            <button key={p} className={`btn sm ${phase === p ? 'primary' : ''}`} onClick={() => { setPhase(p); act({ tool: 'incident', action: 'set_phase', params: { phase: p }, label: `Set phase: ${p}` }); }}>{p}</button>
          ))}
        </div>
        <div className="tiny dim mt">Order matters: contain (preserving evidence) before you eradicate; scope before you eradicate; recover from a known-good point.</div>
      </div>

      <div className="two-col">
        <div className="card">
          <h4>Add IOC</h4>
          <div className="field-row"><input value={ioc} onChange={(e) => setIoc(e.target.value)} placeholder="hash / IP / domain" />
            <button className="btn sm" onClick={() => { if (ioc.trim()) { act({ tool: 'incident', action: 'add_ioc', target: ioc.trim(), label: `Added IOC ${ioc.trim()}` }); setIocs((l) => [...l, ioc.trim()]); setIoc(''); } }}>Add</button></div>
          <div className="pill-row mt">{iocs.map((i) => <span key={i} className="tag mono">{i}</span>)}</div>
        </div>
        <div className="card">
          <h4>Add to scope</h4>
          <div className="field-row"><input value={scope} onChange={(e) => setScope(e.target.value)} placeholder="host or user affected" />
            <button className="btn sm" onClick={() => { if (scope.trim()) { act({ tool: 'incident', action: 'add_scope', target: scope.trim(), label: `Added ${scope.trim()} to scope` }); setScopes((l) => [...l, scope.trim()]); setScope(''); } }}>Add</button></div>
          <div className="pill-row mt">{scopes.map((i) => <span key={i} className="tag mono">{i}</span>)}</div>
        </div>
      </div>

      <div className="card">
        <h4>Timeline entry</h4>
        <div className="field-row"><input value={tl} onChange={(e) => setTl(e.target.value)} placeholder="What happened / what you did, with a time" />
          <button className="btn sm" onClick={() => { if (tl.trim()) { act({ tool: 'incident', action: 'add_timeline', params: { text: tl.trim() }, label: `Timeline: ${tl.trim().slice(0, 50)}` }); setTl(''); toast('Added to timeline', 'good'); } }}>Add</button></div>
      </div>

      <div className="card">
        <h4>Recovery &amp; domain actions</h4>
        <label className="field">Target host / server / account (for the actions below)</label>
        <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="e.g. DEN-FS01 or svc_backup" />
        <div className="pill-row mt">
          <button className="btn sm" disabled={!target} onClick={() => a('collect_triage', `Collected triage from ${target}`)}>Collect triage</button>
          <button className="btn sm" disabled={!target} onClick={() => a('restore_backup', `Restored ${target} from a clean backup point`, { job: 'clean' })}>Restore from backup</button>
          <button className="btn sm danger" disabled={!target} onClick={() => a('reimage', `Reimaged ${target}`, undefined, undefined, 'bad')}>Reimage host</button>
          <button className="btn sm" disabled={!target} onClick={() => a('reset_service_account', `Rotated service account ${target}`)}>Rotate service account</button>
        </div>
        <hr className="sep" />
        <div className="pill-row">
          <button className="btn sm danger" onClick={() => { act({ tool: 'incident', action: 'rotate_krbtgt', label: 'Rotated KRBTGT (twice) to invalidate Golden Tickets' }); toast('KRBTGT rotated x2', 'good'); }}>Rotate KRBTGT (x2)</button>
          <button className="btn sm" onClick={() => { act({ tool: 'incident', action: 'engage_retainer', label: 'Engaged IR retainer / forensics' }); toast('IR retainer engaged', 'good'); }}>Engage IR retainer</button>
          <button className="btn sm" onClick={() => { act({ tool: 'incident', action: 'legal_hold', label: 'Placed a legal hold to preserve evidence' }); toast('Legal hold placed', 'good'); }}>Place legal hold</button>
        </div>
        <div className="tiny dim mt">Notifications are in the work panel on the right. Notify only who the severity matrix (KB-0017) requires.</div>
      </div>
    </div>
  );
}
