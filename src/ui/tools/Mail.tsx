import React, { useState } from 'react';
import { useSession, usePersisted } from '../../engine/session';
import { fmt } from '../../engine/world';
import type { MailMessage } from '../../engine/types';
import { useToast } from '../common';

export function Mail() {
  const { world, act } = useSession();
  const toast = useToast();
  const [tab, setTab] = usePersisted<'trace' | 'mailbox'>('mail.tab', 'trace');
  const [q, setQ] = usePersisted('mail.q', '');
  const [sel, setSel] = usePersisted<string | null>('mail.sel', null);
  const [showHeaders, setShowHeaders] = useState(false);
  const [mbUser, setMbUser] = usePersisted('mail.mbUser', '');

  const msg = sel ? world.mail.find((m) => m.id === sel) : null;
  const traceResults = world.mail.filter((m) => !q || (m.subject + ' ' + m.from + ' ' + m.to.join(' ') + ' ' + m.id).toLowerCase().includes(q.toLowerCase()));

  function doMsg(action: string, label: string, m: MailMessage, effect?: () => void) {
    act({ tool: 'mail', action, target: m.id, label }, () => effect?.());
    toast(label, 'good');
  }

  if (msg) {
    return (
      <div>
        <button className="btn ghost sm mb" onClick={() => { setSel(null); setShowHeaders(false); }}>← Trace results</button>
        <div className="card">
          <div className="between"><h4>{msg.subject}</h4><span className={`chip`} style={{ color: msg.status.includes('block') || msg.status.includes('quarant') ? 'var(--amber)' : undefined }}>{msg.status}</span></div>
          <dl className="kv mt">
            <dt>From</dt><dd className="mono">{msg.from}</dd>
            <dt>To</dt><dd className="mono">{msg.to.join(', ')}</dd>
            <dt>Time</dt><dd>{fmt(msg.time)}</dd>
            {msg.reason && <><dt>Reason</dt><dd>{msg.reason}</dd></>}
          </dl>
          <div className="pill-row mt">
            <button className="btn sm" onClick={() => { setShowHeaders((v) => !v); act({ tool: 'mail', action: 'view_headers', target: msg.id, label: `Viewed headers of ${msg.id}` }); }}>{showHeaders ? 'Hide' : 'Show'} headers</button>
            <button className="btn sm danger" onClick={() => doMsg('purge_all', `Purged ${msg.id} for all recipients`, msg)}>Purge for all</button>
            {msg.status.includes('quarant') && <button className="btn sm" onClick={() => doMsg('release', `Released ${msg.id}`, msg)}>Release</button>}
            {!msg.status.includes('quarant') && <button className="btn sm" onClick={() => doMsg('quarantine', `Quarantined ${msg.id}`, msg)}>Quarantine</button>}
            <button className="btn sm" onClick={() => { const dom = msg.from.match(/@([^ >]+)/)?.[1] ?? msg.from; act({ tool: 'mail', action: 'block_sender', target: dom, label: `Blocked sender ${dom}` }); toast(`Blocked ${dom}`, 'good'); }}>Block sender</button>
          </div>
          {showHeaders && (
            <div className="card mt" style={{ background: 'var(--bg-2)' }}>
              <dl className="kv">
                <dt>From (display)</dt><dd className="mono tiny">{msg.headers.from}</dd>
                <dt>Return-Path</dt><dd className="mono tiny">{msg.headers.returnPath}</dd>
                {msg.headers.replyTo && <><dt>Reply-To</dt><dd className="mono tiny" style={{ color: 'var(--amber)' }}>{msg.headers.replyTo}</dd></>}
                <dt>Received from</dt><dd className="mono tiny">{msg.headers.receivedFrom}</dd>
                <dt>SPF</dt><dd style={{ color: msg.headers.spf === 'pass' ? 'var(--green)' : 'var(--red)' }}>{msg.headers.spf}</dd>
                <dt>DKIM</dt><dd style={{ color: msg.headers.dkim === 'pass' ? 'var(--green)' : 'var(--red)' }}>{msg.headers.dkim}</dd>
                <dt>DMARC</dt><dd style={{ color: msg.headers.dmarc === 'pass' ? 'var(--green)' : 'var(--red)' }}>{msg.headers.dmarc}</dd>
                <dt>Message-ID</dt><dd className="mono tiny">{msg.headers.messageId}</dd>
              </dl>
            </div>
          )}
          <div className="ticket-body mt">{msg.body}</div>
          {msg.urls && msg.urls.length > 0 && <div className="small"><strong>URLs:</strong> {msg.urls.map((u) => <span key={u} className="tag mono" style={{ marginRight: 6 }}>{u}</span>)}</div>}
          {msg.attachments && msg.attachments.length > 0 && <div className="small mt"><strong>Attachments:</strong> {msg.attachments.map((at) => <span key={at.name} className="tag mono">{at.name} {at.hash ? `(${at.hash})` : ''}</span>)}</div>}
          {msg.clicked && msg.clicked.length > 0 && <div className="small mt" style={{ color: 'var(--amber)' }}>Clicked by: {msg.clicked.join(', ')}</div>}
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="tabs">
        <button className={tab === 'trace' ? 'active' : ''} onClick={() => setTab('trace')}>Smart Search</button>
        <button className={tab === 'mailbox' ? 'active' : ''} onClick={() => setTab('mailbox')}>Mailbox</button>
      </div>
      {tab === 'trace' && (
        <div>
          <div className="searchbar"><input value={q} onChange={(e) => { setQ(e.target.value); if (e.target.value) act({ tool: 'mail', action: 'trace', params: { q: e.target.value }, label: `Message trace "${e.target.value}"` }); }} placeholder="Trace by subject, sender, recipient…" autoFocus /></div>
          <table className="data">
            <thead><tr><th>Time</th><th>From</th><th>To</th><th>Subject</th><th>Status</th></tr></thead>
            <tbody>
              {traceResults.map((m) => (
                <tr key={m.id} className="clickable" onClick={() => { setSel(m.id); act({ tool: 'mail', action: 'view', target: m.id, label: `Opened ${m.id}` }); }}>
                  <td className="mono nowrap tiny">{fmt(m.time)}</td><td className="mono tiny">{m.from}</td><td className="mono tiny">{m.to.join(', ')}</td><td>{m.subject}</td>
                  <td style={{ color: m.status.includes('block') || m.status.includes('quarant') ? 'var(--amber)' : undefined }}>{m.status}</td>
                </tr>
              ))}
              {world.mail.length === 0 && <tr><td colSpan={5} className="dim">No mail in scope for this scenario.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
      {tab === 'mailbox' && (
        <div>
          <div className="searchbar"><input value={mbUser} onChange={(e) => setMbUser(e.target.value)} placeholder="Mailbox user id (e.g. hsato)…" /></div>
          {(() => {
            const mb = world.mailboxes.find((m) => m.user === mbUser.trim().toLowerCase());
            if (!mbUser) return <div className="empty">Enter a user id to inspect their mailbox rules, forwarding and quota.</div>;
            if (!mb) return <div className="empty">No mailbox for “{mbUser}”.</div>;
            return (
              <div className="card">
                <div className="between"><h4>{mb.user}</h4>
                  <button className="btn sm" onClick={() => act({ tool: 'mail', action: 'view_mailbox', target: mb.user, label: `Inspected ${mb.user}'s mailbox` })}>Log inspection</button></div>
                <dl className="kv mt"><dt>Quota</dt><dd>{mb.usedGB} / {mb.quotaGB} GB{mb.usedGB >= mb.quotaGB ? ' (FULL)' : ''}</dd>
                  {mb.forwarding && <><dt>Forwarding</dt><dd style={{ color: 'var(--red)' }}>{mb.forwarding}</dd></>}</dl>
                <h4 className="mt">Inbox rules</h4>
                {mb.rules.length === 0 ? <div className="dim small">No rules.</div> : (
                  <table className="data"><thead><tr><th>Rule</th><th>Condition</th><th>Action</th><th></th></tr></thead>
                    <tbody>{mb.rules.map((r) => (
                      <tr key={r.name} className={r.suspicious ? 'bad' : ''}><td>{r.name}</td><td className="tiny">{r.condition}</td><td className="tiny">{r.action}</td>
                        <td><button className="btn sm danger" onClick={() => { act({ tool: 'mail', action: 'remove_rule', target: mb.user, params: { rule: r.name }, label: `Removed inbox rule "${r.name}" from ${mb.user}` }, (w) => { const m2 = w.mailboxes.find((x) => x.user === mb.user)!; m2.rules = m2.rules.filter((x) => x.name !== r.name); }); toast('Rule removed', 'good'); }}>Remove</button></td></tr>
                    ))}</tbody>
                  </table>
                )}
                {mb.forwarding && <button className="btn sm danger mt" onClick={() => { act({ tool: 'mail', action: 'remove_forwarding', target: mb.user, label: `Removed forwarding from ${mb.user}` }, (w) => { w.mailboxes.find((x) => x.user === mb.user)!.forwarding = undefined; }); toast('Forwarding removed', 'good'); }}>Remove forwarding</button>}
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
