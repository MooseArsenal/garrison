import React, { useState } from 'react';
import { useSession } from '../engine/session';
import type { Disposition, EscalationTarget, Priority } from '../engine/types';
import { Modal, useToast } from './common';

const PRIORITIES: Priority[] = ['P1', 'P2', 'P3', 'P4'];
const ESCALATIONS: { id: EscalationTarget; label: string }[] = [
  { id: 'sd2', label: 'Service Desk II' }, { id: 'desktop', label: 'Desktop / Endpoint' }, { id: 'network', label: 'Network Team' },
  { id: 'sysadmin', label: 'Sysadmin / Server' }, { id: 'identity', label: 'Identity Team' }, { id: 'soc', label: 'Security (SOC)' },
  { id: 'cirt', label: 'CIRT' }, { id: 'hr', label: 'HR' }, { id: 'legal', label: 'Legal' }, { id: 'finance', label: 'Finance' },
  { id: 'vendor', label: 'Vendor' }, { id: 'facilities', label: 'Facilities' }, { id: 'management', label: 'Management' },
];
const STAKEHOLDERS: { id: string; label: string }[] = [
  { id: 'it_director', label: 'IT Director / CISO' }, { id: 'executives', label: 'Executive team' }, { id: 'legal', label: 'Legal' },
  { id: 'hr', label: 'HR' }, { id: 'finance', label: 'Finance / AP' }, { id: 'affected_users', label: 'Affected users' },
  { id: 'all_staff', label: 'All staff' }, { id: 'insurance', label: 'Cyber insurer' }, { id: 'law_enforcement', label: 'Law enforcement' },
  { id: 'customers', label: 'Customers' }, { id: 'regulator', label: 'Regulator' }, { id: 'vendor', label: 'Vendor' }, { id: 'plant_ops', label: 'Plant operations' },
];

export function WorkPanel({ onSubmit, goToQueue }: { onSubmit: () => void; goToQueue: () => void }) {
  const { scenario: s, ticket, setTicket, act } = useSession();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  const isSoc = s.tier === 'soc1' || s.tier === 'soc2';
  const isCirt = s.tier === 'cirt';

  function toggleNotify(id: string) {
    const has = ticket.notifications.includes(id);
    const next = has ? ticket.notifications.filter((x) => x !== id) : [...ticket.notifications, id];
    setTicket({ notifications: next });
    act({ tool: 'incident', action: 'notify', target: id, label: `${has ? 'Un-notified' : 'Notified'} ${id.replace(/_/g, ' ')}` });
  }

  const canSubmit = ticket.disposition !== 'pending' || s.closure.disposition === 'pending';

  return (
    <div className="work">
      <div className="wsec">
        <h3>Priority</h3>
        <div className="pri-picker">
          {PRIORITIES.map((p) => (
            <button key={p} className={ticket.priority === p ? `sel ${p}` : ''}
              onClick={() => { setTicket({ priority: p }); act({ tool: 'ticket', action: 'set_priority', params: { priority: p }, label: `Set priority ${p}` }); }}>{p}</button>
          ))}
        </div>
      </div>

      <div className="wsec">
        <h3>Work notes</h3>
        <textarea rows={6} placeholder="What you found, what you did, verification used, cause, and next steps. This is graded."
          value={ticket.notes} onChange={(e) => setTicket({ notes: e.target.value })} />
        <div className="tiny dim" style={{ marginTop: 4 }}>{ticket.notes.length} chars</div>
      </div>

      {isCirt && s.intake.kind === 'incident' && (
        <div className="wsec">
          <h3>Incident report</h3>
          <textarea rows={6} placeholder="Timeline, root cause, containment/recovery, and follow-up actions with owners."
            value={ticket.report} onChange={(e) => setTicket({ report: e.target.value })} />
        </div>
      )}

      <div className="wsec">
        <h3>Classification</h3>
        {isSoc && (
          <>
            <label className="field">Verdict</label>
            <select value={ticket.classification ?? ''} onChange={(e) => setTicket({ classification: (e.target.value || undefined) as never })}>
              <option value="">— choose —</option>
              <option value="true_positive">True Positive</option>
              <option value="benign_true_positive">Benign True Positive</option>
              <option value="false_positive">False Positive</option>
            </select>
          </>
        )}
        {(isSoc || isCirt) && (
          <>
            <label className="field">Severity</label>
            <select value={ticket.severity ?? ''} onChange={(e) => setTicket({ severity: (e.target.value || undefined) as never })}>
              <option value="">— choose —</option>
              <option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option>
            </select>
          </>
        )}
        <label className="field">Category</label>
        <input value={ticket.category} placeholder="e.g. Identity - Account Lockout" onChange={(e) => setTicket({ category: e.target.value })} />
        <label className="field">Resolution code</label>
        <input value={ticket.resolutionCode} placeholder="e.g. Unlocked + password reset" onChange={(e) => setTicket({ resolutionCode: e.target.value })} />
      </div>

      <div className="wsec">
        <h3>Disposition</h3>
        <select value={ticket.disposition} onChange={(e) => setTicket({ disposition: e.target.value as Disposition })}>
          <option value="pending">— choose —</option>
          <option value="resolve">Resolve</option>
          <option value="escalate">Escalate</option>
          <option value="reject">Reject / return</option>
          <option value="pending">Pending (awaiting external)</option>
        </select>
        {ticket.disposition === 'escalate' && (
          <>
            <label className="field">Escalate to</label>
            <select value={ticket.escalateTo ?? ''} onChange={(e) => setTicket({ escalateTo: (e.target.value || undefined) as EscalationTarget })}>
              <option value="">— choose team —</option>
              {ESCALATIONS.map((x) => <option key={x.id} value={x.id}>{x.label}</option>)}
            </select>
          </>
        )}
      </div>

      {isCirt && (
        <div className="wsec">
          <h3>Notifications</h3>
          <div className="tiny dim mb">Notify only who the situation requires. Wrong or premature notifications count against you.</div>
          {STAKEHOLDERS.map((st) => (
            <label key={st.id} className="flex" style={{ gap: 8, padding: '3px 0', fontSize: 12.5 }}>
              <input type="checkbox" style={{ width: 'auto' }} checked={ticket.notifications.includes(st.id)} onChange={() => toggleNotify(st.id)} />
              <span>{st.label}</span>
            </label>
          ))}
        </div>
      )}

      <div className="wsec">
        <button className="btn primary" style={{ width: '100%' }} onClick={() => setConfirm(true)}>Submit &amp; close case</button>
        <div className="tiny dim" style={{ marginTop: 8, textAlign: 'center' }}>Make sure you sent a reply in the Queue tab.</div>
      </div>

      {confirm && (
        <Modal title="Submit this case?" onClose={() => setConfirm(false)}
          footer={<>
            <button className="btn ghost" onClick={() => setConfirm(false)}>Keep working</button>
            <button className="btn primary" onClick={() => { setConfirm(false); onSubmit(); }}>Submit for grading</button>
          </>}>
          <p className="small">You'll get a full breakdown of how you did against a competent analyst's approach. You can retry afterward.</p>
          {!ticket.replyId && <p className="small" style={{ color: 'var(--amber)' }}>⚠ You haven't chosen a reply to the requester/stakeholder yet (Queue tab). That affects your communication score.</p>}
          {ticket.disposition === 'pending' && s.closure.disposition !== 'pending' && <p className="small" style={{ color: 'var(--amber)' }}>⚠ Disposition is still "pending". Set Resolve / Escalate / Reject unless the case truly awaits an external party.</p>}
        </Modal>
      )}
    </div>
  );
}
