import React from 'react';
import { useSession, usePersisted } from '../../engine/session';
import { userName, fmt } from '../../engine/world';
import { Pri, Sev } from '../common';

export function Queue() {
  const { scenario: s, world, ticket, setTicket, act } = useSession();
  const intake = s.intake;
  const [tab, setTab] = usePersisted<'case' | 'contact' | 'reply'>('queue.tab', 'case');
  const requester = intake.kind === 'ticket' ? intake.requester : (s.contactWith ?? (intake.kind === 'alert' ? world.alerts.find((a) => a.id === intake.alertId)?.user : undefined));

  return (
    <div>
      <div className="tabs">
        <button className={tab === 'case' ? 'active' : ''} onClick={() => setTab('case')}>The case</button>
        {s.contact && <button className={tab === 'contact' ? 'active' : ''} onClick={() => setTab('contact')}>Contact ({ticket.askedQuestions.length}/{s.contact.length})</button>}
        {s.replies.length > 0 && <button className={tab === 'reply' ? 'active' : ''} onClick={() => setTab('reply')}>Reply {ticket.replyId ? '✓' : ''}</button>}
      </div>

      {tab === 'case' && (
        <div>
          {intake.kind === 'ticket' && (
            <div className="card">
              <div className="ticket-head">
                <span className="mono dim">{intake.number}</span><Pri p={intake.priority} />
                <span className="chip">{intake.channel}</span><span className="small dim">opened {fmt(intake.openedAt)}</span>
              </div>
              <h3 style={{ margin: '6px 0' }}>{intake.subject}</h3>
              <div className="small dim">From {userName(world, intake.requester)} · {world.users.find((u) => u.id === intake.requester)?.title} · {world.users.find((u) => u.id === intake.requester)?.department}</div>
              <div className="ticket-body">{intake.body}</div>
              {intake.affectedHost && <div className="small">Affected host: <span className="mono">{intake.affectedHost}</span></div>}
            </div>
          )}
          {intake.kind === 'alert' && (() => {
            const a = world.alerts.find((x) => x.id === intake.alertId)!;
            return (
              <div className="card">
                <div className="ticket-head"><span className="mono dim">{a.id}</span><Sev s={a.severity} /><span className="chip">{a.source}</span><span className="small dim">{fmt(a.time)}</span></div>
                <h3 style={{ margin: '6px 0' }}>{a.title}</h3>
                <div className="ticket-body">{a.description}</div>
                <div className="flex wrap small">
                  {a.host && <span className="chip">host: {a.host}</span>}{a.user && <span className="chip">user: {a.user}</span>}
                  {a.indicators.map((i) => <span key={i} className="tag mono">{i}</span>)}
                  {a.mitre?.map((m) => <span key={m} className="tag">{m}</span>)}
                </div>
              </div>
            );
          })()}
          {intake.kind === 'incident' && (
            <div className="card">
              <div className="ticket-head"><span className="mono dim">{intake.number}</span>
                <span className={`sev ${intake.severity === 'SEV1' ? 'critical' : intake.severity === 'SEV2' ? 'high' : 'medium'}`}>{intake.severity}</span>
                <span className="small dim">declared by {userName(world, intake.declaredBy)}</span></div>
              <h3 style={{ margin: '6px 0' }}>{intake.title}</h3>
              <div className="ticket-body">{intake.summary}</div>
              {intake.relatedAlerts.length > 0 && <div className="small dim">Related alerts: {intake.relatedAlerts.join(', ')}</div>}
            </div>
          )}
          <div className="card" style={{ background: 'var(--bg-2)' }}>
            <div className="small dim">Tip: read the relevant SOP in the Knowledge Base, gather evidence with the tools, {s.contact ? 'ask the requester the right questions,' : ''} then reply and close in the work panel.</div>
          </div>
        </div>
      )}

      {tab === 'contact' && s.contact && (
        <div>
          <div className="small dim mb">You reach {userName(world, s.contactWith ?? requester)} ({s.contactWith ? world.users.find((u) => u.id === s.contactWith)?.title : ''}). Ask what you need — irrelevant or leading questions can cost you.</div>
          {s.contact.map((q) => {
            const asked = ticket.askedQuestions.includes(q.id);
            return (
              <div key={q.id} className="card">
                <div className="between">
                  <div className="grow"><strong className="small">You:</strong> <span className="small">{q.question}</span></div>
                  {!asked && <button className="btn sm" onClick={() => {
                    setTicket({ askedQuestions: [...ticket.askedQuestions, q.id] });
                    act({ tool: 'ticket', action: 'contact', target: q.id, params: { purpose: q.purpose ?? 'clarify' }, label: `Asked: ${q.question}` });
                    const person = s.contactWith ?? requester;
                    if (person) act({ tool: 'chat', action: 'send', target: person, params: { text: '[asked a question]' }, label: `Contacted ${userName(world, person)}` });
                  }}>Ask</button>}
                </div>
                {asked && <div className="ticket-body" style={{ marginBottom: 0 }}>{q.answer}</div>}
              </div>
            );
          })}
        </div>
      )}

      {tab === 'reply' && (
        <div>
          <div className="small dim mb">Choose how you respond to {userName(world, requester)}. This is your communication (and often security/process) score.</div>
          {s.replies.map((r) => (
            <button key={r.id} className={`reply-opt ${ticket.replyId === r.id ? 'sel' : ''}`}
              onClick={() => { setTicket({ replyId: r.id }); act({ tool: 'ticket', action: 'reply', target: r.id, label: 'Sent a reply' }); }}>
              {r.text}
            </button>
          ))}
          {ticket.replyId && <div className="small dim mt">Reply selected. You can change it until you submit.</div>}
        </div>
      )}
    </div>
  );
}
