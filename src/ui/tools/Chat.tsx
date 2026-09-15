import React, { useState } from 'react';
import { useSession } from '../../engine/session';
import { userName } from '../../engine/world';
import type { ContactQuestion } from '../../engine/types';

// Chat lets the trainee message the requester or any colleague. For the
// requester/contact, it surfaces the scenario's scripted contact questions;
// for anyone else, free-text messages are logged (and count as investigation
// when they hit the right person, per the scenario's required matchers).
export function Chat() {
  const { scenario: s, world, ticket, setTicket, act } = useSession();
  const [openWith, setOpenWith] = useState<string | null>(null);
  const [draft, setDraft] = useState('');

  const contactPerson = s.contactWith ?? (s.intake.kind === 'ticket' ? s.intake.requester : undefined);
  // People you can reach: the scripted contact + anyone with a chat thread + a few standing colleagues.
  const people = Array.from(new Set([
    contactPerson,
    ...world.chat.map((c) => c.with),
    'kwalsh', 'agrant', 'lchen', 'mreyes', 'pnguyen',
  ].filter(Boolean))) as string[];

  if (openWith) {
    const thread = world.chat.find((c) => c.with === openWith);
    const isContact = openWith === contactPerson && s.contact;
    return (
      <div>
        <button className="btn ghost sm mb" onClick={() => setOpenWith(null)}>← Contacts</button>
        <div className="card">
          <h4>{userName(world, openWith)} <span className="small dim">{world.users.find((u) => u.id === openWith)?.title}</span></h4>
          {thread && thread.messages.map((m, i) => (
            <div key={i} className="ticket-body" style={{ marginBottom: 6 }}><strong>{m.from === 'you' ? 'You' : userName(world, m.from)}:</strong> {m.text}</div>
          ))}
          {isContact && (
            <div className="mt">
              <div className="small dim mb">Quick questions:</div>
              {s.contact!.map((q) => {
                const asked = ticket.askedQuestions.includes(q.id);
                return (
                  <div key={q.id} className="card" style={{ padding: 10 }}>
                    <div className="between"><span className="small grow">{q.question}</span>
                      {!asked && <button className="btn sm" onClick={() => { setTicket({ askedQuestions: [...ticket.askedQuestions, q.id] }); act({ tool: 'ticket', action: 'contact', target: q.id, params: { purpose: q.purpose ?? 'clarify' }, label: `Asked: ${q.question}` }); act({ tool: 'chat', action: 'send', target: openWith!, params: { text: '[asked a question]' }, label: `Contacted ${userName(world, openWith!)}` }); }}>Send</button>}</div>
                    {asked && <div className="ticket-body" style={{ margin: '6px 0 0' }}>{q.answer}</div>}
                  </div>
                );
              })}
            </div>
          )}
          <div className="field-row mt">
            <input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder={`Message ${userName(world, openWith)}…`} onKeyDown={(e) => { if (e.key === 'Enter' && draft.trim()) send(); }} />
            <button className="btn sm" disabled={!draft.trim()} onClick={send}>Send</button>
          </div>
        </div>
      </div>
    );

    function send() {
      act({ tool: 'chat', action: 'send', target: openWith!, params: { text: draft }, label: `Messaged ${userName(world, openWith!)}: "${draft.slice(0, 60)}"` });
      setDraft('');
    }
  }

  return (
    <div>
      <div className="small dim mb">Message the requester or a colleague. Use the requester thread for verification and clarifying questions; message the right team to coordinate.</div>
      {people.map((p) => (
        <button key={p} className="list-item" style={{ width: '100%', textAlign: 'left' }} onClick={() => { setOpenWith(p); act({ tool: 'chat', action: 'open', target: p, label: `Opened chat with ${userName(world, p)}` }); }}>
          <div className="grow"><div className="t">{userName(world, p)}{p === contactPerson && <span className="tag" style={{ marginLeft: 6 }}>requester</span>}</div><div className="s">{world.users.find((u) => u.id === p)?.title ?? p}</div></div>
          <span className="dim">›</span>
        </button>
      ))}
    </div>
  );
}
