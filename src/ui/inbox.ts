// Derives the "inbox" presentation of a scenario for the queue-style home:
// which channel it arrived on, who it's from, its subject and a preview.
// For alert scenarios the title/severity live in the alert the scenario's
// setup() creates, so we run setup once on a throwaway world and cache it.

import type { Scenario } from '../engine/types';
import { buildWorld, cloneWorld, userName } from '../engine/world';

const BASE = buildWorld();

export interface InboxMeta {
  channel: string;       // display label: "Email", "SMS", "Sametime", …
  icon: string;          // emoji
  from: string;          // sender line
  fromSub?: string;      // sender subtitle (title/dept)
  subject: string;
  preview: string;
  tagKind: 'pri' | 'sev';
  tag: string;           // P1..P4 or severity/SEV
}

const CHANNELS: Record<string, { channel: string; icon: string }> = {
  email: { channel: 'Email', icon: '✉️' },
  phone: { channel: 'Phone call', icon: '📞' },
  sms: { channel: 'SMS', icon: '📱' },
  im: { channel: 'Sametime', icon: '💬' },
  chat: { channel: 'Sametime', icon: '💬' },
  portal: { channel: 'Self-service portal', icon: '🎫' },
  'walk-up': { channel: 'Walk-up', icon: '🚶' },
};

const ALERT_SOURCE: Record<string, { channel: string; icon: string }> = {
  edr: { channel: 'CrowdStrike Falcon', icon: '🦅' },
  siem: { channel: 'Splunk alert', icon: '🔔' },
  email: { channel: 'Proofpoint', icon: '✉️' },
  ids: { channel: 'IDS alert', icon: '🔔' },
  cloud: { channel: 'Cloud alert', icon: '☁️' },
  user_report: { channel: 'User report', icon: '🙋' },
  dlp: { channel: 'DLP alert', icon: '🛑' },
};

function clip(s: string, n = 120): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > n ? one.slice(0, n - 1) + '…' : one;
}

const cache = new Map<string, InboxMeta>();

export function inboxMeta(s: Scenario): InboxMeta {
  const hit = cache.get(s.id);
  if (hit) return hit;
  let meta: InboxMeta;
  const intake = s.intake;
  if (intake.kind === 'ticket') {
    const c = CHANNELS[intake.channel] ?? { channel: intake.channel, icon: '🎫' };
    const u = BASE.users.find((x) => x.id === intake.requester);
    meta = {
      ...c,
      from: userName(BASE, intake.requester),
      fromSub: u ? `${u.title} · ${u.department}` : undefined,
      subject: intake.subject,
      preview: clip(intake.body),
      tagKind: 'pri',
      tag: intake.priority,
    };
  } else if (intake.kind === 'incident') {
    meta = {
      channel: 'Incident bridge', icon: '🚨',
      from: `${userName(BASE, intake.declaredBy)} (IC)`,
      fromSub: 'Incident declared',
      subject: intake.title,
      preview: clip(intake.summary),
      tagKind: 'sev',
      tag: intake.severity,
    };
  } else {
    // alert — read the alert the scenario creates
    const w = cloneWorld(BASE);
    try { s.setup(w); } catch { /* ignore */ }
    const a = w.alerts.find((x) => x.id === intake.alertId);
    const src = a ? (ALERT_SOURCE[a.source] ?? { channel: a.source, icon: '🔔' }) : { channel: 'Detection', icon: '🔔' };
    meta = {
      ...src,
      from: src.channel,
      fromSub: a?.host ? `host ${a.host}` : a?.user ? `user ${a.user}` : 'Security detection',
      subject: a?.title ?? s.title,
      preview: clip(a?.description ?? s.objective),
      tagKind: 'sev',
      tag: a?.severity ?? 'medium',
    };
  }
  cache.set(s.id, meta);
  return meta;
}

/** Relative "arrived" time, seeded from the id so it's stable per render. */
export function arrivedAgo(id: string): string {
  let h = 0;
  for (const c of id) h = (h * 31 + c.charCodeAt(0)) & 0xffff;
  const mins = 1 + (h % 55);
  return mins < 60 ? `${mins}m ago` : `${Math.round(mins / 60)}h ago`;
}
