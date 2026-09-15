// Live scenario session: a mutable World, the action log, and the ticket form.
// React components call `act()` for anything the trainee does; `act` records
// the action, applies the optional effect to the world, and bumps a version so
// the UI re-renders.

import { createContext, useContext, useState } from 'react';
import type { Action, Priority, Scenario, TicketState, World } from './types';

export interface Session {
  scenario: Scenario;
  world: World;
  actions: Action[];
  ticket: TicketState;
  startedAt: number;
  version: number;
  notices: { t: number; text: string }[];
  act: (a: Omit<Action, 't'>, effect?: (w: World) => void) => void;
  setTicket: (patch: Partial<TicketState>) => void;
  touch: () => void;
  /** stable scratch store so per-tool navigation state survives tool switches */
  ui: Record<string, unknown>;
}

export const SessionContext = createContext<Session | null>(null);

export function useSession(): Session {
  const s = useContext(SessionContext);
  if (!s) throw new Error('useSession outside SessionProvider');
  return s;
}

/** Like useState, but the value lives in the session's scratch store so it
 *  persists when a tool component unmounts and remounts (tool switching). */
export function usePersisted<T>(key: string, initial: T): [T, (v: T) => void] {
  const { ui } = useSession();
  const [, force] = useState(0);
  const val = (key in ui ? ui[key] : initial) as T;
  const set = (v: T) => { ui[key] = v; force((x) => x + 1); };
  return [val, set];
}

export function initialTicket(s: Scenario): TicketState {
  const pr: Priority = s.intake.kind === 'ticket' ? s.intake.priority : 'P3';
  return {
    priority: pr,
    notes: '',
    disposition: 'pending',
    category: s.intake.kind === 'ticket' ? s.intake.category : '',
    resolutionCode: '',
    notifications: [],
    report: '',
    verified: false,
    askedQuestions: [],
  };
}

/** Tools available per tier (scenario.tools can add more). */
export const TIER_TOOLS: Record<string, string[]> = {
  sd1: ['queue', 'kb', 'directory', 'rdp', 'server', 'assets', 'mail', 'chat'],
  sd2: ['queue', 'kb', 'directory', 'rdp', 'server', 'assets', 'mail', 'chat'],
  soc1: ['queue', 'kb', 'directory', 'rdp', 'server', 'mail', 'chat', 'siem', 'edr', 'intel', 'perimeter'],
  soc2: ['queue', 'kb', 'directory', 'rdp', 'server', 'mail', 'chat', 'siem', 'edr', 'intel', 'perimeter'],
  cirt: ['queue', 'kb', 'directory', 'rdp', 'server', 'mail', 'chat', 'siem', 'edr', 'intel', 'perimeter', 'incident'],
};

// Tools are styled after the products a real best-of-breed SOC runs, so the
// workflows and terminology transfer directly to the job.
export const TOOL_META: Record<string, { label: string; icon: string; blurb: string }> = {
  queue: { label: 'ServiceNow', icon: '🎫', blurb: 'ITSM: the incident record, work notes, state and assignment' },
  kb: { label: 'Knowledge Base', icon: '📚', blurb: 'SOPs, playbooks and troubleshooting runbooks' },
  directory: { label: 'Okta / AD', icon: '👤', blurb: 'Identity: users, groups, System Log sign-ins, sessions & MFA factors' },
  rdp: { label: 'Remote Desktop', icon: '🖥️', blurb: 'Task Manager, Services, Event Viewer and a live terminal on any endpoint' },
  server: { label: 'Infrastructure', icon: '🗄️', blurb: 'Domain controllers, file/print/app servers, DHCP, DNS, backups' },
  assets: { label: 'Asset Mgmt', icon: '📦', blurb: 'CMDB: hardware inventory, warranty, stock, shipping' },
  mail: { label: 'Proofpoint', icon: '✉️', blurb: 'Email security: Smart Search, headers, quarantine, mailbox rules' },
  chat: { label: 'Slack', icon: '💬', blurb: 'Message the requester and colleagues' },
  siem: { label: 'Splunk', icon: '🔎', blurb: 'SIEM: search all logs with SPL, stats and pivots' },
  edr: { label: 'CrowdStrike Falcon', icon: '🦅', blurb: 'EDR: detections, process trees, Network Contain, RTR, triage' },
  intel: { label: 'VirusTotal', icon: '🌐', blurb: 'Reputation & detection ratios for IPs, domains, hashes, URLs' },
  perimeter: { label: 'Palo Alto NGFW', icon: '🧱', blurb: 'Firewall, proxy, mail gateway and DNS sinkhole blocks' },
  incident: { label: 'IR Console', icon: '🚨', blurb: 'Incident workspace: phases, scope, IOCs, notifications, report' },
};
