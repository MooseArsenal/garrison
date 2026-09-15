import type { Host, World, WinEvent, Proc, LogEvent, Alert, MailMessage } from '../engine/types';
import { ago, findHost, findUser } from '../engine/world';

export function host(w: World, id: string): Host {
  const h = findHost(w, id);
  if (!h) throw new Error('no host ' + id);
  return h;
}

export function addEvent(h: Host, e: Partial<WinEvent> & Pick<WinEvent, 'id' | 'level' | 'message'>): void {
  h.events.push({ time: e.time ?? ago(10), source: e.source ?? 'Application', log: e.log ?? 'Application', ...e } as WinEvent);
  h.events.sort((a, b) => b.time.localeCompare(a.time));
}

export function addProc(h: Host, p: Partial<Proc> & Pick<Proc, 'pid' | 'name'>): Proc {
  const proc: Proc = {
    user: h.owner ? `KESTREL\\${h.owner}` : 'SYSTEM', cpu: 0.5, mem: 40, signed: false, ...p,
  };
  h.processes.push(proc);
  return proc;
}

export function addLog(w: World, l: LogEvent): void {
  w.logs.push(l);
  w.logs.sort((a, b) => a.time.localeCompare(b.time));
}

export function addAlert(w: World, a: Alert): void {
  w.alerts.push(a);
}

export function addMail(w: World, m: MailMessage): void {
  w.mail.push(m);
}

export function setConn(h: Host, conns: { proto: string; local: string; remote: string; state: string; pid: number }[]): void {
  (h as unknown as { _connections?: unknown })._connections = conns;
}

export function breakInternet(h: Host): void {
  (h as unknown as { _inetBroken?: boolean })._inetBroken = true;
}
export function breakDns(h: Host): void {
  (h as unknown as { _dnsBroken?: boolean })._dnsBroken = true;
}
export function setDhcpExhausted(h: Host): void {
  (h as unknown as { _dhcpExhausted?: boolean })._dhcpExhausted = true;
}

export function lockOut(w: World, userId: string, badCount = 5): void {
  const u = findUser(w, userId);
  if (!u) return;
  u.lockedOut = true;
  u.badPwdCount = badCount;
}
