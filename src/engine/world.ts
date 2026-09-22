// The fictional company every scenario starts from: Kestrel Dynamics, an
// aerospace-components manufacturer with an HQ in Denver and a plant in
// Wichita. Scenarios clone this and patch it. Keep baseline data *boring* and
// realistic; scenarios add the interesting bits.

import type {
  World, DirUser, DirGroup, Host, Server, Asset, KbArticle, Proc, Svc, WinEvent, LogEvent, IocRecord,
} from './types';

export const NOW = '2026-09-15T09:12:00';

/** ISO timestamp `minutes` before NOW (negative = after). */
export function ago(minutes: number, from: string = NOW): string {
  const d = new Date(from);
  d.setMinutes(d.getMinutes() - minutes);
  return d.toISOString().slice(0, 19);
}
export function daysAgo(days: number): string {
  return ago(days * 24 * 60);
}
export function fmt(iso: string): string {
  return iso.replace('T', ' ').slice(0, 16);
}

// ----------------------------------------------------------------------------
// Users
// ----------------------------------------------------------------------------
interface U {
  id: string; name: string; title: string; dept: string; mgr?: string; loc: string; emp: string;
  groups?: string[]; privileged?: boolean; mfa?: boolean; hire?: string;
}

const RAW_USERS: U[] = [
  { id: 'dvance', name: 'Diane Vance', title: 'Chief Executive Officer', dept: 'Executive', loc: 'Denver HQ', emp: 'E10001', hire: '2014-03-01', groups: ['Executives', 'All Staff'] },
  { id: 'rokafor', name: 'Rachel Okafor', title: 'Chief Financial Officer', dept: 'Finance', mgr: 'dvance', loc: 'Denver HQ', emp: 'E10002', hire: '2016-06-13', groups: ['Executives', 'Finance', 'All Staff'] },
  { id: 'tbrandt', name: 'Tom Brandt', title: 'VP Operations', dept: 'Operations', mgr: 'dvance', loc: 'Wichita Plant', emp: 'E10003', hire: '2015-01-19', groups: ['Executives', 'Operations', 'All Staff'] },
  { id: 'lchen', name: 'Linda Chen', title: 'IT Director', dept: 'IT', mgr: 'dvance', loc: 'Denver HQ', emp: 'E10004', hire: '2017-09-05', groups: ['IT Staff', 'IT-Admins', 'All Staff'], privileged: true },
  { id: 'mreyes', name: 'Marco Reyes', title: 'Systems Administrator', dept: 'IT', mgr: 'lchen', loc: 'Denver HQ', emp: 'E10021', hire: '2019-02-11', groups: ['IT Staff', 'IT-Admins', 'Server Admins', 'All Staff'], privileged: true },
  { id: 'pnguyen', name: 'Priya Nguyen', title: 'Network Engineer', dept: 'IT', mgr: 'lchen', loc: 'Denver HQ', emp: 'E10022', hire: '2020-07-20', groups: ['IT Staff', 'Network Team', 'All Staff'], privileged: true },
  { id: 'kwalsh', name: 'Kevin Walsh', title: 'Service Desk Lead', dept: 'IT', mgr: 'lchen', loc: 'Denver HQ', emp: 'E10023', hire: '2018-11-12', groups: ['IT Staff', 'Service Desk', 'All Staff'] },
  { id: 'agrant', name: 'Aisha Grant', title: 'Security Analyst', dept: 'IT', mgr: 'lchen', loc: 'Denver HQ', emp: 'E10024', hire: '2021-04-05', groups: ['IT Staff', 'Security Team', 'All Staff'], privileged: true },
  { id: 'svc_backup', name: 'svc_backup (service)', title: 'Service Account - Backups', dept: 'IT', loc: 'Denver HQ', emp: 'SVC001', groups: ['Server Admins', 'Backup Operators'], privileged: true, mfa: false },
  { id: 'svc_scanner', name: 'svc_scanner (service)', title: 'Service Account - Vulnerability Scanner', dept: 'IT', loc: 'Denver HQ', emp: 'SVC002', groups: ['Server Admins'], privileged: true, mfa: false },
  { id: 'jmorales', name: 'Jenna Morales', title: 'Accounts Payable Specialist', dept: 'Finance', mgr: 'rokafor', loc: 'Denver HQ', emp: 'E10105', hire: '2022-01-10', groups: ['Finance', 'AP-Team', 'All Staff'] },
  { id: 'bpatel', name: 'Bhavik Patel', title: 'Senior Accountant', dept: 'Finance', mgr: 'rokafor', loc: 'Denver HQ', emp: 'E10106', hire: '2019-08-26', groups: ['Finance', 'All Staff'] },
  { id: 'sturner', name: 'Sarah Turner', title: 'HR Business Partner', dept: 'Human Resources', mgr: 'dvance', loc: 'Denver HQ', emp: 'E10110', hire: '2018-05-14', groups: ['HR', 'All Staff'] },
  { id: 'dkim', name: 'David Kim', title: 'Recruiter', dept: 'Human Resources', mgr: 'sturner', loc: 'Denver HQ', emp: 'E10111', hire: '2023-03-06', groups: ['HR', 'All Staff'] },
  { id: 'ewright', name: 'Emily Wright', title: 'Sales Director', dept: 'Sales', mgr: 'dvance', loc: 'Denver HQ', emp: 'E10120', hire: '2017-02-27', groups: ['Sales', 'All Staff'] },
  { id: 'cflores', name: 'Carlos Flores', title: 'Account Executive', dept: 'Sales', mgr: 'ewright', loc: 'Remote - Phoenix', emp: 'E10121', hire: '2021-10-18', groups: ['Sales', 'VPN Users', 'All Staff'] },
  { id: 'hsato', name: 'Hana Sato', title: 'Account Executive', dept: 'Sales', mgr: 'ewright', loc: 'Remote - Seattle', emp: 'E10122', hire: '2022-06-06', groups: ['Sales', 'VPN Users', 'All Staff'] },
  { id: 'gharris', name: 'Greg Harris', title: 'Plant Manager', dept: 'Operations', mgr: 'tbrandt', loc: 'Wichita Plant', emp: 'E10130', hire: '2016-09-12', groups: ['Operations', 'Plant-Supervisors', 'All Staff'] },
  { id: 'mjohnson', name: 'Mike Johnson', title: 'Machinist II', dept: 'Operations', mgr: 'gharris', loc: 'Wichita Plant', emp: 'E10131', hire: '2020-03-02', groups: ['Operations', 'All Staff'] },
  { id: 'lortiz', name: 'Luis Ortiz', title: 'Quality Inspector', dept: 'Operations', mgr: 'gharris', loc: 'Wichita Plant', emp: 'E10132', hire: '2019-11-04', groups: ['Operations', 'Quality', 'All Staff'] },
  { id: 'nfoster', name: 'Nora Foster', title: 'Design Engineer', dept: 'Engineering', mgr: 'tbrandt', loc: 'Denver HQ', emp: 'E10140', hire: '2018-08-20', groups: ['Engineering', 'CAD Users', 'All Staff'] },
  { id: 'obennett', name: 'Owen Bennett', title: 'Design Engineer', dept: 'Engineering', mgr: 'tbrandt', loc: 'Denver HQ', emp: 'E10141', hire: '2023-09-11', groups: ['Engineering', 'CAD Users', 'All Staff'] },
  { id: 'rsingh', name: 'Raj Singh', title: 'Legal Counsel', dept: 'Legal', mgr: 'dvance', loc: 'Denver HQ', emp: 'E10150', hire: '2019-04-15', groups: ['Legal', 'All Staff'] },
  { id: 'tmartin', name: 'Tanya Martin', title: 'Executive Assistant', dept: 'Executive', mgr: 'dvance', loc: 'Denver HQ', emp: 'E10005', hire: '2015-07-06', groups: ['Executive-Assistants', 'All Staff'] },
  { id: 'jwebb', name: 'Jordan Webb', title: 'Marketing Coordinator', dept: 'Marketing', mgr: 'ewright', loc: 'Denver HQ', emp: 'E10160', hire: '2024-02-19', groups: ['Marketing', 'All Staff'] },
  { id: 'pcole', name: 'Pat Cole', title: 'Receptionist', dept: 'Facilities', mgr: 'tmartin', loc: 'Denver HQ', emp: 'E10170', hire: '2022-11-28', groups: ['Facilities', 'All Staff'] },
  { id: 'abaxter', name: 'Alex Baxter', title: 'Contractor - ERP Consultant', dept: 'Contractors', mgr: 'lchen', loc: 'Remote', emp: 'C20031', hire: '2026-05-01', groups: ['Contractors', 'ERP-Users'] },
];

function mkUser(u: U, i: number): DirUser {
  const isSvc = u.id.startsWith('svc_');
  return {
    id: u.id,
    displayName: u.name,
    title: u.title,
    department: u.dept,
    manager: u.mgr,
    email: `${u.id}@kestreldynamics.com`,
    phone: isSvc ? '' : `303-555-${String(1200 + i).padStart(4, '0')}`,
    employeeId: u.emp,
    location: u.loc,
    enabled: true,
    lockedOut: false,
    passwordLastSet: daysAgo(isSvc ? 400 : 20 + (i * 7) % 60),
    passwordNeverExpires: isSvc || undefined,
    groups: u.groups ?? ['All Staff'],
    lastLogon: ago(isSvc ? 5 : 30 + i * 11),
    badPwdCount: 0,
    mfaEnrolled: u.mfa ?? !isSvc,
    privileged: u.privileged,
    hireDate: u.hire,
    recentSignIns: isSvc ? [] : [
      { time: ago(30 + i * 11), ip: u.loc.startsWith('Remote') ? '73.14.22.190' : '10.10.20.' + (30 + i), location: u.loc.startsWith('Remote') ? u.loc.replace('Remote - ', '') + ', US' : 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'corp device', mfa: 'satisfied' },
      { time: ago(60 * 20 + i * 5), ip: u.loc.startsWith('Remote') ? '73.14.22.190' : '10.10.20.' + (30 + i), location: u.loc.startsWith('Remote') ? u.loc.replace('Remote - ', '') + ', US' : 'Denver, US', app: 'WorkSuite Mail', result: 'success', device: 'corp device', mfa: 'satisfied' },
    ],
  };
}

const GROUP_DEFS: Array<[string, string, boolean?]> = [
  ['All Staff', 'Every employee'],
  ['Executives', 'Executive leadership team', true],
  ['Finance', 'Finance department'],
  ['AP-Team', 'Accounts payable - can approve vendor payment changes in ERP', true],
  ['HR', 'Human resources'],
  ['Sales', 'Sales department'],
  ['Marketing', 'Marketing department'],
  ['Operations', 'Operations and plant staff'],
  ['Plant-Supervisors', 'Wichita plant supervisors'],
  ['Quality', 'Quality assurance'],
  ['Engineering', 'Engineering department'],
  ['CAD Users', 'Licensed CAD seat holders (SolidWorks)'],
  ['Legal', 'Legal department'],
  ['Executive-Assistants', 'EA team - delegate access to exec mailboxes', true],
  ['Facilities', 'Facilities and front desk'],
  ['Contractors', 'External contractors - restricted access'],
  ['ERP-Users', 'Access to the Kestrel ERP web app'],
  ['VPN Users', 'Allowed to connect to corporate VPN'],
  ['IT Staff', 'All IT department staff'],
  ['IT-Admins', 'Tier 2+ IT administrators', true],
  ['Server Admins', 'Local admin on all member servers', true],
  ['Backup Operators', 'Backup service rights', true],
  ['Network Team', 'Network engineering', true],
  ['Security Team', 'SOC / security analysts', true],
  ['Service Desk', 'Tier 1 service desk staff'],
  ['Domain Admins', 'Built-in. Full control of the domain.', true],
  ['FS-Finance-RW', 'Read/write on \\\\FS01\\Finance', true],
  ['FS-Engineering-RW', 'Read/write on \\\\FS01\\Engineering'],
  ['FS-HR-RW', 'Read/write on \\\\FS01\\HR', true],
  ['FS-Shared-RW', 'Read/write on \\\\FS01\\Shared'],
];

function mkGroups(users: DirUser[]): DirGroup[] {
  const groups: DirGroup[] = GROUP_DEFS.map(([name, description, sensitive]) => ({
    id: name.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
    name,
    description,
    type: 'security',
    members: [],
    sensitive,
  }));
  const byName = new Map(groups.map((g) => [g.name, g]));
  // file-share groups derived from department
  const shareMap: Record<string, string> = { Finance: 'FS-Finance-RW', Engineering: 'FS-Engineering-RW', 'Human Resources': 'FS-HR-RW' };
  for (const u of users) {
    if (!u.id.startsWith('svc_') && !u.groups.includes('Contractors')) u.groups.push('FS-Shared-RW');
    const sg = shareMap[u.department];
    if (sg) u.groups.push(sg);
    if (u.groups.includes('IT-Admins')) u.groups.push('FS-Finance-RW', 'FS-HR-RW', 'FS-Engineering-RW');
    if (u.id === 'lchen' || u.id === 'mreyes') u.groups.push('Domain Admins');
    for (const g of u.groups) byName.get(g)?.members.push(u.id);
  }
  return groups;
}

// ----------------------------------------------------------------------------
// Hosts
// ----------------------------------------------------------------------------
export function baseProcesses(user: string): Proc[] {
  return [
    { pid: 4, name: 'System', user: 'SYSTEM', cpu: 0.1, mem: 8, path: 'N/A', signed: true },
    { pid: 620, name: 'csrss.exe', user: 'SYSTEM', cpu: 0.1, mem: 5, path: 'C:\\Windows\\System32\\csrss.exe', signed: true },
    { pid: 704, name: 'wininit.exe', user: 'SYSTEM', cpu: 0, mem: 6, path: 'C:\\Windows\\System32\\wininit.exe', signed: true },
    { pid: 780, name: 'lsass.exe', user: 'SYSTEM', cpu: 0.2, mem: 22, path: 'C:\\Windows\\System32\\lsass.exe', signed: true },
    { pid: 812, name: 'svchost.exe', user: 'SYSTEM', cpu: 0.3, mem: 45, path: 'C:\\Windows\\System32\\svchost.exe', cmdline: 'svchost.exe -k netsvcs', signed: true },
    { pid: 900, name: 'svchost.exe', user: 'NETWORK SERVICE', cpu: 0.1, mem: 30, path: 'C:\\Windows\\System32\\svchost.exe', cmdline: 'svchost.exe -k NetworkService', signed: true },
    { pid: 1204, name: 'spoolsv.exe', user: 'SYSTEM', cpu: 0, mem: 14, path: 'C:\\Windows\\System32\\spoolsv.exe', signed: true },
    { pid: 1388, name: 'MsMpEng.exe', user: 'SYSTEM', cpu: 1.2, mem: 180, path: 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe', signed: true },
    { pid: 1450, name: 'HalberdAgent.exe', user: 'SYSTEM', cpu: 0.4, mem: 95, path: 'C:\\Program Files\\Halberd EDR\\HalberdAgent.exe', signed: true },
    { pid: 2210, name: 'explorer.exe', user, cpu: 0.8, mem: 120, path: 'C:\\Windows\\explorer.exe', signed: true },
    { pid: 2890, name: 'OneDrive.exe', user, cpu: 0.2, mem: 85, path: 'C:\\Users\\' + user.split('\\').pop() + '\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe', signed: true },
    { pid: 3120, name: 'OUTLOOK.EXE', user, cpu: 1.1, mem: 310, path: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', signed: true },
    { pid: 3388, name: 'Teams.exe', user, cpu: 2.4, mem: 540, path: 'C:\\Users\\' + user.split('\\').pop() + '\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe', signed: true },
    { pid: 3610, name: 'chrome.exe', user, cpu: 3.1, mem: 620, path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', signed: true },
    { pid: 3644, name: 'chrome.exe', user, cpu: 0.6, mem: 140, path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', cmdline: 'chrome.exe --type=renderer', parentPid: 3610, signed: true },
    { pid: 4102, name: 'SearchHost.exe', user, cpu: 0.1, mem: 60, path: 'C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe', signed: true },
    { pid: 4320, name: 'RuntimeBroker.exe', user, cpu: 0, mem: 25, path: 'C:\\Windows\\System32\\RuntimeBroker.exe', signed: true },
  ];
}

export function baseServices(): Svc[] {
  return [
    { name: 'Spooler', displayName: 'Print Spooler', status: 'running', startType: 'auto' },
    { name: 'Dhcp', displayName: 'DHCP Client', status: 'running', startType: 'auto' },
    { name: 'Dnscache', displayName: 'DNS Client', status: 'running', startType: 'auto' },
    { name: 'W32Time', displayName: 'Windows Time', status: 'running', startType: 'manual' },
    { name: 'WinDefend', displayName: 'Microsoft Defender Antivirus Service', status: 'running', startType: 'auto' },
    { name: 'HalberdAgent', displayName: 'Halberd EDR Agent', status: 'running', startType: 'auto', path: 'C:\\Program Files\\Halberd EDR\\HalberdAgent.exe' },
    { name: 'wuauserv', displayName: 'Windows Update', status: 'running', startType: 'manual' },
    { name: 'LanmanWorkstation', displayName: 'Workstation', status: 'running', startType: 'auto' },
    { name: 'Netlogon', displayName: 'Netlogon', status: 'running', startType: 'auto' },
    { name: 'WlanSvc', displayName: 'WLAN AutoConfig', status: 'running', startType: 'auto' },
    { name: 'Audiosrv', displayName: 'Windows Audio', status: 'running', startType: 'auto' },
    { name: 'BITS', displayName: 'Background Intelligent Transfer Service', status: 'running', startType: 'manual' },
    { name: 'gpsvc', displayName: 'Group Policy Client', status: 'running', startType: 'auto' },
    { name: 'OneDrive Updater Service', displayName: 'OneDrive Updater', status: 'stopped', startType: 'manual' },
  ];
}

export function baseEvents(user: string): WinEvent[] {
  return [
    { id: 6005, time: daysAgo(1), level: 'Information', source: 'EventLog', log: 'System', message: 'The Event log service was started.' },
    { id: 4624, time: ago(240), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: `An account was successfully logged on. Account: ${user}. Logon Type: 2 (Interactive).` },
    { id: 7036, time: ago(230), level: 'Information', source: 'Service Control Manager', log: 'System', message: 'The Windows Update service entered the running state.' },
    { id: 1001, time: ago(200), level: 'Information', source: 'Windows Error Reporting', log: 'Application', message: 'Fault bucket, type 0. Event Name: AppHangB1. Application: Teams.exe' },
    { id: 10016, time: ago(180), level: 'Warning', source: 'DistributedCOM', log: 'System', message: 'The application-specific permission settings do not grant Local Activation permission for the COM Server application. (This warning is benign and common.)' },
    { id: 4624, time: ago(95), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: `An account was successfully logged on. Account: ${user}. Logon Type: 7 (Unlock).` },
  ];
}

interface H { id: string; owner?: string; kind: Host['kind']; ip: string; site: string; os?: string }

const RAW_HOSTS: H[] = [
  { id: 'DEN-LT-1041', owner: 'jmorales', kind: 'laptop', ip: '10.10.20.41', site: 'Denver HQ' },
  { id: 'DEN-LT-1042', owner: 'bpatel', kind: 'laptop', ip: '10.10.20.42', site: 'Denver HQ' },
  { id: 'DEN-LT-1050', owner: 'sturner', kind: 'laptop', ip: '10.10.20.50', site: 'Denver HQ' },
  { id: 'DEN-LT-1051', owner: 'dkim', kind: 'laptop', ip: '10.10.20.51', site: 'Denver HQ' },
  { id: 'DEN-LT-1060', owner: 'ewright', kind: 'laptop', ip: '10.10.20.60', site: 'Denver HQ' },
  { id: 'DEN-LT-1061', owner: 'cflores', kind: 'laptop', ip: '10.10.99.14', site: 'Remote (VPN)' },
  { id: 'DEN-LT-1062', owner: 'hsato', kind: 'laptop', ip: '10.10.99.22', site: 'Remote (VPN)' },
  { id: 'DEN-WS-2010', owner: 'nfoster', kind: 'workstation', ip: '10.10.21.10', site: 'Denver HQ' },
  { id: 'DEN-WS-2011', owner: 'obennett', kind: 'workstation', ip: '10.10.21.11', site: 'Denver HQ' },
  { id: 'DEN-LT-1001', owner: 'dvance', kind: 'laptop', ip: '10.10.20.11', site: 'Denver HQ' },
  { id: 'DEN-LT-1002', owner: 'rokafor', kind: 'laptop', ip: '10.10.20.12', site: 'Denver HQ' },
  { id: 'DEN-LT-1005', owner: 'tmartin', kind: 'laptop', ip: '10.10.20.15', site: 'Denver HQ' },
  { id: 'DEN-LT-1070', owner: 'jwebb', kind: 'laptop', ip: '10.10.20.70', site: 'Denver HQ' },
  { id: 'DEN-LT-1080', owner: 'rsingh', kind: 'laptop', ip: '10.10.20.80', site: 'Denver HQ' },
  { id: 'DEN-WS-2001', owner: 'pcole', kind: 'workstation', ip: '10.10.20.21', site: 'Denver HQ' },
  { id: 'DEN-LT-1021', owner: 'mreyes', kind: 'laptop', ip: '10.10.20.121', site: 'Denver HQ' },
  { id: 'DEN-LT-1023', owner: 'kwalsh', kind: 'laptop', ip: '10.10.20.123', site: 'Denver HQ' },
  { id: 'DEN-LT-1024', owner: 'agrant', kind: 'laptop', ip: '10.10.20.124', site: 'Denver HQ' },
  { id: 'WIC-WS-3001', owner: 'gharris', kind: 'workstation', ip: '10.20.10.31', site: 'Wichita Plant' },
  { id: 'WIC-WS-3002', owner: 'mjohnson', kind: 'workstation', ip: '10.20.10.32', site: 'Wichita Plant' },
  { id: 'WIC-WS-3003', owner: 'lortiz', kind: 'workstation', ip: '10.20.10.33', site: 'Wichita Plant' },
  { id: 'WIC-WS-3020', owner: 'tbrandt', kind: 'workstation', ip: '10.20.10.50', site: 'Wichita Plant' },
  { id: 'CTR-LT-9001', owner: 'abaxter', kind: 'laptop', ip: '10.10.99.40', site: 'Remote (VPN)', os: 'Windows 11 Pro 23H2' },
];

function mkHost(h: H, i: number): Host {
  const user = `KESTREL\\${h.owner ?? 'nobody'}`;
  const isRemote = h.site.startsWith('Remote');
  const subnet = h.ip.split('.').slice(0, 3).join('.');
  return {
    id: h.id,
    owner: h.owner,
    kind: h.kind,
    os: h.os ?? (h.kind === 'laptop' ? 'Windows 11 Enterprise 24H2' : 'Windows 11 Enterprise 23H2'),
    build: '26100.1742',
    ip: h.ip,
    mac: `3C-52-82-${(0x10 + i).toString(16).toUpperCase().padStart(2, '0')}-A1-${(0x40 + i).toString(16).toUpperCase()}`,
    site: h.site,
    lastSeen: ago(1 + (i % 4)),
    online: true,
    domainJoined: true,
    edrAgent: 'healthy',
    isolated: false,
    processes: baseProcesses(user),
    services: baseServices(),
    events: baseEvents(user),
    programs: [
      { name: 'Microsoft 365 Apps for enterprise', version: '16.0.18129', publisher: 'Microsoft Corporation', installedOn: daysAgo(90) },
      { name: 'Google Chrome', version: '129.0.6668.71', publisher: 'Google LLC', installedOn: daysAgo(12) },
      { name: 'Halberd EDR Agent', version: '5.2.1', publisher: 'Halberd Security', installedOn: daysAgo(45) },
      { name: 'Zoom Workplace', version: '6.1.6', publisher: 'Zoom Video Communications', installedOn: daysAgo(30) },
      { name: 'Adobe Acrobat Reader', version: '24.003', publisher: 'Adobe Inc.', installedOn: daysAgo(60) },
      { name: 'Kestrel VPN Client', version: '3.4.0', publisher: 'Kestrel Dynamics IT', installedOn: daysAgo(120) },
      ...(h.owner && ['nfoster', 'obennett'].includes(h.owner) ? [{ name: 'SOLIDWORKS 2025', version: '33.1', publisher: 'Dassault Systemes', installedOn: daysAgo(200) }] : []),
      ...(h.owner && ['jmorales', 'bpatel', 'rokafor'].includes(h.owner) ? [{ name: 'Kestrel ERP Client', version: '8.2', publisher: 'Kestrel Dynamics IT', installedOn: daysAgo(150) }] : []),
    ],
    devices: [
      { name: 'Intel(R) Wi-Fi 6E AX211', class: 'Network adapters', status: 'ok', driver: '23.30.0.6', driverDate: daysAgo(100) },
      { name: 'Intel(R) Ethernet Connection I219-LM', class: 'Network adapters', status: 'ok', driver: '12.19.2.45', driverDate: daysAgo(200) },
      { name: 'Intel(R) Iris(R) Xe Graphics', class: 'Display adapters', status: 'ok', driver: '31.0.101.5186', driverDate: daysAgo(80) },
      { name: 'Realtek(R) Audio', class: 'Sound, video and game controllers', status: 'ok', driver: '6.0.9613.1', driverDate: daysAgo(150) },
      { name: 'Dell Dock WD22TB4', class: 'USB devices', status: 'ok', driver: '1.0.14', driverDate: daysAgo(180) },
      { name: 'Integrated Webcam', class: 'Cameras', status: 'ok', driver: '10.0.22621.1' },
    ],
    network: {
      dhcp: true,
      ip: h.ip,
      mask: '255.255.255.0',
      gateway: `${subnet}.1`,
      dns: ['10.10.10.5', '10.10.10.6'],
      adapter: h.kind === 'laptop' ? 'Wi-Fi (Intel AX211)' : 'Ethernet (Intel I219-LM)',
      adapterStatus: 'up',
      ssid: h.kind === 'laptop' && !isRemote ? 'Kestrel-Corp' : undefined,
      vpn: isRemote ? 'connected' : 'n/a',
    },
    updates: { lastInstalled: daysAgo(9), pending: 0, status: 'Up to date' },
    disk: { used: 180 + (i * 13) % 200, size: 512 },
    uptimeHours: 5 + (i * 7) % 60,
    localAdmins: ['KESTREL\\Domain Admins', 'KESTREL\\IT-Admins'],
    scheduledTasks: [
      { name: 'OneDrive Standalone Update Task', path: '\\', action: 'OneDriveStandaloneUpdater.exe', trigger: 'Daily 03:00', author: 'Microsoft' },
      { name: 'GoogleUpdateTaskMachineUA', path: '\\', action: 'GoogleUpdate.exe /ua', trigger: 'Hourly', author: 'Google' },
      { name: 'Halberd Inventory', path: '\\Halberd\\', action: 'HalberdAgent.exe --inventory', trigger: 'Every 6 hours', author: 'KESTREL\\mreyes' },
    ],
    files: [
      { path: 'C:\\Users\\' + (h.owner ?? 'Public') + '\\Downloads\\', size: 0, modified: daysAgo(1) },
    ],
    printers: h.site === 'Wichita Plant' ? ['WIC-PRN-Floor1'] : ['DEN-PRN-2F-Copier', 'DEN-PRN-Finance'],
    timeZone: h.site === 'Wichita Plant' ? 'Central Standard Time' : 'Mountain Standard Time',
    clockSkewSec: 0,
    bitlocker: 'on',
    monitors: h.kind === 'laptop'
      ? [{ name: 'Built-in display', status: 'active' }, { name: 'Dell P2422H (dock)', status: 'active' }]
      : [{ name: 'Dell P2422H', status: 'active' }, { name: 'Dell P2422H (2)', status: 'active' }],
  };
}

// ----------------------------------------------------------------------------
// Servers
// ----------------------------------------------------------------------------
function svc(name: string, displayName: string, status: Svc['status'] = 'running', startType: Svc['startType'] = 'auto'): Svc {
  return { name, displayName, status, startType };
}

function mkServers(): Server[] {
  return [
    {
      id: 'DEN-DC01', role: 'Domain Controller / DNS / DHCP (Denver)', ip: '10.10.10.5', os: 'Windows Server 2022', status: 'online',
      services: [svc('NTDS', 'Active Directory Domain Services'), svc('DNS', 'DNS Server'), svc('DHCPServer', 'DHCP Server'), svc('Kdc', 'Kerberos Key Distribution Center'), svc('Netlogon', 'Netlogon'), svc('W32Time', 'Windows Time')],
      disk: [{ drive: 'C:', used: 62, size: 120 }], cpu: 8, mem: 41, uptimeHours: 890, events: [],
      dhcpScopes: [
        { name: 'Denver-Users (10.10.20.0/24)', range: '10.10.20.20 - 10.10.20.250', used: 118, total: 231, leaseHours: 8, status: 'active' },
        { name: 'Denver-Eng (10.10.21.0/24)', range: '10.10.21.10 - 10.10.21.250', used: 24, total: 241, leaseHours: 8, status: 'active' },
        { name: 'Denver-Guest-WiFi (10.10.50.0/24)', range: '10.10.50.10 - 10.10.50.250', used: 61, total: 241, leaseHours: 2, status: 'active' },
        { name: 'Denver-VoIP (10.10.30.0/24)', range: '10.10.30.10 - 10.10.30.250', used: 88, total: 241, leaseHours: 24, status: 'active' },
      ],
      dnsRecords: [
        { name: 'fs01.kestrel.local', type: 'A', value: '10.10.10.20' },
        { name: 'print01.kestrel.local', type: 'A', value: '10.10.10.25' },
        { name: 'erp.kestrel.local', type: 'A', value: '10.10.10.40' },
        { name: 'vpn.kestreldynamics.com', type: 'A', value: '198.51.100.10' },
        { name: 'kestreldynamics.com', type: 'MX', value: '10 mx.worksuite-mail.net' },
        { name: 'kestreldynamics.com', type: 'TXT', value: 'v=spf1 include:spf.worksuite-mail.net -all' },
      ],
    },
    {
      id: 'DEN-DC02', role: 'Domain Controller / DNS (Denver, secondary)', ip: '10.10.10.6', os: 'Windows Server 2022', status: 'online',
      services: [svc('NTDS', 'Active Directory Domain Services'), svc('DNS', 'DNS Server'), svc('Kdc', 'Kerberos Key Distribution Center'), svc('Netlogon', 'Netlogon')],
      disk: [{ drive: 'C:', used: 58, size: 120 }], cpu: 5, mem: 38, uptimeHours: 890, events: [],
    },
    {
      id: 'WIC-DC01', role: 'Domain Controller / DNS / DHCP (Wichita)', ip: '10.20.10.5', os: 'Windows Server 2022', status: 'online',
      services: [svc('NTDS', 'Active Directory Domain Services'), svc('DNS', 'DNS Server'), svc('DHCPServer', 'DHCP Server'), svc('Netlogon', 'Netlogon')],
      disk: [{ drive: 'C:', used: 55, size: 120 }], cpu: 6, mem: 35, uptimeHours: 1200, events: [],
      dhcpScopes: [
        { name: 'Wichita-Users (10.20.10.0/24)', range: '10.20.10.20 - 10.20.10.250', used: 77, total: 231, leaseHours: 8, status: 'active' },
        { name: 'Wichita-Floor (10.20.11.0/24)', range: '10.20.11.20 - 10.20.11.250', used: 140, total: 231, leaseHours: 8, status: 'active' },
      ],
    },
    {
      id: 'DEN-FS01', role: 'File Server', ip: '10.10.10.20', os: 'Windows Server 2022', status: 'online',
      services: [svc('LanmanServer', 'Server'), svc('FsrmSvc', 'File Server Resource Manager'), svc('VSS', 'Volume Shadow Copy', 'running', 'manual'), svc('HalberdAgent', 'Halberd EDR Agent')],
      disk: [{ drive: 'C:', used: 70, size: 120 }, { drive: 'D:', used: 3100, size: 4000 }], cpu: 12, mem: 46, uptimeHours: 400, events: [],
      shares: [
        { name: 'Finance', path: 'D:\\Shares\\Finance', ntfsGroups: ['FS-Finance-RW'], status: 'ok' },
        { name: 'HR', path: 'D:\\Shares\\HR', ntfsGroups: ['FS-HR-RW'], status: 'ok' },
        { name: 'Engineering', path: 'D:\\Shares\\Engineering', ntfsGroups: ['FS-Engineering-RW'], status: 'ok' },
        { name: 'Shared', path: 'D:\\Shares\\Shared', ntfsGroups: ['FS-Shared-RW'], status: 'ok' },
      ],
      backups: [{ job: 'FS01-Daily-Shares', lastRun: ago(60 * 9), status: 'success', restorePoints: 30 }],
    },
    {
      id: 'DEN-PRINT01', role: 'Print Server', ip: '10.10.10.25', os: 'Windows Server 2019', status: 'online',
      services: [svc('Spooler', 'Print Spooler')],
      disk: [{ drive: 'C:', used: 40, size: 100 }], cpu: 3, mem: 30, uptimeHours: 2100, events: [],
      printQueues: [
        { name: 'DEN-PRN-2F-Copier', status: 'ready', jobs: 0, location: 'Denver 2F, near kitchen' },
        { name: 'DEN-PRN-Finance', status: 'ready', jobs: 0, location: 'Denver 3F, Finance' },
        { name: 'DEN-PRN-Exec', status: 'ready', jobs: 0, location: 'Denver 4F, Exec suite' },
        { name: 'WIC-PRN-Floor1', status: 'ready', jobs: 0, location: 'Wichita plant floor office' },
      ],
    },
    {
      id: 'DEN-APP01', role: 'Kestrel ERP application server', ip: '10.10.10.40', os: 'Windows Server 2022', status: 'online',
      services: [svc('W3SVC', 'World Wide Web Publishing Service'), svc('KestrelERP', 'Kestrel ERP Service'), svc('MSSQLSERVER', 'SQL Server (MSSQLSERVER)'), svc('HalberdAgent', 'Halberd EDR Agent')],
      disk: [{ drive: 'C:', used: 80, size: 150 }, { drive: 'E:', used: 420, size: 1000 }], cpu: 22, mem: 63, uptimeHours: 300, events: [],
      backups: [{ job: 'APP01-SQL-Full', lastRun: ago(60 * 10), status: 'success', restorePoints: 14 }],
    },
    {
      id: 'DEN-VPN01', role: 'VPN concentrator (Kestrel VPN)', ip: '198.51.100.10', os: 'Appliance OS 7.2', status: 'online',
      services: [svc('vpnd', 'VPN daemon'), svc('radius-proxy', 'RADIUS proxy')],
      disk: [{ drive: '/', used: 10, size: 64 }], cpu: 14, mem: 40, uptimeHours: 1500, events: [],
    },
    {
      id: 'DEN-BKP01', role: 'Backup server', ip: '10.10.10.60', os: 'Windows Server 2022', status: 'online',
      services: [svc('VeeamBackupSvc', 'Backup Service'), svc('HalberdAgent', 'Halberd EDR Agent')],
      disk: [{ drive: 'C:', used: 60, size: 120 }, { drive: 'R:', used: 18000, size: 40000 }], cpu: 9, mem: 50, uptimeHours: 700, events: [],
      backups: [
        { job: 'FS01-Daily-Shares', lastRun: ago(60 * 9), status: 'success', restorePoints: 30 },
        { job: 'APP01-SQL-Full', lastRun: ago(60 * 10), status: 'success', restorePoints: 14 },
        { job: 'DC-SystemState', lastRun: ago(60 * 11), status: 'success', restorePoints: 7 },
        { job: 'Offsite-Immutable-Copy', lastRun: ago(60 * 26), status: 'success', restorePoints: 30 },
      ],
    },
  ];
}

// ----------------------------------------------------------------------------
// Assets
// ----------------------------------------------------------------------------
function mkAssets(hosts: Host[]): Asset[] {
  const out: Asset[] = hosts.map((h, i) => ({
    tag: `KD-${String(4000 + i).padStart(5, '0')}`,
    type: h.kind === 'laptop' ? 'laptop' : 'desktop',
    model: h.kind === 'laptop' ? 'Dell Latitude 5450' : 'Dell Precision 3680',
    serial: `${h.kind === 'laptop' ? 'DL' : 'DP'}${(7000000 + i * 1337).toString(36).toUpperCase()}`,
    assignedTo: h.owner,
    hostname: h.id,
    status: 'deployed',
    purchaseDate: daysAgo(400 + (i * 37) % 600),
    warrantyEnd: daysAgo(400 + (i * 37) % 600 - 3 * 365),
    location: h.site,
  }));
  out.push(
    { tag: 'KD-05001', type: 'laptop', model: 'Dell Latitude 5450', serial: 'DLSTOCK01', status: 'in stock', purchaseDate: daysAgo(20), warrantyEnd: daysAgo(20 - 3 * 365), location: 'Denver IT stockroom', notes: 'Imaged, ready to deploy' },
    { tag: 'KD-05002', type: 'laptop', model: 'Dell Latitude 5450', serial: 'DLSTOCK02', status: 'in stock', purchaseDate: daysAgo(20), warrantyEnd: daysAgo(20 - 3 * 365), location: 'Denver IT stockroom', notes: 'Imaged, ready to deploy' },
    { tag: 'KD-06010', type: 'monitor', model: 'Dell P2422H', serial: 'CN0MON010', status: 'in stock', purchaseDate: daysAgo(100), warrantyEnd: daysAgo(100 - 3 * 365), location: 'Denver IT stockroom' },
    { tag: 'KD-06011', type: 'dock', model: 'Dell WD22TB4', serial: 'CN0DCK011', status: 'in stock', purchaseDate: daysAgo(100), warrantyEnd: daysAgo(100 - 3 * 365), location: 'Denver IT stockroom' },
    { tag: 'KD-07001', type: 'printer', model: 'HP LaserJet M507', serial: 'HPM507A', status: 'deployed', purchaseDate: daysAgo(700), warrantyEnd: daysAgo(700 - 365), location: 'Denver 3F, Finance', hostname: 'DEN-PRN-Finance' },
    { tag: 'KD-07002', type: 'printer', model: 'Xerox AltaLink C8145', serial: 'XRX8145B', status: 'deployed', purchaseDate: daysAgo(500), warrantyEnd: daysAgo(500 - 3 * 365), location: 'Denver 2F, near kitchen', hostname: 'DEN-PRN-2F-Copier' },
  );
  return out;
}

// ----------------------------------------------------------------------------
// Knowledge base (SOPs). These are the "rules" the grading enforces; make sure
// scenarios reference them so trainees learn to read the KB.
// ----------------------------------------------------------------------------
export const KB: KbArticle[] = [
  {
    id: 'KB-0001', title: 'SOP: Caller identity verification (REQUIRED before any account change)', tags: ['identity', 'verification', 'password', 'unlock', 'security', 'sop'],
    body: `Before performing ANY account action (password reset, unlock, MFA reset, group change, mailbox delegation) you MUST verify the caller.

Acceptable verification (need TWO of the following):
  1. Employee ID (from Directory) - the caller states it, you confirm it matches.
  2. Callback to the phone number on record in the Directory.
  3. Manager confirms by chat/phone (manager name must match the Directory).
  4. Video call with badge shown (Teams/Zoom).

NOT acceptable: name + department, "I'm in a hurry", a phone number the caller gives you, an email from the same account that is locked.

Red flags - STOP and escalate to the Security team:
  - Caller refuses verification or gets aggressive about urgency.
  - Caller asks you to send the new password to a personal (non-corporate) email or text.
  - Caller claims to be an executive or "from IT" and asks for a password/MFA reset for someone else.
  - The account was locked by multiple failures from an external IP.

Document in the ticket: which two factors were used (e.g. "Verified: Employee ID + callback to number on record").`,
  },
  {
    id: 'KB-0002', title: 'SOP: Password reset and account unlock', tags: ['password', 'reset', 'unlock', 'lockout', 'directory', 'sop'],
    body: `1. Verify identity per KB-0001.
2. In Directory, open the user. Check:
   - Locked Out? -> Unlock. Check Bad Password Count and the last sign-in attempts. Many failures from an IP that is not the user's device = possible attack: do NOT just unlock; escalate to Security.
   - Password expired? -> Reset password. Set "must change at next logon".
   - Disabled? -> Do NOT enable. Check with HR/manager: terminated users stay disabled.
3. Give a temporary password by phone only (never email/chat). The user must change it at first logon.
4. If the user's device is off the corporate network (remote, VPN not connected) the cached credential will not update until they connect to VPN and lock/unlock. Tell them.
5. Common lockout causes: old password saved in a phone mail app, mapped drive with saved credentials, scheduled task running as the user, a disconnected RDP session.
6. Document: cause found, action taken, verification factors used.`,
  },
  {
    id: 'KB-0003', title: 'Service Desk ticket priority matrix', tags: ['priority', 'sla', 'p1', 'p2', 'triage', 'sop'],
    body: `Priority = Impact x Urgency.

P1 - Critical (respond 15 min, resolve 4h): whole site / department down; revenue or safety impact; any confirmed security incident; executive unable to work during a board event.
P2 - High (respond 30 min, resolve 8h): single user cannot work at all; shared resource (printer, share, app) down for a team; possible security issue.
P3 - Medium (respond 4h, resolve 3 days): single user degraded but has a workaround; single peripheral issue.
P4 - Low (respond 1 day, resolve 5 days): requests, how-to, cosmetic, name changes, new hardware requests.

Requester-selected priority is a suggestion. The analyst sets the real priority and notes why.`,
  },
  {
    id: 'KB-0004', title: 'Escalation matrix - who owns what', tags: ['escalation', 'matrix', 'sd2', 'network', 'sysadmin', 'soc', 'cirt', 'sop'],
    body: `Service Desk I resolves: password/unlock, basic Windows/Office, printers, peripherals, how-to, VPN client basics, hardware swaps from stock, standard access requests with manager approval.
Escalate to Service Desk II (desktop): driver/OS corruption, reimage, application crashes needing deeper diagnosis, malware cleanup AFTER Security has cleared it.
Escalate to Network Team: switch/AP/WAN issues, DHCP scope exhaustion, VLAN, firewall rule changes, site-wide outages.
Escalate to Sysadmin: server services, file shares/NTFS, DHCP/DNS server issues, ERP app server, backups/restores.
Escalate to Identity team: MFA hardware, SSO/federation, service accounts, privileged group membership.
Escalate to Security (SOC): phishing reports, suspicious sign-ins, malware alerts, data loss, lost/stolen devices, anything where a user entered credentials on a suspicious page, requests that smell like social engineering.
SOC escalates to CIRT when: confirmed compromise of a host or account, ransomware, data exfiltration, anything touching Domain Admins or servers, or when more than one host/user is involved.
HR: name changes, terminations, conduct issues. Legal: anything involving litigation hold, regulator notification, law enforcement.
Never escalate without: what the user reported, what you checked, what you found, what you tried.`,
  },
  {
    id: 'KB-0005', title: 'Phishing report handling (Service Desk)', tags: ['phishing', 'email', 'security', 'sop', 'report'],
    body: `When a user reports a suspicious email:
1. Do NOT open links or attachments yourself.
2. Ask: did you click the link? Did you enter your password? Did you open the attachment? Did you reply?
3. If YES to any -> P2, escalate to Security (SOC) immediately with the message ID, and tell the user not to use the account until Security clears it. Do not reset the password before SOC looks (they need the sign-in evidence intact) unless SOC tells you to.
4. If NO -> thank the user, ask them to use the "Report phishing" button, note the message ID from Mail Admin, and close as "Phishing - reported, no interaction".
5. Never forward the email to other people "to warn them"; Security handles broadcast warnings.`,
  },
  {
    id: 'KB-0006', title: 'New hire / name change / termination requests', tags: ['onboarding', 'name change', 'termination', 'hr', 'access', 'sop'],
    body: `Name change: requires an HR ticket or HR confirmation in the ticket. Change Display Name, and add the new email as an alias (keep the old one). Do NOT rename the sAMAccountName (breaks profiles).
New hire: HR-initiated only; use the template for the department; manager approves group membership beyond the department default.
Termination: only from HR or the manager via ticket. Disable account, reset password, remove from groups, convert mailbox to shared for manager, retrieve the asset. Never re-enable a terminated account because "they need to grab a file" - the manager gets delegate access instead.
Access requests to sensitive groups (Finance, HR, AP-Team, Executive-Assistants, any *-Admins) require the DATA OWNER's approval, not just the requester's manager.`,
  },
  {
    id: 'KB-0007', title: 'Troubleshooting: no network / no internet', tags: ['network', 'dhcp', 'dns', 'wifi', 'ethernet', 'apipa', 'troubleshooting'],
    body: `1. Scope it: one user or many? Same floor/site? Wired or wireless?
2. On the machine: ipconfig /all. An address 169.254.x.x (APIPA) = no DHCP lease. Check the DHCP scope on the site DC for exhaustion.
3. ping the gateway. ping 8.8.8.8 (raw internet). nslookup kestreldynamics.com (DNS). If ping works but nslookup fails -> DNS.
4. Wireless: is the SSID Kestrel-Corp? Guest-WiFi has no internal access.
5. Docks: a dead dock shows as "media disconnected" on the Ethernet adapter. Try another dock from stock.
6. Many users on one site/floor = Network Team, P1/P2. One user = keep it.`,
  },
  {
    id: 'KB-0008', title: 'Troubleshooting: printers', tags: ['printer', 'print', 'spooler', 'queue', 'troubleshooting'],
    body: `1. Is it one user or the whole queue? Check the queue on DEN-PRINT01 (Server Room > Print Queues).
2. Queue paused or stuck job -> clear/resume from the server.
3. Queue error "offline" -> the printer itself: power, network cable, or paper jam. Ask the user to check the panel; facilities handles jams/toner.
4. Only one user: restart the Spooler service on their PC, remove and re-add the printer.
5. Toner: Facilities stocks toner; log a P4 to Facilities.`,
  },
  {
    id: 'KB-0009', title: 'Troubleshooting: shared drive / file access', tags: ['share', 'file', 'ntfs', 'permission', 'access denied', 'mapped drive', 'troubleshooting'],
    body: `1. "Access denied" on \\\\FS01\\<share>: check the user's groups against the share's NTFS groups (Server Room > FS01 > Shares).
2. If the user is missing the group: access to Finance/HR requires the data owner's approval (KB-0006). Don't add on the user's say-so.
3. If they ARE in the group but still denied: a group change needs a fresh logon token. Have them sign out and in (not just lock).
4. "Drive not found": the share may be offline or the drive letter unmapped. Check the server status; run gpupdate /force and re-logon.
5. Deleted files: FS01 has shadow copies and 30 days of backups. Restores of files older than shadow copies go to the Sysadmin.`,
  },
  {
    id: 'KB-0010', title: 'Troubleshooting: displays, docks and peripherals', tags: ['monitor', 'display', 'dock', 'usb', 'peripheral', 'driver', 'troubleshooting'],
    body: `Second monitor black: check Device Manager (display adapter status), reseat the cable, try the other dock port, and check the monitor's input source. A dock with a failed firmware often shows the monitor "no signal" while USB still works.
No audio: Device Manager - audio device status; Windows Audio service running.
Driver error (Code 10/43/28): update or roll back the driver; if it persists, escalate to Desktop (SD2) for reimage consideration.
Hardware under warranty -> log a vendor dispatch via the asset record; out of warranty -> swap from stock.`,
  },
  {
    id: 'KB-0011', title: 'Troubleshooting: VPN and remote workers', tags: ['vpn', 'remote', 'cached credentials', 'troubleshooting'],
    body: `1. VPN user must be in "VPN Users" group and MFA-enrolled.
2. "Authentication failed" right after a password reset: the laptop has the OLD password cached. Connect VPN using the "Sign in as different user" option with the NEW password, then lock/unlock.
3. VPN connects but no internal resources: check the assigned IP (10.10.99.x) and that DNS points at 10.10.10.5/6.
4. Repeated VPN sign-ins from a country the user is not in = Security escalation, do not reset the password first.`,
  },
  {
    id: 'KB-0012', title: 'Malware / pop-ups / unwanted software on a workstation', tags: ['malware', 'adware', 'popup', 'pua', 'security', 'troubleshooting'],
    body: `Service Desk may handle ADWARE / PUA (browser extensions, "PC optimizer" installers) when Halberd EDR shows NO alert for the host:
  - Task Manager: end the unknown process. Programs: uninstall the unknown publisher. Check browser extensions. Run a Defender full scan.
  - Document the program name and where it came from (Downloads folder date).
Anything with an EDR alert, a process running from AppData/Temp with a scheduled task or service persistence, credential prompts, or outbound connections to unknown hosts -> STOP, do not clean, do not reboot (evidence), escalate to Security as P2 and isolate ONLY if Security asks.`,
  },
  {
    id: 'KB-0013', title: 'SOC: Alert triage standard', tags: ['soc', 'triage', 'alert', 'true positive', 'false positive', 'classification', 'sop'],
    body: `Every alert closes with a classification:
  - True Positive: malicious activity confirmed. Contain per playbook, escalate to CIRT if scope > 1 host/user, servers, or privileged accounts.
  - Benign True Positive: the detection fired correctly but the activity is authorized (e.g. admin running a scanner, approved pentest, IT script). Document WHO authorized it and link the change/ticket. Tune if noisy.
  - False Positive: the detection logic misfired (nothing matching the described behavior happened). Document why and open a tuning request.

Minimum evidence before closing: the triggering event in the SIEM, the process tree or mail headers as relevant, the user's recent sign-ins, and a threat intel lookup of every external indicator.
Severity guide: critical = active hands-on-keyboard / ransomware / DA compromise; high = confirmed malware execution or credential compromise; medium = suspicious but unconfirmed / blocked by controls; low = policy violation, PUA, informational.
Containment authority: SOC I may isolate a single workstation and disable a single non-privileged user. Servers, privileged accounts, and firewall blocks require SOC II or CIRT.`,
  },
  {
    id: 'KB-0014', title: 'SOC playbook: Phishing / credential harvesting', tags: ['soc', 'phishing', 'playbook', 'credential', 'mail'],
    body: `1. Pull the message in Mail Admin: headers (SPF/DKIM/DMARC, return-path vs from, reply-to), URLs, attachments. Look up every URL/domain/hash in Threat Intel.
2. Find every recipient (Mail Admin > trace by subject/sender). Quarantine/purge the message for all.
3. For each user who clicked or entered credentials: check Directory sign-ins for new IPs/countries/MFA prompts; check the mailbox for new inbox rules or forwarding (attackers hide their tracks).
4. If credentials were entered: reset the password, revoke sessions, remove malicious inbox rules, keep MFA registrations reviewed. Disable the account first if sign-ins from the attacker are ACTIVE.
5. Block the sender domain and URL at the mail gateway/proxy.
6. Escalate to CIRT if: a privileged user was phished, mailbox rules forward externally, or the attacker signed in successfully.
7. Classification: True Positive if the message is malicious even if nobody clicked.`,
  },
  {
    id: 'KB-0015', title: 'SOC playbook: Malware / suspicious process on endpoint', tags: ['soc', 'malware', 'edr', 'playbook', 'process', 'persistence'],
    body: `1. EDR: open the host, review the process tree of the alerting process: parent (Office app / browser / script host?), command line, path (AppData/Temp/Public are suspicious), signature, hash.
2. Threat Intel: look up the hash and any domain/IP the process contacted (SIEM: proxy/dns/firewall logs for the host around the alert time).
3. Look for persistence: scheduled tasks, services, Run keys (Remote Desktop > Scheduled Tasks/Services).
4. Look for lateral movement: SIEM auth logs for the host's user logging on to OTHER hosts (logon type 3/10) after the alert.
5. Contain: isolate the host in EDR (SOC I may do this for workstations). Do NOT reimage or delete the file before triage collection - collect a triage package first.
6. Reset the user's credentials if the malware is a stealer/RAT.
7. Escalate to CIRT if: lateral movement, server involved, privileged account, ransomware note, or C2 confirmed by intel.
8. Ticket the Service Desk to reimage AFTER CIRT/SOC release the host.`,
  },
  {
    id: 'KB-0016', title: 'SOC playbook: Suspicious sign-in / impossible travel / MFA fatigue', tags: ['soc', 'sign-in', 'identity', 'mfa', 'impossible travel', 'playbook'],
    body: `1. Directory: review the user's recent sign-ins: IPs, locations, apps, MFA result. Compare to their known devices and location.
2. Threat Intel the source IP (anonymizer / VPN / hosting = higher risk).
3. Contact the user (chat) to confirm: were you travelling? did you approve an MFA prompt you didn't start?
4. Signs of compromise: successful sign-in from a new country followed by mailbox rule creation, mass downloads, OAuth app consents, or password change.
5. Contain: revoke sessions, reset password, review MFA methods; if the sign-in is ACTIVE from the attacker, disable first.
6. Benign True Positive when the user confirms travel AND nothing post-authentication looks wrong. Document how you confirmed (chat with the user, not just their manager's guess).
7. Privileged accounts (IT-Admins, Domain Admins, Executives) -> CIRT.`,
  },
  {
    id: 'KB-0017', title: 'CIRT: Incident severity and notification matrix', tags: ['cirt', 'incident', 'severity', 'notification', 'legal', 'regulator', 'sop'],
    body: `SEV1: ransomware, confirmed exfiltration of regulated data, Domain Admin compromise, production plant impact. Incident commander + exec bridge within 30 min.
SEV2: confirmed compromise of a host or account with no evidence of spread; business email compromise attempts on payments.
SEV3: contained single-host malware, policy violations.

Notifications (who and when):
  - IT Director / CISO: every SEV1 and SEV2 immediately.
  - Executive team: SEV1 immediately; SEV2 in the daily update.
  - Legal: any incident that may involve personal data, customer data, contracts, or law enforcement. Legal decides on regulator/customer notification - NOT the analyst. Do not contact regulators or customers directly.
  - HR: when an employee is suspected of intentional wrongdoing (insider).
  - Cyber insurance carrier: SEV1 within 24h (Legal owns the call).
  - Law enforcement: only via Legal.
  - Affected users: after containment, with clear instructions.
  - Finance/AP: for any invoice/payment-fraud attempt, immediately, to stop the payment.
Never notify "all staff" about an active incident before containment: it tips off the attacker if an insider is involved and causes panic. Targeted, factual updates only.`,
  },
  {
    id: 'KB-0018', title: 'CIRT: Incident response lifecycle and evidence handling', tags: ['cirt', 'ir', 'lifecycle', 'containment', 'eradication', 'recovery', 'evidence', 'forensics', 'sop'],
    body: `Phases: Identification -> Containment (short-term, then long-term) -> Eradication -> Recovery -> Lessons Learned.

Evidence FIRST: before you reimage, power off, or delete anything, collect a triage package / memory image and preserve the logs. Reimaging a host destroys the evidence that tells you how they got in and whether they are still in.

Containment order of operations for a compromised account: revoke sessions -> disable account -> reset password -> then review MFA/rules/OAuth. For a compromised host: isolate in EDR (keeps our management channel), do NOT power off.

Scope before eradication: check SIEM for the same indicators (hash, C2 IP, user) across ALL hosts. Eradicating one host while another is still beaconing means you will be back tomorrow.

Recovery: rebuild from a known-good image, restore data from backups taken BEFORE first compromise (check the timeline), rotate every credential the attacker could have seen (including service accounts and the KRBTGT if DA was compromised), monitor for re-entry for 30 days.

Lessons learned within 5 business days: timeline, root cause, what worked, what did not, and actionable improvements with owners.`,
  },
  {
    id: 'KB-0019', title: 'Remote Desktop and Terminal quick reference', tags: ['terminal', 'commands', 'ipconfig', 'gpupdate', 'sfc', 'reference'],
    body: `Useful commands (Remote Desktop > Terminal):
  ipconfig /all        - IP, DHCP, DNS servers, adapter state
  ipconfig /release + /renew  - get a new DHCP lease
  ipconfig /flushdns   - clear the DNS cache
  ping <host>          - reachability;  tracert <host> - path
  nslookup <name>      - DNS resolution
  netstat -ano         - open connections with PIDs (look for unknown remote IPs)
  tasklist / taskkill /PID <n> /F
  sfc /scannow         - repair system files;  DISM /Online /Cleanup-Image /RestoreHealth
  gpupdate /force      - refresh group policy (after group changes: re-logon still needed)
  whoami /groups       - the token's groups (shows whether a new group is active)
  systeminfo           - OS build, uptime, hotfixes
  w32tm /resync        - fix clock skew (Kerberos fails if skew > 5 min)
  net user <user> /domain - account status from the DC`,
  },
  {
    id: 'KB-0020', title: 'Mail Admin: message trace, quarantine and inbox rules', tags: ['mail', 'trace', 'quarantine', 'inbox rule', 'forwarding', 'reference'],
    body: `Message trace shows delivery status: delivered, quarantined (filter held it: release only if you have confirmed the sender is legitimate), blocked, deferred.
Releasing a quarantined message: check the headers first. SPF/DKIM/DMARC fail + a lookalike domain = never release; it is phishing regardless of what the user says.
Inbox rules that forward externally, delete messages from IT/Security, or move messages to RSS Feeds / Deleted Items are classic attacker persistence. Remove them and escalate.
Mailbox over quota: the user cannot send or receive. Have them archive; do not raise quota without the manager's approval.`,
  },
  {
    id: 'KB-0021', title: 'Hardware requests, loaners and shipping', tags: ['hardware', 'request', 'loaner', 'shipping', 'asset', 'reference'],
    body: `Replacement hardware needs an asset record update: mark the old device (repair/retired/lost), assign the new one, and note the ticket number.
Lost or stolen device: this is a SECURITY incident first: escalate to SOC (they will wipe/disable), then handle replacement.
Remote users: ship from stock with a prepaid return label for the old device; log the tracking number in the ticket.`,
  },
];

// ----------------------------------------------------------------------------
// Baseline logs (noise). Scenarios add signal on top.
// ----------------------------------------------------------------------------
// Deterministic PRNG so the baseline corpus is identical every load (a training
// tool should be reproducible; scenarios layer their signal on top).
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Benign SaaS the whole company talks to all day — the noise a hunter filters.
const SAAS: { d: string; ip: string; cat: string }[] = [
  { d: 'teams.microsoft.com', ip: '52.113.194.132', cat: 'collab' },
  { d: 'outlook.office.com', ip: '52.96.1.10', cat: 'mail' },
  { d: 'kestreldynamics.sharepoint.com', ip: '13.107.136.9', cat: 'files' },
  { d: 'login.microsoftonline.com', ip: '20.190.160.20', cat: 'sso' },
  { d: 'cdn.zoom.us', ip: '170.114.52.2', cat: 'collab' },
  { d: 'github.com', ip: '140.82.113.3', cat: 'dev' },
  { d: 'api.salesforce.com', ip: '104.109.10.10', cat: 'crm' },
  { d: 'update.googleapis.com', ip: '142.250.72.4', cat: 'update' },
  { d: 'www.google.com', ip: '142.250.72.4', cat: 'web' },
  { d: 'slack.com', ip: '3.89.11.1', cat: 'collab' },
  { d: 'login.worksuite-mail.net', ip: '52.96.1.10', cat: 'sso' },
  { d: 'graph.microsoft.com', ip: '20.190.161.4', cat: 'api' },
  { d: 'edge.microsoft.com', ip: '13.107.5.88', cat: 'update' },
  { d: 'aws.amazon.com', ip: '52.94.236.2', cat: 'cloud' },
];
const EDR_CLOUD = { d: 'halberd-cloud.net', ip: '34.117.59.81' };

function baselineLogs(users: DirUser[], hosts: Host[]): LogEvent[] {
  const rnd = mulberry32(0xC0FFEE);
  const pick = <T,>(arr: T[]): T => arr[Math.floor(rnd() * arr.length)];
  const logs: LogEvent[] = [];
  const WINDOW = 48 * 60; // last 48h in minutes
  const t = () => Math.floor(rnd() * WINDOW) + 3; // minutes ago within the window

  // ---- per-endpoint activity: web, EDR heartbeats, auth, OS telemetry ----
  for (const h of hosts) {
    const u = users.find((x) => x.id === h.owner);
    const remote = h.site.startsWith('Remote');
    // web / dns browsing
    const hits = 8 + Math.floor(rnd() * 8);
    for (let j = 0; j < hits; j++) {
      const s = pick(SAAS);
      const when = t();
      logs.push({ time: ago(when), source: 'dns', host: h.id, srcIp: h.ip, domain: s.d, action: 'query', message: `A? ${s.d} -> ${s.ip}`, fields: { qtype: 'A' } });
      logs.push({ time: ago(when), source: 'proxy', host: h.id, user: u?.id, srcIp: h.ip, dstIp: s.ip, domain: s.d, url: `https://${s.d}/`, action: 'allow', dstPort: 443, message: `GET https://${s.d}/ 200 (${s.cat})`, fields: { status: 200, category: s.cat } });
    }
    // EDR agent beacons to the vendor cloud
    for (let j = 0; j < 5 + Math.floor(rnd() * 4); j++) {
      logs.push({ time: ago(t()), source: 'firewall', host: h.id, srcIp: h.ip, dstIp: EDR_CLOUD.ip, dstPort: 443, action: 'allow', message: `ALLOW ${h.ip} -> ${EDR_CLOUD.ip}:443 ${EDR_CLOUD.d} (EDR heartbeat)` });
    }
    logs.push({ time: ago(t()), source: 'edr', host: h.id, action: 'health', message: `Halberd sensor healthy on ${h.id} (definitions current)`, fields: { agent: 'healthy' } });
    // DHCP lease
    if (h.network.dhcp) logs.push({ time: ago(t()), source: 'dhcp', host: h.id, srcIp: h.ip, action: 'ack', message: `DHCPACK ${h.ip} to ${h.mac} lease 8h`, fields: { mac: h.mac } });
    // Windows OS telemetry
    logs.push({ time: ago(t()), source: 'windows', host: h.id, action: 'update', message: `Windows Update: scan completed, ${Math.floor(rnd() * 3)} updates pending`, fields: { eventId: 43 } });
    if (u) {
      const srcIp = remote ? (u.recentSignIns[0]?.ip ?? '73.14.22.190') : h.ip;
      // morning interactive logon + a couple of unlocks + logoff
      logs.push({ time: ago(400 + Math.floor(rnd() * 200)), source: 'auth', host: h.id, user: u.id, srcIp, action: 'logon', message: `4624 An account was successfully logged on. Account: ${u.id}. Logon Type: 2 (Interactive). Host: ${h.id}`, fields: { eventId: 4624, logonType: 2 } });
      for (let j = 0; j < 2 + Math.floor(rnd() * 3); j++) {
        logs.push({ time: ago(t()), source: 'auth', host: h.id, user: u.id, srcIp, action: 'unlock', message: `4624 Logon Type: 7 (Unlock). Account: ${u.id} on ${h.id}`, fields: { eventId: 4624, logonType: 7 } });
      }
      // network logon to the file server (SMB) — type 3 is extremely common/benign
      logs.push({ time: ago(t()), source: 'auth', host: 'DEN-FS01', user: u.id, srcIp: h.ip, action: 'logon', message: `4624 Logon Type: 3 (Network). Account: ${u.id} from ${h.id} to \\\\FS01`, fields: { eventId: 4624, logonType: 3 } });
      // occasional benign mistype at the keyboard
      if (rnd() < 0.25) logs.push({ time: ago(t()), source: 'auth', host: h.id, user: u.id, srcIp, action: 'fail', message: `4625 Failed logon. Account: ${u.id}. Reason: bad password (user mistype). Host: ${h.id}`, fields: { eventId: 4625, logonType: 2 } });
    }
  }

  // ---- per-user cloud sign-ins + inbound mail ----
  const mailSenders = ['newsletter@atlassian.com', 'notifications@github.com', 'no-reply@salesforce.com', 'calendar@zoom.us', 'billing@microsoft.com', 'hr-updates@kestreldynamics.com'];
  for (const u of users) {
    if (u.id.startsWith('svc_')) continue;
    const remote = u.location.startsWith('Remote');
    const ip = remote ? (u.recentSignIns[0]?.ip ?? '73.14.22.190') : (hosts.find((h) => h.owner === u.id)?.ip ?? '10.10.20.30');
    for (let j = 0; j < 3 + Math.floor(rnd() * 4); j++) {
      const app = pick(['WorkSuite Mail', 'SharePoint', 'Teams', 'Salesforce', 'GitHub SSO']);
      logs.push({ time: ago(t()), source: 'cloud', user: u.id, srcIp: ip, action: 'signin', message: `Sign-in success user=${u.id} app=${app} mfa=satisfied ip=${ip}`, fields: { result: 'success', app, mfa: 'satisfied' } });
    }
    for (let j = 0; j < 2 + Math.floor(rnd() * 3); j++) {
      const from = pick(mailSenders);
      logs.push({ time: ago(t()), source: 'email', user: u.id, action: 'deliver', message: `Delivered to ${u.id}@kestreldynamics.com from ${from} (spf=pass dkim=pass dmarc=pass)`, fields: { from, verdict: 'clean' } });
    }
  }

  // ---- remote workers on the VPN ----
  for (const [uid, ip, geo, asn] of [['cflores', '73.14.22.190', 'Phoenix,US', '10.10.99.14'], ['hsato', '67.160.8.51', 'Seattle,US', '10.10.99.22'], ['abaxter', '98.42.117.9', 'Austin,US', '10.10.99.40']] as const) {
    for (let j = 0; j < 2 + Math.floor(rnd() * 2); j++) {
      logs.push({ time: ago(t()), source: 'vpn', user: uid, srcIp: ip, action: 'connect', message: `VPN session established user=${uid} assigned=${asn} geo=${geo} mfa=satisfied` });
      logs.push({ time: ago(t()), source: 'vpn', user: uid, srcIp: ip, action: 'disconnect', message: `VPN session closed user=${uid} duration=${1 + Math.floor(rnd() * 6)}h` });
    }
  }

  // ---- perimeter background scanning noise (internet is loud) ----
  const ports = [22, 23, 80, 443, 445, 3389, 1433, 8080, 5900];
  for (let k = 0; k < 90; k++) {
    const oct = 20 + Math.floor(rnd() * 230);
    const port = pick(ports);
    logs.push({ time: ago(t()), source: 'firewall', srcIp: `${pick(['203.0.113', '198.51.100', '141.98.11', '89.248.165', '193.32.162', '92.63.197'])}.${oct}`, dstIp: '198.51.100.10', dstPort: port, action: 'deny', message: `DENY inbound TCP ${oct} -> 198.51.100.10:${port} (internet scan)` });
  }

  // ---- server-side: DCs, file server, app server, backups, scanner ----
  for (const svcAcct of ['svc_backup', 'svc_scanner']) {
    for (let j = 0; j < 6; j++) {
      logs.push({ time: ago(t()), source: 'auth', host: 'DEN-DC01', user: svcAcct, action: 'kerberos', message: `4769 Kerberos service ticket requested by ${svcAcct} (service account, scheduled)`, fields: { eventId: 4769 } });
    }
  }
  for (let j = 0; j < 20; j++) {
    const h = pick(hosts);
    logs.push({ time: ago(t()), source: 'windows', host: 'DEN-FS01', user: h.owner, action: 'smb', message: `5140 A network share object was accessed. \\\\FS01\\Shared by ${h.owner ?? 'system'}`, fields: { eventId: 5140 } });
  }
  logs.push({ time: ago(60 * 9), source: 'edr', host: 'DEN-BKP01', user: 'svc_backup', action: 'backup', message: 'FS01-Daily-Shares backup completed successfully (30 restore points)' });
  logs.push({ time: ago(60 * 6), source: 'edr', host: 'DEN-DC01', user: 'svc_scanner', action: 'info', message: 'Scheduled vulnerability scan started from 10.10.10.70 (svc_scanner) - authorized weekly scan', process: 'nessusd' });
  for (let j = 0; j < 8; j++) {
    logs.push({ time: ago(t()), source: 'dhcp', host: 'DEN-DC01', action: 'ack', message: `DHCPACK issued from Denver-Users scope (${118 + j}/231 leases in use)` });
  }

  return logs.sort((a, b) => a.time.localeCompare(b.time));
}

const BASE_INTEL: IocRecord[] = [
  { indicator: '10.10.10.70', type: 'ip', verdict: 'clean', source: 'Internal asset register', tags: ['internal', 'vuln-scanner'], detail: 'Kestrel vulnerability scanner appliance (authorized). Weekly scans Sunday 03:00 and ad-hoc by Security Team.' },
  { indicator: 'halberd-cloud.net', type: 'domain', verdict: 'clean', source: 'Vendor allowlist', tags: ['edr', 'vendor'], detail: 'Halberd EDR cloud console. Agents beacon here every 5 minutes.' },
  { indicator: 'login.worksuite-mail.net', type: 'domain', verdict: 'clean', source: 'Vendor allowlist', tags: ['mail', 'sso'], detail: 'Legitimate WorkSuite Mail sign-in page.' },
  { indicator: '73.14.22.190', type: 'ip', verdict: 'clean', source: 'ISP lookup', tags: ['residential', 'us'], detail: 'Cox Communications residential, Phoenix AZ. Known home IP of cflores (VPN history).' },
  { indicator: '203.0.113.0/24', type: 'ip', verdict: 'suspicious', source: 'Community feed', tags: ['scanner', 'noise'], detail: 'Mass internet scanning range. Blocked at perimeter; informational only.' },
];

// ----------------------------------------------------------------------------
export function buildWorld(): World {
  const users = RAW_USERS.map(mkUser);
  const groups = mkGroups(users);
  const hosts = RAW_HOSTS.map(mkHost);
  const servers = mkServers();
  const assets = mkAssets(hosts);
  const mailboxes = users.filter((u) => !u.id.startsWith('svc_')).map((u) => ({ user: u.id, quotaGB: 50, usedGB: 4 + (u.id.length * 3) % 30, rules: [] as never[] }));
  return {
    company: { name: 'Kestrel Dynamics', domain: 'kestreldynamics.com', site: 'Denver HQ', helpdeskPhone: '303-555-4357' },
    now: NOW,
    users,
    groups,
    hosts,
    servers,
    assets,
    kb: KB,
    mail: [],
    mailboxes,
    logs: baselineLogs(users, hosts),
    alerts: [],
    intel: [...BASE_INTEL],
    chat: [],
    firewall: [
      { id: 'FW-001', action: 'allow', src: '10.10.0.0/16', dst: 'any', port: '80,443', comment: 'Corp web egress via proxy' },
      { id: 'FW-002', action: 'deny', src: 'any', dst: '10.10.0.0/16', port: 'any', comment: 'Default inbound deny' },
      { id: 'FW-003', action: 'allow', src: 'any', dst: '198.51.100.10', port: '443,4443', comment: 'VPN concentrator' },
      { id: 'FW-004', action: 'allow', src: '10.10.99.0/24', dst: '10.10.0.0/16', port: 'any', comment: 'VPN pool to corp' },
    ],
    blocklist: [],
  };
}

export function cloneWorld(w: World): World {
  return structuredClone(w);
}

export function findUser(w: World, id: string): DirUser | undefined {
  return w.users.find((u) => u.id === id);
}
export function findHost(w: World, id: string): Host | undefined {
  return w.hosts.find((h) => h.id === id);
}
export function findServer(w: World, id: string): Server | undefined {
  return w.servers.find((s) => s.id === id);
}
export function userName(w: World, id?: string): string {
  if (!id) return '';
  return findUser(w, id)?.displayName ?? id;
}
