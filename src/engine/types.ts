// ---------------------------------------------------------------------------
// Garrison core types. Everything in the simulator is data: a World (the fake
// company), Scenarios (patch the world + declare what a good analyst does), and
// an Action log (everything the trainee clicks). Grading is computed purely
// from the action log + the closure form.
// ---------------------------------------------------------------------------

export type Tier = 'sd1' | 'sd2' | 'soc1' | 'soc2' | 'cirt';
export type Priority = 'P1' | 'P2' | 'P3' | 'P4';
export type Skill =
  | 'technical'
  | 'investigation'
  | 'security'
  | 'communication'
  | 'documentation'
  | 'process'
  | 'efficiency';

export const SKILLS: Skill[] = [
  'technical', 'investigation', 'security', 'communication', 'documentation', 'process', 'efficiency',
];

export const SKILL_LABELS: Record<Skill, string> = {
  technical: 'Technical accuracy',
  investigation: 'Investigation & evidence',
  security: 'Security judgment',
  communication: 'Communication',
  documentation: 'Documentation',
  process: 'Process & escalation',
  efficiency: 'Efficiency',
};

export const TIER_LABELS: Record<Tier, string> = {
  sd1: 'Service Desk I',
  sd2: 'Service Desk II',
  soc1: 'SOC Analyst I',
  soc2: 'SOC Analyst II',
  cirt: 'CIRT Member',
};

export const TIER_ORDER: Tier[] = ['sd1', 'sd2', 'soc1', 'soc2', 'cirt'];

// ----------------------------- World -----------------------------------

export interface SignIn {
  time: string;
  ip: string;
  location: string;
  app: string;
  result: 'success' | 'failure';
  reason?: string;
  device?: string;
  mfa?: 'satisfied' | 'not required' | 'failed' | 'fatigue-approved';
}

export interface DirUser {
  id: string; // sAMAccountName
  displayName: string;
  title: string;
  department: string;
  manager?: string; // user id
  email: string;
  phone: string;
  employeeId: string;
  location: string;
  enabled: boolean;
  lockedOut: boolean;
  passwordLastSet: string;
  passwordExpired?: boolean;
  passwordNeverExpires?: boolean;
  groups: string[];
  lastLogon: string;
  badPwdCount: number;
  mfaEnrolled: boolean;
  privileged?: boolean;
  hireDate?: string;
  termDate?: string;
  notes?: string;
  recentSignIns: SignIn[];
}

export interface DirGroup {
  id: string;
  name: string;
  description: string;
  type: 'security' | 'distribution';
  members: string[];
  sensitive?: boolean; // membership requires approval
}

export interface Proc {
  pid: number;
  name: string;
  user: string;
  cpu: number;
  mem: number; // MB
  path?: string;
  cmdline?: string;
  parentPid?: number;
  signed?: boolean;
  hash?: string;
  started?: string;
}

export interface Svc {
  name: string;
  displayName: string;
  status: 'running' | 'stopped' | 'starting' | 'failed';
  startType: 'auto' | 'manual' | 'disabled';
  path?: string;
  suspicious?: boolean;
}

export type EventLevel = 'Information' | 'Warning' | 'Error' | 'Critical' | 'Audit Success' | 'Audit Failure';

export interface WinEvent {
  id: number;
  time: string;
  level: EventLevel;
  source: string;
  log: 'System' | 'Application' | 'Security' | 'Setup' | 'Sysmon';
  message: string;
}

export interface Program {
  name: string;
  version: string;
  publisher: string;
  installedOn: string;
  suspicious?: boolean;
}

export interface Device {
  name: string;
  class: string;
  status: 'ok' | 'error' | 'disabled' | 'missing driver';
  driver: string;
  driverDate?: string;
  error?: string;
}

export interface NetConfig {
  dhcp: boolean;
  ip: string;
  mask: string;
  gateway: string;
  dns: string[];
  adapter: string;
  adapterStatus: 'up' | 'down' | 'media disconnected';
  ssid?: string;
  vpn?: 'connected' | 'disconnected' | 'n/a';
  proxy?: string;
}

export interface ScheduledTask {
  name: string;
  path: string;
  action: string;
  trigger: string;
  author: string;
  suspicious?: boolean;
}

export interface FileEntry {
  path: string;
  size: number;
  modified: string;
  hash?: string;
  signed?: boolean;
  suspicious?: boolean;
}

export interface Host {
  id: string; // hostname
  owner?: string; // user id
  kind: 'workstation' | 'laptop' | 'server';
  os: string;
  build?: string;
  ip: string;
  mac: string;
  site: string;
  lastSeen: string;
  online: boolean;
  domainJoined: boolean;
  edrAgent: 'healthy' | 'offline' | 'missing' | 'tampered';
  isolated: boolean;
  processes: Proc[];
  services: Svc[];
  events: WinEvent[];
  programs: Program[];
  devices: Device[];
  network: NetConfig;
  updates: { lastInstalled: string; pending: number; status: string };
  disk: { used: number; size: number }; // GB
  uptimeHours: number;
  localAdmins: string[];
  scheduledTasks: ScheduledTask[];
  files: FileEntry[];
  printers?: string[];
  timeZone?: string;
  clockSkewSec?: number;
  bitlocker?: 'on' | 'off' | 'suspended';
  monitors?: { name: string; status: 'active' | 'no signal' | 'disconnected' }[];
  notes?: string;
}

export interface DhcpScope {
  name: string;
  range: string;
  used: number;
  total: number;
  leaseHours: number;
  status: 'active' | 'exhausted' | 'disabled';
}

export interface DnsRecord {
  name: string;
  type: 'A' | 'CNAME' | 'MX' | 'TXT';
  value: string;
}

export interface PrintQueue {
  name: string;
  status: 'ready' | 'paused' | 'error' | 'offline';
  jobs: number;
  error?: string;
  location: string;
}

export interface Server {
  id: string;
  role: string;
  ip: string;
  os: string;
  status: 'online' | 'degraded' | 'offline';
  services: Svc[];
  disk: { drive: string; used: number; size: number }[];
  cpu: number;
  mem: number;
  uptimeHours: number;
  events: WinEvent[];
  dhcpScopes?: DhcpScope[];
  dnsRecords?: DnsRecord[];
  printQueues?: PrintQueue[];
  shares?: { name: string; path: string; ntfsGroups: string[]; status: 'ok' | 'offline' }[];
  backups?: { job: string; lastRun: string; status: 'success' | 'failed' | 'warning'; restorePoints: number }[];
  processes?: Proc[];
  notes?: string;
}

export interface Asset {
  tag: string;
  type: 'laptop' | 'desktop' | 'monitor' | 'phone' | 'dock' | 'printer' | 'server' | 'network';
  model: string;
  serial: string;
  assignedTo?: string; // user id
  hostname?: string;
  status: 'deployed' | 'in stock' | 'repair' | 'retired' | 'lost/stolen';
  purchaseDate: string;
  warrantyEnd: string;
  location: string;
  notes?: string;
}

export interface KbArticle {
  id: string;
  title: string;
  tags: string[];
  body: string; // plain text with line breaks
  restricted?: boolean;
}

export interface MailHeaders {
  from: string;
  returnPath: string;
  replyTo?: string;
  receivedFrom: string; // sending host/ip
  spf: 'pass' | 'fail' | 'softfail' | 'none';
  dkim: 'pass' | 'fail' | 'none';
  dmarc: 'pass' | 'fail' | 'none';
  messageId: string;
}

export interface MailMessage {
  id: string;
  time: string;
  from: string;
  to: string[];
  subject: string;
  status: 'delivered' | 'quarantined' | 'blocked' | 'deferred' | 'delivered (junk)';
  reason?: string;
  headers: MailHeaders;
  body: string;
  urls?: string[];
  attachments?: { name: string; type: string; hash?: string; verdict?: string }[];
  phishing?: boolean; // ground truth, not shown
  clicked?: string[]; // users who clicked
}

export interface InboxRule {
  name: string;
  condition: string;
  action: string;
  enabled: boolean;
  created: string;
  suspicious?: boolean;
}

export interface Mailbox {
  user: string;
  quotaGB: number;
  usedGB: number;
  rules: InboxRule[];
  forwarding?: string;
  delegates?: string[];
  litigationHold?: boolean;
}

export type LogSource =
  | 'firewall' | 'proxy' | 'dns' | 'auth' | 'edr' | 'email' | 'vpn' | 'windows' | 'cloud' | 'ids' | 'dhcp' | 'web';

export interface LogEvent {
  time: string;
  source: LogSource;
  host?: string;
  user?: string;
  srcIp?: string;
  dstIp?: string;
  dstPort?: number;
  domain?: string;
  url?: string;
  action?: string;
  process?: string;
  message: string;
  fields?: Record<string, string | number>;
}

export interface Alert {
  id: string;
  time: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: 'edr' | 'siem' | 'email' | 'ids' | 'cloud' | 'user_report' | 'dlp';
  title: string;
  description: string;
  host?: string;
  user?: string;
  indicators: string[];
  mitre?: string[];
  status: 'new' | 'in progress' | 'closed';
  truth?: 'true_positive' | 'false_positive' | 'benign_true_positive'; // hidden
}

export interface IocRecord {
  indicator: string;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  source: string;
  firstSeen?: string;
  tags: string[];
  detail: string;
}

export interface ChatMessage {
  from: string; // user id or 'you'
  time: string;
  text: string;
}

export interface ChatThread {
  id: string;
  with: string; // user id
  messages: ChatMessage[];
}

export interface FirewallRule {
  id: string;
  action: 'allow' | 'deny';
  src: string;
  dst: string;
  port: string;
  comment: string;
}

export interface World {
  company: { name: string; domain: string; site: string; helpdeskPhone: string };
  now: string; // ISO timestamp of "current time"
  users: DirUser[];
  groups: DirGroup[];
  hosts: Host[];
  servers: Server[];
  assets: Asset[];
  kb: KbArticle[];
  mail: MailMessage[];
  mailboxes: Mailbox[];
  logs: LogEvent[];
  alerts: Alert[];
  intel: IocRecord[];
  chat: ChatThread[];
  firewall: FirewallRule[];
  blocklist: { indicator: string; where: 'firewall' | 'proxy' | 'email' | 'dns'; by: string }[];
}

// ----------------------------- Actions ---------------------------------

/** Everything the trainee does. Tools emit these; grading consumes them. */
export interface Action {
  t: number; // ms since scenario start
  tool: string; // 'directory' | 'rdp' | 'server' | 'kb' | 'assets' | 'mail' | 'chat' | 'siem' | 'edr' | 'intel' | 'incident' | 'ticket' | 'terminal'
  action: string; // e.g. 'view', 'unlock', 'reset_password', 'search', 'isolate', 'run'
  target?: string;
  params?: Record<string, string>;
  label: string; // human readable, shown in the timeline
}

export interface ActionMatcher {
  tool: string;
  action: string;
  target?: string | RegExp;
  params?: Record<string, string | RegExp>;
}

// ----------------------------- Scenario --------------------------------

export interface TicketIntake {
  kind: 'ticket';
  number: string;
  subject: string;
  body: string;
  requester: string; // user id
  channel: 'portal' | 'phone' | 'email' | 'walk-up' | 'chat';
  priority: Priority; // as submitted
  category: string; // as submitted (may be wrong)
  openedAt: string;
  affectedHost?: string;
}

export interface AlertIntake {
  kind: 'alert';
  alertId: string; // refers to world.alerts
}

export interface IncidentIntake {
  kind: 'incident';
  number: string;
  title: string;
  declaredBy: string;
  summary: string;
  severity: 'SEV1' | 'SEV2' | 'SEV3';
  openedAt: string;
  relatedAlerts: string[];
}

export type Intake = TicketIntake | AlertIntake | IncidentIntake;

/** A scripted question the trainee may ask the requester/witness. */
export interface ContactQuestion {
  id: string;
  question: string;
  answer: string;
  /** what the question accomplishes; used by grading */
  purpose?: 'verify' | 'clarify' | 'irrelevant' | 'red_flag';
  /** if this question reveals evidence, name it */
  reveals?: string;
}

export interface Evidence {
  id: string;
  label: string; // "Saw that the account is locked out"
  match: ActionMatcher | ActionMatcher[];
  weight?: number; // default 1
  hint?: string;
}

export interface RequiredAction {
  id: string;
  label: string;
  match: ActionMatcher | ActionMatcher[];
  weight?: number;
  /** if set, the action must occur AFTER this other required action id (order matters) */
  after?: string;
  /** if set, this action must occur BEFORE this other required action id */
  before?: string;
  skill?: Skill; // default 'technical'
}

export interface ForbiddenAction {
  id: string;
  label: string;
  why: string;
  match: ActionMatcher | ActionMatcher[];
  penalty?: number; // 0..1 of skill score, default 0.5
  skill?: Skill; // default 'security'
  /** only forbidden if this required action has NOT yet happened (e.g. reset password before verify) */
  unlessAfter?: string;
}

export interface ReplyChoice {
  id: string;
  text: string;
  scores: Partial<Record<Skill, number>>; // 0..1 per skill
  feedback: string;
  best?: boolean;
}

export interface NoteRule {
  label: string;
  pattern: RegExp;
}

export type Disposition = 'resolve' | 'escalate' | 'reject' | 'pending';
export type EscalationTarget =
  | 'sd2' | 'desktop' | 'network' | 'sysadmin' | 'identity' | 'soc' | 'cirt' | 'hr' | 'legal' | 'finance' | 'vendor' | 'facilities' | 'management';

export interface Closure {
  disposition: Disposition;
  escalateTo?: EscalationTarget;
  category: string;
  resolutionCode: string;
  /** SOC only */
  classification?: 'true_positive' | 'false_positive' | 'benign_true_positive';
  severity?: 'low' | 'medium' | 'high' | 'critical';
  /** CIRT only */
  notifications?: string[]; // ids of stakeholders that MUST be notified
  notificationsForbidden?: string[]; // premature / wrong notifications
  reportFields?: NoteRule[]; // rubric for final report
}

export interface Scenario {
  id: string;
  tier: Tier;
  title: string;
  category: string;
  difficulty: 1 | 2 | 3 | 4 | 5;
  estMinutes: number;
  /** Learning objective shown before the scenario. */
  objective: string;
  intake: Intake;
  /** The priority a competent analyst would set. */
  priorityExpected: Priority;
  /** Mutate a fresh copy of the base world to set the scene. */
  setup: (w: World) => void;
  /** Questions available when the trainee contacts the requester. */
  contact?: ContactQuestion[];
  /** Who answers the "contact" - defaults to the requester. */
  contactWith?: string;
  evidence: Evidence[];
  required: RequiredAction[];
  forbidden: ForbiddenAction[];
  replies: ReplyChoice[];
  notesRubric: NoteRule[];
  closure: Closure;
  /** Accepted category strings (case-insensitive substring). */
  categoryAccept: string[];
  resolutionCodeAccept?: string[];
  weights?: Partial<Record<Skill, number>>;
  hints: string[];
  debrief: string;
  /** Extra tools to expose beyond the tier defaults. */
  tools?: string[];
  /** Optional: things that happen on a timer during the scenario. */
  timeline?: { atSec: number; event: (w: World) => void; notice?: string }[];
}

// ----------------------------- Session --------------------------------

export interface TicketState {
  priority: Priority;
  notes: string;
  replyId?: string;
  disposition: Disposition;
  escalateTo?: EscalationTarget;
  category: string;
  resolutionCode: string;
  classification?: 'true_positive' | 'false_positive' | 'benign_true_positive';
  severity?: 'low' | 'medium' | 'high' | 'critical';
  notifications: string[];
  report: string;
  verified: boolean;
  askedQuestions: string[];
}

export interface SkillResult {
  skill: Skill;
  score: number; // 0..100
  details: { ok: boolean; text: string; sub?: string }[];
}

export interface GradeResult {
  overall: number;
  skills: SkillResult[];
  elapsedSec: number;
  actionCount: number;
  passed: boolean;
  forbiddenHits: { label: string; why: string }[];
  missedEvidence: Evidence[];
  missedRequired: RequiredAction[];
}

export interface ScenarioProgress {
  scenarioId: string;
  best: number;
  attempts: number;
  lastPlayed: string;
  passed: boolean;
}
