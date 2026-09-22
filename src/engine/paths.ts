// Learning paths: ordered mini-curricula that mix KB lessons (with a quick
// knowledge check) and hands-on scenarios. Built as first-class "playlists" so
// a teacher can later assign one as a link (roadmap step 5).

import type { Tier } from './types';

export interface Check {
  q: string;
  options: string[];
  answer: number;   // index of the correct option
  explain?: string;
}

export interface PathStep {
  kind: 'lesson' | 'case';
  kb?: string;        // lesson: KB article id to read
  blurb?: string;     // why this step matters
  scenarioId?: string; // case: the scenario to work
}

export interface LearningPath {
  id: string;
  tier: Tier;
  title: string;
  summary: string;
  steps: PathStep[];
}

// One knowledge check per KB article, reused wherever that lesson appears.
export const KB_CHECKS: Record<string, Check> = {
  'KB-0001': {
    q: 'A caller says they are locked out and need a reset urgently. What must happen before you touch the account?',
    options: [
      'Reset it quickly since they sound stressed',
      'Verify their identity with two acceptable factors',
      'Email the new password to whatever address they give',
      'Ask their name and department, then proceed',
    ], answer: 1,
    explain: 'KB-0001 requires two acceptable factors (e.g., employee ID confirmed against the directory plus a callback to the number on record) before any account change.',
  },
  'KB-0003': {
    q: 'A shared printer is down for a whole team, but each person has a nearby alternative. How do you rate it?',
    options: ['P1 Critical', 'P2 High', 'P3 Medium', 'P4 Low'],
    answer: 1,
    explain: 'A shared resource down for a team is P2 High. P1 is for a whole site/department down, safety/revenue impact, or a confirmed security incident.',
  },
  'KB-0004': {
    q: 'A user reports a phishing email they clicked and entered their password on. Who owns it next?',
    options: ['Desktop / Endpoint team', 'Network team', 'Security (SOC)', 'Nobody — just reset the password'],
    answer: 2,
    explain: 'Anything where a user entered credentials on a suspicious page goes to Security (SOC). Preserve the sign-in evidence; do not just reset.',
  },
  'KB-0005': {
    q: 'A user reports a suspicious email but did NOT click or reply. What is the right close?',
    options: [
      'Escalate to SOC as an urgent incident',
      'Forward it to all staff to warn them',
      'Note the message ID, have them report it, close as "reported, no interaction"',
      'Reset their password to be safe',
    ], answer: 2,
    explain: 'No interaction means note the message ID, use the Report Phishing button, and close. Escalate to SOC only when the user clicked/entered credentials.',
  },
  'KB-0006': {
    q: 'Marketing asks for access to the Finance file share for one project. Whose approval is required?',
    options: ["The requester's own manager", 'The data owner (Finance)', 'Nobody, just add them', 'The IT director'],
    answer: 1,
    explain: 'Sensitive shares (Finance, HR, AP, any *-Admins) require the DATA OWNER’s approval, not the requester’s manager.',
  },
  'KB-0009': {
    q: 'A user is in the correct file-share group but still gets "access denied". Most likely fix?',
    options: [
      'Add them to the group again',
      'Have them sign out and back in for a fresh token',
      'Rebuild their profile',
      'Escalate to the sysadmin immediately',
    ], answer: 1,
    explain: 'A group change needs a fresh logon token. If they are already a member, a full sign-out/sign-in usually resolves it.',
  },
  'KB-0010': {
    q: 'A second monitor shows "no signal" but works when plugged straight into the laptop. The likely culprit is:',
    options: ['A corrupt OS needing a reimage', 'The dock / its DisplayPort hub', 'The user’s account', 'The network'],
    answer: 1,
    explain: 'If the monitor works directly, the monitor and cable are fine — suspect the dock. Device Manager often shows the dock erroring.',
  },
  'KB-0013': {
    q: 'A detection fired on real activity that turns out to be an authorized weekly vulnerability scan. Classify it as:',
    options: ['False Positive', 'True Positive', 'Benign True Positive', 'Ignore it'],
    answer: 2,
    explain: 'The detection fired correctly on real activity that is authorized — a benign true positive. Document who authorized it and tune the noise.',
  },
  'KB-0014': {
    q: 'First step when confirming and containing a phishing campaign that reached several mailboxes?',
    options: [
      'Reset every recipient’s password',
      'Analyze the headers, then scope every recipient and purge',
      'Reply to the sender to confirm',
      'Warn all staff by email',
    ], answer: 1,
    explain: 'Confirm it’s malicious (headers/intel), scope all recipients, purge, check who interacted, then block. Match response to interaction evidence.',
  },
  'KB-0015': {
    q: 'You confirm malware with C2 on an endpoint. What must you do BEFORE isolating/reimaging?',
    options: ['Reboot the host', 'Collect a triage package to preserve evidence', 'Delete the malicious file', 'Nothing — wipe it immediately'],
    answer: 1,
    explain: 'Collect triage first. Isolation preserves the EDR channel; reimaging destroys the evidence of how they got in and whether they spread.',
  },
  'KB-0016': {
    q: 'An "impossible travel" alert fires. What confirms whether it is benign?',
    options: [
      'The user’s manager guessing they might be travelling',
      'The IP being residential',
      'Contacting the user AND checking post-authentication behavior (rules, downloads)',
      'The login using a browser',
    ], answer: 2,
    explain: 'Confirm with the user directly and inspect what happened after login (new inbox rules, mass downloads, OAuth grants). Benign only if the user confirms and nothing post-auth looks wrong.',
  },
  'KB-0017': {
    q: 'During an active incident, who decides on regulator and customer notification?',
    options: ['The analyst, immediately', 'All staff by broadcast', 'Legal (analysts feed them facts)', 'The vendor'],
    answer: 2,
    explain: 'Legal owns regulator/customer/law-enforcement notification decisions and timing. Never notify them directly, and never send an all-staff notice during active response.',
  },
  'KB-0018': {
    q: 'You’ve contained one host in a multi-host intrusion. What comes before eradication?',
    options: [
      'Reimage the first host right away',
      'Scope the indicators across ALL hosts',
      'Notify all staff',
      'Close the incident',
    ], answer: 1,
    explain: 'Scope before eradication. Cleaning one host while another still beacons means the attacker stays resident and you’ll be back tomorrow.',
  },
  'KB-0019': {
    q: 'A domain-joined PC fails logons with "trust relationship" errors, the account is not locked and the network is up. First thing to check?',
    options: ['Rejoin it to the domain', 'The system clock / time skew', 'Reset the password', 'Reimage it'],
    answer: 1,
    explain: 'Kerberos rejects tickets when the clock is off by more than 5 minutes, producing misleading trust/no-logon-server errors. Check time (w32tm) first.',
  },
  'KB-0020': {
    q: 'A quarantined message has SPF/DKIM/DMARC all failing and comes from a lookalike domain. The user insists it’s legit. You:',
    options: ['Release it', 'Never release it — it is phishing regardless', 'Ask the user to decide', 'Forward it to IT'],
    answer: 1,
    explain: 'Authentication failures plus a lookalike domain mean phishing; never release it no matter what the recipient believes.',
  },
};

export const LEARNING_PATHS: LearningPath[] = [
  {
    id: 'sd1-foundations', tier: 'sd1', title: 'Service Desk Foundations',
    summary: 'The core moves of the front line: verify a caller, set the right priority, escalate cleanly, and work your first tickets.',
    steps: [
      { kind: 'lesson', kb: 'KB-0001', blurb: 'The rule that protects every account change.' },
      { kind: 'lesson', kb: 'KB-0003', blurb: 'Impact × urgency: how to triage what lands in your queue.' },
      { kind: 'lesson', kb: 'KB-0004', blurb: 'Who owns what, and how to hand off with evidence.' },
      { kind: 'case', scenarioId: 'sd1-01', blurb: 'A routine lockout with a social-engineering twist.' },
      { kind: 'case', scenarioId: 'sd1-05', blurb: 'A "simple" request with a real landmine.' },
    ],
  },
  {
    id: 'sd1-phishing', tier: 'sd1', title: 'Phishing & Social Engineering (Tier 1)',
    summary: 'Recognize and handle phishing reports and manipulation attempts without contaminating the investigation.',
    steps: [
      { kind: 'lesson', kb: 'KB-0005', blurb: 'The script for handling a reported phish.' },
      { kind: 'case', scenarioId: 'sd1-04', blurb: 'The user clicked and entered credentials.' },
      { kind: 'case', scenarioId: 'sd1-14', blurb: 'A report with no interaction — close it right.' },
      { kind: 'case', scenarioId: 'sd1-17', blurb: 'A caller who is not who they claim to be.' },
    ],
  },
  {
    id: 'sd2-endpoints', tier: 'sd2', title: 'Endpoint Troubleshooting',
    summary: 'Diagnose peripherals, drivers, and the counterintuitive Windows faults, using the tools instead of guessing.',
    steps: [
      { kind: 'lesson', kb: 'KB-0010', blurb: 'Displays, docks and peripherals.' },
      { kind: 'lesson', kb: 'KB-0019', blurb: 'The terminal commands a tech leans on.' },
      { kind: 'case', scenarioId: 'sd2-02', blurb: 'Clean adware — and know when it becomes Security’s.' },
      { kind: 'case', scenarioId: 'sd2-04', blurb: 'A logon failure that is really a clock problem.' },
    ],
  },
  {
    id: 'sd2-access', tier: 'sd2', title: 'Identity & Access Control',
    summary: 'Grant the right access the right way: least privilege, data-owner approval, and correct offboarding.',
    steps: [
      { kind: 'lesson', kb: 'KB-0006', blurb: 'Onboarding, name changes, terminations, sensitive groups.' },
      { kind: 'lesson', kb: 'KB-0009', blurb: 'Shared-drive and file-access troubleshooting.' },
      { kind: 'case', scenarioId: 'sd2-03', blurb: 'Access denied — and pressure to just add them.' },
      { kind: 'case', scenarioId: 'sd1-13', blurb: 'Offboard a departing employee correctly.' },
    ],
  },
  {
    id: 'soc1-triage', tier: 'soc1', title: 'SOC Triage 101',
    summary: 'Turn a noisy alert into a defensible verdict: true, false, or benign positive, with the evidence to back it.',
    steps: [
      { kind: 'lesson', kb: 'KB-0013', blurb: 'The triage standard and the three closures.' },
      { kind: 'case', scenarioId: 'soc1-01', blurb: 'A scary-looking scan that is authorized.' },
      { kind: 'case', scenarioId: 'soc1-02', blurb: 'Impossible travel that is a real takeover.' },
      { kind: 'case', scenarioId: 'soc1-06', blurb: 'A file the AV already quarantined.' },
    ],
  },
  {
    id: 'soc1-phishing', tier: 'soc1', title: 'Phishing Response (SOC)',
    summary: 'Run the phishing playbook end to end: analyze, scope, purge, check interactions, and block.',
    steps: [
      { kind: 'lesson', kb: 'KB-0014', blurb: 'The SOC phishing / credential-harvesting playbook.' },
      { kind: 'lesson', kb: 'KB-0020', blurb: 'Mail admin: trace, quarantine, and inbox rules.' },
      { kind: 'case', scenarioId: 'soc1-03', blurb: 'How many mailboxes got it?' },
      { kind: 'case', scenarioId: 'soc1-10', blurb: 'A malicious attachment that detonated in the sandbox.' },
    ],
  },
  {
    id: 'soc1-malware', tier: 'soc1', title: 'Endpoint Malware',
    summary: 'Work an endpoint compromise: read the process tree, confirm C2, find persistence, and contain in the right order.',
    steps: [
      { kind: 'lesson', kb: 'KB-0015', blurb: 'The endpoint-malware playbook.' },
      { kind: 'case', scenarioId: 'soc1-04', blurb: 'A macro doc that spawned PowerShell.' },
      { kind: 'case', scenarioId: 'soc1-19', blurb: 'A credential-dumping tool on a host.' },
    ],
  },
  {
    id: 'soc2-hunting', tier: 'soc2', title: 'Threat Hunting & Scoping',
    summary: 'Pivot on indicators across the estate to find what the first alert missed, and scope before you eradicate.',
    steps: [
      { kind: 'lesson', kb: 'KB-0018', blurb: 'IR lifecycle and evidence handling.' },
      { kind: 'lesson', kb: 'KB-0015', blurb: 'Endpoint playbook, revisited for hunting.' },
      { kind: 'case', scenarioId: 'soc2-02', blurb: 'Did the beacon touch anyone else?' },
      { kind: 'case', scenarioId: 'soc2-08', blurb: 'Exfiltration hiding in DNS.' },
    ],
  },
  {
    id: 'soc2-identity', tier: 'soc2', title: 'Identity Attacks',
    summary: 'The modern attacks on identity: consent grants, ticket forgery, and session theft that bypasses MFA.',
    steps: [
      { kind: 'lesson', kb: 'KB-0016', blurb: 'Suspicious sign-ins, MFA fatigue, and containment order.' },
      { kind: 'case', scenarioId: 'soc2-05', blurb: 'An illicit OAuth app consent.' },
      { kind: 'case', scenarioId: 'soc2-09', blurb: 'Session-cookie theft that walked past MFA.' },
    ],
  },
  {
    id: 'cirt-command', tier: 'cirt', title: 'Incident Command',
    summary: 'Run a major incident: contain without destroying evidence, recover from a clean point, and rotate what the attacker saw.',
    steps: [
      { kind: 'lesson', kb: 'KB-0018', blurb: 'The response lifecycle and evidence-first rule.' },
      { kind: 'lesson', kb: 'KB-0017', blurb: 'Severity and the notification matrix.' },
      { kind: 'case', scenarioId: 'cirt-01', blurb: 'Ransomware detonating on the file server.' },
      { kind: 'case', scenarioId: 'cirt-02', blurb: 'A Domain Admin account being abused.' },
    ],
  },
  {
    id: 'cirt-comms', tier: 'cirt', title: 'Comms, Legal & Notifications',
    summary: 'The non-technical core of incident response: who to tell, when, and who owns the decision.',
    steps: [
      { kind: 'lesson', kb: 'KB-0017', blurb: 'Who gets notified, and who decides.' },
      { kind: 'case', scenarioId: 'cirt-03', blurb: 'A breach notice from a SaaS vendor.' },
      { kind: 'case', scenarioId: 'cirt-07', blurb: 'A stolen laptop full of regulated data.' },
    ],
  },
];

export function getPath(id: string): LearningPath | undefined {
  return LEARNING_PATHS.find((p) => p.id === id);
}
