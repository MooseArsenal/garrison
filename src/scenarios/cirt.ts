import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, addAlert, setConn } from './helpers';
import { randIp, randHash, randDomain } from '../engine/instantiate';

// ---------------------------------------------------------------------------
// CIRT-01  Ransomware in progress (full lifecycle, notifications, no wiping)
// ---------------------------------------------------------------------------
const cirt_01: Scenario = {
  id: 'cirt-01',
  tokens: [{ from: '185.220.101.47', gen: randIp }, { from: 'ee55...9f', gen: randHash }],
  tier: 'cirt',
  title: 'Ransomware detonating on the file server',
  category: 'Ransomware',
  difficulty: 5,
  estMinutes: 25,
  objective: 'Command a SEV1 ransomware response: contain fast without destroying evidence, run the lifecycle in order, restore from a clean backup, rotate credentials, and notify the right stakeholders (and only them).',
  intake: {
    kind: 'incident', number: 'IR-2026-014', title: 'Ransomware encryption underway on DEN-FS01',
    declaredBy: 'agrant', summary: 'Mass file encryption and ransom notes appearing on the Finance/Engineering shares. Users locked out of documents. EDR shows a process encrypting from a compromised admin session.',
    severity: 'SEV1', openedAt: ago(10), relatedAlerts: ['ALT-50081'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50081', time: ago(14), severity: 'critical', source: 'edr',
      title: 'Mass file modification + ransom note dropped on DEN-FS01 (D:\\Shares)',
      description: 'lockbit-style encryptor running as svc_backup on DEN-FS01, encrypting D:\\Shares. Ransom note RECOVER-FILES.txt written to every folder.',
      host: 'DEN-FS01', user: 'svc_backup', indicators: ['185.220.101.47', 'lock.exe', 'svc_backup'], mitre: ['T1486', 'T1078.002'], status: 'in progress', truth: 'true_positive',
    });
    const fs = w.servers.find((s) => s.id === 'DEN-FS01')!;
    fs.status = 'degraded';
    fs.processes = [{ pid: 8100, name: 'lock.exe', user: 'KESTREL\\svc_backup', cpu: 95, mem: 300, path: 'C:\\Windows\\Temp\\lock.exe', cmdline: 'lock.exe -enc D:\\Shares', signed: false, hash: 'ee55...9f', started: ago(14) }];
    // The intrusion: svc_backup (over-privileged service account, password never expires, no MFA) was compromised and used for lateral movement + encryption.
    const svc = findUser(w, 'svc_backup')!;
    addLog(w, { time: ago(60 * 30), source: 'auth', host: 'DEN-FS01', user: 'svc_backup', srcIp: '10.10.20.42', action: 'logon', message: '4624 Logon type 3 svc_backup from DEN-LT-1042 (bpatel host) - lateral movement' });
    addLog(w, { time: ago(20), source: 'edr', host: 'DEN-FS01', user: 'svc_backup', action: 'exec', message: 'lock.exe written to C:\\Windows\\Temp and executed (encryptor)', process: 'lock.exe' });
    addLog(w, { time: ago(60 * 40), source: 'firewall', host: 'DEN-LT-1042', srcIp: '10.10.20.42', dstIp: '185.220.101.47', dstPort: 443, action: 'allow', message: 'C2 beacon from patient-zero DEN-LT-1042 -> 185.220.101.47' });
    // Backups: FS01-Daily-Shares success 9h ago (BEFORE encryption at 14 min ago) => clean restore point. Offsite immutable copy exists.
    const bkp = w.servers.find((s) => s.id === 'DEN-BKP01')!;
    bkp.backups = [
      { job: 'FS01-Daily-Shares', lastRun: ago(60 * 9), status: 'success', restorePoints: 30 },
      { job: 'Offsite-Immutable-Copy', lastRun: ago(60 * 26), status: 'success', restorePoints: 30 },
      { job: 'APP01-SQL-Full', lastRun: ago(60 * 10), status: 'success', restorePoints: 14 },
    ];
    w.intel.push({ indicator: '185.220.101.47', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['c2', 'ransomware'], detail: 'C2 associated with the ransomware affiliate. Frankfurt.' });
    w.intel.push({ indicator: 'lock.exe', type: 'hash', verdict: 'malicious', source: 'sandbox', tags: ['ransomware', 'lockbit-like'], detail: 'LockBit-style encryptor. ee55...9f.' });
  },
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'kb18', label: 'Reviewed the IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'patient0', label: 'Traced the intrusion to patient zero (DEN-LT-1042) and the compromised svc_backup', match: [{ tool: 'siem', action: 'search', params: { q: /svc_backup|185\.220\.101\.47|lock\.exe/i } }, { tool: 'siem', action: 'pivot', params: { value: /svc_backup/ } }], hint: 'Where did svc_backup log in from before it hit the file server?' },
    { id: 'backups', label: 'Identified a clean restore point (backup taken before encryption)', match: { tool: 'server', action: 'view_backups', target: 'DEN-BKP01' }, hint: 'When was the last GOOD backup relative to when encryption started?' },
    { id: 'svc_acct', label: 'Noted the root enabler: over-privileged svc_backup (no MFA, password never expires)', match: [{ tool: 'directory', action: 'view', target: 'svc_backup' }], weight: 0.5 },
  ],
  required: [
    { id: 'isolate_fs', label: 'Isolated DEN-FS01 to stop encryption spread', match: [{ tool: 'edr', action: 'isolate', target: 'DEN-FS01' }, { tool: 'incident', action: 'set_phase', params: { phase: /contain/i } }], skill: 'technical' },
    { id: 'disable_svc', label: 'Disabled/rotated the compromised service account', match: [{ tool: 'directory', action: 'disable', target: 'svc_backup' }, { tool: 'incident', action: 'reset_service_account', target: 'svc_backup' }], skill: 'technical' },
    { id: 'isolate_p0', label: 'Isolated patient zero (DEN-LT-1042) too', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1042' }, skill: 'technical' },
    { id: 'restore', label: 'Restored shares from the clean pre-encryption backup', match: [{ tool: 'server', action: 'restore', target: 'DEN-BKP01' }, { tool: 'incident', action: 'restore_backup', target: 'DEN-FS01' }], skill: 'technical', after: 'isolate_fs' },
    { id: 'notify_leadership', label: 'Notified IT Director/CISO and executives (SEV1)', match: [{ tool: 'incident', action: 'notify', target: 'it_director' }, { tool: 'incident', action: 'notify', target: 'executives' }], skill: 'process' },
    { id: 'notify_legal', label: 'Notified Legal (regulated data may be involved)', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'wipe', label: 'Reimaged/powered off the file server before evidence collection', why: 'KB-0018: isolate (keeps EDR channel), do not power off or wipe before triage. You need the memory and logs to know scope and dwell time.', match: [{ tool: 'server', action: 'reboot', target: 'DEN-FS01' }], skill: 'security', penalty: 0.4 },
    { id: 'notify_all', label: 'Sent an all-staff notice during active response', why: 'KB-0017: never broadcast all-staff before containment — it tips off the attacker (possible insider), causes panic, and pre-empts Legal on messaging.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
    { id: 'pay', label: 'Contacted regulators/law enforcement directly (bypassing Legal)', why: 'KB-0017: Legal owns regulator/LE contact and the insurance call. The analyst does not make external legal notifications.', match: [{ tool: 'incident', action: 'notify', target: 'regulator' }, { tool: 'incident', action: 'notify', target: 'law_enforcement' }], skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'SEV1 ransomware contained and recovering. Root cause: patient zero DEN-LT-1042 (bpatel) was C2-beaconing; the attacker pivoted with the over-privileged svc_backup account (no MFA, password never expires) to DEN-FS01 and ran a LockBit-style encryptor from C:\\Windows\\Temp. Actions in order: isolated FS01 and patient zero (EDR, not power-off, to preserve evidence), disabled/rotated svc_backup, collected triage. The 9-hour-old FS01 backup predates encryption, so I\'m restoring shares from that clean point; the offsite immutable copy is our fallback. Notified IT Director/CISO, execs, and Legal (regulated data may be in Finance/HR shares — Legal owns any regulator/customer/insurer notification). No all-staff notice during active response. Next: rotate all credentials the attacker could have seen and monitor for re-entry.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Correct containment order, evidence-preserving, clean restore point, and precise notifications.' },
    { id: 'r_wipe', text: 'Wiped and rebuilt FS01 immediately and restored the latest backup to get everyone working.', scores: { communication: 0.3, security: 0.2, process: 0.3 }, feedback: 'Wiping before triage destroys the evidence, and "latest backup" risks restoring an encrypted or post-compromise state. Preserve, then restore from a verified clean point.' },
    { id: 'r_broadcast', text: 'Sent an all-staff email warning everyone about the ransomware and told them to shut down their PCs.', scores: { communication: 0.3, process: 0.2 }, feedback: 'All-staff during active response tips off the actor and pre-empts Legal. Targeted, factual updates to the right people only.' },
  ],
  notesRubric: [
    { label: 'root cause / entry (patient zero + compromised svc_backup lateral movement)', pattern: /patient zero|1042|svc_backup|lateral|over-?privileg|no mfa/i },
    { label: 'containment order (isolate not power-off, evidence preserved)', pattern: /isolat|preserve|triage|not power|evidence/i },
    { label: 'recovery from a clean pre-encryption backup + credential rotation', pattern: /clean backup|pre-?encryption|9.hour|restore point|rotate credential|immutable/i },
    { label: 'correct notifications (leadership/legal, not all-staff)', pattern: /it director|ciso|legal|exec|not all.?staff/i },
  ],
  closure: {
    disposition: 'resolve', severity: 'critical', category: 'Ransomware - Contained & Recovering', resolutionCode: 'Contained, restored from clean backup, creds rotating',
    notifications: ['it_director', 'executives', 'legal'],
    notificationsForbidden: ['all_staff', 'regulator', 'law_enforcement', 'customers'],
    reportFields: [
      { label: 'timeline from initial access to encryption', pattern: /timeline|patient zero|beacon|lateral|encrypt/i },
      { label: 'root cause (over-privileged service account / macro entry)', pattern: /svc_backup|service account|over-?privileg|no mfa|root cause/i },
      { label: 'recovery approach (clean backup point)', pattern: /backup|restore|clean|immutable|pre-?encryption/i },
      { label: 'follow-up actions with owners', pattern: /rotate|krbtgt|mfa|monitor|lesson|owner|remediat/i },
    ],
  },
  categoryAccept: ['ransomware', 'incident', 'contained'],
  resolutionCodeAccept: ['contain', 'restore', 'ransomware', 'recover'],
  hints: [
    'This is a SEV1. Contain the spread first (isolate FS01 and patient zero) — but isolate in EDR, do not power off or wipe.',
    'Trace it: patient zero DEN-LT-1042 was beaconing; the attacker used the over-privileged svc_backup to reach the file server.',
    'Check the backups: the FS01 backup 9 hours ago predates encryption (14 min ago) — that is your clean restore point.',
    'Notify IT Director/CISO, execs, and Legal. Do NOT send an all-staff notice or contact regulators/LE yourself — that is Legal\'s call. Rotate credentials after.',
  ],
  debrief: 'Ransomware is the exam that combines everything: fast containment that still preserves evidence (isolate in EDR, never power-off/wipe first), lifecycle discipline (contain → eradicate → recover), a verified-clean restore point (the backup that predates encryption — restoring the "latest" can reintroduce the attacker), credential rotation for everything the attacker could have touched, and surgical notifications. The recurring notification error is the all-staff blast, which tips off the actor and steps on Legal; regulator, law-enforcement, insurer, and customer contact all route through Legal. The root enabler here — an over-privileged service account with no MFA and a non-expiring password — is your lessons-learned headline.',
};

// ---------------------------------------------------------------------------
// CIRT-02  Domain Admin compromise (KRBTGT, scoping, plant impact)
// ---------------------------------------------------------------------------
const cirt_02: Scenario = {
  id: 'cirt-02',
  tier: 'cirt',
  title: 'A Domain Admin account is being abused',
  category: 'Identity Compromise',
  difficulty: 5,
  estMinutes: 28,
  objective: 'Respond to a domain-wide identity compromise: recognize when tier-2 credentials require domain-level remediation (KRBTGT double reset), scope for Golden Ticket persistence, and coordinate a controlled recovery.',
  intake: {
    kind: 'incident', number: 'IR-2026-018', title: 'Suspected Domain Admin (mreyes) compromise / possible Golden Ticket',
    declaredBy: 'agrant', summary: 'The mreyes Domain Admin account created a new admin account and accessed multiple servers at 3am from an unusual host. DCSync-style replication was observed. Possible full AD compromise.',
    severity: 'SEV1', openedAt: ago(20), relatedAlerts: ['ALT-50091'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50091', time: ago(25), severity: 'critical', source: 'siem',
      title: 'DCSync-style replication + rogue admin account creation by mreyes at 03:14',
      description: 'DEN-DC01 logged directory replication requests (DCSync) from a non-DC host using mreyes, followed by creation of account "svc_helpdesk2" added to Domain Admins.',
      user: 'mreyes', host: 'DEN-DC01', indicators: ['mreyes', 'svc_helpdesk2', '98.42.117.9'], mitre: ['T1003.006', 'T1098', 'T1558'], status: 'in progress', truth: 'true_positive',
    });
    const mreyes = findUser(w, 'mreyes')!;
    mreyes.recentSignIns = [
      { time: ago(28), ip: '98.42.117.9', location: 'Austin, US', app: 'Windows Sign-in (DEN-DC01)', result: 'success', device: 'CTR-LT-9001', mfa: 'not required' },
      { time: ago(60 * 26), ip: '10.10.20.121', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1021', mfa: 'satisfied' },
    ];
    // Rogue admin account created
    w.users.push({
      id: 'svc_helpdesk2', displayName: 'svc_helpdesk2 (ROGUE)', title: 'Service Account', department: 'IT', email: 'svc_helpdesk2@kestreldynamics.com', phone: '', employeeId: 'SVC999', location: 'unknown', enabled: true, lockedOut: false,
      passwordLastSet: ago(28), passwordNeverExpires: true, groups: ['Domain Admins', 'Server Admins'], lastLogon: ago(15), badPwdCount: 0, mfaEnrolled: false, privileged: true, notes: 'Created 03:14 by mreyes from CTR-LT-9001. Not in HR records.', recentSignIns: [],
    });
    const dg = w.groups.find((g) => g.name === 'Domain Admins')!;
    dg.members.push('svc_helpdesk2');
    // Entry: the contractor laptop CTR-LT-9001 (abaxter) was the pivot; attacker stole mreyes creds from it
    addLog(w, { time: ago(28), source: 'auth', host: 'DEN-DC01', user: 'mreyes', srcIp: '98.42.117.9', action: 'dcsync', message: '4662 Replication (DCSync) requested by mreyes from CTR-LT-9001 (98.42.117.9) - NOT a domain controller' });
    addLog(w, { time: ago(27), source: 'auth', host: 'DEN-DC01', user: 'mreyes', action: 'account_create', message: '4720/4728 svc_helpdesk2 created and added to Domain Admins by mreyes' });
    addLog(w, { time: ago(60 * 34), source: 'edr', host: 'CTR-LT-9001', user: 'abaxter', action: 'creddump', message: 'LSASS access by unknown tool on CTR-LT-9001 (contractor laptop) - credential theft; mreyes had an active admin session here' });
    w.intel.push({ indicator: '98.42.117.9', type: 'ip', verdict: 'suspicious', source: 'geo/ISP', tags: ['residential', 'austin'], detail: 'Austin residential — matches the contractor abaxter\'s home IP, but the activity (DCSync at 3am) is not consistent with his role.' });
    w.chat.push({ id: 'ch-lchen', with: 'lchen', messages: [] });
  },
  evidence: [
    { id: 'kb18', label: 'Reviewed IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'dcsync', label: 'Confirmed DCSync from a non-DC host using mreyes', match: [{ tool: 'siem', action: 'search', params: { q: /dcsync|replication|4662|mreyes/i } }, { tool: 'siem', action: 'pivot', params: { value: /mreyes/ } }], hint: 'Directory replication from a non-DC is DCSync — credential theft at domain scale.' },
    { id: 'rogue', label: 'Found the rogue Domain Admin account (svc_helpdesk2)', match: [{ tool: 'directory', action: 'view', target: 'svc_helpdesk2' }, { tool: 'directory', action: 'view_group', target: 'Domain Admins' }], hint: 'Check Domain Admins membership for anything new.' },
    { id: 'entry', label: 'Traced the credential theft to the contractor laptop (LSASS dump)', match: [{ tool: 'siem', action: 'search', params: { q: /lsass|creddump|CTR-LT-9001|abaxter/i } }, { tool: 'edr', action: 'view_host', target: 'CTR-LT-9001' }], hint: 'Where were mreyes\'s credentials stolen from?' },
  ],
  required: [
    { id: 'disable_rogue', label: 'Disabled the rogue admin account', match: { tool: 'directory', action: 'disable', target: 'svc_helpdesk2' }, skill: 'technical' },
    { id: 'reset_mreyes', label: 'Reset the compromised DA account (revoke sessions + reset)', match: [{ tool: 'directory', action: 'revoke_sessions', target: 'mreyes' }, { tool: 'directory', action: 'reset_password', target: 'mreyes' }], skill: 'technical' },
    { id: 'isolate_entry', label: 'Isolated the entry host (contractor laptop)', match: { tool: 'edr', action: 'isolate', target: 'CTR-LT-9001' }, skill: 'technical' },
    { id: 'krbtgt', label: 'Rotated KRBTGT twice to invalidate Golden Tickets', match: { tool: 'incident', action: 'rotate_krbtgt' }, skill: 'technical', after: 'disable_rogue' },
    { id: 'notify', label: 'Notified IT Director/CISO, execs, and Legal', match: [{ tool: 'incident', action: 'notify', target: 'it_director' }, { tool: 'incident', action: 'notify', target: 'legal' }], skill: 'process' },
  ],
  forbidden: [
    { id: 'reset_only', label: 'Reset mreyes\'s password but skipped KRBTGT', why: 'With DCSync/DA compromise, the attacker can forge Golden Tickets. Resetting one account does not evict them — you must rotate KRBTGT (twice) to invalidate forged Kerberos tickets. (KB-0018)', match: { tool: 'ticket', action: 'reply', target: 'r_partial' }, skill: 'security', penalty: 0.5 },
    { id: 'ignore_scope', label: 'Closed without rotating the credentials the attacker could have replicated', why: 'DCSync dumps the whole directory. Every privileged credential and service account must be treated as exposed.', match: { tool: 'ticket', action: 'reply', target: 'r_narrow' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Full AD compromise, contained. Entry was the contractor laptop CTR-LT-9001, where mreyes had a live admin session — the attacker dumped LSASS, stole his Domain Admin credentials, then from that host ran DCSync against DEN-DC01 (replicating the directory) and created a rogue DA account (svc_helpdesk2) at 03:14. Actions: disabled the rogue account, revoked and reset mreyes, isolated the contractor laptop, and — critically — rotated KRBTGT twice to invalidate any Golden Tickets, since DCSync means they could forge Kerberos tickets. Because the directory was replicated, we treat ALL privileged and service-account credentials as exposed and are rotating them. Notified IT Director/CISO, execs, and Legal. Lessons: no MFA on privileged logons and admins using workstations with harvestable sessions.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Recognizes domain-scale compromise, does the KRBTGT double-rotation, and scopes credential exposure correctly.' },
    { id: 'r_partial', text: 'Disabled the rogue account and reset mreyes\'s password. That cuts off the attacker.', scores: { communication: 0.3, security: 0.2 }, feedback: 'Not for a DCSync/DA compromise — forged Golden Tickets survive a password reset. You must rotate KRBTGT (twice).' },
    { id: 'r_narrow', text: 'Reset mreyes and rotated KRBTGT, closing.', scores: { communication: 0.5, process: 0.4 }, feedback: 'Better, but DCSync exposed every credential in the directory. All privileged and service accounts must be rotated and monitored.' },
  ],
  notesRubric: [
    { label: 'the attack chain (LSASS on contractor laptop -> DCSync -> rogue DA)', pattern: /lsass|contractor|ctr-lt-9001|dcsync|replicat|rogue|svc_helpdesk2/i },
    { label: 'the KRBTGT double rotation and why (Golden Ticket)', pattern: /krbtgt|golden ticket|twice|two times|forge/i },
    { label: 'scoping credential exposure (all privileged/service accounts)', pattern: /all (privileged|service)|rotate.*credential|directory.*exposed|every.*account/i },
    { label: 'notifications (leadership/legal)', pattern: /it director|ciso|legal|exec/i },
  ],
  closure: {
    disposition: 'resolve', severity: 'critical', category: 'Identity - Domain Compromise', resolutionCode: 'Contained; KRBTGT rotated; credentials rotating',
    notifications: ['it_director', 'executives', 'legal'],
    notificationsForbidden: ['all_staff', 'regulator', 'customers'],
    reportFields: [
      { label: 'attack chain and dwell time', pattern: /lsass|dcsync|timeline|03:14|dwell|chain/i },
      { label: 'domain remediation (KRBTGT twice, credential rotation)', pattern: /krbtgt|twice|rotate|credential/i },
      { label: 'root cause (no MFA on privileged logon / admin on harvestable host)', pattern: /mfa|privileged|admin.*workstation|harvest|root cause|tier/i },
      { label: 'follow-up (tiered admin model, monitoring)', pattern: /tier|paw|monitor|lesson|owner|follow/i },
    ],
  },
  categoryAccept: ['identity', 'domain', 'compromise', 'ad'],
  resolutionCodeAccept: ['krbtgt', 'contain', 'rotate', 'domain'],
  hints: [
    'DCSync from a non-DC host means the attacker replicated the directory — this is a domain-scale compromise.',
    'Find the rogue Domain Admin (svc_helpdesk2) and disable it. Trace where mreyes\'s creds were stolen (LSASS on the contractor laptop).',
    'A password reset alone is not enough: rotate KRBTGT TWICE to invalidate Golden Tickets. Isolate the entry host.',
    'Because the directory was replicated, treat all privileged/service accounts as exposed and rotate them. Notify leadership and Legal.',
  ],
  debrief: 'This scenario teaches the mental model that identity is the new perimeter. When credential theft reaches DCSync and Domain Admin, per-account remediation is insufficient — the attacker can mint Golden Tickets that outlive any single password reset, so KRBTGT must be rotated twice (the account keeps the current and previous key, so one rotation leaves forged tickets valid). Scoping is domain-wide: a directory replication exposes every hash, so all privileged and service credentials are burned. The root cause worth escalating in lessons-learned is the practice that made it possible: privileged logons without MFA and administrators leaving harvestable sessions on ordinary workstations, which a tiered-admin / PAW model prevents.',
};

// ---------------------------------------------------------------------------
// CIRT-03  Third-party / supply-chain breach notification (comms, legal)
// ---------------------------------------------------------------------------
const cirt_03: Scenario = {
  id: 'cirt-03',
  tier: 'cirt',
  title: 'Our SaaS vendor was breached',
  category: 'Third-Party / Comms',
  difficulty: 4,
  estMinutes: 22,
  objective: 'Run the non-technical side of incident response: validate a third-party breach claim, scope your own exposure, and drive stakeholder communications and regulatory decisions through the right owners without over- or under-reacting.',
  intake: {
    kind: 'incident', number: 'IR-2026-021', title: 'Breach notification from ERP/payroll SaaS vendor (PaystreamHR)',
    declaredBy: 'lchen', summary: 'Our payroll/HR SaaS vendor PaystreamHR emailed that they suffered a breach; customer data "may have been accessed," including employee PII. They provided an IOC list and ask us to rotate API keys and monitor for suspicious logins.',
    severity: 'SEV2', openedAt: ago(60), relatedAlerts: [],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    // Vendor-provided IOCs; scope OUR exposure. One of our integration accounts did see a suspicious login.
    addLog(w, { time: ago(60 * 30), source: 'cloud', user: 'svc_scanner', srcIp: '203.0.113.55', action: 'signin', message: 'PaystreamHR API login for Kestrel integration key from 203.0.113.55 (vendor-listed IOC) - anomalous' });
    addLog(w, { time: ago(60 * 5), source: 'cloud', user: 'sturner', srcIp: '10.10.20.50', action: 'signin', message: 'PaystreamHR portal login sturner (HR) from Denver - normal' });
    w.intel.push({ indicator: '203.0.113.55', type: 'ip', verdict: 'malicious', source: 'Vendor breach IOC list', tags: ['vendor-breach', 'paystreamhr'], detail: 'Listed by PaystreamHR as attacker infrastructure used in their breach.' });
    // The vendor email itself is legit (validate it's really from the vendor, not a phish exploiting the news)
    w.mail.push({
      id: 'MSG-VEND1', time: ago(65), from: 'security@paystreamhr.com', to: ['lchen@kestreldynamics.com'],
      subject: '[Security Notice] PaystreamHR Security Incident - Action Requested',
      status: 'delivered' as const,
      headers: { from: 'PaystreamHR Security <security@paystreamhr.com>', returnPath: 'security@paystreamhr.com', receivedFrom: 'mta.paystreamhr.com [203.0.113.9]', spf: 'pass', dkim: 'pass', dmarc: 'pass', messageId: '<vend1@paystreamhr.com>' },
      body: 'We are notifying customers of a security incident. Customer data may have been accessed. Please rotate your API integration keys and review logins from the attached IOC list. Our status page: https://status.paystreamhr.com',
      urls: ['https://status.paystreamhr.com'], phishing: false,
    });
    w.chat.push({ id: 'ch-lc2', with: 'lchen', messages: [] }, { id: 'ch-rs', with: 'rsingh', messages: [] });
  },
  contactWith: 'rsingh',
  contact: [
    { id: 'validate', question: 'Validate the vendor notice is genuine (headers/DMARC, official channel)', answer: 'Headers: SPF/DKIM/DMARC all pass from paystreamhr.com; matches their official status page. Genuine notice, not a phish riding the news.', purpose: 'verify', reveals: 'genuine' },
    { id: 'legal', question: 'Engage Legal (rsingh) on regulatory/notification obligations for employee PII', answer: 'Raj Singh (Legal): "If employee PII was exposed we have breach-notification duties in several states. WE decide on regulator and employee notification and timing — keep me copied on everything. Do not notify employees or regulators directly."', purpose: 'verify', reveals: 'legal-owns' },
    { id: 'scope', question: 'Scope our own exposure: any suspicious use of our integration keys?', answer: 'Yes — our PaystreamHR integration key was used from 203.0.113.55 (a vendor IOC) 30h ago. HR portal logins otherwise look normal.', purpose: 'clarify', reveals: 'our-exposure' },
    { id: 'panic', question: 'Draft an all-staff email telling everyone their data was stolen', answer: '(KB-0017: do not send all-staff / employee notifications yourself — Legal owns messaging and timing.)', purpose: 'red_flag' },
  ],
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'validate', label: 'Validated the vendor notice is genuine (not a phish)', match: [{ tool: 'mail', action: 'view_headers', target: 'MSG-VEND1' }, { tool: 'chat', action: 'send', target: 'lchen' }], hint: 'Attackers send fake "vendor breach" notices. Confirm it is really from the vendor first.' },
    { id: 'ioc', label: 'Checked the vendor IOC against our logs and found our key used from it', match: [{ tool: 'siem', action: 'search', params: { q: /paystream|203\.0\.113\.55|integration/i } }, { tool: 'intel', action: 'lookup', target: '203.0.113.55' }], hint: 'Did any of the vendor\'s attacker IPs touch our accounts?' },
  ],
  required: [
    { id: 'rotate_key', label: 'Rotated the exposed API integration key / credential', match: [{ tool: 'incident', action: 'reset_service_account', target: 'svc_scanner' }, { tool: 'directory', action: 'reset_password', target: 'svc_scanner' }], skill: 'technical' },
    { id: 'block_ioc', label: 'Blocked the vendor-provided attacker IOC', match: { tool: 'perimeter', action: 'block', target: '203.0.113.55' }, skill: 'technical' },
    { id: 'notify_legal', label: 'Routed regulatory/employee notification through Legal', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
    { id: 'notify_hr', label: 'Engaged HR (employee PII owner) and leadership', match: [{ tool: 'incident', action: 'notify', target: 'hr' }, { tool: 'incident', action: 'notify', target: 'it_director' }], skill: 'process' },
  ],
  forbidden: [
    { id: 'notify_reg', label: 'Notified regulators / employees directly', why: 'KB-0017: Legal decides on and owns regulator and employee notification and its timing. Doing it yourself creates legal exposure and may be premature.', match: [{ tool: 'incident', action: 'notify', target: 'regulator' }, { tool: 'incident', action: 'notify', target: 'affected_users' }, { tool: 'incident', action: 'notify', target: 'all_staff' }], skill: 'process', penalty: 0.4 },
    { id: 'assume_phish', label: 'Dismissed the notice / assumed nothing touched us', why: 'The notice is genuine AND one of our keys was used from a listed attacker IP. Ignoring it leaves a live exposure.', match: { tool: 'ticket', action: 'reply', target: 'r_dismiss' }, skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'The PaystreamHR breach notice is genuine (SPF/DKIM/DMARC pass, matches their official status page). Scoping our exposure: our integration key was used from 203.0.113.55 — one of the attacker IPs on their IOC list — 30 hours ago, so that credential is compromised. I rotated the integration key and blocked the IOC. Employee PII is potentially in scope, so I\'ve engaged HR (the data owner) and Legal; Legal owns the decision and timing on regulator and employee notification — we do not notify anyone externally ourselves. Also briefed the IT Director. I\'m preparing a factual internal summary for Legal/leadership, not an all-staff message.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Validates, scopes real exposure, contains, and routes notification decisions to the right owners.' },
    { id: 'r_dismiss', text: 'These vendor breach emails are usually overblown / could be a phish — monitoring but no action for now.', scores: { communication: 0.3, security: 0.1 }, feedback: 'It is genuine and your key was already abused. Passive monitoring leaves a live compromised credential.' },
    { id: 'r_overreach', text: 'Notified all staff and emailed the state regulator that employee data was breached.', scores: { communication: 0.3, process: 0.1 }, feedback: 'Legal owns regulatory and employee notification. Getting ahead of them creates legal exposure and may be inaccurate this early.' },
  ],
  notesRubric: [
    { label: 'validating the notice is genuine', pattern: /genuine|spf|dkim|dmarc|status page|verified.*vendor|legitimate/i },
    { label: 'our own exposure scoped (integration key used from IOC)', pattern: /integration key|203\.0\.113\.55|our exposure|key.*used|compromised credential/i },
    { label: 'containment (rotate key, block IOC)', pattern: /rotate|reset.*key|block|contain/i },
    { label: 'notification ownership (Legal/HR, not direct external)', pattern: /legal|hr|owns|route|do not notify|not.*directly/i },
  ],
  closure: {
    disposition: 'escalate', escalateTo: 'legal', severity: 'high', category: 'Third-Party - Vendor Breach', resolutionCode: 'Exposure contained; Legal/HR driving notification',
    notifications: ['legal', 'hr', 'it_director'],
    notificationsForbidden: ['regulator', 'affected_users', 'all_staff', 'customers'],
    reportFields: [
      { label: 'validation that the notice is genuine', pattern: /genuine|verified|spf|dkim|dmarc/i },
      { label: 'our exposure (key abused from IOC)', pattern: /key|203\.0\.113\.55|exposure|integration/i },
      { label: 'containment and who owns notification', pattern: /rotate|block|legal|hr|notification|owner/i },
    ],
  },
  categoryAccept: ['third-party', 'vendor', 'breach', 'supply'],
  resolutionCodeAccept: ['vendor', 'legal', 'contain', 'rotate'],
  hints: [
    'First, confirm the breach notice is real — attackers send fake vendor notices to exploit the news. Check the headers.',
    'Scope YOUR exposure: run the vendor\'s IOC list against your logs. Your integration key was used from an attacker IP.',
    'Contain what you control: rotate the key, block the IOC.',
    'Employee PII means HR and Legal lead. Do NOT notify regulators or employees yourself — Legal owns that decision and timing.',
  ],
  debrief: 'Most of incident response above the analyst tier is not technical, and this scenario is deliberately light on packets and heavy on judgment. The three moves: validate the claim (fake breach notices are a real phishing genre), scope your own exposure against the provided IOCs (here a real one — your integration key was abused), and contain what you own (rotate, block). Everything about who-gets-told is owned by Legal and HR: regulator, employee, and customer notification decisions and their timing are legal determinations with real liability, and the analyst\'s job is to feed them accurate facts, not to send the emails. Under-reacting (dismissing it as hype) and over-reacting (notifying regulators yourself) are both failures.',
};

export const CIRT_SCENARIOS: Scenario[] = [cirt_01, cirt_02, cirt_03];
