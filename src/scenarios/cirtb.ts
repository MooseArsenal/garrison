import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, addAlert, setConn } from './helpers';

// ---------------------------------------------------------------------------
// CIRT-04  Business email compromise - fraudulent vendor wire ALREADY sent
// ---------------------------------------------------------------------------
const cirt_04: Scenario = {
  id: 'cirt-04',
  tier: 'cirt',
  title: 'Fraudulent vendor wire already went out ($480k)',
  category: 'BEC - Wire Fraud (funds sent)',
  difficulty: 5,
  estMinutes: 24,
  objective: 'Command a live business-email-compromise wire fraud: move first to claw the money back (bank recall via Finance), preserve the evidence and place a legal hold, and route insurance and law-enforcement contact through Legal - never notify regulators, customers, or all-staff yourself.',
  intake: {
    kind: 'incident', number: 'IR-2026-022', title: 'BEC wire fraud - $480k paid to fraudulent vendor bank account',
    declaredBy: 'rokafor', summary: 'AP specialist jmorales changed a vendor\'s bank details and sent a $480,000 wire after receiving an "urgent, confidential" email that appeared to come from the CFO. The CFO never sent it; the email is a spoof from a look-alike domain. The wire has already left our account.',
    severity: 'SEV1', openedAt: ago(25), relatedAlerts: ['ALT-50101'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50101', time: ago(30), severity: 'high', source: 'email',
      title: 'Executive impersonation / vendor bank-change fraud (jmorales)',
      description: 'Look-alike domain kestreldynamlcs.com impersonating CFO rokafor instructed AP to change vendor banking and wire $480k. SPF/DKIM/DMARC all fail. Payment executed.',
      user: 'jmorales', indicators: ['kestreldynamlcs.com', 'rokafor@kestreldynamlcs.com'], mitre: ['T1566', 'T1656'], status: 'in progress', truth: 'true_positive',
    });
    // The spoofed CFO email that started it (look-alike domain, auth fails).
    w.mail.push({
      id: 'MSG-BEC1', time: ago(60 * 5), from: 'rokafor@kestreldynamlcs.com', to: ['jmorales@kestreldynamics.com'],
      subject: 'RE: Confidential - urgent vendor payment before EOD',
      status: 'delivered' as const,
      headers: { from: 'Rachel Okafor <rokafor@kestreldynamlcs.com>', returnPath: 'billing@securewire-transfers.com', replyTo: 'rokafor.cfo@securewire-transfers.com', receivedFrom: 'vps-11.securewire-transfers.com [45.155.205.211]', spf: 'fail', dkim: 'fail', dmarc: 'fail', messageId: '<bec1@kestreldynamlcs.com>' },
      body: 'Jenna - I\'m in a board session and cannot take calls. Titan Fabrication changed banks; please update their record and release the outstanding $480,000 today. New details attached. Keep this strictly between us until I announce it. - Rachel',
      urls: [], phishing: true,
    });
    // A benign, genuine CFO note from earlier the same day (red herring - looks similar, but real).
    w.mail.push({
      id: 'MSG-BEC2', time: ago(60 * 9), from: 'rokafor@kestreldynamics.com', to: ['jmorales@kestreldynamics.com'],
      subject: 'Q3 AP close reminder',
      status: 'delivered' as const,
      headers: { from: 'Rachel Okafor <rokafor@kestreldynamics.com>', returnPath: 'rokafor@kestreldynamics.com', receivedFrom: 'mta.worksuite-mail.net [198.51.100.44]', spf: 'pass', dkim: 'pass', dmarc: 'pass', messageId: '<bec2@kestreldynamics.com>' },
      body: 'Reminder to finish the AP close by Friday. Thanks.',
      urls: [], phishing: false,
    });
    // ERP + banking trail
    addLog(w, { time: ago(60 * 4), source: 'web', user: 'jmorales', srcIp: '10.10.20.41', action: 'vendor_bank_change', message: 'Kestrel ERP: vendor "Titan Fabrication" bank account changed by jmorales (new beneficiary: SecureWire Transfers, acct ****8841)' });
    addLog(w, { time: ago(60 * 3), source: 'web', user: 'jmorales', srcIp: '10.10.20.41', action: 'wire_release', message: 'Kestrel ERP: outbound wire $480,000.00 released to Titan Fabrication (new beneficiary) by jmorales' });
    w.intel.push({ indicator: 'kestreldynamlcs.com', type: 'domain', verdict: 'malicious', source: 'phish feed', tags: ['bec', 'lookalike', 'typosquat'], detail: 'Typosquat of kestreldynamics.com (m -> rn). Registered 6 days ago. Used for CFO impersonation.' });
    w.intel.push({ indicator: '45.155.205.211', type: 'ip', verdict: 'malicious', source: 'phish feed', tags: ['bec', 'bulletproof'], detail: 'Bulletproof VPS sending the spoofed CFO mail.' });
    w.chat.push({ id: 'ch-jmorales', with: 'jmorales', messages: [] }, { id: 'ch-rsingh4', with: 'rsingh', messages: [] });
  },
  contactWith: 'jmorales',
  contact: [
    { id: 'timeline', question: 'Ask jmorales exactly what happened and when the wire was released', answer: 'Jenna Morales (AP): "The CFO emailed me directly, marked confidential and urgent, said Titan changed banks. I updated the vendor and released the $480k about 3 hours ago. I never called to confirm because she said she was in a board session."', purpose: 'clarify', reveals: 'timeline' },
    { id: 'confirm_cfo', question: 'Confirm with the real CFO (rokafor) whether she sent the request', answer: 'Rachel Okafor (CFO): "I never sent that. I don\'t email banking changes and never bypass callback. That domain isn\'t ours."', purpose: 'verify', reveals: 'spoof-confirmed' },
    { id: 'bank', question: 'Ask Finance to call the bank NOW to attempt a recall / SWIFT return', answer: 'Finance: "Calling the bank\'s fraud line to request a recall and a fraud freeze on the beneficiary. The first 24 hours are critical - many wires can still be clawed back."', purpose: 'verify', reveals: 'recall-started' },
    { id: 'panic', question: 'Draft an all-staff warning that finance was defrauded', answer: '(KB-0017: do not broadcast to all staff during an active incident, and Legal owns external messaging.)', purpose: 'red_flag' },
  ],
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'headers', label: 'Read the spoofed email headers (look-alike domain, SPF/DKIM/DMARC fail)', match: [{ tool: 'mail', action: 'view_headers', target: 'MSG-BEC1' }, { tool: 'mail', action: 'view', target: 'MSG-BEC1' }], hint: 'Compare the From domain and the auth results against a genuine CFO email.' },
    { id: 'trail', label: 'Traced the ERP vendor-bank change and the wire release', match: [{ tool: 'siem', action: 'search', params: { q: /wire|vendor.?bank|titan|jmorales|480/i } }, { tool: 'siem', action: 'pivot', params: { value: /jmorales/ } }], hint: 'Who changed the beneficiary and released the payment, and when?' },
    { id: 'intel', label: 'Confirmed the sender domain/IP are attacker infrastructure', match: [{ tool: 'intel', action: 'lookup', target: 'kestreldynamlcs.com' }, { tool: 'intel', action: 'lookup', target: '45.155.205.211' }] },
  ],
  required: [
    { id: 'notify_finance', label: 'Alerted Finance/AP to contact the bank immediately for a wire recall/freeze', match: { tool: 'incident', action: 'notify', target: 'finance' }, skill: 'process' },
    { id: 'preserve', label: 'Placed a legal hold to preserve the email and ERP/banking evidence', match: { tool: 'incident', action: 'legal_hold' }, skill: 'investigation' },
    { id: 'notify_legal', label: 'Engaged Legal (owns insurance, law-enforcement, and any regulator/customer decision)', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
    { id: 'notify_leadership', label: 'Notified the IT Director/CISO and executives (SEV1)', match: [{ tool: 'incident', action: 'notify', target: 'it_director' }, { tool: 'incident', action: 'notify', target: 'executives' }], skill: 'process' },
    { id: 'block_sender', label: 'Blocked the look-alike sender domain and purged the spoof from other inboxes', match: [{ tool: 'perimeter', action: 'block', target: /kestreldynamlcs\.com/i }, { tool: 'mail', action: 'block_sender', target: /kestreldynamlcs\.com/i }, { tool: 'mail', action: 'purge_all', target: 'MSG-BEC1' }], skill: 'technical', after: 'preserve' },
  ],
  forbidden: [
    { id: 'notify_all', label: 'Sent an all-staff notice that the company was defrauded', why: 'KB-0017: no all-staff broadcast during an active incident - it causes panic and pre-empts Legal on messaging. Brief only the people who need to act.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
    { id: 'le_direct', label: 'Contacted law enforcement / the FBI directly, bypassing Legal', why: 'KB-0017: law-enforcement (IC3/FBI) and cyber-insurance contact route through Legal. You feed Legal the facts; you do not make the external notifications yourself.', match: [{ tool: 'incident', action: 'notify', target: 'law_enforcement' }, { tool: 'incident', action: 'notify', target: 'insurance' }], skill: 'process', penalty: 0.3 },
    { id: 'reg_cust', label: 'Notified the regulator / customers directly', why: 'KB-0017: Legal decides on and owns any regulator or customer notification. Doing it yourself creates legal exposure and may be premature.', match: [{ tool: 'incident', action: 'notify', target: 'regulator' }, { tool: 'incident', action: 'notify', target: 'customers' }], skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed BEC wire fraud. A typosquat domain (kestreldynamlcs.com, "rn" for "m", SPF/DKIM/DMARC all fail) impersonated the CFO and instructed AP (jmorales) to change Titan Fabrication\'s bank details and wire $480k, which was released ~3 hours ago. First move: I\'ve told Finance to call the bank\'s fraud line NOW for a recall/SWIFT return and a freeze on the beneficiary - the first 24 hours are when the money is recoverable. I placed a legal hold on the email and the ERP/banking records, blocked the look-alike domain, and purged the spoof from other mailboxes. Notified the IT Director, executives, and Legal; Legal owns the cyber-insurance claim, any law-enforcement (IC3/FBI) report, and any regulator/customer decision - I am not making those external notifications myself. No all-staff message. Root cause: the callback control on vendor bank changes was skipped under manufactured urgency.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Money-recall first, evidence preserved, and notifications routed to the right owners.' },
    { id: 'r_slow', text: 'Preserved the email and opened a forensic case; we can pursue the bank recall tomorrow once the investigation is further along.', scores: { communication: 0.4, security: 0.3, process: 0.3 }, feedback: 'Too slow on the money. The bank recall is the highest-value action and is time-critical - it happens in parallel with, not after, the investigation.' },
    { id: 'r_overreach', text: 'Reported it to the FBI and the state regulator, filed the insurance claim, and emailed all staff to watch for CFO fraud.', scores: { communication: 0.3, process: 0.1 }, feedback: 'Those external contacts (LE, insurer, regulator) and messaging are Legal\'s to own; getting ahead of them creates exposure. And no all-staff during an active incident.' },
  ],
  notesRubric: [
    { label: 'root cause / attack (CFO impersonation from a look-alike domain, callback control skipped)', pattern: /impersonat|spoof|look-?alike|typosquat|kestreldynamlcs|callback|dmarc|urgen/i },
    { label: 'money recovery is first (bank recall / freeze via Finance)', pattern: /bank|recall|swift|freeze|finance|claw/i },
    { label: 'evidence preserved (legal hold), containment (block domain, purge)', pattern: /legal hold|preserve|block|purge|quarantine/i },
    { label: 'notifications (Finance/Legal/leadership; LE & insurer via Legal, not direct)', pattern: /legal|finance|it director|exec|insurance.*legal|not.*direct|via legal/i },
  ],
  closure: {
    disposition: 'escalate', escalateTo: 'legal', severity: 'critical', category: 'BEC - Wire Fraud (funds sent)', resolutionCode: 'Bank recall initiated; evidence held; Legal driving insurance/LE',
    notifications: ['finance', 'legal', 'executives', 'it_director'],
    notificationsForbidden: ['all_staff', 'regulator', 'law_enforcement', 'customers', 'insurance'],
    reportFields: [
      { label: 'timeline (spoof email -> bank change -> wire release)', pattern: /timeline|spoof|bank change|wire|480|3 hour/i },
      { label: 'root cause (executive impersonation, skipped verification control)', pattern: /impersonat|look-?alike|typosquat|callback|control|root cause/i },
      { label: 'recovery actions (bank recall, block, purge, legal hold)', pattern: /recall|freeze|block|purge|legal hold/i },
      { label: 'notification ownership (Legal owns LE/insurer/regulator)', pattern: /legal|insurance|law enforcement|regulator|owner|via legal/i },
    ],
  },
  categoryAccept: ['bec', 'wire', 'fraud', 'business email'],
  resolutionCodeAccept: ['bec', 'wire', 'recall', 'fraud', 'legal'],
  hints: [
    'The money is the emergency. Get Finance to call the bank\'s fraud line for a recall/freeze immediately - recovery odds drop sharply after 24 hours.',
    'Prove the spoof: the From domain is a typosquat (kestreldynamlcs.com) and SPF/DKIM/DMARC all fail. Compare against a genuine CFO email.',
    'Preserve first: legal hold on the email and the ERP/banking records before you purge the spoof from other mailboxes.',
    'Notify Finance, Legal, the IT Director, and executives. Legal owns the insurance claim, the law-enforcement (IC3/FBI) report, and any regulator/customer notice - do not do those yourself. No all-staff.',
  ],
  debrief: 'Business email compromise is a finance incident as much as a security one, and the clock is on the money. When a fraudulent wire has already left, the single highest-value action is the bank recall/SWIFT return, driven through Finance to the bank\'s fraud desk - it runs in parallel with everything else and its window is roughly the first 24 hours. Everything else is standard discipline: prove the spoof (a typosquat domain with failing SPF/DKIM/DMARC, not the real CFO), preserve the evidence with a legal hold before you purge the message, and contain by blocking the domain. The notification trap here is doing Legal\'s job: the cyber-insurance claim, the IC3/FBI report, and any regulator or customer notice are all Legal-owned decisions - the analyst supplies facts, never sends those notices, and never blasts all-staff. The lessons-learned headline is the process control that failed: vendor bank changes must require an out-of-band callback that manufactured urgency cannot wave away.',
};

// ---------------------------------------------------------------------------
// CIRT-05  Insider sabotage - departing admin, deleted shares + logic bomb
// ---------------------------------------------------------------------------
const cirt_05: Scenario = {
  id: 'cirt-05',
  tier: 'cirt',
  title: 'Departing admin deleted shares and left a logic bomb',
  category: 'Insider - Sabotage',
  difficulty: 5,
  estMinutes: 26,
  objective: 'Run an insider-sabotage response: preserve evidence and place a legal hold BEFORE remediating, cut the insider\'s access and rotate the credentials they knew, neutralize the planted logic bomb, restore the data - all without tipping the suspect off, and with HR and Legal (not all-staff) in the loop.',
  intake: {
    kind: 'incident', number: 'IR-2026-023', title: 'Suspected sabotage by departing sysadmin (mreyes)',
    declaredBy: 'lchen', summary: 'Systems Administrator Marco Reyes (mreyes) resigned and is in his notice period. Overnight, several FS01 shares were deleted and a hidden scheduled task ("KestrelCleanup") was found on his workstation set to run a wiper script against the file shares next week. His account is still fully active with Domain Admin rights.',
    severity: 'SEV1', openedAt: ago(35), relatedAlerts: ['ALT-50111'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50111', time: ago(40), severity: 'high', source: 'edr',
      title: 'Mass file deletion on DEN-FS01 + hidden scheduled task on DEN-LT-1021 (mreyes)',
      description: 'Bulk deletion of D:\\Shares\\Finance and D:\\Shares\\Engineering by mreyes at 02:41. A hidden scheduled task "KestrelCleanup" on DEN-LT-1021 is set to run a wiper against \\\\FS01 shares on 2026-09-20.',
      user: 'mreyes', host: 'DEN-FS01', indicators: ['mreyes', 'KestrelCleanup', 'cleanup.ps1'], mitre: ['T1485', 'T1489', 'T1053.005'], status: 'in progress', truth: 'true_positive',
    });
    const m = findUser(w, 'mreyes')!;
    m.termDate = daysAgo(-9); // resigns / last day ~9 days out (negative days => future)
    m.notes = 'Resigned; in notice period. Retains Domain Admin. HR flagged a dispute over the departure.';
    m.recentSignIns = [
      { time: ago(41), ip: '10.10.20.121', location: 'Denver, US', app: 'Windows Sign-in (DEN-FS01)', result: 'success', device: 'DEN-LT-1021', mfa: 'satisfied' },
      { time: ago(60 * 20), ip: '10.10.20.121', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1021', mfa: 'satisfied' },
    ];
    // The planted logic bomb on his workstation.
    const mh = host(w, 'DEN-LT-1021');
    mh.scheduledTasks.push({ name: 'KestrelCleanup', path: '\\', action: 'powershell.exe -WindowStyle Hidden -File C:\\ProgramData\\cleanup.ps1', trigger: 'Once 2026-09-20 02:00', author: 'KESTREL\\mreyes', suspicious: true });
    mh.files.push({ path: 'C:\\ProgramData\\cleanup.ps1', size: 4096, modified: ago(60 * 8), signed: false, suspicious: true });
    addEvent(mh, { id: 4698, time: ago(60 * 8), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A scheduled task was created. Task: KestrelCleanup. Subject: KESTREL\\mreyes. Command: powershell -File C:\\ProgramData\\cleanup.ps1' });
    // File-server deletion trail + the shares now show gaps.
    const fs = w.servers.find((s) => s.id === 'DEN-FS01')!;
    if (fs.shares) {
      fs.shares.find((s) => s.name === 'Finance')!.status = 'offline';
      fs.shares.find((s) => s.name === 'Engineering')!.status = 'offline';
    }
    addLog(w, { time: ago(60 * 9), source: 'windows', host: 'DEN-FS01', user: 'mreyes', action: 'file_delete', message: '4660/4663 mass DELETE on D:\\Shares\\Finance and D:\\Shares\\Engineering by mreyes (14,204 objects)' });
    addLog(w, { time: ago(60 * 8), source: 'windows', host: 'DEN-LT-1021', user: 'mreyes', action: 'schtask_create', message: '4698 scheduled task KestrelCleanup created by mreyes (wiper against \\\\FS01, trigger 2026-09-20)' });
    // Clean restore point BEFORE the deletion (deletion 9h ago; last good backup 12h ago).
    const bkp = w.servers.find((s) => s.id === 'DEN-BKP01')!;
    bkp.backups = [
      { job: 'FS01-Daily-Shares', lastRun: ago(60 * 12), status: 'success', restorePoints: 30 },
      { job: 'Offsite-Immutable-Copy', lastRun: ago(60 * 26), status: 'success', restorePoints: 30 },
      { job: 'DC-SystemState', lastRun: ago(60 * 11), status: 'success', restorePoints: 7 },
    ];
    w.chat.push({ id: 'ch-mreyes5', with: 'mreyes', messages: [] }, { id: 'ch-sturner5', with: 'sturner', messages: [] }, { id: 'ch-rsingh5', with: 'rsingh', messages: [] });
  },
  contactWith: 'sturner',
  contact: [
    { id: 'hr', question: 'Ask HR (sturner) about the departure and how to handle the suspect', answer: 'Sarah Turner (HR): "It\'s a contested resignation - there\'s a grievance. HR and Legal will coordinate any conversation with Marco. Do NOT contact him or tip him off; just cut his access and preserve everything."', purpose: 'verify', reveals: 'hr-owns-confrontation' },
    { id: 'legal', question: 'Confirm with Legal (rsingh) the evidence-handling expectations', answer: 'Raj Singh (Legal): "Place a litigation/legal hold immediately and image before you change anything - this may go to employment litigation or prosecution. Preserve the scheduled task and the deletion logs."', purpose: 'verify', reveals: 'legal-hold' },
    { id: 'scope', question: 'Ask what else the admin could reach', answer: 'He was a Domain Admin with the backup and server-admin rights - treat every privileged and service credential he knew as exposed.', purpose: 'clarify', reveals: 'scope' },
    { id: 'confront', question: 'Message Marco directly to ask why he deleted the shares', answer: '(Do NOT: confronting the suspect tips him off, lets him destroy more or invoke the still-armed logic bomb, and cuts across HR/Legal.)', purpose: 'red_flag' },
  ],
  evidence: [
    { id: 'kb18', label: 'Reviewed the IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'bomb', label: 'Found the hidden logic-bomb scheduled task on DEN-LT-1021', match: [{ tool: 'rdp', action: 'view_tasks', target: 'DEN-LT-1021' }, { tool: 'siem', action: 'search', params: { q: /kestrelcleanup|cleanup\.ps1|4698|schtask/i } }], hint: 'Look for a scheduled task the admin created that runs in the future.' },
    { id: 'deletion', label: 'Confirmed the mass deletion of the FS01 shares by mreyes', match: [{ tool: 'siem', action: 'search', params: { q: /delete|4660|4663|shares|mreyes/i } }, { tool: 'server', action: 'view_shares', target: 'DEN-FS01' }], hint: 'Which shares went offline, and who deleted them?' },
    { id: 'backup', label: 'Identified a clean restore point taken before the deletion', match: { tool: 'server', action: 'view_backups', target: 'DEN-BKP01' }, hint: 'Is there a backup that predates the 02:41 deletion?' },
  ],
  required: [
    { id: 'preserve', label: 'Placed a legal hold to preserve evidence before remediating', match: { tool: 'incident', action: 'legal_hold' }, skill: 'process' },
    { id: 'triage', label: 'Collected a triage/forensic package from the workstation', match: [{ tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1021' }, { tool: 'incident', action: 'collect_triage' }], skill: 'investigation', after: 'preserve' },
    { id: 'disable_suspect', label: 'Disabled the suspect account and revoked its sessions', match: [{ tool: 'directory', action: 'disable', target: 'mreyes' }, { tool: 'directory', action: 'revoke_sessions', target: 'mreyes' }], skill: 'technical' },
    { id: 'krbtgt', label: 'Rotated KRBTGT / privileged credentials the DA insider knew', match: [{ tool: 'incident', action: 'rotate_krbtgt' }, { tool: 'incident', action: 'reset_service_account', target: /svc_/i }], skill: 'security', after: 'disable_suspect' },
    { id: 'neutralize', label: 'Removed the planted logic-bomb scheduled task', match: { tool: 'rdp', action: 'delete_task', target: 'DEN-LT-1021', params: { task: /kestrelcleanup/i } }, skill: 'technical', after: 'triage' },
    { id: 'restore', label: 'Restored the deleted shares from the clean pre-deletion backup', match: [{ tool: 'server', action: 'restore', target: 'DEN-BKP01' }, { tool: 'incident', action: 'restore_backup', target: 'DEN-FS01' }], skill: 'technical', after: 'triage' },
    { id: 'notify', label: 'Engaged HR, Legal, the IT Director, and executives', match: [{ tool: 'incident', action: 'notify', target: 'hr' }, { tool: 'incident', action: 'notify', target: 'legal' }, { tool: 'incident', action: 'notify', target: 'it_director' }], skill: 'process' },
  ],
  forbidden: [
    { id: 'tip_off', label: 'Messaged / confronted the suspect directly', why: 'Confronting an insider tips them off: they can destroy more, trigger the still-armed logic bomb, or invoke counsel before evidence is preserved. HR and Legal orchestrate any conversation.', match: [{ tool: 'chat', action: 'send', target: 'mreyes' }, { tool: 'chat', action: 'open', target: 'mreyes' }], skill: 'process', penalty: 0.4 },
    { id: 'notify_all', label: 'Sent an all-staff notice about the insider', why: 'KB-0017: no all-staff during an active incident, and especially not for an insider case - it tips the suspect and is an HR/Legal matter.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
    { id: 'reg_direct', label: 'Notified a regulator / law enforcement directly', why: 'KB-0017: any external legal action (regulator, prosecution referral) is Legal\'s decision, not the analyst\'s.', match: [{ tool: 'incident', action: 'notify', target: 'regulator' }, { tool: 'incident', action: 'notify', target: 'law_enforcement' }], skill: 'process', penalty: 0.3 },
    { id: 'wipe_first', label: 'Reimaged the workstation before collecting evidence', why: 'KB-0018: evidence first. Reimaging destroys the forensic record needed for HR/Legal action and to prove intent.', match: { tool: 'incident', action: 'reimage', target: 'DEN-LT-1021' }, skill: 'security', penalty: 0.4, unlessAfter: 'triage' },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Insider sabotage by the departing DA (mreyes), contained. Evidence first: I placed a legal hold and collected a triage/forensic image of his workstation before touching anything. Then cut access - disabled the account and revoked its sessions - and, because he was a Domain Admin, rotated KRBTGT and the privileged/service credentials he knew. Neutralized the armed logic bomb by removing the hidden "KestrelCleanup" scheduled task (wiper set for 2026-09-20). The Finance and Engineering shares he mass-deleted at 02:41 are being restored from the 12-hour-old backup that predates the deletion. Engaged HR and Legal (contested departure - they own any conversation with him and the litigation hold) plus the IT Director and executives. I did NOT contact him or send any all-staff notice. Lessons: no offboarding lockout on notice, and a single admin with unchecked Domain Admin + backup rights.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Evidence-first, access cut, DA credentials rotated, bomb defused, data restored, HR/Legal engaged - and no tip-off.' },
    { id: 'r_fast', text: 'Disabled Marco, deleted the malicious task, and reimaged his laptop to be safe, then restored the shares.', scores: { communication: 0.3, security: 0.2, process: 0.3 }, feedback: 'Reimaging before imaging destroys the evidence HR/Legal need to prove intentional sabotage. Preserve first; and rotate the DA credentials he knew.' },
    { id: 'r_confront', text: 'Asked Marco directly what he did and warned all staff to watch for tampering while we investigate.', scores: { communication: 0.2, process: 0.1 }, feedback: 'Both tip the suspect. HR/Legal run any confrontation, and there is no all-staff during an active insider incident.' },
  ],
  notesRubric: [
    { label: 'evidence first (legal hold + triage image before remediation)', pattern: /legal hold|preserve|triage|image|forensic|evidence first/i },
    { label: 'access cut + DA credential rotation (KRBTGT / privileged / service accounts)', pattern: /disable|revoke|krbtgt|rotate|privileged|service account/i },
    { label: 'logic bomb neutralized + data restored from clean backup', pattern: /kestrelcleanup|scheduled task|logic bomb|restore|clean backup|pre-?deletion/i },
    { label: 'HR/Legal engaged, suspect not tipped off, no all-staff', pattern: /hr|legal|not.*tip|do not contact|no all.?staff/i },
  ],
  closure: {
    disposition: 'resolve', severity: 'critical', category: 'Insider - Sabotage', resolutionCode: 'Access cut, bomb removed, data restored, HR/Legal engaged',
    notifications: ['hr', 'legal', 'it_director', 'executives'],
    notificationsForbidden: ['all_staff', 'regulator', 'law_enforcement', 'customers'],
    reportFields: [
      { label: 'what the insider did (deletion + planted logic bomb) and timeline', pattern: /delet|logic bomb|kestrelcleanup|02:41|timeline|schedul/i },
      { label: 'evidence handling (legal hold, triage before remediation)', pattern: /legal hold|triage|image|forensic|preserve/i },
      { label: 'remediation (access cut, credential rotation, bomb removed, restore)', pattern: /disable|revoke|krbtgt|rotate|remove.*task|restore/i },
      { label: 'root cause / lessons (offboarding, unchecked DA + backup rights)', pattern: /offboard|notice period|domain admin|separation of duties|least privilege|lesson|owner/i },
    ],
  },
  categoryAccept: ['insider', 'sabotage', 'malicious'],
  resolutionCodeAccept: ['insider', 'sabotage', 'contain', 'restore'],
  hints: [
    'Evidence FIRST (KB-0018): place a legal hold and collect a triage image of his workstation before you change or delete anything.',
    'Cut access: disable the account and revoke sessions. He was a Domain Admin, so rotate KRBTGT and the privileged/service credentials he knew.',
    'Neutralize the armed logic bomb (delete the hidden KestrelCleanup task) and restore the shares from the backup that predates the 02:41 deletion.',
    'This is an HR/Legal matter: engage them plus the IT Director and executives. Do NOT contact the suspect or send an all-staff notice.',
  ],
  debrief: 'Insider cases invert the usual instinct to act fast: because the output feeds HR and possibly litigation or prosecution, evidence handling comes first - legal hold, then a forensic image, then remediation. Only then do you cut access and, because this insider held Domain Admin plus backup rights, rotate KRBTGT and every privileged and service credential he could have known. Two things make sabotage distinct from an external compromise: a planted logic bomb that must be found and defused before it detonates, and a live human suspect who must not be tipped off - confrontation is HR and Legal\'s to stage, never the analyst\'s, and there is no all-staff notice. Recovery uses the same clean-restore-point discipline as ransomware. The lessons-learned headline is offboarding hygiene: admins on notice should lose privileged access immediately, and no single administrator should hold unchecked Domain Admin and backup rights at once.',
};

// ---------------------------------------------------------------------------
// CIRT-06  Public website defacement / possible customer-facing exposure
// ---------------------------------------------------------------------------
const cirt_06: Scenario = {
  id: 'cirt-06',
  tier: 'cirt',
  title: 'Public marketing website defaced',
  category: 'Web - Defacement',
  difficulty: 4,
  estMinutes: 20,
  objective: 'Handle a customer-facing web defacement: preserve evidence, take the site to a controlled maintenance state, scope for any data exposure, and drive all external communication (customers, regulator, holding statement) through Legal instead of speaking for the company yourself.',
  intake: {
    kind: 'incident', number: 'IR-2026-024', title: 'Defacement of the public website (kestreldynamics.com)',
    declaredBy: 'jwebb', summary: 'The public marketing site (DEN-WEB01, DMZ) is showing a defacement page instead of the homepage. A CMS admin login was brute-forced from an external IP; the attacker replaced index content and may have accessed the CMS database (marketing contact-form submissions).',
    severity: 'SEV2', openedAt: ago(20), relatedAlerts: ['ALT-50121'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50121', time: ago(24), severity: 'high', source: 'ids',
      title: 'Web defacement + CMS admin brute force on DEN-WEB01',
      description: 'Public site index replaced with a defacement page. Preceded by successful CMS admin login from 91.219.236.18 after ~600 failed attempts. Possible access to the contact-form/marketing database.',
      host: 'DEN-WEB01', indicators: ['91.219.236.18', 'DEN-WEB01'], mitre: ['T1190', 'T1491.002'], status: 'in progress', truth: 'true_positive',
    });
    // Add the DMZ marketing web server (not in the base world).
    w.servers.push({
      id: 'DEN-WEB01', role: 'DMZ Marketing Web Server (public kestreldynamics.com CMS)', ip: '198.51.100.20', os: 'Windows Server 2022', status: 'degraded',
      services: [
        { name: 'W3SVC', displayName: 'World Wide Web Publishing Service', status: 'running', startType: 'auto' },
        { name: 'MSSQL$CMS', displayName: 'SQL Server (CMS)', status: 'running', startType: 'auto' },
        { name: 'HalberdAgent', displayName: 'Halberd EDR Agent', status: 'running', startType: 'auto' },
      ],
      disk: [{ drive: 'C:', used: 55, size: 120 }, { drive: 'E:', used: 40, size: 200 }], cpu: 18, mem: 44, uptimeHours: 260, events: [],
      backups: [{ job: 'WEB01-Daily', lastRun: ago(60 * 8), status: 'success', restorePoints: 14 }],
    });
    addLog(w, { time: ago(60), source: 'web', host: 'DEN-WEB01', srcIp: '91.219.236.18', action: 'brute_force', message: 'CMS /admin login: ~600 failed attempts then SUCCESS from 91.219.236.18' });
    addLog(w, { time: ago(30), source: 'web', host: 'DEN-WEB01', srcIp: '91.219.236.18', action: 'defacement', message: 'index.html replaced; POST /admin/pages/edit from 91.219.236.18' });
    addLog(w, { time: ago(28), source: 'web', host: 'DEN-WEB01', srcIp: '91.219.236.18', action: 'db_query', message: 'CMS DB export query on contact_submissions table (name/email/message) from admin session' });
    w.intel.push({ indicator: '91.219.236.18', type: 'ip', verdict: 'malicious', source: 'IDS/GreyNoise', tags: ['defacement', 'scanner', 'brute-force'], detail: 'Hosting-provider IP tied to web-defacement and CMS brute-force campaigns.' });
    w.chat.push({ id: 'ch-rsingh6', with: 'rsingh', messages: [] }, { id: 'ch-jwebb6', with: 'jwebb', messages: [] });
  },
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'entry', label: 'Traced entry to a brute-forced CMS admin login', match: [{ tool: 'siem', action: 'search', params: { q: /brute|admin|91\.219\.236\.18|deface|cms/i } }, { tool: 'server', action: 'view_events', target: 'DEN-WEB01' }], hint: 'How did the attacker get into the CMS - and from where?' },
    { id: 'exposure', label: 'Scoped possible data exposure (contact-form/marketing DB access)', match: [{ tool: 'siem', action: 'search', params: { q: /contact_submissions|db|export|database/i } }, { tool: 'server', action: 'view', target: 'DEN-WEB01' }], hint: 'Did the attacker only change the page, or also read data?' },
    { id: 'intel', label: 'Confirmed the source IP is known-malicious', match: { tool: 'intel', action: 'lookup', target: '91.219.236.18' } },
  ],
  required: [
    { id: 'preserve', label: 'Preserved web/CMS evidence (legal hold + triage) before rebuilding', match: [{ tool: 'incident', action: 'legal_hold' }, { tool: 'edr', action: 'collect_triage', target: 'DEN-WEB01' }], skill: 'investigation' },
    { id: 'contain', label: 'Took the site to a controlled maintenance/offline state', match: [{ tool: 'edr', action: 'isolate', target: 'DEN-WEB01' }, { tool: 'server', action: 'stop_service', target: 'DEN-WEB01', params: { service: /w3svc/i } }], skill: 'technical', after: 'preserve' },
    { id: 'block', label: 'Blocked the attacker IP at the perimeter', match: { tool: 'perimeter', action: 'block', target: '91.219.236.18' }, skill: 'technical' },
    { id: 'notify_legal', label: 'Engaged Legal to own comms and any customer/regulator decision', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
    { id: 'notify_leadership', label: 'Notified the IT Director and executives', match: [{ tool: 'incident', action: 'notify', target: 'it_director' }, { tool: 'incident', action: 'notify', target: 'executives' }], skill: 'process' },
  ],
  forbidden: [
    { id: 'notify_customers', label: 'Notified customers directly / posted a public statement', why: 'KB-0017: Legal owns customer and public messaging and its timing. A premature or inaccurate statement creates legal and reputational exposure.', match: [{ tool: 'incident', action: 'notify', target: 'customers' }, { tool: 'incident', action: 'notify', target: 'all_staff' }], skill: 'process', penalty: 0.4 },
    { id: 'notify_reg', label: 'Notified a regulator directly', why: 'KB-0017: any regulator notification (if the exposed contact data even triggers one) is Legal\'s determination, not the analyst\'s.', match: { tool: 'incident', action: 'notify', target: 'regulator' }, skill: 'process', penalty: 0.3 },
    { id: 'rebuild_first', label: 'Rebuilt/restored the site before preserving evidence', why: 'KB-0018: preserve first. Restoring over the defaced site destroys the forensic record of how they got in and what they touched.', match: [{ tool: 'server', action: 'restore', target: 'DEN-WEB01' }, { tool: 'incident', action: 'restore_backup', target: 'DEN-WEB01' }], skill: 'security', penalty: 0.3, unlessAfter: 'preserve' },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Public site (DEN-WEB01) defacement contained. Entry was a brute-forced CMS admin login from 91.219.236.18 (~600 failures then success); the attacker replaced the homepage and ran an export query against the contact_submissions table, so limited marketing contact data (name/email/message) is potentially exposed. I preserved evidence first (legal hold + triage of the server), then took the site to a maintenance state and blocked the attacker IP. Engaged Legal, the IT Director, and executives - Legal owns the holding statement and any customer or regulator notification; I am not posting anything public or emailing customers myself. Next: Legal drafts the factual holding statement, we rebuild from a known-good backup and reset the CMS admin credentials with MFA before bringing the site back.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Preserve, contain, block, and let Legal own the customer-facing message.' },
    { id: 'r_public', text: 'Put up our own "we\'ve been hacked, your data may be affected" banner and emailed our customer list right away to be transparent.', scores: { communication: 0.3, process: 0.1 }, feedback: 'Customer and public messaging is Legal\'s to own and time. A premature, self-authored statement creates exposure and may be inaccurate this early.' },
    { id: 'r_rebuild', text: 'Restored the site from last night\'s backup immediately so customers see the real page again, then looked into the cause.', scores: { communication: 0.3, security: 0.2 }, feedback: 'Restoring first destroys the evidence of how they got in and what data they touched. Preserve, then rebuild.' },
  ],
  notesRubric: [
    { label: 'entry vector (brute-forced CMS admin from a known-bad IP)', pattern: /brute|cms|admin|91\.219\.236\.18|weak|password/i },
    { label: 'data exposure scoped (contact-form / marketing DB)', pattern: /contact|database|db|export|exposure|submission/i },
    { label: 'evidence preserved, site contained, IP blocked', pattern: /legal hold|preserve|triage|maintenance|isolat|block/i },
    { label: 'Legal owns comms; no direct customer/regulator/public notice', pattern: /legal|holding statement|comms|not.*customer|not.*direct|owner/i },
  ],
  closure: {
    disposition: 'escalate', escalateTo: 'legal', severity: 'high', category: 'Web - Defacement', resolutionCode: 'Preserved & contained; Legal owns comms; rebuild pending',
    notifications: ['legal', 'executives', 'it_director'],
    notificationsForbidden: ['customers', 'regulator', 'all_staff'],
    reportFields: [
      { label: 'entry vector and timeline', pattern: /brute|cms|admin|timeline|deface/i },
      { label: 'scope of exposure (page change vs data access)', pattern: /contact|database|export|exposure|data/i },
      { label: 'containment and recovery plan (preserve, maintenance, rebuild + MFA)', pattern: /preserve|legal hold|maintenance|isolat|rebuild|mfa/i },
      { label: 'communication ownership (Legal, holding statement)', pattern: /legal|holding statement|comms|customer|owner/i },
    ],
  },
  categoryAccept: ['web', 'defacement', 'website'],
  resolutionCodeAccept: ['web', 'deface', 'contain', 'legal'],
  hints: [
    'Preserve before you rebuild (KB-0018): legal hold and a triage collection of the web server first - restoring over the defacement destroys the evidence.',
    'Contain by taking the site to a controlled maintenance/offline state and blocking the attacker IP (91.219.236.18).',
    'Scope it: the attacker did more than change the page - check for a database export of the contact-form data.',
    'This is customer-facing. Legal owns the holding statement and any customer/regulator notice. Notify Legal, the IT Director, and executives - do not post publicly or email customers yourself.',
  ],
  debrief: 'A defacement is loud but the real questions are quiet: how did they get in, and did they only change the page or also take data? Here a brute-forced CMS admin login (no MFA, weak password) let the attacker both deface the site and export the marketing contact database - so this is a possible data exposure, not just vandalism. The response is ordinary IR discipline applied to a DMZ asset: preserve first (a restore-over would erase the forensic trail), take the site to a controlled maintenance state rather than leaving the defacement up, block the source, and rebuild from a known-good image with the admin credentials reset and MFA added. What makes it a CIRT judgment case is the communication: the moment an incident is customer-facing, everyone wants to say something, and every external word - the holding statement, customer notice, regulator notification - belongs to Legal. The analyst\'s job is to give Legal accurate scope, not to speak for the company.',
};

// ---------------------------------------------------------------------------
// CIRT-07  Lost/stolen laptop containing regulated PII
// ---------------------------------------------------------------------------
const cirt_07: Scenario = {
  id: 'cirt-07',
  tier: 'cirt',
  title: 'Stolen laptop containing regulated PII',
  category: 'Device - Lost/Stolen (PII)',
  difficulty: 4,
  estMinutes: 20,
  objective: 'Handle a lost/stolen device with regulated data: contain the device and the user\'s identity, then let the encryption status drive the breach determination - and route the notification decision to Legal rather than declaring (or dismissing) a breach yourself.',
  intake: {
    kind: 'incident', number: 'IR-2026-025', title: 'Stolen corporate laptop (DEN-LT-1002) with regulated PII',
    declaredBy: 'rokafor', summary: 'The CFO\'s laptop (DEN-LT-1002) was stolen from a car overnight; a police report is filed. It held finance and HR spreadsheets with regulated PII (SSNs, bank details). Need containment and a breach-risk determination.',
    severity: 'SEV2', openedAt: ago(30), relatedAlerts: ['ALT-50131'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50131', time: ago(32), severity: 'medium', source: 'user_report',
      title: 'Lost/stolen device report - DEN-LT-1002 (rokafor)',
      description: 'CFO laptop stolen overnight; police report filed. Contains regulated PII. Determine breach risk (encryption at rest?) and contain identity.',
      user: 'rokafor', host: 'DEN-LT-1002', indicators: ['DEN-LT-1002'], mitre: ['T1078'], status: 'new', truth: 'true_positive',
    });
    // Mark the device host offline/last-seen and confirm BitLocker (encryption lowers breach risk).
    const h = host(w, 'DEN-LT-1002');
    h.online = false;
    h.lastSeen = ago(60 * 12);
    h.bitlocker = 'on';
    h.notes = 'Reported stolen. BitLocker enabled (TPM + PIN), disk encrypted at rest. No screen-unlock compromise reported.';
    // Update the asset record to a known, unique tag so the wipe target is deterministic.
    const laptop = w.assets.find((a) => a.hostname === 'DEN-LT-1002');
    if (laptop) {
      laptop.tag = 'KD-09002';
      laptop.status = 'lost/stolen';
      laptop.notes = 'Stolen overnight; police report #DEN-2026-88213 on file. BitLocker was enabled.';
    }
    addLog(w, { time: ago(60 * 12), source: 'windows', host: 'DEN-LT-1002', user: 'rokafor', action: 'last_seen', message: 'DEN-LT-1002 last check-in; BitLocker protected volume, TPM+PIN. Offline since.' });
    w.chat.push({ id: 'ch-rokafor7', with: 'rokafor', messages: [] }, { id: 'ch-rsingh7', with: 'rsingh', messages: [] });
  },
  contactWith: 'rokafor',
  contact: [
    { id: 'circumstances', question: 'Ask the CFO about the theft and whether the laptop was locked/encrypted', answer: 'Rachel Okafor: "Stolen from my car overnight, filed a police report. It was powered off and locked; BitLocker is on with a PIN. I did not save any passwords in plaintext on the desktop."', purpose: 'verify', reveals: 'encrypted-locked' },
    { id: 'data', question: 'Ask what regulated data was actually on the device', answer: 'It held finance and HR spreadsheets with SSNs and bank details - regulated PII - but the volume was BitLocker-encrypted at rest.', purpose: 'clarify', reveals: 'data-scope' },
    { id: 'legal', question: 'Ask Legal (rsingh) who makes the breach/notification determination', answer: 'Raj Singh (Legal): "Encryption at rest is a safe-harbor factor under most breach laws, so an encrypted device usually is not a reportable breach - but WE make that determination and any notification decision, not the responder. Send us the encryption evidence."', purpose: 'verify', reveals: 'legal-owns' },
    { id: 'panic', question: 'Email all staff and our customers that a device with data was stolen', answer: '(Do NOT: no all-staff for this, and any customer/regulator notice is Legal\'s call once they assess the encryption.)', purpose: 'red_flag' },
  ],
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'encryption', label: 'Confirmed the disk was BitLocker-encrypted at rest (breach-risk factor)', match: [{ tool: 'assets', action: 'view', target: /kd-09002/i }, { tool: 'directory', action: 'view_computer', target: 'DEN-LT-1002' }], hint: 'Encryption at rest is the single biggest factor in whether this is a reportable breach.' },
    { id: 'asset', label: 'Located the asset/device record for the stolen laptop', match: [{ tool: 'assets', action: 'search', params: { q: /rokafor|DEN-LT-1002|stolen/i } }, { tool: 'assets', action: 'view', target: /kd-09002/i }] },
  ],
  required: [
    { id: 'wipe', label: 'Issued a remote wipe / marked the device lost-stolen', match: [{ tool: 'assets', action: 'remote_wipe', target: /kd-09002/i }, { tool: 'assets', action: 'remote_wipe' }], skill: 'technical' },
    { id: 'revoke', label: 'Revoked the user\'s active sessions', match: { tool: 'directory', action: 'revoke_sessions', target: 'rokafor' }, skill: 'technical' },
    { id: 'reset', label: 'Reset the user\'s credentials after revoking sessions', match: [{ tool: 'directory', action: 'reset_password', target: 'rokafor' }, { tool: 'directory', action: 'reset_mfa', target: 'rokafor' }], skill: 'technical', after: 'revoke' },
    { id: 'notify_legal', label: 'Routed the breach/notification determination to Legal', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
    { id: 'notify_it', label: 'Notified the IT Director', match: { tool: 'incident', action: 'notify', target: 'it_director' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'notify_reg', label: 'Notified a regulator directly', why: 'KB-0017: Legal determines whether an encrypted lost device is even a reportable breach and owns any regulator notice. The analyst supplies the encryption evidence.', match: { tool: 'incident', action: 'notify', target: 'regulator' }, skill: 'process', penalty: 0.4 },
    { id: 'notify_cust_all', label: 'Notified customers / all staff directly', why: 'KB-0017: no all-staff, and any customer notification is Legal\'s decision and timing - not the responder\'s.', match: [{ tool: 'incident', action: 'notify', target: 'customers' }, { tool: 'incident', action: 'notify', target: 'all_staff' }], skill: 'process', penalty: 0.3 },
    { id: 'dismiss', label: 'Closed it as "encrypted, no risk" without containing or informing Legal', why: 'Even with encryption, you still wipe, rotate the user\'s credentials, and let Legal make the breach call. Encryption is a factor, not a self-issued clearance.', match: { tool: 'ticket', action: 'reply', target: 'r_dismiss' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Stolen CFO laptop (DEN-LT-1002) contained. The device was BitLocker-encrypted at rest (TPM+PIN) and powered off/locked when taken, which is the key breach-risk factor. Actions: issued a remote wipe and marked the asset lost/stolen, revoked the CFO\'s sessions and reset her credentials (and MFA) in case anything cached was reachable. Regulated PII (SSNs, bank details) was on the disk, so I\'ve engaged Legal with the encryption evidence and the police report - Legal makes the breach determination and any notification decision. Because it was encrypted at rest, this most likely falls under safe-harbor and is not a reportable breach, but that is Legal\'s call, not mine. Also briefed the IT Director. No customer, regulator, or all-staff notice from me.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Contained device + identity, captured the encryption evidence, and let Legal own the breach determination.' },
    { id: 'r_dismiss', text: 'BitLocker was on, so there\'s no risk and nothing regulated is exposed - closing as no breach, no action needed.', scores: { communication: 0.3, security: 0.2, process: 0.2 }, feedback: 'Encryption is a factor, not a clearance you issue. You still wipe, rotate credentials, and Legal makes the breach determination.' },
    { id: 'r_overreach', text: 'Assumed the PII is compromised, notified the state regulator and emailed staff that a data breach occurred.', scores: { communication: 0.3, process: 0.1 }, feedback: 'Premature and not yours to send. The disk was encrypted; Legal weighs safe-harbor and owns any regulator/customer notice.' },
  ],
  notesRubric: [
    { label: 'device contained (remote wipe / marked lost-stolen)', pattern: /remote wipe|wipe|lost.?stolen|mark|asset/i },
    { label: 'identity contained (sessions revoked, credentials reset)', pattern: /revoke|reset|password|mfa|session/i },
    { label: 'encryption status captured as the breach-risk factor', pattern: /bitlocker|encrypt|at rest|safe.?harbor|tpm/i },
    { label: 'Legal owns the breach/notification determination', pattern: /legal|determination|breach.*legal|notification|owner|not.*direct/i },
  ],
  closure: {
    disposition: 'escalate', escalateTo: 'legal', severity: 'high', category: 'Device - Lost/Stolen (PII)', resolutionCode: 'Device wiped, identity contained, Legal owns breach determination',
    notifications: ['legal', 'it_director'],
    notificationsForbidden: ['regulator', 'all_staff', 'customers', 'affected_users'],
    reportFields: [
      { label: 'device and data on it (regulated PII)', pattern: /laptop|device|pii|ssn|bank|regulated/i },
      { label: 'encryption status (BitLocker at rest) and why it matters', pattern: /bitlocker|encrypt|at rest|safe.?harbor|tpm/i },
      { label: 'containment (remote wipe, sessions revoked, credentials reset)', pattern: /wipe|revoke|reset|mfa|session/i },
      { label: 'breach determination ownership (Legal)', pattern: /legal|determination|notification|breach|owner/i },
    ],
  },
  categoryAccept: ['device', 'lost', 'stolen', 'pii'],
  resolutionCodeAccept: ['device', 'stolen', 'wipe', 'contain', 'legal'],
  hints: [
    'Contain the device: issue a remote wipe and mark the asset lost/stolen.',
    'Contain the identity: revoke the user\'s sessions, then reset her password and MFA.',
    'Capture the deciding fact: was the disk encrypted at rest? BitLocker was on - that is the biggest breach-risk factor and often triggers safe-harbor.',
    'Engage Legal (with the encryption evidence) and the IT Director. Do NOT notify regulators, customers, or all-staff yourself - the breach determination is Legal\'s.',
  ],
  debrief: 'A lost or stolen device is two incidents in one: a device to contain and an identity to contain. You remote-wipe and mark the asset, and you revoke sessions and reset the user\'s credentials in case anything cached could be reached. But the judgment that makes this a CIRT scenario is the breach determination, and it turns on a single fact - encryption at rest. Under most breach-notification laws, a device that was encrypted (here BitLocker with TPM+PIN, powered off and locked) qualifies for a safe-harbor and usually is not a reportable breach, whereas an unencrypted device holding SSNs almost certainly is. The trap runs both ways: don\'t dismiss it as "encrypted, no risk" and skip containment, and don\'t panic-notify a regulator. The responder\'s job is to contain and to hand Legal the deciding evidence - the encryption status and the police report - and let Legal make and own the notification call.',
};

// ---------------------------------------------------------------------------
// CIRT-08  Third-party / MSP compromise pivoting into our network
// ---------------------------------------------------------------------------
const cirt_08: Scenario = {
  id: 'cirt-08',
  tier: 'cirt',
  title: 'MSP remote-access account compromised into our network',
  category: 'Third-Party - MSP Compromise',
  difficulty: 5,
  estMinutes: 27,
  objective: 'Respond to a supply-chain intrusion through a trusted third party: cut the vendor\'s access, hunt for everything it touched, validate scope before eradicating, rotate the credentials that account could see, and coordinate with the vendor and Legal - without a premature all-staff or external notice.',
  intake: {
    kind: 'incident', number: 'IR-2026-026', title: 'Compromised MSP remote-access account (NorthPeak) reaching our servers',
    declaredBy: 'agrant', summary: 'Our managed service provider NorthPeak\'s shared remote-admin account (svc_msp) logged in from an unusual IP and was used to RDP into DEN-APP01 and DEN-FS01 overnight. NorthPeak confirms their jump host was compromised. The account has Server Admin rights across our estate.',
    severity: 'SEV1', openedAt: ago(30), relatedAlerts: ['ALT-50141'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50141', time: ago(34), severity: 'critical', source: 'siem',
      title: 'MSP account svc_msp lateral movement from anomalous IP',
      description: 'NorthPeak MSP shared account svc_msp authenticated from 185.100.87.202 (not their known jump host) and RDP\'d into DEN-APP01 and DEN-FS01. Vendor confirms their remote-access host was compromised.',
      user: 'svc_msp', host: 'DEN-APP01', indicators: ['svc_msp', '185.100.87.202'], mitre: ['T1199', 'T1078.004', 'T1021.001'], status: 'in progress', truth: 'true_positive',
    });
    // The MSP shared remote-access account (not in the base world).
    w.users.push({
      id: 'svc_msp', displayName: 'NorthPeak MSP (shared remote admin)', title: 'MSP Remote Admin', department: 'Contractors',
      email: 'noc@northpeakmsp.com', phone: '', employeeId: 'MSP001', location: 'External - NorthPeak MSP', enabled: true, lockedOut: false,
      passwordLastSet: daysAgo(300), passwordNeverExpires: true, groups: ['Server Admins', 'IT-Admins'], lastLogon: ago(30), badPwdCount: 0, mfaEnrolled: false, privileged: true,
      notes: 'Shared MSP remote-admin account. Server Admin across the estate. No MFA. Access via NorthPeak jump host only (policy).',
      recentSignIns: [
        { time: ago(33), ip: '185.100.87.202', location: 'Bucharest, RO', app: 'RDP (DEN-APP01)', result: 'success', device: 'unknown', mfa: 'not required' },
        { time: ago(29), ip: '185.100.87.202', location: 'Bucharest, RO', app: 'RDP (DEN-FS01)', result: 'success', device: 'unknown', mfa: 'not required' },
        { time: ago(60 * 30), ip: '203.0.113.77', location: 'Denver, US (NorthPeak jump)', app: 'RDP', result: 'success', device: 'NP-JUMP01', mfa: 'satisfied' },
      ],
    });
    const g = w.groups.find((gr) => gr.name === 'Server Admins');
    if (g) g.members.push('svc_msp');
    // Lateral movement + what it touched.
    addLog(w, { time: ago(33), source: 'auth', host: 'DEN-APP01', user: 'svc_msp', srcIp: '185.100.87.202', action: 'logon', message: '4624 Logon type 10 (RDP) svc_msp from 185.100.87.202 (NOT the NorthPeak jump host)' });
    addLog(w, { time: ago(29), source: 'auth', host: 'DEN-FS01', user: 'svc_msp', srcIp: '185.100.87.202', action: 'logon', message: '4624 Logon type 10 (RDP) svc_msp on DEN-FS01 from 185.100.87.202' });
    addLog(w, { time: ago(27), source: 'edr', host: 'DEN-APP01', user: 'svc_msp', action: 'discovery', message: 'svc_msp ran net group "Server Admins", read C:\\scripts\\creds.txt, and browsed the SQL backup share', process: 'cmd.exe' });
    addLog(w, { time: ago(25), source: 'edr', host: 'DEN-FS01', user: 'svc_msp', action: 'collection', message: 'svc_msp staged a 3.2GB archive from D:\\Shares\\Finance (possible exfil prep) - no successful outbound transfer observed yet', process: 'powershell.exe' });
    w.intel.push({ indicator: '185.100.87.202', type: 'ip', verdict: 'malicious', source: 'threat feed', tags: ['msp-breach', 'ransomware-precursor'], detail: 'Hosting IP tied to an active MSP-targeting intrusion set. Bucharest.' });
    w.chat.push({ id: 'ch-lchen8', with: 'lchen', messages: [] }, { id: 'ch-rsingh8', with: 'rsingh', messages: [] });
  },
  evidence: [
    { id: 'kb18', label: 'Reviewed the IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'lateral', label: 'Confirmed the MSP account logged in from a non-jump-host IP and pivoted to servers', match: [{ tool: 'siem', action: 'search', params: { q: /svc_msp|185\.100\.87\.202|rdp|logon type 10/i } }, { tool: 'directory', action: 'view_signins', target: 'svc_msp' }], hint: 'Compare where svc_msp logged in from against its allowed NorthPeak jump host.' },
    { id: 'touched', label: 'Scoped what the account touched (discovery, creds file, staged Finance data)', match: [{ tool: 'siem', action: 'search', params: { q: /creds\.txt|server admins|staged|archive|finance|discovery/i } }, { tool: 'edr', action: 'view_host', target: 'DEN-APP01' }], hint: 'What did the account read or stage on the servers it reached?' },
    { id: 'account', label: 'Reviewed the MSP account\'s excessive standing rights (Server Admin, no MFA)', match: { tool: 'directory', action: 'view', target: 'svc_msp' }, weight: 0.5 },
  ],
  required: [
    { id: 'disable_msp', label: 'Disabled the compromised MSP account and revoked its sessions', match: [{ tool: 'directory', action: 'disable', target: 'svc_msp' }, { tool: 'directory', action: 'revoke_sessions', target: 'svc_msp' }], skill: 'technical' },
    { id: 'scope', label: 'Hunted/validated scope across the estate before eradicating', match: [{ tool: 'incident', action: 'add_scope', target: /den-app01|den-fs01|svc_msp/i }, { tool: 'siem', action: 'pivot', params: { value: /svc_msp|185\.100\.87\.202/ } }], skill: 'investigation' },
    { id: 'isolate', label: 'Isolated the affected servers', match: [{ tool: 'edr', action: 'isolate', target: 'DEN-APP01' }, { tool: 'edr', action: 'isolate', target: 'DEN-FS01' }], skill: 'technical', after: 'scope' },
    { id: 'rotate', label: 'Rotated the credentials the MSP account could see (service/privileged accounts)', match: [{ tool: 'incident', action: 'reset_service_account', target: 'svc_msp' }, { tool: 'incident', action: 'reset_service_account', target: /svc_backup|svc_scanner/i }], skill: 'security', after: 'scope' },
    { id: 'notify_vendor', label: 'Engaged the vendor (NorthPeak) to coordinate on their end', match: { tool: 'incident', action: 'notify', target: 'vendor' }, skill: 'process' },
    { id: 'notify_leadership', label: 'Notified Legal, the IT Director, and executives', match: [{ tool: 'incident', action: 'notify', target: 'legal' }, { tool: 'incident', action: 'notify', target: 'it_director' }, { tool: 'incident', action: 'notify', target: 'executives' }], skill: 'process' },
  ],
  forbidden: [
    { id: 'eradicate_first', label: 'Reimaged a server before validating scope', why: 'KB-0018: scope before eradication. If you rebuild one server while the account still has access elsewhere or another host is beaconing, you will be back tomorrow - and you lose the evidence of what was taken.', match: [{ tool: 'incident', action: 'reimage', target: 'DEN-APP01' }, { tool: 'incident', action: 'reimage', target: 'DEN-FS01' }], skill: 'security', penalty: 0.4, unlessAfter: 'scope' },
    { id: 'notify_all', label: 'Sent an all-staff notice during active response', why: 'KB-0017: no all-staff before containment - it tips the actor and causes panic. Targeted updates only.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
    { id: 'ext_direct', label: 'Notified a regulator / customers directly', why: 'KB-0017: with possible Finance data staged, any regulator or customer notification is Legal\'s determination and timing, not the analyst\'s.', match: [{ tool: 'incident', action: 'notify', target: 'regulator' }, { tool: 'incident', action: 'notify', target: 'customers' }], skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Supply-chain intrusion via our MSP, contained. NorthPeak\'s shared remote-admin account (svc_msp, Server Admin, no MFA) authenticated from 185.100.87.202 - not their jump host - and RDP\'d into DEN-APP01 and DEN-FS01, where it ran discovery, read a creds file, and staged a 3.2GB archive from the Finance share (exfil prep; no successful outbound transfer seen yet). Actions in order: disabled the MSP account and revoked its sessions, hunted across the estate to validate scope, then isolated the two affected servers and rotated the credentials that account could have seen (its own plus the service/privileged accounts). Engaged NorthPeak to lock down and investigate their compromised jump host, and notified Legal, the IT Director, and executives - Legal owns any regulator/customer decision given the staged Finance data. No all-staff or external notice from me. Root cause: a standing, shared vendor account with Server Admin rights and no MFA, and remote access not pinned to the jump host.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Cut vendor access, scoped before eradicating, rotated exposed credentials, and coordinated with the vendor and Legal.' },
    { id: 'r_fast', text: 'Reimaged DEN-APP01 and DEN-FS01 right away to get clean servers back, then disabled the MSP account.', scores: { communication: 0.3, security: 0.2, process: 0.3 }, feedback: 'Eradicating before scoping loses the evidence of what was taken and misses anywhere else the account reached. Cut access, scope, then rebuild.' },
    { id: 'r_narrow', text: 'Disabled svc_msp and isolated the two servers - that cuts the attacker off, so we\'re done.', scores: { communication: 0.4, security: 0.4, process: 0.4 }, feedback: 'Better, but the account read a creds file and had Server Admin everywhere - you must rotate the credentials it could see and confirm scope across the estate, and Legal needs the staged-Finance-data facts.' },
  ],
  notesRubric: [
    { label: 'attack path (MSP shared account from non-jump IP -> RDP to servers)', pattern: /svc_msp|msp|northpeak|185\.100\.87\.202|jump host|rdp|logon type 10/i },
    { label: 'scope before eradication (hunt across estate, what was touched/staged)', pattern: /scope|hunt|staged|creds|finance|before erad|estate/i },
    { label: 'containment + credential rotation (disable, isolate, rotate exposed creds)', pattern: /disable|revoke|isolat|rotate|service account|credential/i },
    { label: 'vendor coordination + notifications (vendor/Legal/leadership, not all-staff)', pattern: /vendor|northpeak|legal|it director|exec|not all.?staff/i },
  ],
  closure: {
    disposition: 'escalate', escalateTo: 'vendor', severity: 'critical', category: 'Third-Party - MSP Compromise', resolutionCode: 'Vendor access cut; scoped; credentials rotating; vendor/Legal engaged',
    notifications: ['vendor', 'legal', 'executives', 'it_director'],
    notificationsForbidden: ['all_staff', 'regulator', 'customers'],
    reportFields: [
      { label: 'entry via the MSP account and lateral movement', pattern: /msp|svc_msp|jump host|185\.100\.87\.202|rdp|lateral/i },
      { label: 'scope of access (servers reached, creds read, data staged)', pattern: /app01|fs01|creds|staged|finance|scope/i },
      { label: 'containment + eradication (disable, isolate, rotate credentials)', pattern: /disable|revoke|isolat|rotate|credential/i },
      { label: 'root cause / follow-up (no MFA, shared standing vendor access, jump-host pinning)', pattern: /mfa|shared account|standing|least privilege|jump host|lesson|owner|vendor risk/i },
    ],
  },
  categoryAccept: ['third-party', 'msp', 'supply', 'vendor'],
  resolutionCodeAccept: ['msp', 'vendor', 'supply', 'contain', 'rotate'],
  hints: [
    'Cut the vendor\'s access first: disable svc_msp and revoke its sessions - it authenticated from an IP that is not the NorthPeak jump host.',
    'Scope before you eradicate (KB-0018): hunt across the estate for the account and the attacker IP, and see what it touched (it read a creds file and staged Finance data).',
    'Isolate the affected servers, then rotate every credential that Server Admin account could have seen - its own and the service/privileged accounts.',
    'Coordinate with NorthPeak on their compromised jump host, and notify Legal, the IT Director, and executives. No all-staff or direct regulator/customer notice.',
  ],
  debrief: 'A trusted third party is just another way into your network, and a compromised MSP is especially dangerous because vendor accounts tend to be shared, standing, over-privileged, and exempt from MFA - exactly the profile here (svc_msp held Server Admin across the estate with no MFA). The response order matters: cut the vendor\'s access immediately, then hunt to validate scope before eradicating, because rebuilding one server while the account still reaches others - or while a host still beacons - just resets the clock and destroys evidence of what was taken. Since the account read a credentials file and had broad rights, every credential it could have seen is burned and must be rotated. Two coordination duties are unique to supply-chain cases: you work the incident jointly with the vendor (who must lock down their compromised jump host), and because Finance data was staged for exfiltration, Legal owns the regulator and customer decision. The lessons-learned headline is vendor access hygiene: no shared standing accounts, MFA and least privilege for third parties, and remote access pinned to a monitored jump host.',
};

export const CIRT_SCENARIOS_B: Scenario[] = [cirt_04, cirt_05, cirt_06, cirt_07, cirt_08];
