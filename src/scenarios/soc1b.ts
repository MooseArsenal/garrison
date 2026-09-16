import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, addAlert, addMail, setConn } from './helpers';

// ---------------------------------------------------------------------------
// SOC1-05  Password spray / brute force against the VPN + WorkSuite
// ---------------------------------------------------------------------------
const soc1_05: Scenario = {
  id: 'soc1-05',
  tier: 'soc1',
  title: 'Password spray against the VPN / WorkSuite',
  category: 'Identity',
  difficulty: 3,
  estMinutes: 14,
  objective: 'Work an authentication-anomaly alert to ground truth: use the SIEM to see the spread of a spray, look up the source, and determine whether ANY account was actually compromised — then contain proportionally.',
  intake: { kind: 'alert', alertId: 'ALT-50051' },
  priorityExpected: 'P2',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50051', time: ago(22), severity: 'high', source: 'siem',
      title: 'Distributed authentication failures across many users from a single external IP (45.135.232.17)',
      description: 'SIEM correlation fired on 30+ failed sign-ins spread across many accounts from 45.135.232.17 over ~15 minutes against the VPN and WorkSuite — a classic password spray. One authentication ultimately succeeded.',
      indicators: ['45.135.232.17'], mitre: ['T1110.003'], status: 'new', truth: 'true_positive',
    });
    // Ground truth: a low-and-slow spray from a hosting IP. Failures across many users, ONE success (cflores).
    const sprayed = ['bpatel', 'jmorales', 'ewright', 'sturner', 'dkim', 'obennett', 'hsato'];
    let m = 40;
    for (const u of sprayed) {
      addLog(w, { time: ago(m), source: 'auth', user: u, srcIp: '45.135.232.17', action: 'logon_failure', message: `4625 authentication failure user=${u} srcip=45.135.232.17 app=WorkSuite reason=bad password (password spray)`, fields: { eventId: 4625, result: 'failure' } });
      m -= 2;
    }
    // A couple of extra fails then the success on cflores
    addLog(w, { time: ago(24), source: 'vpn', user: 'cflores', srcIp: '45.135.232.17', action: 'auth_failure', message: 'VPN authentication failure user=cflores srcip=45.135.232.17 reason=bad password (password spray)' });
    addLog(w, { time: ago(21), source: 'vpn', user: 'cflores', srcIp: '45.135.232.17', action: 'auth_success', message: 'VPN authentication SUCCESS user=cflores srcip=45.135.232.17 assigned=10.10.99.14 geo=Amsterdam,NL mfa=not required (LEGACY client, MFA bypassed)', fields: { result: 'success' } });
    addLog(w, { time: ago(20), source: 'cloud', user: 'cflores', srcIp: '45.135.232.17', action: 'signin', message: 'WorkSuite sign-in success user=cflores app=Mail geo=Amsterdam,NL device=unknown', fields: { result: 'success' } });
    // cflores sign-ins: normal Phoenix history + the malicious Amsterdam login
    const cf = findUser(w, 'cflores')!;
    cf.recentSignIns = [
      { time: ago(20), ip: '45.135.232.17', location: 'Amsterdam, NL', app: 'WorkSuite Mail', result: 'success', device: 'unknown', mfa: 'not required' },
      { time: ago(21), ip: '45.135.232.17', location: 'Amsterdam, NL', app: 'Kestrel VPN', result: 'success', device: 'unknown', mfa: 'not required' },
      { time: ago(300), ip: '73.14.22.190', location: 'Phoenix, US', app: 'Kestrel VPN', result: 'success', device: 'DEN-LT-1061', mfa: 'satisfied' },
    ];
    w.intel.push({ indicator: '45.135.232.17', type: 'ip', verdict: 'malicious', source: 'Abuse feed + brute-force honeypot', tags: ['brute-force', 'password-spray', 'hosting'], detail: 'Hosting/VPS IP (NL) repeatedly seen conducting credential spraying against O365/VPN endpoints. No legitimate business here.' });
    w.chat.push({ id: 'ch-cf', with: 'cflores', messages: [] });
  },
  contactWith: 'cflores',
  contact: [
    { id: 'travel', question: 'Are you signing in from Amsterdam / did you connect the VPN in the last half hour?', answer: '"Amsterdam? No — I\'m in Phoenix, I haven\'t touched the VPN today."', purpose: 'clarify', reveals: 'not-him' },
    { id: 'reuse', question: 'Is your VPN/WorkSuite password one you have used on other sites?', answer: '"...yeah, probably. It\'s similar to my old personal one."', purpose: 'clarify', reveals: 'weak-reused' },
    { id: 'empid', question: 'Confirm your employee ID before I make changes to your account.', answer: '"E10121."', purpose: 'verify' },
    { id: 'weather', question: 'How hot is it in Phoenix today?', answer: '"110. Can we focus?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the SOC triage standard (KB-0013)', match: { tool: 'kb', action: 'read', target: 'KB-0013' } },
    { id: 'siem', label: 'Pulled the SIEM to see the spread of the spray and the ONE success', match: [{ tool: 'siem', action: 'search', params: { q: /45\.135\.232\.17|authentication failure|password spray|success/i } }, { tool: 'siem', action: 'pivot', params: { value: /45\.135\.232\.17/ } }], hint: 'How many accounts, and did any attempt SUCCEED?' },
    { id: 'intel', label: 'Looked up the source IP (spraying hosting IP)', match: { tool: 'intel', action: 'lookup', target: '45.135.232.17' } },
    { id: 'signins', label: 'Confirmed cflores was compromised via his sign-ins (Amsterdam, unknown device, MFA bypassed)', match: { tool: 'directory', action: 'view_signins', target: 'cflores' }, hint: 'The one success is the whole game. Whose account, and from where?' },
    { id: 'contacted', label: 'Contacted the affected user to confirm it was not him', match: { tool: 'chat', action: 'send', target: 'cflores' } },
  ],
  required: [
    { id: 'revoke', label: 'Revoked the compromised user\'s sessions', match: { tool: 'directory', action: 'revoke_sessions', target: 'cflores' }, skill: 'technical', weight: 1 },
    { id: 'reset', label: 'Reset the compromised user\'s password', match: { tool: 'directory', action: 'reset_password', target: 'cflores' }, skill: 'technical', after: 'revoke', weight: 1 },
    { id: 'block', label: 'Blocked the source IP at the perimeter', match: { tool: 'perimeter', action: 'block', target: '45.135.232.17' }, skill: 'security' },
    { id: 'escalate', label: 'Escalated to CIRT (a spray succeeded — a real account is compromised)', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'noise', label: 'Closed it as noise / false positive because most attempts failed', why: 'A spray that succeeds on even one account is a true positive and a live compromise. Counting the failures and ignoring the single success is exactly the miss attackers rely on.', match: { tool: 'ticket', action: 'reply', target: 'r_noise' }, skill: 'security', penalty: 0.6 },
    { id: 'reset_first', label: 'Reset the password before revoking sessions', why: 'KB-0016: revoke the live sessions first (or together), or the attacker\'s existing token keeps working after the password changes.', match: { tool: 'directory', action: 'reset_password', target: 'cflores' }, unlessAfter: 'revoke', skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed password spray from 45.135.232.17 (a known brute-force hosting IP): ~8 accounts hit with failures, but crucially ONE succeeded — cflores authenticated to the VPN and WorkSuite from Amsterdam on an unknown device with MFA bypassed (legacy client). He confirms he is in Phoenix and never connected. I revoked his sessions, reset his password, and blocked the source IP at the perimeter. Escalating to CIRT because a spray landed a live account compromise. Also flagging the legacy-auth MFA bypass for follow-up.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Read the spread correctly, caught the single success, contained in the right order, and escalated a real compromise.' },
    { id: 'r_noise', text: 'Mostly failed logins from an internet scanner — no accounts locked, treating as spray noise / false positive and closing.', scores: { communication: 0.3, security: 0.1 }, feedback: 'One attempt succeeded. This is a true positive and a live account takeover, not noise.' },
    { id: 'r_lock_only', text: 'Cleared the lockouts on the affected users and reminded them to change passwords. Closing.', scores: { communication: 0.4, security: 0.3, process: 0.3 }, feedback: 'You treated the symptom (lockouts) and missed the disease: cflores is compromised right now. Contain and escalate.' },
  ],
  notesRubric: [
    { label: 'the source and pattern identified (spray from 45.135.232.17)', pattern: /45\.135\.232\.17|password spray|spray|brute/i },
    { label: 'the one successful compromise (cflores from Amsterdam / MFA bypass)', pattern: /cflores|succe|amsterdam|mfa bypass|legacy/i },
    { label: 'containment (revoke, reset, block the IP)', pattern: /revoke|reset|block/i },
    { label: 'escalation to CIRT', pattern: /cirt|escalat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Identity - Password Spray', resolutionCode: 'Contained (revoke/reset/block); escalated to CIRT - spray succeeded' },
  categoryAccept: ['identity', 'password spray', 'spray', 'brute'],
  resolutionCodeAccept: ['contain', 'cirt', 'spray', 'block'],
  hints: [
    'KB-0013 is the triage standard. Start in the SIEM: how wide is the spread and did anything SUCCEED?',
    'Look up 45.135.232.17 — a known brute-force hosting IP.',
    'One attempt succeeded: cflores, from Amsterdam, MFA bypassed via a legacy client. Check his sign-ins and confirm with him.',
    'Contain in order (revoke -> reset), block the IP, and escalate to CIRT because a real account was taken over.',
  ],
  debrief: 'Password sprays generate a wall of failures, and the failure mode is to count them and shrug. The single successful authentication is the entire investigation. Here the spray from a hosting IP landed on cflores because he reused a weak password and a legacy client let the attacker skip MFA. The right move is proportional: contain the one compromised account (revoke then reset), block the source, and escalate the live compromise to CIRT — while flagging the legacy-auth bypass so it cannot happen again.',
};

// ---------------------------------------------------------------------------
// SOC1-06  AV/EDR quarantined a file before it ran — real, but blocked
// ---------------------------------------------------------------------------
const soc1_06: Scenario = {
  id: 'soc1-06',
  tier: 'soc1',
  title: 'EDR quarantined a file — is it real?',
  category: 'Endpoint',
  difficulty: 2,
  estMinutes: 12,
  objective: 'Validate a control-blocked detection: confirm the file was malicious via intel and the EDR record, and classify it correctly — a blocked malicious file is still a true positive, not a false positive.',
  intake: { kind: 'alert', alertId: 'ALT-50061' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50061', time: ago(18), severity: 'medium', source: 'edr',
      title: 'Halberd blocked and quarantined a malicious file on DEN-LT-1070 (jwebb) before execution',
      description: 'Halberd EDR detected and quarantined C:\\Users\\jwebb\\Downloads\\Invoice_Viewer_Setup.exe on write, prevention mode. The file never executed. Verify and classify.',
      host: 'DEN-LT-1070', user: 'jwebb', indicators: ['9f2c4e77aa10bb63d1e0f4c2a8b71d55'], mitre: ['T1204.002'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'DEN-LT-1070');
    h.files.push({ path: 'C:\\Users\\jwebb\\Downloads\\Invoice_Viewer_Setup.exe', size: 1840000, modified: ago(19), signed: false, hash: '9f2c4e77aa10bb63d1e0f4c2a8b71d55', suspicious: true });
    addEvent(h, { id: 1117, time: ago(18), level: 'Warning', source: 'Halberd EDR', log: 'Application', message: 'Threat detected and quarantined: Invoice_Viewer_Setup.exe (Trojan:Win32/Downloader). Action: Quarantine succeeded. No execution observed (blocked on write).' });
    addLog(w, { time: ago(18), source: 'edr', host: 'DEN-LT-1070', user: 'jwebb', action: 'quarantine', message: 'Halberd PREVENTION: quarantined Invoice_Viewer_Setup.exe hash=9f2c4e77aa10bb63d1e0f4c2a8b71d55 on DEN-LT-1070 (no process ever spawned)', process: 'Invoice_Viewer_Setup.exe' });
    // Red herring: a benign download the same day
    h.files.push({ path: 'C:\\Users\\jwebb\\Downloads\\Q3_campaign_brief.pdf', size: 240000, modified: ago(40), signed: true });
    w.intel.push({ indicator: '9f2c4e77aa10bb63d1e0f4c2a8b71d55', type: 'hash', verdict: 'malicious', source: 'Sandbox + multi-AV', tags: ['downloader', 'trojan'], detail: 'Fake "invoice viewer" installer. First-stage downloader. 47/70 AV detections. Would fetch a second-stage payload if run.' });
    w.chat.push({ id: 'ch-jw', with: 'jwebb', messages: [] });
  },
  contactWith: 'jwebb',
  contact: [
    { id: 'origin', question: 'Where did Invoice_Viewer_Setup.exe come from — did you download it?', answer: '"I got an invoice email and it said to install a viewer to open it. I downloaded it but my laptop blocked it before I could run it."', purpose: 'clarify', reveals: 'download' },
    { id: 'ran', question: 'Did the program ever open or run?', answer: '"No, it just disappeared / got blocked. Nothing happened."', purpose: 'clarify', reveals: 'not-run' },
    { id: 'lunch', question: 'What email client do you like better?', answer: '"...Outlook? Why?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the endpoint-malware playbook (KB-0015)', match: { tool: 'kb', action: 'read', target: 'KB-0015' } },
    { id: 'host', label: 'Reviewed the EDR host record / quarantine event (blocked on write, no execution)', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-LT-1070' }, { tool: 'edr', action: 'view_tree', target: 'DEN-LT-1070' }, { tool: 'rdp', action: 'view_files', target: 'DEN-LT-1070' }], hint: 'Did the file ever spawn a process, or was it stopped on write?' },
    { id: 'intel', label: 'Looked up the file hash (malicious downloader)', match: { tool: 'intel', action: 'lookup', target: '9f2c4e77aa10bb63d1e0f4c2a8b71d55' }, hint: 'Confirm the verdict before you classify — do not assume the EDR was wrong.' },
  ],
  required: [
    { id: 'classify', label: 'Classified it correctly (true positive, contained by control) and documented', match: { tool: 'ticket', action: 'submit' }, skill: 'documentation' },
  ],
  forbidden: [
    { id: 'fp', label: 'Closed it as a false positive because it was blocked', why: 'The file is confirmed malicious by intel and multi-AV. Prevention working as designed is a BLOCKED true positive, not a false positive. The distinction drives metrics and tuning.', match: { tool: 'ticket', action: 'reply', target: 'r_fp' }, skill: 'security', penalty: 0.6 },
    { id: 'isolate', label: 'Isolated the host over an already-quarantined file', why: 'The file was blocked on write and never executed. Isolating the user\'s laptop for a control that already did its job is a self-inflicted disruption.', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1070' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Verified: Halberd quarantined Invoice_Viewer_Setup.exe on write on DEN-LT-1070 (jwebb). Threat intel confirms the hash is a malicious first-stage downloader (47/70 AV). The EDR record shows it was blocked before any process spawned — no execution, no follow-on activity. jwebb confirms he downloaded it from a fake invoice email and it never ran. This is a TRUE POSITIVE contained by prevention, severity medium. No isolation or credential reset needed; I coached jwebb on the fake-invoice lure and left a note to watch the sending domain.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Confirmed maliciousness, verified it never executed, and classified it as a blocked true positive — proportionate.' },
    { id: 'r_fp', text: 'Nothing ran and Halberd handled it, so this is a false positive — closing as no threat.', scores: { communication: 0.3, security: 0.1 }, feedback: 'The file was genuinely malicious; the detection was correct. That is a blocked true positive, never a false positive.' },
    { id: 'r_over', text: 'Malware on the endpoint — isolating the host, reimaging, and escalating to CIRT.', scores: { communication: 0.3, security: 0.3, process: 0.2 }, feedback: 'Over-response. The file never executed. Match the action to the evidence: it was blocked on write.' },
  ],
  notesRubric: [
    { label: 'the confirmation (hash malicious per intel/AV)', pattern: /malicious|downloader|intel|47|hash|9f2c4e77/i },
    { label: 'that it was blocked before execution', pattern: /block|quarantin|prevent|never (ran|execut)|no execution|on write/i },
    { label: 'the classification (true positive, contained)', pattern: /true positive|blocked true positive|contained|medium/i },
  ],
  closure: { disposition: 'resolve', classification: 'true_positive', severity: 'medium', category: 'Endpoint - Malware (blocked)', resolutionCode: 'True positive blocked by EDR prevention; no execution' },
  categoryAccept: ['endpoint', 'malware', 'blocked'],
  resolutionCodeAccept: ['blocked', 'prevention', 'true positive', 'quarantin', 'contained'],
  hints: [
    'KB-0015 is the playbook. Do not assume a blocked detection is a false alarm.',
    'Look up the hash: it is a confirmed malicious downloader.',
    'Check the EDR record: it was quarantined on write and never spawned a process.',
    'Classify it a TRUE POSITIVE contained by prevention (medium). Do not call it a false positive and do not isolate.',
  ],
  debrief: 'The most common mislabel in a SOC is calling a blocked malicious file a "false positive" because nothing bad happened. It did happen — a malicious file was written to the endpoint — and the control did its job. That is a blocked true positive. The distinction is not pedantic: false-positive counts drive detection tuning, and inflating them hides real attack attempts and can get good detections tuned out. Confirm the verdict with intel, verify from the EDR record that it never executed, and close it proportionately.',
};

// ---------------------------------------------------------------------------
// SOC1-07  DLP: spreadsheet emailed to a personal account (honest mistake)
// ---------------------------------------------------------------------------
const soc1_07: Scenario = {
  id: 'soc1-07',
  tier: 'soc1',
  title: 'DLP: spreadsheet sent to a personal Gmail',
  category: 'DLP',
  difficulty: 2,
  estMinutes: 12,
  objective: 'Scope and right-size a DLP hit: determine the sensitivity of what left, talk to the user, and distinguish an honest policy violation from an insider case — without over- or under-reacting.',
  intake: { kind: 'alert', alertId: 'ALT-50071' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50071', time: ago(30), severity: 'low', source: 'dlp',
      title: 'DLP: pcole emailed a spreadsheet attachment to a personal (gmail.com) address',
      description: 'DLP rule "Spreadsheet to external personal domain" fired: pcole@kestreldynamics.com sent one .xlsx to patcole1987@gmail.com at 23:41 last night. Scope and classify.',
      user: 'pcole', indicators: ['patcole1987@gmail.com'], mitre: ['T1567'], status: 'new', truth: 'benign_true_positive',
    });
    addMail(w, {
      id: 'MSG-9100', time: ago(600), from: 'pcole@kestreldynamics.com', to: ['patcole1987@gmail.com'],
      subject: 'supplies list to finish at home', status: 'delivered',
      headers: { from: 'pcole@kestreldynamics.com', returnPath: 'pcole@kestreldynamics.com', receivedFrom: 'worksuite-mail.net [internal]', spf: 'pass', dkim: 'pass', dmarc: 'pass', messageId: '<MSG-9100@kestreldynamics.com>' },
      body: 'emailing myself the front desk supply reorder sheet so I can finish it tonight, will import back tomorrow',
      attachments: [{ name: 'front_desk_supplies_reorder.xlsx', type: 'xlsx', verdict: 'clean' }],
    });
    addLog(w, { time: ago(600), source: 'email', user: 'pcole', action: 'send_external', message: 'DLP match rule="Spreadsheet to external personal domain" from=pcole to=patcole1987@gmail.com attach=front_desk_supplies_reorder.xlsx size=22KB markings=none' });
    // Ground truth context: pcole is a receptionist; no access to sensitive shares; the file has no PII/financial markings.
    w.chat.push({ id: 'ch-pc', with: 'pcole', messages: [] });
  },
  contactWith: 'pcole',
  contact: [
    { id: 'why', question: 'Did you email a supplies spreadsheet to your personal Gmail last night, and why?', answer: '"Oh — yes. I was finishing the front-desk supply reorder from home and mailed it to myself so I could work on it. I imported it back this morning. Was that not okay?"', purpose: 'clarify', reveals: 'honest-mistake' },
    { id: 'content', question: 'Does that sheet contain any employee, customer, or financial data?', answer: '"No, it\'s just item names and quantities for reception supplies — pens, paper, coffee."', purpose: 'clarify', reveals: 'non-sensitive' },
    { id: 'more', question: 'Have you sent any other work files to personal accounts recently?', answer: '"No, just that one. I didn\'t realize it was against policy — I\'ll use the VPN next time."', purpose: 'clarify' },
    { id: 'coffee', question: 'What coffee are you reordering?', answer: '"House blend. Is that relevant?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the SOC triage standard (KB-0013)', match: { tool: 'kb', action: 'read', target: 'KB-0013' } },
    { id: 'trace', label: 'Traced the message and reviewed what was sent (one small, unmarked xlsx)', match: [{ tool: 'mail', action: 'trace', params: { q: /pcole|supplies|gmail|patcole/i } }, { tool: 'mail', action: 'view', target: 'MSG-9100' }, { tool: 'mail', action: 'view_headers', target: 'MSG-9100' }], hint: 'What actually left, how big, and does it carry sensitive markings?' },
    { id: 'access', label: 'Checked the user\'s role/access (receptionist, no sensitive shares)', match: [{ tool: 'directory', action: 'view', target: 'pcole' }, { tool: 'siem', action: 'search', params: { q: /pcole|patcole1987|supplies/i } }], weight: 0.5 },
    { id: 'contacted', label: 'Contacted the user and established intent (honest mistake, non-sensitive data)', match: { tool: 'chat', action: 'send', target: 'pcole' } },
  ],
  required: [
    { id: 'coach', label: 'Coached the user on the policy (approved channels, no personal email)', match: { tool: 'chat', action: 'send', target: 'pcole' }, skill: 'communication' },
    { id: 'log', label: 'Logged and closed it as a benign policy violation', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'insider', label: 'Escalated it to CIRT / opened an insider-threat case', why: 'One small, unmarked supply list, sent by a receptionist to her own account to finish after hours, is a policy violation and coaching moment — not an insider incident. Escalating burns CIRT and legal cycles and is disproportionate.', match: [{ tool: 'ticket', action: 'reply', target: 'r_insider' }, { tool: 'incident', action: 'set_phase' }], skill: 'process', penalty: 0.5 },
    { id: 'disable', label: 'Disabled the user\'s account over the DLP hit', why: 'Disabling a receptionist over an honest mistake with non-sensitive data is punitive and disproportionate. Coach and log.', match: { tool: 'directory', action: 'disable', target: 'pcole' }, skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Scoped the DLP hit: pcole mailed one 22KB spreadsheet (front-desk supply reorder, no PII/financial/customer data, no sensitivity markings) to her personal Gmail at 23:41 to finish it from home, and imported it back this morning. She has no access to sensitive shares. This is a genuine policy violation, not data theft — a benign true positive, severity low. I coached her to use the VPN/approved channels instead of personal email, logged the coaching, and closed it. No escalation warranted.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Established intent and sensitivity, classified as a benign policy violation, coached, and closed — proportionate.' },
    { id: 'r_insider', text: 'Data exfiltration to a personal account — opening an insider-threat incident and escalating to CIRT and Legal.', scores: { communication: 0.3, process: 0.1 }, feedback: 'Over-escalation. Non-sensitive data, honest intent, no access to sensitive systems. Coach and log; do not cry insider.' },
    { id: 'r_ignore', text: 'Just noise from the DLP tool — closing with no action.', scores: { communication: 0.3, process: 0.3 }, feedback: 'It IS a real policy violation and the user should be coached and it should be logged. Ignoring it means the behavior repeats.' },
  ],
  notesRubric: [
    { label: 'what left and its sensitivity (one small unmarked supply xlsx)', pattern: /xlsx|spreadsheet|supplies|22|no (pii|sensitive)|unmarked|non-sensitive/i },
    { label: 'the intent established with the user (honest, working from home)', pattern: /honest|mistake|home|finish|intent|imported back/i },
    { label: 'the disposition (benign policy violation, coached and logged)', pattern: /benign|policy violation|coach|logged|low/i },
  ],
  closure: { disposition: 'resolve', classification: 'benign_true_positive', severity: 'low', category: 'DLP - Policy Violation', resolutionCode: 'Benign policy violation - user coached, no data loss' },
  categoryAccept: ['dlp', 'policy violation', 'policy'],
  resolutionCodeAccept: ['policy', 'coach', 'benign', 'no data loss'],
  hints: [
    'KB-0013 defines benign true positive. Scope what actually left before you judge intent.',
    'View the message: one small spreadsheet, no PII or financial data, no sensitivity markings.',
    'Talk to pcole: she mailed a supply list to herself to finish from home. Check her access (receptionist, nothing sensitive).',
    'Coach on approved channels, log it, and close as a benign policy violation (low). Do not open an insider case.',
  ],
  debrief: 'DLP alerts are where proportion is everything. The two failure modes bracket the right answer: cry "insider!" and haul in CIRT and Legal over a supply list, or wave it off as tool noise and let the behavior repeat. The competent move is to scope what actually left (small, unmarked, non-sensitive), establish intent by talking to the person, and match the response — coach and log a benign policy violation. Save the insider machinery for sensitive data, privileged access, or a pattern of concealment, none of which is present here.',
};

// ---------------------------------------------------------------------------
// SOC1-08  Suspicious PowerShell on a sysadmin's box — authorized IT script
// ---------------------------------------------------------------------------
const soc1_08: Scenario = {
  id: 'soc1-08',
  tier: 'soc1',
  title: 'Suspicious PowerShell on an admin\'s box',
  category: 'Endpoint',
  difficulty: 3,
  estMinutes: 13,
  objective: 'Resolve a scary-looking endpoint alert on a privileged user\'s host by reading the process tree and confirming authorization before reacting — the discipline of checking change management before isolating an admin.',
  intake: { kind: 'alert', alertId: 'ALT-50081' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50081', time: ago(16), severity: 'high', source: 'edr',
      title: 'PowerShell with -ExecutionPolicy Bypass running from a scheduled task on DEN-LT-1021 (mreyes, sysadmin)',
      description: 'Halberd flagged powershell.exe -ExecutionPolicy Bypass -File launched by the Task Scheduler on DEN-LT-1021, a Domain Admin\'s laptop. Determine whether this is an attack or authorized administration.',
      host: 'DEN-LT-1021', user: 'mreyes', indicators: ['KD-Maintenance.ps1'], mitre: ['T1059.001', 'T1053.005'], status: 'new', truth: 'benign_true_positive',
    });
    const h = host(w, 'DEN-LT-1021');
    // Process tree: Task Scheduler (svchost) -> powershell running a SIGNED script from a managed Scripts path.
    addProc(h, { pid: 6120, name: 'svchost.exe', user: 'SYSTEM', cpu: 0.2, mem: 40, path: 'C:\\Windows\\System32\\svchost.exe', cmdline: 'svchost.exe -k netsvcs -p -s Schedule', signed: true, started: ago(50) });
    addProc(h, { pid: 6240, name: 'powershell.exe', user: 'KESTREL\\mreyes', cpu: 5, mem: 82, path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmdline: 'powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\KestrelIT\\Scripts\\KD-Maintenance.ps1', parentPid: 6120, signed: true, hash: '4b8e2f00c1', started: ago(16) });
    h.scheduledTasks.push({ name: 'KD-Weekly-Maintenance', path: '\\KestrelIT\\', action: 'powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\KestrelIT\\Scripts\\KD-Maintenance.ps1', trigger: 'Weekly Tue 09:00', author: 'KESTREL\\mreyes' });
    h.files.push({ path: 'C:\\ProgramData\\KestrelIT\\Scripts\\KD-Maintenance.ps1', size: 14000, modified: daysAgo(40), signed: true, hash: '4b8e2f00c1' });
    addLog(w, { time: ago(16), source: 'edr', host: 'DEN-LT-1021', user: 'mreyes', action: 'process_start', message: 'powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\KestrelIT\\Scripts\\KD-Maintenance.ps1 (SIGNED, parent=Task Scheduler) on DEN-LT-1021', process: 'powershell.exe' });
    addLog(w, { time: ago(15), source: 'proxy', host: 'DEN-LT-1021', user: 'mreyes', domain: 'wsus.kestrel.local', dstIp: '10.10.10.6', action: 'allow', dstPort: 8530, message: 'KD-Maintenance.ps1 checked internal WSUS wsus.kestrel.local (internal, expected)' });
    // Red herring: benign DCOM warning
    addEvent(h, { id: 10016, time: ago(120), level: 'Warning', source: 'DistributedCOM', log: 'System', message: 'DCOM 10016 local activation permission (benign, common).' });
    w.intel.push({ indicator: 'KD-Maintenance.ps1', type: 'hash', verdict: 'clean', source: 'Internal script allowlist', tags: ['it-script', 'signed', 'maintenance'], detail: 'Signed Kestrel IT weekly maintenance script (disk cleanup, WSUS check, log rotation). Authored by mreyes, deployed via change management.' });
    w.chat.push({ id: 'ch-mr', with: 'mreyes', messages: [] });
  },
  contactWith: 'mreyes',
  contact: [
    { id: 'script', question: 'Is KD-Maintenance.ps1 running from a scheduled task on your laptop yours / authorized?', answer: '"Yes — that\'s my weekly maintenance script (disk cleanup, WSUS check, log rotation). Runs Tuesday 9am. It\'s signed and it\'s under change CHG-2287."', purpose: 'clarify', reveals: 'authorized' },
    { id: 'chg', question: 'Do you have a change ticket for it?', answer: '"CHG-2287. Aisha reviewed it. Happy to send the script if you want to read it."', purpose: 'verify', reveals: 'change-ticket' },
    { id: 'recent', question: 'Did you modify the script or the task recently?', answer: '"No, it\'s been the same for months."', purpose: 'clarify' },
    { id: 'coffee', question: 'Long week?', answer: '"Always. What\'s up?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the SOC triage standard (KB-0013)', match: { tool: 'kb', action: 'read', target: 'KB-0013' } },
    { id: 'tree', label: 'Read the process tree (Task Scheduler -> signed powershell running a script from ProgramData\\KestrelIT)', match: [{ tool: 'edr', action: 'view_tree', target: 'DEN-LT-1021' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1021' }], hint: 'What launched it? Is the script signed and where does it live?' },
    { id: 'task', label: 'Confirmed the scheduled task authoring / trigger', match: [{ tool: 'rdp', action: 'view_tasks', target: 'DEN-LT-1021' }, { tool: 'terminal', action: 'schtasks', target: 'DEN-LT-1021' }], weight: 0.5 },
    { id: 'intel', label: 'Looked up the script (internal allowlisted IT script)', match: { tool: 'intel', action: 'lookup', target: 'KD-Maintenance.ps1' } },
    { id: 'confirm', label: 'Confirmed authorization with the admin / change ticket', match: { tool: 'chat', action: 'send', target: 'mreyes' } },
  ],
  required: [
    { id: 'classify', label: 'Documented the authorization (change ticket) and closed as benign true positive', match: { tool: 'ticket', action: 'submit' }, skill: 'documentation' },
  ],
  forbidden: [
    { id: 'isolate', label: 'Isolated the sysadmin\'s host before checking authorization', why: 'KB-0013: reach ground truth first. Isolating a Domain Admin\'s laptop over an authorized, signed maintenance script cuts off IT and is a self-inflicted outage.', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1021' }, skill: 'security', penalty: 0.5 },
    { id: 'escalate_compromise', label: 'Escalated to CIRT as a Domain Admin compromise', why: 'The activity is signed, task-scheduled, allowlisted, and confirmed by the admin under a change ticket. Declaring a DA compromise cries wolf and burns CIRT.', match: { tool: 'ticket', action: 'reply', target: 'r_cirt' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Triaged the PowerShell alert on DEN-LT-1021 (mreyes). The process tree shows Task Scheduler launching a SIGNED powershell script, KD-Maintenance.ps1, from C:\\ProgramData\\KestrelIT\\Scripts — not a user-writable path — that only touched the internal WSUS server. Threat intel has the script allowlisted, and mreyes confirms it is his weekly maintenance task under change CHG-2287 (reviewed by Aisha). Benign true positive, severity low. No containment; adding a tuning note so the signed script from that path/task stops paging us. -ExecutionPolicy Bypass is normal for IT automation.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Read the tree, confirmed the signature and the change ticket, and tuned the noise instead of isolating an admin.' },
    { id: 'r_cirt', text: 'PowerShell with ExecutionPolicy Bypass on a Domain Admin\'s box — isolating and escalating to CIRT as a DA compromise.', scores: { communication: 0.3, security: 0.2, process: 0.1 }, feedback: 'You skipped the authorization check. Signed script, managed path, scheduled task, confirmed by the admin under a change ticket. This is sanctioned IT work.' },
    { id: 'r_fp', text: 'False positive, PowerShell is normal — closing.', scores: { communication: 0.4, process: 0.4 }, feedback: 'The detection fired correctly on real behavior; it is authorized, so it is a benign true positive, not a false positive. That distinction drives tuning.' },
  ],
  notesRubric: [
    { label: 'the process tree / signed script from a managed path', pattern: /kd-maintenance|signed|programdata|kestrelit|task schedul|scheduled task/i },
    { label: 'the authorization (change ticket / admin confirmation)', pattern: /chg-2287|change|authoriz|mreyes|allowlist|approved/i },
    { label: 'the classification (benign true positive, tune)', pattern: /benign|true positive|tune|suppress|expected/i },
  ],
  closure: { disposition: 'resolve', classification: 'benign_true_positive', severity: 'low', category: 'Triage - Authorized Admin Activity', resolutionCode: 'Benign true positive - authorized IT maintenance script' },
  categoryAccept: ['triage', 'authorized', 'admin'],
  resolutionCodeAccept: ['benign', 'authorized', 'admin', 'true positive', 'script'],
  hints: [
    'KB-0013: reach ground truth before you contain, especially on a privileged user\'s host.',
    'Read the process tree: Task Scheduler launched a SIGNED script from C:\\ProgramData\\KestrelIT\\Scripts, and it only hit the internal WSUS.',
    'The script is allowlisted in intel; confirm with mreyes and get his change ticket (CHG-2287).',
    'Close as benign true positive (low), add a tuning note. Do NOT isolate the admin\'s host or escalate a compromise.',
  ],
  debrief: 'Legitimate administration and attacks share a lot of surface: PowerShell, ExecutionPolicy Bypass, scheduled tasks. The tells that separate them are the signature, the path (a managed ProgramData\\KestrelIT location, not user-writable AppData/Temp), what it talked to (internal WSUS, not a C2), and — decisively — authorization confirmed with the admin and a change ticket. On a Domain Admin\'s host the temptation to isolate first is strongest and the cost of doing it wrong is highest. Verify authorization, then tune the detection so signed, scheduled admin scripts do not keep paging the SOC.',
};

// ---------------------------------------------------------------------------
// SOC1-09  IDS: outbound to a known-bad IP — but the proxy blocked it
// ---------------------------------------------------------------------------
const soc1_09: Scenario = {
  id: 'soc1-09',
  tier: 'soc1',
  title: 'Outbound to a known-bad IP — did the block hold?',
  category: 'Network',
  difficulty: 3,
  estMinutes: 13,
  objective: 'Triage an attempted C2 connection that a control blocked: confirm the block held, identify the process that tried, contain the indicator more broadly, and classify an attempted-but-contained true positive.',
  intake: { kind: 'alert', alertId: 'ALT-50091' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50091', time: ago(17), severity: 'medium', source: 'ids',
      title: 'Repeated outbound attempts from DEN-LT-1041 (jmorales) to a known-bad IP 194.26.135.60 — proxy DENIED',
      description: 'IDS/proxy logged an unknown binary on DEN-LT-1041 repeatedly trying to reach 194.26.135.60:443. The proxy denied every attempt. Confirm the block held and find what is trying to beacon.',
      host: 'DEN-LT-1041', user: 'jmorales', indicators: ['194.26.135.60', 'ms-edge-sync.exe'], mitre: ['T1071.001'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'DEN-LT-1041');
    // The process that tried: an unsigned binary from AppData, denied by the proxy every time.
    addProc(h, { pid: 7220, name: 'ms-edge-sync.exe', user: 'KESTREL\\jmorales', cpu: 2, mem: 48, path: 'C:\\Users\\jmorales\\AppData\\Roaming\\ms-edge-sync.exe', cmdline: 'ms-edge-sync.exe', signed: false, hash: 'd41c9be7', started: ago(30) });
    h.files.push({ path: 'C:\\Users\\jmorales\\AppData\\Roaming\\ms-edge-sync.exe', size: 120000, modified: ago(31), signed: false, hash: 'd41c9be7', suspicious: true });
    setConn(h, [{ proto: 'TCP', local: `${h.ip}:51888`, remote: '194.26.135.60:443', state: 'SYN_SENT', pid: 7220 }]);
    // Several proxy DENY logs — the block held every time.
    for (let i = 0; i < 5; i++) {
      addLog(w, { time: ago(17 - i * 2), source: 'proxy', host: 'DEN-LT-1041', user: 'jmorales', dstIp: '194.26.135.60', url: 'https://194.26.135.60/api/v1/beacon', action: 'deny', dstPort: 443, process: 'ms-edge-sync.exe', message: 'DENY https://194.26.135.60/api/v1/beacon reason=threat-intel-blocklist process=ms-edge-sync.exe (attempt blocked)' });
    }
    addLog(w, { time: ago(18), source: 'edr', host: 'DEN-LT-1041', user: 'jmorales', action: 'process_start', message: 'Unsigned ms-edge-sync.exe started from AppData\\Roaming on DEN-LT-1041', process: 'ms-edge-sync.exe' });
    w.intel.push({ indicator: '194.26.135.60', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['c2', 'malware'], detail: 'Known malware command-and-control endpoint. Beacon over 443. Blocked at the proxy by intel feed.' });
    w.intel.push({ indicator: 'd41c9be7', type: 'hash', verdict: 'malicious', source: 'Sandbox', tags: ['loader', 'beacon'], detail: 'Masquerades as "ms-edge-sync.exe". Loader that beacons to C2; no valid Microsoft signature.' });
    w.chat.push({ id: 'ch-jm2', with: 'jmorales', messages: [] });
  },
  contactWith: 'jmorales',
  contact: [
    { id: 'install', question: 'Did you install anything called "Edge Sync" or run an unusual download recently?', answer: '"I clicked something in a browser popup a couple days ago that said my Edge needed updating. Nothing seemed to happen."', purpose: 'clarify', reveals: 'drive-by' },
    { id: 'symptoms', question: 'Is the laptop behaving oddly — slow, pop-ups, redirects?', answer: '"A little slow, but I figured it was Tuesday."', purpose: 'clarify' },
    { id: 'lunch', question: 'Where do you like to get lunch?', answer: '"The taco place. Why?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the endpoint-malware playbook (KB-0015)', match: { tool: 'kb', action: 'read', target: 'KB-0015' } },
    { id: 'siem', label: 'Confirmed in the SIEM that every attempt was DENIED (block held)', match: [{ tool: 'siem', action: 'search', params: { q: /194\.26\.135\.60|deny|ms-edge-sync|beacon/i } }, { tool: 'siem', action: 'pivot', params: { value: /194\.26\.135\.60/ } }], hint: 'Was the connection allowed or denied? Did anything ever succeed?' },
    { id: 'intel', label: 'Looked up the destination IP (known C2)', match: { tool: 'intel', action: 'lookup', target: '194.26.135.60' } },
    { id: 'host', label: 'Checked the host and found the unsigned AppData binary that tried to beacon', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-LT-1041' }, { tool: 'edr', action: 'view_tree', target: 'DEN-LT-1041' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1041' }], hint: 'What process is generating the outbound attempts? Where does it run from?' },
    { id: 'hash', label: 'Looked up the binary hash (malicious loader)', match: { tool: 'intel', action: 'lookup', target: 'd41c9be7' }, weight: 0.5 },
  ],
  required: [
    { id: 'block', label: 'Blocked the C2 IP more broadly at the perimeter', match: { tool: 'perimeter', action: 'block', target: '194.26.135.60' }, skill: 'security' },
    { id: 'contain_host', label: 'Contained the offending binary on the host (quarantine/kill) or isolated the single workstation', match: [{ tool: 'edr', action: 'quarantine_file', target: 'DEN-LT-1041' }, { tool: 'edr', action: 'kill_process', target: 'DEN-LT-1041' }, { tool: 'edr', action: 'isolate', target: 'DEN-LT-1041' }], skill: 'technical' },
    { id: 'submit', label: 'Classified attempted-but-contained and ticketed host review', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'fp', label: 'Closed as a false positive because the proxy blocked it', why: 'There is real malware on the host actively trying to reach a known C2; the proxy stopped the egress but the compromise attempt is real. Blocked C2 is an attempted true positive, not a false positive.', match: { tool: 'ticket', action: 'reply', target: 'r_fp' }, skill: 'security', penalty: 0.5 },
    { id: 'incident', label: 'Declared a full-scale incident / escalated to CIRT for a single blocked host', why: 'The egress was blocked, it is one non-privileged workstation, and there is no evidence of successful C2 or lateral movement. Contain the host and indicator; do not spin up CIRT for a contained single-host attempt.', match: { tool: 'ticket', action: 'reply', target: 'r_incident' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed: an unsigned loader posing as ms-edge-sync.exe (from jmorales\'s AppData\\Roaming, likely a browser-popup drive-by) is repeatedly trying to beacon to 194.26.135.60, a known C2. The SIEM shows the proxy DENIED every attempt — no successful egress, connection stuck at SYN_SENT. Both the IP and the binary hash are malicious in intel. I blocked the C2 IP at the perimeter, quarantined the binary and isolated the single workstation, and ticketed Desktop to clean/reimage. True positive, attempted C2 contained by controls, severity medium. One non-privileged host, no lateral movement — no CIRT.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Confirmed the block held, found and contained the offending binary, blocked the indicator broadly, and classified proportionately.' },
    { id: 'r_fp', text: 'The proxy blocked it, so nothing got out — false positive, closing.', scores: { communication: 0.3, security: 0.1 }, feedback: 'A control blocking real malware is not a false positive. There is an active loader on the host trying to reach C2 — that is an attempted true positive to be contained.' },
    { id: 'r_incident', text: 'C2 traffic detected — declaring a major incident and escalating to CIRT immediately.', scores: { communication: 0.4, process: 0.3, security: 0.4 }, feedback: 'Over-response. The egress was blocked, it is one non-privileged workstation, no successful C2 or spread. Contain the host and indicator at SOC I.' },
  ],
  notesRubric: [
    { label: 'the attempt and that the block held (proxy denied every beacon)', pattern: /194\.26\.135\.60|deny|denied|block held|no egress|syn_sent/i },
    { label: 'the offending binary (unsigned AppData loader)', pattern: /ms-edge-sync|appdata|unsigned|loader|d41c9be7/i },
    { label: 'containment (perimeter block + host quarantine/isolate)', pattern: /block|perimeter|quarantin|kill|isolat/i },
    { label: 'the classification (attempted true positive, contained, medium)', pattern: /true positive|attempt|contained|medium/i },
  ],
  closure: { disposition: 'resolve', classification: 'true_positive', severity: 'medium', category: 'Network - Blocked C2 Attempt', resolutionCode: 'Attempted C2 blocked by proxy; IP blocked at perimeter, host contained + ticketed' },
  categoryAccept: ['network', 'blocked c2', 'c2'],
  resolutionCodeAccept: ['block', 'c2', 'contained', 'attempt', 'perimeter'],
  hints: [
    'KB-0015 is the playbook. First question in the SIEM: was the connection allowed or DENIED?',
    'Every proxy attempt to 194.26.135.60 was denied — the block held, no egress succeeded.',
    'Find the process on the host: an unsigned ms-edge-sync.exe in AppData\\Roaming (both IP and hash are malicious).',
    'Block the IP at the perimeter, contain the binary/host, ticket a review. Classify attempted-but-contained (medium). Not a false positive, not a CIRT incident.',
  ],
  debrief: 'A control catching an attack is a success, not a non-event. The proxy denied every beacon to a known C2, but a real malicious loader is sitting in AppData actively trying to phone home — that is an attempted true positive contained by a control. The two wrong calls are symmetric: "false positive" because nothing got out (there is real malware on the box), or "major incident, call CIRT" (it is one non-privileged host with no successful egress or spread). The right answer is to widen the block to the perimeter, contain the offending binary/host at SOC I authority, and ticket a cleanup — while noting the drive-by delivery for awareness.',
};

// ---------------------------------------------------------------------------
// SOC1-10  Phishing email with a malicious attachment (sandbox detonated it)
// ---------------------------------------------------------------------------
const soc1_10: Scenario = {
  id: 'soc1-10',
  tier: 'soc1',
  title: 'Malicious attachment — scope, purge, block',
  category: 'Email',
  difficulty: 3,
  estMinutes: 15,
  objective: 'Run the phishing playbook for an attachment-based campaign: confirm via headers and sandbox/intel, scope every recipient, check who opened it, purge, and block the sender — then classify.',
  intake: { kind: 'alert', alertId: 'ALT-50101' },
  priorityExpected: 'P2',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50101', time: ago(28), severity: 'high', source: 'email',
      title: 'Sandbox detonated a malicious macro attachment (Invoice_4471.xlsm) delivered to multiple users',
      description: 'The mail sandbox flagged Invoice_4471.xlsm as malicious (macro dropper) AFTER delivery to Junk. SPF/DKIM/DMARC all fail. Scope the campaign, check who opened it, purge, and block.',
      indicators: ['3b1f9d2e77c04a5581aa2f6e0d9c4471', 'billing@acme-invoicing.co', '91.219.236.18'], mitre: ['T1566.001', 'T1204.002'], status: 'new', truth: 'true_positive',
    });
    const mkMsg = (id: string, to: string, opened = false) => {
      addMail(w, {
        id, time: ago(75), from: 'ACME Billing <billing@acme-invoicing.co>', to: [`${to}@kestreldynamics.com`],
        subject: 'Overdue Invoice #4471 - payment required',
        status: 'delivered (junk)' as const, reason: 'DMARC fail; delivered to Junk',
        headers: { from: 'ACME Billing <billing@acme-invoicing.co>', returnPath: 'bounce@acme-invoicing.co', replyTo: 'billing@acme-invoicing.co', receivedFrom: 'mail.acme-invoicing.co [91.219.236.18]', spf: 'fail' as const, dkim: 'fail' as const, dmarc: 'fail' as const, messageId: `<${id}@acme-invoicing.co>` },
        body: 'Please see the attached overdue invoice. Enable content to view the secured document and remit payment immediately.',
        attachments: [{ name: 'Invoice_4471.xlsm', type: 'xlsm', hash: '3b1f9d2e77c04a5581aa2f6e0d9c4471', verdict: 'malicious' }],
        phishing: true, clicked: opened ? [to] : [],
      });
    };
    mkMsg('MSG-9200', 'nfoster');
    mkMsg('MSG-9201', 'obennett', true); // obennett opened the attachment
    mkMsg('MSG-9202', 'dkim');
    // obennett opened it but Defender blocked the macro payload on his endpoint (no execution / no C2).
    addLog(w, { time: ago(60), source: 'edr', host: 'DEN-WS-2011', user: 'obennett', action: 'block', message: 'Defender blocked macro child process from EXCEL.EXE (Invoice_4471.xlsm) on DEN-WS-2011 - attachment opened but payload prevented', process: 'EXCEL.EXE' });
    const ob = findUser(w, 'obennett')!;
    ob.recentSignIns = [{ time: ago(30), ip: '10.10.21.11', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-WS-2011', mfa: 'satisfied' }];
    w.intel.push({ indicator: '3b1f9d2e77c04a5581aa2f6e0d9c4471', type: 'hash', verdict: 'malicious', source: 'Mail sandbox + multi-AV', tags: ['macro', 'dropper', 'qakbot'], detail: 'Malicious Excel macro dropper (Invoice_4471.xlsm). Detonation dropped a loader that beacons; 52/70 AV.' });
    w.intel.push({ indicator: 'acme-invoicing.co', type: 'domain', verdict: 'malicious', source: 'Feeds + WHOIS', tags: ['phishing', 'invoice-fraud'], detail: 'Lookalike invoicing domain registered 8 days ago. Used for malicious-attachment campaigns.' });
    w.intel.push({ indicator: '91.219.236.18', type: 'ip', verdict: 'malicious', source: 'Abuse feed', tags: ['phishing', 'sender'], detail: 'Sending host for invoice-themed malspam.' });
    w.chat.push({ id: 'ch-ob', with: 'obennett', messages: [] });
  },
  contactWith: 'obennett',
  contact: [
    { id: 'opened', question: 'Did you open the attachment on the "Overdue Invoice #4471" email, and did you enable content/macros?', answer: '"I opened the spreadsheet but it popped a warning and then said it was blocked. I didn\'t enable anything after that."', purpose: 'clarify', reveals: 'opened-blocked' },
    { id: 'creds', question: 'Did you type your password anywhere or approve anything after opening it?', answer: '"No, nothing like that."', purpose: 'clarify' },
    { id: 'empid', question: 'Confirm your employee ID.', answer: '"E10141."', purpose: 'verify' },
    { id: 'weather', question: 'Busy morning?', answer: '"Kind of. What\'s going on?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the phishing playbook (KB-0014)', match: { tool: 'kb', action: 'read', target: 'KB-0014' } },
    { id: 'headers', label: 'Analyzed the headers (SPF/DKIM/DMARC fail, lookalike sender domain)', match: { tool: 'mail', action: 'view_headers', target: /MSG-920/ }, hint: 'Confirm it is malicious from the headers and the sandbox verdict.' },
    { id: 'intel', label: 'Looked up the attachment hash and sender domain/IP', match: { tool: 'intel', action: 'lookup', target: /3b1f9d2e|acme-invoicing|91\.219\.236\.18/ } },
    { id: 'trace', label: 'Traced the campaign to find every recipient', match: { tool: 'mail', action: 'trace', params: { q: /acme-invoicing|invoice|4471/i } }, hint: 'How many got it? Trace by sender/subject.' },
    { id: 'whoopened', label: 'Identified that obennett opened it and checked his endpoint/sign-ins (payload blocked, clean)', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-WS-2011' }, { tool: 'directory', action: 'view_signins', target: 'obennett' }, { tool: 'chat', action: 'send', target: 'obennett' }], hint: 'Who opened the attachment? Check that host for execution/C2.' },
  ],
  required: [
    { id: 'purge', label: 'Purged the message for all recipients', match: { tool: 'mail', action: 'purge_all', target: /MSG-920/ }, skill: 'technical' },
    { id: 'block', label: 'Blocked the sender domain / IP at the gateway', match: [{ tool: 'perimeter', action: 'block', target: /acme-invoicing|91\.219\.236\.18/ }, { tool: 'mail', action: 'block_sender', target: /acme-invoicing/ }], skill: 'technical' },
    { id: 'submit', label: 'Classified and closed (true positive, contained)', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'fp', label: 'Classified it a false positive because it landed in Junk / was blocked', why: 'The attachment is a confirmed malicious macro dropper delivered to real mailboxes. A malicious email that reaches inboxes is a true positive regardless of the folder or whether the endpoint blocked the payload.', match: { tool: 'ticket', action: 'reply', target: 'r_fp' }, skill: 'security', penalty: 0.5 },
    { id: 'skip_scope', label: 'Closed without scoping who opened it', why: 'KB-0014: you must check who interacted. One user (obennett) opened the attachment — you have to verify his endpoint and account before closing.', match: { tool: 'ticket', action: 'reply', target: 'r_quick' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed malicious-attachment campaign: "Overdue Invoice #4471" from a lookalike domain (acme-invoicing.co), SPF/DKIM/DMARC all fail, carrying Invoice_4471.xlsm — a macro dropper the sandbox and 52/70 AV flag as malicious. Scope: three mailboxes (nfoster, obennett, dkim), all delivered to Junk. I purged all three copies and blocked the sender domain and IP at the gateway/proxy. One user, obennett, opened the attachment, but Defender blocked the macro payload on his endpoint (no execution, no C2) and his sign-ins are clean, so no account action beyond a heads-up. Classifying True Positive, severity medium — contained, no execution or credential loss.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Full scope, purge, block, correct read on the opened-but-blocked endpoint, and an accurate classification.' },
    { id: 'r_fp', text: 'It went to Junk and the endpoint blocked it — false positive, closing.', scores: { communication: 0.3, security: 0.1 }, feedback: 'A confirmed malicious attachment that reached mailboxes is a true positive, whatever folder it landed in.' },
    { id: 'r_quick', text: 'Purged the emails and blocked the sender — done.', scores: { communication: 0.5, technical: 0.6, process: 0.3 }, feedback: 'You skipped the interaction check. One recipient opened the attachment; you must verify his endpoint and account before closing.' },
  ],
  notesRubric: [
    { label: 'the confirmation (headers fail + sandbox/intel malicious)', pattern: /spf|dkim|dmarc|sandbox|macro|dropper|malicious|acme-invoicing|3b1f9d2e/i },
    { label: 'the scope (all recipients found and purged)', pattern: /3 |three|nfoster|obennett|dkim|recipients|purge/i },
    { label: 'who opened it and the endpoint check (obennett, payload blocked, clean)', pattern: /obennett|opened|defender block|no execution|clean sign-?in|no cred/i },
    { label: 'the block and classification (true positive, contained)', pattern: /block|gateway|proxy|true positive|contained|medium/i },
  ],
  closure: { disposition: 'resolve', classification: 'true_positive', severity: 'medium', category: 'Email - Malicious Attachment', resolutionCode: 'Purged + blocked; attachment opened once but payload blocked, no compromise' },
  categoryAccept: ['email', 'malicious attachment', 'attachment', 'phishing'],
  resolutionCodeAccept: ['purge', 'block', 'attachment', 'contained', 'true positive'],
  hints: [
    'KB-0014 is the step list. Confirm malicious via headers and the sandbox/intel verdict first.',
    'Trace the campaign by sender/subject to get all recipients — there are three.',
    'One recipient (obennett) opened the attachment. Check his endpoint: Defender blocked the macro payload and his sign-ins are clean.',
    'Purge all copies, block the sender domain and IP, classify True Positive (medium — contained, no execution).',
  ],
  debrief: 'Attachment phishing follows the same playbook as link phishing — confirm, scope, purge, check interactions, block, classify — but the interaction check moves to the endpoint. Here the sandbox verdict plus failed authentication and a lookalike domain confirm the dropper; the campaign reached three Junk folders; and the one user who opened it was saved by Defender blocking the macro child process. Because a genuinely malicious attachment reached real mailboxes, it is a true positive no matter where it landed. The calibration is in the proportion: purge and block for everyone, verify the single opener\'s endpoint and account, and resolve at medium since nothing executed.',
};

export const SOC1_SCENARIOS_B: Scenario[] = [soc1_05, soc1_06, soc1_07, soc1_08, soc1_09, soc1_10];
