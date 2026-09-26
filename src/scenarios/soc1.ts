import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, addAlert, addMail, setConn } from './helpers';
import { randIp, randHash, randDomain } from '../engine/instantiate';

// ---------------------------------------------------------------------------
// SOC1-01  EDR alert that is an authorized vuln scan (benign true positive)
// ---------------------------------------------------------------------------
const soc1_01: Scenario = {
  id: 'soc1-01',
  tier: 'soc1',
  title: 'EDR: suspicious scanning from an internal host',
  category: 'Triage',
  difficulty: 2,
  estMinutes: 12,
  objective: 'Triage a noisy alert to ground truth: correlate the source, check the change calendar/intel, and classify a benign true positive without wasting a containment action.',
  intake: { kind: 'alert', alertId: 'ALT-50011' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50011', time: ago(35), severity: 'high', source: 'ids',
      title: 'Internal host performing port scan / vulnerability probes across multiple subnets',
      description: 'IDS flagged 10.10.10.70 sending SYN scans and CVE probes to 10.10.20.0/24, 10.10.21.0/24 and the server VLAN over ~20 minutes.',
      host: 'DEN-DC01', indicators: ['10.10.10.70'], mitre: ['T1046'], status: 'new', truth: 'benign_true_positive',
    });
    // Ground truth: 10.10.10.70 is the authorized scanner (svc_scanner), running the weekly scan.
    addLog(w, { time: ago(38), source: 'edr', host: 'DEN-DC01', user: 'svc_scanner', action: 'info', message: 'Authenticated scan initiated from 10.10.10.70 (nessusd) against corp subnets - weekly authorized scan window', process: 'nessusd' });
    addLog(w, { time: ago(36), source: 'ids', srcIp: '10.10.10.70', action: 'alert', message: 'Port scan signature: 10.10.10.70 -> 10.10.20.0/24 SYN sweep (1024 ports)' });
    addLog(w, { time: ago(34), source: 'auth', user: 'svc_scanner', srcIp: '10.10.10.70', action: 'logon', message: '4624 Logon type 3 svc_scanner from 10.10.10.70 to DEN-FS01, DEN-APP01 (credentialed scan)' });
    // A prior week's identical benign event exists in intel/history
  },
  contact: [
    { id: 'sec_team', question: 'Ping the Security Team channel: is anyone running a scan from 10.10.10.70?', answer: 'Aisha Grant replies: "Yep — that\'s the weekly Nessus scan from the scanner appliance (svc_scanner). Runs Sunday and I kicked an ad-hoc one this morning. Change ticket CHG-2291."', purpose: 'clarify', reveals: 'authorized' },
    { id: 'user_check', question: 'Message the "user" behind svc_scanner directly', answer: 'svc_scanner is a service account; there\'s no human to message. Confirm authorization via the change ticket / Security team instead.', purpose: 'irrelevant' },
  ],
  contactWith: 'agrant',
  evidence: [
    { id: 'kb', label: 'Read the SOC triage standard (KB-0013)', match: { tool: 'kb', action: 'read', target: 'KB-0013' } },
    { id: 'intel', label: 'Looked up the source IP in Threat Intel (internal scanner, authorized)', match: { tool: 'intel', action: 'lookup', target: '10.10.10.70' }, hint: 'Every external and internal indicator gets a reputation/asset lookup.' },
    { id: 'siem', label: 'Pulled the SIEM around the alert and identified nessusd / svc_scanner', match: [{ tool: 'siem', action: 'search', params: { q: /10\.10\.10\.70|scanner|nessus|svc_scanner/i } }, { tool: 'siem', action: 'pivot', params: { value: /10\.10\.10\.70/ } }], hint: 'What process and account is behind the scan traffic?' },
    { id: 'confirm', label: 'Confirmed authorization with the Security team / change ticket', match: { tool: 'chat', action: 'send', target: 'agrant' }, weight: 1 },
  ],
  required: [
    { id: 'classify_note', label: 'Documented WHO authorized it (change ticket) and closed as benign true positive', match: { tool: 'ticket', action: 'submit' }, skill: 'documentation' },
  ],
  forbidden: [
    { id: 'isolate_dc', label: 'Isolated / disabled the domain controller or scanner', why: 'KB-0013: SOC I may isolate a single workstation, not servers or a DC. Isolating a DC over an authorized scan is a self-inflicted outage.', match: [{ tool: 'edr', action: 'isolate', target: 'DEN-DC01' }, { tool: 'directory', action: 'disable', target: 'svc_scanner' }], skill: 'security', penalty: 0.6 },
    { id: 'escalate_cirt', label: 'Escalated to CIRT as an active attack', why: 'This is authorized activity; declaring an incident cries wolf and burns CIRT capacity.', match: { tool: 'ticket', action: 'reply', target: 'r_cirt' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Triaged: the "scan" originates from 10.10.10.70, our Nessus vulnerability-scanner appliance (svc_scanner), running a credentialed scan under change CHG-2291 and confirmed by Aisha on the Security team. This is expected, authorized activity — a benign true positive. No containment needed. I\'m adding a suppression/tuning note so the IDS scan signature from the scanner\'s IP during the scan window doesn\'t re-page us.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Ground-truth confirmed, correctly classified, and reduces future noise via tuning.' },
    { id: 'r_cirt', text: 'Active internal reconnaissance across multiple subnets — declaring an incident and escalating to CIRT.', scores: { communication: 0.3, process: 0.1, security: 0.2 }, feedback: 'Confident but wrong: you skipped the authorization check. This is the sanctioned scanner.' },
    { id: 'r_fp', text: 'False positive — nothing really happened, closing.', scores: { communication: 0.4, process: 0.4 }, feedback: 'The scan DID happen and the detection fired correctly; it\'s a benign true positive, not a false positive. The distinction matters for tuning and metrics.' },
  ],
  notesRubric: [
    { label: 'the source identified (scanner appliance / svc_scanner)', pattern: /10\.10\.10\.70|scanner|nessus|svc_scanner/i },
    { label: 'the authorization evidence (change ticket / Security confirmation)', pattern: /chg-2291|change|authoriz|aisha|security team|approved/i },
    { label: 'the classification and reasoning (benign true positive, tune)', pattern: /benign|true positive|tune|suppress|expected/i },
  ],
  closure: { disposition: 'resolve', classification: 'benign_true_positive', severity: 'low', category: 'Triage - Authorized Scan', resolutionCode: 'Benign true positive - authorized vuln scan' },
  categoryAccept: ['triage', 'scan', 'benign'],
  resolutionCodeAccept: ['benign', 'authorized', 'scan', 'true positive'],
  hints: [
    'KB-0013 defines the three closures. Note the difference between false positive and benign true positive.',
    'Look up 10.10.10.70 in Threat Intel — it is a known internal asset.',
    'Pivot in the SIEM: the traffic is nessusd running as svc_scanner. Confirm with the Security team.',
    'Classify benign true positive (severity low), document the change ticket, and add a tuning note. Do NOT isolate a DC.',
  ],
  debrief: 'The most common SOC I reality is noise, and the skill is reaching ground truth fast without overreacting. The alert is real behavior (a port/vuln scan) but authorized — a benign true positive, distinct from a false positive (which means the detection misfired). Getting that distinction right feeds accurate tuning and metrics. The two failure modes are the dramatic one (isolate/disable, escalate to CIRT) and the lazy one (call it a false positive and move on). Both skip the one action that resolves it: confirm who authorized it.',
};

// ---------------------------------------------------------------------------
// SOC1-02  Impossible travel that is really a benign VPN (careful sign-in review)
// ---------------------------------------------------------------------------
const soc1_02: Scenario = {
  id: 'soc1-02',
  tokens: [{ from: '185.220.101.47', gen: randIp }, { from: '67.160.8.51', gen: randIp }],
  tier: 'soc1',
  title: 'Impossible travel sign-in alert',
  category: 'Identity',
  difficulty: 3,
  estMinutes: 13,
  objective: 'Work an impossible-travel alert to a defensible verdict by examining the sign-ins, IP reputation, and post-auth behavior, and by actually contacting the user — not guessing.',
  intake: { kind: 'alert', alertId: 'ALT-50021' },
  priorityExpected: 'P2',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50021', time: ago(20), severity: 'medium', source: 'cloud',
      title: 'Impossible travel: hsato signed in from Seattle and then Frankfurt, DE within 40 minutes',
      description: 'WorkSuite flagged two successful sign-ins for hsato that are geographically impossible in the time elapsed.',
      user: 'hsato', indicators: ['67.160.8.51', '185.220.101.47'], mitre: ['T1078'], status: 'new', truth: 'true_positive',
    });
    const u = findUser(w, 'hsato')!;
    // Real compromise: Seattle (home, MFA satisfied) then Frankfurt via a Tor/anonymizer IP with MFA "fatigue-approved", followed by an inbox rule creation.
    u.recentSignIns = [
      { time: ago(18), ip: '185.220.101.47', location: 'Frankfurt, DE', app: 'WorkSuite Mail', result: 'success', device: 'unknown browser', mfa: 'fatigue-approved' },
      { time: ago(58), ip: '67.160.8.51', location: 'Seattle, US', app: 'WorkSuite Mail', result: 'success', device: 'DEN-LT-1062', mfa: 'satisfied' },
      { time: ago(60 * 20), ip: '67.160.8.51', location: 'Seattle, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1062', mfa: 'satisfied' },
    ];
    // Post-auth: attacker created an inbox rule to hide replies
    w.mailboxes.find((m) => m.user === 'hsato')!.rules = [
      { name: 'zzz', condition: 'from contains "IT" or "security" or "phish"', action: 'move to RSS Feeds; mark read', enabled: true, created: ago(17), suspicious: true },
    ];
    w.intel.push({ indicator: '185.220.101.47', type: 'ip', verdict: 'malicious', source: 'Tor exit list + abuse feed', tags: ['tor', 'anonymizer'], detail: 'Known Tor exit node in Frankfurt. Frequently used in account-takeover.' });
    w.intel.push({ indicator: '67.160.8.51', type: 'ip', verdict: 'clean', source: 'ISP lookup', tags: ['residential', 'us'], detail: 'Comcast residential Seattle. Matches hsato\'s known home/VPN IP.' });
    addLog(w, { time: ago(18), source: 'cloud', user: 'hsato', srcIp: '185.220.101.47', action: 'signin', message: 'WorkSuite sign-in success user=hsato app=Mail geo=Frankfurt,DE mfa=fatigue-approved device=unknown' });
    addLog(w, { time: ago(17), source: 'cloud', user: 'hsato', srcIp: '185.220.101.47', action: 'mailrule', message: 'Inbox rule "zzz" created moving IT/security mail to RSS Feeds (mark read)' });
    w.chat.push({ id: 'ch-hsato', with: 'hsato', messages: [] });
  },
  contactWith: 'hsato',
  contact: [
    { id: 'travel', question: 'Are you travelling? Did you sign in from Germany in the last hour?', answer: '"No! I\'m at home in Seattle. I\'ve never been to Germany. Why?"', purpose: 'clarify', reveals: 'not-travel' },
    { id: 'mfa', question: 'Did you approve an MFA prompt you didn\'t start?', answer: '"Actually... my phone buzzed a few times with approve requests and I hit approve once to make it stop. I thought it was glitching."', purpose: 'clarify', reveals: 'mfa-fatigue' },
    { id: 'rule', question: 'Did you create an inbox rule called "zzz" that moves IT mail to RSS Feeds?', answer: '"No, I have no idea what that is."', purpose: 'clarify', reveals: 'attacker-rule' },
    { id: 'mgr', question: 'Confirm with her manager whether she\'s travelling', answer: 'Emily Wright: "Hana? No, she\'s home in Seattle this week, not travelling."', purpose: 'verify' },
    { id: 'weather', question: 'How\'s Seattle weather?', answer: '"Rainy. Can we deal with the account thing?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the suspicious sign-in playbook (KB-0016)', match: { tool: 'kb', action: 'read', target: 'KB-0016' } },
    { id: 'signins', label: 'Reviewed the sign-ins (Seattle MFA-satisfied vs Frankfurt MFA-fatigue from unknown device)', match: { tool: 'directory', action: 'view_signins', target: 'hsato' }, hint: 'Compare the two logins: device, MFA result, location.' },
    { id: 'intel1', label: 'Looked up the Frankfurt IP (Tor exit, malicious)', match: { tool: 'intel', action: 'lookup', target: '185.220.101.47' } },
    { id: 'intel2', label: 'Looked up the Seattle IP (her known home IP)', match: { tool: 'intel', action: 'lookup', target: '67.160.8.51' }, weight: 0.5 },
    { id: 'rule', label: 'Found the attacker-created inbox rule hiding IT/security mail', match: { tool: 'mail', action: 'view_mailbox', target: 'hsato' }, hint: 'Attackers create rules to hide their tracks. Check her mailbox rules.' },
    { id: 'contacted', label: 'Contacted the user and confirmed she did not travel / approved a stray MFA prompt', match: { tool: 'chat', action: 'send', target: 'hsato' } },
  ],
  required: [
    { id: 'revoke', label: 'Revoked her sessions', match: { tool: 'directory', action: 'revoke_sessions', target: 'hsato' }, skill: 'technical', weight: 1 },
    { id: 'reset', label: 'Reset her password', match: { tool: 'directory', action: 'reset_password', target: 'hsato' }, skill: 'technical', after: 'revoke', weight: 1 },
    { id: 'rmrule', label: 'Removed the malicious inbox rule', match: { tool: 'mail', action: 'remove_rule', target: 'hsato' }, skill: 'technical', weight: 1 },
    { id: 'escalate', label: 'Escalated to CIRT (successful attacker sign-in + persistence)', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'benign', label: 'Closed it as benign travel / VPN', why: 'The Frankfurt login is a Tor exit on an unknown device with MFA fatigue, followed by a hidden inbox rule, and the user denies travelling. This is a confirmed account takeover.', match: { tool: 'ticket', action: 'reply', target: 'r_benign' }, skill: 'security', penalty: 0.6 },
    { id: 'reset_only', label: 'Reset the password without revoking sessions first', why: 'KB-0016/0018: revoke active sessions BEFORE (or with) the reset, or the attacker\'s live token keeps working after the password changes.', match: { tool: 'directory', action: 'reset_password', target: 'hsato' }, unlessAfter: 'revoke', skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed account takeover of hsato. Timeline: legit Seattle login (her device, MFA satisfied), then 40 min later a successful login from a Frankfurt Tor exit on an unknown device via MFA fatigue — she approved a stray prompt. The attacker then created a hidden inbox rule shunting IT/Security mail to RSS Feeds. I revoked her sessions, reset her password, and removed the rule. Escalating to CIRT because the attacker successfully authenticated and established persistence.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Clear timeline, correct containment order, persistence removed, and escalated because the sign-in succeeded.' },
    { id: 'r_benign', text: 'Likely her VPN exiting through a European node — marking benign true positive.', scores: { communication: 0.3, security: 0.1 }, feedback: 'Tor exit + unknown device + MFA fatigue + a hidden inbox rule + user denies travel. That is not a VPN quirk.' },
    { id: 'r_disable_only', text: 'Disabled the account, done.', scores: { communication: 0.4, security: 0.5, process: 0.4 }, feedback: 'Disabling helps but you left the inbox rule (persistence) in place and didn\'t escalate a successful compromise.' },
  ],
  notesRubric: [
    { label: 'the timeline (Seattle legit -> Frankfurt Tor via MFA fatigue)', pattern: /seattle|frankfurt|tor|mfa fatigue|impossible travel|timeline/i },
    { label: 'the persistence found (malicious inbox rule)', pattern: /inbox rule|zzz|rss feed|rule|persistence/i },
    { label: 'containment in the right order (revoke -> reset -> remove rule)', pattern: /revoke|reset|removed.*rule|contain/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Identity - Account Takeover', resolutionCode: 'Contained; escalated to CIRT (successful ATO)' },
  categoryAccept: ['identity', 'account takeover', 'ato', 'compromise'],
  resolutionCodeAccept: ['contain', 'cirt', 'takeover', 'compromise'],
  hints: [
    'KB-0016 is the playbook. Do not decide before you check post-auth behavior.',
    'The two IPs tell the story: her home Seattle IP (clean) vs a Frankfurt Tor exit (malicious) on an unknown device with MFA fatigue.',
    'Check her mailbox for new inbox rules — attackers hide IT/Security mail. There is a "zzz" rule.',
    'Contain in order: revoke sessions, then reset, then remove the rule. Escalate to CIRT because the login SUCCEEDED.',
  ],
  debrief: 'This is the sibling of the benign impossible-travel case, and the point is that you cannot tell them apart without doing the work. Here every signal is bad: a Tor exit node, an unknown device, MFA fatigue (the user approved a prompt she didn\'t initiate), the user denies travelling, and there is post-auth persistence in the form of an inbox rule hiding security mail. Containment order matters — revoke the live sessions before/with the reset, or the attacker\'s existing token outlives the password change. Because the attacker actually authenticated and persisted, this goes to CIRT.',
};

// ---------------------------------------------------------------------------
// SOC1-03  Phishing campaign — scope all recipients, purge, block
// ---------------------------------------------------------------------------
const soc1_03: Scenario = {
  id: 'soc1-03',
  tokens: [{ from: 'docu-sign-verify.app', gen: randDomain }, { from: '193.42.33.14', gen: randIp }],
  tier: 'soc1',
  title: 'Reported phish — how many got it?',
  category: 'Email',
  difficulty: 3,
  estMinutes: 14,
  objective: 'Run the phishing playbook end to end: analyze headers, scope every recipient, purge, check who clicked, and block the indicators — then classify.',
  intake: { kind: 'alert', alertId: 'ALT-50031' },
  priorityExpected: 'P2',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50031', time: ago(25), severity: 'medium', source: 'user_report',
      title: 'User-reported phishing: fake "DocuSign - Q3 vendor contract" with credential link',
      description: 'bpatel reported a DocuSign lookalike. Need to scope the campaign, purge, and block.',
      user: 'bpatel', indicators: ['docu-sign-verify.app', '193.42.33.14'], mitre: ['T1566.002'], status: 'new', truth: 'true_positive',
    });
    const mkMsg = (id: string, to: string, clicked = false) => ({
      id, time: ago(70), from: 'DocuSign <no-reply@docu-sign-verify.app>', to: [`${to}@kestreldynamics.com`],
      subject: 'Please DocuSign: Q3 Vendor Contract - Action Required',
      status: 'delivered (junk)' as const, reason: 'DMARC fail; delivered to Junk',
      headers: { from: 'DocuSign <no-reply@docu-sign-verify.app>', returnPath: 'bounce@docu-sign-verify.app', replyTo: 'no-reply@docu-sign-verify.app', receivedFrom: 'docu-sign-verify.app [193.42.33.14]', spf: 'fail' as const, dkim: 'fail' as const, dmarc: 'fail' as const, messageId: `<${id}@docu-sign-verify.app>` },
      body: 'You have a document to review and sign. REVIEW DOCUMENT: https://docu-sign-verify.app/sign?id=' + id,
      urls: ['https://docu-sign-verify.app/sign?id=' + id], phishing: true, clicked: clicked ? [to] : [],
    });
    addMail(w, mkMsg('MSG-9001', 'bpatel'));
    addMail(w, mkMsg('MSG-9002', 'jmorales', true)); // jmorales clicked!
    addMail(w, mkMsg('MSG-9003', 'ewright'));
    addMail(w, mkMsg('MSG-9004', 'cflores'));
    // jmorales clicked but did NOT enter creds (page didn't load fully) — her sign-ins are clean.
    const jm = findUser(w, 'jmorales')!;
    jm.recentSignIns = [{ time: ago(30), ip: '10.10.20.41', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1041', mfa: 'satisfied' }];
    w.intel.push({ indicator: 'docu-sign-verify.app', type: 'domain', verdict: 'malicious', source: 'URL sandbox + feeds', tags: ['phishing', 'credential-harvest'], detail: 'Credential-harvesting page impersonating DocuSign. Registered 5 days ago.' });
    w.intel.push({ indicator: '193.42.33.14', type: 'ip', verdict: 'malicious', source: 'abuse feed', tags: ['phishing', 'bulletproof'], detail: 'Sending host for multiple phishing campaigns.' });
    w.chat.push({ id: 'ch-jm', with: 'jmorales', messages: [] });
  },
  evidence: [
    { id: 'kb', label: 'Read the phishing playbook (KB-0014)', match: { tool: 'kb', action: 'read', target: 'KB-0014' } },
    { id: 'headers', label: 'Analyzed the headers (SPF/DKIM/DMARC fail, lookalike domain)', match: { tool: 'mail', action: 'view_headers', target: /MSG-900/ }, hint: 'Confirm it is malicious from the headers before anything else.' },
    { id: 'intel', label: 'Looked up the URL/domain and sending IP', match: { tool: 'intel', action: 'lookup', target: /docu-sign-verify|193\.42\.33\.14/ } },
    { id: 'trace', label: 'Traced the campaign to find every recipient', match: { tool: 'mail', action: 'trace', params: { q: /docu-sign|docusign|vendor contract/i } }, hint: 'How many people got this? Trace by sender/subject.' },
    { id: 'whoclicked', label: 'Identified that jmorales clicked and checked her sign-ins (clean)', match: [{ tool: 'directory', action: 'view_signins', target: 'jmorales' }, { tool: 'chat', action: 'send', target: 'jmorales' }], hint: 'Who interacted? Check their account for follow-on compromise.' },
  ],
  required: [
    { id: 'purge', label: 'Purged the message for all recipients', match: { tool: 'mail', action: 'purge_all', target: /MSG-900/ }, skill: 'technical' },
    { id: 'block_domain', label: 'Blocked the sender domain / URL at the gateway', match: [{ tool: 'perimeter', action: 'block', target: /docu-sign-verify/ }, { tool: 'mail', action: 'block_sender', target: /docu-sign-verify/ }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'reset_jm', label: 'Reset jmorales\'s password even though she entered no credentials', why: 'She clicked but did not submit credentials and her sign-ins are clean. A reset here is not wrong per se, but classifying/escalating her as compromised without evidence overstates it. Focus on the confirmed facts.', match: { tool: 'ticket', action: 'reply', target: 'r_over' }, skill: 'process', penalty: 0.2 },
    { id: 'fp', label: 'Classified as false positive', why: 'The message is unquestionably malicious (failed auth, malicious domain). Even if nobody had clicked, a malicious email that reached inboxes is a true positive.', match: { tool: 'ticket', action: 'reply', target: 'r_fp' }, skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed phishing (DocuSign lookalike, SPF/DKIM/DMARC all fail, malicious domain + sender IP). Campaign hit 4 mailboxes: bpatel, jmorales, ewright, cflores. I purged all 4 copies and blocked docu-sign-verify.app and the sending IP at the mail gateway and proxy. One user (jmorales) clicked the link but did not enter credentials — her recent sign-ins are clean, so no account action needed beyond a heads-up. Classifying True Positive, severity medium (contained, no credential loss).', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Full scope, purge, block, correct read on the click-without-creds, and an accurate classification.' },
    { id: 'r_fp', text: 'Only landed in Junk and nobody was harmed — false positive, closing.', scores: { communication: 0.3, security: 0.1 }, feedback: 'A malicious email that reached mailboxes is a true positive regardless of where it landed or whether anyone bit.' },
    { id: 'r_over', text: 'Assuming full compromise — reset passwords for all 4 recipients and escalate to CIRT.', scores: { communication: 0.4, process: 0.3 }, feedback: 'Overreach. Three never clicked; the one who clicked entered nothing and has clean sign-ins. Match the response to the evidence.' },
  ],
  notesRubric: [
    { label: 'the confirmation (headers/intel show malicious)', pattern: /spf|dkim|dmarc|lookalike|malicious|docu-sign-verify/i },
    { label: 'the scope (all recipients found and purged)', pattern: /4 |four |bpatel|jmorales|ewright|cflores|recipients|purge/i },
    { label: 'the block and the click-without-creds finding', pattern: /block|gateway|proxy|clicked.*no cred|clean sign-?in|no credential/i },
  ],
  closure: { disposition: 'resolve', classification: 'true_positive', severity: 'medium', category: 'Email - Phishing Campaign', resolutionCode: 'Purged + blocked; no credential loss' },
  categoryAccept: ['email', 'phishing', 'campaign'],
  resolutionCodeAccept: ['purge', 'block', 'phishing', 'contained'],
  hints: [
    'KB-0014 is the step list. Confirm malicious via headers/intel first.',
    'Trace the campaign to get the full recipient list before you purge — there are four.',
    'One recipient clicked. Check her sign-ins: clean, and she entered no credentials, so no reset needed.',
    'Purge all copies, block the domain and IP, classify True Positive (medium — contained).',
  ],
  debrief: 'Phishing response is about scope and proportion. The playbook order is confirm, scope, purge, check interactions, block, classify. The trap on both ends: calling it a false positive because it hit Junk (it is a true positive the moment a malicious mail reaches a mailbox), or over-responding by treating everyone as compromised. Matching action to evidence — one clicker who submitted nothing, three who never clicked — is what separates a calibrated analyst from a noisy one.',
};

// ---------------------------------------------------------------------------
// SOC1-04  EDR malware on an endpoint — isolate a single workstation
// ---------------------------------------------------------------------------
const soc1_04: Scenario = {
  id: 'soc1-04',
  tokens: [{ from: '45.146.164.90', gen: randIp }, { from: 'cdn-updates.xyz', gen: randDomain }, { from: 'c1d2...ab', gen: randHash }],
  tier: 'soc1',
  title: 'EDR alert: malicious document spawned PowerShell',
  category: 'Endpoint',
  difficulty: 3,
  estMinutes: 15,
  objective: 'Triage an endpoint malware alert: read the process tree, look up the C2 indicator, check for persistence and spread, isolate the workstation, and know when it becomes a CIRT case.',
  intake: { kind: 'alert', alertId: 'ALT-50041' },
  priorityExpected: 'P2',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50041', time: ago(15), severity: 'high', source: 'edr',
      title: 'Office spawned PowerShell with encoded command (WINWORD -> powershell -enc) on DEN-LT-1050',
      description: 'Halberd flagged WINWORD.EXE spawning powershell.exe with a base64 -EncodedCommand that downloaded a payload. Host: DEN-LT-1050 (sturner, HR).',
      host: 'DEN-LT-1050', user: 'sturner', indicators: ['45.146.164.90', 'update-svc.exe'], mitre: ['T1566.001', 'T1059.001'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'DEN-LT-1050');
    const word = addProc(h, { pid: 5120, name: 'WINWORD.EXE', user: 'KESTREL\\sturner', cpu: 1, mem: 240, path: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', signed: true, started: ago(16) });
    const ps = addProc(h, { pid: 5240, name: 'powershell.exe', user: 'KESTREL\\sturner', cpu: 8, mem: 90, path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmdline: 'powershell.exe -w hidden -enc SQBFAFgAKA...', parentPid: 5120, signed: true, started: ago(15) });
    addProc(h, { pid: 5320, name: 'update-svc.exe', user: 'KESTREL\\sturner', cpu: 3, mem: 55, path: 'C:\\Users\\sturner\\AppData\\Roaming\\update-svc.exe', cmdline: 'update-svc.exe', parentPid: 5240, signed: false, hash: 'c1d2...ab', started: ago(14) });
    // Persistence: scheduled task + run key
    h.scheduledTasks.push({ name: 'UpdateService', path: '\\', action: 'C:\\Users\\sturner\\AppData\\Roaming\\update-svc.exe', trigger: 'At logon', author: 'KESTREL\\sturner', suspicious: true });
    h.files.push({ path: 'C:\\Users\\sturner\\AppData\\Roaming\\update-svc.exe', size: 240000, modified: ago(14), signed: false, hash: 'c1d2...ab', suspicious: true });
    h.files.push({ path: 'C:\\Users\\sturner\\Downloads\\Q3_Benefits_Update.docm', size: 88000, modified: ago(18), suspicious: true });
    setConn(h, [{ proto: 'TCP', local: `${h.ip}:50120`, remote: '45.146.164.90:443', state: 'ESTABLISHED', pid: 5320 }]);
    addLog(w, { time: ago(14), source: 'proxy', host: 'DEN-LT-1050', user: 'sturner', domain: 'cdn-updates.xyz', dstIp: '45.146.164.90', url: 'https://cdn-updates.xyz/beacon', action: 'allow', dstPort: 443, message: 'POST https://cdn-updates.xyz/beacon (repeating every 60s)' });
    // Crucially: no lateral movement (sturner does not log on to other hosts), single host, non-privileged user
    w.intel.push({ indicator: '45.146.164.90', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['c2', 'cobalt-strike'], detail: 'Known Cobalt Strike C2. Beacon over 443.' });
    w.intel.push({ indicator: 'update-svc.exe', type: 'hash', verdict: 'malicious', source: 'sandbox', tags: ['loader', 'stealer'], detail: 'Info-stealer/loader dropped by malicious macro. c1d2...ab.' });
    w.chat.push({ id: 'ch-st', with: 'sturner', messages: [] });
  },
  contactWith: 'sturner',
  contact: [
    { id: 'doc', question: 'Did you open a document called "Q3 Benefits Update" and enable content/macros?', answer: '"Yes! It came in an email about benefits, it said to Enable Editing and Enable Content so I did."', purpose: 'clarify', reveals: 'macro' },
    { id: 'creds', question: 'Any credential prompts after that, or did you type your password anywhere?', answer: '"No password prompts. It just seemed to do nothing after."', purpose: 'clarify' },
    { id: 'other', question: 'Are you logged into any other computers or servers right now?', answer: '"No, just my laptop."', purpose: 'clarify', reveals: 'single-host' },
    { id: 'lunch', question: 'What did you have for lunch?', answer: '"...a sandwich?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the endpoint-malware playbook (KB-0015)', match: { tool: 'kb', action: 'read', target: 'KB-0015' } },
    { id: 'tree', label: 'Reviewed the process tree (WINWORD -> powershell -enc -> update-svc.exe in AppData)', match: [{ tool: 'edr', action: 'view_tree', target: 'DEN-LT-1050' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1050' }], hint: 'What launched what? Where does the child process run from?' },
    { id: 'intel_c2', label: 'Looked up the C2 IP (45.146.164.90 = Cobalt Strike)', match: { tool: 'intel', action: 'lookup', target: '45.146.164.90' } },
    { id: 'intel_hash', label: 'Looked up the dropped file hash (malicious loader)', match: { tool: 'intel', action: 'lookup', target: 'update-svc.exe' }, weight: 0.5 },
    { id: 'persist', label: 'Found the persistence (scheduled task / run at logon)', match: [{ tool: 'rdp', action: 'view_tasks', target: 'DEN-LT-1050' }, { tool: 'terminal', action: 'schtasks', target: 'DEN-LT-1050' }], hint: 'Malware wants to survive reboot. Check scheduled tasks.' },
    { id: 'lateral', label: 'Checked the SIEM for lateral movement (none — user not on other hosts)', match: [{ tool: 'siem', action: 'search', params: { q: /sturner|logon type 3|logon type 10/i } }, { tool: 'siem', action: 'pivot', params: { value: /sturner/ } }], hint: 'Did the user\'s account log on to any OTHER host after the alert?' },
  ],
  required: [
    { id: 'triage', label: 'Collected a triage package before destructive actions', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1050' }, skill: 'process', before: 'isolate' },
    { id: 'isolate', label: 'Isolated the workstation in EDR', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1050' }, skill: 'technical' },
    { id: 'reset', label: 'Reset the user\'s credentials (stealer on the host)', match: { tool: 'directory', action: 'reset_password', target: 'sturner' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'reimage', label: 'Reimaged / wiped the host before triage collection', why: 'KB-0015/0018: collect a triage package first. Reimaging destroys the evidence of how they got in and whether they spread.', match: [{ tool: 'rdp', action: 'reboot', target: 'DEN-LT-1050' }, { tool: 'assets', action: 'remote_wipe' }], skill: 'security', penalty: 0.5 },
    { id: 'ignore_persist', label: 'Closed without finding/killing the persistence', why: 'If the scheduled task survives, the malware relaunches. Isolation alone is not eradication.', match: { tool: 'ticket', action: 'reply', target: 'r_quick' }, skill: 'technical', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed malware on DEN-LT-1050 (HR, sturner): a macro doc (Q3_Benefits_Update.docm) spawned hidden PowerShell that dropped update-svc.exe in AppData, which is beaconing to a known Cobalt Strike C2 (45.146.164.90) and set a logon persistence task. Scope check: single host, non-privileged user, no lateral movement in the SIEM. I collected a triage package, isolated the host in EDR, and reset sturner\'s credentials. Because it\'s a confirmed C2/hands-on-keyboard framework, I\'m escalating to CIRT and ticketing Desktop to reimage only after CIRT releases it.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Right order (triage before isolate), full scope, credential reset, and escalation because Cobalt Strike C2 is confirmed.' },
    { id: 'r_quick', text: 'Isolated the machine, that stops it. Closing.', scores: { communication: 0.4, technical: 0.3 }, feedback: 'Isolation contains but you left the persistence and never reset the credentials the stealer grabbed, and didn\'t escalate a C2 compromise.' },
    { id: 'r_reimage', text: 'Told Desktop to wipe and reimage it immediately to be safe.', scores: { communication: 0.3, security: 0.2, process: 0.2 }, feedback: 'Reimaging before collecting evidence destroys the investigation. Contain first, collect, then reimage after CIRT clears it.' },
  ],
  notesRubric: [
    { label: 'the process tree / initial access (macro -> powershell -enc -> AppData exe)', pattern: /winword|macro|powershell|-enc|appdata|update-svc/i },
    { label: 'the C2 confirmation and persistence', pattern: /c2|cobalt|45\.146\.164\.90|scheduled task|persistence|beacon/i },
    { label: 'the scope check (single host, no lateral movement)', pattern: /single host|no lateral|one host|scope|not spread/i },
    { label: 'the containment order (triage -> isolate -> reset)', pattern: /triage|isolate|reset|contain/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Endpoint - Malware (C2)', resolutionCode: 'Isolated + credentials reset; escalated to CIRT' },
  categoryAccept: ['endpoint', 'malware', 'c2', 'compromise'],
  resolutionCodeAccept: ['isolate', 'cirt', 'malware', 'contain'],
  hints: [
    'KB-0015 is the playbook. The alert names the host and the indicators.',
    'Read the process tree: a Word macro launched encoded PowerShell that dropped update-svc.exe in AppData — classic.',
    'Look up the C2 IP (Cobalt Strike) and the dropped hash. Find the persistence (a logon scheduled task).',
    'Scope it in the SIEM: single host, no lateral movement. Collect triage FIRST, then isolate, reset creds, escalate to CIRT.',
  ],
  debrief: 'A clean endpoint-malware triage. The process tree tells the initial-access story (malicious macro to encoded PowerShell to an AppData dropper), threat intel confirms a Cobalt Strike C2, and you find the logon-task persistence. Two order-of-operations rules decide the score: collect a triage package before you isolate or reimage (isolation preserves the EDR channel; reimaging destroys evidence), and reset the user\'s credentials because a stealer sat on the host. Scoping shows a single, non-privileged host with no lateral movement — but confirmed C2 framework activity still earns a CIRT escalation.',
};

export const SOC1_SCENARIOS: Scenario[] = [soc1_01, soc1_02, soc1_03, soc1_04];
