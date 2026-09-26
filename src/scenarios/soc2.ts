import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, addAlert, addMail, setConn } from './helpers';
import { randIp, randHash, randDomain } from '../engine/instantiate';

// ---------------------------------------------------------------------------
// SOC2-01  Business email compromise / payment-fraud attempt
// ---------------------------------------------------------------------------
const soc2_01: Scenario = {
  id: 'soc2-01',
  tier: 'soc2',
  title: 'CFO "approved" a vendor bank-change — did they?',
  category: 'BEC / Fraud',
  difficulty: 4,
  estMinutes: 16,
  objective: 'Investigate a business email compromise: separate a spoof from a real mailbox takeover, protect the money first, and coordinate the identity and finance response.',
  intake: { kind: 'alert', alertId: 'ALT-50051' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50051', time: ago(12), severity: 'high', source: 'dlp',
      title: 'AP specialist about to change a vendor\'s bank details based on emailed "CFO approval"',
      description: 'jmorales (AP) opened a ticket to update vendor "Aerofix Ltd" bank account per an email chain that appears to come from CFO rokafor approving an urgent change. DLP flagged the payment-detail change.',
      user: 'rokafor', indicators: ['rokafor@kestreldynamlcs.com'], mitre: ['T1566', 'T1656'], status: 'new', truth: 'true_positive',
    });
    // Ground truth: this is a SPOOF (lookalike domain), NOT a mailbox takeover. rokafor's real account is clean.
    addMail(w, {
      id: 'MSG-7001', time: ago(90), from: 'Rachel Okafor <rokafor@kestreldynamlcs.com>', to: ['jmorales@kestreldynamics.com'],
      subject: 'RE: URGENT - Aerofix bank details update before EOD',
      status: 'delivered' as const,
      headers: { from: 'Rachel Okafor <rokafor@kestreldynamlcs.com>', returnPath: 'rokafor@kestreldynamlcs.com', replyTo: 'rokafor.finance@gmail.com', receivedFrom: 'mta-out.sendgrid-relay.net [149.72.x.x]', spf: 'pass', dkim: 'none', dmarc: 'fail', messageId: '<7001@kestreldynamlcs.com>' },
      body: 'Jenna — Aerofix changed banks. Please update their account to IBAN GB29 NWBK 6016 1331 9268 19 and push the pending $48,200 invoice today. I\'m in meetings, just handle it. Do not call, email me only. — Rachel',
      urls: [], phishing: true,
    });
    w.intel.push({ indicator: 'kestreldynamlcs.com', type: 'domain', verdict: 'malicious', source: 'internal', tags: ['lookalike', 'bec'], detail: 'Lookalike of kestreldynamics.com ("l" for "i"). Not owned by Kestrel. Classic BEC.' });
    // rokafor's real sign-ins clean
    const r = findUser(w, 'rokafor')!;
    r.recentSignIns = [{ time: ago(120), ip: '10.10.20.12', location: 'Denver, US', app: 'WorkSuite Mail', result: 'success', device: 'DEN-LT-1002', mfa: 'satisfied' }];
    w.mailboxes.find((m) => m.user === 'rokafor')!.rules = []; // no takeover
    w.chat.push({ id: 'ch-jm2', with: 'jmorales', messages: [] }, { id: 'ch-ro', with: 'rokafor', messages: [] });
  },
  contactWith: 'rokafor',
  contact: [
    { id: 'cfo', question: 'Call/chat the CFO out-of-band: did you email jmorales to change Aerofix\'s bank details?', answer: 'Rachel Okafor: "Absolutely not. I never sent that. And I\'d never tell someone not to call me. That\'s not my address either."', purpose: 'verify', reveals: 'spoof' },
    { id: 'ap', question: 'Tell jmorales to HOLD the payment and bank change immediately.', answer: 'Jenna: "Oh thank god, I hadn\'t hit submit yet. Holding it now."', purpose: 'clarify', reveals: 'money-held' },
    { id: 'reply_to', question: 'Compare the reply-to and sender domain to the real ones', answer: 'Sender is rokafor@kestreldynamlcs.com (lookalike) with reply-to a Gmail. The real domain is kestreldynamics.com.', purpose: 'clarify', reveals: 'lookalike' },
    { id: 'weather', question: 'Ask jmorales how her weekend was', answer: '"Fine? Kind of busy with this..."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'headers', label: 'Analyzed the headers: lookalike domain, DMARC fail, Gmail reply-to', match: { tool: 'mail', action: 'view_headers', target: 'MSG-7001' }, hint: 'Is this the CFO\'s real mailbox, or a lookalike domain?' },
    { id: 'intel', label: 'Confirmed the lookalike domain in intel', match: { tool: 'intel', action: 'lookup', target: 'kestreldynamlcs.com' } },
    { id: 'realbox', label: 'Checked the CFO\'s real account/mailbox (no takeover: clean sign-ins, no rules)', match: [{ tool: 'directory', action: 'view_signins', target: 'rokafor' }, { tool: 'mail', action: 'view_mailbox', target: 'rokafor' }], hint: 'Rule in or out an actual mailbox compromise vs. a pure external spoof.' },
    { id: 'verify_cfo', label: 'Verified out-of-band with the CFO that they did not send it', match: { tool: 'chat', action: 'send', target: 'rokafor' } },
  ],
  required: [
    { id: 'hold', label: 'Stopped the payment / bank change (money first)', match: { tool: 'chat', action: 'send', target: 'jmorales' }, skill: 'process' },
    { id: 'block', label: 'Blocked the lookalike domain and purged the message', match: [{ tool: 'perimeter', action: 'block', target: /kestreldynamlcs/ }, { tool: 'mail', action: 'block_sender', target: /kestreldynamlcs/ }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'reset_cfo', label: 'Reset the CFO\'s password / treated it as a mailbox takeover', why: 'This is an external spoof from a lookalike domain, not a compromise of the CFO\'s real mailbox (clean sign-ins, no rules). Resetting her password chases the wrong threat and disrupts an exec for nothing.', match: { tool: 'directory', action: 'reset_password', target: 'rokafor' }, skill: 'security', penalty: 0.4 },
    { id: 'reply', label: 'Replied to the attacker email to "confirm"', why: 'Never engage the sender — it confirms a live target and can leak internal detail.', match: { tool: 'mail', action: 'release', target: 'MSG-7001' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is a business email compromise / payment-fraud attempt — an EXTERNAL spoof, not a takeover of the CFO\'s mailbox. The email came from a lookalike domain (kestreldynamlcs.com, "l" for "i") with a Gmail reply-to and a "don\'t call me" pressure line; the CFO confirmed out-of-band she never sent it, and her real account is clean (good sign-ins, no rules). Most important: I had AP hold the $48,200 payment and the bank change before submit. I purged the message and blocked the lookalike domain at the gateway. Notifying Finance leadership to watch for repeats; no CFO account action needed.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Correct diagnosis (spoof vs takeover), money protected first, contained, and no wasted exec disruption.' },
    { id: 'r_takeover', text: 'The CFO\'s mailbox is compromised — resetting her password and revoking sessions.', scores: { communication: 0.3, security: 0.2 }, feedback: 'Her real mailbox is clean; this is an external lookalike. You\'re fixing a compromise that didn\'t happen and missing the payment hold.' },
    { id: 'r_slow', text: 'Documented the phish and blocked the domain. Closing.', scores: { communication: 0.4, process: 0.2 }, feedback: 'You forgot the whole point: stop the money. Blocking the domain doesn\'t un-send a wire.' },
  ],
  notesRubric: [
    { label: 'the diagnosis (external BEC spoof, lookalike domain, not a takeover)', pattern: /spoof|lookalike|kestreldynamlcs|bec|external|not.*takeover|dmarc fail/i },
    { label: 'the money protected (payment/bank change held)', pattern: /hold|held|stopped|payment|bank|48,?200|before submit/i },
    { label: 'containment (purge + block) and out-of-band verification', pattern: /purge|block|out.?of.?band|confirmed with|verified.*cfo/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'finance', classification: 'true_positive', severity: 'high', category: 'BEC - Payment Fraud (spoof)', resolutionCode: 'Payment held; domain blocked; Finance notified' },
  categoryAccept: ['bec', 'fraud', 'payment', 'phishing'],
  resolutionCodeAccept: ['held', 'block', 'bec', 'finance', 'contained'],
  hints: [
    'The alert is about money moving. Your first job is to stop the payment, then investigate.',
    'Read the headers: a lookalike domain and a Gmail reply-to, with "don\'t call me" pressure — the BEC signature.',
    'Rule out a real mailbox takeover: the CFO\'s actual account has clean sign-ins and no inbox rules.',
    'Verify with the CFO out-of-band, purge, block the lookalike domain, and notify Finance. Do not reset the CFO\'s password.',
  ],
  debrief: 'BEC is where security and money meet, and the muscle memory is "protect the funds first." The investigative subtlety is telling a spoof (external lookalike domain) from a takeover (the real mailbox is controlled by the attacker). Here the CFO\'s real account is clean and the mail came from kestreldynamlcs.com, so it is a spoof — resetting her password would be chasing a ghost while the wire goes out. The correct sequence: hold the payment, verify out-of-band, purge and block, and notify Finance to watch for follow-ups.',
};

// ---------------------------------------------------------------------------
// SOC2-02  Threat hunt: is the C2 IP anywhere else? (scoping/hunting)
// ---------------------------------------------------------------------------
const soc2_02: Scenario = {
  id: 'soc2-02',
  tokens: [{ from: '45.146.164.90', gen: randIp }],
  tier: 'soc2',
  title: 'Hunt: did the beacon touch anyone else?',
  category: 'Threat Hunting',
  difficulty: 4,
  estMinutes: 16,
  objective: 'Pivot on a confirmed indicator across the whole estate to find a second, quieter victim that the original alert missed — and contain the right hosts.',
  intake: { kind: 'alert', alertId: 'ALT-50061' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50061', time: ago(30), severity: 'high', source: 'siem',
      title: 'Confirmed C2 beacon from DEN-LT-1042 to 45.146.164.90 — hunt for other affected hosts',
      description: 'Yesterday\'s incident confirmed 45.146.164.90 as C2. DEN-LT-1042 (bpatel) is already isolated. Task: hunt the indicator across the estate for other victims before eradication.',
      host: 'DEN-LT-1042', indicators: ['45.146.164.90', 'update-svc.exe'], mitre: ['T1071'], status: 'in progress', truth: 'true_positive',
    });
    const known = host(w, 'DEN-LT-1042'); known.isolated = true; known.edrAgent = 'healthy';
    // The hidden second victim: DEN-LT-1070 (jwebb) also beacons to the same C2, but never alerted (EDR was offline/tampered there).
    const victim2 = host(w, 'DEN-LT-1070');
    victim2.edrAgent = 'offline';
    addProc(victim2, { pid: 6120, name: 'update-svc.exe', user: 'KESTREL\\jwebb', cpu: 2, mem: 50, path: 'C:\\Users\\jwebb\\AppData\\Roaming\\update-svc.exe', signed: false, hash: 'c1d2...ab', started: ago(50) });
    setConn(victim2, [{ proto: 'TCP', local: `${victim2.ip}:50990`, remote: '45.146.164.90:443', state: 'ESTABLISHED', pid: 6120 }]);
    victim2.scheduledTasks.push({ name: 'UpdateService', path: '\\', action: 'C:\\Users\\jwebb\\AppData\\Roaming\\update-svc.exe', trigger: 'At logon', author: 'KESTREL\\jwebb', suspicious: true });
    // Logs: BOTH hosts beacon to the C2. Only 1042 alerted.
    addLog(w, { time: ago(55), source: 'firewall', host: 'DEN-LT-1070', srcIp: victim2.ip, dstIp: '45.146.164.90', dstPort: 443, action: 'allow', message: `ALLOW ${victim2.ip} -> 45.146.164.90:443 (repeating 60s)` });
    addLog(w, { time: ago(52), source: 'proxy', host: 'DEN-LT-1070', user: 'jwebb', dstIp: '45.146.164.90', domain: 'cdn-updates.xyz', url: 'https://cdn-updates.xyz/beacon', action: 'allow', dstPort: 443, message: 'POST https://cdn-updates.xyz/beacon' });
    addLog(w, { time: ago(28), source: 'firewall', host: 'DEN-LT-1042', srcIp: known.ip, dstIp: '45.146.164.90', dstPort: 443, action: 'allow', message: `ALLOW ${known.ip} -> 45.146.164.90:443` });
    // Red herring: a benign host talking to halberd-cloud.net (looks like beaconing but is EDR)
    addLog(w, { time: ago(20), source: 'firewall', host: 'DEN-LT-1041', srcIp: '10.10.20.41', dstIp: '34.117.59.81', dstPort: 443, action: 'allow', message: 'ALLOW 10.10.20.41 -> 34.117.59.81:443 halberd-cloud.net (EDR beacon, benign)' });
    w.intel.push({ indicator: '45.146.164.90', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['c2', 'cobalt-strike'], detail: 'Confirmed Cobalt Strike C2 from prior incident.' });
    w.intel.push({ indicator: '34.117.59.81', type: 'ip', verdict: 'clean', source: 'vendor allowlist', tags: ['edr'], detail: 'Halberd EDR cloud (halberd-cloud.net). Benign agent beacon.' });
  },
  evidence: [
    { id: 'kb', label: 'Reviewed the endpoint playbook scope step (KB-0015 / KB-0018)', match: [{ tool: 'kb', action: 'read', target: 'KB-0015' }, { tool: 'kb', action: 'read', target: 'KB-0018' }], weight: 0.5 },
    { id: 'hunt_c2', label: 'Pivoted on the C2 IP across firewall/proxy logs (found a SECOND host)', match: [{ tool: 'siem', action: 'search', params: { q: /45\.146\.164\.90/ } }, { tool: 'siem', action: 'pivot', params: { value: /45\.146\.164\.90/ } }], hint: 'Search the whole estate for the C2 IP, not just the known host.' },
    { id: 'find_v2', label: 'Identified DEN-LT-1070 (jwebb) as a second victim', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-LT-1070' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1070' }], hint: 'One of the beaconing hosts is not the one in the alert.' },
    { id: 'edr_gap', label: 'Noticed the second host\'s EDR agent was offline (why it never alerted)', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-LT-1070' }], weight: 0.5, hint: 'Why did EDR miss it? Check the agent health.' },
    { id: 'rule_out', label: 'Distinguished the benign EDR beacon (halberd-cloud) from the C2', match: { tool: 'intel', action: 'lookup', target: '34.117.59.81' }, weight: 0.5 },
  ],
  required: [
    { id: 'triage2', label: 'Collected triage on the second host before containment', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1070' }, skill: 'process', before: 'isolate2' },
    { id: 'isolate2', label: 'Isolated the second host (DEN-LT-1070)', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1070' }, skill: 'technical' },
    { id: 'reset2', label: 'Reset the second victim\'s credentials (jwebb)', match: { tool: 'directory', action: 'reset_password', target: 'jwebb' }, skill: 'technical' },
    { id: 'block_c2', label: 'Blocked the C2 IP at the perimeter', match: { tool: 'perimeter', action: 'block', target: '45.146.164.90' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'eradicate_early', label: 'Told IT to reimage the known host and closed before hunting', why: 'KB-0018: scope BEFORE eradication. If you clean 1042 while 1070 keeps beaconing, the attacker is still in and you\'ll be back tomorrow.', match: { tool: 'ticket', action: 'reply', target: 'r_early' }, skill: 'process', penalty: 0.5 },
    { id: 'chase_benign', label: 'Isolated the benign host talking to Halberd EDR', why: 'halberd-cloud.net (34.117.59.81) is the EDR agent\'s own cloud. Isolating that host is a false-positive containment.', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1041' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Hunt result: the C2 (45.146.164.90) has TWO talkers, not one. Besides the isolated DEN-LT-1042, DEN-LT-1070 (jwebb, Marketing) has been beaconing since ~50 min ago with the same update-svc.exe loader and logon persistence — it never alerted because its Halberd agent is offline. I collected triage and isolated 1070, reset jwebb\'s credentials, and blocked the C2 at the perimeter so neither host can reach it. I ruled out DEN-LT-1041 (that\'s just the benign EDR beacon to halberd-cloud). Escalating both hosts to CIRT as one incident and flagging the EDR coverage gap.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Found the quiet second victim, understood why EDR missed it, contained correctly, and avoided the benign red herring.' },
    { id: 'r_early', text: 'Confirmed 1042 is the only host — told Desktop to reimage it, closing the hunt.', scores: { communication: 0.2, process: 0.1, security: 0.2 }, feedback: 'You stopped at the alert. A second host was beaconing the whole time; eradicating one leaves the attacker resident.' },
    { id: 'r_partial', text: 'Blocked the C2 IP at the firewall — that cuts them off, done.', scores: { communication: 0.4, technical: 0.4 }, feedback: 'A perimeter block helps but you left a live loader with logon persistence on 1070 and its stolen credentials unreset.' },
  ],
  notesRubric: [
    { label: 'the pivot and the second victim found', pattern: /45\.146\.164\.90|pivot|second host|1070|jwebb|two hosts/i },
    { label: 'why EDR missed it (agent offline)', pattern: /agent offline|edr.*offline|coverage gap|no agent|tamper/i },
    { label: 'containment of both + C2 block, benign host ruled out', pattern: /isolat|block|c2|halberd|ruled out|both hosts/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Threat Hunt - C2 Scoping', resolutionCode: 'Second victim found and contained; C2 blocked' },
  categoryAccept: ['hunt', 'c2', 'scoping', 'malware'],
  resolutionCodeAccept: ['second', 'contain', 'c2', 'hunt', 'block'],
  hints: [
    'The task is to scope, not to re-confirm the known host. Pivot on the C2 IP across ALL logs.',
    'Two internal hosts talk to 45.146.164.90. One is the known 1042; find the other.',
    'DEN-LT-1070 never alerted because its EDR agent is offline. That is your coverage gap.',
    'One host talking to 34.117.59.81 is just the benign Halberd EDR beacon — do not isolate it. Contain 1070 (triage first), reset jwebb, block the C2.',
  ],
  debrief: 'Scoping before eradication is the difference between closing an incident and reopening it. Pivoting on the confirmed C2 indicator across the estate reveals a second victim that never generated an alert because its EDR agent was offline — exactly the kind of gap hunting exists to catch. The discipline points: collect triage before isolating, contain the real second host, block the shared C2 so nothing else can reach it, and do not get baited into isolating the host that is merely beaconing to your own EDR cloud.',
};

// ---------------------------------------------------------------------------
// SOC2-03  Insider data exfiltration to personal cloud (nuance: HR/Legal)
// ---------------------------------------------------------------------------
const soc2_03: Scenario = {
  id: 'soc2-03',
  tier: 'soc2',
  title: 'Departing engineer uploading CAD files',
  category: 'Insider / DLP',
  difficulty: 5,
  estMinutes: 18,
  objective: 'Handle a suspected insider case: confirm the activity with evidence, preserve it, and loop in HR/Legal without tipping the subject — a very different playbook from external attacks.',
  intake: { kind: 'alert', alertId: 'ALT-50071' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50071', time: ago(40), severity: 'high', source: 'dlp',
      title: 'Large upload of Engineering CAD files to personal cloud storage by obennett',
      description: 'DLP flagged ~3.2 GB of SOLIDWORKS files from \\\\FS01\\Engineering uploaded to a personal Dropbox account from DEN-WS-2011 over the last day. obennett resigned last week (last day Friday).',
      host: 'DEN-WS-2011', user: 'obennett', indicators: ['dropbox.com', 'obennett'], mitre: ['T1567.002', 'T1052'], status: 'new', truth: 'true_positive',
    });
    const o = findUser(w, 'obennett')!;
    o.notes = 'Resignation submitted; last day this Friday. Manager: tbrandt.';
    const h = host(w, 'DEN-WS-2011');
    addLog(w, { time: ago(300), source: 'proxy', host: 'DEN-WS-2011', user: 'obennett', domain: 'dropbox.com', url: 'https://www.dropbox.com/upload', action: 'allow', dstPort: 443, message: 'PUT 3.2GB to personal Dropbox (files: *.SLDPRT, *.SLDASM)' });
    addLog(w, { time: ago(280), source: 'windows', host: 'DEN-WS-2011', user: 'obennett', action: 'file_access', message: 'Bulk read of \\\\FS01\\Engineering\\Projects\\Falcon (412 files) by obennett' });
    addLog(w, { time: ago(200), source: 'edr', host: 'DEN-WS-2011', user: 'obennett', action: 'usb', message: 'USB mass storage device connected (SanDisk 128GB); 2.1GB copied from Engineering share', process: 'explorer.exe' });
    // No external attacker; obennett's own account, own device, normal auth.
    o.recentSignIns = [{ time: ago(310), ip: h.ip, location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-WS-2011', mfa: 'satisfied' }];
    w.chat.push({ id: 'ch-tb', with: 'tbrandt', messages: [] });
  },
  contactWith: 'tbrandt',
  contact: [
    { id: 'mgr', question: 'Ask the manager (tbrandt) privately: is obennett authorized to take these files, and confirm the resignation.', answer: 'Tom Brandt: "No, absolutely not authorized to copy project files out. Yes, he resigned, last day Friday — going to a competitor, actually."', purpose: 'verify', reveals: 'unauthorized' },
    { id: 'confront', question: 'Message obennett directly and ask why he\'s uploading files.', answer: '(Careful: KB-0017 — do not tip off a suspected insider. Confronting him lets him destroy evidence or accelerate. This is HR/Legal-led.)', purpose: 'red_flag' },
    { id: 'scope_files', question: 'Determine what was taken (share, USB, cloud) from the logs', answer: 'Proxy: 3.2GB to personal Dropbox. EDR: 2.1GB to a USB stick. Windows: bulk read of the Falcon project (412 files).', purpose: 'clarify', reveals: 'scope' },
    { id: 'weather', question: 'Ask tbrandt about his weekend plans', answer: '"...I\'d rather focus on this."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb17', label: 'Read the CIRT notification matrix (KB-0017) for insider handling', match: { tool: 'kb', action: 'read', target: 'KB-0017' }, hint: 'Who must be involved when an employee is the suspect?' },
    { id: 'proxy', label: 'Confirmed the cloud upload in the proxy logs', match: [{ tool: 'siem', action: 'search', params: { q: /dropbox|obennett|upload/i } }, { tool: 'siem', action: 'pivot', params: { value: /obennett/ } }] },
    { id: 'usb', label: 'Found the USB exfiltration path in EDR logs', match: [{ tool: 'siem', action: 'search', params: { q: /usb|mass storage/i } }, { tool: 'edr', action: 'view_host', target: 'DEN-WS-2011' }], hint: 'Cloud was not the only channel.' },
    { id: 'mgr_confirm', label: 'Confirmed with the manager that it is unauthorized + the resignation', match: { tool: 'chat', action: 'send', target: 'tbrandt' } },
  ],
  required: [
    { id: 'preserve', label: 'Preserved evidence (triage the host, legal hold) before any cleanup', match: [{ tool: 'edr', action: 'collect_triage', target: 'DEN-WS-2011' }], skill: 'process' },
    { id: 'block_and_watch', label: 'Blocked further exfil (proxy block / isolate) without alerting the user', match: [{ tool: 'perimeter', action: 'block', target: /dropbox/ }, { tool: 'edr', action: 'isolate', target: 'DEN-WS-2011' }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'confront', label: 'Confronted obennett / disabled his account overtly', why: 'KB-0017: do not tip off a suspected insider. A visible action (message, sudden disable) invites evidence destruction and is HR/Legal\'s call on timing. Contain quietly and hand to CIRT/HR/Legal.', match: [{ tool: 'chat', action: 'send', target: 'obennett' }, { tool: 'directory', action: 'disable', target: 'obennett' }], skill: 'security', penalty: 0.4 },
    { id: 'no_legal', label: 'Handled it as routine malware and closed without HR/Legal', why: 'Insider IP theft by a departing employee going to a competitor is an HR and Legal matter with potential litigation hold — not a reimage-and-close.', match: { tool: 'ticket', action: 'reply', target: 'r_routine' }, skill: 'process', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed insider data theft: obennett (resigning Friday, headed to a competitor per his manager) copied ~3.2 GB of Falcon-project CAD files to personal Dropbox AND ~2.1 GB to a USB stick from the Engineering share — his manager confirms this is unauthorized. I preserved evidence (host triage + placing a legal hold) BEFORE touching anything, and quietly blocked Dropbox and isolated the workstation to stop further exfil without alerting him. Escalating to CIRT as an insider case and notifying HR and Legal — timing of any confrontation or account disable is their call, not ours. I did NOT contact obennett.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Evidence-first, quiet containment, and the correct HR/Legal-led insider path.' },
    { id: 'r_routine', text: 'Cleaned the host, revoked the Dropbox session, reimaged it and closed as a policy violation.', scores: { communication: 0.3, process: 0.1, security: 0.2 }, feedback: 'Reimaging destroys evidence and closing without HR/Legal fumbles a potential IP-theft legal case.' },
    { id: 'r_confront', text: 'Messaged obennett to stop uploading and disabled his account immediately.', scores: { communication: 0.3, security: 0.2 }, feedback: 'Tips off the suspect, risks evidence destruction, and pre-empts HR/Legal\'s decision on timing.' },
  ],
  notesRubric: [
    { label: 'the confirmed activity and channels (Dropbox + USB, unauthorized)', pattern: /dropbox|usb|3\.2|2\.1|cad|solidworks|falcon|unauthoriz/i },
    { label: 'evidence preserved before action (triage / legal hold)', pattern: /preserv|triage|legal hold|evidence|before/i },
    { label: 'HR/Legal engaged and the "do not tip off" handling', pattern: /hr|legal|do not|didn.t contact|quiet|without alert|insider/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Insider - Data Exfiltration', resolutionCode: 'Evidence preserved; contained; HR/Legal + CIRT engaged' },
  categoryAccept: ['insider', 'exfil', 'dlp', 'data'],
  resolutionCodeAccept: ['insider', 'preserve', 'legal', 'contain', 'cirt'],
  hints: [
    'This is an insider case, not an external attack — read KB-0017 for who must be involved.',
    'Confirm the activity across channels: proxy (Dropbox) AND EDR (USB). Confirm with the manager it is unauthorized.',
    'Preserve evidence first (triage, legal hold). Then contain quietly — block Dropbox, isolate the host.',
    'Do NOT message or overtly disable obennett; timing is HR/Legal\'s call. Escalate to CIRT and notify HR + Legal.',
  ],
  debrief: 'Insider cases invert the external playbook. The subject has legitimate access and a login that looks normal, so "compromise" signals are absent; the tells are behavioral (bulk reads, personal cloud, USB, a resignation to a competitor). Two rules dominate: preserve evidence before you touch anything because this may become litigation, and do not tip off the subject — a premature message or account disable can trigger evidence destruction and steps on HR/Legal\'s timing. Quiet containment (block the channel, isolate the host) plus a clean handoff to CIRT/HR/Legal is the win.',
};

export const SOC2_SCENARIOS: Scenario[] = [soc2_01, soc2_02, soc2_03];
