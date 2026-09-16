import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, addAlert, addMail, setConn } from './helpers';

// ---------------------------------------------------------------------------
// SOC2-04  Lateral movement via PsExec/WMI from patient zero (scope the spread)
// ---------------------------------------------------------------------------
const soc2_04: Scenario = {
  id: 'soc2-04',
  tier: 'soc2',
  title: 'Patient zero is spreading — where did the account go?',
  category: 'Threat Hunting',
  difficulty: 4,
  estMinutes: 18,
  objective: 'Take a single infected endpoint and pivot on the compromised account across the estate to map lateral movement (PsExec/WMI), then contain every host it reached — scoping BEFORE eradication.',
  intake: { kind: 'alert', alertId: 'ALT-50081' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50081', time: ago(25), severity: 'high', source: 'edr',
      title: 'Credential theft + remote service creation from DEN-LT-1041 (jmorales)',
      description: 'Halberd flagged a stealer on DEN-LT-1041 (jmorales, AP) that dumped LSASS, followed by PSEXESVC service creation on remote hosts using jmorales\'s credentials. Task: scope how far the account moved before anyone eradicates.',
      host: 'DEN-LT-1041', user: 'jmorales', indicators: ['PSEXESVC', 'jmorales', '185.220.101.47'], mitre: ['T1021.002', 'T1570', 'T1569.002', 'T1003.001'], status: 'new', truth: 'true_positive',
    });
    // Patient zero: DEN-LT-1041, loader beaconing out + LSASS dump
    const pz = host(w, 'DEN-LT-1041');
    pz.edrAgent = 'healthy';
    addProc(pz, { pid: 7420, name: 'svchost-update.exe', user: 'KESTREL\\jmorales', cpu: 3, mem: 60, path: 'C:\\Users\\jmorales\\AppData\\Roaming\\svchost-update.exe', signed: false, hash: 'ab77...9f', started: ago(130), parentPid: 3610 });
    setConn(pz, [{ proto: 'TCP', local: `${pz.ip}:51022`, remote: '185.220.101.47:443', state: 'ESTABLISHED', pid: 7420 }]);
    addEvent(pz, { id: 4688, time: ago(120), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A new process has been created: PsExec.exe (KESTREL\\jmorales) -> \\\\DEN-LT-1042 -accepteula cmd' });
    addLog(w, { time: ago(128), source: 'firewall', host: 'DEN-LT-1041', srcIp: pz.ip, dstIp: '185.220.101.47', dstPort: 443, action: 'allow', message: `ALLOW ${pz.ip} -> 185.220.101.47:443 (beacon, repeating)` });

    // Spread host 1: DEN-LT-1042 (bpatel) via PsExec
    const v1 = host(w, 'DEN-LT-1042');
    addProc(v1, { pid: 5210, name: 'PSEXESVC.exe', user: 'SYSTEM', cpu: 1, mem: 20, path: 'C:\\Windows\\PSEXESVC.exe', signed: false, hash: 'e0b1...42', started: ago(78) });
    addProc(v1, { pid: 5260, name: 'svchost-update.exe', user: 'KESTREL\\jmorales', cpu: 2, mem: 55, path: 'C:\\Users\\jmorales\\AppData\\Roaming\\svchost-update.exe', signed: false, hash: 'ab77...9f', started: ago(76), parentPid: 5210 });
    addEvent(v1, { id: 7045, time: ago(78), level: 'Information', source: 'Service Control Manager', log: 'System', message: 'A new service was installed: PSEXESVC (C:\\Windows\\PSEXESVC.exe), start=demand, account=LocalSystem' });

    // Spread host 2: DEN-WS-2010 (nfoster) via WMI
    const v2 = host(w, 'DEN-WS-2010');
    addProc(v2, { pid: 6110, name: 'svchost-update.exe', user: 'KESTREL\\jmorales', cpu: 2, mem: 52, path: 'C:\\Users\\jmorales\\AppData\\Roaming\\svchost-update.exe', signed: false, hash: 'ab77...9f', started: ago(66), parentPid: 900 });
    addEvent(v2, { id: 4688, time: ago(68), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A new process has been created: WmiPrvSE.exe -> cmd.exe /c svchost-update.exe (KESTREL\\jmorales, remote WMI)' });

    // Auth logs: jmorales network logons (type 3) FROM patient zero into the two victims + the file share
    addLog(w, { time: ago(80), source: 'auth', host: 'DEN-LT-1042', user: 'jmorales', srcIp: pz.ip, action: 'logon', message: `4624 Logon type 3 (Network) jmorales from DEN-LT-1041 (${pz.ip}) -> DEN-LT-1042`, fields: { eventId: 4624, logonType: 3, source: 'DEN-LT-1041' } });
    addLog(w, { time: ago(70), source: 'auth', host: 'DEN-WS-2010', user: 'jmorales', srcIp: pz.ip, action: 'logon', message: `4624 Logon type 3 (Network) jmorales from DEN-LT-1041 (${pz.ip}) -> DEN-WS-2010`, fields: { eventId: 4624, logonType: 3, source: 'DEN-LT-1041' } });
    addLog(w, { time: ago(60), source: 'auth', host: 'DEN-FS01', user: 'jmorales', srcIp: pz.ip, action: 'logon', message: `4624 Logon type 3 (Network) jmorales -> \\\\DEN-FS01\\Finance from ${pz.ip} (bulk file listing)`, fields: { eventId: 4624, logonType: 3, source: 'DEN-LT-1041' } });
    addLog(w, { time: ago(78), source: 'windows', host: 'DEN-LT-1042', user: 'jmorales', action: 'service_install', message: '7045 Service PSEXESVC installed on DEN-LT-1042 (LocalSystem)' });
    addLog(w, { time: ago(68), source: 'windows', host: 'DEN-WS-2010', user: 'jmorales', action: 'process', message: '4688 Remote WMI process creation on DEN-WS-2010 (cmd.exe -> svchost-update.exe)' });

    // Red herring: mreyes doing a NORMAL admin network logon (patching) + benign DCOM warning
    addLog(w, { time: ago(90), source: 'auth', host: 'DEN-WS-2010', user: 'mreyes', srcIp: '10.10.20.121', action: 'logon', message: '4624 Logon type 3 (Network) mreyes from DEN-LT-1021 -> DEN-WS-2010 (scheduled patch run, authorized)', fields: { eventId: 4624, logonType: 3, source: 'DEN-LT-1021' } });
    addEvent(v1, { id: 10016, time: ago(100), level: 'Warning', source: 'DistributedCOM', log: 'System', message: 'DCOM 10016 local activation permission (benign, common).' });

    w.intel.push({ indicator: '185.220.101.47', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['c2', 'stealer'], detail: 'Known infostealer C2 / exfil node. Loader svchost-update.exe beacons here on 443.' });
    w.intel.push({ indicator: 'ab77...9f', type: 'hash', verdict: 'malicious', source: 'Sandbox', tags: ['stealer', 'loader'], detail: 'svchost-update.exe infostealer/loader. Dumps LSASS and self-copies via PsExec/WMI.' });
    w.chat.push({ id: 'ch-jm', with: 'jmorales', messages: [] });
  },
  contactWith: 'jmorales',
  contact: [
    { id: 'confirm', question: 'Ask jmorales: did you run any admin tools or connect to DEN-LT-1042 / DEN-WS-2010 today?', answer: 'Jenna: "No — I only work in the ERP client on my own laptop. I have no reason to connect to anyone else\'s machine."', purpose: 'verify', reveals: 'not-authorized' },
    { id: 'origin', question: 'Ask jmorales what she opened before the machine got slow.', answer: '"An invoice PDF from an email this morning. It asked me to enable content and then nothing happened."', purpose: 'clarify', reveals: 'initial-access' },
    { id: 'scope_q', question: 'Determine which hosts jmorales\'s account touched from the auth logs', answer: 'Type-3 logons from DEN-LT-1041 into DEN-LT-1042 and DEN-WS-2010, plus a bulk listing of \\\\DEN-FS01\\Finance.', purpose: 'clarify', reveals: 'spread' },
    { id: 'weather', question: 'Ask jmorales how her commute was.', answer: '"...fine? Can we focus on my laptop please?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the endpoint + scoping playbooks (KB-0015 / KB-0018)', match: [{ tool: 'kb', action: 'read', target: 'KB-0015' }, { tool: 'kb', action: 'read', target: 'KB-0018' }], weight: 0.5, hint: 'Scope before eradication — where does the KB say that?' },
    { id: 'tree', label: 'Reviewed patient-zero process tree (LSASS dump + PsExec)', match: [{ tool: 'edr', action: 'view_tree', target: 'DEN-LT-1041' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1041' }] },
    { id: 'pivot', label: 'Pivoted on jmorales\'s account across auth logs (found type-3 logons to other hosts)', match: [{ tool: 'siem', action: 'search', params: { q: /jmorales|4769|logon type 3|psexesvc/i } }, { tool: 'siem', action: 'pivot', params: { value: /jmorales/ } }], hint: 'Search the account, not just the alert host — where else did it log on (type 3)?' },
    { id: 'find_v1', label: 'Confirmed DEN-LT-1042 as a spread host (PSEXESVC service)', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-LT-1042' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1042' }] },
    { id: 'find_v2', label: 'Confirmed DEN-WS-2010 as a spread host (remote WMI)', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-WS-2010' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-WS-2010' }] },
    { id: 'intel', label: 'Confirmed the C2 IP / loader hash in intel', match: [{ tool: 'intel', action: 'lookup', target: '185.220.101.47' }, { tool: 'intel', action: 'lookup', target: 'ab77...9f' }] },
  ],
  required: [
    { id: 'triage_pz', label: 'Collected triage on patient zero before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1041' }, skill: 'process', before: 'isolate_pz' },
    { id: 'isolate_pz', label: 'Isolated patient zero (DEN-LT-1041)', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1041' }, skill: 'technical' },
    { id: 'triage_v1', label: 'Collected triage on DEN-LT-1042 before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1042' }, skill: 'process', before: 'isolate_v1' },
    { id: 'isolate_v1', label: 'Isolated the first spread host (DEN-LT-1042)', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1042' }, skill: 'technical' },
    { id: 'isolate_v2', label: 'Isolated the second spread host (DEN-WS-2010)', match: { tool: 'edr', action: 'isolate', target: 'DEN-WS-2010' }, skill: 'technical' },
    { id: 'reset', label: 'Reset the compromised account and revoked its sessions', match: [{ tool: 'directory', action: 'reset_password', target: 'jmorales' }, { tool: 'directory', action: 'revoke_sessions', target: 'jmorales' }], skill: 'security' },
    { id: 'block', label: 'Blocked the C2 IP at the perimeter', match: { tool: 'perimeter', action: 'block', target: '185.220.101.47' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'eradicate_early', label: 'Reimaged/closed patient zero before scoping the spread', why: 'KB-0018: scope BEFORE eradication. If you clean DEN-LT-1041 while jmorales\'s creds keep spawning PSEXESVC on 1042 and 2010, the attacker is still resident and re-enters within the hour.', match: [{ tool: 'incident', action: 'reimage', target: 'DEN-LT-1041' }, { tool: 'ticket', action: 'reply', target: 'r_eradicate' }], skill: 'process', penalty: 0.5 },
    { id: 'chase_benign', label: 'Contained the host mreyes patched (benign admin logon)', why: 'mreyes\'s type-3 logon to DEN-WS-2010 is an authorized scheduled patch run from an IT-Admin host, not the attacker. Isolating DEN-LT-1021 chases a false positive.', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1021' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'The stealer on DEN-LT-1041 (jmorales) dumped LSASS and used her credentials to move laterally: PSEXESVC on DEN-LT-1042 and remote WMI execution on DEN-WS-2010, plus a bulk listing of \\\\FS01\\Finance — three hosts, one account. I pivoted on the account across the auth logs to map that spread, collected triage and isolated all three hosts (patient zero first), reset jmorales and revoked her sessions, and blocked the C2 (185.220.101.47). I ruled out mreyes\'s type-3 logon as an authorized patch run. Escalating to CIRT as one incident so the credential reset and reimaging are coordinated before recovery.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Scoped the account across the estate, contained every reached host with triage-first, and avoided the benign admin red herring.' },
    { id: 'r_eradicate', text: 'Confirmed DEN-LT-1041 is infected — told Desktop to reimage it and closed the alert.', scores: { communication: 0.2, process: 0.1, security: 0.2 }, feedback: 'You eradicated patient zero without scoping. Two more hosts were running the loader under jmorales\'s creds; you will be back tomorrow.' },
    { id: 'r_partial', text: 'Isolated DEN-LT-1041 and blocked the C2 IP. Done.', scores: { communication: 0.4, technical: 0.4 }, feedback: 'A perimeter block helps, but 1042 and 2010 still hold the loader and jmorales\'s credentials were never reset.' },
  ],
  notesRubric: [
    { label: 'the technique (LSASS dump + PsExec/WMI lateral movement)', pattern: /psexec|psexesvc|wmi|lateral|logon type 3|lsass|4624/i },
    { label: 'the scope found (patient zero + two spread hosts / the account)', pattern: /1041|1042|2010|three hosts|two.*hosts|spread|jmorales|fs01/i },
    { label: 'containment: triage-first isolate all hosts + credential reset', pattern: /triage|isolat|reset|revoke|contain/i },
    { label: 'scope-before-eradicate / escalation to CIRT', pattern: /scope|before erad|cirt|escalat|block|185\.220\.101\.47/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Lateral Movement - PsExec/WMI', resolutionCode: 'Spread scoped to 3 hosts; contained; account reset; C2 blocked; CIRT engaged' },
  categoryAccept: ['lateral', 'movement', 'psexec'],
  resolutionCodeAccept: ['scope', 'spread', 'contain', 'lateral', 'cirt'],
  hints: [
    'The task is to scope the account, not just clean the alert host. Pivot on jmorales across the auth logs.',
    'Look for type-3 (network) logons FROM DEN-LT-1041 and remote service creation (PSEXESVC / WMI) on other hosts.',
    'jmorales\'s creds reached DEN-LT-1042 and DEN-WS-2010. mreyes\'s type-3 logon is a benign authorized patch run — do not contain it.',
    'Collect triage before isolating, contain all three hosts, reset + revoke jmorales, block the C2, and hand to CIRT. Do NOT reimage patient zero before scoping.',
  ],
  debrief: 'Lateral movement is why "clean the alerting host and close" fails. A stealer dumped credentials on patient zero and reused them via PsExec (a remote PSEXESVC service) and WMI to run the same loader on two more machines — visible only if you pivot on the ACCOUNT across the auth logs and hunt type-3 logons and remote service creation. The discipline: collect triage before isolating, contain every host the account reached, reset and revoke the credential itself (the real vector), block the C2, and escalate to CIRT so eradication and recovery happen after scoping — never before.',
};

// ---------------------------------------------------------------------------
// SOC2-05  Illicit OAuth app consent / cloud token abuse (O365)
// ---------------------------------------------------------------------------
const soc2_05: Scenario = {
  id: 'soc2-05',
  tier: 'soc2',
  title: 'A password reset won\'t save this mailbox',
  category: 'Cloud / Identity',
  difficulty: 4,
  estMinutes: 17,
  objective: 'Investigate a consent-phishing (illicit OAuth grant) case where the attacker holds a refresh token, not the password — and contain it the way tokens actually die: revoke sessions, remove the app and its persistence, then reset.',
  intake: { kind: 'alert', alertId: 'ALT-50082' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50082', time: ago(20), severity: 'high', source: 'cloud',
      title: 'Risky OAuth consent granted by bpatel to unverified third-party app',
      description: 'Cloud identity flagged bpatel granting delegated consent (Mail.ReadWrite, offline_access) to an unverified publisher app "PDF Invoice Reader Pro" shortly after a phishing email. The app is now reading mail and has created an inbox rule via Graph.',
      user: 'bpatel', indicators: ['PDF Invoice Reader Pro', 'invoice-reader-app.co'], mitre: ['T1528', 'T1114.002', 'T1098.003'], status: 'new', truth: 'true_positive',
    });
    const b = findUser(w, 'bpatel')!;
    // Password NOT compromised: sign-ins are clean and normal.
    b.recentSignIns = [
      { time: ago(75), ip: '10.10.20.42', location: 'Denver, US', app: 'WorkSuite Mail', result: 'success', device: 'DEN-LT-1042', mfa: 'satisfied' },
      { time: ago(300), ip: '10.10.20.42', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1042', mfa: 'satisfied' },
    ];
    // The phishing email carrying the consent link
    addMail(w, {
      id: 'MSG-8201', time: ago(85), from: 'WorkSuite Docs <noreply@invoice-reader-app.co>', to: ['bpatel@kestreldynamics.com'],
      subject: 'Action required: review a shared invoice',
      status: 'delivered' as const,
      headers: { from: 'WorkSuite Docs <noreply@invoice-reader-app.co>', returnPath: 'bounce@invoice-reader-app.co', receivedFrom: 'mail.invoice-reader-app.co [45.61.136.22]', spf: 'pass', dkim: 'pass', dmarc: 'pass', messageId: '<8201@invoice-reader-app.co>' },
      body: 'A supplier shared an invoice with you. Click to connect PDF Invoice Reader Pro to your mailbox and view it.',
      urls: ['https://login.worksuite-mail.net/oauth2/authorize?client_id=9f3c2b&scope=Mail.ReadWrite+offline_access&redirect_uri=https://invoice-reader-app.co/cb'], phishing: true,
    });
    // Cloud audit trail: consent -> mail read -> inbox rule creation, all via the app / Graph
    addLog(w, { time: ago(70), source: 'cloud', user: 'bpatel', srcIp: '10.10.20.42', action: 'oauth_consent', message: 'Delegated consent GRANTED by bpatel to app "PDF Invoice Reader Pro" (appId 9f3c2b, unverified publisher) scopes: Mail.ReadWrite, offline_access', fields: { app: 'PDF Invoice Reader Pro', appId: '9f3c2b', scopes: 'Mail.ReadWrite offline_access', publisher: 'unverified' } });
    addLog(w, { time: ago(64), source: 'cloud', user: 'bpatel', srcIp: '45.61.136.22', action: 'mail_access', message: 'App "PDF Invoice Reader Pro" read 318 mailbox items via Graph from 45.61.136.22 (Netherlands)', fields: { app: 'PDF Invoice Reader Pro', items: 318 } });
    addLog(w, { time: ago(62), source: 'cloud', user: 'bpatel', srcIp: '45.61.136.22', action: 'inbox_rule', message: 'App created inbox rule "Invoices" via Graph: move messages containing invoice/payment/wire to RSS Feeds and mark as read', fields: { rule: 'Invoices' } });
    addLog(w, { time: ago(40), source: 'cloud', user: 'bpatel', srcIp: '45.61.136.22', action: 'mail_send', message: 'App sent 1 message on behalf of bpatel (vendor bank-change request to jmorales)', fields: { app: 'PDF Invoice Reader Pro' } });
    // The malicious inbox rule on the mailbox
    const mbx = w.mailboxes.find((m) => m.user === 'bpatel')!;
    mbx.rules.push({ name: 'Invoices', condition: "subject/body contains 'invoice','payment','wire'", action: 'Move to RSS Feeds; mark as read', enabled: true, created: ago(62), suspicious: true });
    // Red herring: a legitimate, previously authorized OAuth app (approved by IT) — do NOT revoke this one.
    addLog(w, { time: daysAgo(40), source: 'cloud', user: 'bpatel', srcIp: '10.10.20.42', action: 'oauth_consent', message: 'Delegated consent GRANTED to "Zoom for Outlook" (verified publisher, IT-approved catalog app) scopes: Calendars.Read', fields: { app: 'Zoom for Outlook', publisher: 'verified' } });
    w.intel.push({ indicator: 'invoice-reader-app.co', type: 'domain', verdict: 'malicious', source: 'threat feed', tags: ['consent-phishing', 'oauth'], detail: 'Consent-phishing infrastructure. Redirect/callback domain for the rogue "PDF Invoice Reader Pro" OAuth app.' });
    w.intel.push({ indicator: '45.61.136.22', type: 'ip', verdict: 'malicious', source: 'threat feed', tags: ['oauth', 'graph-abuse'], detail: 'Hosting IP (NL) used by the rogue app to call Microsoft Graph against consented mailboxes.' });
    w.chat.push({ id: 'ch-bp', with: 'bpatel', messages: [] });
  },
  contactWith: 'bpatel',
  contact: [
    { id: 'confirm', question: 'Ask bpatel: did you connect a "PDF Invoice Reader" app to your mailbox today?', answer: 'Bhavik: "There was an invoice email — I clicked to view it and a Microsoft page asked to allow an app, so I clicked accept. Was that wrong?"', purpose: 'verify', reveals: 'consent' },
    { id: 'rule_q', question: 'Ask bpatel if he created a rule that files invoices into RSS Feeds.', answer: '"No, I\'ve never made an inbox rule in my life."', purpose: 'clarify', reveals: 'rule' },
    { id: 'pw_q', question: 'Ask bpatel if he typed his password into any page.', answer: '"No — it was the normal Microsoft consent screen, it didn\'t ask for my password again."', purpose: 'clarify', reveals: 'token-not-password' },
    { id: 'weather', question: 'Ask bpatel about his lunch plans.', answer: '"...not really thinking about lunch right now."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the sign-in/OAuth and triage playbooks (KB-0016 / KB-0013)', match: [{ tool: 'kb', action: 'read', target: 'KB-0016' }, { tool: 'kb', action: 'read', target: 'KB-0013' }], weight: 0.5, hint: 'Which signal in KB-0016 is an OAuth app consent?' },
    { id: 'consent', label: 'Found the illicit consent grant + Graph mail access in the cloud logs', match: [{ tool: 'siem', action: 'search', params: { q: /oauth|consent|graph|invoice reader|9f3c2b/i } }, { tool: 'siem', action: 'pivot', params: { value: /bpatel/ } }], hint: 'The trail is in the cloud audit logs: consent -> mail read -> rule.' },
    { id: 'rule', label: 'Found the attacker inbox rule in the mailbox', match: { tool: 'mail', action: 'view_mailbox', target: 'bpatel' }, hint: 'Attackers hide their tracks — check the mailbox rules.' },
    { id: 'signins', label: 'Confirmed sign-ins are clean (password not the vector — a token is)', match: { tool: 'directory', action: 'view_signins', target: 'bpatel' }, hint: 'If the password were stolen you\'d see bad sign-ins. Do you?' },
    { id: 'intel', label: 'Confirmed the app callback domain / IP in intel', match: [{ tool: 'intel', action: 'lookup', target: 'invoice-reader-app.co' }, { tool: 'intel', action: 'lookup', target: '45.61.136.22' }] },
  ],
  required: [
    { id: 'revoke', label: 'Revoked the user\'s sessions/tokens (kills the OAuth refresh token)', match: { tool: 'directory', action: 'revoke_sessions', target: 'bpatel' }, skill: 'security' },
    { id: 'remove_rule', label: 'Removed the malicious inbox rule', match: { tool: 'mail', action: 'remove_rule', target: 'bpatel' }, skill: 'technical' },
    { id: 'reset', label: 'Reset the user\'s password (after revoking sessions)', match: { tool: 'directory', action: 'reset_password', target: 'bpatel' }, skill: 'security', after: 'revoke' },
    { id: 'block', label: 'Blocked the rogue app\'s domain at the gateway/proxy', match: { tool: 'perimeter', action: 'block', target: /invoice-reader-app/ }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'pw_only', label: 'Treated a password reset as the fix and closed', why: 'Consent phishing steals an OAuth refresh token, not the password. A password reset does NOT invalidate an existing refresh token — the app keeps reading and sending mail until you revoke sessions AND remove the app consent/rule.', match: { tool: 'ticket', action: 'reply', target: 'r_pwonly' }, skill: 'security', penalty: 0.5 },
    { id: 'revoke_legit', label: 'Revoked/blocked the legitimate IT-approved app', why: '"Zoom for Outlook" is a verified-publisher, IT-approved catalog app with a benign scope (Calendars.Read). Treating it as malicious breaks a sanctioned integration.', match: { tool: 'perimeter', action: 'block', target: /zoom/i }, skill: 'process', penalty: 0.25 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is consent phishing: bpatel was tricked into granting an unverified app "PDF Invoice Reader Pro" delegated Mail.ReadWrite + offline_access, so the attacker holds a refresh token — his password was never compromised (sign-ins are clean). The app read 318 items, created a hide-the-evidence inbox rule, and already sent a vendor bank-change note to AP. I revoked bpatel\'s sessions to kill the token, removed the malicious rule, then reset his password, and blocked invoice-reader-app.co at the gateway. I left the IT-approved Zoom app alone. Escalating to CIRT to get the app consent globally revoked/quarantined and to check other users who got the same lure.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Correct diagnosis (token, not password), token-killing containment in the right order, rule removed, benign app spared.' },
    { id: 'r_pwonly', text: 'Reset bpatel\'s password and told him to pick something stronger. Closed.', scores: { communication: 0.3, security: 0.1 }, feedback: 'The refresh token survives a password reset. The app is still reading and sending mail; you have to revoke sessions and remove the consent/rule.' },
    { id: 'r_ignore', text: 'Sign-ins are clean and no bad logins — looks like a false positive. Closing.', scores: { communication: 0.2, security: 0.1 }, feedback: 'Clean sign-ins are exactly the signature of token abuse. The Graph audit trail shows active mail theft.' },
    { id: 'r_partial', text: 'Revoked bpatel\'s sessions — that cuts the token, we\'re good.', scores: { communication: 0.4, security: 0.4 }, feedback: 'Revoking is the key step, but the malicious inbox rule and the app grant persist; remove the rule and get the consent revoked, and block the domain.' },
  ],
  notesRubric: [
    { label: 'the diagnosis (illicit OAuth consent / token abuse, not password theft)', pattern: /oauth|consent|token|refresh|graph|not.*password|delegated/i },
    { label: 'what the app did (mail read + inbox rule + send)', pattern: /inbox rule|rss|read.*mail|318|sent|invoice/i },
    { label: 'containment: revoke sessions + remove rule + reset (order)', pattern: /revoke|remove rule|reset|revok.*before|session/i },
    { label: 'block the app domain + escalate CIRT', pattern: /block|invoice-reader-app|app consent|cirt|escalat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Cloud - OAuth Consent', resolutionCode: 'Sessions revoked; rule removed; password reset; app domain blocked; CIRT to revoke consent' },
  categoryAccept: ['oauth', 'cloud', 'consent'],
  resolutionCodeAccept: ['revoke', 'consent', 'token', 'rule', 'cirt'],
  hints: [
    'Read the cloud audit trail: a consent grant, then Graph mail reads and an inbox rule from a foreign IP.',
    'Check the sign-ins — they are clean. This is a stolen OAuth token, not a stolen password.',
    'A password reset does not kill a refresh token. Revoke sessions FIRST, then remove the rule and reset.',
    'Block invoice-reader-app.co, leave the IT-approved Zoom app alone, and escalate to CIRT to revoke the app consent org-wide.',
  ],
  debrief: 'Consent phishing is the identity attack that laughs at password resets. The victim is walked through a real Microsoft consent screen and grants a rogue app delegated mail scopes plus offline_access, handing the attacker a refresh token that lives independently of the password. The tells invert the usual playbook: sign-ins are clean, but the cloud audit log shows an app reading mail, creating a hide-the-evidence rule, and sending on the user\'s behalf. Containment must target the token: revoke sessions, remove the inbox rule and the app grant, then reset — and block the app infrastructure. Resetting the password alone leaves the attacker fully inside.',
};

// ---------------------------------------------------------------------------
// SOC2-06  Web application attack against the ERP portal (SQLi -> webshell)
// ---------------------------------------------------------------------------
const soc2_06: Scenario = {
  id: 'soc2-06',
  tier: 'soc2',
  title: 'Did the SQLi against the ERP actually land?',
  category: 'Web / Application Attack',
  difficulty: 4,
  estMinutes: 17,
  objective: 'Triage a burst of web-application attacks against a public-facing ERP server and answer the only question that matters — did any of it succeed — before deciding it is noise.',
  intake: { kind: 'alert', alertId: 'ALT-50083' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50083', time: ago(22), severity: 'high', source: 'ids',
      title: 'SQL injection burst against DEN-APP01 (Kestrel ERP) from 194.26.135.60',
      description: 'The WAF/IDS logged a sustained SQL-injection campaign against the ERP portal on DEN-APP01 from external IP 194.26.135.60. Most requests were blocked, but several returned HTTP 200. Determine whether the app was actually exploited.',
      host: 'DEN-APP01', indicators: ['194.26.135.60', 'sqli', '/erp/uploads/x.aspx'], mitre: ['T1190', 'T1505.003'], status: 'new', truth: 'true_positive',
    });
    // Web logs: mostly blocked SQLi, but a few 200s + a dropped webshell + command exec = SUCCESS.
    addLog(w, { time: ago(70), source: 'web', host: 'DEN-APP01', srcIp: '194.26.135.60', url: "/erp/login.aspx?u=admin'--", action: 'block', message: "403 WAF blocked SQLi /erp/login.aspx?u=admin'--", fields: { status: 403 } });
    addLog(w, { time: ago(69), source: 'web', host: 'DEN-APP01', srcIp: '194.26.135.60', url: "/erp/report.aspx?id=1' OR '1'='1", action: 'block', message: "403 WAF blocked SQLi /erp/report.aspx?id=1' OR '1'='1", fields: { status: 403 } });
    addLog(w, { time: ago(66), source: 'web', host: 'DEN-APP01', srcIp: '194.26.135.60', url: '/erp/report.aspx?id=1;WAITFOR DELAY \'0:0:5\'--', action: 'allow', message: '200 response delayed ~5s (time-based blind SQLi succeeded)', fields: { status: 200, ms: 5030 } });
    addLog(w, { time: ago(60), source: 'web', host: 'DEN-APP01', srcIp: '194.26.135.60', url: '/erp/report.aspx?id=1 UNION SELECT username,password_hash FROM dbo.users--', action: 'allow', message: '200 15234 bytes returned (union select — possible credential dump)', fields: { status: 200, bytes: 15234 } });
    addLog(w, { time: ago(54), source: 'web', host: 'DEN-APP01', srcIp: '194.26.135.60', url: '/erp/uploads/x.aspx', action: 'allow', message: '200 POST /erp/uploads/x.aspx (unexpected .aspx written to uploads dir)', fields: { status: 200, method: 'POST' } });
    addLog(w, { time: ago(48), source: 'web', host: 'DEN-APP01', srcIp: '194.26.135.60', url: '/erp/uploads/x.aspx?cmd=whoami', action: 'allow', message: '200 webshell output: nt authority\\network service', fields: { status: 200 } });
    addLog(w, { time: ago(45), source: 'web', host: 'DEN-APP01', srcIp: '194.26.135.60', url: '/erp/uploads/x.aspx?cmd=net+user+kadmin+P%40ss+/add', action: 'allow', message: '200 webshell output: command completed successfully', fields: { status: 200 } });
    // Server-side confirmation: w3wp spawned cmd/whoami; webshell process tree on DEN-APP01
    const app = w.servers.find((s) => s.id === 'DEN-APP01')!;
    app.processes = [
      { pid: 4, name: 'System', user: 'SYSTEM', cpu: 0.1, mem: 8, signed: true },
      { pid: 980, name: 'sqlservr.exe', user: 'NT SERVICE\\MSSQLSERVER', cpu: 6, mem: 2200, path: 'C:\\Program Files\\Microsoft SQL Server\\MSSQL16\\Binn\\sqlservr.exe', signed: true },
      { pid: 2140, name: 'w3wp.exe', user: 'IIS APPPOOL\\KestrelERP', cpu: 4, mem: 640, path: 'C:\\Windows\\System32\\inetsrv\\w3wp.exe', signed: true, cmdline: 'w3wp.exe -ap "KestrelERP"' },
      { pid: 6620, name: 'cmd.exe', user: 'NT AUTHORITY\\NETWORK SERVICE', cpu: 0.2, mem: 6, path: 'C:\\Windows\\System32\\cmd.exe', parentPid: 2140, signed: true, cmdline: 'cmd.exe /c net user kadmin P@ss /add', started: ago(45) },
      { pid: 6680, name: 'whoami.exe', user: 'NT AUTHORITY\\NETWORK SERVICE', cpu: 0, mem: 3, path: 'C:\\Windows\\System32\\whoami.exe', parentPid: 2140, signed: true, started: ago(48) },
    ];
    app.events.push(
      { id: 4720, time: ago(45), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A user account was created: kadmin (by NETWORK SERVICE via w3wp.exe child cmd.exe)' },
      { id: 4688, time: ago(48), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'New process w3wp.exe -> cmd.exe (webshell x.aspx executing OS commands)' },
    );
    // Red herring: the AUTHORIZED weekly vuln scanner also probes the app (benign 200s).
    addLog(w, { time: ago(90), source: 'web', host: 'DEN-APP01', srcIp: '10.10.10.70', url: '/erp/login.aspx', action: 'allow', message: '200 authenticated scan (svc_scanner, authorized weekly Nessus scan)', fields: { status: 200 } });
    addLog(w, { time: ago(89), source: 'web', host: 'DEN-APP01', srcIp: '10.10.10.70', url: '/erp/version', action: 'allow', message: '200 version probe (10.10.10.70 vuln scanner appliance)', fields: { status: 200 } });
    w.intel.push({ indicator: '194.26.135.60', type: 'ip', verdict: 'malicious', source: 'threat feed', tags: ['web-attack', 'sqli', 'exploitation'], detail: 'Known web-exploitation host. Automated SQLi + webshell tooling against internet-facing apps.' });
  },
  evidence: [
    { id: 'kb', label: 'Reviewed the endpoint/exploitation + triage playbooks (KB-0015 / KB-0013)', match: [{ tool: 'kb', action: 'read', target: 'KB-0015' }, { tool: 'kb', action: 'read', target: 'KB-0013' }], weight: 0.5 },
    { id: 'weblogs', label: 'Analyzed the web logs and saw the 200-status SQLi/webshell requests', match: [{ tool: 'siem', action: 'search', params: { q: /sqli|union select|x\.aspx|194\.26\.135\.60|erp/i } }, { tool: 'siem', action: 'pivot', params: { value: /194\.26\.135\.60/ } }], hint: 'Do not stop at the blocked 403s — look for the requests that returned 200.' },
    { id: 'server', label: 'Confirmed exploitation on the server (w3wp -> cmd webshell, rogue kadmin)', match: [{ tool: 'server', action: 'view_processes', target: 'DEN-APP01' }, { tool: 'server', action: 'view_events', target: 'DEN-APP01' }], hint: 'A web server does not normally spawn cmd.exe. Check the process tree and Security log.' },
    { id: 'intel', label: 'Confirmed the source IP is a known exploitation host', match: { tool: 'intel', action: 'lookup', target: '194.26.135.60' } },
    { id: 'rule_out', label: 'Distinguished the authorized vuln scanner (10.10.10.70) from the attacker', match: { tool: 'intel', action: 'lookup', target: '10.10.10.70' }, weight: 0.5 },
  ],
  required: [
    { id: 'inspect', label: 'Inspected the server to determine if it was actually exploited', match: { tool: 'server', action: 'view_processes', target: 'DEN-APP01' }, skill: 'investigation', before: 'block' },
    { id: 'block', label: 'Blocked the attacker source IP at the perimeter', match: { tool: 'perimeter', action: 'block', target: '194.26.135.60' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'close_noise', label: 'Closed as scanner noise / false positive without checking for success', why: 'Several SQLi requests returned HTTP 200, a webshell (x.aspx) was written, and it executed OS commands and created a rogue local account. Classifying this as noise leaves an actively exploited, internet-facing ERP server compromised.', match: { tool: 'ticket', action: 'reply', target: 'r_noise' }, skill: 'security', penalty: 0.5 },
    { id: 'block_scanner', label: 'Blocked the authorized vulnerability scanner', why: '10.10.10.70 is the authorized internal Nessus appliance doing its weekly ERP scan. Blocking it breaks vulnerability management and is a false-positive containment.', match: { tool: 'perimeter', action: 'block', target: '10.10.10.70' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'The SQLi against the ERP portal on DEN-APP01 landed — this is not noise. Most attempts were WAF-blocked, but a time-based blind payload succeeded, a UNION SELECT pulled ~15 KB (likely the users table with password hashes), and the attacker then wrote a webshell (x.aspx) that ran OS commands and created a rogue local account "kadmin" — confirmed on the server by w3wp.exe spawning cmd.exe and a 4720 account-creation event. I blocked the source IP (194.26.135.60) at the perimeter and ruled out the internal Nessus scanner (10.10.10.70). Escalating to CIRT and Sysadmin: this server needs to be pulled for forensics/rebuild, the DB credentials rotated, the rogue account removed, and the app patched. Severity high, true positive.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Answered the real question (did it succeed?), proved compromise on the server, blocked the attacker, spared the scanner, and escalated the server correctly.' },
    { id: 'r_noise', text: 'The WAF blocked the SQLi and the scanner generates this kind of traffic weekly — closing as false positive / noise.', scores: { communication: 0.2, security: 0.1 }, feedback: 'You never checked the 200s or the server. A webshell is live and a rogue admin account exists; this is a confirmed compromise, not noise.' },
    { id: 'r_blockonly', text: 'Blocked 194.26.135.60 at the firewall — attacker is cut off, done.', scores: { communication: 0.4, technical: 0.4 }, feedback: 'The perimeter block is right, but the webshell, the rogue kadmin account, and possible stolen DB hashes remain on a production server. Escalate it.' },
  ],
  notesRubric: [
    { label: 'the attack (SQLi against the ERP / DEN-APP01)', pattern: /sqli|sql injection|union select|erp|app01|194\.26\.135\.60/i },
    { label: 'proof it SUCCEEDED (200s, webshell, rogue account)', pattern: /200|webshell|x\.aspx|kadmin|4720|w3wp|exploited|succeed/i },
    { label: 'containment: blocked source + escalate server to CIRT/sysadmin', pattern: /block|cirt|sysadmin|rebuild|forensic|escalat/i },
    { label: 'ruled out the authorized scanner', pattern: /scanner|nessus|10\.10\.10\.70|authorized|ruled out/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Web - Application Attack', resolutionCode: 'Exploitation confirmed (webshell); source blocked; server escalated for rebuild' },
  categoryAccept: ['web', 'application', 'attack'],
  resolutionCodeAccept: ['exploit', 'webshell', 'block', 'sqli', 'cirt'],
  hints: [
    'The alert admits most requests were blocked but some returned 200. Those are your lead — do not close on the 403s.',
    'Look at the successful requests: time-based blind SQLi, a UNION SELECT, then an x.aspx upload and ?cmd= commands.',
    'Confirm on the server: w3wp.exe spawning cmd.exe and a 4720 event creating "kadmin" prove the webshell ran.',
    'Block 194.26.135.60, leave the internal Nessus scanner (10.10.10.70) alone, and escalate the server to CIRT/Sysadmin for forensics and rebuild.',
  ],
  debrief: 'Web-attack alerts are where analysts get lulled: the WAF blocks the noisy majority, so it is tempting to close as "attempted, blocked." But the job is to answer whether anything landed. Here the 200-status responses tell the story — a time-based blind payload, a UNION SELECT that returned data, then a webshell upload that executed commands and created a rogue admin account, all corroborated on the server by w3wp.exe spawning cmd.exe and a 4720 event. A public-facing app server with a webshell is a confirmed compromise: block the source, rule out the authorized scanner, and escalate the server for forensics and rebuild rather than reclassifying real exploitation as noise.',
};

// ---------------------------------------------------------------------------
// SOC2-07  Kerberoasting / service-account abuse
// ---------------------------------------------------------------------------
const soc2_07: Scenario = {
  id: 'soc2-07',
  tier: 'soc2',
  title: 'A service account asking for a lot of tickets',
  category: 'Identity / Kerberoasting',
  difficulty: 5,
  estMinutes: 19,
  objective: 'Recognize Kerberoasting hiding inside "normal" service-account traffic, understand why an over-privileged, no-MFA service account is the prize, and rotate the credential and contain the harvesting host without breaking production.',
  intake: { kind: 'alert', alertId: 'ALT-50084' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50084', time: ago(18), severity: 'high', source: 'siem',
      title: 'Anomalous burst of RC4 Kerberos service-ticket requests for svc_scanner',
      description: 'The SIEM correlated a burst of Event 4769 (Kerberos service ticket) requests for the SPN of svc_scanner, all RC4-encrypted (0x17), from a single user workstation in a two-minute window off-hours — a Kerberoasting signature. The account was then used at 03:xx.',
      user: 'svc_scanner', indicators: ['svc_scanner', '4769', 'DEN-LT-1060'], mitre: ['T1558.003', 'T1078.002'], status: 'new', truth: 'true_positive',
    });
    // Harvesting host: DEN-LT-1060 (ewright) running Rubeus
    const hh = host(w, 'DEN-LT-1060');
    addProc(hh, { pid: 7810, name: 'Rubeus.exe', user: 'KESTREL\\ewright', cpu: 5, mem: 40, path: 'C:\\Users\\ewright\\AppData\\Local\\Temp\\Rubeus.exe', signed: false, hash: 'd41c...77', started: ago(64) });
    addEvent(hh, { id: 4688, time: ago(64), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A new process has been created: Rubeus.exe kerberoast /outfile:hashes.txt (KESTREL\\ewright)' });
    // The RC4 4769 burst for svc_scanner from that host (Kerberoasting)
    for (let i = 0; i < 8; i++) {
      addLog(w, { time: ago(65 - i * 0.2), source: 'auth', host: 'DEN-DC01', user: 'ewright', srcIp: hh.ip, action: 'kerberos', message: `4769 Kerberos service ticket requested SPN=MSSQLSvc/svc_scanner enc=0x17 (RC4-HMAC) client=ewright from ${hh.ip}`, fields: { eventId: 4769, ticketEncryption: '0x17', serviceName: 'svc_scanner', client: 'ewright' } });
    }
    // Then the harvested service account is used off-hours (type 3) to reach a server
    addLog(w, { time: ago(40), source: 'auth', host: 'DEN-APP01', user: 'svc_scanner', srcIp: hh.ip, action: 'logon', message: `4624 Logon type 3 (Network) svc_scanner from DEN-LT-1060 (${hh.ip}) at 03:14 off-hours -> DEN-APP01`, fields: { eventId: 4624, logonType: 3, source: 'DEN-LT-1060' } });
    // svc_scanner is over-privileged, no MFA, password never expires (from base world) — set a stale password + note
    const svc = findUser(w, 'svc_scanner')!;
    svc.passwordLastSet = daysAgo(612);
    svc.notes = 'SPN MSSQLSvc/svc_scanner. Member of Server Admins. MFA not enrolled; password never expires. Owner: mreyes.';
    // Red herring: a NORMAL 4769 with AES for a routine service (benign, not roastable pattern)
    addLog(w, { time: ago(120), source: 'auth', host: 'DEN-DC01', user: 'mreyes', srcIp: '10.10.20.121', action: 'kerberos', message: '4769 Kerberos service ticket SPN=HOST/DEN-FS01 enc=0x12 (AES256) client=mreyes (routine admin, single request)', fields: { eventId: 4769, ticketEncryption: '0x12', serviceName: 'DEN-FS01' } });
    w.intel.push({ indicator: 'd41c...77', type: 'hash', verdict: 'malicious', source: 'Sandbox', tags: ['kerberoast', 'rubeus', 'hacktool'], detail: 'Rubeus offensive toolkit (Kerberoasting / ticket abuse). Not authorized software.' });
    w.chat.push({ id: 'ch-mr', with: 'mreyes', messages: [] });
  },
  contactWith: 'mreyes',
  contact: [
    { id: 'owner', question: 'Ask the account owner (mreyes): is svc_scanner supposed to request tickets from ewright\'s laptop off-hours?', answer: 'Marco: "Absolutely not. svc_scanner only ever runs from the scanner appliance (10.10.10.70). It has no business on ewright\'s laptop, and never at 3am."', purpose: 'verify', reveals: 'unauthorized' },
    { id: 'priv', question: 'Confirm svc_scanner\'s privileges and controls.', answer: '"It\'s in Server Admins, no MFA, password never expires — yeah, I know, it\'s on the remediation list. That\'s exactly why it\'s a juicy target."', purpose: 'clarify', reveals: 'over-privileged' },
    { id: 'rotate_ok', question: 'Ask mreyes whether rotating svc_scanner\'s credential now will break anything.', answer: '"Rotate it — I can update the stored credential on the appliance in minutes. Do NOT disable it; that would kill tonight\'s scans and the SQL jobs."', purpose: 'clarify', reveals: 'rotate-not-disable' },
    { id: 'weather', question: 'Ask mreyes if he watched the game last night.', answer: '"Didn\'t catch it. Let\'s deal with this."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the triage standard + IR lifecycle (KB-0013 / KB-0018)', match: [{ tool: 'kb', action: 'read', target: 'KB-0013' }, { tool: 'kb', action: 'read', target: 'KB-0018' }], weight: 0.5 },
    { id: 'burst', label: 'Found the RC4 4769 burst for svc_scanner from one host', match: [{ tool: 'siem', action: 'search', params: { q: /4769|svc_scanner|rc4|0x17|kerberoast/i } }, { tool: 'siem', action: 'pivot', params: { value: /svc_scanner/ } }], hint: 'It is not one ticket request — it is a burst, RC4-encrypted, from a single workstation.' },
    { id: 'acct', label: 'Reviewed the service account (over-privileged, no MFA, password never expires)', match: { tool: 'directory', action: 'view', target: 'svc_scanner' }, hint: 'Why is THIS account the target? Check its groups and controls.' },
    { id: 'host', label: 'Identified the harvesting host / Rubeus on DEN-LT-1060', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-LT-1060' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1060' }], hint: 'Where did the 4769 requests originate? What is running there?' },
    { id: 'intel', label: 'Confirmed the Rubeus tool hash in intel', match: { tool: 'intel', action: 'lookup', target: 'd41c...77' } },
    { id: 'offhours', label: 'Saw the service account used off-hours after the roast', match: { tool: 'siem', action: 'search', params: { q: /off.?hours|03:|svc_scanner.*logon|logon type 3/i } }, weight: 0.5 },
  ],
  required: [
    { id: 'triage', label: 'Collected triage on the harvesting host before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1060' }, skill: 'process', before: 'isolate' },
    { id: 'isolate', label: 'Isolated the harvesting host (DEN-LT-1060)', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1060' }, skill: 'technical' },
    { id: 'rotate', label: 'Rotated the service-account credential (kerberoasted SPN)', match: [{ tool: 'incident', action: 'reset_service_account', target: 'svc_scanner' }, { tool: 'directory', action: 'reset_password', target: 'svc_scanner' }], skill: 'security' },
    { id: 'reset_user', label: 'Reset the harvesting user\'s credentials (ewright / compromised host)', match: [{ tool: 'directory', action: 'reset_password', target: 'ewright' }, { tool: 'directory', action: 'revoke_sessions', target: 'ewright' }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'benign', label: 'Dismissed it as the service account "doing its job"', why: 'A burst of RC4-encrypted 4769 requests for a service SPN from a user\'s laptop, off-hours, is the Kerberoasting signature — the attacker is harvesting the hash to crack it offline. Service accounts do not request their own tickets in bursts from random workstations.', match: { tool: 'ticket', action: 'reply', target: 'r_benign' }, skill: 'security', penalty: 0.5 },
    { id: 'disable_svc', label: 'Disabled the service account (production outage)', why: 'Disabling svc_scanner kills the nightly scans and the SQL jobs that depend on it — an availability incident. The correct move is to ROTATE the credential (with the owner updating the stored secret), not disable it.', match: { tool: 'directory', action: 'disable', target: 'svc_scanner' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is Kerberoasting, not routine service traffic: Rubeus on DEN-LT-1060 (ewright) fired a burst of eight RC4 (0x17) 4769 requests for svc_scanner\'s SPN in two minutes to harvest the hash for offline cracking, and the account was then used off-hours (03:14) into DEN-APP01 — so treat it as compromised. svc_scanner is the prize because it is in Server Admins with no MFA and a 600-day-old password. I collected triage and isolated the harvesting host, reset ewright and revoked sessions, and rotated svc_scanner\'s credential with the owner (mreyes) updating the stored secret — I did NOT disable it, which would have killed the scans. Escalating to CIRT to confirm no further use of the account and to drive AES-only + a managed/gMSA fix. True positive, high.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Read the Kerberoasting signature, understood the target, rotated (not disabled), contained the host, and escalated the systemic fix.' },
    { id: 'r_benign', text: 'It\'s a service account requesting Kerberos tickets — that\'s normal behavior. Closing as benign/false positive.', scores: { communication: 0.2, security: 0.1 }, feedback: 'The burst, the RC4 encryption, the user workstation origin, and the off-hours reuse are all Kerberoasting. This is credential theft in progress, not normal.' },
    { id: 'r_disable', text: 'Suspicious — I disabled svc_scanner to be safe and closed.', scores: { communication: 0.3, security: 0.3, process: 0.1 }, feedback: 'Disabling the account stops tonight\'s scans and SQL jobs. Rotate the credential with the owner; don\'t cause an outage.' },
    { id: 'r_partial', text: 'Rotated svc_scanner\'s password. That kills the cracked hash, done.', scores: { communication: 0.4, security: 0.4 }, feedback: 'Rotating is essential, but ewright\'s laptop ran Rubeus and is compromised — contain that host and reset ewright too.' },
  ],
  notesRubric: [
    { label: 'the technique (Kerberoasting: RC4 4769 burst / Rubeus)', pattern: /kerberoast|4769|rc4|0x17|rubeus|service ticket|spn/i },
    { label: 'why svc_scanner is the target (over-privileged / no MFA / stale pw)', pattern: /server admins|no mfa|never expires|privileg|stale|600/i },
    { label: 'rotate the credential (not disable) + contain the host', pattern: /rotat|reset.*svc_scanner|triage|isolat|ewright|not disable/i },
    { label: 'escalate CIRT / systemic fix (AES, gMSA)', pattern: /cirt|escalat|aes|gmsa|managed|remediat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Identity - Kerberoasting', resolutionCode: 'Credential rotated; harvesting host contained; ewright reset; CIRT engaged' },
  categoryAccept: ['identity', 'kerberoast'],
  resolutionCodeAccept: ['rotat', 'kerberoast', 'contain', 'service account', 'cirt'],
  hints: [
    'This is not one ticket request — it is a burst of RC4 (0x17) 4769s for a service SPN from a single laptop, off-hours.',
    'Find where the requests came from: DEN-LT-1060 (ewright) is running Rubeus to harvest the hash.',
    'svc_scanner is the prize: Server Admins, no MFA, password never expires. Rotate its credential with the owner.',
    'Contain the harvesting host (triage first), reset ewright, rotate svc_scanner (do NOT disable it), and escalate to CIRT.',
  ],
  debrief: 'Kerberoasting abuses a design feature: any authenticated user can request a service ticket for any SPN, and the ticket is encrypted with the service account\'s password hash — so an attacker requests tickets (forcing weak RC4), then cracks them offline. The signal is not a single 4769 but a burst, RC4-encrypted, from a user endpoint, and here Rubeus on ewright\'s laptop makes it explicit; the off-hours reuse of svc_scanner shows the crack succeeded. The account is the target precisely because it is over-privileged, MFA-exempt, and has an ancient password. Contain the harvesting host, rotate the service credential WITH the owner (never disable it into an outage), reset the compromised user, and escalate the systemic fix (AES-only, a gMSA, least privilege).',
};

// ---------------------------------------------------------------------------
// SOC2-08  DNS tunneling data exfiltration
// ---------------------------------------------------------------------------
const soc2_08: Scenario = {
  id: 'soc2-08',
  tier: 'soc2',
  title: 'That\'s not DNS noise — it\'s a tunnel',
  category: 'Exfiltration / DNS Tunneling',
  difficulty: 5,
  estMinutes: 20,
  objective: 'Separate DNS tunneling exfiltration from ordinary DNS chatter by reading the shape of the traffic, then find the host and process behind it, contain, and cut the channel.',
  intake: { kind: 'alert', alertId: 'ALT-50085' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50085', time: ago(15), severity: 'high', source: 'siem',
      title: 'High-volume long-label TXT queries to a single domain from DEN-LT-1050',
      description: 'DEN-LT-1050 (sturner, HR) is generating hundreds of TXT/A queries to subdomains of exfil-tunnel.net, each label a long random base32 string — a DNS-tunneling exfiltration pattern. HR data may be leaving via DNS.',
      host: 'DEN-LT-1050', user: 'sturner', indicators: ['exfil-tunnel.net'], mitre: ['T1048.001', 'T1071.004'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'DEN-LT-1050');
    // The tunneling process on the host
    addProc(h, { pid: 7020, name: 'dnsc.exe', user: 'KESTREL\\sturner', cpu: 6, mem: 48, path: 'C:\\Users\\sturner\\AppData\\Roaming\\dnsc.exe', signed: false, hash: 'f19a...c3', started: ago(70), parentPid: 3610 });
    addEvent(h, { id: 4688, time: ago(70), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A new process has been created: dnsc.exe (C:\\Users\\sturner\\AppData\\Roaming\\dnsc.exe) — DNS tunneling client' });
    // ~8 long/random subdomain TXT queries to the attacker domain
    const labels = ['nb2hi4dthixs65lsmvxgg33n', 'mfrggzdfmztwq2lknnwg23tp', 'orsxg5bnmrxwg5lsmvzxik3u', 'gezdgnbvgy3tqojqmqzdambq', 'nvqws3bnmnxw4idjnzsgkylx', 'krugkidsn5xg2ylsmvwgc3th', 'mjqxiztjnztheylsmuqggzjt', 'obqxg43foieduqzlmnrxs43u'];
    for (let i = 0; i < labels.length; i++) {
      addLog(w, { time: ago(60 - i * 0.5), source: 'dns', host: 'DEN-LT-1050', srcIp: h.ip, user: 'sturner', domain: `${labels[i]}.exfil-tunnel.net`, action: 'query', message: `TXT ${labels[i]}.exfil-tunnel.net (label 24 chars, response 198 bytes)`, fields: { type: 'TXT', qlen: 24 } });
    }
    addLog(w, { time: ago(58), source: 'dns', host: 'DEN-LT-1050', srcIp: h.ip, user: 'sturner', domain: 'exfil-tunnel.net', action: 'query', message: 'SIEM stats: 417 queries to *.exfil-tunnel.net in 12 min (avg label 23 chars) from DEN-LT-1050', fields: { count: 417, window: '12m' } });
    // Host also read the HR share heavily just before (staging the data)
    addLog(w, { time: ago(75), source: 'windows', host: 'DEN-LT-1050', user: 'sturner', action: 'file_access', message: 'Bulk read of \\\\FS01\\HR\\Payroll (compensation + PII, 260 files) by sturner', fields: { files: 260 } });
    setConn(h, [{ proto: 'UDP', local: `${h.ip}:52210`, remote: '10.10.10.5:53', state: '', pid: 7020 }]);
    // Red herring: genuinely high-volume DNS to a benign CDN (short, dictionary labels) — NOT tunneling
    for (let i = 0; i < 4; i++) {
      addLog(w, { time: ago(50 - i * 3), source: 'dns', host: 'DEN-LT-1060', srcIp: '10.10.20.60', domain: `seg-${i}.cdn.akamai-content.net`, action: 'query', message: `A seg-${i}.cdn.akamai-content.net (video segment prefetch)`, fields: { type: 'A', qlen: 5 } });
    }
    w.intel.push({ indicator: 'exfil-tunnel.net', type: 'domain', verdict: 'malicious', source: 'threat feed', tags: ['dns-tunneling', 'exfiltration', 'c2'], detail: 'DNS-tunneling / exfiltration domain. Uses long base32 subdomain labels and TXT records to smuggle data over port 53.' });
    w.intel.push({ indicator: 'f19a...c3', type: 'hash', verdict: 'malicious', source: 'Sandbox', tags: ['dns-tunnel', 'exfil'], detail: 'dnsc.exe DNS-tunneling client (iodine/dnscat2-family). Encodes files into DNS queries.' });
    w.intel.push({ indicator: 'akamai-content.net', type: 'domain', verdict: 'clean', source: 'Vendor allowlist', tags: ['cdn'], detail: 'Legitimate CDN. High query volume is video segment prefetch, not tunneling (short labels).' });
    w.chat.push({ id: 'ch-st', with: 'sturner', messages: [] });
  },
  contactWith: 'sturner',
  contact: [
    { id: 'confirm', question: 'Ask sturner: are you running any tool that talks to exfil-tunnel.net, and did you open anything unusual?', answer: 'Sarah: "I have no idea what that is. I did open a resume attachment from a recruiter email this morning — it looked blank so I closed it."', purpose: 'verify', reveals: 'initial-access' },
    { id: 'data_q', question: 'Determine what data was staged before the tunneling (from the logs)', answer: 'A bulk read of \\\\FS01\\HR\\Payroll (260 comp/PII files) at ago(75), just before dnsc.exe started and the queries began.', purpose: 'clarify', reveals: 'data-staged' },
    { id: 'shape_q', question: 'Compare the query shape to the benign high-volume DNS on the network', answer: 'exfil-tunnel.net: hundreds of 23-char random base32 TXT labels to one domain. The Akamai CDN traffic is high-volume too but short dictionary labels — normal.', purpose: 'clarify', reveals: 'discriminate' },
    { id: 'weather', question: 'Ask sturner about her vacation plans.', answer: '"Can we deal with the laptop first?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the endpoint + IR/evidence playbooks (KB-0015 / KB-0018)', match: [{ tool: 'kb', action: 'read', target: 'KB-0015' }, { tool: 'kb', action: 'read', target: 'KB-0018' }], weight: 0.5 },
    { id: 'stats', label: 'Analyzed DNS volume/shape by domain in the SIEM (found the tunnel)', match: [{ tool: 'siem', action: 'search', params: { q: /exfil-tunnel|dns|txt|tunnel|417/i } }, { tool: 'siem', action: 'pivot', params: { value: /exfil-tunnel\.net/ } }], hint: 'Aggregate by domain: hundreds of long random TXT labels to ONE domain is the signature.' },
    { id: 'intel', label: 'Confirmed the tunneling domain in intel', match: { tool: 'intel', action: 'lookup', target: 'exfil-tunnel.net' } },
    { id: 'proc', label: 'Identified the tunneling process on the host (dnsc.exe)', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-LT-1050' }, { tool: 'edr', action: 'view_tree', target: 'DEN-LT-1050' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1050' }], hint: 'Which process is generating the queries? Check the tree / connections.' },
    { id: 'staged', label: 'Saw the HR data staged (bulk payroll read) before exfil', match: { tool: 'siem', action: 'search', params: { q: /payroll|hr|bulk read|260|pii/i } }, weight: 0.5 },
    { id: 'rule_out', label: 'Distinguished the benign high-volume CDN DNS from the tunnel', match: { tool: 'intel', action: 'lookup', target: 'akamai-content.net' }, weight: 0.5 },
  ],
  required: [
    { id: 'triage', label: 'Collected triage on the host before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1050' }, skill: 'process', before: 'isolate' },
    { id: 'isolate', label: 'Isolated the exfiltrating host (DEN-LT-1050)', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1050' }, skill: 'technical' },
    { id: 'block', label: 'Blocked the tunneling domain at the perimeter/DNS', match: { tool: 'perimeter', action: 'block', target: /exfil-tunnel/ }, skill: 'technical' },
    { id: 'reset', label: 'Reset the user\'s credentials (host compromised)', match: [{ tool: 'directory', action: 'reset_password', target: 'sturner' }, { tool: 'directory', action: 'revoke_sessions', target: 'sturner' }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'noise', label: 'Dismissed it as DNS noise / false positive', why: 'Hundreds of long random base32 TXT labels to a single non-categorized domain is textbook DNS tunneling, and a bulk HR payroll read preceded it. Closing as noise lets regulated PII exfiltrate over port 53 while everyone watches web/proxy.', match: { tool: 'ticket', action: 'reply', target: 'r_noise' }, skill: 'security', penalty: 0.5 },
    { id: 'block_cdn', label: 'Blocked the benign CDN domain', why: 'akamai-content.net is a legitimate CDN; its volume is short-label video prefetch, not tunneling. Blocking it breaks streaming/content and is a false-positive containment.', match: { tool: 'perimeter', action: 'block', target: /akamai/i }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is DNS-tunneling exfiltration, not noise: DEN-LT-1050 (sturner, HR) fired ~417 TXT queries in 12 minutes to *.exfil-tunnel.net, each label a ~23-char random base32 string — data encoded over port 53. dnsc.exe in her AppData is the tunneling client, and it started right after a bulk read of \\\\FS01\\HR\\Payroll (260 comp/PII files), so treat this as active exfil of regulated data. I collected triage and isolated the host, blocked exfil-tunnel.net at the perimeter/DNS, and reset sturner. I ruled out the Akamai CDN traffic (high volume but short labels = benign). Escalating to CIRT and flagging Legal given the HR/PII exposure. True positive, high — likely SEV-worthy at CIRT.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Read the traffic shape, found the process and the staged data, contained and cut the channel, and avoided the benign CDN.' },
    { id: 'r_noise', text: 'It\'s just a lot of DNS queries — probably an app being chatty. Closing as noise/false positive.', scores: { communication: 0.2, security: 0.1 }, feedback: 'Long random base32 TXT labels to one domain are not chatter; that is a tunnel, and payroll PII was staged first. This is active exfiltration.' },
    { id: 'r_blockonly', text: 'Blocked exfil-tunnel.net at the firewall — channel cut, done.', scores: { communication: 0.4, technical: 0.4 }, feedback: 'Blocking the domain helps, but dnsc.exe is still resident on the host and sturner\'s creds are exposed; contain the host and reset her, and escalate the PII exposure.' },
  ],
  notesRubric: [
    { label: 'the technique (DNS tunneling: long TXT labels to one domain)', pattern: /dns tunnel|tunneling|txt|base32|exfil-tunnel|417|port 53/i },
    { label: 'the process + staged data (dnsc.exe, HR payroll read)', pattern: /dnsc|appdata|payroll|hr|260|pii|staged/i },
    { label: 'containment: triage-first isolate + block domain + reset', pattern: /triage|isolat|block|reset|revoke|contain/i },
    { label: 'ruled out benign CDN + escalate CIRT/Legal (PII)', pattern: /akamai|cdn|ruled out|cirt|legal|escalat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Exfiltration - DNS Tunneling', resolutionCode: 'Tunnel confirmed; host contained; domain blocked; user reset; CIRT/Legal engaged' },
  categoryAccept: ['exfil', 'dns', 'tunnel'],
  resolutionCodeAccept: ['tunnel', 'exfil', 'contain', 'block', 'cirt'],
  hints: [
    'Do not judge DNS by volume alone. Aggregate by domain and look at the label shape.',
    'Hundreds of long random base32 TXT labels to a single domain (exfil-tunnel.net) is DNS tunneling; the Akamai CDN volume is benign short labels.',
    'Find the process: dnsc.exe in sturner\'s AppData started right after a bulk HR payroll read.',
    'Collect triage, isolate the host, block the domain, reset sturner, and escalate to CIRT/Legal for the PII exposure. Do not block the CDN.',
  ],
  debrief: 'DNS tunneling exploits the one protocol nearly always allowed to egress. Attackers encode stolen data into the subdomain labels of queries to a domain whose authoritative server they control, and answers come back in TXT records — so exfiltration hides in "DNS noise." The discriminator is shape, not volume: long, high-entropy base32 labels, many unique subdomains under a single domain, sustained rate. Here the tell is complete — a bulk HR payroll read stages the data, dnsc.exe in AppData drives it, and a known tunneling domain receives it — while a genuinely chatty CDN with short labels is the benign foil. Contain the host (triage first), cut the channel at DNS/perimeter, reset the user, and escalate the PII exposure to CIRT and Legal.',
};

export const SOC2_SCENARIOS_B: Scenario[] = [soc2_04, soc2_05, soc2_06, soc2_07, soc2_08];
