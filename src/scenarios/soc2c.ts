import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, addAlert, addMail, setConn } from './helpers';

// ---------------------------------------------------------------------------
// SOC2-09  AiTM / Evilginx session-cookie theft that bypassed MFA
// ---------------------------------------------------------------------------
const soc2_09: Scenario = {
  id: 'soc2-09',
  tier: 'soc2',
  title: 'MFA was satisfied — so why is she signed in from Bulgaria?',
  category: 'Identity / AiTM',
  difficulty: 4,
  estMinutes: 17,
  objective: 'Recognize an adversary-in-the-middle (Evilginx) attack where a stolen session cookie — not the password — gives the attacker an already-MFA-satisfied session, and contain it the way a token actually dies: revoke sessions first, remove persistence, then reset.',
  intake: { kind: 'alert', alertId: 'ALT-50109' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50109', time: ago(16), severity: 'high', source: 'cloud',
      title: 'Successful sign-in for cflores from a new country with MFA already satisfied (no prompt)',
      description: 'WorkSuite flagged a successful sign-in for cflores (Sales, remote-Phoenix) from 45.133.216.18 (Sofia, BG) marked mfa=satisfied although no MFA challenge was issued — a session-token replay following a phishing click. An inbox rule was then created via the session.',
      user: 'cflores', indicators: ['45.133.216.18', 'worksuite-mail.secure-login.co'], mitre: ['T1557', 'T1550.004', 'T1539', 'T1114.003'], status: 'new', truth: 'true_positive',
    });
    const c = findUser(w, 'cflores')!;
    // Real user's normal sign-ins from home + VPN, then the attacker's cookie replay from BG.
    c.recentSignIns = [
      { time: ago(320), ip: '73.14.22.190', location: 'Phoenix, US', app: 'WorkSuite Mail', result: 'success', device: 'DEN-LT-1061', mfa: 'satisfied' },
      { time: ago(90), ip: '73.14.22.190', location: 'Phoenix, US', app: 'WorkSuite Mail', result: 'success', device: 'DEN-LT-1061', mfa: 'satisfied' },
      { time: ago(14), ip: '45.133.216.18', location: 'Sofia, BG', app: 'WorkSuite Mail', result: 'success', device: 'unknown (token replay)', mfa: 'satisfied' },
    ];
    // The AiTM phishing email carrying the reverse-proxy link
    addMail(w, {
      id: 'MSG-9101', time: ago(70), from: 'WorkSuite Security <security@worksuite-mail.secure-login.co>', to: ['cflores@kestreldynamics.com'],
      subject: 'Your mailbox password expires today - re-authenticate',
      status: 'delivered' as const,
      headers: { from: 'WorkSuite Security <security@worksuite-mail.secure-login.co>', returnPath: 'bounce@secure-login.co', receivedFrom: 'mail.secure-login.co [45.133.216.18]', spf: 'pass', dkim: 'pass', dmarc: 'pass', messageId: '<9101@secure-login.co>' },
      body: 'Your password expires in 2 hours. Sign in now to keep access.',
      urls: ['https://worksuite-mail.secure-login.co/auth?rt=1'], phishing: true, clicked: ['cflores'],
    });
    // Cloud audit trail: cookie replay -> mail read -> inbox rule (hide security replies) -> mail send
    addLog(w, { time: ago(15), source: 'cloud', user: 'cflores', srcIp: '45.133.216.18', action: 'signin', message: 'WorkSuite sign-in SUCCESS cflores from 45.133.216.18 (Sofia,BG) mfa=satisfied via replayed session cookie (no interactive MFA)', fields: { result: 'success', mfa: 'satisfied', method: 'session-cookie' } });
    addLog(w, { time: ago(13), source: 'cloud', user: 'cflores', srcIp: '45.133.216.18', action: 'mail_access', message: 'Mailbox read 214 items from 45.133.216.18 (Sofia,BG)', fields: { items: 214 } });
    addLog(w, { time: ago(12), source: 'cloud', user: 'cflores', srcIp: '45.133.216.18', action: 'inbox_rule', message: 'Inbox rule "Security" created: move messages from IT/Security/helpdesk to RSS Feeds and mark read', fields: { rule: 'Security' } });
    addLog(w, { time: ago(8), source: 'cloud', user: 'cflores', srcIp: '45.133.216.18', action: 'mail_send', message: 'Sent internal message on behalf of cflores to two AE peers with the same secure-login.co lure', fields: {} });
    const mbx = w.mailboxes.find((m) => m.user === 'cflores')!;
    mbx.rules.push({ name: 'Security', condition: "from contains 'it','security','helpdesk'", action: 'Move to RSS Feeds; mark as read', enabled: true, created: ago(12), suspicious: true });
    // Red herring: a benign, prompted MFA sign-in from the user's real VPN IP earlier.
    addLog(w, { time: ago(320), source: 'cloud', user: 'cflores', srcIp: '73.14.22.190', action: 'signin', message: 'WorkSuite sign-in SUCCESS cflores from 73.14.22.190 (Phoenix,US) mfa=satisfied (interactive push approved)', fields: { result: 'success', mfa: 'satisfied' } });
    w.intel.push({ indicator: 'worksuite-mail.secure-login.co', type: 'domain', verdict: 'malicious', source: 'threat feed', tags: ['aitm', 'evilginx', 'phishing'], detail: 'Adversary-in-the-middle reverse-proxy phishing (Evilginx). Relays the real WorkSuite login and steals the post-MFA session cookie.' });
    w.intel.push({ indicator: '45.133.216.18', type: 'ip', verdict: 'malicious', source: 'threat feed', tags: ['aitm', 'hosting'], detail: 'Hosting IP (Sofia, BG) fronting the secure-login.co AiTM kit and replaying stolen cookies.' });
    w.chat.push({ id: 'ch-cf', with: 'cflores', messages: [] });
  },
  contactWith: 'cflores',
  contact: [
    { id: 'confirm', question: 'Ask cflores: did you sign in from Bulgaria, and did you click a "password expires" link today?', answer: 'Carlos: "I\'m in Phoenix, I have not left. I did click a link this morning that said my password was expiring and signed in like normal — it didn\'t even ask for my code."', purpose: 'verify', reveals: 'aitm' },
    { id: 'rule_q', question: 'Ask cflores whether he created a rule hiding IT/Security mail.', answer: '"No, I never make inbox rules."', purpose: 'clarify', reveals: 'rule' },
    { id: 'pw_q', question: 'Ask cflores if the page asked him to re-enter his password and MFA code.', answer: '"It looked exactly like the normal Microsoft/WorkSuite page. I typed my password and approved the push on my phone."', purpose: 'clarify', reveals: 'token-stolen' },
    { id: 'weather', question: 'Ask cflores about the Phoenix weather.', answer: '"Hot. Can we fix my account?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the suspicious sign-in + triage playbooks (KB-0016 / KB-0013)', match: [{ tool: 'kb', action: 'read', target: 'KB-0016' }, { tool: 'kb', action: 'read', target: 'KB-0013' }], weight: 0.5, hint: 'What does KB-0016 say about a sign-in from a new country followed by a mailbox rule?' },
    { id: 'signins', label: 'Saw the foreign sign-in with MFA satisfied but no interactive prompt', match: { tool: 'directory', action: 'view_signins', target: 'cflores' }, hint: 'MFA "satisfied" with no challenge from a new country is the AiTM tell.' },
    { id: 'cloud', label: 'Traced the cookie replay -> mail read -> inbox rule in the cloud logs', match: [{ tool: 'siem', action: 'search', params: { q: /cflores|session|cookie|inbox rule|45\.133\.216\.18/i } }, { tool: 'siem', action: 'pivot', params: { value: /cflores/ } }], hint: 'The audit trail is in the cloud logs: replay, read, rule, send.' },
    { id: 'rule', label: 'Found the attacker inbox rule hiding IT/Security mail', match: { tool: 'mail', action: 'view_mailbox', target: 'cflores' }, hint: 'Attackers hide their tracks — check the mailbox rules.' },
    { id: 'headers', label: 'Analyzed the phishing email that started it (reverse-proxy domain)', match: { tool: 'mail', action: 'view_headers', target: 'MSG-9101' } },
    { id: 'intel', label: 'Confirmed the AiTM domain / IP in intel', match: [{ tool: 'intel', action: 'lookup', target: 'worksuite-mail.secure-login.co' }, { tool: 'intel', action: 'lookup', target: '45.133.216.18' }] },
  ],
  required: [
    { id: 'revoke', label: 'Revoked the user\'s sessions/tokens (kills the stolen session cookie)', match: { tool: 'directory', action: 'revoke_sessions', target: 'cflores' }, skill: 'security' },
    { id: 'remove_rule', label: 'Removed the malicious inbox rule', match: { tool: 'mail', action: 'remove_rule', target: 'cflores' }, skill: 'technical' },
    { id: 'reset', label: 'Reset the password AFTER revoking sessions', match: { tool: 'directory', action: 'reset_password', target: 'cflores' }, skill: 'security', after: 'revoke' },
    { id: 'block', label: 'Blocked the AiTM phishing domain at the gateway', match: [{ tool: 'perimeter', action: 'block', target: /secure-login\.co/ }, { tool: 'mail', action: 'block_sender', target: /secure-login\.co/ }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'reset_only', label: 'Reset the password and closed (session cookie survives)', why: 'AiTM steals the post-MFA session cookie, not the password. A password reset does NOT invalidate an existing session token — the attacker keeps reading and sending mail until you REVOKE sessions and remove the inbox rule. Reset without revoke is the classic AiTM miss.', match: { tool: 'ticket', action: 'reply', target: 'r_resetonly' }, skill: 'security', penalty: 0.5 },
    { id: 'reset_before_revoke', label: 'Reset the password before revoking sessions', why: 'Order matters: reset before revoke leaves the live stolen cookie valid in the gap. Revoke first to kill the token, then reset.', match: { tool: 'directory', action: 'reset_password', target: 'cflores' }, skill: 'process', penalty: 0.25, unlessAfter: 'revoke' },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is an adversary-in-the-middle (Evilginx) attack, not a password leak. cflores clicked a "password expires" lure that proxied the real WorkSuite login (worksuite-mail.secure-login.co) and stole his post-MFA session cookie, so the attacker signed in from Sofia with mfa=satisfied and NO prompt, read 214 items, created a hide-the-evidence inbox rule, and re-sent the lure to two peers. His password was never the vector. I revoked his sessions to kill the stolen cookie, removed the malicious rule, then reset his password, and blocked secure-login.co at the mail gateway/proxy. Escalating to CIRT to hunt the two re-targeted AEs and review MFA method strength (token-binding / phishing-resistant FIDO2). True positive, high.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Correct diagnosis (stolen cookie, not password), token-killing containment in the right order, rule removed, domain blocked.' },
    { id: 'r_resetonly', text: 'Reset cflores\'s password and told him to pick a stronger one. Closed.', scores: { communication: 0.3, security: 0.1 }, feedback: 'The stolen session cookie survives a password reset. The attacker is still in the mailbox — you have to revoke sessions and remove the rule.' },
    { id: 'r_travel', text: 'MFA is satisfied and it is the same user — probably he is travelling. Benign true positive, closing.', scores: { communication: 0.2, security: 0.1 }, feedback: 'He confirmed he is in Phoenix, and mfa=satisfied with no prompt from a new country plus a new inbox rule is textbook token replay, not travel.' },
    { id: 'r_partial', text: 'Revoked his sessions — that cuts the cookie, done.', scores: { communication: 0.4, security: 0.4 }, feedback: 'Revoking is the key step, but the malicious inbox rule persists and the AiTM domain is unblocked and still hitting peers.' },
  ],
  notesRubric: [
    { label: 'the diagnosis (AiTM / stolen session cookie, not password)', pattern: /aitm|adversary.?in.?the.?middle|evilginx|session|cookie|token|reverse.?prox|not.*password/i },
    { label: 'the tells (foreign sign-in, mfa satisfied no prompt, inbox rule)', pattern: /sofia|bulgaria|45\.133\.216\.18|mfa.*satisf|no prompt|inbox rule|new country/i },
    { label: 'containment order: revoke -> remove rule -> reset', pattern: /revoke|remove rule|reset|revok.*before|session/i },
    { label: 'block the AiTM domain + escalate CIRT', pattern: /block|secure-login|cirt|escalat|fido|phishing.?resist/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Identity - AiTM Session Theft', resolutionCode: 'Sessions revoked; rule removed; password reset; AiTM domain blocked; CIRT engaged' },
  categoryAccept: ['aitm', 'identity', 'session', 'phishing', 'token'],
  resolutionCodeAccept: ['revoke', 'aitm', 'session', 'rule', 'cirt'],
  hints: [
    'The sign-in is from a new country with mfa=satisfied but no interactive challenge — that is a replayed session cookie, not travel.',
    'Trace the cloud logs: cookie replay, mailbox read, an inbox rule hiding IT/Security mail, then the lure re-sent to peers.',
    'A password reset does not kill a session cookie. Revoke sessions FIRST, then remove the rule and reset.',
    'Block secure-login.co, escalate to CIRT to hunt the re-targeted AEs, and flag phishing-resistant MFA.',
  ],
  debrief: 'AiTM is the attack that made "we have MFA" stop being a full answer. A reverse proxy (Evilginx) sits between the victim and the real login page, relays the password and the MFA challenge, and captures the resulting session cookie — so the attacker inherits an already-authenticated, MFA-satisfied session without ever knowing the password. The tells invert the usual signals: mfa=satisfied but no interactive prompt, a sign-in from a new country, then a hide-the-evidence inbox rule and lateral re-phishing. Containment must target the token: revoke sessions to kill the cookie, remove the rule, then reset the password, and block the AiTM infrastructure. A password reset alone changes nothing the attacker is using.',
};

// ---------------------------------------------------------------------------
// SOC2-10  Forged Kerberos ticket (golden/silver) anomaly
// ---------------------------------------------------------------------------
const soc2_10: Scenario = {
  id: 'soc2-10',
  tier: 'soc2',
  title: 'A ticket for an account that does not exist',
  category: 'Identity / Kerberos',
  difficulty: 5,
  estMinutes: 20,
  objective: 'Recognize a forged Kerberos ticket (golden/silver) from its anomalies — a logon with no preceding AS-REQ, a ticket for a non-existent account, an absurd lifetime — and understand why a password reset cannot fix it: only KRBTGT rotation invalidates a golden ticket.',
  intake: { kind: 'alert', alertId: 'ALT-50110' },
  priorityExpected: 'P1',
  tools: ['incident'],
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50110', time: ago(14), severity: 'critical', source: 'siem',
      title: 'Kerberos ticket anomalies on the domain: TGT with a 10-year lifetime and a ticket for a non-existent account',
      description: 'The SIEM correlated 4624 Kerberos network logons on DEN-DC01/DEN-FS01 that have NO preceding 4768 (AS-REQ) — the account already held a TGT — including one for "backupadmin", an account that does not exist in the directory, and a TGT lifetime of ~10 years. Origin host: DEN-LT-1042 (bpatel). Golden/forged-ticket signature.',
      host: 'DEN-LT-1042', user: 'bpatel', indicators: ['backupadmin', 'DEN-LT-1042', '91.219.236.14'], mitre: ['T1558.001', 'T1550.003', 'T1078.002'], status: 'new', truth: 'true_positive',
    });
    // Compromised entry host: bpatel's laptop, running a loader beaconing to C2.
    const hh = host(w, 'DEN-LT-1042');
    addProc(hh, { pid: 7710, name: 'rundll32-svc.exe', user: 'KESTREL\\bpatel', cpu: 3, mem: 58, path: 'C:\\Users\\bpatel\\AppData\\Roaming\\rundll32-svc.exe', signed: false, hash: 'b93e...d1', started: ago(140), parentPid: 3610 });
    setConn(hh, [{ proto: 'TCP', local: `${hh.ip}:51330`, remote: '91.219.236.14:443', state: 'ESTABLISHED', pid: 7710 }]);
    addEvent(hh, { id: 4688, time: ago(70), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A new process has been created: mimikatz.exe "kerberos::golden /user:backupadmin /domain:kestrel.local ... /ptt" (KESTREL\\bpatel)' });
    // The forged-ticket anomalies: 4624 with NO preceding 4768, non-existent account, absurd lifetime.
    addLog(w, { time: ago(60), source: 'auth', host: 'DEN-DC01', user: 'backupadmin', srcIp: hh.ip, action: 'logon', message: `4624 Logon type 3 (Network) backupadmin from DEN-LT-1042 (${hh.ip}) -> DEN-DC01. NO matching 4768 (AS-REQ); account "backupadmin" not found in directory; TGT lifetime 3650 days`, fields: { eventId: 4624, logonType: 3, source: 'DEN-LT-1042', ticketLifetimeDays: 3650 } });
    addLog(w, { time: ago(55), source: 'auth', host: 'DEN-FS01', user: 'backupadmin', srcIp: hh.ip, action: 'logon', message: `4624 Logon type 3 (Network) backupadmin -> \\\\DEN-FS01\\Finance from ${hh.ip} (bulk file listing, no prior 4768)`, fields: { eventId: 4624, logonType: 3, source: 'DEN-LT-1042' } });
    addLog(w, { time: ago(52), source: 'auth', host: 'DEN-DC01', user: 'backupadmin', srcIp: hh.ip, action: 'kerberos', message: '4672 Special privileges assigned to new logon: backupadmin (SeDebugPrivilege, SeTcbPrivilege) — privileged token with no AS-REQ', fields: { eventId: 4672 } });
    addLog(w, { time: ago(48), source: 'windows', host: 'DEN-DC01', user: 'backupadmin', action: 'admin', message: '4662 Directory access: DCSync-style replication request from backupadmin (DS-Replication-Get-Changes-All)', fields: { eventId: 4662 } });
    // Red herring: a NORMAL Kerberos flow for mreyes with a matching 4768 and standard 10h lifetime.
    addLog(w, { time: ago(120), source: 'auth', host: 'DEN-DC01', user: 'mreyes', srcIp: '10.10.20.121', action: 'kerberos', message: '4768 TGT requested mreyes (AES256) then 4624 type 3 -> DEN-FS01, lifetime 10h (routine admin, matched AS-REQ)', fields: { eventId: 4768, ticketLifetimeHours: 10 } });
    w.intel.push({ indicator: '91.219.236.14', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['c2', 'loader'], detail: 'Loader C2 for rundll32-svc.exe on the entry host. Hands-on-keyboard operator.' });
    w.intel.push({ indicator: 'b93e...d1', type: 'hash', verdict: 'malicious', source: 'Sandbox', tags: ['loader', 'mimikatz-host'], detail: 'Loader used to stage credential tooling (mimikatz) that forged the Kerberos ticket.' });
    w.chat.push({ id: 'ch-bp', with: 'bpatel', messages: [] });
    w.chat.push({ id: 'ch-mr', with: 'mreyes', messages: [] });
  },
  contactWith: 'mreyes',
  contact: [
    { id: 'exists', question: 'Ask mreyes (sysadmin): is there a service or account called "backupadmin"?', answer: 'Marco: "No. There is no backupadmin account. svc_backup is the backup account. If something is logging in as backupadmin, it is fabricated."', purpose: 'verify', reveals: 'forged' },
    { id: 'krbtgt', question: 'Ask mreyes when the KRBTGT password was last rotated.', answer: '"Honestly? Not since the domain was built. I know, I know — it is on the list."', purpose: 'clarify', reveals: 'krbtgt-stale' },
    { id: 'bpatel_q', question: 'Ask bpatel what he ran on his laptop this morning.', answer: 'Bhavik: "I opened an invoice attachment that asked me to enable macros. Nothing seemed to happen."', purpose: 'clarify', reveals: 'initial-access' },
    { id: 'weather', question: 'Ask mreyes about his lunch.', answer: '"Not now."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the IR lifecycle + triage playbooks (KB-0018 / KB-0013)', match: [{ tool: 'kb', action: 'read', target: 'KB-0018' }, { tool: 'kb', action: 'read', target: 'KB-0013' }], weight: 0.5, hint: 'KB-0018 recovery step: rotate every credential the attacker could have seen, including the KRBTGT.' },
    { id: 'anoms', label: 'Found the ticket anomalies in the auth logs (no 4768, absurd lifetime, DCSync)', match: [{ tool: 'siem', action: 'search', params: { q: /backupadmin|4768|4672|4662|golden|ticket|lifetime/i } }, { tool: 'siem', action: 'pivot', params: { value: /backupadmin/ } }], hint: 'A 4624 with no preceding 4768 means the TGT was not issued by the KDC — it was forged.' },
    { id: 'nonexistent', label: 'Confirmed "backupadmin" does not exist in the directory', match: [{ tool: 'directory', action: 'search', params: { q: /backupadmin/i } }, { tool: 'directory', action: 'view', target: 'backupadmin' }], hint: 'A ticket for a non-existent account is only possible if it was forged.' },
    { id: 'host', label: 'Identified the entry host + credential tooling (mimikatz/loader on DEN-LT-1042)', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-LT-1042' }, { tool: 'edr', action: 'view_tree', target: 'DEN-LT-1042' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1042' }] },
    { id: 'intel', label: 'Confirmed the C2 / loader hash in intel', match: [{ tool: 'intel', action: 'lookup', target: '91.219.236.14' }, { tool: 'intel', action: 'lookup', target: 'b93e...d1' }] },
  ],
  required: [
    { id: 'triage', label: 'Collected triage on the entry host before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1042' }, skill: 'process', before: 'isolate' },
    { id: 'isolate', label: 'Isolated the entry host (DEN-LT-1042)', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1042' }, skill: 'technical' },
    { id: 'reset_user', label: 'Reset the compromised user and revoked sessions (bpatel)', match: [{ tool: 'directory', action: 'reset_password', target: 'bpatel' }, { tool: 'directory', action: 'revoke_sessions', target: 'bpatel' }], skill: 'security' },
    { id: 'krbtgt', label: 'Flagged/initiated KRBTGT rotation (the only fix for a golden ticket)', match: { tool: 'incident', action: 'rotate_krbtgt' }, skill: 'security' },
    { id: 'block', label: 'Blocked the loader C2 at the perimeter', match: { tool: 'perimeter', action: 'block', target: '91.219.236.14' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'reset_fixes', label: 'Reset a user password and treated it as the fix', why: 'A golden ticket is forged offline with the KRBTGT hash; it is not tied to any user\'s password. Resetting bpatel or "backupadmin" (which does not even exist) does nothing to a forged TGT. Only rotating the KRBTGT (twice) invalidates it — this must be escalated to CIRT.', match: { tool: 'ticket', action: 'reply', target: 'r_reset' }, skill: 'security', penalty: 0.5 },
    { id: 'chase_benign', label: 'Contained the host mreyes admins from (benign Kerberos)', why: 'mreyes had a normal 4768 -> 4624 with a 10-hour lifetime; that is a legitimately issued ticket, not a forged one. Isolating DEN-LT-1021 chases a false positive.', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1021' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is a forged Kerberos ticket (golden-ticket) attack. The auth logs show 4624 network logons on DEN-DC01/DEN-FS01 with NO preceding 4768, including one for "backupadmin" — an account that does not exist — carrying a 3650-day TGT lifetime and SeDebug/SeTcb privileges, then a DCSync-style 4662. The entry host DEN-LT-1042 (bpatel) ran a loader that staged mimikatz to mint the ticket. Because a golden ticket is forged with the KRBTGT hash and is not bound to any password, a user reset cannot revoke it — the KRBTGT must be rotated (twice). I collected triage and isolated the entry host, reset bpatel and revoked his sessions, blocked the loader C2, and escalated to CIRT as CRITICAL to rotate the KRBTGT and validate the DCs. I ruled out mreyes\'s normal 10h ticket. True positive, critical.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Read the forged-ticket anomalies, understood why a reset is useless, and drove the KRBTGT rotation via CIRT while containing the entry host.' },
    { id: 'r_reset', text: 'Reset the backupadmin/bpatel password and disabled the account. Closing.', scores: { communication: 0.3, security: 0.1 }, feedback: 'backupadmin does not exist and a golden ticket is not tied to a password — a reset does nothing. This needs KRBTGT rotation via CIRT.' },
    { id: 'r_benign', text: 'A service account requesting Kerberos tickets — probably a backup job. Benign, closing.', scores: { communication: 0.2, security: 0.1 }, feedback: 'A logon with no AS-REQ, a non-existent account, a 10-year lifetime and a DCSync request is a forged ticket, not a backup job.' },
    { id: 'r_partial', text: 'Isolated DEN-LT-1042 and blocked the C2. Done.', scores: { communication: 0.4, technical: 0.4 }, feedback: 'Containing the entry host is right, but the forged ticket persists until the KRBTGT is rotated — escalate that to CIRT.' },
  ],
  notesRubric: [
    { label: 'the technique (forged/golden Kerberos ticket)', pattern: /golden|forged|kerberos|ticket|4768|4624|backupadmin|lifetime|dcsync/i },
    { label: 'the anomalies (no AS-REQ, non-existent account, absurd lifetime)', pattern: /no.*4768|no.*as.?req|non.?exist|does not exist|3650|10.?year|4662/i },
    { label: 'why a reset fails / KRBTGT rotation is the fix', pattern: /krbtgt|rotat|not.*password|twice|reset.*useless|golden/i },
    { label: 'contain entry host + escalate CIRT critical', pattern: /triage|isolat|1042|cirt|escalat|critical|block/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'critical', category: 'Identity - Forged Kerberos Ticket', resolutionCode: 'Entry host contained; user reset; KRBTGT rotation initiated via CIRT; C2 blocked' },
  categoryAccept: ['kerberos', 'identity', 'golden', 'forged', 'ticket'],
  resolutionCodeAccept: ['krbtgt', 'golden', 'forged', 'rotat', 'cirt'],
  hints: [
    'A 4624 with no matching 4768 means the account already held a TGT that the KDC never issued — it was forged.',
    'The ticket is for "backupadmin", an account that does not exist, with a 3650-day lifetime and a DCSync request. That is a golden ticket.',
    'A golden ticket is minted from the KRBTGT hash and is not tied to any password — a user reset cannot revoke it.',
    'Contain the entry host (triage first), block the C2, and escalate to CIRT as CRITICAL to rotate the KRBTGT twice. Do not chase mreyes\'s normal ticket.',
  ],
  debrief: 'Forged Kerberos tickets are the endgame of a domain compromise. With the KRBTGT hash an attacker mints a golden ticket — a TGT for any principal (even a non-existent one), with any privileges and any lifetime — that the KDC will honor because it validates the KRBTGT signature, not a password. The tells are structural: a network logon with no preceding AS-REQ, a ticket for an account the directory has never heard of, a cartoonish lifetime, and privileged/DCSync activity that follows. Crucially, resetting user passwords does nothing; the ticket is bound to the KRBTGT, so the only remediation is rotating the KRBTGT (twice, so both current and previous keys change) — a CIRT action. The SOC job is to prove the forgery, contain the entry host, and get that rotation moving fast.',
};

// ---------------------------------------------------------------------------
// SOC2-11  WMI event-subscription persistence
// ---------------------------------------------------------------------------
const soc2_11: Scenario = {
  id: 'soc2-11',
  tier: 'soc2',
  title: 'The malware you kill keeps coming back',
  category: 'Persistence / WMI',
  difficulty: 4,
  estMinutes: 18,
  objective: 'Hunt fileless WMI event-subscription persistence on a single host — the reason a "cleaned" endpoint reinfects itself — enumerate every persistence mechanism, and contain and remove them all rather than just killing the running payload.',
  intake: { kind: 'alert', alertId: 'ALT-50111' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50111', time: ago(20), severity: 'high', source: 'edr',
      title: 'PowerShell repeatedly spawned by WmiPrvSE.exe on DEN-LT-1051 after each "cleanup"',
      description: 'Halberd flagged DEN-LT-1051 (dkim) where powershell.exe is launched by WmiPrvSE.exe on a recurring basis. Desktop already "removed" the malware twice and it returned. A WMI CommandLineEventConsumer + __EventFilter binding is the suspected persistence.',
      host: 'DEN-LT-1051', user: 'dkim', indicators: ['DEN-LT-1051', 'WmiPrvSE.exe', 'update-checker.ps1', '188.114.97.7'], mitre: ['T1546.003', 'T1059.001', 'T1053.005'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'DEN-LT-1051');
    // The recurring payload spawned by WMI + the dropper in AppData.
    addProc(h, { pid: 6410, name: 'powershell.exe', user: 'KESTREL\\dkim', cpu: 4, mem: 70, path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmdline: 'powershell -w hidden -enc <b64> (C:\\Users\\dkim\\AppData\\Roaming\\update-checker.ps1)', parentPid: 3100, signed: true, hash: '00aa...ps', started: ago(9) });
    addProc(h, { pid: 3100, name: 'WmiPrvSE.exe', user: 'NETWORK SERVICE', cpu: 1, mem: 30, path: 'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe', signed: true, started: ago(200) });
    setConn(h, [{ proto: 'TCP', local: `${h.ip}:52880`, remote: '188.114.97.7:443', state: 'ESTABLISHED', pid: 6410 }]);
    // Persistence #1: the WMI event subscription (fileless), visible as events.
    addEvent(h, { id: 5861, time: ago(150), level: 'Information', source: 'Microsoft-Windows-WMI-Activity', log: 'Application', message: 'WMI ESS: __EventFilter "UpdateFilter" (WITHIN 60 __InstanceModificationEvent Win32_LocalTime) bound to CommandLineEventConsumer "UpdateConsumer" -> powershell -w hidden -enc ... (permanent subscription)' });
    addEvent(h, { id: 4688, time: ago(9), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A new process has been created: powershell.exe (parent WmiPrvSE.exe) running update-checker.ps1' });
    // Persistence #2: a suspicious scheduled task (redundant persistence).
    h.scheduledTasks.push({ name: 'SystemHealthCheck', path: '\\Microsoft\\Windows\\Maintenance\\', action: 'powershell -w hidden -File C:\\Users\\dkim\\AppData\\Roaming\\update-checker.ps1', trigger: 'At logon + every 4 hours', author: 'KESTREL\\dkim', suspicious: true });
    // Persistence #3: a Run key noted in events.
    addEvent(h, { id: 13, time: ago(148), level: 'Information', source: 'Sysmon', log: 'Sysmon', message: 'Registry value set: HKCU\\...\\Run\\UpdateChecker = powershell -w hidden -File ...update-checker.ps1' });
    addLog(w, { time: ago(9), source: 'proxy', host: 'DEN-LT-1051', user: 'dkim', dstIp: '188.114.97.7', domain: 'cfg.update-checker.io', url: 'https://cfg.update-checker.io/p', action: 'allow', dstPort: 443, message: 'POST https://cfg.update-checker.io/p (beacon from update-checker.ps1)' });
    addLog(w, { time: ago(150), source: 'windows', host: 'DEN-LT-1051', user: 'dkim', action: 'wmi', message: '5861 Permanent WMI event consumer "UpdateConsumer" created on DEN-LT-1051', fields: { eventId: 5861 } });
    // Red herring: the benign, standard Halberd Inventory scheduled task (do NOT delete it).
    // (already present from base world as "Halberd Inventory")
    w.intel.push({ indicator: '188.114.97.7', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['c2', 'powershell'], detail: 'C2 for the update-checker.ps1 loader. Persists via WMI event subscription.' });
    w.intel.push({ indicator: 'cfg.update-checker.io', type: 'domain', verdict: 'malicious', source: 'threat feed', tags: ['c2', 'persistence'], detail: 'Config/C2 domain contacted by the fileless PowerShell payload.' });
    w.chat.push({ id: 'ch-dk', with: 'dkim', messages: [] });
  },
  contactWith: 'dkim',
  contact: [
    { id: 'confirm', question: 'Ask dkim: did you install an "update checker" or schedule any maintenance task?', answer: 'David: "No. IT already cleaned my laptop twice today and it keeps acting up again after I log in."', purpose: 'verify', reveals: 'reinfect' },
    { id: 'origin', question: 'Ask dkim what he opened before this started.', answer: '"A resume ZIP from a candidate. There was a .lnk inside that I double-clicked."', purpose: 'clarify', reveals: 'initial-access' },
    { id: 'persist_q', question: 'Enumerate the persistence mechanisms from the host (tasks, WMI, Run key)', answer: 'A permanent WMI CommandLineEventConsumer "UpdateConsumer", a scheduled task "SystemHealthCheck", and an HKCU Run key — all launching update-checker.ps1.', purpose: 'clarify', reveals: 'persistence' },
    { id: 'weather', question: 'Ask dkim about his weekend.', answer: '"Fine, thanks. The laptop though..."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the endpoint malware/persistence + triage playbooks (KB-0015 / KB-0013)', match: [{ tool: 'kb', action: 'read', target: 'KB-0015' }, { tool: 'kb', action: 'read', target: 'KB-0013' }], weight: 0.5, hint: 'KB-0015: look for persistence — scheduled tasks, services, Run keys, WMI.' },
    { id: 'tree', label: 'Saw powershell spawned by WmiPrvSE.exe in the process tree', match: [{ tool: 'edr', action: 'view_tree', target: 'DEN-LT-1051' }, { tool: 'edr', action: 'view_host', target: 'DEN-LT-1051' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1051' }], hint: 'WmiPrvSE.exe as the parent of powershell is the WMI-subscription tell.' },
    { id: 'wmi', label: 'Found the WMI event-subscription persistence in the host events', match: [{ tool: 'rdp', action: 'view_events', target: 'DEN-LT-1051' }, { tool: 'siem', action: 'search', params: { q: /wmi|5861|eventconsumer|__eventfilter|update-checker/i } }], hint: 'Event 5861 records a permanent WMI consumer being created.' },
    { id: 'tasks', label: 'Enumerated scheduled tasks + Run key (redundant persistence)', match: [{ tool: 'rdp', action: 'view_tasks', target: 'DEN-LT-1051' }, { tool: 'terminal', action: 'schtasks', target: 'DEN-LT-1051' }], hint: 'Attackers layer persistence — check the scheduled tasks and Run keys too.' },
    { id: 'intel', label: 'Confirmed the C2 IP / domain in intel', match: [{ tool: 'intel', action: 'lookup', target: '188.114.97.7' }, { tool: 'intel', action: 'lookup', target: 'cfg.update-checker.io' }] },
  ],
  required: [
    { id: 'triage', label: 'Collected triage on the host before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1051' }, skill: 'process', before: 'isolate' },
    { id: 'isolate', label: 'Isolated the host (DEN-LT-1051)', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1051' }, skill: 'technical' },
    { id: 'remove_task', label: 'Removed the malicious scheduled-task persistence', match: [{ tool: 'rdp', action: 'delete_task', params: { task: /systemhealthcheck/i } }, { tool: 'terminal', action: 'schtasks', target: 'DEN-LT-1051', params: { cmd: /delete/i } }], skill: 'technical' },
    { id: 'block', label: 'Blocked the C2 at the perimeter', match: [{ tool: 'perimeter', action: 'block', target: '188.114.97.7' }, { tool: 'perimeter', action: 'block', target: /update-checker\.io/ }], skill: 'technical' },
    { id: 'reset', label: 'Reset the user\'s credentials (host compromised)', match: [{ tool: 'directory', action: 'reset_password', target: 'dkim' }, { tool: 'directory', action: 'revoke_sessions', target: 'dkim' }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'kill_only', label: 'Killed the PowerShell and closed without removing persistence', why: 'Killing update-checker.ps1 does nothing durable: the WMI event subscription (and the scheduled task and Run key) will relaunch it within the hour — exactly why Desktop\'s two "cleanups" failed. You must enumerate and remove every persistence mechanism and contain the host, not just kill the process.', match: { tool: 'ticket', action: 'reply', target: 'r_killonly' }, skill: 'security', penalty: 0.5 },
    { id: 'delete_benign', label: 'Deleted the legitimate Halberd Inventory task', why: 'The "Halberd Inventory" scheduled task is the EDR agent\'s own inventory job authored by mreyes — deleting it breaks endpoint telemetry. Remove the attacker task (SystemHealthCheck), not the vendor one.', match: { tool: 'rdp', action: 'delete_task', params: { task: /halberd/i } }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'DEN-LT-1051 (dkim) reinfects because the persistence is fileless: a permanent WMI event subscription — __EventFilter "UpdateFilter" bound to CommandLineEventConsumer "UpdateConsumer" (event 5861) — relaunches update-checker.ps1 via WmiPrvSE.exe on a timer, backed up by a "SystemHealthCheck" scheduled task and an HKCU Run key. That is why Desktop\'s two cleanups failed: they killed the payload but left the triggers. It beacons to 188.114.97.7 / cfg.update-checker.io. I collected triage, isolated the host, removed the scheduled task and flagged the WMI consumer + Run key for scripted removal, blocked the C2, and reset dkim. I left the legitimate Halberd Inventory task alone. Escalating to CIRT to confirm full WMI-namespace cleanup before the host is released for reimage. True positive, high.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Found the fileless WMI persistence, enumerated the redundant mechanisms, contained and removed them, and spared the benign vendor task.' },
    { id: 'r_killonly', text: 'Ended the PowerShell process and ran a Defender scan. Cleaned, closing.', scores: { communication: 0.2, security: 0.1 }, feedback: 'That is exactly what failed twice already. The WMI subscription, the task, and the Run key will respawn the payload — remove the persistence and contain the host.' },
    { id: 'r_reimage_now', text: 'Told Desktop to reimage it immediately and closed.', scores: { communication: 0.3, process: 0.2 }, feedback: 'Reimaging before triage destroys the evidence of how they got in, and without understanding the persistence you cannot confirm it will not return via a still-live account or a second host.' },
    { id: 'r_partial', text: 'Removed the SystemHealthCheck task and blocked the C2. Done.', scores: { communication: 0.4, technical: 0.4 }, feedback: 'Good start, but the WMI consumer and the Run key still relaunch the payload, and dkim\'s creds were never reset. Enumerate them all.' },
  ],
  notesRubric: [
    { label: 'the persistence (WMI event subscription / consumer)', pattern: /wmi|5861|eventconsumer|__eventfilter|subscription|wmiprvse|fileless/i },
    { label: 'the redundant mechanisms (scheduled task + Run key)', pattern: /scheduled task|systemhealthcheck|run key|hkcu|schtasks|redundan/i },
    { label: 'why kill-only failed + remove all + contain', pattern: /reinfect|respawn|relaunch|remove|triage|isolat|persistence/i },
    { label: 'block C2 + spare Halberd task + escalate CIRT', pattern: /block|188\.114\.97\.7|update-checker|halberd|cirt|escalat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Persistence - WMI Subscription', resolutionCode: 'WMI/task/Run persistence removed; host contained; C2 blocked; user reset; CIRT engaged' },
  categoryAccept: ['persistence', 'wmi', 'malware'],
  resolutionCodeAccept: ['wmi', 'persistence', 'remove', 'contain', 'cirt'],
  hints: [
    'The host reinfects after cleanup — that means persistence, not a stubborn process. Find what relaunches the payload.',
    'WmiPrvSE.exe parenting powershell plus event 5861 is a permanent WMI event subscription (fileless persistence).',
    'Enumerate everything: the WMI consumer, the SystemHealthCheck scheduled task, and the HKCU Run key all launch update-checker.ps1.',
    'Collect triage, isolate, remove all persistence (leave the Halberd Inventory task), block the C2, reset dkim, and escalate to CIRT.',
  ],
  debrief: 'WMI event-subscription persistence is a favorite because it is fileless and survives naive cleanup: an __EventFilter (a trigger, e.g. every 60 seconds of local time) is bound to a CommandLineEventConsumer (a command to run) as a permanent subscription living in the WMI repository, so killing the spawned process just resets the clock. The signal is WmiPrvSE.exe parenting an interpreter and a 5861 consumer-creation event. Real intrusions layer persistence — here a scheduled task and a Run key back up the WMI subscription — so the discipline is to enumerate and remove every mechanism, contain the host, block the C2, and reset the user, while not deleting the legitimate vendor task that happens to look scheduled. Kill-the-process-and-close is the trap that put this alert on your desk twice.',
};

// ---------------------------------------------------------------------------
// SOC2-12  Data staging before exfiltration (catch it pre-exfil)
// ---------------------------------------------------------------------------
const soc2_12: Scenario = {
  id: 'soc2-12',
  tier: 'soc2',
  title: 'A 2.4 GB archive that has not left yet',
  category: 'Exfiltration / Staging',
  difficulty: 4,
  estMinutes: 18,
  objective: 'Catch an attacker in the staging phase — a large archive of collected files built but not yet uploaded — and act on the narrow window: contain fast to stop the exfil, and preserve the archive as evidence rather than treating "nothing left yet" as "nothing happened".',
  intake: { kind: 'alert', alertId: 'ALT-50112' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50112', time: ago(12), severity: 'high', source: 'edr',
      title: '7-Zip building a large multi-part archive from Finance + Engineering shares on DEN-WS-2010',
      description: 'Halberd flagged 7z.exe on DEN-WS-2010 (nfoster) creating C:\\Users\\Public\\bk.7z (~2.4 GB, multi-part) after bulk reads of \\\\FS01\\Finance and \\\\FS01\\Engineering. A loader is beaconing to a known C2 but NO large outbound upload has occurred yet — staging in progress.',
      host: 'DEN-WS-2010', user: 'nfoster', indicators: ['DEN-WS-2010', 'bk.7z', '45.87.43.29'], mitre: ['T1560.001', 'T1074.001', 'T1005'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'DEN-WS-2010');
    // The loader (external attacker, NOT insider) + the staging archiver.
    addProc(h, { pid: 7250, name: 'msedge-update.exe', user: 'KESTREL\\nfoster', cpu: 3, mem: 62, path: 'C:\\Users\\nfoster\\AppData\\Roaming\\msedge-update.exe', signed: false, hash: '5c2f...a9', started: ago(120), parentPid: 3610 });
    addProc(h, { pid: 7460, name: '7z.exe', user: 'KESTREL\\nfoster', cpu: 22, mem: 180, path: 'C:\\Users\\Public\\7z.exe', cmdline: '7z a -v200m -pInfr@2026 C:\\Users\\Public\\bk.7z \\\\FS01\\Finance\\* \\\\FS01\\Engineering\\Projects\\*', parentPid: 7250, signed: false, started: ago(35) });
    setConn(h, [{ proto: 'TCP', local: `${h.ip}:51770`, remote: '45.87.43.29:443', state: 'ESTABLISHED', pid: 7250 }]);
    h.files.push(
      { path: 'C:\\Users\\Public\\bk.7z.001', size: 209715200, modified: ago(20), signed: false, suspicious: true },
      { path: 'C:\\Users\\Public\\bk.7z.002', size: 209715200, modified: ago(14), signed: false, suspicious: true },
      { path: 'C:\\Users\\Public\\bk.7z.003', size: 158000000, modified: ago(3), signed: false, suspicious: true },
    );
    addEvent(h, { id: 4688, time: ago(35), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A new process has been created: 7z.exe a -v200m -p<redacted> bk.7z \\\\FS01\\Finance\\* (parent msedge-update.exe)' });
    // Bulk reads that fed the archive (data collection).
    addLog(w, { time: ago(50), source: 'windows', host: 'DEN-WS-2010', user: 'nfoster', action: 'file_access', message: 'Bulk read of \\\\FS01\\Finance (payroll, contracts, 512 files) by nfoster', fields: { files: 512 } });
    addLog(w, { time: ago(44), source: 'windows', host: 'DEN-WS-2010', user: 'nfoster', action: 'file_access', message: 'Bulk read of \\\\FS01\\Engineering\\Projects\\Falcon (387 files) by nfoster', fields: { files: 387 } });
    addLog(w, { time: ago(20), source: 'firewall', host: 'DEN-WS-2010', srcIp: h.ip, dstIp: '45.87.43.29', dstPort: 443, action: 'allow', message: `ALLOW ${h.ip} -> 45.87.43.29:443 (loader beacon, small keepalives only — no bulk upload yet)`, fields: { bytesOut: 4200 } });
    // Red herring: the authorized backup service reading the same shares (benign, large but sanctioned).
    addLog(w, { time: ago(120), source: 'windows', host: 'DEN-FS01', user: 'svc_backup', action: 'file_access', message: 'FS01-Daily-Shares backup job read \\\\FS01\\Finance and \\\\FS01\\Engineering (svc_backup, authorized nightly job)', fields: {} });
    w.intel.push({ indicator: '45.87.43.29', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['c2', 'loader', 'exfil'], detail: 'Loader C2 / staging-and-exfil infrastructure. Typically pulls a staged archive over 443 after collection.' });
    w.intel.push({ indicator: '5c2f...a9', type: 'hash', verdict: 'malicious', source: 'Sandbox', tags: ['loader'], detail: 'msedge-update.exe loader. Drops 7-Zip and stages share data for exfiltration.' });
    w.chat.push({ id: 'ch-nf', with: 'nfoster', messages: [] });
  },
  contactWith: 'nfoster',
  contact: [
    { id: 'confirm', question: 'Ask nfoster: are you archiving Finance/Engineering files to C:\\Users\\Public today?', answer: 'Nora: "No. I never touch Finance files, and I would not zip anything to a Public folder. My machine has been really slow though."', purpose: 'verify', reveals: 'unauthorized' },
    { id: 'origin', question: 'Ask nfoster what she ran before the machine got slow.', answer: '"A PDF from an email that wanted me to enable editing. It flashed and closed."', purpose: 'clarify', reveals: 'initial-access' },
    { id: 'scope_q', question: 'Determine what has been staged vs. what has left (from the logs)', answer: 'A 2.4 GB multi-part 7z of Finance + Falcon files exists on disk; the loader only sent small keepalives — no bulk upload has happened yet.', purpose: 'clarify', reveals: 'pre-exfil' },
    { id: 'weather', question: 'Ask nfoster about her lunch plans.', answer: '"Not thinking about lunch, thanks."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the endpoint + evidence-handling playbooks (KB-0015 / KB-0018)', match: [{ tool: 'kb', action: 'read', target: 'KB-0015' }, { tool: 'kb', action: 'read', target: 'KB-0018' }], weight: 0.5, hint: 'KB-0018: preserve evidence before you touch anything.' },
    { id: 'tree', label: 'Saw 7z.exe spawned by the loader building the archive', match: [{ tool: 'edr', action: 'view_tree', target: 'DEN-WS-2010' }, { tool: 'edr', action: 'view_host', target: 'DEN-WS-2010' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-WS-2010' }], hint: 'A non-Public tool archiving share data to C:\\Users\\Public is staging.' },
    { id: 'archive', label: 'Found the staged multi-part archive on disk', match: [{ tool: 'rdp', action: 'view_files', target: 'DEN-WS-2010' }, { tool: 'siem', action: 'search', params: { q: /bk\.7z|7z|archive|staging|public/i } }], hint: 'The bk.7z.001/.002/.003 parts are the staged data.' },
    { id: 'notyet', label: 'Confirmed the data has NOT left yet (only small keepalives outbound)', match: [{ tool: 'siem', action: 'search', params: { q: /45\.87\.43\.29|keepalive|upload|bytesout/i } }, { tool: 'siem', action: 'pivot', params: { value: /45\.87\.43\.29/ } }], hint: 'Compare bytes out to the archive size — has the upload happened?' },
    { id: 'collect', label: 'Saw the bulk share reads that fed the archive', match: { tool: 'siem', action: 'search', params: { q: /bulk read|finance|falcon|512|387|file_access/i } }, weight: 0.5 },
    { id: 'intel', label: 'Confirmed the C2 IP / loader hash in intel', match: [{ tool: 'intel', action: 'lookup', target: '45.87.43.29' }, { tool: 'intel', action: 'lookup', target: '5c2f...a9' }] },
  ],
  required: [
    { id: 'triage', label: 'Collected triage (preserving the archive) before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-WS-2010' }, skill: 'process', before: 'isolate' },
    { id: 'isolate', label: 'Isolated the host fast to stop the pending exfil', match: { tool: 'edr', action: 'isolate', target: 'DEN-WS-2010' }, skill: 'technical' },
    { id: 'block', label: 'Blocked the C2 at the perimeter (belt-and-suspenders)', match: { tool: 'perimeter', action: 'block', target: '45.87.43.29' }, skill: 'technical' },
    { id: 'reset', label: 'Reset the user\'s credentials (host compromised)', match: [{ tool: 'directory', action: 'reset_password', target: 'nfoster' }, { tool: 'directory', action: 'revoke_sessions', target: 'nfoster' }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'wait', label: 'Decided nothing left yet, so monitored / closed as benign', why: 'Staging IS the incident. A 2.4 GB archive of payroll, contracts, and Falcon designs is built and a known exfil C2 is connected — the upload is minutes away. "Nothing has left yet" is the reason to contain NOW, not to wait and watch it leave.', match: { tool: 'ticket', action: 'reply', target: 'r_wait' }, skill: 'security', penalty: 0.5 },
    { id: 'reimage_early', label: 'Reimaged / wiped the host (and the archive) before triage', why: 'Reimaging before collecting triage destroys the staged archive and the loader — the evidence of what was targeted and how they got in. Isolate (which cuts the network and preserves disk), collect triage, THEN let CIRT decide on rebuild.', match: [{ tool: 'incident', action: 'reimage', target: 'DEN-WS-2010' }, { tool: 'rdp', action: 'quarantine_file', params: { path: /bk\.7z/i } }], skill: 'process', penalty: 0.4, unlessAfter: 'triage' },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'We caught this in the staging phase — the best possible time. A loader (msedge-update.exe) on DEN-WS-2010 (nfoster) dropped 7-Zip and built a 2.4 GB multi-part archive (bk.7z.001-003) in C:\\Users\\Public from bulk reads of \\\\FS01\\Finance (payroll, contracts) and the Falcon engineering project. The loader is connected to a known exfil C2 (45.87.43.29) but has only sent small keepalives — the data has NOT left yet. I collected triage (preserving the archive) and isolated the host immediately to close the window, blocked the C2, and reset nfoster. I confirmed the concurrent share reads by svc_backup are the authorized nightly backup, not the attacker. Escalating to CIRT as a confirmed intrusion with staged, not-yet-exfiltrated, regulated data — flagging Legal given the payroll/contract content. True positive, high.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Recognized staging as the incident, contained fast to beat the upload, preserved the archive, and ruled out the benign backup job.' },
    { id: 'r_wait', text: 'The archive has not been uploaded, so no data loss yet — I will keep monitoring and close if nothing leaves.', scores: { communication: 0.2, security: 0.1 }, feedback: 'Watching a packed archive next to a live exfil C2 is watching the crime in slow motion. Staging is the incident; contain now.' },
    { id: 'r_deletearchive', text: 'Deleted bk.7z to stop the exfil and ran a scan. Closed.', scores: { communication: 0.3, security: 0.2, process: 0.1 }, feedback: 'Deleting the archive destroys evidence of exactly what was targeted, and the loader and stolen creds remain. Isolate and preserve, do not wipe.' },
    { id: 'r_partial', text: 'Blocked the C2 IP at the firewall — the archive can\'t go anywhere now.', scores: { communication: 0.4, technical: 0.4 }, feedback: 'A block helps, but the loader can switch infrastructure and nfoster\'s creds are exposed. Isolate the host (triage first) and reset her.' },
  ],
  notesRubric: [
    { label: 'the phase (data staging, pre-exfil, archive built not sent)', pattern: /stag|archive|7z|bk\.7z|pre.?exfil|not.*(left|uploaded|sent)|2\.4/i },
    { label: 'the data collected (Finance/payroll/contracts + Falcon)', pattern: /finance|payroll|contract|falcon|engineering|share|bulk read/i },
    { label: 'contain fast + preserve (triage before isolate, do not wipe)', pattern: /triage|preserv|isolat|contain|before|evidence/i },
    { label: 'block C2 + ruled out backup + escalate CIRT/Legal', pattern: /block|45\.87\.43\.29|svc_backup|backup|cirt|legal|escalat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Exfil - Data Staging', resolutionCode: 'Caught pre-exfil; archive preserved; host contained; C2 blocked; user reset; CIRT/Legal engaged' },
  categoryAccept: ['exfil', 'staging', 'data'],
  resolutionCodeAccept: ['stag', 'pre-exfil', 'contain', 'preserve', 'cirt'],
  hints: [
    'A loader dropped 7-Zip and is building a 2.4 GB archive of Finance + Engineering data in C:\\Users\\Public — that is staging.',
    'Check outbound bytes vs. the archive size: only small keepalives have gone out, so the data has not been exfiltrated yet.',
    'Staging is the incident. Collect triage (preserve the archive), then isolate the host FAST to beat the upload.',
    'Block the C2, reset nfoster, rule out the authorized svc_backup share reads, and escalate to CIRT/Legal for the regulated data.',
  ],
  debrief: 'Attackers rarely exfiltrate file-by-file; they collect from shares, compress into a password-protected multi-part archive, then upload it in one burst. Catching the staging phase — archive built, exfil C2 connected, but the big upload not yet sent — is a gift, because containment now prevents the loss entirely. The reasoning trap is "no bytes left, no incident": the packed 2.4 GB of payroll, contracts, and design data sitting next to a live C2 is precisely the moment to act. The discipline is speed plus preservation: collect triage so the archive and loader are captured (they prove what was targeted and how entry happened), isolate to cut the network while keeping disk intact, block the C2, reset the user, and hand a scoped intrusion to CIRT and Legal — never wipe the host or watch the upload happen.',
};

// ---------------------------------------------------------------------------
// SOC2-13  Credential stuffing success across SaaS (password reuse)
// ---------------------------------------------------------------------------
const soc2_13: Scenario = {
  id: 'soc2-13',
  tier: 'soc2',
  title: 'One password, many doors',
  category: 'Identity / Credential Stuffing',
  difficulty: 4,
  estMinutes: 17,
  objective: 'Separate a noisy credential-stuffing spray from the one account it actually broke into, understand why password reuse turns a breach elsewhere into access here, and scope the compromise across every SaaS the reused password opened.',
  intake: { kind: 'alert', alertId: 'ALT-50113' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50113', time: ago(18), severity: 'high', source: 'siem',
      title: 'Credential-stuffing spray from 185.220.101.62 with a successful login for dkim across multiple SaaS apps',
      description: 'The SIEM saw hundreds of failed logins across many usernames from 185.220.101.62 (Tor exit), then SUCCESS for dkim on WorkSuite SSO, the Greenhouse ATS, and the Kestrel ERP portal — no interactive MFA on the SaaS apps. Password-reuse credential stuffing with at least one confirmed hit.',
      user: 'dkim', indicators: ['185.220.101.62', 'dkim', 'greenhouse', 'ERP'], mitre: ['T1110.004', 'T1078.004', 'T1621'], status: 'new', truth: 'true_positive',
    });
    const d = findUser(w, 'dkim')!;
    // dkim's successful compromise from the attacker IP; MFA not challenged on the federated SaaS.
    d.recentSignIns = [
      { time: ago(400), ip: '10.10.20.51', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1051', mfa: 'satisfied' },
      { time: ago(16), ip: '185.220.101.62', location: 'Tor exit (unknown)', app: 'WorkSuite SSO', result: 'success', device: 'unknown', mfa: 'not required' },
    ];
    // The spray: many failures across users, then the successes for dkim.
    for (let i = 0; i < 6; i++) {
      const u = ['jmorales', 'bpatel', 'sturner', 'jwebb', 'cflores', 'hsato'][i];
      addLog(w, { time: ago(30 - i * 0.5), source: 'cloud', user: u, srcIp: '185.220.101.62', action: 'signin', message: `WorkSuite sign-in FAILURE ${u} from 185.220.101.62 (bad password) — credential stuffing`, fields: { result: 'failure', reason: 'bad-password' } });
    }
    addLog(w, { time: ago(16), source: 'cloud', user: 'dkim', srcIp: '185.220.101.62', action: 'signin', message: 'WorkSuite SSO sign-in SUCCESS dkim from 185.220.101.62 (Tor) — reused password matched; MFA not required for this app', fields: { result: 'success', mfa: 'not-required' } });
    addLog(w, { time: ago(14), source: 'cloud', user: 'dkim', srcIp: '185.220.101.62', action: 'saas_login', message: 'Greenhouse ATS login SUCCESS dkim via SSO from 185.220.101.62 — accessed 40 candidate records with PII', fields: { app: 'Greenhouse', records: 40 } });
    addLog(w, { time: ago(11), source: 'cloud', user: 'dkim', srcIp: '185.220.101.62', action: 'saas_login', message: 'Kestrel ERP portal login SUCCESS dkim from 185.220.101.62 — viewed vendor + payroll screens', fields: { app: 'ERP' } });
    addLog(w, { time: ago(9), source: 'cloud', user: 'dkim', srcIp: '185.220.101.62', action: 'mfa_enroll', message: 'Attempt to register a new authenticator for dkim from 185.220.101.62 (MFA persistence)', fields: {} });
    // Red herring: sturner locked out by her OWN saved phone password (benign, internal IP, not the spray).
    d.notes = 'Password last set 84 days ago; same string appears in a public breach corpus (haveibeenpwned match).';
    for (let i = 0; i < 3; i++) {
      addLog(w, { time: ago(200 - i * 5), source: 'auth', host: 'DEN-LT-1050', user: 'sturner', srcIp: '10.10.20.50', action: 'logon', message: '4625 Logon failure sturner from her own device 10.10.20.50 (stale saved password in phone mail app) — benign lockout cause', fields: { eventId: 4625 } });
    }
    w.intel.push({ indicator: '185.220.101.62', type: 'ip', verdict: 'malicious', source: 'threat feed', tags: ['tor', 'credential-stuffing', 'brute-force'], detail: 'Tor exit node repeatedly used for credential-stuffing sprays against SaaS SSO endpoints.' });
    w.chat.push({ id: 'ch-dk', with: 'dkim', messages: [] });
  },
  contactWith: 'dkim',
  contact: [
    { id: 'confirm', question: 'Ask dkim: did you sign in via Tor, and do you reuse this password on personal sites?', answer: 'David: "No, I have not travelled or used Tor. And... yeah, honestly I use the same password on a few personal sites. Was one of them breached?"', purpose: 'verify', reveals: 'reuse' },
    { id: 'mfa_q', question: 'Ask dkim if he registered a new authenticator app today.', answer: '"No, I did not add any new authenticator."', purpose: 'clarify', reveals: 'mfa-persistence' },
    { id: 'saas_q', question: 'Determine which SaaS apps the attacker reached with the reused password', answer: 'WorkSuite SSO, the Greenhouse ATS (40 candidate PII records viewed), and the Kestrel ERP portal — none of which forced MFA.', purpose: 'clarify', reveals: 'scope' },
    { id: 'weather', question: 'Ask dkim about his weekend plans.', answer: '"Can we sort my account out first?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the suspicious sign-in + triage playbooks (KB-0016 / KB-0013)', match: [{ tool: 'kb', action: 'read', target: 'KB-0016' }, { tool: 'kb', action: 'read', target: 'KB-0013' }], weight: 0.5 },
    { id: 'spray', label: 'Saw the spray of failures then the successful hit for dkim', match: [{ tool: 'siem', action: 'search', params: { q: /185\.220\.101\.62|stuffing|failure|success|dkim/i } }, { tool: 'siem', action: 'pivot', params: { value: /185\.220\.101\.62/ } }], hint: 'Pivot on the source IP: many failures, one success — find the success.' },
    { id: 'signins', label: 'Confirmed dkim\'s successful Tor sign-in with MFA not required', match: { tool: 'directory', action: 'view_signins', target: 'dkim' }, hint: 'The SaaS apps did not challenge MFA — that is why the reused password worked.' },
    { id: 'saas', label: 'Scoped which SaaS the reused password opened (WorkSuite/Greenhouse/ERP)', match: [{ tool: 'siem', action: 'search', params: { q: /greenhouse|ats|erp|saas_login|candidate|payroll/i } }, { tool: 'siem', action: 'pivot', params: { value: /dkim/ } }], hint: 'Reuse means one password opens many doors — enumerate them.' },
    { id: 'mfa', label: 'Spotted the attacker\'s attempt to register a new MFA method', match: { tool: 'directory', action: 'view', target: 'dkim' }, weight: 0.5, hint: 'Adding an authenticator is how they keep access after a reset.' },
    { id: 'intel', label: 'Confirmed the source IP is a stuffing Tor exit', match: { tool: 'intel', action: 'lookup', target: '185.220.101.62' } },
  ],
  required: [
    { id: 'revoke', label: 'Revoked dkim\'s sessions/tokens', match: { tool: 'directory', action: 'revoke_sessions', target: 'dkim' }, skill: 'security' },
    { id: 'reset', label: 'Reset dkim\'s password after revoking', match: { tool: 'directory', action: 'reset_password', target: 'dkim' }, skill: 'security', after: 'revoke' },
    { id: 'mfa', label: 'Reset/enforced MFA (removes the attacker\'s registered method)', match: { tool: 'directory', action: 'reset_mfa', target: 'dkim' }, skill: 'security' },
    { id: 'block', label: 'Blocked the stuffing source IP at the perimeter', match: { tool: 'perimeter', action: 'block', target: '185.220.101.62' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'noise', label: 'Closed as blocked brute-force / noise, missing the success', why: 'A spray with hundreds of failures is easy to wave off as noise, but dkim\'s login SUCCEEDED from Tor and reached Greenhouse (PII) and the ERP. Closing as "brute force, all blocked" leaves an actively compromised account with an attacker MFA method registered.', match: { tool: 'ticket', action: 'reply', target: 'r_noise' }, skill: 'security', penalty: 0.5 },
    { id: 'chase_benign', label: 'Reset/disabled sturner over her benign lockout', why: 'sturner\'s 4625 failures are from her OWN device (10.10.20.50) — a stale saved password in a phone mail app, not the Tor spray. Actioning her account is a false positive; she is not one of the compromised users.', match: [{ tool: 'directory', action: 'disable', target: 'sturner' }, { tool: 'directory', action: 'reset_password', target: 'sturner' }], skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is a credential-stuffing spray from 185.220.101.62 (Tor) that landed. Amid hundreds of failures across users, dkim\'s WorkSuite SSO login SUCCEEDED because he reused a password that is in a public breach corpus, and no SaaS forced MFA — so the attacker pivoted through SSO into the Greenhouse ATS (40 candidate PII records viewed) and the Kestrel ERP portal, and tried to register a new authenticator for persistence. I revoked dkim\'s sessions, reset his password, reset his MFA to strip the attacker\'s method, and blocked the source IP. I ruled out sturner\'s failures as her own stale phone password. Escalating to CIRT to review the Greenhouse PII exposure (Legal) and to enforce MFA on all federated SaaS. True positive, high.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Found the one success in the noise, scoped the SaaS blast radius, stripped the attacker MFA method, and avoided the benign lockout.' },
    { id: 'r_noise', text: 'Hundreds of failed logins from a Tor node — brute force, all blocked. Closing as noise/false positive.', scores: { communication: 0.2, security: 0.1 }, feedback: 'One of those attempts succeeded. dkim is compromised across three SaaS apps with an attacker MFA method pending — this is not noise.' },
    { id: 'r_pwonly', text: 'Reset dkim\'s password and told him to stop reusing it. Closed.', scores: { communication: 0.4, security: 0.3 }, feedback: 'Good instinct, but you left his sessions live and the attacker\'s new authenticator registered — revoke sessions and reset MFA, and block the source.' },
    { id: 'r_partial', text: 'Blocked 185.220.101.62 at the perimeter. Attacker is cut off, done.', scores: { communication: 0.4, technical: 0.4 }, feedback: 'They will rotate to another Tor exit. dkim\'s creds and MFA are still compromised and his SaaS sessions are live — reset and revoke him.' },
  ],
  notesRubric: [
    { label: 'the technique (credential stuffing / password reuse, one success)', pattern: /stuffing|spray|reuse|reused|breach corpus|185\.220\.101\.62|tor|one success/i },
    { label: 'the SaaS blast radius (WorkSuite/Greenhouse PII/ERP, no MFA)', pattern: /greenhouse|ats|erp|saas|pii|candidate|no.*mfa|mfa not/i },
    { label: 'containment: revoke + reset + reset MFA + block', pattern: /revoke|reset|mfa|block|authenticator|session/i },
    { label: 'ruled out benign lockout + escalate CIRT/Legal', pattern: /sturner|benign|ruled out|cirt|legal|enforce mfa|escalat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Identity - Credential Stuffing', resolutionCode: 'Account reset+revoked; MFA reset; source blocked; SaaS scope + PII escalated to CIRT/Legal' },
  categoryAccept: ['stuffing', 'identity', 'credential', 'reuse'],
  resolutionCodeAccept: ['stuffing', 'revoke', 'mfa', 'reset', 'cirt'],
  hints: [
    'Pivot on the source IP: hundreds of failures across users, but look for the one login that SUCCEEDED.',
    'dkim reused a breached password and the SaaS apps did not force MFA — so the attacker reached WorkSuite, Greenhouse (PII) and the ERP.',
    'Contain the account: revoke sessions, reset the password, and reset MFA to remove the attacker\'s registered authenticator; block the source IP.',
    'sturner\'s failures are from her own device (stale phone password) — do not action her. Escalate the PII exposure to CIRT/Legal and enforce SaaS MFA.',
  ],
  debrief: 'Credential stuffing weaponizes password reuse: attackers replay username/password pairs leaked from other breaches against your SSO and SaaS logins, so almost everything fails — until it doesn\'t. The analytic move is to pivot on the source and find the single success buried in the noise, then scope the blast radius, because with SSO one reused password opens every federated app that did not independently enforce MFA. Here dkim\'s hit reached an ATS full of candidate PII and the ERP, and the attacker tried to register their own MFA method for durable access — so containment must revoke sessions, reset the password, AND reset MFA, not just change the password. The foil is a benign lockout from a user\'s own stale saved password; actioning her would be chasing noise while the real account stays open.',
};

// ---------------------------------------------------------------------------
// SOC2-14  Public cloud storage exposure (misconfiguration)
// ---------------------------------------------------------------------------
const soc2_14: Scenario = {
  id: 'soc2-14',
  tier: 'soc2',
  title: 'The backup bucket the whole internet can read',
  category: 'Cloud / Data Exposure',
  difficulty: 4,
  estMinutes: 16,
  priorityExpected: 'P1',
  tools: ['incident'],
  objective: 'Handle a cloud data-exposure alert where the "attack" is a misconfiguration: a world-readable storage container. Confirm the exposure, distinguish anonymous public reads from authorized replication, stop the bleeding, and hand the exposure assessment to CIRT and Legal.',
  intake: { kind: 'alert', alertId: 'ALT-50114' },
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50114', time: ago(25), severity: 'high', source: 'cloud',
      title: 'Storage container "kestrel-offsite-backups" is world-readable; anonymous downloads observed',
      description: 'Cloud posture flagged the blob container kestrel-offsite-backups (holding SQL backups + HR exports) with public "list + read" access. Access logs show anonymous GETs from several external IPs enumerating and downloading objects over the last day.',
      indicators: ['kestrel-offsite-backups', 'anonymous-read', '203.0.113.66'], mitre: ['T1530', 'T1580'], status: 'new', truth: 'true_positive',
    });
    // Anonymous public reads from several external IPs (the exposure).
    addLog(w, { time: ago(300), source: 'cloud', action: 'storage_config', message: 'Container kestrel-offsite-backups ACL changed to public "list+read" (anonymous) during a migration change by contractor abaxter', fields: { container: 'kestrel-offsite-backups', acl: 'public-read' } });
    addLog(w, { time: ago(120), source: 'cloud', srcIp: '203.0.113.66', action: 'storage_read', message: 'Anonymous GET (no auth) LIST kestrel-offsite-backups then download APP01-SQL-Full.bak (2.1GB) from 203.0.113.66', fields: { container: 'kestrel-offsite-backups', auth: 'anonymous', bytes: 2100000000 } });
    addLog(w, { time: ago(90), source: 'cloud', srcIp: '198.51.100.77', action: 'storage_read', message: 'Anonymous GET (no auth) download HR-exports/payroll-2026Q3.csv from 198.51.100.77', fields: { container: 'kestrel-offsite-backups', auth: 'anonymous' } });
    addLog(w, { time: ago(40), source: 'cloud', srcIp: '45.155.205.90', action: 'storage_read', message: 'Anonymous GET (no auth) LIST kestrel-offsite-backups (mass enumeration) from 45.155.205.90', fields: { container: 'kestrel-offsite-backups', auth: 'anonymous' } });
    // Red herring: the AUTHORIZED offsite replication service reading the same container (authenticated, expected).
    addLog(w, { time: ago(60), source: 'cloud', srcIp: '20.150.44.10', user: 'svc_backup', action: 'storage_read', message: 'Authenticated read of kestrel-offsite-backups by svc_backup from 20.150.44.10 (Offsite-Immutable-Copy replication job, authorized)', fields: { container: 'kestrel-offsite-backups', auth: 'sas-token', job: 'Offsite-Immutable-Copy' } });
    w.intel.push({ indicator: '203.0.113.66', type: 'ip', verdict: 'suspicious', source: 'community feed', tags: ['scanner', 'cloud-enum'], detail: 'Cloud-storage enumeration host; scans for public buckets/containers and pulls readable objects.' });
    w.intel.push({ indicator: '45.155.205.90', type: 'ip', verdict: 'malicious', source: 'threat feed', tags: ['cloud-enum', 'exposure'], detail: 'Known automated public-bucket harvesting infrastructure.' });
    w.intel.push({ indicator: '20.150.44.10', type: 'ip', verdict: 'clean', source: 'Vendor allowlist', tags: ['cloud', 'backup'], detail: 'Kestrel offsite replication endpoint (authorized, uses SAS token, not anonymous).' });
    w.chat.push({ id: 'ch-ab', with: 'abaxter', messages: [] });
    w.chat.push({ id: 'ch-mr', with: 'mreyes', messages: [] });
  },
  contactWith: 'mreyes',
  contact: [
    { id: 'owner', question: 'Ask mreyes: should kestrel-offsite-backups ever be publicly readable?', answer: 'Marco: "Absolutely not. It holds SQL backups and HR exports — it should only be reachable by the replication service with a SAS token. If it is public, that is a misconfiguration."', purpose: 'verify', reveals: 'misconfig' },
    { id: 'change_q', question: 'Ask who changed the container ACL and when.', answer: '"The change log shows the contractor abaxter flipped it to public during last week\'s migration. That was a mistake, not sanctioned."', purpose: 'clarify', reveals: 'root-cause' },
    { id: 'scope_q', question: 'Determine what was exposed and who read it anonymously', answer: 'A full SQL backup (2.1GB) and payroll-2026Q3.csv were downloaded anonymously from three external IPs; the svc_backup reads are the authorized SAS-token replication.', purpose: 'clarify', reveals: 'exposure' },
    { id: 'weather', question: 'Ask mreyes how his day is going.', answer: '"Better once this container is private."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the triage standard + IR/evidence playbooks (KB-0013 / KB-0018)', match: [{ tool: 'kb', action: 'read', target: 'KB-0013' }, { tool: 'kb', action: 'read', target: 'KB-0018' }], weight: 0.5, hint: 'KB-0017/0018: personal-data exposure means Legal decides on notification, not the analyst.' },
    { id: 'config', label: 'Confirmed the container is public (ACL change in the cloud logs)', match: [{ tool: 'siem', action: 'search', params: { q: /kestrel-offsite-backups|public|acl|anonymous|storage_config/i } }, { tool: 'siem', action: 'pivot', params: { value: /kestrel-offsite-backups/ } }], hint: 'Find when and by whom the ACL was flipped to public.' },
    { id: 'reads', label: 'Scoped the anonymous downloads (SQL backup + payroll CSV)', match: { tool: 'siem', action: 'search', params: { q: /anonymous|storage_read|payroll|APP01-SQL|download/i } }, hint: 'Which objects were pulled, and by which external IPs, without auth?' },
    { id: 'rule_out', label: 'Distinguished the authorized SAS-token replication from anonymous reads', match: [{ tool: 'intel', action: 'lookup', target: '20.150.44.10' }, { tool: 'siem', action: 'pivot', params: { value: /svc_backup/ } }], hint: 'One reader is the legitimate offsite replication job — not an attacker.' },
    { id: 'intel', label: 'Confirmed the enumerating IPs in intel', match: [{ tool: 'intel', action: 'lookup', target: '45.155.205.90' }, { tool: 'intel', action: 'lookup', target: '203.0.113.66' }] },
  ],
  required: [
    { id: 'restrict', label: 'Stopped the exposure by blocking anonymous public access (interim)', match: [{ tool: 'perimeter', action: 'block', target: /kestrel-offsite-backups/ }, { tool: 'perimeter', action: 'block', target: '45.155.205.90' }], skill: 'technical' },
    { id: 'legal', label: 'Preserved the access logs / triggered legal hold for the exposure', match: { tool: 'incident', action: 'legal_hold' }, skill: 'process', after: 'restrict' },
  ],
  forbidden: [
    { id: 'noise', label: 'Closed as internet scanner noise / informational', why: 'The container was genuinely world-readable and a full SQL backup and a payroll CSV were downloaded anonymously. This is a real data exposure of regulated data — not scan noise — and closing it skips the exposure assessment and the Legal notification decision.', match: { tool: 'ticket', action: 'reply', target: 'r_noise' }, skill: 'security', penalty: 0.5 },
    { id: 'block_repl', label: 'Blocked the authorized offsite replication endpoint', why: '20.150.44.10 (svc_backup, SAS token) is the sanctioned Offsite-Immutable-Copy replication job, not an attacker. Blocking it breaks the offsite backup chain — remove PUBLIC/anonymous access, do not cut the legitimate authenticated reader.', match: { tool: 'perimeter', action: 'block', target: '20.150.44.10' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is a cloud data-exposure via misconfiguration, not an intrusion. The kestrel-offsite-backups container was flipped to public "list+read" during last week\'s migration (change by contractor abaxter), and anonymous external IPs (203.0.113.66, 198.51.100.77, 45.155.205.90) enumerated it and downloaded a full 2.1GB SQL backup and payroll-2026Q3.csv — regulated data. I confirmed the ACL change and scoped the anonymous downloads, and distinguished them from the authorized svc_backup SAS-token replication (20.150.44.10), which I left alone. I stopped the bleeding by blocking public/anonymous access at the perimeter and preserved the access logs under legal hold. Escalating to CIRT to make the container private and rotate the exposed backup/DB credentials, and to Legal, who owns the regulatory/customer-notification decision given the HR PII. True positive, high.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Confirmed a real exposure, scoped it, cut public access without breaking replication, preserved evidence, and routed the notification decision to Legal.' },
    { id: 'r_noise', text: 'Just internet scanners hitting a bucket — informational. Closing as noise.', scores: { communication: 0.2, security: 0.1 }, feedback: 'The container was actually public and regulated data was downloaded anonymously. That is a reportable exposure, not scanner noise.' },
    { id: 'r_partial', text: 'Blocked the scanning IPs at the perimeter. Done.', scores: { communication: 0.4, technical: 0.3 }, feedback: 'Blocking a few IPs does not fix a public container — anyone else can still read it. Cut anonymous access, preserve logs, and escalate to CIRT/Legal.' },
  ],
  notesRubric: [
    { label: 'the root cause (public/world-readable container misconfig)', pattern: /public|world.?read|anonymous|acl|misconfig|kestrel-offsite-backups/i },
    { label: 'the exposure scoped (SQL backup + payroll/HR PII downloaded)', pattern: /sql|backup|payroll|hr|pii|download|2\.1|regulated/i },
    { label: 'stop the bleeding + preserve + rule out authorized replication', pattern: /private|block|anonymous|preserv|legal hold|svc_backup|sas|replication/i },
    { label: 'escalate CIRT + Legal owns notification', pattern: /cirt|legal|notif|regulator|rotate|escalat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Cloud - Data Exposure', resolutionCode: 'Public access cut; exposure scoped; logs preserved; CIRT to lock down + Legal for notification' },
  categoryAccept: ['cloud', 'exposure', 'data', 'bucket'],
  resolutionCodeAccept: ['exposure', 'public', 'private', 'legal', 'cirt'],
  hints: [
    'This is a misconfiguration, not an intrusion: the container ACL was flipped to public during a migration.',
    'Scope it: a full SQL backup and a payroll CSV were downloaded anonymously by several external IPs.',
    'One reader (svc_backup, 20.150.44.10, SAS token) is the authorized replication job — do not block it.',
    'Cut anonymous public access, preserve the access logs, and escalate to CIRT to lock it down and to Legal, who owns the notification call for the HR PII.',
  ],
  debrief: 'Not every high-severity cloud alert is an attacker; some are your own misconfiguration doing the attacker\'s work. A storage container flipped to public "list+read" — often during a migration by someone without the full picture — lets anyone on the internet enumerate and download objects with no authentication, and automated harvesters find these within hours. The analytic tasks are to confirm the exposure and its root cause, scope exactly what was readable and what was actually pulled, and carefully separate anonymous public reads from the authorized, authenticated replication that legitimately touches the same data. Remediation is to cut public access immediately, preserve the access logs, and rotate any credentials in the exposed backups. Because regulated HR/PII was involved, the notification decision belongs to Legal, not the analyst — the SOC confirms, contains, and escalates.',
};

// ---------------------------------------------------------------------------
// SOC2-15  Ransomware operator recon before encryption
// ---------------------------------------------------------------------------
const soc2_15: Scenario = {
  id: 'soc2-15',
  tier: 'soc2',
  title: 'Mapping the domain right before the lights go out',
  category: 'Pre-Ransomware',
  difficulty: 5,
  estMinutes: 19,
  objective: 'Recognize hands-on-keyboard ransomware pre-encryption reconnaissance (BloodHound, net/AD discovery) for the emergency it is, and contain fast to deny the operator the map they need to detonate estate-wide.',
  intake: { kind: 'alert', alertId: 'ALT-50115' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50115', time: ago(8), severity: 'critical', source: 'edr',
      title: 'BloodHound/AD reconnaissance burst from DEN-LT-1042 (bpatel) — ransomware pre-encryption pattern',
      description: 'Halberd flagged SharpHound.exe plus a rapid burst of net/AD discovery (net group "Domain Admins", net view /all, nltest /dclist, net accounts) on DEN-LT-1042 (bpatel), with a live operator C2. This is the recon that immediately precedes ransomware deployment. No encryption yet — act now.',
      host: 'DEN-LT-1042', user: 'bpatel', indicators: ['DEN-LT-1042', 'SharpHound.exe', '193.239.85.55'], mitre: ['T1087.002', 'T1482', 'T1069.002', 'T1018'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'DEN-LT-1042');
    addProc(h, { pid: 8120, name: 'SharpHound.exe', user: 'KESTREL\\bpatel', cpu: 18, mem: 210, path: 'C:\\Users\\bpatel\\AppData\\Local\\Temp\\SharpHound.exe', signed: false, hash: '7ad9...b2', started: ago(10) });
    addProc(h, { pid: 7005, name: 'cobaltstrike-beacon.dll(host)', user: 'KESTREL\\bpatel', cpu: 2, mem: 44, path: 'C:\\Users\\bpatel\\AppData\\Roaming\\rundll32.exe', cmdline: 'rundll32.exe beacon.dll,Start', signed: false, hash: 'c8e1...44', started: ago(140), parentPid: 3610 });
    setConn(h, [{ proto: 'TCP', local: `${h.ip}:51990`, remote: '193.239.85.55:443', state: 'ESTABLISHED', pid: 7005 }]);
    // The recon command burst.
    const cmds = ['net group "Domain Admins" /domain', 'net group "Enterprise Admins" /domain', 'net view /all', 'nltest /dclist:kestrel.local', 'net accounts /domain', 'net localgroup administrators'];
    for (let i = 0; i < cmds.length; i++) {
      addEvent(h, { id: 4688, time: ago(9 - i * 0.3), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: `A new process has been created: cmd.exe /c ${cmds[i]} (KESTREL\\bpatel)` });
      addLog(w, { time: ago(9 - i * 0.3), source: 'windows', host: 'DEN-LT-1042', user: 'bpatel', action: 'process', message: `4688 discovery: ${cmds[i]} on DEN-LT-1042`, fields: { eventId: 4688 } });
    }
    addLog(w, { time: ago(10), source: 'edr', host: 'DEN-LT-1042', user: 'bpatel', action: 'alert', message: 'SharpHound.exe collected AD objects (users, groups, sessions, ACLs) to a .zip in Temp', process: 'SharpHound.exe' });
    addLog(w, { time: ago(140), source: 'firewall', host: 'DEN-LT-1042', srcIp: h.ip, dstIp: '193.239.85.55', dstPort: 443, action: 'allow', message: `ALLOW ${h.ip} -> 193.239.85.55:443 (Cobalt Strike beacon, jittered)` });
    // Red herring: mreyes running a single legitimate "net group" during authorized admin work.
    addLog(w, { time: ago(70), source: 'windows', host: 'DEN-LT-1021', user: 'mreyes', action: 'process', message: '4688 net group "Server Admins" /domain on DEN-LT-1021 (mreyes, single authorized admin lookup)', fields: { eventId: 4688 } });
    w.intel.push({ indicator: '193.239.85.55', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['cobalt-strike', 'c2', 'ransomware-precursor'], detail: 'Cobalt Strike C2 associated with ransomware affiliates. Recon here typically precedes domain-wide encryption within hours.' });
    w.intel.push({ indicator: '7ad9...b2', type: 'hash', verdict: 'malicious', source: 'Sandbox', tags: ['bloodhound', 'sharphound', 'recon'], detail: 'SharpHound (BloodHound collector). Maps AD attack paths to Domain Admin.' });
    w.chat.push({ id: 'ch-bp', with: 'bpatel', messages: [] });
    w.chat.push({ id: 'ch-mr', with: 'mreyes', messages: [] });
  },
  contactWith: 'bpatel',
  contact: [
    { id: 'confirm', question: 'Ask bpatel: are you running any admin or AD-mapping tools right now?', answer: 'Bhavik: "No — I am in Accounts Payable, I do not run domain commands. My laptop has been really laggy for the last couple of hours."', purpose: 'verify', reveals: 'unauthorized' },
    { id: 'origin', question: 'Ask bpatel what he opened a couple of hours ago.', answer: '"An invoice attachment that wanted macros enabled. It seemed to do nothing."', purpose: 'clarify', reveals: 'initial-access' },
    { id: 'scope_q', question: 'Confirm what the recon targeted (from the events)', answer: 'A burst of Domain/Enterprise Admins enumeration, DC listing, net view, and a SharpHound AD collection to Temp — mapping paths to Domain Admin.', purpose: 'clarify', reveals: 'recon' },
    { id: 'weather', question: 'Ask bpatel about his lunch.', answer: '"Please just fix my laptop."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the endpoint + IR lifecycle playbooks (KB-0015 / KB-0018)', match: [{ tool: 'kb', action: 'read', target: 'KB-0015' }, { tool: 'kb', action: 'read', target: 'KB-0018' }], weight: 0.5 },
    { id: 'tree', label: 'Saw SharpHound + the Cobalt Strike beacon in the process tree', match: [{ tool: 'edr', action: 'view_tree', target: 'DEN-LT-1042' }, { tool: 'edr', action: 'view_host', target: 'DEN-LT-1042' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1042' }], hint: 'SharpHound + a beacon is a hands-on-keyboard operator, not a script.' },
    { id: 'recon', label: 'Found the AD-discovery command burst in the events', match: [{ tool: 'siem', action: 'search', params: { q: /domain admins|net group|nltest|net view|sharphound|discovery/i } }, { tool: 'rdp', action: 'view_events', target: 'DEN-LT-1042' }], hint: 'A rapid burst of Domain Admins / DC enumeration is the pre-ransomware map.' },
    { id: 'c2', label: 'Confirmed the operator C2 beacon in the logs', match: { tool: 'siem', action: 'search', params: { q: /193\.239\.85\.55|cobalt|beacon/i } }, hint: 'A jittered 443 beacon is the live operator channel.' },
    { id: 'intel', label: 'Confirmed the C2 IP / SharpHound hash in intel', match: [{ tool: 'intel', action: 'lookup', target: '193.239.85.55' }, { tool: 'intel', action: 'lookup', target: '7ad9...b2' }] },
    { id: 'rule_out', label: 'Distinguished mreyes\'s single authorized net group lookup', match: { tool: 'siem', action: 'pivot', params: { value: /mreyes/ } }, weight: 0.5 },
  ],
  required: [
    { id: 'triage', label: 'Collected triage on the host before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1042' }, skill: 'process', before: 'isolate' },
    { id: 'isolate', label: 'Isolated the host immediately to deny detonation', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1042' }, skill: 'technical' },
    { id: 'reset', label: 'Reset the compromised user and revoked sessions (bpatel)', match: [{ tool: 'directory', action: 'reset_password', target: 'bpatel' }, { tool: 'directory', action: 'revoke_sessions', target: 'bpatel' }], skill: 'security' },
    { id: 'block', label: 'Blocked the operator C2 at the perimeter', match: { tool: 'perimeter', action: 'block', target: '193.239.85.55' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'lowsev', label: 'Treated it as low-priority internal scanning / scheduled it for later', why: 'A hands-on-keyboard operator running BloodHound and enumerating Domain Admins over a live Cobalt Strike beacon is the final step before domain-wide ransomware. Down-prioritizing or queuing it for later gives the operator the map and the time to detonate. This is contain-now, CRITICAL.', match: { tool: 'ticket', action: 'reply', target: 'r_lowsev' }, skill: 'security', penalty: 0.5 },
    { id: 'chase_benign', label: 'Contained the host mreyes ran a normal net group lookup from', why: 'mreyes ran a SINGLE authorized "net group" on his admin laptop — not a recon burst, no BloodHound, no C2. Isolating DEN-LT-1021 chases a false positive and delays containing the real host.', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1021' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is pre-ransomware reconnaissance and it is time-critical. A hands-on-keyboard operator on DEN-LT-1042 (bpatel), running over a Cobalt Strike beacon to 193.239.85.55, launched SharpHound and a rapid burst of AD discovery (net group "Domain Admins"/"Enterprise Admins", nltest /dclist, net view, net accounts) to map paths to Domain Admin — the step that immediately precedes estate-wide encryption. There is no encryption yet, so the priority is to deny them the finish: I collected fast triage and isolated the host, reset bpatel and revoked his sessions, and blocked the operator C2. I ruled out mreyes\'s single authorized net group lookup. Escalating to CIRT as CRITICAL right now to hunt for other beacons and any privileged accounts the operator may already hold before they can deploy. True positive, critical.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Read the pre-ransomware pattern, contained fast to deny detonation, and did not get baited by the benign admin lookup.' },
    { id: 'r_lowsev', text: 'Looks like internal enumeration / a curious user. Low severity — I will schedule a look later.', scores: { communication: 0.2, security: 0.1 }, feedback: 'BloodHound + Domain Admins enumeration over a Cobalt Strike beacon is the ransomware pre-game. "Later" is when the estate gets encrypted. Contain now, critical.' },
    { id: 'r_partial', text: 'Blocked the C2 IP at the firewall — that cuts the operator off.', scores: { communication: 0.4, technical: 0.4 }, feedback: 'A block helps for one channel, but the operator can have a second beacon and already-harvested creds. Isolate the host immediately and escalate to CIRT to hunt.' },
  ],
  notesRubric: [
    { label: 'the pattern (pre-ransomware AD recon: BloodHound/net discovery)', pattern: /bloodhound|sharphound|domain admins|net group|nltest|recon|pre.?ransom|discovery/i },
    { label: 'the live operator (Cobalt Strike beacon C2)', pattern: /cobalt|beacon|193\.239\.85\.55|hands.?on|operator/i },
    { label: 'contain FAST to deny detonation (triage-then-isolate now)', pattern: /triage|isolat|contain|now|fast|deny|before.*encrypt/i },
    { label: 'ruled out benign admin + escalate CIRT critical', pattern: /mreyes|benign|ruled out|cirt|critical|escalat|hunt/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'critical', category: 'Pre-Ransomware Recon', resolutionCode: 'Host contained pre-encryption; user reset; C2 blocked; CIRT engaged critical' },
  categoryAccept: ['ransomware', 'recon', 'pre-ransomware'],
  resolutionCodeAccept: ['ransomware', 'recon', 'contain', 'critical', 'cirt'],
  hints: [
    'SharpHound plus a rapid burst of Domain Admins / DC enumeration is the AD mapping ransomware operators do right before encrypting.',
    'There is a live Cobalt Strike beacon (193.239.85.55) — a hands-on-keyboard operator, not a stray script.',
    'No encryption yet means you can still prevent it. Collect fast triage and isolate the host immediately.',
    'Reset bpatel, block the C2, and escalate to CIRT as CRITICAL to hunt for other beacons. Ignore mreyes\'s single authorized net group lookup.',
  ],
  debrief: 'By the time ransomware encrypts, the operator has usually spent hours on reconnaissance — and that recon is the window where a SOC can still win. Human-operated ransomware crews land a beacon (Cobalt Strike here), then map the environment: BloodHound/SharpHound to graph attack paths to Domain Admin, and quick net/AD discovery (net group "Domain Admins", nltest /dclist, net view, net accounts) to find targets and defenses. Recognizing this burst as a pre-encryption emergency — not "internal scanning" — is the whole skill. The response is speed over completeness: fast triage, isolate the host to sever the operator\'s hands, reset the foothold account, block the C2, and escalate to CIRT as CRITICAL to hunt for the second beacon and any privileged access already taken. The foil is a single legitimate admin lookup, which must not distract from containing the real host now.',
};

// ---------------------------------------------------------------------------
// SOC2-16  Compromised service account abused in CI/CD pushing to prod
// ---------------------------------------------------------------------------
const soc2_16: Scenario = {
  id: 'soc2-16',
  tier: 'soc2',
  title: 'The deploy account logged in from the wrong laptop',
  category: 'Identity / Service Account',
  difficulty: 4,
  estMinutes: 18,
  objective: 'Investigate abuse of an over-scoped CI/CD service account: recognize it authenticating from an unusual host and pushing changes into production, rotate the credential without causing an outage, and scope everything it touched.',
  intake: { kind: 'alert', alertId: 'ALT-50116' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50116', time: ago(22), severity: 'high', source: 'siem',
      title: 'svc_backup (CI/CD deploy account) authenticating from a user laptop and pushing to the prod ERP',
      description: 'svc_backup — used by both backups and the CI/CD deploy pipeline — authenticated from DEN-LT-1051 (dkim, HR laptop) instead of the build server, then wrote to the ERP webroot on DEN-APP01 and added a scheduled task. Its credential is stored in the pipeline; likely exposed. Rotate carefully to avoid breaking prod.',
      host: 'DEN-APP01', user: 'svc_backup', indicators: ['svc_backup', 'DEN-LT-1051', 'DEN-APP01'], mitre: ['T1078.003', 'T1098', 'T1053.005', 'T1552.001'], status: 'new', truth: 'true_positive',
    });
    const svc = findUser(w, 'svc_backup')!;
    svc.notes = 'Service Account - Backups AND CI/CD deploy pipeline (over-scoped). Member of Server Admins + Backup Operators. No MFA; password never expires. Normally authenticates ONLY from the build host 10.10.10.62. Owner: mreyes.';
    svc.passwordLastSet = daysAgo(455);
    // The abuse: svc_backup auth from dkim's laptop (unusual), then prod changes on DEN-APP01.
    addLog(w, { time: ago(40), source: 'auth', host: 'DEN-LT-1051', user: 'svc_backup', srcIp: '10.10.20.51', action: 'logon', message: '4624 Logon type 3 (Network) svc_backup from DEN-LT-1051 (10.10.20.51, dkim HR laptop) — NOT the build host', fields: { eventId: 4624, logonType: 3, source: 'DEN-LT-1051' } });
    addLog(w, { time: ago(36), source: 'windows', host: 'DEN-APP01', user: 'svc_backup', action: 'file_write', message: 'svc_backup wrote /erp/webroot/health.aspx and modified web.config on DEN-APP01 (out-of-band deploy, no change ticket)', fields: {} });
    addLog(w, { time: ago(34), source: 'windows', host: 'DEN-APP01', user: 'svc_backup', action: 'task', message: '4698 Scheduled task "ERPSync" created on DEN-APP01 by svc_backup (runs powershell from E:\\deploy\\sync.ps1 hourly)', fields: { eventId: 4698 } });
    addLog(w, { time: ago(30), source: 'windows', host: 'DEN-APP01', user: 'svc_backup', action: 'account', message: '4732 svc_backup added local account "deploysvc" to Administrators on DEN-APP01', fields: { eventId: 4732 } });
    addLog(w, { time: ago(28), source: 'cloud', user: 'svc_backup', srcIp: '10.10.20.51', action: 'git_push', message: 'CI/CD: svc_backup pushed commit to prod branch of the ERP repo and triggered a deploy from DEN-LT-1051', fields: { repo: 'kestrel-erp', branch: 'prod' } });
    // The exposure source: creds found on the HR laptop (which is itself compromised).
    addLog(w, { time: ago(55), source: 'edr', host: 'DEN-LT-1051', user: 'dkim', action: 'alert', message: 'Credential access: pipeline config with svc_backup password read from C:\\ci\\agent\\.env on DEN-LT-1051', process: 'powershell.exe' });
    // Server-side confirmation on DEN-APP01.
    const app = w.servers.find((s) => s.id === 'DEN-APP01')!;
    app.events.push(
      { id: 4698, time: ago(34), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A scheduled task was created: ERPSync (svc_backup) -> powershell E:\\deploy\\sync.ps1 hourly' },
      { id: 4732, time: ago(30), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'A member was added to a security-enabled local group: deploysvc -> Administrators (by svc_backup)' },
    );
    // Red herring: the NORMAL svc_backup auth from the build host earlier (authorized).
    addLog(w, { time: ago(300), source: 'auth', host: 'DEN-APP01', user: 'svc_backup', srcIp: '10.10.10.62', action: 'logon', message: '4624 Logon type 3 (Network) svc_backup from the build host 10.10.10.62 -> DEN-APP01 (authorized nightly deploy)', fields: { eventId: 4624, logonType: 3, source: 'build-host' } });
    w.intel.push({ indicator: '10.10.10.62', type: 'ip', verdict: 'clean', source: 'Internal asset register', tags: ['ci-cd', 'build'], detail: 'Kestrel CI/CD build host. The ONLY authorized source for svc_backup deploys.' });
    w.chat.push({ id: 'ch-mr', with: 'mreyes', messages: [] });
    w.chat.push({ id: 'ch-dk', with: 'dkim', messages: [] });
  },
  contactWith: 'mreyes',
  contact: [
    { id: 'owner', question: 'Ask mreyes (owner): should svc_backup ever log in from an HR laptop or deploy off-ticket?', answer: 'Marco: "No. svc_backup only deploys from the build host 10.10.10.62, and every prod change needs a ticket. From dkim\'s laptop, off-ticket, adding a local admin? That is compromised."', purpose: 'verify', reveals: 'unauthorized' },
    { id: 'rotate_ok', question: 'Ask mreyes whether rotating svc_backup now will break anything, and how.', answer: '"Rotate it — I can update the stored credential in the pipeline vault and the backup job in a few minutes. Do NOT disable it; that kills tonight\'s backups AND every CI deploy."', purpose: 'clarify', reveals: 'rotate-not-disable' },
    { id: 'scope_q', question: 'Determine what svc_backup touched in prod (from the logs)', answer: 'On DEN-APP01: wrote health.aspx + web.config, created the ERPSync scheduled task, added local admin "deploysvc", and pushed to the ERP prod branch — all from dkim\'s laptop.', purpose: 'clarify', reveals: 'scope' },
    { id: 'weather', question: 'Ask mreyes how his morning is going.', answer: '"Let us just contain this."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Reviewed the sign-in + IR lifecycle playbooks (KB-0016 / KB-0018)', match: [{ tool: 'kb', action: 'read', target: 'KB-0016' }, { tool: 'kb', action: 'read', target: 'KB-0018' }], weight: 0.5, hint: 'KB-0018 recovery: rotate every credential the attacker could have seen, including service accounts.' },
    { id: 'unusual', label: 'Saw svc_backup authenticate from an unusual host (not the build server)', match: [{ tool: 'siem', action: 'search', params: { q: /svc_backup|DEN-LT-1051|build host|10\.10\.10\.62|logon type 3/i } }, { tool: 'siem', action: 'pivot', params: { value: /svc_backup/ } }], hint: 'Where does svc_backup normally log in from, and where did it log in from now?' },
    { id: 'acct', label: 'Reviewed the account (over-scoped: Server Admins, no MFA, stale pw)', match: { tool: 'directory', action: 'view', target: 'svc_backup' }, hint: 'Why is this account dangerous if abused? Check its groups and controls.' },
    { id: 'prod', label: 'Confirmed the prod changes on DEN-APP01 (webroot, task, local admin)', match: [{ tool: 'server', action: 'view_events', target: 'DEN-APP01' }, { tool: 'siem', action: 'search', params: { q: /erpsync|deploysvc|web.config|health.aspx|4698|4732|git_push/i } }], hint: 'A backup account writing to the ERP webroot and adding a local admin is not a backup.' },
    { id: 'source', label: 'Found where the credential leaked (pipeline .env on the HR laptop)', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-LT-1051' }, { tool: 'siem', action: 'search', params: { q: /\.env|credential|pipeline|dkim/i } }], hint: 'How did the attacker get the service credential?' },
    { id: 'rule_out', label: 'Distinguished the authorized deploy from the build host', match: { tool: 'intel', action: 'lookup', target: '10.10.10.62' }, weight: 0.5 },
  ],
  required: [
    { id: 'triage', label: 'Collected triage on the compromised source host before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1051' }, skill: 'process', before: 'isolate' },
    { id: 'isolate', label: 'Isolated the source host (DEN-LT-1051)', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1051' }, skill: 'technical' },
    { id: 'rotate', label: 'Rotated the service-account credential (with the owner)', match: [{ tool: 'incident', action: 'reset_service_account', target: 'svc_backup' }, { tool: 'directory', action: 'reset_password', target: 'svc_backup' }], skill: 'security' },
    { id: 'reset_user', label: 'Reset the credential-holding user (dkim / compromised host)', match: [{ tool: 'directory', action: 'reset_password', target: 'dkim' }, { tool: 'directory', action: 'revoke_sessions', target: 'dkim' }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'disable_svc', label: 'Disabled the service account (prod + backup outage)', why: 'Disabling svc_backup stops tonight\'s backups AND every CI/CD deploy that depends on it — a self-inflicted availability incident. The correct move is to ROTATE the credential with the owner updating the pipeline vault, not disable it.', match: { tool: 'directory', action: 'disable', target: 'svc_backup' }, skill: 'process', penalty: 0.4 },
    { id: 'user_only', label: 'Reset only the human user and closed', why: 'Resetting dkim without rotating svc_backup leaves the actual abused credential valid — the attacker keeps deploying to prod with the service account. The service credential is the vector and must be rotated.', match: { tool: 'ticket', action: 'reply', target: 'r_useronly' }, skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'The CI/CD service account svc_backup is compromised. Its pipeline credential was read from a .env on DEN-LT-1051 (dkim\'s HR laptop, itself compromised), and it then authenticated from that laptop — not the authorized build host 10.10.10.62 — and pushed to prod: it wrote health.aspx and web.config in the ERP webroot on DEN-APP01, created the "ERPSync" scheduled task, added local admin "deploysvc", and pushed to the ERP prod branch. svc_backup is over-scoped (Server Admins, no MFA, 455-day password), which is why it was the prize. I collected triage and isolated the source laptop, rotated the svc_backup credential WITH the owner (mreyes updating the pipeline vault and backup job) rather than disabling it, and reset dkim. Escalating to CIRT to review DEN-APP01 (remove the rogue task/local admin/webshell), audit the prod repo history, and scope everything the account touched. I ruled out the earlier authorized deploy from the build host. True positive, high.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Spotted the unusual source, found the leaked credential, rotated (not disabled) with the owner, contained the source host, and scoped the prod blast radius.' },
    { id: 'r_useronly', text: 'Reset dkim and closed — his laptop was the problem.', scores: { communication: 0.3, security: 0.2 }, feedback: 'The abused credential is svc_backup, not dkim. Until you rotate the service account, the attacker keeps deploying to prod with it.' },
    { id: 'r_disable', text: 'Disabled svc_backup to be safe and closed.', scores: { communication: 0.3, security: 0.3, process: 0.1 }, feedback: 'That takes down backups and every CI/CD deploy. Rotate the credential with the owner instead of causing an outage.' },
    { id: 'r_partial', text: 'Rotated svc_backup\'s password. That kills the attacker\'s access, done.', scores: { communication: 0.4, security: 0.4 }, feedback: 'Rotation is essential, but dkim\'s laptop leaked it and is compromised, and the prod changes (rogue task, local admin, repo push) still need to be scoped and reverted via CIRT.' },
  ],
  notesRubric: [
    { label: 'the abuse (svc_backup from an unusual host, pushing to prod)', pattern: /svc_backup|DEN-LT-1051|unusual|build host|prod|deploy|git|webroot/i },
    { label: 'the leaked credential + over-scoped account', pattern: /\.env|pipeline|vault|credential|server admins|no mfa|over.?scop|455|stale/i },
    { label: 'rotate (not disable) with the owner + contain source host', pattern: /rotat|not disable|owner|mreyes|triage|isolat|reset/i },
    { label: 'scope prod changes + escalate CIRT', pattern: /erpsync|deploysvc|local admin|repo|scope|cirt|escalat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Identity - Service Account Abuse (CI/CD)', resolutionCode: 'Credential rotated with owner; source host contained; dkim reset; prod changes scoped via CIRT' },
  categoryAccept: ['service account', 'identity', 'ci/cd', 'cicd'],
  resolutionCodeAccept: ['rotat', 'service account', 'contain', 'ci/cd', 'cirt'],
  hints: [
    'svc_backup normally deploys only from the build host (10.10.10.62). Here it authenticated from dkim\'s HR laptop.',
    'The credential leaked from a pipeline .env on dkim\'s laptop, which is itself compromised — that is the real vector.',
    'On DEN-APP01 the account wrote to the ERP webroot, made a scheduled task, added a local admin, and pushed to the prod branch — scope all of it.',
    'Rotate svc_backup WITH the owner (do not disable it — that breaks backups and CI), contain dkim\'s laptop, reset dkim, and escalate to CIRT.',
  ],
  debrief: 'Service accounts are the quiet keys to production: non-interactive, often over-scoped, MFA-exempt, with passwords that never change and get stored in pipeline config where they leak. The tell of abuse is context, not a failed login — the account authenticated successfully, but from the wrong host (an HR laptop instead of the build server) and did things a backup/deploy account should never do off-ticket: write to the ERP webroot, create a scheduled task, add a local admin, and push to the prod branch. Two disciplines matter. First, rotate rather than disable: the account underpins backups and CI/CD, so disabling it trades an intrusion for an outage; rotate the credential with the owner updating the vault. Second, the vector is the service credential, not just the human whose laptop leaked it — reset both, contain the source host, and hand the production blast radius (rogue task, local admin, repo history) to CIRT to scope and revert.',
};

export const SOC2_SCENARIOS_C: Scenario[] = [soc2_09, soc2_10, soc2_11, soc2_12, soc2_13, soc2_14, soc2_15, soc2_16];
