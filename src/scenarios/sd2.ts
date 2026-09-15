import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, breakInternet, breakDns, lockOut } from './helpers';

// ---------------------------------------------------------------------------
// SD2-01  VPN auth fails after a password reset (cached credentials)
// ---------------------------------------------------------------------------
const sd2_01: Scenario = {
  id: 'sd2-01',
  tier: 'sd2',
  title: 'Remote user can\'t VPN after a password reset',
  category: 'Networking',
  difficulty: 2,
  estMinutes: 10,
  objective: 'Diagnose the cached-credential trap that bites remote users after a password change, and rule out the scarier explanation (account compromise) before acting.',
  intake: {
    kind: 'ticket', number: 'INC457711', subject: 'VPN says authentication failed since my password reset',
    body: 'Escalated from SD1. Carlos Flores (remote, Phoenix) had his password reset yesterday for expiry. Now the Kestrel VPN client says "Authentication failed" every time. He can log into WorkSuite webmail in a browser fine.',
    requester: 'cflores', channel: 'phone', priority: 'P2', category: 'Network', openedAt: ago(30), affectedHost: 'DEN-LT-1061',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const u = findUser(w, 'cflores')!;
    u.passwordLastSet = ago(60 * 20); // reset ~20h ago
    // Webmail works (new password), VPN fails (client sends cached old cred). Sign-ins are all from his home IP.
    u.recentSignIns = [
      { time: ago(15), ip: '73.14.22.190', location: 'Phoenix, US', app: 'WorkSuite Mail (browser)', result: 'success', device: 'DEN-LT-1061', mfa: 'satisfied' },
      { time: ago(16), ip: '73.14.22.190', location: 'Phoenix, US', app: 'Kestrel VPN (RADIUS)', result: 'failure', reason: 'bad credentials', device: 'DEN-LT-1061' },
      { time: ago(22), ip: '73.14.22.190', location: 'Phoenix, US', app: 'Kestrel VPN (RADIUS)', result: 'failure', reason: 'bad credentials', device: 'DEN-LT-1061' },
    ];
    addLog(w, { time: ago(16), source: 'vpn', user: 'cflores', srcIp: '73.14.22.190', action: 'reject', message: 'RADIUS reject user=cflores reason=bad-password geo=Phoenix,US (home IP on record)' });
  },
  contactWith: 'cflores',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10121."', purpose: 'verify' },
    { id: 'mgr', question: 'I\'ll confirm with your manager Emily Wright as a second factor.', answer: 'Emily Wright confirms Carlos is travelling for work as usual and expected to be remote. Verified.', purpose: 'verify' },
    { id: 'webmail', question: 'You said webmail works in a browser — with which password, the new one?', answer: '"Yes, the new one works fine in Chrome for email."', purpose: 'clarify', reveals: 'new-pw-works' },
    { id: 'signin_as', question: 'When the VPN client prompts, are you letting it use saved credentials or typing the new password?', answer: '"It just connects automatically, I never type anything. It used to just work."', purpose: 'clarify', reveals: 'cached' },
    { id: 'location', question: 'Where are you connecting from right now?', answer: '"Home office in Phoenix, same as always."', purpose: 'clarify' },
    { id: 'lunch', question: 'What VPN did you use at your last job?', answer: '"How is that relevant?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the VPN / remote-worker SOP (KB-0011)', match: { tool: 'kb', action: 'read', target: 'KB-0011' } },
    { id: 'signins', label: 'Reviewed sign-ins: all from his home IP, webmail with new password succeeds, VPN fails', match: { tool: 'directory', action: 'view_signins', target: 'cflores' }, hint: 'Are the failures from his known home IP or a strange one? Does anything succeed?' },
    { id: 'vpngroup', label: 'Confirmed he is still in VPN Users and MFA-enrolled', match: [{ tool: 'directory', action: 'view', target: 'cflores' }, { tool: 'directory', action: 'view_group', target: 'VPN Users' }], weight: 0.5 },
  ],
  required: [
    { id: 'guide', label: 'Guided the "connect with new password / sign in as different user" fix', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'reset_again', label: 'Reset the password again', why: 'The password is fine — webmail proves it. Resetting again just repeats the cached-credential cycle and annoys the user.', match: { tool: 'directory', action: 'reset_password', target: 'cflores' }, skill: 'technical', penalty: 0.3 },
    { id: 'escalate_soc', label: 'Escalated to Security as a compromise', why: 'All activity is from his known home IP and webmail with the NEW password succeeds. There is no compromise signal here; escalating wastes SOC time.', match: { tool: 'ticket', action: 'reply', target: 'r_soc' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Your account and new password are fine — that\'s why webmail works. The VPN client is still sending the OLD cached password from before the reset. In the client, choose "Sign in as different user" (or clear saved credentials) and enter your NEW password once; after it connects, lock and unlock Windows so the cached credential updates. You\'ll be set going forward.', scores: { communication: 1, technical: 1 }, feedback: 'Correct root cause and the exact remediation, with the follow-on lock/unlock so it sticks.' },
    { id: 'r_soc', text: 'Repeated failed VPN logins look suspicious — I\'m escalating to Security to investigate a possible compromise.', scores: { communication: 0.3, process: 0.1 }, feedback: 'The failures are from his own home IP and the new password works in the browser. This is a cached-cred issue, not an attack.' },
    { id: 'r_reset', text: 'Let me just reset your password one more time and see if that clears it.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'The password is not the problem; the cached credential is. This loops.' },
  ],
  notesRubric: [
    { label: 'the root cause (VPN client using the old cached password)', pattern: /cached|old password|saved credential|before the reset|stale/i },
    { label: 'evidence it is not a compromise (home IP, webmail with new password works)', pattern: /home ip|73\.14\.22\.190|phoenix|webmail|browser|new password works/i },
    { label: 'the fix (sign in as different user / new password, then lock-unlock)', pattern: /different user|new password|lock.?unlock|clear.*credential|reconnect/i },
  ],
  closure: { disposition: 'resolve', category: 'Network - VPN Authentication', resolutionCode: 'Cleared cached credentials, reconnected' },
  categoryAccept: ['network', 'vpn', 'remote'],
  resolutionCodeAccept: ['cached', 'vpn', 'credential', 'reconnect'],
  hints: [
    'KB-0011 describes exactly this: auth fails right after a reset because the client cached the old password.',
    'Check the sign-ins: webmail with the new password SUCCEEDS from his home IP; only the VPN fails. That rules out compromise.',
    'Fix: connect the VPN using the new password ("sign in as different user"), then lock/unlock Windows.',
    'Do not reset the password again and do not escalate to Security — nothing here is suspicious.',
  ],
  debrief: 'Two skills at once: the technical fix (a cached credential surviving a reset) and the judgment not to over-escalate. "Repeated failed logins" pattern-matches to an attack, but every signal here is benign — same home IP, and the new password works in the browser. The wrong moves are resetting again (loops forever) or escalating to SOC (cries wolf). Confirming with the manager that he is travelling is good hygiene even when you already believe it is benign.',
};

// ---------------------------------------------------------------------------
// SD2-02  Adware / PUA cleanup (SD may handle; escalate if EDR alerts)
// ---------------------------------------------------------------------------
const sd2_02: Scenario = {
  id: 'sd2-02',
  tier: 'sd2',
  title: 'Pop-up ads all over a workstation',
  category: 'Security-adjacent',
  difficulty: 3,
  estMinutes: 12,
  objective: 'Clean a genuine PUA/adware infection at Tier 2, while checking the one condition (an EDR alert / real persistence) that would make this a Security case instead.',
  intake: {
    kind: 'ticket', number: 'INC457712', subject: 'Pop-up ads everywhere and my homepage changed',
    body: 'David (contractor Alex Baxter covering for him) reports: browser pop-ups, a new "PC Mechanic Pro" icon, and the homepage changed to a search site. Started after downloading a "free PDF converter" yesterday. Halberd EDR shows no alert for this host.',
    requester: 'abaxter', channel: 'portal', priority: 'P3', category: 'Malware', openedAt: ago(50), affectedHost: 'CTR-LT-9001',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const h = host(w, 'CTR-LT-9001');
    // Adware: a signed-but-junk PUP running from Program Files, plus a browser extension. No EDR alert, no AppData/Temp persistence, no C2 to a known-bad host.
    addProc(h, { pid: 6620, name: 'PCMechanicPro.exe', user: 'KESTREL\\abaxter', cpu: 6, mem: 210, path: 'C:\\Program Files (x86)\\PC Mechanic Pro\\PCMechanicPro.exe', cmdline: 'PCMechanicPro.exe /tray', signed: true, started: ago(60 * 24) });
    addProc(h, { pid: 6710, name: 'PDFConverterFree.exe', user: 'KESTREL\\abaxter', cpu: 1, mem: 60, path: 'C:\\Program Files (x86)\\PDFConverterFree\\PDFConverterFree.exe', signed: true, started: ago(60 * 24) });
    h.programs.push(
      { name: 'PC Mechanic Pro', version: '9.1', publisher: 'BrightBundle Media Ltd', installedOn: daysAgo(1), suspicious: true },
      { name: 'PDF Converter Free', version: '2.4', publisher: 'BrightBundle Media Ltd', installedOn: daysAgo(1), suspicious: true },
    );
    (h as unknown as { _extensions?: { name: string; id: string; suspicious?: boolean }[] })._extensions = [
      { name: 'Search Boost by BrightBundle', id: 'kkj....', suspicious: true },
      { name: 'Google Docs Offline', id: 'ghbm...', suspicious: false },
    ];
    h.files.push({ path: 'C:\\Users\\abaxter\\Downloads\\FreePDFConverter_Setup.exe', size: 4200000, modified: daysAgo(1), signed: false, suspicious: true });
    // Red herring: benign DCOM warning + a Defender PUA:Win32 informational (quarantined already), NOT an EDR alert.
    addEvent(h, { id: 1116, level: 'Warning', source: 'Windows Defender', log: 'Application', message: 'Defender detected PUA:Win32/BrightBundle and took action: Quarantined. (Informational — no active EDR incident.)', time: ago(45) });
    // proxy shows ad traffic to ad networks, not a known-bad C2
    addLog(w, { time: ago(30), source: 'proxy', host: 'CTR-LT-9001', user: 'abaxter', domain: 'ads.brightbundle-media.net', url: 'https://ads.brightbundle-media.net/serve', action: 'allow', dstPort: 443, message: 'GET ad content' });
  },
  contact: [
    { id: 'source', question: 'Where did the "free PDF converter" come from?', answer: '"A search result — freepdfconverter dot something. It bundled the PC Mechanic thing without asking."', purpose: 'clarify', reveals: 'source' },
    { id: 'creds', question: 'Did you enter any passwords or see credential prompts after installing it?', answer: '"No password prompts, just ads. Nothing asked me to log in."', purpose: 'clarify', reveals: 'no-cred' },
    { id: 'admin', question: 'Did anything ask for admin rights or install a service?', answer: '"It installed to Program Files but I don\'t think it asked for admin. No services that I saw."', purpose: 'clarify' },
    { id: 'coffee', question: 'What\'s your favorite browser?', answer: '"Chrome? Why?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the malware/PUA SOP (KB-0012) to confirm SD can handle this', match: { tool: 'kb', action: 'read', target: 'KB-0012' }, hint: 'The SOP draws the line between adware SD cleans and malware SD escalates.' },
    { id: 'edr', label: 'Checked EDR: no active alert for this host', match: [{ tool: 'edr', action: 'view_host', target: 'CTR-LT-9001' }, { tool: 'edr', action: 'view_alerts' }], hint: 'The go/no-go for SD is whether EDR has an alert. Check it.' },
    { id: 'procs', label: 'Reviewed processes — PUA runs from Program Files (signed), not AppData/Temp', match: [{ tool: 'rdp', action: 'view_processes', target: 'CTR-LT-9001' }, { tool: 'terminal', action: 'tasklist', target: 'CTR-LT-9001' }] },
    { id: 'programs', label: 'Found the bundled programs and download source', match: { tool: 'rdp', action: 'view_programs', target: 'CTR-LT-9001' } },
    { id: 'ext', label: 'Checked browser extensions', match: { tool: 'rdp', action: 'view_browser_extensions', target: 'CTR-LT-9001' }, weight: 0.5 },
  ],
  required: [
    { id: 'kill', label: 'Ended the PUA processes', match: [{ tool: 'rdp', action: 'end_process', target: 'CTR-LT-9001', params: { name: /pcmechanic|pdfconverter/i } }, { tool: 'terminal', action: 'taskkill', target: 'CTR-LT-9001', params: { arg: /pcmechanic|pdfconverter/i } }], skill: 'technical' },
    { id: 'uninstall', label: 'Uninstalled the bundled programs', match: { tool: 'rdp', action: 'uninstall', target: 'CTR-LT-9001', params: { program: /pc mechanic|pdf converter|brightbundle/i } }, skill: 'technical' },
    { id: 'ext_remove', label: 'Removed the malicious browser extension', match: { tool: 'rdp', action: 'remove_extension', target: 'CTR-LT-9001', params: { name: /search boost|brightbundle/i } }, skill: 'technical', weight: 0.5 },
    { id: 'scan', label: 'Ran a full Defender scan to confirm clean', match: [{ tool: 'rdp', action: 'run_scan', target: 'CTR-LT-9001' }, { tool: 'edr', action: 'scan', target: 'CTR-LT-9001' }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'escalate_unneeded', label: 'Escalated to Security despite no EDR alert or persistence', why: 'KB-0012: SD handles PUA/adware when EDR is silent and there\'s no AppData/Temp persistence, service, or credential theft. This is textbook adware; escalating clogs the SOC queue.', match: { tool: 'ticket', action: 'reply', target: 'r_escalate' }, skill: 'process', penalty: 0.25 },
    { id: 'ignore_source', label: 'Closed without noting the download source / advising the user', why: 'The root cause is a bundled installer from an untrusted search result. Note it and coach the contractor, or it recurs.', match: { tool: 'ticket', action: 'reply', target: 'r_quick' }, skill: 'communication', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is adware bundled with that "free PDF converter" — annoying but not a breach. EDR has no alert, nothing was running from hidden folders, and you didn\'t enter any credentials. I removed PC Mechanic Pro and the PDF converter, killed their processes, pulled the "Search Boost" browser extension, and ran a full scan that came back clean. Please install software only from our Software Center; those free-tool sites bundle this stuff. You\'re good.', scores: { communication: 1, security: 1 }, feedback: 'Accurate scope (PUA not breach), complete cleanup, and coaches the root cause.' },
    { id: 'r_escalate', text: 'Malware detected — escalating to the Security team to investigate.', scores: { communication: 0.4, process: 0.2 }, feedback: 'No EDR alert, no persistence, no credential theft. KB-0012 says SD owns this. Over-escalation.' },
    { id: 'r_quick', text: 'Removed the pop-up program. All done.', scores: { communication: 0.4 }, feedback: 'Incomplete (extension left behind, no scan) and no coaching on where it came from, so it will be back.' },
  ],
  notesRubric: [
    { label: 'the go/no-go check (EDR silent, no AppData/Temp persistence, no creds)', pattern: /edr|no alert|program files|no persistence|no credential|pua|adware/i },
    { label: 'the cleanup steps (kill, uninstall, extension, scan)', pattern: /uninstall|removed|extension|scan|killed|ended/i },
    { label: 'the source and user guidance', pattern: /download|bundled|free.*converter|software center|coach|advised/i },
  ],
  closure: { disposition: 'resolve', category: 'Endpoint - PUA/Adware', resolutionCode: 'Removed PUA, extensions, scanned clean' },
  categoryAccept: ['pua', 'adware', 'malware', 'endpoint'],
  resolutionCodeAccept: ['pua', 'adware', 'removed', 'clean'],
  hints: [
    'Read KB-0012 first — it defines when SD cleans vs. when SD escalates.',
    'The single most important check: does Halberd EDR have an alert for this host? (It does not.)',
    'Confirm no persistence (AppData/Temp process, service, scheduled task) and no credential theft — all absent here.',
    'Clean it fully: end processes, uninstall both bundled apps, remove the extension, run a scan. Coach the user on the source.',
  ],
  debrief: 'The lesson is calibration. Not everything with "pop-ups" is a breach for the SOC, and not everything is safe for SD to touch. KB-0012 gives an objective test: EDR alert? Persistence in AppData/Temp, a service, or a scheduled task? Credential prompts? Here all are absent — signed PUPs in Program Files, ads to an ad network, Defender already quarantined the dropper. SD cleans it. Had there been an EDR alert or a process beaconing from AppData, you would stop, preserve, and escalate.',
};

// ---------------------------------------------------------------------------
// SD2-03  Access-denied to a share (needs data-owner approval, not just add)
// ---------------------------------------------------------------------------
const sd2_03: Scenario = {
  id: 'sd2-03',
  tier: 'sd2',
  title: '"Access denied" to the Finance share',
  category: 'Access',
  difficulty: 2,
  estMinutes: 10,
  objective: 'Distinguish a token-refresh problem from a genuine authorization gap, and resist adding a user to a sensitive group without the data owner\'s approval.',
  intake: {
    kind: 'ticket', number: 'INC457713', subject: 'Can\'t get to the Finance share, says access denied',
    body: 'Escalated from SD1. Jordan Webb (Marketing Coordinator) says: "I need the Q3 budget file on \\\\FS01\\Finance for a campaign report. It says access denied. Ewright told me to just get access."',
    requester: 'jwebb', channel: 'portal', priority: 'P3', category: 'Access', openedAt: ago(40),
  },
  priorityExpected: 'P3',
  setup: (w) => {
    // jwebb is in Marketing, NOT in FS-Finance-RW. This is a genuine authorization gap to a sensitive share.
    const fs = w.servers.find((s) => s.id === 'DEN-FS01')!;
    // ensure the Finance share requires FS-Finance-RW (already does from world)
    w.chat.push({ id: 'ch-ew', with: 'ewright', messages: [
      { from: 'ewright', time: ago(35), text: 'Yeah I told Jordan to get into the Finance folder for the budget numbers. Can you just add them?' },
    ] });
  },
  contactWith: 'jwebb',
  contact: [
    { id: 'which', question: 'Which exact path and file do you need?', answer: '"\\\\FS01\\Finance, the Q3 budget spreadsheet."', purpose: 'clarify' },
    { id: 'ever', question: 'Have you ever had access to the Finance share before?', answer: '"No, first time. Emily said I\'d need it for this project."', purpose: 'clarify', reveals: 'never-had' },
    { id: 'why', question: 'What do you actually need from it — the whole folder or one file?', answer: '"Honestly just the Q3 budget summary numbers for a slide."', purpose: 'clarify', reveals: 'scope' },
    { id: 'coffee', question: 'Do you take cream in your coffee?', answer: '"Uh, no thanks."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb9', label: 'Read the file-access SOP (KB-0009)', match: { tool: 'kb', action: 'read', target: 'KB-0009' } },
    { id: 'kb6', label: 'Read the access-request rule for sensitive groups (KB-0006)', match: { tool: 'kb', action: 'read', target: 'KB-0006' }, hint: 'Who has to approve access to Finance/HR shares?' },
    { id: 'groups', label: 'Checked Jordan\'s groups vs. the share\'s NTFS group', match: [{ tool: 'directory', action: 'view', target: 'jwebb' }, { tool: 'server', action: 'view_shares', target: 'DEN-FS01' }], hint: 'Is she missing FS-Finance-RW, or in it but denied (a token issue)?' },
  ],
  required: [
    { id: 'get_approval', label: 'Sought the data owner\'s (Finance/CFO) approval, not just the requester\'s manager', match: [{ tool: 'chat', action: 'send', target: 'rokafor' }, { tool: 'ticket', action: 'reply', target: 'r_best' }], skill: 'process' },
  ],
  forbidden: [
    { id: 'just_add', label: 'Added Jordan to FS-Finance-RW on the manager\'s say-so', why: 'Finance is a sensitive share (KB-0006). It needs the DATA OWNER\'s approval (Finance/CFO), not the requester\'s own manager. Marketing managers can\'t authorize Finance access.', match: { tool: 'directory', action: 'add_group', target: 'jwebb', params: { group: /finance/i } }, skill: 'security', penalty: 0.5 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'You\'re not in the Finance share group, and access to Finance data needs the data owner\'s sign-off — your manager can request it, but Finance (Rachel Okafor\'s team) has to approve, not Marketing. I\'ve routed an approval request to Finance explaining you need the Q3 budget summary for a slide. Often they\'ll just send you the numbers directly, which may be faster. I\'ll grant access the moment they approve.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Correct authorization path, least-privilege framing, and a faster alternative for the user.' },
    { id: 'r_add', text: 'Done — I\'ve added you to the Finance share group, try again now.', scores: { communication: 0.4, security: 0.1, process: 0.1 }, feedback: 'Granting sensitive access on a manager\'s casual say-so is exactly the over-provisioning that audits flag.' },
    { id: 'r_deny', text: 'Sorry, Marketing can\'t have Finance access. Closing.', scores: { communication: 0.4, process: 0.4 }, feedback: 'The need may be legitimate; the right move is to route it for approval, not to flatly refuse.' },
  ],
  notesRubric: [
    { label: 'the finding (not in FS-Finance-RW; genuine gap, not a token issue)', pattern: /not in|missing|fs-finance|not a member|no access|authoriz/i },
    { label: 'the rule (sensitive share needs data-owner approval)', pattern: /data owner|approval|cfo|finance approve|sensitive|kb-0006/i },
    { label: 'the action (routed for approval / offered the numbers directly)', pattern: /routed|requested approval|okafor|finance team|send.*numbers|pending approval/i },
  ],
  closure: { disposition: 'pending', category: 'Access - Sensitive Share Request', resolutionCode: 'Pending data-owner approval' },
  categoryAccept: ['access', 'share', 'permission', 'finance'],
  resolutionCodeAccept: ['approval', 'pending', 'data owner', 'access'],
  hints: [
    'Read KB-0009 (file access) and KB-0006 (who approves sensitive groups).',
    'Check her groups against the share: she is simply not in FS-Finance-RW. This is a real gap, not a token refresh.',
    'Finance is sensitive — the data owner (Finance/CFO), not her Marketing manager, must approve.',
    'Route the request for approval; consider that Finance may just hand over the specific numbers.',
  ],
  debrief: 'The pressure here is social: a director says "just add them." KB-0006 is explicit that sensitive shares (Finance, HR, AP, any *-Admins) require the data owner\'s approval, not the requester\'s manager. First you rule out the easy case (in the group but denied = re-logon for a fresh token); here she is genuinely not a member. The right disposition is "pending approval," routed to Finance, with a helpful nudge that they might just send the numbers. Adding her on the spot is the least-privilege violation auditors live for.',
};

// ---------------------------------------------------------------------------
// SD2-04  Kerberos clock skew breaks logons at the plant
// ---------------------------------------------------------------------------
const sd2_04: Scenario = {
  id: 'sd2-04',
  tier: 'sd2',
  title: 'Plant PC won\'t authenticate to anything',
  category: 'Windows',
  difficulty: 3,
  estMinutes: 12,
  objective: 'Diagnose a Kerberos failure caused by clock skew — a symptom that masquerades as "network down" or "account locked" — using the event log and terminal.',
  intake: {
    kind: 'ticket', number: 'INC457714', subject: 'Can\'t log in or reach any shares on the plant PC',
    body: 'Escalated from SD1. Mike Johnson\'s Wichita workstation (WIC-WS-3002): domain logon fails with "The security database on the server does not have a computer account for this workstation trust relationship" intermittently, mapped drives are gone, and Outlook keeps prompting for a password. His account is NOT locked and the network is up.',
    requester: 'mjohnson', channel: 'phone', priority: 'P2', category: 'Windows', openedAt: ago(25), affectedHost: 'WIC-WS-3002',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const h = host(w, 'WIC-WS-3002');
    // CMOS battery dying -> clock drifted ~11 minutes. Kerberos allows max 5 min skew.
    h.clockSkewSec = 660;
    h.network.adapterStatus = 'up'; // network is fine
    addEvent(h, { id: 4, level: 'Error', source: 'Security-Kerberos', log: 'System', message: 'The Kerberos client received a KRB_AP_ERR_SKEW error from the server WIC-DC01$. This indicates the workstation clock differs from the domain controller by more than the allowed skew (5 minutes).', time: ago(24) });
    addEvent(h, { id: 5719, level: 'Error', source: 'NETLOGON', log: 'System', message: 'This computer was not able to set up a secure session with a domain controller due to the following: There are currently no logon servers available. (Downstream symptom of clock skew.)', time: ago(23) });
    // Red herring: an old benign W32Time warning and a normal account (not locked)
    addEvent(h, { id: 36, level: 'Warning', source: 'Time-Service', log: 'System', message: 'The time service has not synchronized the system time for 49152 seconds because none of the time providers was reachable.', time: ago(60 * 12) });
  },
  contact: [
    { id: 'locked', question: 'Just to confirm — is the "account locked" message, or a different error?', answer: '"It says something about a trust relationship and no logon servers. Not locked I don\'t think."', purpose: 'clarify' },
    { id: 'others', question: 'Are other plant PCs having this, or just yours?', answer: '"Just mine. The guy next to me is fine."', purpose: 'clarify', reveals: 'single-host' },
    { id: 'age', question: 'How old is this machine, and has it done anything weird like the clock being wrong?', answer: '"It\'s an old one. Actually yeah — the clock on it is always wrong when I turn it on in the morning, I fix it manually."', purpose: 'clarify', reveals: 'clock' },
    { id: 'weather', question: 'Is it cold in the plant today?', answer: '"...it\'s a factory. Focus?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Consulted the terminal quick reference (KB-0019)', match: { tool: 'kb', action: 'read', target: 'KB-0019' }, weight: 0.5 },
    { id: 'events', label: 'Read the System log and found the Kerberos KRB_AP_ERR_SKEW error', match: [{ tool: 'rdp', action: 'view_events', target: 'WIC-WS-3002', params: { log: 'System' } }, { tool: 'rdp', action: 'view_events', target: 'WIC-WS-3002' }], hint: 'The event log names the exact error. Look in System for Kerberos/Netlogon.' },
    { id: 'time', label: 'Confirmed the clock skew (w32tm or systeminfo)', match: [{ tool: 'terminal', action: 'w32tm', target: 'WIC-WS-3002' }, { tool: 'terminal', action: 'systeminfo', target: 'WIC-WS-3002' }], hint: 'How far off is this machine\'s clock from the DC?' },
    { id: 'notlocked', label: 'Confirmed the account is not locked (rules out the obvious)', match: [{ tool: 'directory', action: 'view', target: 'mjohnson' }, { tool: 'terminal', action: 'net_user', target: 'WIC-WS-3002' }], weight: 0.5 },
  ],
  required: [
    { id: 'resync', label: 'Re-synced the clock (w32tm /resync) to fix Kerberos', match: { tool: 'terminal', action: 'w32tm_resync', target: 'WIC-WS-3002' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'rejoin', label: 'Rebuilt the domain trust / rejoined the domain first', why: 'The "trust relationship" message is a red herring caused by skew. Rejoining the domain is a heavy, disruptive fix for what a clock resync solves in seconds.', match: [{ tool: 'rdp', action: 'reboot', target: 'WIC-WS-3002' }], skill: 'efficiency', penalty: 0.2 },
    { id: 'reset_pw', label: 'Reset the user\'s password', why: 'The account is not locked and the password is not the problem — Kerberos can\'t validate the ticket because of time skew.', match: { tool: 'directory', action: 'reset_password', target: 'mjohnson' }, skill: 'technical', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Found it: your PC\'s clock had drifted about 11 minutes, and Kerberos rejects logins when the clock is off by more than 5. That\'s why you saw "trust relationship" and "no logon servers" even though your account is fine and the network is up. I re-synced the time and you should be able to log in and reach your drives now. The clock keeps drifting because the machine\'s CMOS battery is dying — I\'m logging a hardware follow-up to replace it so this doesn\'t come back.', scores: { communication: 1, technical: 1 }, feedback: 'Explains the counterintuitive cause, fixes it, and addresses why it recurs (the battery).' },
    { id: 'r_rejoin', text: 'Your computer lost its domain trust — I\'ll need to rejoin it to the domain, which means a reboot and a wait.', scores: { communication: 0.4, technical: 0.3 }, feedback: 'Treats the symptom message literally. A clock resync fixes it far faster.' },
    { id: 'r_net', text: 'This looks like a network problem — escalating to the Network team.', scores: { communication: 0.3, process: 0.2 }, feedback: 'The network is up and only one host is affected. This is a local time/Kerberos issue, not a network one.' },
  ],
  notesRubric: [
    { label: 'the true cause (clock skew > 5 min breaking Kerberos)', pattern: /skew|clock|kerberos|krb_ap_err|time drift|5 min/i },
    { label: 'ruling out the misleading symptoms (trust/account not the real issue)', pattern: /trust relationship|red herring|not locked|network up|misleading|symptom/i },
    { label: 'the fix and the recurrence cause (resync + CMOS battery)', pattern: /resync|w32tm|cmos|battery|hardware follow/i },
  ],
  closure: { disposition: 'resolve', category: 'Windows - Kerberos / Time', resolutionCode: 'Clock resync; CMOS battery follow-up logged' },
  categoryAccept: ['windows', 'kerberos', 'time', 'auth'],
  resolutionCodeAccept: ['resync', 'clock', 'kerberos', 'time'],
  hints: [
    'The error text mentions a trust relationship and no logon servers — but the account is not locked and the network is up.',
    'Read the System event log. A Kerberos KRB_AP_ERR_SKEW error is a dead giveaway.',
    'Check the clock with w32tm or systeminfo — it is ~11 minutes off. Kerberos allows only 5.',
    'Fix: w32tm /resync. Then log a hardware follow-up for the dying CMOS battery so it stops drifting.',
  ],
  debrief: 'Kerberos authentication depends on synchronized clocks; a skew over five minutes makes tickets invalid, and Windows reports that with scary, misleading messages about trust relationships and missing logon servers. The trap is taking those messages literally and rejoining the domain, or blaming the network. Reading the event log points straight at KRB_AP_ERR_SKEW. A resync fixes it instantly, and a good tech also kills the recurrence by replacing the CMOS battery that let the clock drift.',
};

export const SD2_SCENARIOS: Scenario[] = [sd2_01, sd2_02, sd2_03, sd2_04];
