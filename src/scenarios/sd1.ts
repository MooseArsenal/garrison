import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, breakInternet, breakDns, setDhcpExhausted, lockOut, setConn } from './helpers';

// ---------------------------------------------------------------------------
// SD1-01  Password reset with a social-engineering twist
// ---------------------------------------------------------------------------
const sd1_01: Scenario = {
  id: 'sd1-01',
  tier: 'sd1',
  title: 'Locked out before a deadline',
  category: 'Identity',
  difficulty: 1,
  estMinutes: 8,
  objective: 'Verify a caller before touching their account, resolve a routine lockout, and recognize when a lockout is actually an attack.',
  intake: {
    kind: 'ticket', number: 'INC457701', subject: 'Locked out of my computer, need this fixed NOW',
    body: `Caller (phone): "Hi, this is Jenna in AP. I'm locked out and payroll is due in twenty minutes. Can you just reset my password real quick? Send the new one to my Gmail, I'm not at my desk."`,
    requester: 'jmorales', channel: 'phone', priority: 'P2', category: 'Access', openedAt: ago(4),
  },
  priorityExpected: 'P2',
  setup: (w) => {
    lockOut(w, 'jmorales', 4);
    const u = findUser(w, 'jmorales')!;
    // Benign cause: old password saved in phone mail app. Failures come from her own device/IP.
    u.recentSignIns = [
      { time: ago(8), ip: '10.10.20.41', location: 'Denver, US', app: 'Windows Sign-in', result: 'failure', reason: 'wrong password', device: 'DEN-LT-1041' },
      { time: ago(9), ip: '10.10.20.41', location: 'Denver, US', app: 'Exchange ActiveSync (iPhone)', result: 'failure', reason: 'wrong password', device: 'personal iPhone' },
      { time: ago(11), ip: '10.10.20.41', location: 'Denver, US', app: 'Exchange ActiveSync (iPhone)', result: 'failure', reason: 'wrong password', device: 'personal iPhone' },
      { time: ago(180), ip: '10.10.20.41', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1041', mfa: 'satisfied' },
    ];
  },
  contactWith: 'jmorales',
  contact: [
    { id: 'empid', question: 'Can you confirm your employee ID for verification?', answer: '"It\'s E10105."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll call you back on the number we have on file to verify. That OK?', answer: 'You call 303-555-1310 (the number on record) and she picks up. Verified.', purpose: 'verify' },
    { id: 'phone_mail', question: 'Did you recently change your password, and do you have work mail on your phone?', answer: '"Oh... yeah, I changed it Monday. My iPhone has my work email set up. It keeps buzzing."', purpose: 'clarify', reveals: 'phone-mail-cause' },
    { id: 'where', question: 'Where are you right now, and is this your work laptop?', answer: '"I\'m at my desk on my Kestrel laptop, DEN-LT-1041."', purpose: 'clarify' },
    { id: 'gmail', question: 'Sure, what\'s the Gmail address to send it to?', answer: '"jmorales.home@gmail.com"  — (Sending credentials to personal email violates KB-0001. Do not do this.)', purpose: 'red_flag' },
    { id: 'weather', question: 'How\'s the weather in Denver today?', answer: '"...fine? Can we focus on my password?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'read_verify', label: 'Read the caller-verification SOP (KB-0001)', match: { tool: 'kb', action: 'read', target: 'KB-0001' }, hint: 'There is a required procedure before any account change.' },
    { id: 'view_user', label: 'Opened Jenna\'s account in the Directory', match: { tool: 'directory', action: 'view', target: 'jmorales' } },
    { id: 'view_signins', label: 'Reviewed the failed sign-in attempts to find the cause', match: { tool: 'directory', action: 'view_signins', target: 'jmorales' }, hint: 'Where did the bad passwords come from? Her own device, or somewhere else?' },
  ],
  required: [
    { id: 'unlock', label: 'Unlocked the account', match: { tool: 'directory', action: 'unlock', target: 'jmorales' }, skill: 'technical', weight: 1 },
    { id: 'reset', label: 'Reset the password with "must change at next logon"', match: { tool: 'directory', action: 'reset_password', target: 'jmorales', params: { mustChange: 'true' } }, skill: 'technical', weight: 1 },
  ],
  forbidden: [
    { id: 'email_pw', label: 'Sent the password to a personal Gmail', why: 'Never send credentials to a non-corporate address (KB-0001, KB-0002). Give a temp password by phone only.', match: [{ tool: 'chat', action: 'send', target: 'jmorales', params: { text: /gmail|email|@/i } }], penalty: 0.6 },
    { id: 'no_verify_reset', label: 'Reset the password before verifying identity', match: { tool: 'directory', action: 'reset_password', target: 'jmorales' }, unlessAfter: 'verify_gate', penalty: 0.5, why: 'Identity must be verified with two factors first (KB-0001).' },
  ],
  replies: [
    { id: 'r1', best: true, text: 'Verified your identity by employee ID and a callback. Your account is unlocked and I\'ve set a temporary password I\'ll read to you now — you\'ll be prompted to change it at logon. Heads up: your iPhone still has the old work password saved and was locking you out; update it there or it will lock again.', scores: { communication: 1, security: 1 }, feedback: 'Clear, verified, and fixes the root cause (the phone) so it does not recur.' },
    { id: 'r2', text: 'All set, I reset your password to Winter2026! — you\'re good to go.', scores: { communication: 0.3, security: 0.1 }, feedback: 'Spoke a password in a way that could be logged, used a weak/guessable one, and never addressed why she locked out (the phone). It will happen again.' },
    { id: 'r3', text: 'I can\'t reset anything until you come to the IT desk in person with your badge.', scores: { communication: 0.4, security: 0.6 }, feedback: 'Over-strict: phone verification (employee ID + callback to the number on record) is acceptable per KB-0001. This needlessly blocks a deadline.' },
  ],
  notesRubric: [
    { label: 'the verification method used (two factors)', pattern: /(employee id|e10105).*(callback|call back|number on record)|(callback|call back).*(employee id|e10105)|two factor|verified/i },
    { label: 'the root cause (old password cached on her iPhone)', pattern: /iphone|phone|activesync|cached|saved password|mail app/i },
    { label: 'the action taken (unlock + reset, must-change)', pattern: /unlock|reset|temp(orary)? password|change at (next )?logon/i },
  ],
  closure: { disposition: 'resolve', category: 'Identity - Account Lockout', resolutionCode: 'Unlocked + password reset' },
  categoryAccept: ['identity', 'lockout', 'account', 'access', 'password'],
  resolutionCodeAccept: ['unlock', 'reset', 'password'],
  hints: [
    'Start in the Knowledge Base — search "verification".',
    'Two acceptable verification factors: employee ID confirmed against the Directory, plus a callback to the number on record.',
    'Look at the sign-in log: are the failures from her own laptop/phone, or from a strange IP? That tells you attack vs. self-inflicted.',
    'Give the temp password by phone; never by email or chat. Tell her to fix the saved password on her iPhone.',
  ],
  debrief: 'This is the single most common service-desk call — and the most common social-engineering vector. The failures all came from Jenna\'s own laptop and iPhone, so it is a benign lockout: her phone\'s mail app kept trying the old password. The trap was the request to send the new password to a personal Gmail; the right move is a phone-only temp password and fixing the phone so it does not recur. Had the failures come from an unknown external IP, the correct answer flips to "escalate to Security, do not just unlock."',
};

// ---------------------------------------------------------------------------
// SD1-02  Second monitor black (dock)
// ---------------------------------------------------------------------------
const sd1_02: Scenario = {
  id: 'sd1-02',
  tier: 'sd1',
  title: 'The second monitor went black',
  category: 'Hardware',
  difficulty: 1,
  estMinutes: 7,
  objective: 'Work a hardware/peripheral fault methodically with Device Manager and the asset record instead of guessing.',
  intake: {
    kind: 'ticket', number: 'INC457702', subject: 'My second monitor just went black and will not come back on',
    body: 'Portal ticket from Nora Foster (Design Engineer): "My left monitor went black about 20 minutes ago. The right one is fine. I\'ve tried turning it off and on. I have a design review at 11."',
    requester: 'nfoster', channel: 'portal', priority: 'P3', category: 'Hardware', openedAt: ago(20), affectedHost: 'DEN-WS-2010',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const h = host(w, 'DEN-WS-2010');
    h.monitors = [{ name: 'Dell P2422H', status: 'active' }, { name: 'Dell P2422H (2) via dock', status: 'no signal' }];
    // Dock firmware fault: the dock's downstream display port dropped. Device Manager shows the dock with a warning.
    const dock = h.devices.find((d) => d.class === 'USB devices');
    if (dock) { dock.status = 'error'; dock.error = 'Code 43: Windows has stopped this device because it reported problems (dock DisplayPort hub).'; }
  },
  contactWith: 'nfoster',
  contact: [
    { id: 'when', question: 'Did anything change right before it went black — new cable, moved the dock, Windows update?', answer: '"Not that I noticed. It just blinked off. The dock\'s little light is orange now, it\'s usually white."', purpose: 'clarify', reveals: 'dock' },
    { id: 'swap', question: 'Can you try plugging that monitor\'s cable into the other dock port?', answer: '"Tried it — still no signal on that monitor from either dock port. The monitor works if I plug it straight into the laptop though."', purpose: 'clarify', reveals: 'dock' },
    { id: 'input', question: 'On the black monitor, can you press its Input/Source button and cycle inputs?', answer: '"Did that. It says \'No DisplayPort signal\' and goes to sleep."', purpose: 'clarify' },
    { id: 'review', question: 'What time is your design review, and can you present from the one working screen if needed?', answer: '"11am. Yeah I can manage on one screen for now, but I\'d like both back."', purpose: 'clarify' },
    { id: 'color', question: 'What color is your desk chair?', answer: '"...why?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the displays/docks SOP (KB-0010)', match: { tool: 'kb', action: 'read', target: 'KB-0010' } },
    { id: 'devices', label: 'Checked Device Manager and found the dock in a Code 43 error', match: { tool: 'rdp', action: 'view_devices', target: 'DEN-WS-2010' }, hint: 'Remote in and open Device Manager — is a device erroring?' },
    { id: 'monitors', label: 'Confirmed the monitor state (one active, one no-signal via dock)', match: { tool: 'rdp', action: 'view_monitors', target: 'DEN-WS-2010' } },
    { id: 'asset', label: 'Looked up the dock/monitor asset and warranty', match: { tool: 'assets', action: 'view', target: /KD-/ }, weight: 0.5, hint: 'Is the hardware under warranty? That changes whether you swap from stock or dispatch the vendor.' },
  ],
  required: [
    { id: 'stock', label: 'Arranged a replacement dock from stock (or vendor dispatch)', match: [{ tool: 'assets', action: 'set_status', target: /KD-06011/ }, { tool: 'assets', action: 'dispatch_vendor' }, { tool: 'assets', action: 'assign', params: { user: 'nfoster' } }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'reimage', label: 'Escalated to Desktop for a reimage', why: 'This is a dead dock, not an OS problem. Reimaging wastes a day and does not fix hardware.', match: { tool: 'ticket', action: 'reply', target: 'r_reimage' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Found it: the monitor and cable are fine, but your dock\'s DisplayPort hub is faulting (Device Manager Code 43, and its light went amber). I\'m bringing you a replacement dock from stock and updating your asset record. For your 11am, run on the one working screen; I\'ll have you back on two before lunch.', scores: { communication: 1 }, feedback: 'Names the real cause, gives a workaround for the deadline, and sets a realistic ETA.' },
    { id: 'r_guess', text: 'Sounds like a driver problem — please restart your PC a few times and let me know if it comes back.', scores: { communication: 0.3 }, feedback: '"Have you tried turning it off and on" without diagnosing. The dock is dead; reboots will not help and you look like you did not look.' },
    { id: 'r_reimage', text: 'I\'ll escalate this to the Desktop team to reimage your machine.', scores: { communication: 0.3, process: 0.1 }, feedback: 'Wrong team and wrong fix for a hardware fault.' },
  ],
  notesRubric: [
    { label: 'the diagnosis (dock DisplayPort fault, Code 43)', pattern: /dock|code 43|displayport|hub/i },
    { label: 'ruling out the monitor/cable', pattern: /monitor works|cable|direct|straight into|other port|ruled out/i },
    { label: 'the action (dock swap from stock / vendor, asset updated)', pattern: /stock|replace|swap|vendor|asset|dispatch/i },
  ],
  closure: { disposition: 'resolve', category: 'Hardware - Docking Station', resolutionCode: 'Replaced faulty dock from stock' },
  categoryAccept: ['hardware', 'dock', 'monitor', 'display', 'peripheral'],
  resolutionCodeAccept: ['dock', 'replace', 'swap', 'stock', 'vendor'],
  hints: [
    'Read KB-0010 first — it tells you the dock-vs-monitor discrimination.',
    'Remote into DEN-WS-2010 and open Device Manager. A Code 43 on the dock is your answer.',
    'The monitor works when plugged straight into the laptop, so the monitor and cable are fine.',
    'Swap the dock from stock (KD-06011) and update the asset record. Do not reimage.',
  ],
  debrief: 'Peripheral faults reward a decision tree, not guesses. By confirming the monitor works directly and seeing the dock error in Device Manager, you isolate the dock. The red herrings were "restart your PC" (useless for hardware) and the temptation to escalate to a reimage. Always check the asset record: in-warranty gear gets a vendor dispatch, out-of-warranty gets a stock swap.',
};

// ---------------------------------------------------------------------------
// SD1-03  Whole floor lost internet (DHCP scope exhausted -> Network)
// ---------------------------------------------------------------------------
const sd1_03: Scenario = {
  id: 'sd1-03',
  tier: 'sd1',
  title: 'Nobody on the 3rd floor has internet',
  category: 'Networking',
  difficulty: 2,
  estMinutes: 9,
  objective: 'Scope an outage (one user vs. many), diagnose a DHCP failure from the endpoint, and escalate correctly with evidence when it is beyond Tier 1.',
  intake: {
    kind: 'ticket', number: 'INC457703', subject: 'Nobody on the 3rd floor has internet right now',
    body: 'Phone call from Mike Reeves relayed by reception: multiple people on the Denver 3rd floor (Finance) say they lost network in the last 15 minutes. New arrivals can\'t connect at all; some who were already on still work.',
    requester: 'jmorales', channel: 'phone', priority: 'P3', category: 'Network', openedAt: ago(12), affectedHost: 'DEN-LT-1041',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    // DHCP scope for Denver-Users is exhausted. New leases fail -> APIPA. Existing leases still work.
    const dc = w.servers.find((s) => s.id === 'DEN-DC01')!;
    const scope = dc.dhcpScopes!.find((s) => s.name.startsWith('Denver-Users'))!;
    scope.used = scope.total; scope.status = 'exhausted';
    // Jenna's laptop just tried to renew and fell to APIPA.
    const h = host(w, 'DEN-LT-1041');
    h.network.ip = '169.254.88.12';
    h.ip = '169.254.88.12';
    setDhcpExhausted(h);
    addEvent(h, { id: 1003, level: 'Warning', source: 'Dhcp-Client', log: 'System', message: 'Your computer was unable to obtain an address from the DHCP server. The following error occurred: The semaphore timeout period has expired. Assigned APIPA address 169.254.88.12.', time: ago(11) });
  },
  contactWith: 'jmorales',
  contact: [
    { id: 'howmany', question: 'How many people are affected, and are they all on the 3rd floor / all wired or wireless?', answer: '"Pretty much the whole Finance area, maybe a dozen. Mix of wired and Wi-Fi. People who never disconnected are fine; anyone who rebooted or just got in is dead."', purpose: 'clarify', reveals: 'scope-many' },
    { id: 'otherfloors', question: 'Is anyone on other floors affected?', answer: '"No, 2nd and 4th are fine. Just us."', purpose: 'clarify', reveals: 'scope-floor' },
    { id: 'when', question: 'When did it start, and did anything change — power blip, new equipment?', answer: '"About 15 minutes ago. No idea what changed. We did have a bunch of new contractor laptops join this week."', purpose: 'clarify' },
    { id: 'lunch', question: 'Have you had lunch yet?', answer: '"Seriously?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the no-network SOP (KB-0007)', match: { tool: 'kb', action: 'read', target: 'KB-0007' } },
    { id: 'ipconfig', label: 'Ran ipconfig on an affected machine and saw a 169.254.x.x APIPA address', match: [{ tool: 'terminal', action: 'ipconfig_all', target: 'DEN-LT-1041' }, { tool: 'terminal', action: 'ipconfig', target: 'DEN-LT-1041' }, { tool: 'rdp', action: 'view_network', target: 'DEN-LT-1041' }], hint: 'Remote in and run ipconfig /all. A 169.254 address means no DHCP lease.' },
    { id: 'renew', label: 'Tried ipconfig /renew and saw the DHCP request fail', match: { tool: 'terminal', action: 'ipconfig_renew', target: 'DEN-LT-1041' }, weight: 0.5 },
    { id: 'scope', label: 'Checked the DHCP scope on DEN-DC01 and found it exhausted', match: [{ tool: 'server', action: 'view_dhcp', target: 'DEN-DC01' }, { tool: 'server', action: 'view', target: 'DEN-DC01' }], hint: 'The Server Room shows DHCP scopes. Is the Denver-Users pool full?' },
  ],
  required: [
    { id: 'escalate_note', label: 'Escalated to the Network team (this is beyond Tier 1)', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'fix_scope', label: 'Tried to extend the DHCP scope yourself', why: 'DHCP scope changes are the Network team\'s call (KB-0004). Tier 1 diagnoses and hands off with evidence; changing server config without change control can break the whole site.', match: [{ tool: 'server', action: 'extend_scope' }, { tool: 'server', action: 'reduce_lease' }], skill: 'process', penalty: 0.3 },
    { id: 'closeit', label: 'Resolved the ticket as a single-user issue', why: 'A dozen users on a floor is not a single-user fix. Under-prioritizing a floor outage misses the SLA.', match: { tool: 'ticket', action: 'reply', target: 'r_single' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed: the whole 3rd floor DHCP pool (Denver-Users, 10.10.20.0/24) is exhausted — affected machines are falling back to 169.254 addresses and can\'t get a lease. Machines that kept their lease still work. Escalating to Network as P2 with the scope screenshot; likely the new contractor laptops consumed the free leases. Please shorten the lease time or extend the scope.', scores: { communication: 1, process: 1 }, feedback: 'Scoped it, proved the cause, escalated to the right team with everything they need to act.' },
    { id: 'r_single', text: 'Renewed the IP on the affected laptop — should be good now. Closing.', scores: { communication: 0.2, process: 0.1 }, feedback: 'Treats a floor-wide outage as one machine, and the renew fails anyway because the pool is empty.' },
    { id: 'r_reboot', text: 'Please have everyone reboot their machines and routers.', scores: { communication: 0.2 }, feedback: 'There are no "routers" at user desks, and rebooting into an empty DHCP pool changes nothing.' },
  ],
  notesRubric: [
    { label: 'the scope (a floor/dozen users, one site, existing leases still work)', pattern: /floor|finance|dozen|multiple|scope|many users/i },
    { label: 'the evidence (APIPA 169.254 + exhausted DHCP pool)', pattern: /169\.254|apipa|dhcp|exhaust|pool|lease/i },
    { label: 'the escalation target and why (Network, scope change)', pattern: /network team|escalat|extend|lease time|scope/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'network', category: 'Network - DHCP Scope Exhaustion', resolutionCode: 'Escalated to Network with diagnosis' },
  categoryAccept: ['network', 'dhcp', 'outage'],
  resolutionCodeAccept: ['escalat', 'network', 'dhcp'],
  hints: [
    'First question: one user or many? That decides everything (KB-0007).',
    'ipconfig /all on an affected machine — a 169.254 address means DHCP is not answering.',
    'Server Room > DEN-DC01 > DHCP scopes. Is Denver-Users full?',
    'This is a Network team fix. Escalate P2 with your evidence; do not change server config yourself.',
  ],
  debrief: 'Great Tier 1 work is knowing the boundary. You correctly diagnosed an exhausted DHCP scope (new contractor devices ate the free leases) and proved it with an APIPA address plus the server view — but the fix (extending the scope or shortening lease time) belongs to Network under change control. The failure modes were treating a floor outage as one laptop, and over-reaching to reconfigure the DHCP server yourself.',
};

// ---------------------------------------------------------------------------
// SD1-04  Phishing report, user clicked -> escalate to SOC
// ---------------------------------------------------------------------------
const sd1_04: Scenario = {
  id: 'sd1-04',
  tier: 'sd1',
  title: '"Was this email real? I think I clicked it"',
  category: 'Security',
  difficulty: 2,
  estMinutes: 9,
  objective: 'Handle a phishing report at Tier 1: triage the user\'s interaction, preserve evidence, and escalate to Security without contaminating the investigation.',
  intake: {
    kind: 'ticket', number: 'INC457704', subject: 'Was this email real? I think I clicked it',
    body: 'Chat from Owen Bennett (Design Engineer): "I got an email from \'IT Support\' saying my mailbox was full and I had to verify my password. I clicked the link and it looked like our login page so I typed my password. Then it just went to a blank page. Was that real??"',
    requester: 'obennett', channel: 'chat', priority: 'P3', category: 'Email', openedAt: ago(6),
  },
  priorityExpected: 'P2',
  setup: (w) => {
    w.mail.push({
      id: 'MSG-88120', time: ago(40), from: 'it-support@kestreldynamlcs.com', to: ['obennett@kestreldynamics.com'],
      subject: '[Action Required] Your mailbox is full — verify to avoid losing email',
      status: 'delivered (junk)', reason: 'DMARC fail; delivered to Junk',
      headers: { from: 'IT Support <it-support@kestreldynamlcs.com>', returnPath: 'bounce@mail-secure-verify.top', replyTo: 'it-support@mail-secure-verify.top', receivedFrom: 'mail-secure-verify.top [193.42.33.14]', spf: 'fail', dkim: 'fail', dmarc: 'fail', messageId: '<9912@mail-secure-verify.top>' },
      body: 'Your mailbox has exceeded its quota. Verify your credentials within 24 hours or your account will be suspended. Verify now: http://kestrel-mailverify.top/login',
      urls: ['http://kestrel-mailverify.top/login'], phishing: true, clicked: ['obennett'],
    });
    w.intel.push({ indicator: 'kestrel-mailverify.top', type: 'domain', verdict: 'malicious', source: 'PhishTank + internal', tags: ['phishing', 'credential-harvest'], detail: 'Credential-harvesting page mimicking the WorkSuite login. Registered 3 days ago. .top TLD, no relation to Kestrel.' });
    w.intel.push({ indicator: 'kestreldynamlcs.com', type: 'domain', verdict: 'malicious', source: 'internal', tags: ['lookalike', 'typosquat'], detail: 'Lookalike of kestreldynamics.com (note the "l" replacing "i"). Not owned by Kestrel.' });
  },
  contactWith: 'obennett',
  contact: [
    { id: 'clicked', question: 'Did you click the link, and did you actually type your password on that page?', answer: '"Yes to both. I typed my normal password and hit submit."', purpose: 'clarify', reveals: 'entered-creds' },
    { id: 'attach', question: 'Did you open any attachment or download anything?', answer: '"No attachment, just the link."', purpose: 'clarify' },
    { id: 'reply', question: 'Did you reply to the email or forward it to anyone?', answer: '"No. I got suspicious after and messaged you."', purpose: 'clarify' },
    { id: 'when', question: 'Roughly when did you enter your password?', answer: '"Maybe half an hour ago?"', purpose: 'clarify' },
    { id: 'reset_self', question: 'Can you change your own password right now to be safe?', answer: '"I can try — should I?"  (Careful: KB-0005 says do not reset before SOC reviews the sign-in evidence, unless SOC directs it.)', purpose: 'red_flag' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the phishing-handling SOP (KB-0005)', match: { tool: 'kb', action: 'read', target: 'KB-0005' } },
    { id: 'headers', label: 'Pulled the message headers in Mail Admin (SPF/DKIM/DMARC all fail, lookalike domain)', match: [{ tool: 'mail', action: 'view_headers', target: 'MSG-88120' }, { tool: 'mail', action: 'view', target: 'MSG-88120' }], hint: 'Mail Admin > find the message > headers. Do the authentication checks pass?' },
  ],
  required: [
    { id: 'note_id', label: 'Recorded the message ID and that credentials were entered', match: { tool: 'ticket', action: 'submit' }, skill: 'documentation' },
    { id: 'escalate', label: 'Escalated to Security (SOC) as P2', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'reset_pw', label: 'Reset the user\'s password before SOC reviewed it', why: 'KB-0005: when creds were entered, escalate to SOC first — they need the sign-in evidence intact. Reset only if SOC directs it. (An active attacker session is the exception, which SOC decides.)', match: { tool: 'directory', action: 'reset_password', target: 'obennett' }, skill: 'security', penalty: 0.4 },
    { id: 'forward', label: 'Forwarded the email to warn other staff', why: 'KB-0005: never broadcast the phish yourself; Security handles warnings and purges.', match: { tool: 'ticket', action: 'reply', target: 'r_forward' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Thank you for reporting it — that was a phishing page, not ours (lookalike domain, all authentication checks failed). Because you entered your password, I\'m escalating to Security right now as urgent. Please don\'t use your account or change your password until they contact you — they need to check the sign-in activity first. Don\'t forward the email; just leave it where it is.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Reassures the user for reporting, preserves evidence, escalates correctly, and gives clear instructions.' },
    { id: 'r_reset', text: 'No problem — I\'ve reset your password, you\'re safe now. Closing this out.', scores: { communication: 0.4, security: 0.1, process: 0.1 }, feedback: 'Feels helpful but destroys the evidence SOC needs and closes an active security incident at Tier 1.' },
    { id: 'r_forward', text: 'Got it — I\'ll send a warning to the whole company so nobody else falls for it.', scores: { communication: 0.3, security: 0.2 }, feedback: 'Well-meant but against SOP; broadcasting tips off the attacker and floods the desk. Security owns warnings.' },
  ],
  notesRubric: [
    { label: 'that the user entered credentials (interaction)', pattern: /entered|typed|submitted|clicked.*(password|creds)|credential/i },
    { label: 'the message ID / evidence', pattern: /msg-88120|message id|header|dmarc|spf|lookalike|kestrel-mailverify|kestreldynamlcs/i },
    { label: 'the escalation to Security and the "do not use account" instruction', pattern: /security|soc|escalat|do not use|don.t use|preserve/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'soc', category: 'Security - Phishing (credentials entered)', resolutionCode: 'Escalated to SOC, evidence preserved' },
  categoryAccept: ['security', 'phishing', 'email'],
  resolutionCodeAccept: ['escalat', 'soc', 'security', 'phishing'],
  hints: [
    'KB-0005 is your script for phishing reports.',
    'The three questions that set severity: did you click, did you enter your password, did you open an attachment?',
    'Because he entered credentials, this is P2 to Security. Pull the message ID from Mail Admin for them.',
    'Do NOT reset his password yourself and do NOT forward the email. Preserve evidence; SOC drives from here.',
  ],
  debrief: 'Tier 1\'s job on a phishing report is triage and clean escalation, not investigation. Owen entered his credentials, so this is an active credential-compromise: escalate to SOC immediately, record the message ID, and tell the user to stop using the account. The instinct to "just reset the password" is exactly wrong here — it wipes the sign-in evidence SOC needs to see whether the attacker already logged in. Notice the tells you can cite: the lookalike sender domain, the .top link, and SPF/DKIM/DMARC all failing.',
};

// ---------------------------------------------------------------------------
// SD1-05  Name change after marriage (process + do not break the account)
// ---------------------------------------------------------------------------
const sd1_05: Scenario = {
  id: 'sd1-05',
  tier: 'sd1',
  title: 'Legal name change after marriage',
  category: 'Identity',
  difficulty: 1,
  estMinutes: 6,
  objective: 'Follow the name-change process: confirm HR authorization, update the display name and email alias, and avoid the classic mistake that breaks a user\'s profile.',
  intake: {
    kind: 'ticket', number: 'INC457705', subject: 'Legal name change after marriage - please update my account',
    body: 'Portal ticket from Hana Sato: "I got married and legally changed my last name to Sato-Klein. Please update my name and email. HR (Sarah Turner) said she\'d approve the ticket."',
    requester: 'hsato', channel: 'portal', priority: 'P4', category: 'Request', openedAt: ago(90),
  },
  priorityExpected: 'P4',
  setup: (w) => {
    // HR confirmation present in chat with sturner.
    w.chat.push({ id: 'ch-hr', with: 'sturner', messages: [
      { from: 'sturner', time: ago(70), text: 'Confirming for ticket INC457705: Hana Sato\'s legal name is now Hana Sato-Klein, effective this week. HR-approved. Please keep her old email as an alias so nothing bounces.' },
    ] });
  },
  contactWith: 'sturner',
  contact: [
    { id: 'hr', question: 'Confirm HR authorization for the name change', answer: 'Sarah Turner (HR) confirms in chat: legally Hana Sato-Klein, HR-approved, keep old email as an alias.', purpose: 'verify' },
    { id: 'newname', question: 'What is the exact new legal name to display?', answer: '"Hana Sato-Klein."', purpose: 'clarify' },
    { id: 'alias', question: 'Should we keep the old email address working?', answer: '"Yes — keep hsato@ as an alias so replies to old threads still arrive. Add the new alias too."', purpose: 'clarify' },
    { id: 'title', question: 'Any title or department change with this?', answer: '"No, same role."', purpose: 'clarify' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the name-change SOP (KB-0006)', match: { tool: 'kb', action: 'read', target: 'KB-0006' } },
    { id: 'view', label: 'Opened Hana\'s account', match: { tool: 'directory', action: 'view', target: 'hsato' } },
  ],
  required: [
    { id: 'display', label: 'Updated the display name to Hana Sato-Klein', match: { tool: 'directory', action: 'set_display_name', target: 'hsato', params: { name: /sato-klein/i } }, skill: 'technical' },
    { id: 'alias', label: 'Added the new email as an alias (kept the old address)', match: { tool: 'directory', action: 'add_alias', target: 'hsato' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'rename_sam', label: 'Renamed the sAMAccountName / removed the old email', why: 'KB-0006: never rename the logon account or drop the old address — it breaks her Windows profile, mapped drives, and any mail sent to the old address.', match: [{ tool: 'directory', action: 'reset_password', target: 'hsato' }], skill: 'technical', penalty: 0.2 },
    { id: 'no_hr', label: 'Made the change without HR confirmation', why: 'Name changes require HR authorization (KB-0006).', match: { tool: 'directory', action: 'set_display_name', target: 'hsato' }, unlessAfter: 'verify_gate', skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Congratulations! I\'ve confirmed the change with HR and updated your display name to Hana Sato-Klein. I added hana.sato-klein@kestreldynamics.com as your new address and kept your old one as an alias, so nothing you\'re already on the thread for will bounce. Your username and password don\'t change. It may take a bit to show everywhere as it syncs.', scores: { communication: 1 }, feedback: 'Warm, accurate, and sets the expectation that the login itself is unchanged.' },
    { id: 'r_rename', text: 'Done — I\'ve changed your username and email to sato-klein and removed the old one. Please log in with the new username.', scores: { communication: 0.3, technical: 0.1 }, feedback: 'Renaming the account and dropping the old alias is the classic break: profile, drives, and old-thread mail all fail.' },
    { id: 'r_stall', text: 'We can\'t change names without a copy of your marriage certificate sent to us.', scores: { communication: 0.4, process: 0.3 }, feedback: 'HR handles legal documentation, and HR already approved. Asking the employee for a certificate is not IT\'s role here.' },
  ],
  notesRubric: [
    { label: 'HR authorization confirmed', pattern: /hr|sarah turner|sturner|approv|authoriz/i },
    { label: 'display name updated, old email kept as alias', pattern: /display name|alias|kept|old (email|address)|sato-klein/i },
    { label: 'that the logon account was intentionally not renamed', pattern: /username|samaccount|logon|not renamed|unchanged|same login/i },
  ],
  closure: { disposition: 'resolve', category: 'Identity - Name Change', resolutionCode: 'Display name + alias updated (HR-approved)' },
  categoryAccept: ['identity', 'name', 'request'],
  resolutionCodeAccept: ['name', 'alias', 'display'],
  hints: [
    'KB-0006 covers name changes. Note what you must NOT rename.',
    'Confirm HR authorization first — it is already in your Chat with Sarah Turner.',
    'Change the Display Name and ADD a new alias. Keep the old address so old mail still arrives.',
    'Do not touch the username/sAMAccountName or the password.',
  ],
  debrief: 'A "simple" P4 with a real landmine. HR authorization is required and was provided. The change is: update the display name, add the new email alias, keep the old address. The mistake that generates a follow-up ticket every time is renaming the sAMAccountName or removing the old alias, which orphans the profile and bounces in-flight mail. Small requests still deserve the SOP.',
};

export const SD1_SCENARIOS: Scenario[] = [sd1_01, sd1_02, sd1_03, sd1_04, sd1_05];
