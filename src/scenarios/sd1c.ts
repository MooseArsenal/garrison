import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, breakInternet, breakDns, setDhcpExhausted, lockOut, setConn } from './helpers';

// ---------------------------------------------------------------------------
// SD1-13  Offboarding / termination (HR email) - disable, don't delete
// ---------------------------------------------------------------------------
const sd1_13: Scenario = {
  id: 'sd1-13',
  tier: 'sd1',
  title: 'Offboard a departing employee',
  category: 'Identity',
  difficulty: 2,
  estMinutes: 8,
  objective: 'Run the offboarding checklist from an authorized HR request: disable the account, reset the password, strip group access, and convert the mailbox to shared for the manager — without deleting or re-enabling anything.',
  intake: {
    kind: 'ticket', number: 'INC457713', subject: 'Termination - offboard Carlos Flores, effective today',
    body: `Email from Sarah Turner (HR): "Please offboard Carlos Flores (Sales, remote Phoenix) — his resignation is effective today. Disable his account, reset the password, remove his group access, and convert his mailbox to a shared mailbox for his manager Emily Wright. Do NOT delete the account (we keep it for records) and do not re-enable it for anyone."`,
    requester: 'sturner', channel: 'email', priority: 'P3', category: 'Request', openedAt: ago(20), affectedHost: 'DEN-LT-1061',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const u = findUser(w, 'cflores')!;
    u.termDate = ago(0);
    u.notes = 'Resignation effective today; offboard per HR ticket INC457713 (Sarah Turner). Do not delete or re-enable.';
  },
  contactWith: 'sturner',
  contact: [
    { id: 'hr_auth', question: 'Confirm this termination is authorized by HR and effective today.', answer: 'Sarah Turner (HR) confirms: Carlos Flores, Sales, termination effective today, HR-authorized under INC457713.', purpose: 'verify' },
    { id: 'mailbox_owner', question: 'Confirm we should convert his mailbox to shared and who receives it.', answer: '"Yes — convert it to a shared mailbox and give his manager, Emily Wright, access so nothing is lost."', purpose: 'verify' },
    { id: 'asset', question: 'He is remote — how should we recover his laptop?', answer: '"Ship him a prepaid return label for the laptop; that part is not urgent."', purpose: 'clarify', reveals: 'asset-return' },
    { id: 'timing', question: 'Should the account be disabled now or at end of day?', answer: '"Now, please. He has already been notified."', purpose: 'clarify' },
    { id: 'reenable', question: 'Emily asks if we can re-enable his login for an hour so he can grab some personal files. OK?', answer: '"—" (KB-0006: never re-enable a terminated account so someone can "grab a file." The manager gets delegate/shared access instead. Decline this.)', purpose: 'red_flag' },
    { id: 'party', question: 'Is the team throwing him a farewell lunch?', answer: '"...that is not really an IT question. Can we finish the offboarding?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the termination SOP (KB-0006)', match: { tool: 'kb', action: 'read', target: 'KB-0006' }, hint: 'What are the exact termination steps, and what must you never do?' },
    { id: 'view', label: 'Opened the departing user\'s account', match: { tool: 'directory', action: 'view', target: 'cflores' } },
  ],
  required: [
    { id: 'disable', label: 'Disabled the account', match: { tool: 'directory', action: 'disable', target: 'cflores' }, skill: 'technical' },
    { id: 'reset', label: 'Reset the password', match: { tool: 'directory', action: 'reset_password', target: 'cflores' }, skill: 'technical' },
    { id: 'remove_groups', label: 'Removed the account from its groups', match: { tool: 'directory', action: 'remove_group', target: 'cflores' }, skill: 'process' },
    { id: 'convert', label: 'Converted the mailbox to shared for the manager', match: { tool: 'mail', action: 'convert_shared', target: 'cflores' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'reenable', label: 'Re-enabled the terminated account', why: 'KB-0006: never re-enable a terminated account so someone can "grab a file." The manager gets delegate/shared mailbox access instead — re-enabling reopens a live credential for a person who has left.', match: { tool: 'directory', action: 'enable', target: 'cflores' }, skill: 'security', penalty: 0.5 },
    { id: 'reply_reenable', label: 'Told the manager you would re-enable the login', why: 'Offering to switch the account back on defeats the offboarding. Give the manager the shared mailbox, not the login.', match: { tool: 'ticket', action: 'reply', target: 'r_reenable' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Offboarding done per HR: I disabled Carlos\'s account, reset the password, removed his group access, and converted his mailbox to a shared mailbox with Emily Wright as the owner so nothing is lost. The account is retained (not deleted) for your records. I\'m shipping a prepaid label for his laptop. If Emily needs his files, she now has them through the shared mailbox — I won\'t re-enable the login.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Completed every step, kept the account for records, and correctly refused the re-enable by giving the manager the shared mailbox instead.' },
    { id: 'r_reenable', text: 'All set — and sure, I\'ll re-enable his login for an hour so he can pull his personal files, then disable it again.', scores: { communication: 0.4, security: 0.1, process: 0.1 }, feedback: 'Re-enabling a terminated account is exactly what KB-0006 forbids. The manager gets shared-mailbox access; the login stays off.' },
    { id: 'r_delete', text: 'Done — I deleted his account and mailbox entirely so it\'s cleaned up.', scores: { communication: 0.3, technical: 0.1, process: 0.1 }, feedback: 'HR explicitly said not to delete. Deleting destroys records and the mailbox the manager needs; disable and convert to shared instead.' },
    { id: 'r_partial', text: 'I disabled his account. Let me know if you need anything else.', scores: { communication: 0.4, process: 0.3 }, feedback: 'Only the first step. The password reset, group removal, and mailbox conversion are all part of the offboarding.' },
  ],
  notesRubric: [
    { label: 'HR authorization for the termination', pattern: /hr|sarah|turner|sturner|authoriz|approv|termination/i },
    { label: 'the actions taken (disable, reset, remove groups)', pattern: /disable|reset|remove.*group|revok|offboard/i },
    { label: 'mailbox converted to shared for the manager', pattern: /shared mailbox|convert|delegate|emily|wright|manager/i },
    { label: 'did not delete or re-enable', pattern: /not delet|retain|kept|did not re-?enable|not re-?enable|stays? (off|disabled)/i },
  ],
  closure: { disposition: 'resolve', category: 'Identity - Offboarding', resolutionCode: 'Account disabled + mailbox converted to shared (HR-authorized)' },
  categoryAccept: ['identity', 'offboarding', 'termination', 'account'],
  resolutionCodeAccept: ['offboard', 'disable', 'shared', 'mailbox', 'termination'],
  hints: [
    'KB-0006 has the termination checklist. Confirm HR authorization first.',
    'The steps: disable, reset password, remove groups, convert mailbox to shared for the manager.',
    'Do NOT delete the account (HR wants it retained) and do NOT re-enable it for anyone.',
    'If the manager needs the files, give her the shared mailbox — not the login.',
  ],
  debrief: 'Offboarding is a checklist, and the whole point is to remove a live credential cleanly while preserving data. HR authorized it, so you disable, reset, strip groups, and convert the mailbox to shared for Emily. The two traps are the ones that generate audit findings: deleting the account (HR said retain it, and it destroys the mailbox and records) and re-enabling it later "just to grab a file." The manager gets the shared mailbox; the login never comes back on.',
};

// ---------------------------------------------------------------------------
// SD1-14  Phishing reported, NO interaction (email) - close, don't escalate
// ---------------------------------------------------------------------------
const sd1_14: Scenario = {
  id: 'sd1-14',
  tier: 'sd1',
  title: 'Reported a phishing email — didn\'t touch it',
  category: 'Security',
  difficulty: 2,
  estMinutes: 7,
  objective: 'Triage a phishing report where the user did NOT interact: confirm no click / no credentials, record the message ID, close it as reported-no-interaction, and resist the urge to escalate or forward.',
  intake: {
    kind: 'ticket', number: 'INC457714', subject: 'Forwarding a suspicious email - I did not click anything',
    body: `Email from Bhavik Patel (Senior Accountant): "Heads up — I got a sketchy email claiming to be a shared invoice, but the sender looked wrong so I didn't click the link or open anything. I just wanted to report it. Do I need to do anything?"`,
    requester: 'bpatel', channel: 'email', priority: 'P2', category: 'Email', openedAt: ago(12),
  },
  priorityExpected: 'P3',
  setup: (w) => {
    w.mail.push({
      id: 'MSG-91455', time: ago(70), from: 'billing@invoicES-share.top', to: ['bpatel@kestreldynamics.com'],
      subject: 'Shared invoice #INV-88231 requires your review',
      status: 'delivered (junk)', reason: 'Proofpoint: DMARC fail; delivered to Junk',
      headers: { from: 'Invoice Share <billing@invoices-share.top>', returnPath: 'bounce@invoices-share.top', replyTo: 'billing@invoices-share.top', receivedFrom: 'invoices-share.top [45.147.230.9]', spf: 'fail', dkim: 'fail', dmarc: 'fail', messageId: '<PPX-2026-91455@proofpoint.kestreldynamics.com>' },
      body: 'You have a shared invoice awaiting review. Sign in to view: http://invoices-share.top/view?id=88231',
      urls: ['http://invoices-share.top/view?id=88231'], phishing: true, clicked: [],
    });
    w.intel.push({ indicator: 'invoices-share.top', type: 'domain', verdict: 'malicious', source: 'PhishTank', tags: ['phishing', 'invoice-lure'], detail: 'Credential-harvest / invoice-lure domain, .top TLD, registered 5 days ago. No relation to Kestrel.' });
  },
  contactWith: 'bpatel',
  contact: [
    { id: 'clicked', question: 'Just to confirm — did you click the link or type your password anywhere?', answer: '"No. The sender address looked off so I stopped and reported it. Never clicked."', purpose: 'clarify', reveals: 'no-interaction' },
    { id: 'attach', question: 'Did you open any attachment or reply to it?', answer: '"No attachment, no reply. I just forwarded it to you."', purpose: 'clarify' },
    { id: 'others', question: 'Did anyone else on your team get the same message that you know of?', answer: '"Not sure — I only saw mine."', purpose: 'clarify' },
    { id: 'forward', question: 'Should you forward it around to warn the rest of Finance?', answer: '"—" (KB-0005: never broadcast the phish yourself; Security handles warnings and purges. Advise against forwarding.)', purpose: 'red_flag' },
    { id: 'coffee', question: 'How\'s month-end treating you otherwise?', answer: '"Busy — anyway, is there anything I need to do about the email?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the phishing-handling SOP (KB-0005)', match: { tool: 'kb', action: 'read', target: 'KB-0005' }, hint: 'What do you do when the answer to "did you click?" is NO?' },
    { id: 'headers', label: 'Looked up the message in Mail Admin and noted the Proofpoint message ID', match: [{ tool: 'mail', action: 'view_headers', target: 'MSG-91455' }, { tool: 'mail', action: 'view', target: 'MSG-91455' }], hint: 'Mail Admin > find the message. Record the message ID for the record.' },
  ],
  required: [
    { id: 'close', label: 'Recorded the message ID and closed as reported-no-interaction', match: { tool: 'ticket', action: 'submit' }, skill: 'documentation' },
  ],
  forbidden: [
    { id: 'escalate_soc', label: 'Escalated to SOC despite no interaction', why: 'KB-0005: when the user did not click or enter credentials, thank them and close as "reported, no interaction." Escalating a non-event burns SOC time.', match: { tool: 'ticket', action: 'reply', target: 'r_escalate' }, skill: 'process', penalty: 0.3 },
    { id: 'forward', label: 'Forwarded the phish to warn other staff', why: 'KB-0005: never broadcast a phishing message yourself; Security owns warnings and gateway purges.', match: { tool: 'ticket', action: 'reply', target: 'r_forward' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Thanks Bhavik — you did exactly the right thing by not clicking and reporting it. It was a phishing attempt (spoofed sender, all authentication checks failed). Since you didn\'t click the link or enter anything, there\'s nothing you need to do; I\'ve recorded the message ID (Proofpoint PPX-2026-91455) and closed this as reported with no interaction. Going forward, use the "Report phishing" button and leave it — no need to forward it around; Security handles any warnings.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Reinforces the good reporting behavior, documents the message ID, and closes at the right level without over-escalating.' },
    { id: 'r_escalate', text: 'Thanks — I\'m escalating this to our SOC as a security incident so they can investigate fully.', scores: { communication: 0.5, process: 0.2 }, feedback: 'Nobody clicked or entered credentials, so this closes as reported-no-interaction. Escalating a non-event wastes SOC\'s time (KB-0005).' },
    { id: 'r_forward', text: 'Good catch — I\'ll forward this to all of Finance so nobody else falls for it.', scores: { communication: 0.4, security: 0.2 }, feedback: 'Well-meant, but broadcasting the phish is against SOP. Security owns warnings and purges.' },
    { id: 'r_dismiss', text: 'It\'s just spam — delete it and don\'t worry about it.', scores: { communication: 0.3, security: 0.3 }, feedback: 'Dismissive and skips the record. Confirm no interaction, note the message ID, and close it properly.' },
  ],
  notesRubric: [
    { label: 'confirmed no interaction (no click, no credentials)', pattern: /no (click|interaction)|did ?n.t click|no creds|no credential|didn.t enter/i },
    { label: 'the message ID / evidence', pattern: /msg-91455|ppx-2026-91455|message id|proofpoint|dmarc|spf/i },
    { label: 'closed as reported, no interaction; report-phishing guidance', pattern: /no interaction|reported|report phishing|closed|button/i },
    { label: 'did not escalate or forward', pattern: /no(t)? escalat|did not escalat|no(t)? forward|did not forward/i },
  ],
  closure: { disposition: 'resolve', category: 'Security - Phishing (no interaction)', resolutionCode: 'Phishing - reported, no interaction' },
  categoryAccept: ['security', 'phishing', 'email'],
  resolutionCodeAccept: ['no interaction', 'no-interaction', 'reported', 'phishing'],
  hints: [
    'KB-0005 is the script. The pivotal questions: did you click, enter your password, open an attachment, or reply?',
    'The answer here is NO to all — so this is not an incident.',
    'Pull the message in Mail Admin and record the Proofpoint message ID for the record.',
    'Close as "Phishing - reported, no interaction." Do not escalate to SOC and do not forward the email.',
  ],
  debrief: 'The whole game on a phishing report is the interaction question. Bhavik did not click, enter credentials, or open anything, so there is no compromise to chase: you thank him (reinforcing the exact behavior you want), record the Proofpoint message ID, and close it as reported-no-interaction. The two traps are over-reactions — escalating a non-event to SOC, and forwarding the phish "to warn people," which is Security\'s job, not a Tier 1 broadcast. Contrast this with SD1-04, where credentials WERE entered and escalation to SOC is exactly right.',
};

// ---------------------------------------------------------------------------
// SD1-15  Account disabled, user returning from leave (phone)
// ---------------------------------------------------------------------------
const sd1_15: Scenario = {
  id: 'sd1-15',
  tier: 'sd1',
  title: 'Back from leave and my account is disabled',
  category: 'Identity',
  difficulty: 2,
  estMinutes: 7,
  objective: 'Reinstate a disabled account the right way: verify the caller AND confirm HR authorized the return before re-enabling. Never re-enable a disabled account on the caller\'s say-so alone.',
  intake: {
    kind: 'ticket', number: 'INC457715', subject: 'Returning from leave - can\'t log in, account disabled',
    body: `Phone call: "Hi, it's Mike Johnson out at the Wichita plant. I've been on medical leave and today's my first day back, but my login says my account is disabled. Can you turn it back on so I can get to work?"`,
    requester: 'mjohnson', channel: 'phone', priority: 'P2', category: 'Access', openedAt: ago(8),
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const u = findUser(w, 'mjohnson')!;
    u.enabled = false;
    u.notes = 'Account disabled during leave of absence; re-enable only with HR confirmation of return-to-work.';
    // HR has confirmed the return in a chat thread the analyst can check.
    w.chat.push({ id: 'ch-hr-return', with: 'sturner', messages: [
      { from: 'sturner', time: ago(40), text: 'Confirming for INC457715: Mike Johnson\'s medical leave has ended and HR has cleared his return-to-work effective today. You\'re good to re-enable his account with the same access as before.' },
    ] });
  },
  contactWith: 'mjohnson',
  contact: [
    { id: 'empid', question: 'Can you confirm your employee ID for verification?', answer: '"It\'s E10131."', purpose: 'verify' },
    { id: 'hr_confirm', question: 'I\'ll confirm your return is cleared by HR before I re-enable anything.', answer: 'Sarah Turner (HR) has confirmed in chat: Mike Johnson\'s leave ended, return-to-work cleared effective today, same access as before.', purpose: 'verify' },
    { id: 'leave', question: 'Just to confirm — you were on an approved leave, not a termination?', answer: '"Right, medical leave. HR knew I was coming back today."', purpose: 'clarify', reveals: 'reinstatement' },
    { id: 'access', question: 'Should your groups and access be exactly what they were before?', answer: '"Yeah, same job, same access. Just need to log in."', purpose: 'clarify' },
    { id: 'rush', question: 'Can you just flip it on now and check with HR afterward? My shift is starting.', answer: '"—" (Do not re-enable a disabled account on the caller\'s word alone; confirm HR cleared the return first, per KB-0006/KB-0002.)', purpose: 'red_flag' },
    { id: 'drive', question: 'How was the drive in this morning?', answer: '"Fine. Can we get me logged in?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb2', label: 'Read the unlock/disabled-account SOP (KB-0002)', match: { tool: 'kb', action: 'read', target: 'KB-0002' }, hint: 'What does the SOP say to do when an account is disabled rather than locked?' },
    { id: 'view', label: 'Opened the account and confirmed it is disabled (not locked)', match: { tool: 'directory', action: 'view', target: 'mjohnson' } },
  ],
  required: [
    { id: 'enable', label: 'Re-enabled the account after verifying and confirming the return', match: { tool: 'directory', action: 'enable', target: 'mjohnson' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'enable_no_verify', label: 'Re-enabled on the caller\'s say-so before verifying / confirming HR', why: 'A disabled account is disabled for a reason. KB-0002/KB-0006: verify the caller AND confirm HR cleared the return before re-enabling — never on the caller\'s word alone.', match: { tool: 'directory', action: 'enable', target: 'mjohnson' }, unlessAfter: 'verify_gate', skill: 'security', penalty: 0.5 },
    { id: 'reset_pw', label: 'Reset the password as if this were a lockout', why: 'The account is disabled, not locked, and the password is not the problem. A reset does not re-enable it and just adds a step; enable it after confirming the return.', match: { tool: 'directory', action: 'reset_password', target: 'mjohnson' }, skill: 'technical', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Thanks Mike — I verified you by employee ID and confirmed with HR that your leave has ended and your return is cleared for today. I\'ve re-enabled your account with the same access as before; you should be able to log in now. Welcome back. If anything looks missing once you\'re in, ping me.', scores: { communication: 1, security: 1 }, feedback: 'Verified the caller, confirmed HR cleared the return, then re-enabled with the original access.' },
    { id: 'r_saysso', text: 'No problem — I\'ve turned your account back on. You\'re all set.', scores: { communication: 0.5, security: 0.1 }, feedback: 'Re-enabling a disabled account on the caller\'s say-so skips the required HR confirmation. Disabled accounts stay off until HR clears the return.' },
    { id: 'r_overstrict', text: 'I can\'t re-enable accounts at all — you\'ll have to have HR file a whole new onboarding for you.', scores: { communication: 0.4, process: 0.3 }, feedback: 'Over-strict and wrong: this is a reinstatement, not a new hire. Once HR confirms the return, re-enabling is the correct, simple fix.' },
  ],
  notesRubric: [
    { label: 'verified the caller (employee ID / callback)', pattern: /employee id|e10131|verified|callback|call back/i },
    { label: 'confirmed HR cleared the return', pattern: /hr|sarah|turner|sturner|return|leave|cleared|confirm/i },
    { label: 'the action (re-enabled the disabled account, same access)', pattern: /re-?enabl|enabled|reinstat|same access/i },
    { label: 'noted it was disabled, not locked', pattern: /disabled|not locked|reinstatement/i },
  ],
  closure: { disposition: 'resolve', category: 'Identity - Reinstatement', resolutionCode: 'Re-enabled account (HR-confirmed return from leave)' },
  categoryAccept: ['identity', 'reinstatement', 'account', 'access'],
  resolutionCodeAccept: ['re-enable', 'reenable', 'enable', 'reinstat', 'account'],
  hints: [
    'First: is the account locked or disabled? Disabled is different — check KB-0002.',
    'Verify the caller (employee ID), and separately confirm with HR that his return-to-work is cleared (it\'s in your Chat).',
    'Only then re-enable the account with his original access.',
    'Do not re-enable just because the caller says he\'s back, and do not reset the password — it\'s not a lockout.',
  ],
  debrief: 'A disabled account is a deliberate state, so reinstatement is not the same as clearing a lockout. The correct path is two gates: verify the caller, and confirm HR has cleared the return-to-work — the confirmation was waiting in your Chat with HR. Only then do you re-enable. The trap is flipping it on because the caller sounds legitimate and is in a hurry; disabled accounts stay off until the authorizing party (HR) says otherwise. Resetting the password is a red herring — the credential is not the problem, the enabled flag is.',
};

// ---------------------------------------------------------------------------
// SD1-16  Shared mailbox access request (portal) - route for data-owner approval
// ---------------------------------------------------------------------------
const sd1_16: Scenario = {
  id: 'sd1-16',
  tier: 'sd1',
  title: 'Access to the AP shared mailbox, please',
  category: 'Access',
  difficulty: 2,
  estMinutes: 6,
  objective: 'Recognize a sensitive access request, and route it for the data owner\'s approval instead of granting it — even when the requester\'s manager is fine with it.',
  intake: {
    kind: 'ticket', number: 'INC457716', subject: 'Please add me to the AP Invoices shared mailbox',
    body: `Portal ticket from Jordan Webb (Marketing Coordinator): "I'm helping cover accounts-payable invoices during month-end, so I need access to the AP-Invoices shared mailbox. My manager Emily is fine with it. Can you add me today? It's kind of urgent."`,
    requester: 'jwebb', channel: 'portal', priority: 'P3', category: 'Request', openedAt: ago(30),
  },
  priorityExpected: 'P4',
  setup: (w) => {
    const u = findUser(w, 'jwebb')!;
    u.notes = 'Requested access to the AP-Invoices shared mailbox (Finance-owned, sensitive).';
    // Add the shared mailbox so it exists as an object the analyst can reason about.
    w.mailboxes.push({ user: 'ap-invoices', quotaGB: 50, usedGB: 12, rules: [], delegates: ['jmorales', 'bpatel'] });
  },
  contactWith: 'jwebb',
  contact: [
    { id: 'mgr_appr', question: 'Has your manager approved this request?', answer: '"Yes, Emily said it\'s fine for me to help with AP this month."', purpose: 'verify' },
    { id: 'owner_appr', question: 'Do you have the Finance data owner\'s approval for the AP mailbox specifically?', answer: '"No — I figured IT could just add me. Isn\'t my manager\'s OK enough?"', purpose: 'verify', reveals: 'no-owner-approval' },
    { id: 'why', question: 'What exactly do you need to do in the AP mailbox?', answer: '"Read and respond to vendor invoice emails while AP is short-staffed for month-end."', purpose: 'clarify', reveals: 'business-need' },
    { id: 'duration', question: 'Is this a temporary need or ongoing?', answer: '"Just for month-end, a couple of weeks."', purpose: 'clarify' },
    { id: 'rush', question: 'Can you just add me now and we\'ll sort out approvals later? It\'s month-end.', answer: '"—" (KB-0006: sensitive access needs the DATA OWNER\'s approval BEFORE granting, not after. Do not add first and paper it later.)', purpose: 'red_flag' },
    { id: 'desk', question: 'Which floor do you sit on again?', answer: '"Second floor — but does that matter for the mailbox?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the access-approval SOP (KB-0006)', match: { tool: 'kb', action: 'read', target: 'KB-0006' }, hint: 'Who must approve access to a Finance / AP resource?' },
    { id: 'group', label: 'Confirmed the AP resource is sensitive (data-owner controlled)', match: { tool: 'directory', action: 'view_group', target: /ap-team|finance/i }, hint: 'Is the AP/Finance group flagged as sensitive?' },
  ],
  required: [
    { id: 'route', label: 'Routed the request for the Finance data owner\'s approval', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'grant_delegate', label: 'Granted mailbox access without data-owner approval', why: 'The AP mailbox is a Finance-owned, sensitive resource. KB-0006: access requires the DATA OWNER\'s approval, not just the requester\'s manager. Granting it on a manager\'s OK is over-provisioning.', match: [{ tool: 'mail', action: 'add_delegate', target: 'ap-invoices' }, { tool: 'directory', action: 'add_group', target: 'jwebb', params: { group: /ap-team|finance/i } }], skill: 'security', penalty: 0.5 },
    { id: 'reply_grant', label: 'Told the user access was granted', why: 'Promising the access before the data owner signs off is the wrong answer even if you never touch the mailbox. Route it, don\'t grant it.', match: { tool: 'ticket', action: 'reply', target: 'r_grant' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Happy to help get this moving. Access to the AP-Invoices mailbox is a Finance-owned, sensitive resource, so it needs the Finance data owner\'s approval — your manager\'s OK covers your side, but not the data owner\'s. I\'ve routed the request to Finance for sign-off with your business reason (month-end AP cover); as soon as they approve, I\'ll add you the same day. I can\'t grant it before that approval.', scores: { communication: 1, process: 1, security: 1 }, feedback: 'Meets the need through the right path and clearly explains why the data owner must approve first.' },
    { id: 'r_grant', text: 'Done — I\'ve added you to the AP-Invoices mailbox so you\'re ready for month-end.', scores: { communication: 0.4, security: 0.1, process: 0.1 }, feedback: 'Granting sensitive Finance access on a manager\'s casual OK is exactly the over-provisioning KB-0006 forbids. It needs the data owner.' },
    { id: 'r_refuse', text: 'Marketing doesn\'t get AP access. Denied.', scores: { communication: 0.3, process: 0.3 }, feedback: 'Too blunt and not your call. There\'s a legitimate business need; route it for the data owner to decide rather than refusing outright.' },
  ],
  notesRubric: [
    { label: 'the request (access to a sensitive AP/Finance mailbox)', pattern: /ap|accounts payable|finance|shared mailbox|invoice/i },
    { label: 'the business need and manager OK', pattern: /month-end|cover|manager|emily|business (need|reason)/i },
    { label: 'data-owner approval required; routed for approval', pattern: /data owner|owner approval|sensitive|routed|route|approval|pending/i },
    { label: 'did not grant before approval', pattern: /not grant|did not add|withheld|before approval|pending approval/i },
  ],
  closure: { disposition: 'pending', category: 'Access - Shared Mailbox', resolutionCode: 'Routed for data-owner approval (pending)' },
  categoryAccept: ['access', 'shared mailbox', 'mailbox', 'shared'],
  resolutionCodeAccept: ['route', 'approval', 'pending', 'data owner', 'data-owner'],
  hints: [
    'Separate the two approvals: the manager\'s (for the person\'s time) vs. the data owner\'s (for the resource).',
    'KB-0006: Finance/AP is a sensitive resource — the DATA OWNER must approve access.',
    'The request is legitimate, so don\'t refuse it — route it to Finance for sign-off and leave it pending.',
    'Do not add the delegate/group before that approval, no matter how urgent month-end feels.',
  ],
  debrief: 'This is a least-privilege / approval-chain test disguised as a routine request. The need is real and the manager is on board, but the AP mailbox is a Finance-owned sensitive resource, so KB-0006 requires the data owner\'s approval before any grant. The correct disposition is pending: route it to Finance and hold. The trap is the "just add me now, we\'ll sort approvals later" pressure — granting sensitive access first and papering it afterward is exactly backwards. Refusing outright is also wrong; you route the legitimate request rather than killing it.',
};

// ---------------------------------------------------------------------------
// SD1-17  Vishing - "exec's assistant" wants a forwarding rule (phone) -> SOC
// ---------------------------------------------------------------------------
const sd1_17: Scenario = {
  id: 'sd1-17',
  tier: 'sd1',
  title: 'A caller wants a rule added to the CEO\'s mailbox',
  category: 'Security',
  difficulty: 3,
  estMinutes: 8,
  objective: 'Recognize a vishing / business-email-compromise attempt: when verification fails and a caller wants a forwarding rule on an executive mailbox, make no changes and escalate to Security.',
  intake: {
    kind: 'ticket', number: 'INC457717', subject: 'Urgent - add an email forwarding rule to Diane Vance\'s mailbox',
    body: `Phone call: "Hi, this is Tanya, Diane Vance's executive assistant. Diane's travelling and asked me to have you set up a rule on her mailbox to auto-forward all her incoming email to an outside address so she can keep up. It's urgent, she's about to board — can you just add it now?"`,
    requester: 'tmartin', channel: 'phone', priority: 'P3', category: 'Email', openedAt: ago(5),
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const ceo = findUser(w, 'dvance')!;
    ceo.notes = 'Target of a phone request to add external mail forwarding — verify independently.';
    // The real Tanya Martin is at her desk and made no such request (discoverable via callback on record).
    const ea = findUser(w, 'tmartin')!;
    ea.notes = 'On site at Denver HQ today.';
  },
  contactWith: 'tmartin',
  contact: [
    { id: 'empid', question: 'Can you confirm your employee ID so I can verify you?', answer: '"Uh… I don\'t have it in front of me right now, I\'m walking with Diane. Can we skip that? It\'s really urgent."', purpose: 'verify', reveals: 'verify-fail' },
    { id: 'callback', question: 'I\'ll call Tanya back on the number we have on record to confirm this request.', answer: 'You call the number on record for Tanya Martin — the real Tanya answers at her desk and says she made NO such request and isn\'t with Diane. Verification FAILS.', purpose: 'verify', reveals: 'social-engineering' },
    { id: 'address', question: 'What forwarding address am I being asked to add?', answer: '"Send it to d.vance.assistant@proton-mail-secure.com — an outside inbox she can check."', purpose: 'clarify', reveals: 'external-forward' },
    { id: 'why', question: 'Why external forwarding rather than her just using her phone?', answer: '"She just wants everything in one place, it\'s easier. Look, she\'s boarding — can you please just do it?"', purpose: 'clarify' },
    { id: 'comply', question: 'Sure, I\'ll add the forwarding rule to Diane\'s mailbox right now, correct?', answer: '"—" (STOP. Adding external forwarding to an exec mailbox for an unverified caller is textbook BEC. Do not do it; escalate to Security.)', purpose: 'red_flag' },
    { id: 'flight', question: 'What time is Diane\'s flight?', answer: '"Soon! That\'s why this is urgent." (Irrelevant to whether the request is legitimate.)', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb1', label: 'Read the caller-verification SOP and its red flags (KB-0001)', match: { tool: 'kb', action: 'read', target: 'KB-0001' }, hint: 'Which red flags say STOP and escalate to Security?' },
    { id: 'kb20', label: 'Read the mail-rules reference on external forwarding (KB-0020)', match: { tool: 'kb', action: 'read', target: 'KB-0020' }, hint: 'What does external forwarding on a mailbox usually indicate?' },
    { id: 'view', label: 'Checked the executive\'s directory record / the claimed assistant', match: [{ tool: 'directory', action: 'view', target: 'dvance' }, { tool: 'directory', action: 'view', target: 'tmartin' }], weight: 0.5 },
  ],
  required: [
    { id: 'escalate', label: 'Escalated to Security (SOC) as a social-engineering attempt', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
    { id: 'priority', label: 'Set the priority to P2 (possible security incident)', match: { tool: 'ticket', action: 'set_priority', params: { priority: 'P2' } }, skill: 'security' },
  ],
  forbidden: [
    { id: 'act_mailbox', label: 'Made a change to the executive\'s mailbox for an unverified caller', why: 'KB-0001/KB-0020: never modify a mailbox (delegate, forwarding, rules) for a caller you could not verify — external forwarding on an exec mailbox is classic business-email-compromise persistence.', match: { tool: 'mail', action: 'add_delegate', target: 'dvance' }, skill: 'security', penalty: 0.6 },
    { id: 'reply_comply', label: 'Told the caller the forwarding rule was added', why: 'Complying with a relayed, unverified request to forward an executive\'s mail externally is the exact outcome the attacker wants.', match: { tool: 'ticket', action: 'reply', target: 'r_comply' }, skill: 'security', penalty: 0.6 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'I\'m not able to make that change. I couldn\'t verify the caller — a callback to Tanya\'s number on record reached the real Tanya, who did not make this request — and setting external auto-forwarding on an executive\'s mailbox is a hallmark of an account-takeover / BEC attempt. I\'ve made no changes and I\'m escalating this to our Security team as an urgent possible social-engineering attack. If Diane genuinely needs something, she can be verified directly through Security.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Verification failed, so no change was made; correctly identified BEC and escalated to Security at the right priority.' },
    { id: 'r_comply', text: 'No problem — I\'ve added the auto-forward on Diane\'s mailbox to the outside address as requested.', scores: { communication: 0.3, security: 0.02 }, feedback: 'This is the catastrophe: external forwarding on an exec mailbox for an unverified caller hands the attacker every email. Never do this.' },
    { id: 'r_pushback', text: 'I can\'t do that without verification — please have Diane email us from her own account first.', scores: { communication: 0.6, security: 0.6, process: 0.4 }, feedback: 'Right instinct to refuse, but it stops there: this is a likely attack that Security must see. Escalate it rather than just deflecting.' },
    { id: 'r_hangup', text: 'That sounds like a scam — I told them no and hung up.', scores: { communication: 0.4, security: 0.5, process: 0.2 }, feedback: 'Correct to refuse, but an attempted attack on an executive mailbox needs to be reported to Security, not just dismissed.' },
  ],
  notesRubric: [
    { label: 'verification failed (callback reached the real assistant)', pattern: /verif|callback|real tanya|could ?n.t verify|failed verification|not verified/i },
    { label: 'the red flag (external forwarding on an exec mailbox / BEC)', pattern: /forward|external|exec|bec|business email|social eng|takeover/i },
    { label: 'made no changes and escalated to Security', pattern: /no change|made no|escalat|security|soc/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'soc', category: 'Security - Social Engineering', resolutionCode: 'Escalated to SOC (vishing / BEC attempt), no changes made' },
  categoryAccept: ['security', 'social engineering', 'social-engineering', 'vishing'],
  resolutionCodeAccept: ['escalat', 'soc', 'security', 'social', 'vishing', 'bec'],
  hints: [
    'Run verification first (KB-0001). What happens when you call the assistant\'s number on record?',
    'The request itself is a red flag: external auto-forwarding on an executive mailbox (KB-0020).',
    'Verification fails and the ask is dangerous — make NO changes to the mailbox.',
    'Escalate to Security (SOC) at P2. Refusing is necessary but not sufficient; report it.',
  ],
  debrief: 'This is vishing in service of business-email-compromise. Two independent red flags fire: the caller cannot be verified (a callback to the number on record reaches the real assistant, who made no request), and the request itself — external auto-forwarding on the CEO\'s mailbox — is the classic way an attacker siphons an executive\'s mail. The Tier 1 job is to make zero changes and escalate to Security at P2. Simply saying "no" and hanging up is better than complying, but it leaves Security blind to an active attempt against an executive. Urgency is the pressure lever; it never substitutes for verification.',
};

// ---------------------------------------------------------------------------
// SD1-18  Teams mic not working (im) - audio device disabled in Device Manager
// ---------------------------------------------------------------------------
const sd1_18: Scenario = {
  id: 'sd1-18',
  tier: 'sd1',
  title: 'My mic doesn\'t work in Teams',
  category: 'Hardware',
  difficulty: 1,
  estMinutes: 6,
  objective: 'Diagnose a "mic not working" report to the real cause in Device Manager (a disabled audio device) and fix it, rather than blaming the app or jumping to a reimage.',
  intake: {
    kind: 'ticket', number: 'INC457718', subject: 'No one can hear me on Teams calls - mic not working',
    body: `IM from Owen Bennett (Design Engineer): "My microphone stopped working in Teams — people say they can't hear me, and my mic doesn't even show up in Teams settings anymore. Speakers are fine, I can hear everyone. Started this morning. I have a design review at 2."`,
    requester: 'obennett', channel: 'im', priority: 'P3', category: 'Hardware', openedAt: ago(15), affectedHost: 'DEN-WS-2011',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const h = host(w, 'DEN-WS-2011');
    const audio = h.devices.find((d) => d.class === 'Sound, video and game controllers');
    if (audio) { audio.status = 'disabled'; audio.error = 'Device disabled. (Code 22) The audio endpoint is turned off in Device Manager.'; }
    // Red herring: a benign DCOM warning, unrelated to audio.
    addEvent(h, { id: 10016, level: 'Warning', source: 'DistributedCOM', log: 'System', message: 'The application-specific permission settings do not grant Local Activation permission for the COM Server application. (Benign, common.)', time: ago(190) });
  },
  contactWith: 'obennett',
  contact: [
    { id: 'device', question: 'In Teams devices settings, does your microphone appear in the list at all?', answer: '"No — the mic dropdown is empty. Speakers show up fine though."', purpose: 'clarify', reveals: 'device-missing' },
    { id: 'when', question: 'Did anything change this morning — a Windows update, new headset, someone else on the PC?', answer: '"Not that I did. It just wasn\'t there when I joined my first call."', purpose: 'clarify' },
    { id: 'headset', question: 'Are you using the built-in mic or a headset/webcam mic?', answer: '"Built-in mic, no headset plugged in."', purpose: 'clarify', reveals: 'builtin' },
    { id: 'other_apps', question: 'Does the mic work in any other app, like Voice Recorder?', answer: '"No — nothing picks it up anywhere, not just Teams."', purpose: 'clarify', reveals: 'not-app-specific' },
    { id: 'lunch', question: 'Big design review — nervous?', answer: '"Ha, a little. Can we just get my mic back?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the audio/peripheral SOP (KB-0010)', match: { tool: 'kb', action: 'read', target: 'KB-0010' }, hint: 'For "no audio," what does the SOP have you check first?' },
    { id: 'devices', label: 'Opened Device Manager and found the audio device disabled', match: { tool: 'rdp', action: 'view_devices', target: 'DEN-WS-2011' }, hint: 'Remote in and check the sound device status.' },
  ],
  required: [
    { id: 'fix_audio', label: 'Re-enabled (or updated the driver for) the audio device', match: [{ tool: 'rdp', action: 'enable_device', target: 'DEN-WS-2011', params: { device: /audio|realtek|sound/i } }, { tool: 'rdp', action: 'update_driver', target: 'DEN-WS-2011', params: { device: /audio|realtek|sound/i } }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'reinstall_teams', label: 'Uninstalled/reinstalled Teams as the fix', why: 'The mic is missing in every app, not just Teams, and Device Manager shows the audio device disabled — the app is not the problem (KB-0010). Reinstalling Teams wastes time.', match: { tool: 'rdp', action: 'uninstall', target: 'DEN-WS-2011', params: { program: /teams/i } }, skill: 'technical', penalty: 0.3 },
    { id: 'reimage', label: 'Escalated to Desktop for a reimage', why: 'A disabled audio device is a two-click Device Manager fix, not OS corruption. Escalating to a reimage is wildly disproportionate.', match: { tool: 'ticket', action: 'reply', target: 'r_reimage' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Found it — your audio input device was disabled in Device Manager (that\'s why the mic doesn\'t appear in Teams or any other app). I\'ve re-enabled it and updated the driver; your mic is back and I did a quick test. You\'re all set for your 2pm review. If it drops again, let me know and I\'ll check for a bad driver update.', scores: { communication: 1, technical: 1 }, feedback: 'Isolated the cause in Device Manager, fixed it centrally, and confirmed before the deadline.' },
    { id: 'r_teams', text: 'Sounds like a Teams glitch — please uninstall and reinstall Teams and try again.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'The mic is gone in every app and the device is disabled — it\'s not Teams. Reinstalling the app changes nothing.' },
    { id: 'r_reimage', text: 'I\'ll escalate this to the Desktop team to reimage your workstation.', scores: { communication: 0.3, process: 0.1 }, feedback: 'Enormously disproportionate for a disabled device. Re-enable it in Device Manager.' },
  ],
  notesRubric: [
    { label: 'the cause (audio device disabled in Device Manager)', pattern: /device manager|disabled|audio device|code 22|sound (device|card)/i },
    { label: 'ruled out the app (mic missing everywhere, not just Teams)', pattern: /every app|not just teams|all apps|not app|no other app/i },
    { label: 'the action (re-enabled / updated the audio device)', pattern: /re-?enabl|enabled|updated (the )?driver|driver/i },
  ],
  closure: { disposition: 'resolve', category: 'Hardware - Audio', resolutionCode: 'Re-enabled audio device in Device Manager' },
  categoryAccept: ['hardware', 'audio', 'mic', 'sound'],
  resolutionCodeAccept: ['audio', 'device', 'enable', 'driver', 'sound'],
  hints: [
    'The tell: the mic is missing in EVERY app, not just Teams — so it\'s not a Teams problem.',
    'KB-0010: for no audio, check the device status in Device Manager first.',
    'Remote in and look at the sound device — it\'s disabled. Re-enable it (and update the driver).',
    'Do not reinstall Teams and do not escalate to a reimage.',
  ],
  debrief: 'The discriminator is scope: the mic is gone in every application, which points below the app to the device layer. Device Manager shows the audio input disabled, and re-enabling it is a two-click fix. The traps are both forms of not-looking: blaming Teams and reinstalling it, or escalating a trivial device toggle to a full reimage. Always confirm whether a peripheral fault is app-specific before you touch the app.',
};

// ---------------------------------------------------------------------------
// SD1-19  OneDrive files 'missing' after sync paused (chat) - not data loss
// ---------------------------------------------------------------------------
const sd1_19: Scenario = {
  id: 'sd1-19',
  tier: 'sd1',
  title: 'All my files disappeared from OneDrive',
  category: 'Endpoint',
  difficulty: 2,
  estMinutes: 7,
  objective: 'Calm a "my files are gone" panic by diagnosing a paused OneDrive sync (not data loss), resuming it, and pointing to version history — without escalating a backup restore or reimaging.',
  intake: {
    kind: 'ticket', number: 'INC457719', subject: 'URGENT all my documents are gone!!',
    body: `Chat from Jordan Webb (Marketing): "I opened my laptop this morning and my Documents folder is basically empty — a bunch of campaign files are just GONE. I didn't delete anything! The little OneDrive cloud icon has a pause symbol on it. Please tell me my work isn't lost."`,
    requester: 'jwebb', channel: 'chat', priority: 'P1', category: 'Software', openedAt: ago(10), affectedHost: 'DEN-LT-1070',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const h = host(w, 'DEN-LT-1070');
    h.notes = 'OneDrive sync paused; local Known Folder view looks empty though files are intact in the cloud.';
    // OneDrive process is running but paused (not the cause of loss); files are intact.
    h.files = [
      { path: 'C:\\Users\\jwebb\\OneDrive\\Documents\\ (sync paused - files intact in cloud)', size: 4200, modified: ago(20) },
      { path: 'C:\\Users\\jwebb\\OneDrive\\Documents\\Q3-campaign-brief.docx', size: 3, modified: daysAgo(2) },
      { path: 'C:\\Users\\jwebb\\OneDrive\\Documents\\social-calendar.xlsx', size: 2, modified: daysAgo(1) },
    ];
    addEvent(h, { id: 6013, level: 'Information', source: 'OneDrive', log: 'Application', message: 'OneDrive syncing paused (user selected "Pause syncing"). Files remain available online.', time: ago(30) });
    // Red herring: a benign disk-space info event that has nothing to do with the "missing" files.
    addEvent(h, { id: 10016, level: 'Warning', source: 'DistributedCOM', log: 'System', message: 'Local Activation permission warning for a COM server. (Benign, common.)', time: ago(200) });
  },
  contactWith: 'jwebb',
  contact: [
    { id: 'icon', question: 'You mentioned the OneDrive icon has a pause symbol — does it say "Paused" when you hover it?', answer: '"Yes! It says \'Syncing paused.\' I don\'t remember pausing it."', purpose: 'clarify', reveals: 'sync-paused' },
    { id: 'deleted', question: 'Did you (or anyone) delete or move the files, or empty the Recycle Bin?', answer: '"No, I didn\'t touch them. They were just gone this morning."', purpose: 'clarify', reveals: 'not-deleted' },
    { id: 'online', question: 'Can you open OneDrive in a browser (office.com) and see if the files are there online?', answer: '"...Oh. Yeah, they\'re ALL there in the browser. So they\'re not gone?"', purpose: 'clarify', reveals: 'intact-in-cloud' },
    { id: 'when', question: 'When did you last see them locally, and did the laptop update overnight?', answer: '"Yesterday afternoon they were fine. It might\'ve rebooted for an update overnight."', purpose: 'clarify' },
    { id: 'weekend', question: 'Any fun plans this weekend?', answer: '"Not until I know my files are safe — can we focus?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the file-access / restore SOP (KB-0009)', match: { tool: 'kb', action: 'read', target: 'KB-0009' }, hint: 'Before assuming data loss, what should you confirm about where the files actually are?' },
    { id: 'files', label: 'Checked the machine and confirmed the OneDrive files are intact (sync paused)', match: [{ tool: 'rdp', action: 'view_files', target: 'DEN-LT-1070' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1070' }], hint: 'Are the files actually gone, or just not synced down locally?' },
  ],
  required: [
    { id: 'resolve', label: 'Resolved by resuming sync and confirming the files are intact', match: { tool: 'ticket', action: 'submit' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'restore_backup', label: 'Escalated to Sysadmin for a server backup restore', why: 'The files are not lost — they are intact in OneDrive; sync was just paused. Escalating a restore treats a non-event as data loss (KB-0009).', match: { tool: 'ticket', action: 'reply', target: 'r_restore' }, skill: 'process', penalty: 0.3 },
    { id: 'reimage', label: 'Reimaged / reset the laptop in a panic', why: 'Reimaging a machine whose files are safe in the cloud is both unnecessary and risky. Resume sync instead.', match: { tool: 'ticket', action: 'reply', target: 'r_reimage' }, skill: 'technical', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Good news — your files are safe. Nothing was deleted; OneDrive sync was just paused, so your local Documents folder looked empty while everything sat intact in the cloud (you saw them all in the browser). I\'ve resumed syncing and they\'re coming back down now. If you ever need an earlier copy of a file, right-click it and use "Version history." Nothing was lost.', scores: { communication: 1, technical: 1 }, feedback: 'Diagnosed a paused sync, reassured the user with the browser check, resumed it, and taught version history.' },
    { id: 'r_restore', text: 'That\'s data loss — I\'m escalating to the Sysadmin team to restore your files from last night\'s backup.', scores: { communication: 0.3, process: 0.1 }, feedback: 'The files aren\'t lost; they\'re in OneDrive with sync paused. A backup restore is the wrong tool for a non-event.' },
    { id: 'r_reimage', text: 'Sounds like your profile is corrupted — let\'s reimage the laptop to fix it.', scores: { communication: 0.2, technical: 0.1 }, feedback: 'Reimaging a machine whose data is safe in the cloud is drastic and pointless. Resume sync.' },
  ],
  notesRubric: [
    { label: 'the cause (OneDrive sync paused, not deleted)', pattern: /onedrive|sync (paused|was paused)|paused|not deleted|not lost/i },
    { label: 'confirmed files intact in the cloud', pattern: /cloud|online|browser|office\.com|intact|still there|safe/i },
    { label: 'the fix (resumed sync; version history offered)', pattern: /resum|version history|re-?sync|restore point|reconnect/i },
    { label: 'did not treat it as data loss / no backup restore', pattern: /no(t)? data loss|no backup restore|no reimage|not lost/i },
  ],
  closure: { disposition: 'resolve', category: 'Endpoint - OneDrive Sync', resolutionCode: 'Resumed OneDrive sync (files intact, not lost)' },
  categoryAccept: ['endpoint', 'onedrive', 'sync', 'onedrive sync'],
  resolutionCodeAccept: ['onedrive', 'sync', 'resum', 'version history', 'restore'],
  hints: [
    'Before assuming the worst, confirm WHERE the files are: check OneDrive online in a browser.',
    'The OneDrive icon says "Paused" — the files are intact in the cloud, just not synced locally.',
    'Resume syncing; the files come back down. Show the user "Version history" for peace of mind.',
    'Do NOT escalate a backup restore and do NOT reimage — nothing was lost.',
  ],
  debrief: 'A "my files are gone" panic is usually a sync problem, not data loss. Here OneDrive sync was paused (often after an overnight update), so the local Known Folder looked empty while every file sat safely in the cloud — confirmed the instant the user checked OneDrive in a browser. The fix is to resume sync and, for reassurance, point out version history. The traps are the panicked over-reactions: escalating a Sysadmin backup restore or reimaging a laptop whose data was never at risk. Verify the location of the data before you treat anything as lost.',
};

// ---------------------------------------------------------------------------
// SD1-20  Password expired, remote user (sms) - reset + cached-cred/VPN guidance
// ---------------------------------------------------------------------------
const sd1_20: Scenario = {
  id: 'sd1-20',
  tier: 'sd1',
  title: 'Password expired and I\'m locked out remotely',
  category: 'Identity',
  difficulty: 2,
  estMinutes: 8,
  objective: 'Reset an expired password for a remote worker AND give the cached-credential / VPN steps they need to actually get back in — the part that turns a "reset" into a real fix.',
  intake: {
    kind: 'ticket', number: 'INC457720', subject: 'PW expired, can\'t log in from home, VPN won\'t connect',
    body: `SMS to the help line: "Hi it's Hana Sato, remote in Seattle. My password expired and now I can't log in to my laptop and the VPN won't connect either. Can you help me reset it? Really need to get online for a client call."`,
    requester: 'hsato', channel: 'sms', priority: 'P2', category: 'Access', openedAt: ago(9), affectedHost: 'DEN-LT-1062',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const u = findUser(w, 'hsato')!;
    u.passwordExpired = true;
    u.passwordLastSet = daysAgo(95);
    // Failures are benign: her own home IP in Seattle, just an expired password.
    u.recentSignIns = [
      { time: ago(12), ip: '67.160.8.51', location: 'Seattle, US', app: 'Windows Sign-in', result: 'failure', reason: 'password expired', device: 'DEN-LT-1062' },
      { time: ago(20), ip: '67.160.8.51', location: 'Seattle, US', app: 'Kestrel VPN', result: 'failure', reason: 'password expired', device: 'DEN-LT-1062' },
      { time: daysAgo(2), ip: '67.160.8.51', location: 'Seattle, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1062', mfa: 'satisfied' },
    ];
  },
  contactWith: 'hsato',
  contact: [
    { id: 'empid', question: 'Can you confirm your employee ID so I can verify you?', answer: '"It\'s E10122."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll verify you with a callback to the mobile number we have on record. OK?', answer: 'You call the number on record for Hana Sato and she answers; details match. Verified.', purpose: 'verify' },
    { id: 'remote', question: 'Are you fully remote right now, and is the VPN currently connected or not?', answer: '"Fully remote in Seattle. The VPN won\'t connect at all since the password expired."', purpose: 'clarify', reveals: 'cached-cred' },
    { id: 'device', question: 'Is this your Kestrel laptop (DEN-LT-1062)?', answer: '"Yes, my work laptop."', purpose: 'clarify' },
    { id: 'text_pw', question: 'Want me to just text you the new password so it\'s quick?', answer: '"—" (KB-0001: never send credentials by text/SMS or email. Give a temp password by phone only.)', purpose: 'red_flag' },
    { id: 'weather', question: 'Raining in Seattle as usual?', answer: '"Always. Can we fix the login?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb2', label: 'Read the password-reset SOP (KB-0002)', match: { tool: 'kb', action: 'read', target: 'KB-0002' } },
    { id: 'kb11', label: 'Read the VPN / cached-credentials SOP (KB-0011)', match: { tool: 'kb', action: 'read', target: 'KB-0011' }, hint: 'After a reset, why can\'t a remote laptop log in with the new password right away?' },
    { id: 'signins', label: 'Reviewed sign-ins (expired-password failures from her own home IP, not an attack)', match: { tool: 'directory', action: 'view_signins', target: 'hsato' }, hint: 'Are the failures from her own device/IP, or somewhere strange?' },
  ],
  required: [
    { id: 'reset', label: 'Reset the password with "must change at next logon"', match: { tool: 'directory', action: 'reset_password', target: 'hsato', params: { mustChange: 'true' } }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'reset_no_verify', label: 'Reset the password before verifying identity', why: 'Identity must be verified with two factors before any account change (KB-0001).', match: { tool: 'directory', action: 'reset_password', target: 'hsato' }, unlessAfter: 'verify_gate', skill: 'security', penalty: 0.5 },
    { id: 'text_pw', label: 'Sent the new password by SMS/text', why: 'KB-0001: never send credentials by text, SMS, or email. Give a temporary password by phone only.', match: { tool: 'ticket', action: 'reply', target: 'r_text' }, skill: 'security', penalty: 0.5 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Verified you by employee ID and a callback. I\'ve reset your password (you\'ll set your own at first logon) and I\'ll read the temporary one to you by phone. Because you\'re remote, your laptop still has the OLD password cached, so: connect the Kestrel VPN using "Sign in as a different user" with the NEW password, then lock and unlock the laptop once — that updates the cached credential and normal login will work. Call me back if the VPN still refuses.', scores: { communication: 1, security: 1 }, feedback: 'Verified, reset with must-change, delivered the temp password safely, and gave the remote/VPN cached-credential steps that actually get her back in.' },
    { id: 'r_text', text: 'Verified — I\'ll text you the new password now so you can get on your call.', scores: { communication: 0.4, security: 0.1 }, feedback: 'Texting credentials violates KB-0001. Read a temp password by phone; never send it over SMS.' },
    { id: 'r_noguide', text: 'All done — I\'ve reset your password. Just log in with the new one.', scores: { communication: 0.5, technical: 0.3 }, feedback: 'Missing the crucial remote step: her laptop caches the old password, so "just log in" fails until she connects VPN with the new password and re-locks. Without that guidance she\'s still stuck.' },
    { id: 'r_stall', text: 'Password resets have to be done in person at the IT desk with your badge.', scores: { communication: 0.4, security: 0.5 }, feedback: 'Impossible for a remote worker and unnecessary: employee ID plus a callback to the number on record satisfies KB-0001.' },
  ],
  notesRubric: [
    { label: 'verification (two factors)', pattern: /employee id|e10122|callback|call back|verified|two factor/i },
    { label: 'the cause (expired password, benign — her own IP)', pattern: /expired|password expiry|own (ip|device)|seattle|benign/i },
    { label: 'the action (reset, must-change at logon)', pattern: /reset|temp(orary)? password|must change|change at (next )?logon/i },
    { label: 'the remote / cached-credential / VPN guidance', pattern: /cached|vpn|sign in as|different user|lock.?unlock|reconnect/i },
  ],
  closure: { disposition: 'resolve', category: 'Identity - Password Expiry', resolutionCode: 'Password reset (must-change) + VPN cached-credential guidance' },
  categoryAccept: ['identity', 'password', 'expiry', 'password expiry'],
  resolutionCodeAccept: ['password', 'reset', 'expiry', 'vpn', 'cached'],
  hints: [
    'Verify first (KB-0001): employee ID plus a callback to the number on record.',
    'Check the sign-ins — the failures are just an expired password from her own Seattle IP, not an attack.',
    'Reset with "must change at next logon" and read the temp password by phone (never text it).',
    'Crucial for remote users (KB-0011): the laptop caches the old password — she must connect VPN with the new password and lock/unlock to update it.',
  ],
  debrief: 'A remote password reset is only half-done if you stop at the reset. Verification is routine (employee ID + callback), and the sign-in failures are plainly benign — expired password from her own home IP. The reset itself is easy; the part that actually gets her working is the cached-credential dance from KB-0011: a remote laptop still holds the old password, so she connects the VPN with "sign in as a different user" using the new password, then locks/unlocks to refresh the cached credential. The traps are texting the password (never send credentials over SMS) and doing the reset without the remote guidance, which leaves her just as locked out as before.',
};

// ---------------------------------------------------------------------------
// SD1-21  New laptop / hardware refresh (portal) - stock, assign, ship, CMDB
// ---------------------------------------------------------------------------
const sd1_21: Scenario = {
  id: 'sd1-21',
  tier: 'sd1',
  title: 'Approved laptop refresh for a remote user',
  category: 'Hardware',
  difficulty: 1,
  estMinutes: 7,
  objective: 'Fulfil a hardware refresh end to end: pull a machine from stock, assign it, ship it to the remote user with a return label, and update the asset record — without wiping the old device in the field.',
  intake: {
    kind: 'ticket', number: 'INC457721', subject: 'Approved hardware refresh - my laptop is 4 years old',
    body: `Portal ticket from Carlos Flores (Account Executive, remote Phoenix): "My laptop is about four years old, the battery is shot and it's really slow. My manager approved a refresh. I'm fully remote — how do we do this? I don't want to lose my files."`,
    requester: 'cflores', channel: 'portal', priority: 'P4', category: 'Request', openedAt: ago(120), affectedHost: 'DEN-LT-1061',
  },
  priorityExpected: 'P4',
  setup: (w) => {
    const u = findUser(w, 'cflores')!;
    u.notes = 'Manager-approved hardware refresh; fully remote (Phoenix), files in OneDrive.';
    const h = host(w, 'DEN-LT-1061');
    h.uptimeHours = 60;
    h.disk = { used: 300, size: 512 };
    // Old asset is well out of warranty; two imaged laptops are in stock (KD-05001/05002).
    const old = w.assets.find((a) => a.hostname === 'DEN-LT-1061');
    if (old) old.notes = '4 years old, battery degraded, out of warranty; eligible for refresh.';
  },
  contactWith: 'cflores',
  contact: [
    { id: 'reason', question: 'Is this the manager-approved refresh, and what\'s the main problem with the current laptop?', answer: '"Yes, Emily approved it. Battery\'s dead and it\'s slow. Nothing broken-broken."', purpose: 'clarify', reveals: 'refresh' },
    { id: 'remote', question: 'You\'re remote in Phoenix, right? We\'ll ship the new one and send a return label for the old one.', answer: '"Yep, fully remote. Shipping works great."', purpose: 'clarify', reveals: 'remote-ship' },
    { id: 'data', question: 'Are your files in OneDrive so they move over cleanly to the new machine?', answer: '"Yeah, everything\'s in OneDrive. That\'s a relief."', purpose: 'clarify', reveals: 'onedrive' },
    { id: 'timing', question: 'Any deadline, or is this a routine swap?', answer: '"No rush, whenever you can get to it."', purpose: 'clarify' },
    { id: 'color', question: 'Can I pick the color?', answer: '"Ha — I\'ll take whatever\'s standard."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the hardware-request / shipping SOP (KB-0021)', match: { tool: 'kb', action: 'read', target: 'KB-0021' }, hint: 'What must you update, and how do you handle a remote user\'s old device?' },
    { id: 'stock', label: 'Checked stock for an available laptop', match: [{ tool: 'assets', action: 'search', params: { q: /laptop|stock/i } }, { tool: 'assets', action: 'view', target: /KD-05001|KD-05002/ }], hint: 'Is there an imaged laptop in the stockroom to assign?' },
  ],
  required: [
    { id: 'assign', label: 'Assigned a stock laptop to the user', match: { tool: 'assets', action: 'assign', params: { user: 'cflores' } }, skill: 'technical' },
    { id: 'ship', label: 'Shipped the new laptop to the remote user', match: { tool: 'assets', action: 'ship', params: { user: 'cflores' } }, skill: 'process' },
    { id: 'cmdb', label: 'Updated the asset records (new deployed, old flagged for return)', match: { tool: 'assets', action: 'set_status' }, skill: 'documentation' },
  ],
  forbidden: [
    { id: 'wipe_old', label: 'Remotely wiped the old laptop before it was returned', why: 'KB-0021: send a prepaid return label and recover the device — do not remote-wipe a working laptop still in the user\'s hands. A field wipe risks data loss and leaves the user with a brick before the new one arrives.', match: { tool: 'assets', action: 'remote_wipe' }, skill: 'security', penalty: 0.3 },
    { id: 'come_in', label: 'Told the remote user to come to the office to swap', why: 'The user is fully remote in Phoenix. KB-0021 says ship from stock with a return label; making them travel to Denver is not a real option.', match: { tool: 'ticket', action: 'reply', target: 'r_comein' }, skill: 'process', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'All set up. I\'ve pulled an imaged laptop from stock, assigned it to you, and I\'m shipping it to your Phoenix address with a prepaid return label for the old one. I\'ve updated the asset records — the new machine as deployed to you, the old one flagged for return. Since your files are in OneDrive, just sign in on the new laptop and everything syncs down; once you\'ve confirmed it\'s all there, box up the old one with the label. Nothing to lose.', scores: { communication: 1, technical: 1, process: 1 }, feedback: 'Pulled from stock, assigned, shipped with a return label, and updated the CMDB — the full refresh workflow.' },
    { id: 'r_comein', text: 'Just stop by the Denver IT desk and we\'ll swap it out for you in five minutes.', scores: { communication: 0.3, process: 0.1 }, feedback: 'He\'s fully remote in Phoenix. Ship from stock with a return label; don\'t make him fly in.' },
    { id: 'r_nocmdb', text: 'I\'ll ship you a new laptop from stock. Done.', scores: { communication: 0.5, documentation: 0.3 }, feedback: 'Ships the machine but skips updating the asset records and recovering the old device — the CMDB will be wrong and a laptop goes unaccounted for.' },
  ],
  notesRubric: [
    { label: 'the request (manager-approved refresh, remote user)', pattern: /refresh|approved|manager|emily|remote|phoenix/i },
    { label: 'pulled from stock and assigned', pattern: /stock|assign|kd-050|imaged|pulled/i },
    { label: 'shipped with a return label for the old device', pattern: /ship|return label|prepaid|recover|send back/i },
    { label: 'updated the asset / CMDB records', pattern: /asset|cmdb|record|status|retired|deployed/i },
  ],
  closure: { disposition: 'resolve', category: 'Hardware - Refresh', resolutionCode: 'Assigned + shipped stock laptop; asset records updated' },
  categoryAccept: ['hardware', 'refresh', 'asset', 'laptop'],
  resolutionCodeAccept: ['refresh', 'asset', 'ship', 'assign', 'stock', 'cmdb'],
  hints: [
    'KB-0021 is the workflow: assign from stock, update the asset record, and handle the old device.',
    'There are imaged laptops in the stockroom (KD-05001 / KD-05002) — assign one to Carlos.',
    'He\'s remote, so ship it with a prepaid return label for the old laptop; his OneDrive files follow him.',
    'Update both asset records. Do NOT remote-wipe the old laptop while it\'s still in the field.',
  ],
  debrief: 'A hardware refresh is a small workflow that people routinely leave half-finished. The full path: pull an imaged laptop from stock, assign it, ship it to the remote user with a prepaid return label, and update the CMDB (new machine deployed, old one flagged for return). OneDrive makes the data migration a non-event. The traps are telling a fully-remote user to "come to the desk," skipping the asset-record update (which leaves the CMDB wrong and a device unaccounted for), and the tempting-but-wrong instinct to remote-wipe the old laptop before it\'s back — that risks data loss and bricks the user mid-transition. Recover the device, then retire it.',
};

// ---------------------------------------------------------------------------
// SD1-22  Printer faded / toner low (email) - Facilities, not a driver issue
// ---------------------------------------------------------------------------
const sd1_22: Scenario = {
  id: 'sd1-22',
  tier: 'sd1',
  title: 'Printouts are faded and streaky',
  category: 'Printers',
  difficulty: 1,
  estMinutes: 6,
  objective: 'Recognize a consumables (toner) problem versus a driver or queue fault, and route it to Facilities — who stock and swap toner — instead of chasing a software fix.',
  intake: {
    kind: 'ticket', number: 'INC457722', subject: 'Finance printer prints faded/streaky - please fix the driver',
    body: `Email from Bhavik Patel (Senior Accountant): "The Finance printer on 3F is printing really faded and streaky on every page. The panel is showing a 'Toner Low - Black' message. Someone said it might be a driver problem — can you reinstall the driver? We've got month-end packets to print."`,
    requester: 'bpatel', channel: 'email', priority: 'P3', category: 'Hardware', openedAt: ago(25), affectedHost: 'DEN-LT-1042',
  },
  priorityExpected: 'P4',
  setup: (w) => {
    // The print queue is healthy - this is NOT a queue or driver problem.
    const ps = w.servers.find((s) => s.id === 'DEN-PRINT01')!;
    const q = ps.printQueues!.find((p) => p.name === 'DEN-PRN-Finance')!;
    q.status = 'ready'; q.jobs = 0;
    // Red herring: an unrelated benign spooler firmware-sync note on another printer.
    ps.events.push({ id: 372, time: ago(150), level: 'Warning', source: 'PrintService', log: 'System', message: 'DEN-PRN-2F-Copier paused 2 min for a routine firmware sync (auto-resumed).' });
    const printer = w.assets.find((a) => a.hostname === 'DEN-PRN-Finance');
    if (printer) printer.notes = 'Panel reports Toner Low - Black; consumable, not a fault. Facilities stocks toner.';
  },
  contactWith: 'bpatel',
  contact: [
    { id: 'symptom', question: 'Is every page faded/streaky, and what exactly does the printer panel say?', answer: '"Every page. The panel says \'Toner Low - Black.\' Otherwise it prints fine, just light."', purpose: 'clarify', reveals: 'toner-low' },
    { id: 'scope', question: 'Is it faded for everyone on that printer or just your prints?', answer: '"Everyone on the Finance printer — it\'s the printer, not my PC."', purpose: 'clarify', reveals: 'shared-consumable' },
    { id: 'errors', question: 'Does it print at all / any errors or stuck jobs in the queue?', answer: '"It prints, nothing\'s stuck, no error other than the toner message."', purpose: 'clarify', reveals: 'queue-ok' },
    { id: 'model', question: 'Which printer is it — the 3F Finance HP?', answer: '"Yeah, the HP LaserJet by Finance."', purpose: 'clarify' },
    { id: 'weather', question: 'How\'s month-end going otherwise?', answer: '"Stressful — hence needing this printer. Can you sort the toner?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the printer SOP (KB-0008)', match: { tool: 'kb', action: 'read', target: 'KB-0008' }, hint: 'Who handles toner, and is this a queue/driver problem at all?' },
    { id: 'queue', label: 'Confirmed the print queue is healthy (rules out a queue/driver fault)', match: { tool: 'server', action: 'view_print_queues', target: 'DEN-PRINT01' }, hint: 'Is the Finance queue ready with no stuck jobs?' },
  ],
  required: [
    { id: 'facilities', label: 'Logged the toner replacement to Facilities', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'driver', label: 'Reinstalled / updated the printer driver as the fix', why: 'Faded print with a "Toner Low" panel message is a consumable, not a driver problem (KB-0008). Touching the driver wastes time and fixes nothing.', match: [{ tool: 'rdp', action: 'update_driver', target: 'DEN-LT-1042', params: { device: /print/i } }, { tool: 'ticket', action: 'reply', target: 'r_driver' }], skill: 'technical', penalty: 0.3 },
    { id: 'queue', label: 'Cleared/paused the (healthy) print queue', why: 'The queue is ready with no stuck jobs — clearing or pausing it does nothing for low toner and can disrupt other prints (KB-0008).', match: [{ tool: 'server', action: 'clear_queue', target: 'DEN-PRINT01', params: { queue: /finance/i } }, { tool: 'server', action: 'pause_queue', target: 'DEN-PRINT01', params: { queue: /finance/i } }], skill: 'technical', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This is low toner, not a driver or queue problem — the panel\'s "Toner Low - Black" message and the faded output on every page are the giveaway, and the print queue is healthy. I\'ve logged it to Facilities, who stock and swap the toner cartridges; they\'ll replace the black toner on the 3F Finance HP. As a stopgap for your month-end packets, gently removing and rocking the cartridge side to side can eke out a few more pages until they swap it.', scores: { communication: 1, technical: 1, process: 1 }, feedback: 'Correctly identified a consumable, ruled out queue/driver, routed to Facilities, and gave a practical stopgap.' },
    { id: 'r_driver', text: 'Sounds like a driver issue — I\'ll remote in and reinstall the printer driver for you.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'A "Toner Low" panel message and faded pages are a consumable problem. The driver is fine; reinstalling it changes nothing.' },
    { id: 'r_network', text: 'I\'ll escalate this to the Network team to look at the print server.', scores: { communication: 0.3, process: 0.2 }, feedback: 'The queue and server are healthy. This is a toner swap for Facilities, not a network or server issue.' },
  ],
  notesRubric: [
    { label: 'the cause (low/empty toner - consumable)', pattern: /toner|consumable|cartridge|faded|streak/i },
    { label: 'ruled out driver and queue', pattern: /not (a )?driver|queue.*(ok|healthy|ready)|not (a )?queue|no stuck/i },
    { label: 'routed to Facilities (who stock toner)', pattern: /facilities|stock toner|toner (swap|replace)|log(ged)? to facilities/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'facilities', category: 'Printers - Consumables', resolutionCode: 'Logged to Facilities for toner replacement' },
  categoryAccept: ['printer', 'print', 'consumable', 'toner'],
  resolutionCodeAccept: ['toner', 'facilities', 'consumable', 'print'],
  hints: [
    'Read the symptom literally: faded/streaky pages plus a "Toner Low" panel message.',
    'KB-0008: toner is a consumable that Facilities stocks and swaps — it is not a driver or queue fault.',
    'Confirm the queue is healthy so you can rule out a software/queue cause.',
    'Log it to Facilities. Do not reinstall the driver or touch the print queue.',
  ],
  debrief: 'The requester pre-diagnosed a "driver problem," and the trap is to just do what they asked. But faded, streaky output with a "Toner Low - Black" panel message is a textbook consumable issue: the queue is healthy, the driver is fine, and no amount of reinstalling fixes an empty cartridge. Per KB-0008, toner is stocked and swapped by Facilities, so you route it there and offer the rock-the-cartridge stopgap for the month-end crunch. Reinstalling the driver or clearing a healthy queue are both motion without progress.',
};

// ---------------------------------------------------------------------------
// SD1-23  Lockout that IS an attack (phone) - foreign IP failures -> SOC
// ---------------------------------------------------------------------------
const sd1_23: Scenario = {
  id: 'sd1-23',
  tier: 'sd1',
  title: 'Locked out — but the failures come from abroad',
  category: 'Security',
  difficulty: 3,
  estMinutes: 8,
  objective: 'Distinguish a routine lockout from a lockout that is actually an attack: when the failed sign-ins come from an unknown foreign IP, do NOT just unlock — escalate to Security.',
  intake: {
    kind: 'ticket', number: 'INC457723', subject: 'Locked out again - please just unlock me, I have a client call',
    body: `Phone call: "Hi, this is Emily Wright, Sales Director. I'm locked out of my account — second time today. I haven't even been typing my password wrong. Can you just unlock me quickly? I've got a client call in ten minutes."`,
    requester: 'ewright', channel: 'phone', priority: 'P2', category: 'Access', openedAt: ago(6),
  },
  priorityExpected: 'P2',
  setup: (w) => {
    lockOut(w, 'ewright', 12);
    const u = findUser(w, 'ewright')!;
    // Failures are from an unknown foreign IP - NOT her device. One earlier success from her real Denver IP.
    u.recentSignIns = [
      { time: ago(5), ip: '45.133.216.71', location: 'Bucharest, RO', app: 'WorkSuite Mail', result: 'failure', reason: 'wrong password', device: 'unknown' },
      { time: ago(7), ip: '45.133.216.71', location: 'Bucharest, RO', app: 'WorkSuite Mail', result: 'failure', reason: 'wrong password', device: 'unknown' },
      { time: ago(9), ip: '45.133.216.71', location: 'Bucharest, RO', app: 'WorkSuite Mail', result: 'failure', reason: 'wrong password', device: 'unknown' },
      { time: ago(11), ip: '45.133.216.71', location: 'Bucharest, RO', app: 'WorkSuite Mail', result: 'failure', reason: 'wrong password', device: 'unknown' },
      { time: ago(200), ip: '10.10.20.60', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1060', mfa: 'satisfied' },
    ];
    w.intel.push({ indicator: '45.133.216.71', type: 'ip', verdict: 'malicious', source: 'AbuseIPDB + internal', tags: ['brute-force', 'credential-stuffing', 'hosting'], detail: 'Hosting/VPS IP in Bucharest, RO, reported for credential-stuffing against O365/WorkSuite tenants. No Kestrel user is based there.' });
  },
  contactWith: 'ewright',
  contact: [
    { id: 'empid', question: 'Can you confirm your employee ID for verification?', answer: '"E10120."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll call you back on the number on record to verify. That OK?', answer: 'You call the number on record for Emily Wright; she answers at her desk in Denver. Verified — and she confirms she is here, not travelling.', purpose: 'verify' },
    { id: 'where', question: 'Are you the one entering the password, and do you have work mail saved on a phone?', answer: '"No — that\'s the weird part. I haven\'t typed my password wrong once. Nothing new on my phone."', purpose: 'clarify', reveals: 'not-self-inflicted' },
    { id: 'travel', question: 'Have you signed in from outside the US recently, or is anyone else using your account?', answer: '"No, I\'ve been in Denver all week. Nobody else has my login."', purpose: 'clarify', reveals: 'foreign-is-attacker' },
    { id: 'just_unlock', question: 'Sure, I\'ll just unlock you so you can make your call, right?', answer: '"—" (STOP. The failures are from an unknown foreign IP — unlocking now just hands the account back to the attacker. Escalate to Security instead, per KB-0002.)', purpose: 'red_flag' },
    { id: 'client', question: 'Who\'s the client call with?', answer: '"Does that matter? Please, the clock\'s ticking." (Irrelevant to the security decision.)', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb2', label: 'Read the lockout SOP (KB-0002)', match: { tool: 'kb', action: 'read', target: 'KB-0002' }, hint: 'What does the SOP say when failures come from an IP that is not the user\'s device?' },
    { id: 'signins', label: 'Reviewed the sign-ins and saw failures from a foreign IP (not her device)', match: { tool: 'directory', action: 'view_signins', target: 'ewright' }, hint: 'Where are the failed attempts coming from — her laptop, or a strange IP?' },
    { id: 'intel', label: 'Looked up the source IP in Threat Intel (malicious / credential-stuffing)', match: { tool: 'intel', action: 'lookup', target: '45.133.216.71' }, hint: 'What does Threat Intel say about that IP?' },
  ],
  required: [
    { id: 'escalate', label: 'Escalated to Security (SOC) as a suspicious lockout', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
    { id: 'priority', label: 'Set the priority to P2 (possible security incident)', match: { tool: 'ticket', action: 'set_priority', params: { priority: 'P2' } }, skill: 'security' },
  ],
  forbidden: [
    { id: 'unlock', label: 'Just unlocked the account', why: 'KB-0002: when the failures come from an IP that is not the user\'s device (here a foreign credential-stuffing IP), do NOT just unlock — that hands the account straight back to the attacker to keep trying. Escalate to Security.', match: { tool: 'directory', action: 'unlock', target: 'ewright' }, skill: 'security', penalty: 0.5 },
    { id: 'reset', label: 'Reset the password at Tier 1', why: 'Resetting at the desk on a suspected active attack is SOC\'s call — they need the sign-in evidence and may need to revoke sessions / disable first. Don\'t pre-empt them.', match: { tool: 'directory', action: 'reset_password', target: 'ewright' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'I verified you, and I need to hold off on unlocking — here\'s why: your lockout is being caused by repeated failed logins from an IP in Bucharest, Romania that isn\'t you or your device, and Threat Intel flags it for credential-stuffing. If I just unlock you now, the attacker keeps hammering it. I\'m escalating this to our Security team as an urgent P2 with the sign-in evidence; please don\'t try to log in until they clear you. I\'ll flag your client call so Security prioritizes it.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Recognized an attack (not a routine lockout), refused the unlock, and escalated to Security at the right priority with evidence.' },
    { id: 'r_unlock', text: 'No problem — I\'ve unlocked you, you\'re good for your call.', scores: { communication: 0.4, security: 0.02 }, feedback: 'This is the trap: the failures are from a foreign attacker, so unlocking just reopens the account for them. Escalate, don\'t unlock.' },
    { id: 'r_reset', text: 'I\'ll reset your password so the attacker\'s guesses stop working, then you\'re set.', scores: { communication: 0.4, security: 0.2 }, feedback: 'Better instinct, but on a suspected active attack the reset/revoke is SOC\'s call — they need the evidence and may disable first. Escalate.' },
    { id: 'r_dismiss', text: 'Weird — I unlocked it and told her to change her password when she gets a chance.', scores: { communication: 0.3, security: 0.1 }, feedback: 'Unlocks into an active attack and leaves remediation to "whenever." This needs Security now.' },
  ],
  notesRubric: [
    { label: 'the evidence (failures from an unknown foreign IP)', pattern: /foreign|bucharest|romania|45\.133|external ip|unknown ip|not (her|the user'?s) (device|ip)/i },
    { label: 'threat intel / attack judgment (credential-stuffing / brute force)', pattern: /credential.?stuff|brute|malicious|threat intel|attack|compromis/i },
    { label: 'did NOT unlock; escalated to Security', pattern: /did not unlock|no(t)? unlock|escalat|security|soc/i },
    { label: 'verified the caller', pattern: /verif|employee id|e10120|callback/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'soc', category: 'Security - Suspicious Lockout', resolutionCode: 'Escalated to SOC (lockout from foreign IP); account not unlocked' },
  categoryAccept: ['security', 'suspicious lockout', 'lockout', 'suspicious'],
  resolutionCodeAccept: ['escalat', 'soc', 'security', 'lockout', 'suspicious'],
  hints: [
    'This looks like SD1-01, but check the sign-in log before you unlock anything.',
    'The failures come from a foreign IP that is not her device — KB-0002 says that is a possible attack.',
    'Look the IP up in Threat Intel: it\'s a known credential-stuffing source.',
    'Do NOT unlock (or reset) — escalate to Security as P2 with the evidence.',
  ],
  debrief: 'This is the deliberate mirror of the routine lockout (SD1-01). The caller is genuine and verifies fine, and the urgency is real — but the sign-in log shows the failures coming from a foreign hosting IP flagged for credential-stuffing, not from her own laptop. That flips the correct answer: unlocking now simply hands the account back to the attacker to keep guessing. Tier 1\'s job is to recognize the pattern, refuse the unlock despite the pressure, and escalate to Security at P2 with the evidence (the foreign IP, the intel verdict, the confirmation she isn\'t travelling). The password reset is also SOC\'s call here, because they need the evidence intact and may disable/revoke first.',
};

// ---------------------------------------------------------------------------
// SD1-24  Contractor/guest account expiry extension (email) - sponsor approval
// ---------------------------------------------------------------------------
const sd1_24: Scenario = {
  id: 'sd1-24',
  tier: 'sd1',
  title: 'Extend my contractor account before it expires',
  category: 'Identity',
  difficulty: 2,
  estMinutes: 6,
  objective: 'Handle a contractor account-extension request: contractor accounts are time-boxed and require the sponsoring manager\'s approval, so route it — don\'t extend it (or remove its expiry) on the contractor\'s own say-so.',
  intake: {
    kind: 'ticket', number: 'INC457724', subject: 'My contractor account expires this week - please extend it',
    body: `Email from Alex Baxter (Contractor - ERP Consultant): "My account is set to expire in a few days, but the ERP go-live slipped so I'll be on the project a while longer. Can you extend my account? Maybe just set it to not expire so we don't have to keep doing this every month."`,
    requester: 'abaxter', channel: 'email', priority: 'P3', category: 'Request', openedAt: ago(40),
  },
  priorityExpected: 'P4',
  setup: (w) => {
    const u = findUser(w, 'abaxter')!;
    u.termDate = ago(-4 * 24 * 60); // expires in ~4 days
    u.notes = 'Contractor (ERP), sponsored by Linda Chen (IT). Account time-boxed; extension needs sponsor approval.';
  },
  contactWith: 'abaxter',
  contact: [
    { id: 'sponsor', question: 'Has your sponsoring manager approved the extension?', answer: '"Not formally — I figured I\'d just ask IT directly. Linda knows the project slipped though."', purpose: 'verify', reveals: 'no-sponsor-approval' },
    { id: 'enddate', question: 'What\'s the new contract end date, and is it agreed with your sponsor?', answer: '"Probably another two or three months? It\'s not nailed down yet."', purpose: 'verify', reveals: 'no-firm-date' },
    { id: 'why', question: 'What\'s the reason for the extension?', answer: '"The ERP go-live got pushed, so my engagement runs longer than planned."', purpose: 'clarify', reveals: 'business-need' },
    { id: 'access', question: 'Do you need the same access, or has your scope changed?', answer: '"Same ERP access as now, nothing new."', purpose: 'clarify' },
    { id: 'never_expire', question: 'Should I just set the account to never expire so this doesn\'t come up again?', answer: '"—" (No: contractor accounts are deliberately time-boxed. Removing the expiry defeats the control. Route it for a bounded extension instead, per KB-0006.)', purpose: 'red_flag' },
    { id: 'timezone', question: 'What timezone are you working from these days?', answer: '"Central. Does that matter for the extension?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the access-approval SOP (KB-0006)', match: { tool: 'kb', action: 'read', target: 'KB-0006' }, hint: 'Who approves access/extensions for restricted contractor accounts?' },
    { id: 'view', label: 'Opened the contractor account and saw its expiry / restricted status', match: { tool: 'directory', action: 'view', target: 'abaxter' }, hint: 'Is this a time-boxed contractor account?' },
  ],
  required: [
    { id: 'route', label: 'Routed the extension for the sponsoring manager\'s approval', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'never_expire', label: 'Set the account to never expire', why: 'Contractor accounts are deliberately time-boxed. KB-0006: removing the expiry defeats the control and is never granted on the contractor\'s own request. A bounded extension needs the sponsor\'s approval.', match: { tool: 'directory', action: 'set_password_never_expires', target: 'abaxter', params: { value: 'true' } }, skill: 'security', penalty: 0.5 },
    { id: 'reply_extend', label: 'Told the contractor the account was extended', why: 'Extending (or promising to extend) a restricted account without the sponsor\'s sign-off is an unapproved access grant. Route it first.', match: { tool: 'ticket', action: 'reply', target: 'r_extend' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Happy to get this moving. Contractor accounts are time-boxed on purpose, so I can\'t extend it on request — it needs your sponsoring manager (Linda Chen) to approve the extension with a firm new end date. I\'ve routed it to Linda for sign-off with your reason (the ERP go-live slipping); once she confirms the new date, I\'ll set the account to expire then. I won\'t set it to never-expire — the time limit is a security control we keep in place.', scores: { communication: 1, process: 1, security: 1 }, feedback: 'Routes the legitimate request to the sponsor for a bounded extension and correctly refuses the never-expire shortcut.' },
    { id: 'r_extend', text: 'No problem — I\'ve extended your account and set it not to expire so we don\'t have to keep doing this.', scores: { communication: 0.4, security: 0.1, process: 0.1 }, feedback: 'Removing the expiry on a contractor account, on the contractor\'s own say-so, defeats the control and is exactly what KB-0006 forbids.' },
    { id: 'r_refuse', text: 'Contractor accounts can\'t be extended — you\'ll have to reapply as a new contractor.', scores: { communication: 0.3, process: 0.3 }, feedback: 'Unhelpful and wrong: extensions are normal with sponsor approval. Route it rather than forcing a needless re-onboarding.' },
  ],
  notesRubric: [
    { label: 'the request (contractor account extension, expiring)', pattern: /contractor|guest|expir|extension|extend|time-?box/i },
    { label: 'the business reason', pattern: /erp|go-live|project|slipp|engagement|reason/i },
    { label: 'sponsor / manager approval required; routed', pattern: /sponsor|linda|chen|manager|approval|routed|route|pending/i },
    { label: 'did not set never-expire / not granted on say-so', pattern: /not (set )?never.?expir|time-?box|bounded|not grant|kept.*expir/i },
  ],
  closure: { disposition: 'pending', category: 'Identity - Guest Access', resolutionCode: 'Routed to sponsor for approval (bounded extension, pending)' },
  categoryAccept: ['identity', 'guest access', 'guest', 'contractor', 'access'],
  resolutionCodeAccept: ['route', 'approval', 'sponsor', 'pending', 'guest', 'extend'],
  hints: [
    'KB-0006: contractor/guest access is restricted and approvals come from the sponsoring manager.',
    'The request is reasonable (project slipped), so route it — don\'t refuse it.',
    'It needs the sponsor (Linda Chen) to approve a firm new end date; leave the ticket pending on that.',
    'Do NOT set the account to never-expire — the time limit is the control.',
  ],
  debrief: 'Contractor accounts are deliberately time-boxed so access ends when the engagement does. The extension request is legitimate, but two things are missing: the sponsoring manager\'s approval and a firm new end date. The correct move is to route it to the sponsor (Linda Chen) and hold it pending — not to extend it on the contractor\'s own email. The headline trap is the "just set it to never expire" shortcut: that quietly removes the exact control that makes a contractor account safe, and it is never granted on the contractor\'s say-so. Refusing outright is the opposite failure — the extension is routine once the sponsor signs off.',
};

export const SD1_SCENARIOS_C: Scenario[] = [
  sd1_13, sd1_14, sd1_15, sd1_16, sd1_17, sd1_18, sd1_19, sd1_20, sd1_21, sd1_22, sd1_23, sd1_24,
];
