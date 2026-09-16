import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, breakInternet, breakDns, lockOut } from './helpers';

// ---------------------------------------------------------------------------
// SD2-05  Repeated BSOD / display-driver crash loop
// ---------------------------------------------------------------------------
const sd2_05: Scenario = {
  id: 'sd2-05',
  tier: 'sd2',
  title: 'Laptop blue-screens several times a day',
  category: 'Windows',
  difficulty: 3,
  estMinutes: 12,
  objective: 'Read the event log to pin a BSOD loop on a specific driver, then fix it the light way (roll the driver back) instead of reaching for a reimage or a hardware swap.',
  intake: {
    kind: 'ticket', number: 'INC457715', subject: 'Blue screen keeps crashing my laptop',
    body: 'Escalated from SD1. Emily Wright (Sales Director) reports her laptop DEN-LT-1060 blue-screens several times a day, usually when she docks or joins a video call. It reboots on its own each time. Started a couple of days ago. She has a demo Thursday and is stressed.',
    requester: 'ewright', channel: 'phone', priority: 'P2', category: 'Hardware', openedAt: ago(35), affectedHost: 'DEN-LT-1060',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const h = host(w, 'DEN-LT-1060');
    // A recent display-driver update is crashing (VIDEO_TDR_FAILURE). Roll it back.
    const disp = h.devices.find((d) => d.class === 'Display adapters');
    if (disp) {
      disp.status = 'error';
      disp.error = 'This device has stopped responding and disconnected. (Code 43)';
      disp.driver = '31.0.101.5333';
      disp.driverDate = daysAgo(3); // freshly updated ~3 days ago -> when crashes began
    }
    // System log tells the story: bugcheck + display TDR, faulting driver named.
    addEvent(h, { id: 41, level: 'Critical', source: 'Kernel-Power', log: 'System', message: 'The system has rebooted without cleanly shutting down first. This error may be caused by the system stopping responding, crashing, or losing power unexpectedly.', time: ago(30) });
    addEvent(h, { id: 1001, level: 'Error', source: 'BugCheck', log: 'System', message: 'The computer has rebooted from a bugcheck. The bugcheck was: 0x00000116 (VIDEO_TDR_FAILURE). A dump was saved. Faulting driver: igdkmd64.sys (Intel display driver 31.0.101.5333, installed 3 days ago).', time: ago(31) });
    addEvent(h, { id: 4101, level: 'Warning', source: 'Display', log: 'System', message: 'Display driver igfx stopped responding and has successfully recovered.', time: ago(90) });
    // Red herring: a benign Setup/servicing note. (The base 10016 DCOM warning is also present.)
    addEvent(h, { id: 19, level: 'Information', source: 'WindowsUpdateClient', log: 'System', message: 'Installation Successful: Windows successfully installed the following update: Intel Corporation - Display - 31.0.101.5333.', time: ago(60 * 24 * 3) });
  },
  contactWith: 'ewright',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID before I remote in, please.', answer: '"E10120."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll call you back on the desk number we have on record to confirm before I connect.', answer: 'Callback to the number on record reaches Emily. Verified.', purpose: 'verify' },
    { id: 'when', question: 'When did the blue screens start, and did anything change on the laptop right before?', answer: '"The last few days. Windows did some updates over the weekend, then it started."', purpose: 'clarify', reveals: 'recent-update' },
    { id: 'trigger', question: 'What are you usually doing when it crashes?', answer: '"When I dock to the big monitor or when I turn my camera on in a Teams call."', purpose: 'clarify', reveals: 'display' },
    { id: 'freq', question: 'How often, and does it fully blue-screen or just freeze?', answer: '"Full blue screen with a sad face, then it restarts. Three or four times a day."', purpose: 'clarify' },
    { id: 'color', question: 'What color is the laptop lid?', answer: '"...silver? Why does that matter?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the display/driver SOP (KB-0010)', match: { tool: 'kb', action: 'read', target: 'KB-0010' }, hint: 'KB-0010 covers driver error codes (10/43) and rollback vs. reimage.' },
    { id: 'events', label: 'Read the System log and found the VIDEO_TDR_FAILURE bugcheck naming the display driver', match: [{ tool: 'rdp', action: 'view_events', target: 'DEN-LT-1060', params: { log: 'System' } }, { tool: 'rdp', action: 'view_events', target: 'DEN-LT-1060' }], hint: 'The System log names the faulting driver in the bugcheck.' },
    { id: 'devices', label: 'Checked Device Manager: display adapter in error (Code 43), driver updated 3 days ago', match: { tool: 'rdp', action: 'view_devices', target: 'DEN-LT-1060' }, hint: 'Which device is flagged, and when did its driver change?' },
  ],
  required: [
    { id: 'fix_driver', label: 'Rolled back (or reinstalled) the display driver', match: [{ tool: 'rdp', action: 'rollback_driver', target: 'DEN-LT-1060', params: { device: /iris|xe|display|graphics/i } }, { tool: 'rdp', action: 'update_driver', target: 'DEN-LT-1060', params: { device: /iris|xe|display|graphics/i } }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'reimage', label: 'Jumped straight to a reimage', why: 'A reimage is a heavy, day-killing fix for a problem the event log points straight at: one bad display driver. Roll the driver back first; reimaging is a last resort.', match: { tool: 'ticket', action: 'reply', target: 'r_reimage' }, skill: 'efficiency', penalty: 0.3 },
    { id: 'blame_hw', label: 'Blamed the hardware and dispatched a vendor / marked the asset for repair', why: 'Nothing shows a failing GPU chip — the bugcheck names a driver that was updated 3 days ago, right when crashes began. Sending it to a vendor wastes days and money before the free fix (rollback) is even tried.', match: [{ tool: 'assets', action: 'dispatch_vendor' }, { tool: 'assets', action: 'set_status', params: { status: /repair/i } }], skill: 'technical', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Found it: the blue screens are a VIDEO_TDR_FAILURE bugcheck caused by the Intel display driver that updated 3 days ago — that\'s why it hits when you dock or turn the camera on. I rolled the driver back to the previous stable version and the display adapter is healthy again. Keep using it and let me know if you see even one more crash before Thursday; I\'ll also pin that driver version so Windows Update doesn\'t re-push the bad one.', scores: { communication: 1, technical: 1 }, feedback: 'Correct root cause from the log, the light fix (rollback), and prevents recurrence.' },
    { id: 'r_reimage', text: 'Your Windows install looks corrupted — I\'ll back up your files and reimage the laptop, should be ready tomorrow.', scores: { communication: 0.4, technical: 0.2 }, feedback: 'The log points at one driver, not a corrupt OS. A rollback fixes it in minutes; a reimage costs her a day for no reason.' },
    { id: 'r_hardware', text: 'This looks like a failing graphics chip — I\'ll open a warranty dispatch to swap the mainboard.', scores: { communication: 0.4, technical: 0.2 }, feedback: 'No hardware-failure evidence; the bugcheck names a driver updated the day the crashes started. Try the rollback before blaming hardware.' },
    { id: 'r_wait', text: 'Blue screens happen sometimes — try to keep it undocked and let\'s see if it settles down.', scores: { communication: 0.3, technical: 0.1 }, feedback: 'That is a workaround, not a fix, and it ignores the driver the log is pointing at.' },
  ],
  notesRubric: [
    { label: 'the root cause (bad display driver / VIDEO_TDR_FAILURE, Code 43)', pattern: /video_tdr|tdr|display driver|igdkmd|code 43|bugcheck|0x116|0x00000116/i },
    { label: 'the evidence it is a driver, not hardware or OS (recent update, docking/camera trigger)', pattern: /updated|3 days|recent|driver date|dock|camera|not hardware|event log|system log/i },
    { label: 'the fix (rolled back / reinstalled the driver) and recurrence prevention', pattern: /roll(ed)? ?back|rollback|previous version|reinstall|pin.*driver|blocked update/i },
  ],
  closure: { disposition: 'resolve', category: 'Endpoint - Driver/BSOD', resolutionCode: 'Rolled back display driver' },
  categoryAccept: ['driver', 'bsod', 'endpoint', 'display'],
  resolutionCodeAccept: ['driver', 'rollback', 'rolled back', 'update'],
  hints: [
    'Read the System event log first — a bugcheck (0x116 VIDEO_TDR_FAILURE) names the exact faulting driver.',
    'Device Manager shows the display adapter in error (Code 43) with a driver dated 3 days ago — the same window the crashes began.',
    'Roll the driver back to the previous version (KB-0010). Do not reimage and do not dispatch a vendor yet.',
    'Confirm with her the crashes stop, and pin the driver so Windows Update does not re-push the bad one.',
  ],
  debrief: 'A BSOD loop feels catastrophic, and the tempting responses are the heavy ones: reimage the machine or condemn the hardware. Both are premature. The System log names the faulting driver in the bugcheck, and Device Manager shows it was updated three days ago — exactly when the crashes started, and it only fires under GPU load (docking, camera). Rolling the driver back is a two-minute fix. Reserve reimaging and vendor dispatches for when the evidence actually points at the OS or the silicon.',
};

// ---------------------------------------------------------------------------
// SD2-06  Mapped drive vanished after the file-server migration (stale token)
// ---------------------------------------------------------------------------
const sd2_06: Scenario = {
  id: 'sd2-06',
  tier: 'sd2',
  title: 'My S: drive to \\\\FS01\\Shared disappeared',
  category: 'Access',
  difficulty: 2,
  estMinutes: 10,
  objective: 'Separate a stale drive-mapping / token problem from a genuine permission gap, and fix it with gpupdate + a real re-logon instead of granting access the user already has.',
  intake: {
    kind: 'ticket', number: 'INC457716', subject: 'Can\'t see the S: drive since the file server was moved',
    body: 'Escalated from SD1. David Kim (Recruiter) says his S: drive to \\\\FS01\\Shared is gone since IT "migrated the file server" over the weekend. He gets "drive not found" and sometimes "access denied". He needs it for onboarding paperwork.',
    requester: 'dkim', channel: 'portal', priority: 'P3', category: 'Access', openedAt: ago(40), affectedHost: 'DEN-LT-1051',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const h = host(w, 'DEN-LT-1051');
    // dkim is STILL in FS-Shared-RW and the share is online. The GPO drive map just
    // failed to reapply after the migration -> stale token, fixed by gpupdate + re-logon.
    addEvent(h, { id: 4098, level: 'Warning', source: 'Group Policy Drive Maps', log: 'Application', message: "The user 'KESTREL\\dkim' preference item 'S:' in the 'Drive Maps' Group Policy Object did not apply because the network path was not found at logon (0x80070035). Will retry at next policy refresh.", time: ago(45) });
    // Red herring: benign print-spooler informational.
    addEvent(h, { id: 7036, level: 'Information', source: 'Service Control Manager', log: 'System', message: 'The Print Spooler service entered the running state.', time: ago(120) });
  },
  contactWith: 'dkim',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10111."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll confirm on the desk number on record before we start.', answer: 'Callback to the number on record reaches David. Verified.', purpose: 'verify' },
    { id: 'ever', question: 'Did you have the S: drive working before the weekend migration?', answer: '"Yes, it worked fine on Friday. It only broke after the move."', purpose: 'clarify', reveals: 'had-before' },
    { id: 'others', question: 'Are your teammates seeing this too, or just you?', answer: '"A couple of us mentioned it, but signing out and in seemed to fix it for one of them."', purpose: 'clarify', reveals: 'relogon-helps' },
    { id: 'error', question: 'Does it say "drive not found" or "access denied" specifically?', answer: '"Mostly \'not found\', once \'access denied\' when I retyped the path."', purpose: 'clarify' },
    { id: 'lunch', question: 'Did you have a good weekend?', answer: '"It was fine, thanks. Can we fix the drive?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the shared-drive / mapped-drive SOP (KB-0009)', match: { tool: 'kb', action: 'read', target: 'KB-0009' }, hint: 'KB-0009 splits "not in the group" from "in the group but stale token".' },
    { id: 'groups', label: 'Confirmed dkim is still in FS-Shared-RW and the Shared share is online', match: [{ tool: 'directory', action: 'view', target: 'dkim' }, { tool: 'server', action: 'view_shares', target: 'DEN-FS01' }], hint: 'Is he missing FS-Shared-RW (a real gap) or in it (a token/mapping issue)?' },
    { id: 'token', label: 'Checked the live token groups on the machine', match: [{ tool: 'terminal', action: 'whoami_groups', target: 'DEN-LT-1051' }, { tool: 'rdp', action: 'view_events', target: 'DEN-LT-1051', params: { log: 'Application' } }], weight: 0.5 },
  ],
  required: [
    { id: 'gpupdate', label: 'Refreshed policy with gpupdate /force so the drive map reapplies', match: { tool: 'terminal', action: 'gpupdate', target: 'DEN-LT-1051' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'add_group', label: 'Added dkim to a share group he is already in', why: 'He already has FS-Shared-RW — the file server confirms it. This is a stale mapping, not a missing group. Adding groups does not fix a token and just over-provisions access.', match: { tool: 'directory', action: 'add_group', target: 'dkim' }, skill: 'security', penalty: 0.3 },
    { id: 'route_approval', label: 'Routed a new access request as if it were a permission gap', why: 'Treating a re-mapping glitch as an access request sends him for approvals he does not need and leaves him blocked for days.', match: { tool: 'ticket', action: 'reply', target: 'r_request' }, skill: 'process', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Good news — you already have access. You\'re still in the FS-Shared-RW group and the Shared folder on FS01 is online. After the migration your PC kept a stale drive mapping, so it showed "not found". I refreshed group policy (gpupdate /force); now fully sign OUT and back IN (not just lock the screen) and S: to \\\\FS01\\Shared will remap. If it doesn\'t come back after the re-logon, ping me right away.', scores: { communication: 1, technical: 1, process: 1 }, feedback: 'Correctly rules out a permission gap, applies the right fix, and specifies a real re-logon (not just a lock).' },
    { id: 'r_request', text: 'Looks like you don\'t have permission to that share — I\'ve submitted an access request for approval, hang tight.', scores: { communication: 0.4, process: 0.2 }, feedback: 'He already has the group. This is a token/mapping issue; an approval request just blocks him needlessly.' },
    { id: 'r_sysadmin', text: 'The file server migration must have broken the share — escalating to Sysadmin, the drive is down.', scores: { communication: 0.3, process: 0.2 }, feedback: 'The share is online and other users are fine after a re-logon. This is a client-side stale mapping, not a server outage.' },
  ],
  notesRubric: [
    { label: 'the finding (still in FS-Shared-RW; share online; not a permission gap)', pattern: /fs-shared|still in|already (a )?member|has access|share.*online|not a permission|not a gap/i },
    { label: 'the cause (stale mapping / token after migration)', pattern: /stale|token|mapping|drive map|migration|gpo|group policy|0x80070035|not found/i },
    { label: 'the fix (gpupdate + full sign-out/in)', pattern: /gpupdate|policy refresh|sign ?out|log ?off|re-?logon|re-?map/i },
  ],
  closure: { disposition: 'resolve', category: 'Access - Mapped Drive', resolutionCode: 'gpupdate + re-logon restored drive mapping' },
  categoryAccept: ['mapped drive', 'access', 'drive', 'share'],
  resolutionCodeAccept: ['gpupdate', 're-logon', 'relogon', 'mapping', 'token'],
  hints: [
    'First decide which problem this is: KB-0009 separates "not in the group" from "in the group but stale token".',
    'Check his groups against the share on FS01 — he is still in FS-Shared-RW and the Shared share is online. That rules out a permission gap.',
    'The Application log shows the GPO drive map failed to apply at logon. Run gpupdate /force.',
    'Have him fully sign out and back in (a screen lock is not enough) so the token and mapping refresh. Do not add groups.',
  ],
  debrief: 'An "access denied / drive not found" after a migration reads like a permissions problem, and the reflex is to grant access or route an approval. But he never lost access — he is still in FS-Shared-RW and the share is online. The GPO drive map simply failed to reapply against the moved server, leaving a stale mapping. gpupdate plus a genuine sign-out/sign-in fixes it. Adding groups he already has is the over-provisioning auditors flag, and escalating a client glitch as a server outage wastes the sysadmin\'s time.',
};

// ---------------------------------------------------------------------------
// SD2-07  Outlook keeps asking for a password (corrupt profile, not compromise)
// ---------------------------------------------------------------------------
const sd2_07: Scenario = {
  id: 'sd2-07',
  tier: 'sd2',
  title: 'Outlook keeps prompting for my password',
  category: 'Email',
  difficulty: 3,
  estMinutes: 12,
  objective: 'Recognise a corrupt local Outlook profile after a password change, prove the password and account are fine, and rebuild the profile — without resetting the password on a loop or crying "compromise".',
  intake: {
    kind: 'ticket', number: 'INC457717', subject: 'Outlook won\'t stop asking for my password',
    body: 'Escalated from SD1. Bhavik Patel (Senior Accountant) changed his password yesterday when it expired. Now desktop Outlook on DEN-LT-1042 prompts for the password over and over and never connects. He says webmail in the browser works fine with the new password. SD1 already reset the password once with no change.',
    requester: 'bpatel', channel: 'phone', priority: 'P2', category: 'Security', openedAt: ago(28), affectedHost: 'DEN-LT-1042',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const u = findUser(w, 'bpatel')!;
    u.passwordLastSet = ago(60 * 22); // changed ~22h ago on expiry
    // Webmail with the NEW password works; only the desktop Outlook profile is stuck.
    // Every sign-in is from his own corporate IP -> no compromise signal.
    u.recentSignIns = [
      { time: ago(20), ip: '10.10.20.42', location: 'Denver, US', app: 'WorkSuite Mail (browser)', result: 'success', device: 'DEN-LT-1042', mfa: 'satisfied' },
      { time: ago(22), ip: '10.10.20.42', location: 'Denver, US', app: 'Outlook (desktop, modern auth)', result: 'failure', reason: 'stale token / profile', device: 'DEN-LT-1042' },
      { time: ago(35), ip: '10.10.20.42', location: 'Denver, US', app: 'Outlook (desktop, modern auth)', result: 'failure', reason: 'stale token / profile', device: 'DEN-LT-1042' },
    ];
    const h = host(w, 'DEN-LT-1042');
    addEvent(h, { id: 27, level: 'Error', source: 'Outlook', log: 'Application', message: 'The Outlook data file C:\\Users\\bpatel\\AppData\\Local\\Microsoft\\Outlook\\bpatel@kestreldynamics.com.ost is corrupted or cannot be opened (0x8004010F). Outlook could not sign in and is repeatedly prompting for credentials.', time: ago(24) });
    addEvent(h, { id: 45, level: 'Warning', source: 'Outlook', log: 'Application', message: 'Cannot start Microsoft Outlook cached mode: the profile "Outlook" references a data file that failed integrity checks.', time: ago(23) });
    // Red herring: base benign 10016 DCOM warning is present on the host.
  },
  contactWith: 'bpatel',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10106."', purpose: 'verify' },
    { id: 'mgr', question: 'I\'ll confirm with your manager Rachel Okafor as a second factor before I touch your mailbox setup.', answer: 'Rachel Okafor confirms Bhavik is at his desk and expected. Verified.', purpose: 'verify' },
    { id: 'webmail', question: 'When you say webmail works — you signed in with the NEW password, in a browser?', answer: '"Yes, the new password logs me into webmail in Chrome, no problem. Only desktop Outlook keeps nagging."', purpose: 'clarify', reveals: 'new-pw-works' },
    { id: 'prompts', question: 'When Outlook prompts, does typing the new password work even once, or does it just ask again?', answer: '"I type it, it thinks, then asks again. Endless loop."', purpose: 'clarify', reveals: 'loop' },
    { id: 'other', question: 'Did you get any odd emails or approve any sign-in prompt you didn\'t start?', answer: '"No, nothing weird. Just the password change yesterday and then this."', purpose: 'clarify', reveals: 'no-compromise' },
    { id: 'weather', question: 'Busy quarter-end for you?', answer: '"Always. Can we focus on Outlook?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'signins', label: 'Reviewed sign-ins: webmail with the new password succeeds from his own PC; only desktop Outlook fails', match: { tool: 'directory', action: 'view_signins', target: 'bpatel' }, hint: 'Does anything succeed with the new password? From what IP?' },
    { id: 'events', label: 'Read the Application log and found the corrupt OST / profile error', match: [{ tool: 'rdp', action: 'view_events', target: 'DEN-LT-1042', params: { log: 'Application' } }, { tool: 'rdp', action: 'view_events', target: 'DEN-LT-1042' }], hint: 'The Application log names the OST/profile problem.' },
    { id: 'kb', label: 'Consulted the password/account SOP (KB-0002)', match: { tool: 'kb', action: 'read', target: 'KB-0002' }, weight: 0.5 },
  ],
  required: [
    { id: 'guide', label: 'Guided a mail-profile rebuild after proving the password is fine', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'reset_again', label: 'Reset the password again', why: 'Webmail works with the new password, so the password is fine — SD1 already reset it once with no effect. Resetting again does nothing but restart the expiry clock and annoy the user.', match: { tool: 'directory', action: 'reset_password', target: 'bpatel' }, skill: 'technical', penalty: 0.3 },
    { id: 'escalate_soc', label: 'Escalated to Security as a compromised account', why: 'Every sign-in is from his own corporate IP, webmail with the new password succeeds, and there are no rogue rules or prompts. There is no compromise signal; escalating cries wolf and delays the real fix.', match: { tool: 'ticket', action: 'reply', target: 'r_soc' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Your account and new password are fine — that\'s exactly why webmail signs you in. The problem is local: desktop Outlook\'s profile and its offline data file (OST) got corrupted around the password change, so it can\'t authenticate and just loops the prompt. I\'ll rebuild your Outlook mail profile: create a fresh profile, let it re-download the mailbox (OST), and remove the corrupted one. Your mail is all safe on the server. Give it a few minutes to sync after I\'m done.', scores: { communication: 1, technical: 1 }, feedback: 'Proves the password is fine, names the real cause (corrupt profile/OST), and rebuilds it — the correct fix.' },
    { id: 'r_reset', text: 'Let me reset your password one more time; that usually clears credential prompts.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'The password is not the problem — webmail proves it, and SD1 already reset it once. This loops.' },
    { id: 'r_soc', text: 'Repeated password prompts can mean someone\'s trying your account — I\'m escalating to Security to check for compromise.', scores: { communication: 0.3, process: 0.1 }, feedback: 'All activity is from his own PC and IP and webmail works. There is no compromise here — this is a corrupt local profile.' },
  ],
  notesRubric: [
    { label: 'the root cause (corrupt Outlook profile / OST after the password change)', pattern: /profile|\.ost|ost|corrupt|0x8004010f|cached mode|data file/i },
    { label: 'the proof it is not a compromise (webmail with new password works, own corp IP)', pattern: /webmail|browser|new password works|10\.10\.20\.42|own (corp|corporate)? ?ip|no compromise|no rules/i },
    { label: 'the fix (recreate/rebuild the mail profile)', pattern: /recreate|rebuild|new profile|re-?create|re-?build|re-?download|new ost/i },
  ],
  closure: { disposition: 'resolve', category: 'Endpoint - Outlook Profile', resolutionCode: 'Recreated Outlook mail profile' },
  categoryAccept: ['outlook profile', 'outlook', 'endpoint', 'email'],
  resolutionCodeAccept: ['profile', 'outlook', 'recreate', 'rebuild', 'ost'],
  hints: [
    'Check the sign-ins: webmail with the NEW password succeeds from his own PC — the password and account are fine.',
    'Read the Application log: it names a corrupt OST / profile integrity failure.',
    'The fix is to rebuild the Outlook mail profile (new profile, re-download the OST), not to touch the password.',
    'Do NOT reset the password again (SD1 already did, no effect) and do NOT escalate to Security — there is no compromise signal.',
  ],
  debrief: 'Two traps sit on either side of the right answer. On one side, "it keeps asking for my password" tempts you to reset the password — but webmail with the new password already works, so the credential is fine and resetting just loops. On the other, "repeated password prompts" pattern-matches to an attack and tempts a SOC escalation — but every sign-in is from his own PC and IP with no rogue rules. The real cause is a corrupt local Outlook profile/OST after the change. Rebuild the profile; the mailbox itself is safe on the server.',
};

// ---------------------------------------------------------------------------
// SD2-08  Group Policy not applying (client DNS pointed at a public resolver)
// ---------------------------------------------------------------------------
const sd2_08: Scenario = {
  id: 'sd2-08',
  tier: 'sd2',
  title: 'Drive maps and settings missing - Group Policy won\'t apply',
  category: 'Windows',
  difficulty: 3,
  estMinutes: 13,
  objective: 'Diagnose a Group Policy failure down to its real cause (the client\'s DNS was pointed away from the domain controllers), fix it at the desk, and avoid escalating a single-host misconfig as a replication problem.',
  intake: {
    kind: 'ticket', number: 'INC457718', subject: 'My mapped drives and desktop settings are all gone',
    body: 'Escalated from SD1. Greg Harris (Plant Manager) on WIC-WS-3001: his mapped drives, printer and desktop policy settings all disappeared. He can browse the internet fine. Other plant PCs are normal. A vendor tech was on this machine last week.',
    requester: 'gharris', channel: 'phone', priority: 'P2', category: 'Network', openedAt: ago(30), affectedHost: 'WIC-WS-3001',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const h = host(w, 'WIC-WS-3001');
    // Someone set static public DNS on the client. It can reach the internet but cannot
    // resolve the domain controllers / SYSVOL, so Group Policy silently fails.
    h.network.dhcp = false;
    h.network.dns = ['8.8.8.8', '1.1.1.1'];
    h.network.adapterStatus = 'up'; // network itself is fine
    addEvent(h, { id: 1129, level: 'Error', source: 'Group Policy', log: 'System', message: 'The processing of Group Policy failed because of lack of network connectivity to a domain controller. This may be a transient condition. Group Policy settings, including folder redirection and drive maps, cannot be applied until this event is resolved.', time: ago(28) });
    addEvent(h, { id: 1055, level: 'Error', source: 'Group Policy', log: 'System', message: 'The processing of Group Policy failed. Windows could not resolve the computer name of a domain controller. This could be caused by DNS resolution pointing at a server that is not authoritative for the Active Directory domain.', time: ago(28) });
    // Red herring: benign time-service warning from long ago; base 10016 DCOM also present.
    addEvent(h, { id: 36, level: 'Warning', source: 'Time-Service', log: 'System', message: 'The time service has not synchronized the system time for 3600 seconds. (Benign; not the cause here.)', time: ago(60 * 30) });
  },
  contactWith: 'gharris',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID before I remote in, please.', answer: '"E10130."', purpose: 'verify' },
    { id: 'mgr', question: 'I\'ll confirm with your manager Tom Brandt before I make changes on the plant PC.', answer: 'Tom Brandt confirms Greg is the machine\'s user and expected. Verified.', purpose: 'verify' },
    { id: 'vendor', question: 'You mentioned a vendor tech — do you know what they changed?', answer: '"They were fixing our internet last week. Fiddled with the network settings on this PC, I think."', purpose: 'clarify', reveals: 'dns-changed' },
    { id: 'others', question: 'Are other plant PCs missing their drives and settings, or just this one?', answer: '"Just mine. The machine next to me is totally normal."', purpose: 'clarify', reveals: 'single-host' },
    { id: 'internet', question: 'Can you still browse the web on it?', answer: '"Yeah, internet\'s fine. It\'s just all my work drives and settings that vanished."', purpose: 'clarify' },
    { id: 'coffee', question: 'Is the plant busy today?', answer: '"It\'s a factory, always busy. Can we fix the PC?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the network/DNS troubleshooting SOP (KB-0007)', match: { tool: 'kb', action: 'read', target: 'KB-0007' }, hint: 'KB-0007: ping works but name resolution fails -> DNS.' },
    { id: 'events', label: 'Read the System log: Group Policy failed - no DC connectivity / name resolution', match: [{ tool: 'rdp', action: 'view_events', target: 'WIC-WS-3001', params: { log: 'System' } }, { tool: 'rdp', action: 'view_events', target: 'WIC-WS-3001' }], hint: 'The GP errors say the client cannot resolve a domain controller.' },
    { id: 'gpupdate', label: 'Ran gpupdate /force and watched it fail', match: { tool: 'terminal', action: 'gpupdate', target: 'WIC-WS-3001' }, hint: 'Force a policy refresh and read the failure.' },
    { id: 'dns', label: 'Proved it is DNS: nslookup of the domain/DC fails while ping by IP works', match: [{ tool: 'terminal', action: 'nslookup', target: 'WIC-WS-3001' }, { tool: 'terminal', action: 'ipconfig_all', target: 'WIC-WS-3001' }, { tool: 'terminal', action: 'ping', target: 'WIC-WS-3001' }], hint: 'Where is this machine\'s DNS pointing? Not at 10.10.10.5/6.' },
  ],
  required: [
    { id: 'fix_dns', label: 'Pointed the client DNS back at the domain controllers (or restored DHCP)', match: [{ tool: 'rdp', action: 'set_dns', target: 'WIC-WS-3001', params: { dns: /10\.(10|20)\.10\.(5|6)/ } }, { tool: 'rdp', action: 'set_dhcp', target: 'WIC-WS-3001' }], skill: 'technical' },
    { id: 'reapply', label: 'Re-ran gpupdate /force to reapply policy after fixing DNS', match: { tool: 'terminal', action: 'gpupdate', target: 'WIC-WS-3001' }, skill: 'technical', after: 'fix_dns', weight: 0.5 },
  ],
  forbidden: [
    { id: 'escalate_sysadmin', label: 'Escalated to Sysadmin as a GPO / replication problem without checking the client', why: 'Only this one host is affected and the DCs are serving everyone else fine. The cause is local: the client\'s DNS was pointed at a public resolver so it could not find a domain controller. That is a desk fix, not a sysadmin replication case.', match: { tool: 'ticket', action: 'reply', target: 'r_escalate' }, skill: 'process', penalty: 0.25 },
    { id: 'blind_reboot', label: 'Rebooted / rejoined the domain as a blind first move', why: 'A reboot or domain rejoin is a heavy shot in the dark when the event log and nslookup point straight at a DNS misconfiguration. Fix the DNS first.', match: [{ tool: 'rdp', action: 'reboot', target: 'WIC-WS-3001' }], skill: 'efficiency', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Found it: your PC\'s DNS had been set manually to a public resolver (8.8.8.8), so it could reach the internet but could NOT find a domain controller — which is why Group Policy stopped applying and your drive maps, printer and settings vanished. Only your machine was affected. I pointed DNS back at our domain controllers (and restored DHCP so it stays correct), then re-ran gpupdate — policy applied and your drives and settings are back. That vendor tech\'s "internet fix" was the culprit.', scores: { communication: 1, technical: 1 }, feedback: 'Nails the real cause (client DNS), fixes it at the desk, and explains why only one host broke.' },
    { id: 'r_escalate', text: 'Group Policy isn\'t applying — this is a GPO or AD replication issue, escalating to Sysadmin.', scores: { communication: 0.4, process: 0.2 }, feedback: 'A replication problem would hit many machines; only this one is affected. Check the client\'s DNS first — that is where the fault is.' },
    { id: 'r_network', text: 'Sounds like a network outage at the plant — escalating to the Network team.', scores: { communication: 0.3, process: 0.2 }, feedback: 'The network is up (he can browse and ping works). This is a local DNS misconfiguration, not an outage.' },
    { id: 'r_reboot', text: 'Let me just reboot it a few times and see if the drives come back.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'Blind reboots ignore the event log and nslookup, which point directly at DNS.' },
  ],
  notesRubric: [
    { label: 'the root cause (client DNS pointed away from the DCs -> GP cannot reach a DC)', pattern: /dns|8\.8\.8\.8|1\.1\.1\.1|resolver|domain controller|resolve|sysvol/i },
    { label: 'the scoping that rules out replication/outage (single host, internet works, DCs fine)', pattern: /single host|only (this|one)|one machine|others (are )?fine|internet works|ping.*works|not (a )?(replication|outage)/i },
    { label: 'the fix (set DNS to the DCs / restore DHCP, then gpupdate)', pattern: /set dns|10\.10\.10\.5|10\.10\.10\.6|10\.20\.10\.5|dhcp|gpupdate|reappl/i },
  ],
  closure: { disposition: 'resolve', category: 'Windows - Group Policy', resolutionCode: 'Corrected client DNS; Group Policy reapplied' },
  categoryAccept: ['group policy', 'windows', 'gpo', 'dns'],
  resolutionCodeAccept: ['dns', 'group policy', 'gpupdate', 'gpo', 'dhcp'],
  hints: [
    'Only one host is affected and he can browse the web — that argues against a site outage or DC replication problem.',
    'Read the System log: Group Policy failed because it could not reach / resolve a domain controller.',
    'Run gpupdate /force (it fails) and check ipconfig /all + nslookup — the DNS is set to 8.8.8.8, not the domain controllers.',
    'Fix: set DNS back to 10.10.10.5/6 (or restore DHCP), then gpupdate /force again. Don\'t escalate as a replication issue.',
  ],
  debrief: 'When Group Policy stops applying, the scary explanations are GPO corruption or AD replication — sysadmin-level problems. But the scope test collapses that: only one host is broken and it still reaches the internet. The event log and nslookup show the real cause — a vendor "fixed the internet" by hard-coding a public DNS resolver, so the client could browse but never resolve a domain controller to pull policy. Correcting DNS (and restoring DHCP so it stays fixed) plus a gpupdate resolves it at the desk. Escalating a single-host DNS mistake as replication, or blind-rebooting, both skip the two-minute diagnosis.',
};

// ---------------------------------------------------------------------------
// SD2-09  "Give me local admin" - least privilege, offer JIT / Software Center
// ---------------------------------------------------------------------------
const sd2_09: Scenario = {
  id: 'sd2-09',
  tier: 'sd2',
  title: 'Engineer requests standing local admin rights',
  category: 'Access',
  difficulty: 3,
  estMinutes: 10,
  objective: 'Hold the least-privilege line on a standing-local-admin request: deny it as written, verify the requester, and route them to the approved alternatives (Software Center, just-in-time elevation) with proper approval.',
  intake: {
    kind: 'ticket', number: 'INC457719', subject: 'Please make me a local admin on my workstation',
    body: 'Nora Foster (Design Engineer, DEN-WS-2010) writes: "I install and update engineering tools and plugins constantly and it\'s slow to keep asking IT. Can you just add me to the local Administrators group on my machine permanently? My manager is fine with it."',
    requester: 'nfoster', channel: 'portal', priority: 'P4', category: 'Access', openedAt: ago(55), affectedHost: 'DEN-WS-2010',
  },
  priorityExpected: 'P4',
  setup: (w) => {
    // No compromise, no incident - a policy/access decision. Local admins is the built-in
    // Domain Admins + IT-Admins only; nfoster is a standard user and must stay one.
    w.chat.push({ id: 'ch-nf', with: 'nfoster', messages: [
      { from: 'nfoster', time: ago(50), text: 'Any update? I really just need admin so I stop getting UAC prompts when I install SolidWorks add-ins.' },
    ] });
  },
  contactWith: 'nfoster',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10140."', purpose: 'verify' },
    { id: 'mgr', question: 'You said your manager approves — I\'ll confirm with Tom Brandt directly.', answer: 'Tom Brandt: "She does install a lot of CAD tools, but I\'ll defer to IT policy on how to grant it. I\'m not insisting on standing admin."', purpose: 'verify', reveals: 'mgr-defers' },
    { id: 'need', question: 'What specifically are you installing, and how often?', answer: '"SolidWorks add-ins and the occasional plugin update — a few times a month, not daily really."', purpose: 'clarify', reveals: 'scope' },
    { id: 'softwarecenter', question: 'Are the tools you need already in our Software Center self-service catalog?', answer: '"Some are. The add-ins aren\'t, that\'s the annoying part."', purpose: 'clarify', reveals: 'catalog-gap' },
    { id: 'hobby', question: 'What do you think of the new cafeteria menu?', answer: '"Haven\'t tried it. Is that relevant?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the approval SOP for sensitive/privileged access (KB-0006)', match: { tool: 'kb', action: 'read', target: 'KB-0006' }, hint: 'Who has to approve privileged access, and is a requester\'s own manager enough?' },
    { id: 'esc', label: 'Checked the escalation matrix - Identity owns privileged group membership (KB-0004)', match: { tool: 'kb', action: 'read', target: 'KB-0004' }, weight: 0.5 },
    { id: 'admins', label: 'Reviewed the local Administrators group on her machine (standard user, no standing admins)', match: { tool: 'rdp', action: 'view_local_admins', target: 'DEN-WS-2010' }, hint: 'Confirm the current membership before deciding — it is Domain Admins + IT-Admins only.' },
  ],
  required: [
    { id: 'deny_offer', label: 'Declined standing admin and offered the approved alternatives (Software Center / JIT elevation, with justification+approval)', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'security' },
  ],
  forbidden: [
    { id: 'grant_admin', label: 'Granted standing local admin', why: 'Standing local admin on a user\'s daily machine violates least privilege - it lets malware and phishing run with admin rights and is a top audit finding. A manager\'s casual "fine with it" is not the approval this needs, and the need (occasional installs) is met by Software Center / just-in-time elevation instead.', match: { tool: 'ticket', action: 'reply', target: 'r_grant' }, skill: 'security', penalty: 0.5 },
    { id: 'add_priv_group', label: 'Added her to a privileged admin group', why: 'Adding an engineer to IT-Admins / Server Admins (or any *-Admins) is a far bigger privilege grant than she asked for and is never done on request - privileged group membership is Identity-team territory with data-owner approval.', match: { tool: 'directory', action: 'add_group', target: 'nfoster', params: { group: /admin/i } }, skill: 'security', penalty: 0.5 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'I can\'t grant standing local admin on your daily machine — it\'s against least-privilege policy and it\'s one of the biggest security risks we get flagged on (admin rights are what malware and phishing borrow). But I can solve the actual pain: most engineering tools are in Software Center for self-service install with no admin needed, and for the SolidWorks add-ins that aren\'t, we use just-in-time elevation (a one-time, time-boxed admin token) or push the install for you. If you need that regularly, send me the exact add-ins and a short business justification and I\'ll route it for approval through the Identity team. Which add-ins are you stuck on right now?', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Holds the least-privilege line, explains why, and gives real, approved ways to get her work done.' },
    { id: 'r_grant', text: 'Sure — I\'ve added you to the local Administrators group on DEN-WS-2010. You\'re all set, no more UAC prompts.', scores: { communication: 0.4, security: 0.0, process: 0.1 }, feedback: 'Standing local admin granted on a say-so. This is the exact over-privilege that audits and attackers exploit.' },
    { id: 'r_flat', text: 'No, we don\'t give out admin rights. Closing the ticket.', scores: { communication: 0.3, security: 0.6, process: 0.3 }, feedback: 'The security answer is right but the service is poor - offer Software Center / JIT so her real need is met.' },
    { id: 'r_route', text: 'I\'ll just forward your request to the Identity team to make you an admin.', scores: { communication: 0.4, security: 0.3, process: 0.3 }, feedback: 'Passing through a standing-admin request without shaping it or offering alternatives just relocates the bad ask.' },
  ],
  notesRubric: [
    { label: 'the decision and rationale (deny standing admin; least privilege)', pattern: /least privilege|standing admin|deny|declin|not grant|policy|audit/i },
    { label: 'the alternatives offered (Software Center / JIT elevation / packaged install)', pattern: /software center|self-service|just-?in-?time|jit|elevat|packaged|push the install|laps/i },
    { label: 'the correct approval path (justification + approval, Identity team, not just the manager)', pattern: /justification|approval|identity team|data owner|not just the manager|kb-0006/i },
  ],
  closure: { disposition: 'reject', category: 'Access - Local Admin Request', resolutionCode: 'Denied standing admin; offered Software Center / JIT elevation' },
  categoryAccept: ['local admin', 'access', 'admin', 'privilege'],
  resolutionCodeAccept: ['least privilege', 'denied', 'software center', 'jit', 'elevation', 'approval'],
  hints: [
    'This is a policy decision, not a break/fix. Read KB-0006 (approval for sensitive/privileged access) first.',
    'Check the local Administrators group on her machine to confirm the baseline: Domain Admins + IT-Admins only, no standing users.',
    'Standing local admin fails least privilege. Offer Software Center self-service and just-in-time elevation instead.',
    'If there\'s a recurring need, require a business justification and route for approval (Identity team) - a requester\'s own manager saying "fine" is not enough.',
  ],
  debrief: 'The social pressure here is politeness plus "my manager\'s fine with it." Neither overrides least privilege. Standing local admin on a daily-driver machine means every phishing click or malicious macro inherits admin rights - it is a top audit and breach factor, which is why it is not granted on request and why a requester\'s own manager is not the approver. The skilled move refuses the ask as written but does not leave the user stuck: Software Center covers self-service installs, just-in-time elevation covers the rest, and a genuine recurring need goes through a justified, approved request. Adding her to any *-Admins group would be an even larger over-grant.',
};

// ---------------------------------------------------------------------------
// SD2-10  Expired TLS certificate on the ERP site (diagnose, then escalate)
// ---------------------------------------------------------------------------
const sd2_10: Scenario = {
  id: 'sd2-10',
  tier: 'sd2',
  title: 'Security warning on the ERP website for everyone',
  category: 'Infrastructure',
  difficulty: 4,
  estMinutes: 15,
  objective: 'Diagnose a browser TLS warning down to an expired server certificate, recognise it is beyond the desk\'s hands, and escalate to Sysadmin with evidence - never coaching users to click through the warning.',
  intake: {
    kind: 'ticket', number: 'INC457720', subject: 'ERP site says "your connection is not private"',
    body: 'Jenna Morales (AP Specialist) reports the whole AP team gets a red "your connection is not private" warning at https://erp.kestrel.local this morning and can\'t reach the ERP. Nothing changed on their PCs. She\'s asking whether it\'s safe to click "proceed anyway" to get their invoices done.',
    requester: 'jmorales', channel: 'phone', priority: 'P2', category: 'Application', openedAt: ago(20),
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const app = w.servers.find((s) => s.id === 'DEN-APP01')!;
    // The ERP server's TLS cert expired. Service is up; only the cert is the problem.
    app.notes = 'TLS certificate for erp.kestrel.local (CN=erp.kestrel.local) expired 2026-09-14. IIS/W3SVC still serving; browsers show NET::ERR_CERT_DATE_INVALID. Cert renewal/rebind is a sysadmin task.';
    app.events.push(
      { id: 36885, time: ago(30), level: 'Warning', source: 'Schannel', log: 'System', message: 'When asking for client authentication, this server sends a list of trust anchors... The current TLS certificate bound to https (erp.kestrel.local) has an expiration date of 2026-09-14 and is now expired.' },
      { id: 36887, time: ago(25), level: 'Error', source: 'Schannel', log: 'System', message: 'A fatal alert was generated and sent to the remote endpoint. TLS handshakes for erp.kestrel.local are failing certificate validation (expired certificate).' },
    );
    // Users report the browser error; log the proxy/web view of it.
    addLog(w, { time: ago(18), source: 'web', host: 'DEN-LT-1041', user: 'jmorales', domain: 'erp.kestrel.local', url: 'https://erp.kestrel.local/', action: 'cert_error', message: 'TLS certificate validation failed: NET::ERR_CERT_DATE_INVALID (certificate expired 2026-09-14) for erp.kestrel.local' });
  },
  contactWith: 'jmorales',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10105."', purpose: 'verify' },
    { id: 'mgr', question: 'I\'ll confirm with Rachel Okafor since this affects the whole AP team and ERP.', answer: 'Rachel Okafor confirms the AP team is blocked from ERP and asks for a quick fix or a clear status. Verified.', purpose: 'verify' },
    { id: 'exact', question: 'What exactly does the warning say - is there an error code?', answer: '"It says \'Your connection is not private\' and \'NET::ERR_CERT_DATE_INVALID\'."', purpose: 'clarify', reveals: 'cert-date' },
    { id: 'scope', question: 'Is it just you or the whole team, and does it happen on more than one browser/PC?', answer: '"Everyone on AP, every browser. It started this morning; nothing changed on our end."', purpose: 'clarify', reveals: 'many-users' },
    { id: 'other', question: 'Do other internal sites work, or just ERP is warning?', answer: '"Other sites are fine. Only the ERP site throws the warning."', purpose: 'clarify', reveals: 'erp-only' },
    { id: 'lunch', question: 'How\'s quarter-end treating the AP team?', answer: '"Stressful, which is why we need ERP back. Focus?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Checked the escalation matrix - the ERP app server is Sysadmin territory (KB-0004)', match: { tool: 'kb', action: 'read', target: 'KB-0004' }, hint: 'Who owns the ERP application server and its certificate?' },
    { id: 'server', label: 'Inspected the ERP server (DEN-APP01): note flags an expired TLS certificate', match: { tool: 'server', action: 'view', target: 'DEN-APP01' }, hint: 'Look at the ERP application server itself, not the users\' PCs.' },
    { id: 'events', label: 'Read the server event log: Schannel reports the certificate expired', match: { tool: 'server', action: 'view_events', target: 'DEN-APP01' }, hint: 'Schannel events name the expired cert and its date.' },
  ],
  required: [
    { id: 'escalate', label: 'Escalated to Sysadmin with evidence to reissue/rebind the certificate', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'clickthrough', label: 'Told users to click "proceed anyway" or add a certificate exception', why: 'Coaching users to bypass a TLS warning trains them to ignore exactly the protection that stops man-in-the-middle attacks, and normalises it for the next (real) malicious cert. The warning is a symptom to fix at the server, never to click past.', match: { tool: 'ticket', action: 'reply', target: 'r_clickthrough' }, skill: 'security', penalty: 0.5 },
    { id: 'blind_restart', label: 'Restarted / rebooted the production ERP server as a blind fix', why: 'Bouncing the ERP service or server will not renew an expired certificate and risks the production system mid-quarter-end. It is also beyond the desk\'s scope - server changes go to Sysadmin.', match: [{ tool: 'server', action: 'restart_service', target: 'DEN-APP01' }, { tool: 'server', action: 'reboot', target: 'DEN-APP01' }], skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Diagnosed: the ERP site\'s TLS certificate for erp.kestrel.local expired on 2026-09-14, which is exactly why every browser shows "not private / NET::ERR_CERT_DATE_INVALID." It\'s the server\'s certificate, not your PCs, and it is NOT a hacking attempt - but please do not click "proceed anyway", since that trains everyone to ignore real warnings. Renewing and rebinding a server certificate is a Sysadmin task, so I\'ve escalated to Sysadmin (Marco Reyes\' team) as P2 with the Schannel events and the expiry date, flagging that the whole AP team is blocked at quarter-end. I\'ll keep you posted the moment it\'s reissued.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Correct diagnosis, correct owner (Sysadmin), evidence attached, and explicitly warns against clicking through.' },
    { id: 'r_clickthrough', text: 'It\'s just an expired certificate, totally safe - click "Advanced" then "Proceed to erp.kestrel.local (unsafe)", or add a certificate exception, and you can keep working.', scores: { communication: 0.4, security: 0.0 }, feedback: 'Never coach users past a TLS warning. It defeats the control and normalises ignoring the next real one.' },
    { id: 'r_soc', text: 'A certificate warning could mean someone\'s intercepting your traffic - escalating to Security as a possible attack.', scores: { communication: 0.4, process: 0.2 }, feedback: 'The server\'s own cert simply expired (Schannel confirms it). This is a sysadmin renewal, not a security incident.' },
    { id: 'r_restart', text: 'I\'ll restart the ERP service on the server - that usually clears certificate errors.', scores: { communication: 0.3, process: 0.2 }, feedback: 'A restart cannot renew an expired cert, and touching the production ERP server is out of the desk\'s scope.' },
  ],
  notesRubric: [
    { label: 'the diagnosis (expired TLS/SSL certificate on the ERP server)', pattern: /expired|certificate|cert|tls|ssl|err_cert_date|erp\.kestrel|schannel/i },
    { label: 'the reason it is escalated (server cert = sysadmin, beyond desk scope; whole team affected)', pattern: /sysadmin|server|beyond.*(scope|desk)|reissue|rebind|renew|whole (team|ap)|all users/i },
    { label: 'the safety point (do not click through / add an exception)', pattern: /do ?n(o|')t click|not click|proceed anyway|no exception|don\'t bypass|never bypass/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'sysadmin', category: 'Infrastructure - Certificate', resolutionCode: 'Escalated to Sysadmin to reissue/rebind expired TLS certificate' },
  categoryAccept: ['certificate', 'infrastructure', 'tls', 'cert'],
  resolutionCodeAccept: ['certificate', 'cert', 'tls', 'escalated', 'reissue', 'sysadmin'],
  hints: [
    'The error NET::ERR_CERT_DATE_INVALID and "your connection is not private" point at the site\'s certificate, not the users\' PCs.',
    'Look at the ERP application server (DEN-APP01), not the endpoints - its note and Schannel events show the TLS cert expired 2026-09-14.',
    'Renewing/rebinding a server certificate is a Sysadmin task (KB-0004), so escalate with the evidence.',
    'Never tell users to click "proceed anyway" or add an exception - that defeats the warning and trains bad habits.',
  ],
  debrief: 'A TLS warning across a whole team is high-impact (P2) and easy to mishandle two ways: the convenient wrong answer is to tell users to click "proceed anyway" so invoices get done - which trains everyone to ignore the very control that catches interception - and the over-reaction is to escalate it to Security as an attack. The evidence on the ERP server settles it: the certificate simply expired, per the Schannel events and the server note. Renewing and rebinding a server certificate is beyond the desk and belongs to Sysadmin, so the right move is a clean, evidence-backed escalation with a clear "do not click through" instruction to the users in the meantime.',
};

export const SD2_SCENARIOS_B: Scenario[] = [sd2_05, sd2_06, sd2_07, sd2_08, sd2_09, sd2_10];
