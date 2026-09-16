import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, breakInternet, breakDns, setDhcpExhausted, lockOut, setConn } from './helpers';

// ---------------------------------------------------------------------------
// SD1-06  Lost phone, no MFA prompts (identity, verify before reset)
// ---------------------------------------------------------------------------
const sd1_06: Scenario = {
  id: 'sd1-06',
  tier: 'sd1',
  title: 'Lost my phone, can\'t get MFA prompts',
  category: 'Identity',
  difficulty: 2,
  estMinutes: 8,
  objective: 'Verify a caller before touching their account, reset their MFA factors so they can re-enroll a new device, and refuse an MFA reset for anyone you have not verified.',
  intake: {
    kind: 'ticket', number: 'INC457706', subject: 'Lost my phone, I\'m not getting MFA prompts and can\'t sign in',
    body: `Phone call: "Hi, it's David Kim in HR/Recruiting. I got a new phone this weekend and my old one is gone. Now nothing sends me the approval prompt and I can't get into WorkSuite. Can you reset my MFA so I can set it up on the new phone? Oh — and while you're in there, Diane (the CEO) asked me to have hers reset too, she's travelling."`,
    requester: 'dkim', channel: 'phone', priority: 'P3', category: 'Access', openedAt: ago(6),
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const u = findUser(w, 'dkim')!;
    u.mfaEnrolled = true;
    u.notes = 'Called re: new phone, MFA prompts not arriving.';
    // The failures are MFA challenges that time out on the old (missing) device, from his own laptop/IP.
    u.recentSignIns = [
      { time: ago(10), ip: '10.10.20.51', location: 'Denver, US', app: 'WorkSuite Mail', result: 'failure', reason: 'MFA not satisfied (no response)', device: 'DEN-LT-1051', mfa: 'failed' },
      { time: ago(14), ip: '10.10.20.51', location: 'Denver, US', app: 'WorkSuite Mail', result: 'failure', reason: 'MFA not satisfied (no response)', device: 'DEN-LT-1051', mfa: 'failed' },
      { time: daysAgo(3), ip: '10.10.20.51', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1051', mfa: 'satisfied' },
    ];
  },
  contactWith: 'dkim',
  contact: [
    { id: 'empid', question: 'Can you confirm your employee ID for verification?', answer: '"It\'s E10111."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll verify you with a callback to the desk number on file — or your manager can confirm. OK?', answer: 'You call 303-555-1212 (the number on record) at his desk and he answers; Sarah Turner (his manager) is also next to him and confirms. Verified.', purpose: 'verify' },
    { id: 'whatchanged', question: 'What changed — new phone number too, or same number on a new device?', answer: '"Same number, brand-new phone. The Authenticator app was never restored, so I have no codes and no prompts."', purpose: 'clarify', reveals: 'new-device-cause' },
    { id: 'oldphone', question: 'Any chance the old phone still works or could be logged in by someone else?', answer: '"No, it\'s gone for good — screen was cracked, I recycled it. Nobody has it."', purpose: 'clarify' },
    { id: 'ceo', question: 'Sure, and you want me to reset the CEO\'s MFA too since she asked?', answer: '"Yeah, Diane said just go ahead and do hers, she\'s in the air."  — (KB-0001: never reset MFA for a third party on someone else\'s say-so. The CEO must call/verify herself. Decline this part.)', purpose: 'red_flag' },
    { id: 'parking', question: 'Did you have a good weekend?', answer: '"It was fine, thanks — can we fix the login?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the caller-verification SOP (KB-0001)', match: { tool: 'kb', action: 'read', target: 'KB-0001' }, hint: 'Identity verification is required before ANY account change, including MFA.' },
    { id: 'view', label: 'Opened David\'s account in the Directory', match: { tool: 'directory', action: 'view', target: 'dkim' } },
    { id: 'signins', label: 'Reviewed the sign-in log (MFA timeouts from his own laptop, not an attacker)', match: { tool: 'directory', action: 'view_signins', target: 'dkim' }, hint: 'Are the failed MFA prompts from his own device/IP, or from somewhere strange?' },
  ],
  required: [
    { id: 'reset_mfa', label: 'Reset the MFA factors so he can re-enroll the new phone', match: { tool: 'directory', action: 'reset_mfa', target: 'dkim' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'mfa_no_verify', label: 'Reset MFA before verifying identity', why: 'Identity must be verified with two factors before any account change, MFA included (KB-0001).', match: { tool: 'directory', action: 'reset_mfa', target: 'dkim' }, unlessAfter: 'verify_gate', skill: 'security', penalty: 0.5 },
    { id: 'reset_ceo', label: 'Reset the CEO\'s MFA on David\'s say-so', why: 'Never reset MFA for a third party because a caller relays a request. The CEO must call and verify herself (KB-0001 red flag: reset for someone else).', match: { tool: 'directory', action: 'reset_mfa', target: 'dvance' }, skill: 'security', penalty: 0.6 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Thanks David — I verified you by employee ID and a callback with Sarah confirming. I\'ve cleared your MFA registrations; you\'ll be prompted to enroll your new phone at the next sign-in, so open the Authenticator and follow the setup prompt. On Diane\'s: I can\'t reset an executive\'s MFA on a relayed request — please have her call us directly and we\'ll verify and help her.', scores: { communication: 1, security: 1 }, feedback: 'Verified, fixed the real problem (re-enroll the new device), and correctly refused the third-party reset.' },
    { id: 'r_both', text: 'No problem — I\'ve reset your MFA and Diane\'s too so you\'re both good to go.', scores: { communication: 0.4, security: 0.1 }, feedback: 'Resetting the CEO\'s MFA on a caller\'s say-so is exactly the social-engineering move KB-0001 warns about.' },
    { id: 'r_stall', text: 'MFA resets can only be done in person at the IT desk with your badge.', scores: { communication: 0.4, security: 0.6 }, feedback: 'Over-strict: employee ID plus a manager-confirmed callback satisfies KB-0001. This needlessly blocks the user.' },
  ],
  notesRubric: [
    { label: 'the verification method used (two factors)', pattern: /(employee id|e10111).*(callback|manager|sarah|turner)|(callback|manager).*(employee id|e10111)|two factor|verified/i },
    { label: 'the cause (new phone, authenticator not restored)', pattern: /new phone|authenticator|re-?enroll|not restored|lost phone|new device/i },
    { label: 'the action taken (MFA reset + re-enroll)', pattern: /reset.*mfa|mfa.*reset|cleared.*(factor|registration)|re-?enroll/i },
    { label: 'declined the third-party (CEO) reset', pattern: /ceo|diane|dvance|third party|declined|her (own )?self|call (us )?directly/i },
  ],
  closure: { disposition: 'resolve', category: 'Identity - MFA Reset', resolutionCode: 'MFA reset for re-enrollment (verified)' },
  categoryAccept: ['identity', 'mfa', 'access', 'account'],
  resolutionCodeAccept: ['mfa', 'reset', 're-enroll', 'reenroll'],
  hints: [
    'Verify first (KB-0001): two factors, e.g. employee ID plus a callback or manager confirmation.',
    'Check the sign-in log — the MFA timeouts are from his own laptop, so this is a lost device, not an attack.',
    'The fix is to reset his MFA factors so the new phone can enroll; walk him through the enroll prompt.',
    'Do NOT reset the CEO\'s MFA because David asked — she must verify herself.',
  ],
  debrief: 'A new-phone MFA reset is routine, but only after verification. David checks out (employee ID + manager-confirmed callback) and the failed prompts come from his own laptop, so resetting his factors to re-enroll the new device is correct. The trap is the tacked-on request to reset the CEO\'s MFA "because she asked" — a textbook social-engineering vector. Never reset MFA for a third party on a relayed request; make the executive call and verify herself.',
};

// ---------------------------------------------------------------------------
// SD1-07  Finance printer queue stuck for the whole team
// ---------------------------------------------------------------------------
const sd1_07: Scenario = {
  id: 'sd1-07',
  tier: 'sd1',
  title: 'The Finance printer queue is stuck for everyone',
  category: 'Networking',
  difficulty: 2,
  estMinutes: 7,
  objective: 'Discriminate a stuck print QUEUE (a Service Desk fix on the print server) from a dead physical printer (a Facilities job), and clear the queue for the whole team.',
  intake: {
    kind: 'ticket', number: 'INC457707', subject: 'Finance printer is dead - nothing prints for anyone up here',
    body: 'Phone call from Bhavik Patel (Senior Accountant): "The Finance printer on 3F has stopped for the whole team. Everyone\'s jobs just pile up and nothing comes out. We\'ve got month-end packets to print. The printer itself looks fine — screen is on, no error, no jam."',
    requester: 'bpatel', channel: 'phone', priority: 'P3', category: 'Hardware', openedAt: ago(10), affectedHost: 'DEN-LT-1042',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const ps = w.servers.find((s) => s.id === 'DEN-PRINT01')!;
    const q = ps.printQueues!.find((p) => p.name === 'DEN-PRN-Finance')!;
    q.status = 'paused';
    q.jobs = 17;
    q.error = 'Queue paused by administrator; 17 jobs held.';
    // Red herring: an unrelated benign spooler warning on the server.
    ps.events.push({ id: 372, time: ago(120), level: 'Warning', source: 'PrintService', log: 'System', message: 'The printer DEN-PRN-2F-Copier was paused for 2 minutes during a routine firmware sync (auto-resumed).' });
  },
  contactWith: 'bpatel',
  contact: [
    { id: 'howmany', question: 'Is it just you, or the whole Finance team on that printer?', answer: '"The whole team — nobody on 3F can print. The 2F copier works fine if we walk down there."', purpose: 'clarify', reveals: 'scope-team' },
    { id: 'panel', question: 'On the printer\'s own panel — any error, amber light, paper/toner warning?', answer: '"No, it says Ready. Green light. Plenty of paper. It just doesn\'t print."', purpose: 'clarify', reveals: 'printer-ok' },
    { id: 'jobs', question: 'When you print, does the job leave your queue or does it sit there?', answer: '"It sits in the queue forever. Says \'spooling\' then nothing."', purpose: 'clarify' },
    { id: 'when', question: 'When did it start, and did anyone touch the printer settings?', answer: '"Maybe an hour ago. Not that I know of."', purpose: 'clarify' },
    { id: 'coffee', question: 'Is the break-room coffee machine working up there?', answer: '"...what? Yes? Please just fix the printer."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the printer troubleshooting SOP (KB-0008)', match: { tool: 'kb', action: 'read', target: 'KB-0008' }, hint: 'The SOP tells you how to tell a queue problem from a physical printer problem.' },
    { id: 'queue', label: 'Checked the print queue on DEN-PRINT01 and found DEN-PRN-Finance paused with jobs held', match: { tool: 'server', action: 'view_print_queues', target: 'DEN-PRINT01' }, hint: 'Server Room > DEN-PRINT01 > Print Queues. Is the Finance queue ready, or paused/errored?' },
  ],
  required: [
    { id: 'resume', label: 'Resumed (or cleared) the paused Finance queue on the print server', match: [{ tool: 'server', action: 'resume_queue', target: 'DEN-PRINT01', params: { queue: /finance/i } }, { tool: 'server', action: 'clear_queue', target: 'DEN-PRINT01', params: { queue: /finance/i } }], skill: 'technical' },
  ],
  forbidden: [
    { id: 'facilities', label: 'Escalated to Facilities as a broken physical printer', why: 'The printer panel is healthy and the queue is paused on the server — this is a queue fix, not a jam/toner call. Escalating to Facilities loses time on a printer that is fine (KB-0008).', match: { tool: 'ticket', action: 'reply', target: 'r_facilities' }, skill: 'process', penalty: 0.3 },
    { id: 'wrong_queue', label: 'Paused or cleared the wrong (2F copier) queue', why: 'DEN-PRN-2F-Copier is working normally. Touching it disrupts another team and does not fix Finance.', match: [{ tool: 'server', action: 'pause_queue', target: 'DEN-PRINT01', params: { queue: /copier|2f/i } }, { tool: 'server', action: 'clear_queue', target: 'DEN-PRINT01', params: { queue: /copier|2f/i } }], skill: 'technical', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Found it — the DEN-PRN-Finance queue on the print server was paused, so all 17 jobs were held. I\'ve resumed the queue and your held jobs are printing now. The printer hardware itself was fine; nothing to do on your end. If it happens again, let us know and we\'ll look at what paused it.', scores: { communication: 1, technical: 1 }, feedback: 'Correctly isolated a paused queue, fixed it centrally for the whole team, and reassured that the hardware is fine.' },
    { id: 'r_facilities', text: 'Sounds like the printer\'s hardware — I\'ll log it with Facilities to come look at the unit.', scores: { communication: 0.3, process: 0.1 }, feedback: 'The panel reads Ready and the queue is paused on the server; this is a Service Desk queue fix, not a Facilities repair.' },
    { id: 'r_local', text: 'Please have each person on the team remove and re-add the printer on their own PC.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'A whole-team stoppage points at the shared queue, not every individual PC. Re-adding the printer for a dozen people fixes nothing.' },
  ],
  notesRubric: [
    { label: 'the scope (whole Finance team, one shared queue)', pattern: /whole team|finance team|everyone|team|shared queue|all users/i },
    { label: 'the cause (queue paused / jobs held on the print server)', pattern: /paus|queue|held|stuck|spool|17 jobs/i },
    { label: 'the action (resumed/cleared the queue on DEN-PRINT01)', pattern: /resum|clear|print server|den-print01|queue/i },
    { label: 'ruled out the physical printer', pattern: /panel|ready|hardware.*fine|no (error|jam)|printer.*ok|not facilities/i },
  ],
  closure: { disposition: 'resolve', category: 'Printers - Print Queue', resolutionCode: 'Resumed paused Finance queue on print server' },
  categoryAccept: ['printer', 'print', 'queue'],
  resolutionCodeAccept: ['queue', 'resum', 'clear', 'print'],
  hints: [
    'First: one user or the whole team? That points at a shared queue vs. one PC (KB-0008).',
    'The printer panel reads Ready with no error — so the hardware is not the problem.',
    'Server Room > DEN-PRINT01 > Print Queues. The Finance queue is paused with jobs held.',
    'Resume (or clear) that queue on the server. Do not send this to Facilities.',
  ],
  debrief: 'The key discrimination in KB-0008 is queue vs. hardware. A whole-team stoppage with a healthy printer panel and jobs piling up in a "spooling" state is a paused/stuck queue on the print server — a Service Desk fix you make centrally by resuming the queue. The traps were escalating to Facilities (the printer is fine) and telling a dozen people to re-add the printer. Had the panel shown offline/jam/toner, that flips to a Facilities job.',
};

// ---------------------------------------------------------------------------
// SD1-08  Laptop crawling, out of disk space (not a reimage)
// ---------------------------------------------------------------------------
const sd1_08: Scenario = {
  id: 'sd1-08',
  tier: 'sd1',
  title: 'My laptop is crawling and I\'m out of disk space',
  category: 'Windows',
  difficulty: 2,
  estMinutes: 8,
  objective: 'Diagnose a slow, full-disk laptop to a real cause (a runaway process and bloated temp/Downloads), reclaim space, and avoid the reflex escalation to a reimage.',
  intake: {
    kind: 'ticket', number: 'INC457708', subject: 'Laptop is crawling and Windows says I\'m out of disk space',
    body: 'Portal ticket from David Kim (Recruiter): "My laptop has slowed to a crawl the last two days and now I get \'low disk space\' warnings constantly. Apps take forever to open. Do I need a new machine or a reinstall?"',
    requester: 'dkim', channel: 'portal', priority: 'P2', category: 'Hardware', openedAt: ago(25), affectedHost: 'DEN-LT-1051',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const h = host(w, 'DEN-LT-1051');
    h.disk = { used: 502, size: 512 }; // ~98% full
    // Runaway (but signed/legit) process spewing crash dumps into temp.
    addProc(h, { pid: 6620, name: 'CrashReportUploader.exe', user: 'KESTREL\\dkim', cpu: 24, mem: 610, path: 'C:\\Program Files\\Zoom Workplace\\CrashReportUploader.exe', signed: true, cmdline: 'CrashReportUploader.exe --spool C:\\Users\\dkim\\AppData\\Local\\Temp\\zoomdumps' });
    h.files = [
      { path: 'C:\\Users\\dkim\\AppData\\Local\\Temp\\zoomdumps\\', size: 141000, modified: ago(20) },
      { path: 'C:\\Users\\dkim\\Downloads\\Q3-allhands-recording.mp4', size: 8800, modified: daysAgo(9) },
      { path: 'C:\\Users\\dkim\\Downloads\\candidate-portfolios-archive.zip', size: 6200, modified: daysAgo(4) },
      { path: 'C:\\Windows\\Temp\\', size: 9700, modified: ago(60) },
    ];
    // Red herring: benign DCOM 10016 warning, and a normal OneDrive cache note.
    addEvent(h, { id: 10016, level: 'Warning', source: 'DistributedCOM', log: 'System', message: 'The application-specific permission settings do not grant Local Activation permission for the COM Server application. (Benign, common.)', time: ago(200) });
    addEvent(h, { id: 2013, level: 'Warning', source: 'Srv', log: 'System', message: 'The C: disk is at or near capacity. You may need to delete some files.', time: ago(18) });
  },
  contactWith: 'dkim',
  contact: [
    { id: 'when', question: 'When did it start, and did you install anything or download big files recently?', answer: '"Started two days ago. I did download an all-hands recording and a big zip of candidate portfolios last week, but nothing new installed."', purpose: 'clarify', reveals: 'downloads' },
    { id: 'app', question: 'Is any one app the worst, or is everything slow across the board?', answer: '"Everything\'s slow, but the fan runs constantly and Zoom keeps popping a \'crash report\' thing."', purpose: 'clarify', reveals: 'runaway' },
    { id: 'onedrive', question: 'Are your files in OneDrive/synced, so we can safely clear local temp and Downloads copies?', answer: '"Yeah, my real docs are in OneDrive. The Downloads stuff I can lose once I\'ve grabbed what I need."', purpose: 'clarify' },
    { id: 'warranty', question: 'Roughly how old is the laptop and is it otherwise fine?', answer: '"Couple years, no other issues until this. I don\'t really want to lose two days to a reinstall."', purpose: 'clarify' },
    { id: 'lunch', question: 'What did you have for lunch?', answer: '"...a sandwich? Why?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'procs', label: 'Checked Task Manager and found a runaway process (CrashReportUploader) pinning CPU', match: { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1051' }, hint: 'Remote in and look at the processes — is one app running hot?' },
    { id: 'files', label: 'Looked at the disk and found temp crash-dumps + huge Downloads eating the drive', match: { tool: 'rdp', action: 'view_files', target: 'DEN-LT-1051' }, hint: 'Where is the space going? Check Temp and Downloads.' },
    { id: 'sys', label: 'Confirmed the disk is nearly full', match: { tool: 'rdp', action: 'view_system', target: 'DEN-LT-1051' }, weight: 0.5 },
  ],
  required: [
    { id: 'end_proc', label: 'Ended the runaway crash-uploader process that was filling temp', match: { tool: 'rdp', action: 'end_process', target: 'DEN-LT-1051', params: { name: /crashreportuploader/i } }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'reimage', label: 'Escalated to Desktop for a reimage / told the user to get a new machine', why: 'This is a full disk and a stuck process, not OS corruption. A reimage wastes a day and does not address the runaway app; reclaim space and stop the process first (KB-0004, KB-0012).', match: { tool: 'ticket', action: 'reply', target: 'r_reimage' }, skill: 'process', penalty: 0.3 },
    { id: 'quarantine', label: 'Quarantined the crash uploader as malware', why: 'CrashReportUploader is a signed Zoom component with no EDR alert — it is a misbehaving legit app, not malware. Quarantining a signed binary is the wrong tool (KB-0012).', match: { tool: 'rdp', action: 'quarantine_file', target: 'DEN-LT-1051' }, skill: 'security', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Good news — you don\'t need a new laptop or a reinstall. A Zoom crash-report helper got stuck and filled your Temp folder with ~140 GB of dumps, and a couple of big Downloads (an all-hands recording, a portfolio zip) finished off the drive. I\'ve stopped the runaway process and cleared the temp dumps; once you copy anything you still want out of Downloads I\'ll clean those too and run Disk Cleanup. Your OneDrive files are untouched. It should be back to normal speed.', scores: { communication: 1, technical: 1 }, feedback: 'Names the real cause, reclaims space, avoids a needless reimage, and reassures about data.' },
    { id: 'r_reimage', text: 'Your machine is probably just old and full — I\'ll get Desktop to reimage it or requisition a replacement.', scores: { communication: 0.3, process: 0.1 }, feedback: 'Jumps to the most expensive, slowest fix without diagnosing. The disk is full because of a stuck process, not a bad OS.' },
    { id: 'r_guess', text: 'Try restarting a few times and deleting some files, then let me know if it\'s still slow.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'Punts the diagnosis back to the user. The runaway process will refill Temp after every reboot until you stop it.' },
  ],
  notesRubric: [
    { label: 'the cause (runaway process filling temp + large Downloads)', pattern: /crashreport|runaway|temp|dump|downloads|full disk|disk space/i },
    { label: 'the action (ended the process, reclaimed space)', pattern: /end(ed)? (the )?process|killed|stopped|cleared|deleted|disk cleanup|reclaim/i },
    { label: 'preserved user data (OneDrive / confirmed before deleting)', pattern: /onedrive|synced|backed up|confirmed|kept|before delet/i },
    { label: 'did not reimage', pattern: /no reimage|not a reimage|without reimag|no new (machine|laptop)|avoid.*reimage/i },
  ],
  closure: { disposition: 'resolve', category: 'Endpoint - Performance/Disk', resolutionCode: 'Stopped runaway process, reclaimed disk space' },
  categoryAccept: ['endpoint', 'performance', 'disk', 'windows', 'hardware'],
  resolutionCodeAccept: ['disk', 'space', 'process', 'cleanup', 'reclaim'],
  hints: [
    'Remote in and open Task Manager — look for a process pinning CPU and writing to Temp.',
    'Check where the space went: Temp (crash dumps) and Downloads (a big recording and a zip).',
    'Stop the runaway process, then clear temp and confirm-before-deleting the large Downloads.',
    'Do NOT reimage or requisition a new laptop for a full disk. That is the trap.',
  ],
  debrief: 'A slow, full-disk laptop is a diagnosis, not a hardware death sentence. The space was eaten by a runaway Zoom crash-uploader dumping ~140 GB into Temp, plus a couple of oversized Downloads. Ending the process and reclaiming space fixes it in minutes. Two traps: escalating to a reimage/new machine (expensive and beside the point) and quarantining the uploader as malware — it is a signed, legit app misbehaving, with no EDR alert, so it is a performance issue under KB-0012, not a security one.',
};

// ---------------------------------------------------------------------------
// SD1-09  New hire onboarding (HR-initiated, least privilege)
// ---------------------------------------------------------------------------
const sd1_09: Scenario = {
  id: 'sd1-09',
  tier: 'sd1',
  title: 'New hire starts Monday - please set up their account',
  category: 'Identity',
  difficulty: 2,
  estMinutes: 9,
  objective: 'Onboard a new hire the right way: confirm the request is HR-initiated, provision to the department default, and refuse to add sensitive groups without the data owner\'s approval.',
  intake: {
    kind: 'ticket', number: 'INC457709', subject: 'New Sales hire starts Monday - please set up their account and access',
    body: 'Portal ticket from Sarah Turner (HR): "New hire Katie Adams joins Sales on Monday, reporting to Emily Wright. Please set up her account with the standard Sales access. Her manager mentioned she\'ll also help with vendor payments, so maybe add her to the Finance/AP group too so she\'s ready."',
    requester: 'sturner', channel: 'portal', priority: 'P4', category: 'Request', openedAt: ago(180),
  },
  priorityExpected: 'P4',
  setup: (w) => {
    // Staged account already created by the provisioning job, disabled, no dept groups yet.
    w.users.push({
      id: 'kadams', displayName: 'Katie Adams', title: 'Account Executive', department: 'Sales', manager: 'ewright',
      email: 'kadams@kestreldynamics.com', phone: '303-555-1399', employeeId: 'E10123', location: 'Denver HQ',
      enabled: false, lockedOut: false, passwordLastSet: ago(60), groups: ['All Staff'], lastLogon: ago(60),
      badPwdCount: 0, mfaEnrolled: false, hireDate: '2026-09-21', notes: 'Staged for onboarding INC457709; enable on start date.',
      recentSignIns: [],
    });
    // HR confirmation thread; note it does NOT authorize the AP/Finance add.
    w.chat.push({ id: 'ch-hr-onb', with: 'sturner', messages: [
      { from: 'sturner', time: ago(170), text: 'Confirming onboarding for INC457709: Katie Adams, Account Executive, Sales, manager Emily Wright, start date Mon 9/21. HR-approved for the standard Sales setup.' },
      { from: 'sturner', time: ago(168), text: 'The AP/Finance bit was just something Emily mentioned in passing - I have no data-owner sign-off for that, so only do it if Finance approves it properly.' },
    ] });
  },
  contactWith: 'sturner',
  contact: [
    { id: 'hr_auth', question: 'Confirm this onboarding is HR-initiated and approved', answer: 'Sarah Turner (HR) confirms in chat: Katie Adams, Sales, manager Emily Wright, start 9/21, HR-approved for standard Sales access.', purpose: 'verify' },
    { id: 'mgr', question: 'Who is the hiring manager who approves anything beyond the Sales default?', answer: '"Emily Wright is her manager. Anything past the standard Sales setup needs Emily\'s approval — and Finance\'s for AP."', purpose: 'verify' },
    { id: 'ap_owner', question: 'Do you have Finance/data-owner approval for the AP-Team / Finance group?', answer: '"No — that was just Emily thinking out loud. There\'s no Finance sign-off, so leave it off for now."', purpose: 'clarify', reveals: 'no-ap-approval' },
    { id: 'startdate', question: 'What is the exact start date, and should the account be enabled now or on that day?', answer: '"Starts Monday 9/21. Enable it for her start date; standard Sales access is fine."', purpose: 'clarify' },
    { id: 'desk', question: 'Which desk will she sit at?', answer: '"Not sure yet — Facilities is handling seating."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the onboarding SOP (KB-0006)', match: { tool: 'kb', action: 'read', target: 'KB-0006' }, hint: 'Who may initiate a new hire, and what needs the data owner\'s approval?' },
    { id: 'view', label: 'Opened the staged account for Katie Adams', match: { tool: 'directory', action: 'view', target: 'kadams' } },
    { id: 'group', label: 'Reviewed the AP-Team group to see it is sensitive', match: { tool: 'directory', action: 'view_group', target: /ap-team|finance/i }, weight: 0.5, hint: 'Is the group the manager suggested a sensitive one?' },
  ],
  required: [
    { id: 'add_sales', label: 'Added her to the standard Sales department group', match: { tool: 'directory', action: 'add_group', target: 'kadams', params: { group: /sales/i } }, skill: 'process' },
    { id: 'enable', label: 'Enabled the account for her start date', match: { tool: 'directory', action: 'enable', target: 'kadams' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'add_ap', label: 'Added her to Finance / AP-Team without data-owner approval', why: 'AP-Team and Finance are sensitive groups; membership requires the DATA OWNER\'s approval, not a manager\'s passing suggestion (KB-0006). HR explicitly said there is no sign-off.', match: [{ tool: 'directory', action: 'add_group', target: 'kadams', params: { group: /ap-team|finance/i } }], skill: 'security', penalty: 0.5 },
    { id: 'add_admin', label: 'Added her to an admin / privileged group', why: 'A new sales hire gets least-privilege department access, never *-Admins (KB-0006).', match: [{ tool: 'directory', action: 'add_group', target: 'kadams', params: { group: /admin/i } }], skill: 'security', penalty: 0.5 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Katie\'s account is set up with the standard Sales access and enabled for her Monday start (username and a temp password to hand off per your process). I did NOT add the Finance/AP group — that\'s a sensitive group that needs the data owner\'s (Finance) approval, and there\'s no sign-off yet. If she truly needs AP access, have Emily raise it and I\'ll get Finance to approve, then add it.', scores: { communication: 1, process: 1, security: 1 }, feedback: 'Provisions the department default, and correctly withholds the sensitive group pending proper approval.' },
    { id: 'r_all', text: 'All done — set up Sales access and added her to the Finance/AP group too so she\'s ready to go on day one.', scores: { communication: 0.4, security: 0.1, process: 0.1 }, feedback: 'Adds a sensitive group on a manager\'s casual mention. AP/Finance need the data owner\'s approval; this is exactly the over-provisioning KB-0006 forbids.' },
    { id: 'r_reject', text: 'I can\'t create new accounts from a ticket — have the new hire call us herself once she starts.', scores: { communication: 0.3, process: 0.2 }, feedback: 'Onboarding is HR-initiated and Sarah already approved it; making the new hire self-serve on day one is wrong and unhelpful.' },
  ],
  notesRubric: [
    { label: 'HR-initiated and approved', pattern: /hr|sarah|sturner|approv|authoriz|hr-initiated/i },
    { label: 'provisioned the Sales department default', pattern: /sales|department default|standard access|dept template/i },
    { label: 'withheld the sensitive AP/Finance group (data owner approval)', pattern: /ap|finance|data owner|sensitive|not add|withheld|approval/i },
    { label: 'manager approves anything beyond the default', pattern: /manager|emily|wright|beyond|extra access|approve/i },
  ],
  closure: { disposition: 'resolve', category: 'Identity - Onboarding', resolutionCode: 'Provisioned Sales default (AP withheld pending data-owner approval)' },
  categoryAccept: ['identity', 'onboarding', 'request', 'access'],
  resolutionCodeAccept: ['onboard', 'provision', 'sales', 'account'],
  hints: [
    'KB-0006: new hires are HR-initiated. Confirm Sarah\'s approval (it is in your Chat).',
    'Provision the department default — the Sales group — and enable the staged account for her start date.',
    'The AP/Finance add is a sensitive group. It needs the data owner\'s approval, which nobody has given.',
    'Never add a new hire to a *-Admins or sensitive group on a casual manager mention.',
  ],
  debrief: 'Onboarding rewards least privilege and following the approval chain. HR initiated and approved the standard Sales setup, so you provision the Sales group and enable the account. The landmine is the tacked-on "also add her to Finance/AP so she\'s ready" — AP-Team and Finance are sensitive groups that require the data owner\'s approval under KB-0006, and HR confirmed there is no sign-off. Provision what is approved, and route the sensitive request for proper approval rather than granting it to be helpful.',
};

// ---------------------------------------------------------------------------
// SD1-10  Software install + local admin request (least privilege)
// ---------------------------------------------------------------------------
const sd1_10: Scenario = {
  id: 'sd1-10',
  tier: 'sd1',
  title: 'I need Photoshop installed - and admin rights to install it',
  category: 'Software',
  difficulty: 2,
  estMinutes: 7,
  objective: 'Handle a software request through the approval path and firmly deny a request for standing local admin rights, escalating rather than granting.',
  intake: {
    kind: 'ticket', number: 'INC457710', subject: 'Please install Photoshop - or just give me local admin so I can do it myself',
    body: 'Portal ticket from Jordan Webb (Marketing Coordinator): "I need Adobe Photoshop for some campaign graphics. Honestly it\'d be easier if you just made me a local admin on my laptop so I can install this and other tools myself without opening a ticket every time. Can you set that up today?"',
    requester: 'jwebb', channel: 'portal', priority: 'P3', category: 'Request', openedAt: ago(30), affectedHost: 'DEN-LT-1070',
  },
  priorityExpected: 'P4',
  setup: (w) => {
    const u = findUser(w, 'jwebb')!;
    u.notes = 'Requested Photoshop + standing local admin.';
    // Confirm the account is a standard user (not privileged) so the admin ask is a real escalation of rights.
    u.privileged = undefined;
  },
  contactWith: 'jwebb',
  contact: [
    { id: 'need', question: 'What exactly do you need the software for, and is Photoshop specifically required or would our licensed design tools work?', answer: '"Campaign graphics — resizing, retouching. Photoshop specifically; the free tools don\'t cut it. Marketing has a budget code for Adobe."', purpose: 'clarify', reveals: 'business-need' },
    { id: 'admin_why', question: 'Why local admin rather than us pushing the app? What else would you install?', answer: '"Just so I don\'t have to wait on tickets — Photoshop now, and whatever plugins/tools come up later."', purpose: 'clarify', reveals: 'standing-admin' },
    { id: 'mgr', question: 'Has your manager approved the Adobe license/cost?', answer: '"Emily\'s fine with it — she said to put it on the Marketing budget."', purpose: 'clarify' },
    { id: 'timeline', question: 'How soon do you need it — is there a deadline?', answer: '"This week would be great, nothing on fire today."', purpose: 'clarify' },
    { id: 'font', question: 'What\'s your favorite font?', answer: '"Ha - Helvetica, I guess? Anyway, about the install..."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb_esc', label: 'Read the escalation matrix (KB-0004) - what SD1 may and may not grant', match: { tool: 'kb', action: 'read', target: 'KB-0004' }, hint: 'What access requests can Tier 1 fulfil, and what needs approval/escalation?' },
    { id: 'view', label: 'Opened Jordan\'s account and confirmed she is a standard user', match: { tool: 'directory', action: 'view', target: 'jwebb' } },
    { id: 'admins', label: 'Checked the laptop\'s local administrators', match: { tool: 'rdp', action: 'view_local_admins', target: 'DEN-LT-1070' }, weight: 0.5, hint: 'Who is already a local admin on the machine?' },
  ],
  required: [
    { id: 'route', label: 'Routed the software request for approval / escalated rather than granting admin', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'grant_admin', label: 'Granted standing local admin rights', why: 'Standing local admin on a user endpoint violates least privilege (KB-0004/KB-0006). Software is deployed via Software Center with approval; admin is not handed out for convenience.', match: [{ tool: 'directory', action: 'add_group', target: 'jwebb', params: { group: /admin/i } }], skill: 'security', penalty: 0.6 },
    { id: 'resolve_grant', label: 'Told the user they now have admin / promised admin rights', why: 'Promising standing admin, even informally, is the wrong answer. Deny the admin, route the software.', match: { tool: 'ticket', action: 'reply', target: 'r_admin' }, skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Happy to get you Photoshop — I\'m routing it through Software Center with the Adobe license approval (Emily\'s budget note helps). What I can\'t do is make you a standing local admin: that\'s against our least-privilege policy for everyone\'s security, and it isn\'t needed. When you need a tool, raise it and we\'ll package and push it — usually same day. I\'ve escalated the Photoshop deployment now.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Meets the real need (the software) through the right path, and denies standing admin clearly and kindly.' },
    { id: 'r_admin', text: 'Done — I\'ve made you a local admin so you can install Photoshop and whatever else you need yourself.', scores: { communication: 0.4, security: 0.1, process: 0.1 }, feedback: 'Standing local admin for convenience is exactly what least privilege prohibits; it lets malware run with her rights and is the classic bad grant.' },
    { id: 'r_flatdeny', text: 'We don\'t install Photoshop. Please use the free tools that are already on your machine.', scores: { communication: 0.3, process: 0.3 }, feedback: 'Refuses a legitimate, manager-backed business need. The answer is to route the software, not to stonewall it.' },
  ],
  notesRubric: [
    { label: 'the legitimate software need (Photoshop, manager/budget)', pattern: /photoshop|adobe|software|license|marketing|budget/i },
    { label: 'routed via Software Center / approval path', pattern: /software center|approval|deploy|package|push|route|escalat/i },
    { label: 'denied standing local admin (least privilege)', pattern: /local admin|least privilege|deny|denied|not grant|no admin|standing admin/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'sd2', category: 'Access - Software Request', resolutionCode: 'Software routed for deployment; local admin denied' },
  categoryAccept: ['access', 'software', 'request'],
  resolutionCodeAccept: ['software', 'route', 'escalat', 'deploy', 'admin denied'],
  hints: [
    'Separate the two asks: a legitimate software need vs. a request for standing admin rights.',
    'KB-0004: software is deployed with approval; SD1 does not hand out local admin.',
    'Route Photoshop through Software Center / deployment with the manager\'s budget approval.',
    'Deny the local-admin request outright — least privilege. Do not add her to any admin group.',
  ],
  debrief: 'Two requests are bundled: a reasonable one (Photoshop, manager-backed) and an unreasonable one (standing local admin "for convenience"). Fulfil the first through the approval and deployment path; deny the second on least-privilege grounds. Standing local admin lets any malware run with the user\'s elevated rights and is a top audit finding — never grant it for convenience. The wrong answers were granting admin (dangerous) and flatly refusing the software (unhelpful and misses a real need).',
};

// ---------------------------------------------------------------------------
// SD1-11  Can't connect to Wi-Fi (on Guest-WiFi instead of Kestrel-Corp)
// ---------------------------------------------------------------------------
const sd1_11: Scenario = {
  id: 'sd1-11',
  tier: 'sd1',
  title: 'Can\'t connect to Wi-Fi from the Denver office',
  category: 'Networking',
  difficulty: 1,
  estMinutes: 6,
  objective: 'Scope a single-user "no network" report, spot that the laptop is on the Guest SSID with no internal access, and reconnect it to the corporate network without over-escalating.',
  intake: {
    kind: 'ticket', number: 'INC457711', subject: 'Can\'t get to any of our systems from the Denver office Wi-Fi',
    body: 'Chat from Jordan Webb (Marketing): "I\'m in the Denver office but I can\'t reach the intranet, the file share, or ERP. The Wi-Fi says I\'m connected and I can browse regular websites, but nothing internal works. It was fine yesterday."',
    requester: 'jwebb', channel: 'chat', priority: 'P3', category: 'Network', openedAt: ago(15), affectedHost: 'DEN-LT-1070',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const h = host(w, 'DEN-LT-1070');
    // Laptop joined the Guest SSID: gets a 10.10.50.x lease, public DNS, no internal access.
    h.network.ssid = 'Guest-WiFi';
    h.network.ip = '10.10.50.63';
    h.ip = '10.10.50.63';
    h.network.gateway = '10.10.50.1';
    h.network.dns = ['1.1.1.1', '8.8.8.8'];
    h.network.adapterStatus = 'up';
  },
  contactWith: 'jwebb',
  contact: [
    { id: 'others', question: 'Is anyone near you having the same problem, or just you?', answer: '"Just me, I think. The person next to me is on our systems fine."', purpose: 'clarify', reveals: 'single-user' },
    { id: 'internet', question: 'Can you browse the regular internet, and does the Wi-Fi name look right?', answer: '"Internet works fine. The network is... \'Guest-WiFi\'? I might have tapped that when mine dropped yesterday."', purpose: 'clarify', reveals: 'guest-ssid' },
    { id: 'yesterday', question: 'What changed since yesterday when it worked?', answer: '"My Wi-Fi blipped in a meeting and I reconnected to whatever popped up. Didn\'t think about it."', purpose: 'clarify' },
    { id: 'wired', question: 'Are you on Wi-Fi or plugged into a dock/ethernet?', answer: '"Just Wi-Fi, no dock right now."', purpose: 'clarify' },
    { id: 'snack', question: 'Is the vending machine on your floor restocked?', answer: '"No idea - can we stick to the Wi-Fi thing?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the no-network SOP (KB-0007)', match: { tool: 'kb', action: 'read', target: 'KB-0007' }, hint: 'The SOP calls out the Guest vs. corporate SSID distinction.' },
    { id: 'net', label: 'Checked the network config and saw the Guest SSID / 10.10.50.x address', match: [{ tool: 'rdp', action: 'view_network', target: 'DEN-LT-1070' }, { tool: 'terminal', action: 'ipconfig_all', target: 'DEN-LT-1070' }, { tool: 'terminal', action: 'ipconfig', target: 'DEN-LT-1070' }], hint: 'Which SSID is she on, and what IP did she get? Guest is 10.10.50.x.' },
  ],
  required: [
    { id: 'resolve', label: 'Resolved the ticket by having her reconnect to Kestrel-Corp', match: { tool: 'ticket', action: 'submit' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'escalate_net', label: 'Escalated to the Network team as an outage', why: 'This is one user on the wrong SSID, not a network fault. Escalating a self-service reconnect wastes the Network team\'s time (KB-0007).', match: { tool: 'ticket', action: 'reply', target: 'r_network' }, skill: 'process', penalty: 0.3 },
    { id: 'reset_pw', label: 'Reset her password as if this were a sign-in problem', why: 'She is authenticated and online — this is an SSID/routing issue, not credentials. A password reset does nothing and disrupts her.', match: { tool: 'directory', action: 'reset_password', target: 'jwebb' }, skill: 'technical', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Found it — your laptop is on the "Guest-WiFi" network (you picked it up when your Wi-Fi blipped yesterday). Guest has internet but no access to our internal systems by design, which is why the intranet, share, and ERP are unreachable. Click the Wi-Fi icon, forget "Guest-WiFi", and reconnect to "Kestrel-Corp" — you\'ll get a 10.10.20.x address and everything internal will come back. Ping me if it doesn\'t.', scores: { communication: 1, technical: 1 }, feedback: 'Pinpoints the SSID cause, explains why internal access failed, and gives a clear self-service fix.' },
    { id: 'r_network', text: 'Sounds like a network outage — I\'ll escalate this to the Network team to look at the Wi-Fi.', scores: { communication: 0.3, process: 0.1 }, feedback: 'One user on the Guest SSID is not an outage. Escalating a reconnect is over-reach.' },
    { id: 'r_reboot', text: 'Please reboot your laptop and your router and let me know.', scores: { communication: 0.2, technical: 0.2 }, feedback: 'There is no user router, and a reboot leaves her on the Guest SSID. It changes nothing.' },
  ],
  notesRubric: [
    { label: 'the scope (single user, others fine)', pattern: /single|one user|just (her|me|jordan)|others (are )?fine|not an outage/i },
    { label: 'the cause (on Guest-WiFi / wrong SSID, no internal access)', pattern: /guest|ssid|wrong (network|wi-?fi)|10\.10\.50|no internal/i },
    { label: 'the fix (reconnect to Kestrel-Corp)', pattern: /kestrel-corp|reconnect|forget.*network|switch (ssid|network)|corporate wi-?fi/i },
  ],
  closure: { disposition: 'resolve', category: 'Network - Wireless', resolutionCode: 'Reconnected to corporate SSID (was on Guest)' },
  categoryAccept: ['network', 'wireless', 'wifi', 'wi-fi'],
  resolutionCodeAccept: ['ssid', 'wireless', 'wifi', 'reconnect', 'corporate'],
  hints: [
    'First: one user or many? Others near her are fine, so this is a single-user issue (KB-0007).',
    'Check the SSID and IP. Guest-WiFi hands out 10.10.50.x with public DNS and no internal access.',
    'The fix is to forget Guest-WiFi and reconnect to Kestrel-Corp. No escalation needed.',
    'Do not reset her password — she is online and authenticated; this is an SSID issue.',
  ],
  debrief: 'The tell is "internet works but nothing internal does": classic Guest-SSID symptom. Guest-WiFi (10.10.50.0/24) is deliberately isolated from corporate resources, so a user who drifts onto it after a Wi-Fi blip loses the intranet, shares, and ERP while keeping plain internet. Scope it as a single user, confirm the SSID, and walk her back onto Kestrel-Corp. The traps were escalating a one-user reconnect to the Network team and treating an SSID problem as a credential problem.',
};

// ---------------------------------------------------------------------------
// SD1-12  Found USB in the parking lot, plugged it in (USB drop -> SOC)
// ---------------------------------------------------------------------------
const sd1_12: Scenario = {
  id: 'sd1-12',
  tier: 'sd1',
  title: 'I found a USB drive in the parking lot and plugged it in',
  category: 'Security',
  difficulty: 3,
  estMinutes: 8,
  objective: 'Recognize an unknown-USB "drop" as a security event, escalate to Security without browsing or executing anything on the device, and coach the user.',
  intake: {
    kind: 'ticket', number: 'INC457712', subject: 'Found a USB stick outside - plugged it in to find the owner',
    body: 'Chat from Pat Cole (Receptionist): "I found a USB drive in the parking lot this morning and plugged it into my PC to see whose it is. There\'s a folder called \'Q3 Bonuses\' and a couple of files. Should I open them to find a name? It also popped up some window for a second."',
    requester: 'pcole', channel: 'chat', priority: 'P4', category: 'Hardware', openedAt: ago(8), affectedHost: 'DEN-WS-2001',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const h = host(w, 'DEN-WS-2001');
    h.notes = 'User plugged an unknown USB found in the parking lot; a window flashed on insert.';
    // The removable drive appears as a device; a flashed window on insert is a classic drop tell.
    h.devices.push({ name: 'SanDisk Cruzer USB Device (removable)', class: 'Disk drives', status: 'ok', driver: '10.0.22621.1' });
    addEvent(h, { id: 20001, level: 'Information', source: 'Microsoft-Windows-Ntfs', log: 'System', message: 'A removable volume (E:) was mounted: SanDisk Cruzer. Unknown device, first seen on this host.', time: ago(9) });
    // Red herring: benign DCOM warning unrelated to the USB.
    addEvent(h, { id: 10016, level: 'Warning', source: 'DistributedCOM', log: 'System', message: 'The application-specific permission settings do not grant Local Activation permission. (Benign, common.)', time: ago(200) });
  },
  contactWith: 'pcole',
  contact: [
    { id: 'opened', question: 'Have you opened any of the files or run anything on the drive yet?', answer: '"Not yet — well, a black window flashed when I plugged it in, then closed. I haven\'t double-clicked the files."', purpose: 'clarify', reveals: 'autorun-flash' },
    { id: 'still_in', question: 'Is the drive still plugged in right now?', answer: '"Yeah, it\'s still in the front USB port."', purpose: 'clarify' },
    { id: 'where', question: 'Where exactly did you find it, and did anyone hand it to you?', answer: '"Just lying in the parking lot by the front entrance. Nobody gave it to me."', purpose: 'clarify', reveals: 'drop' },
    { id: 'files', question: 'Sure, go ahead and open the files to look for a name, right?', answer: '"I can if you want..."  — (Do NOT advise opening files on an unknown drive; that can execute malware. This is the wrong instruction.)', purpose: 'red_flag' },
    { id: 'brand', question: 'What brand is the USB stick?', answer: '"Some SanDisk one, red and black. Does that matter?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb_esc', label: 'Read the escalation matrix - who owns removable-media / security events (KB-0004)', match: { tool: 'kb', action: 'read', target: 'KB-0004' }, hint: 'Who owns "anything that smells like an attack," including dropped devices?' },
    { id: 'kb_mal', label: 'Read the malware/endpoint SOP - do not clean, do not reboot, preserve evidence (KB-0012)', match: { tool: 'kb', action: 'read', target: 'KB-0012' }, hint: 'When something might be malicious, what must you NOT do at Tier 1?' },
  ],
  required: [
    { id: 'escalate_soc', label: 'Escalated to Security (SOC) as a removable-media security event', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
    { id: 'priority', label: 'Set the priority to P2 (possible security incident)', match: { tool: 'ticket', action: 'set_priority', params: { priority: 'P2' } }, skill: 'security' },
  ],
  forbidden: [
    { id: 'browse', label: 'Browsed the files on the unknown USB drive', why: 'Opening or previewing files on a dropped USB can execute malware and contaminates evidence. Do not browse it; escalate to Security (KB-0012).', match: [{ tool: 'rdp', action: 'view_files', target: 'DEN-WS-2001' }], skill: 'security', penalty: 0.5 },
    { id: 'advise_open', label: 'Told the user to open the files to find the owner', why: 'Advising the user to open files on an unknown drive is the exact wrong move — that is how baiting attacks land. Tell them to stop and leave it (KB-0012).', match: { tool: 'ticket', action: 'reply', target: 'r_open' }, skill: 'security', penalty: 0.5 },
    { id: 'clean', label: 'Treated it as routine adware and ran a scan/quarantine yourself', why: 'A dropped USB with an autorun flash is a possible targeted attack, not routine PUA — do not clean or reboot; preserve it and hand to Security (KB-0012).', match: [{ tool: 'rdp', action: 'run_scan', target: 'DEN-WS-2001' }, { tool: 'rdp', action: 'quarantine_file', target: 'DEN-WS-2001' }], skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Thanks for flagging this — please DON\'T open any of the files. A USB found in the parking lot is a known attack trick (someone hopes a person plugs it in), and the window that flashed suggests something may have auto-run. Leave the drive in and don\'t touch it, don\'t reboot, and step away from opening anything. I\'m escalating this to our Security team as a priority; they\'ll take it from here and check your PC. You did the right thing telling us.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Names the risk, stops the user, preserves evidence, and escalates to Security at the right priority.' },
    { id: 'r_open', text: 'Good thinking — go ahead and open the files to find a name so we can return it, then let me know who it belongs to.', scores: { communication: 0.4, security: 0.05 }, feedback: 'This is the trap: opening files on a dropped USB is exactly how baiting attacks execute. Never advise this.' },
    { id: 'r_routine', text: 'No worries — just run a quick antivirus scan on the drive and delete anything it flags, you\'re fine.', scores: { communication: 0.4, security: 0.2 }, feedback: 'Treats a possible targeted drop as routine cleanup. Do not clean or scan it yourself; Security must triage and preserve evidence.' },
  ],
  notesRubric: [
    { label: 'the nature (unknown USB found/dropped, plugged in, window flashed)', pattern: /usb|removable|parking lot|dropped|found|autorun|flash/i },
    { label: 'the security judgment (baiting / possible malware, do not open)', pattern: /bait|attack|malware|do not open|don.t open|social eng|targeted|suspicious/i },
    { label: 'the action (escalate to Security/SOC, preserve, advise user)', pattern: /security|soc|escalat|preserve|leave it|do not reboot|advis/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'soc', category: 'Security - Removable Media', resolutionCode: 'Escalated to SOC (USB drop), evidence preserved' },
  categoryAccept: ['security', 'removable', 'media', 'usb'],
  resolutionCodeAccept: ['escalat', 'soc', 'security', 'usb', 'removable'],
  hints: [
    'A USB found in a parking lot and plugged in is a classic "USB drop" / baiting attack.',
    'The flashed window on insert suggests something may have auto-run. Treat it as a possible incident.',
    'Do NOT open the files, do NOT reboot, and do NOT run your own cleanup — preserve the evidence (KB-0012).',
    'Escalate to Security (SOC) at P2 and tell the user to leave the drive alone.',
  ],
  debrief: 'This is a "USB drop" (baiting): an attacker leaves a tempting drive - here labelled "Q3 Bonuses" - where a curious employee will plug it in, and the window that flashed on insert is a tell that something auto-ran. The Tier 1 job is not to investigate or "clean" it: escalate to Security at P2, preserve the device and host (no opening files, no reboot, no scan), and coach the user to stop. The traps were the helpful-but-fatal instinct to open the files to find the owner, and treating it as routine adware. Praise the user for reporting - that instinct is what you want to reinforce.',
};

export const SD1_SCENARIOS_B: Scenario[] = [sd1_06, sd1_07, sd1_08, sd1_09, sd1_10, sd1_11, sd1_12];
