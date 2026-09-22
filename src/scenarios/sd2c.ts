import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, breakInternet, breakDns, lockOut } from './helpers';

// ---------------------------------------------------------------------------
// SD2-11  Malware WITH an active EDR alert - preserve and escalate (do NOT clean)
// (Deliberate contrast with SD2-02, where EDR was silent and SD cleaned it.)
// ---------------------------------------------------------------------------
const sd2_11: Scenario = {
  id: 'sd2-11',
  tier: 'sd2',
  title: 'Suspicious process on an engineer\'s PC - and Halberd EDR is alerting',
  category: 'Security',
  difficulty: 3,
  estMinutes: 13,
  objective: 'Apply the KB-0012 go/no-go the other way from the adware case: when Halberd EDR has an alert and there is real persistence and C2, STOP - do not clean or reboot, preserve the evidence, and escalate to Security.',
  intake: {
    kind: 'ticket', number: 'INC457721', subject: 'Weird process and my antivirus popped a warning',
    body: 'Escalated from SD1. Owen Bennett (Design Engineer, DEN-WS-2011) noticed his fan spinning and a process he doesn\'t recognise, plus a Halberd EDR toast. SD1 was about to "just kill it and reboot" and escalated instead. Halberd EDR shows an ACTIVE alert for this host.',
    requester: 'obennett', channel: 'phone', priority: 'P3', category: 'Malware', openedAt: ago(22), affectedHost: 'DEN-WS-2011',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const h = host(w, 'DEN-WS-2011');
    // Real malware: unsigned binary running from AppData, scheduled-task persistence,
    // beaconing to a known-bad C2, and an ACTIVE Halberd EDR alert.
    addProc(h, { pid: 8123, name: 'svch0st.exe', user: 'KESTREL\\obennett', cpu: 18, mem: 140, path: 'C:\\Users\\obennett\\AppData\\Roaming\\Microsoft\\svch0st.exe', cmdline: 'svch0st.exe -w hidden', signed: false, parentPid: 3120, started: ago(60 * 3), hash: 'e3b0c44298fc1c149afbf4c8996fb924' });
    h.files.push({ path: 'C:\\Users\\obennett\\AppData\\Roaming\\Microsoft\\svch0st.exe', size: 288000, modified: ago(60 * 3), signed: false, suspicious: true });
    h.scheduledTasks.push({ name: 'MicrosoftEdgeUpdateHealth', path: '\\Microsoft\\', action: 'C:\\Users\\obennett\\AppData\\Roaming\\Microsoft\\svch0st.exe', trigger: 'At logon + every 30 min', author: 'KESTREL\\obennett', suspicious: true });
    // Active EDR alert on this host.
    w.alerts.push({
      id: 'ALT-40231', time: ago(20), severity: 'high', source: 'edr',
      title: 'Suspicious unsigned binary with persistence (svch0st.exe)',
      description: 'Halberd EDR: unsigned process launched from AppData\\Roaming with a masquerading name, created a scheduled task, and made outbound connections to a low-reputation host. Detection: Behavior:Win32/Persist.C2.',
      host: 'DEN-WS-2011', user: 'obennett', indicators: ['svch0st.exe', '185.242.7.31', 'update-cdn-sync.net'],
      mitre: ['T1547.001', 'T1071.001'], status: 'new', truth: 'true_positive',
    });
    // Beacon to a malicious C2 + intel says so.
    addLog(w, { time: ago(18), source: 'proxy', host: 'DEN-WS-2011', user: 'obennett', domain: 'update-cdn-sync.net', url: 'https://update-cdn-sync.net/gate.php', action: 'allow', dstPort: 443, message: 'POST https://update-cdn-sync.net/gate.php (beacon, 512B every 30s)', process: 'svch0st.exe' });
    w.intel.push({ indicator: 'update-cdn-sync.net', type: 'domain', verdict: 'malicious', source: 'ThreatFox', tags: ['c2', 'stealer'], firstSeen: daysAgo(6), detail: 'Known command-and-control for a commodity infostealer. Registered 6 days ago; hosted on 185.242.7.31 (bulletproof).' });
    // Red herring: the usual benign Defender PUA informational + base 10016 DCOM.
    addEvent(h, { id: 1116, level: 'Information', source: 'Windows Defender', log: 'Application', message: 'Defender scanned a browser cache item (PUA:Win32/Presenoker) and took no action. Informational; unrelated to the EDR alert.', time: ago(200) });
  },
  contactWith: 'obennett',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10141."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll call you back on the desk number on record before we go further.', answer: 'Callback to the number on record reaches Owen. Verified.', purpose: 'verify' },
    { id: 'origin', question: 'Do you remember downloading or opening anything unusual in the last few hours?', answer: '"I opened a resume PDF a recruiter emailed me, and my machine got loud right after."', purpose: 'clarify', reveals: 'delivery' },
    { id: 'creds', question: 'Have you typed any passwords or approved any prompts since it started?', answer: '"I logged into a couple of sites, yeah. Should I not have?"', purpose: 'clarify', reveals: 'possible-cred-theft' },
    { id: 'stop', question: 'Please stop using it and don\'t shut it down - leave it exactly as it is for now.', answer: '"Okay, I\'ll leave it alone."', purpose: 'clarify', reveals: 'preserved' },
    { id: 'coffee', question: 'How\'s the new CAD workstation treating you otherwise?', answer: '"Fine normally. Why?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the malware/PUA SOP (KB-0012) and hit the STOP condition', match: { tool: 'kb', action: 'read', target: 'KB-0012' }, hint: 'KB-0012 says an EDR alert + persistence + unknown C2 is a hard STOP, not an SD clean.' },
    { id: 'edr', label: 'Confirmed the ACTIVE Halberd EDR alert for this host', match: [{ tool: 'edr', action: 'view_alerts' }, { tool: 'edr', action: 'view_host', target: 'DEN-WS-2011' }], hint: 'Unlike the adware case, EDR is alerting here. That alone changes the answer.' },
    { id: 'procs', label: 'Saw the unsigned process running from AppData\\Roaming', match: [{ tool: 'rdp', action: 'view_processes', target: 'DEN-WS-2011' }, { tool: 'terminal', action: 'tasklist', target: 'DEN-WS-2011' }], hint: 'Where is it running from, and is it signed?' },
    { id: 'persist', label: 'Found the scheduled-task persistence', match: [{ tool: 'rdp', action: 'view_tasks', target: 'DEN-WS-2011' }, { tool: 'terminal', action: 'schtasks', target: 'DEN-WS-2011' }], hint: 'A logon/every-30-min task pointing at the AppData binary = persistence.' },
    { id: 'intel', label: 'Looked up the C2 indicator (malicious)', match: { tool: 'intel', action: 'lookup', target: /update-cdn-sync\.net|185\.242\.7\.31/ }, weight: 0.5 },
  ],
  required: [
    { id: 'escalate', label: 'Preserved the host and escalated to Security (SOC) as P2', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'clean', label: 'Killed / uninstalled / quarantined / scanned the malware yourself', why: 'KB-0012: with an EDR alert, real persistence, and C2, this is a Security case. Killing the process, deleting the task/file, or running a scan destroys the volatile evidence (running process, network state) SOC needs to scope the intrusion. Do not clean it.', match: [{ tool: 'rdp', action: 'end_process', target: 'DEN-WS-2011' }, { tool: 'terminal', action: 'taskkill', target: 'DEN-WS-2011' }, { tool: 'edr', action: 'kill_process', target: 'DEN-WS-2011' }, { tool: 'rdp', action: 'quarantine_file', target: 'DEN-WS-2011' }, { tool: 'rdp', action: 'delete_task', target: 'DEN-WS-2011' }, { tool: 'rdp', action: 'uninstall', target: 'DEN-WS-2011' }, { tool: 'rdp', action: 'run_scan', target: 'DEN-WS-2011' }], skill: 'security', penalty: 0.5 },
    { id: 'reboot', label: 'Rebooted the host', why: 'A reboot wipes memory-resident evidence and can trigger further payloads. Preserve the machine as-is; let Security isolate it in EDR if they choose.', match: { tool: 'rdp', action: 'reboot', target: 'DEN-WS-2011' }, skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This one is different from ordinary adware: Halberd EDR has an active alert, there\'s an unsigned program running from your AppData folder that installed a hidden scheduled task, and it\'s talking to a known-malicious server. That means it\'s a Security matter, not a desktop clean-up. I have NOT killed it or rebooted - doing that would destroy evidence. Please keep the machine on and stop using it. I\'m escalating to the Security team as P2 right now with the alert, the process details, and the malicious address, and since you may have typed passwords while it was running, they\'ll advise on resetting them.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Correctly reads the EDR alert + persistence + C2 as a STOP, preserves evidence, and escalates with the right details.' },
    { id: 'r_clean', text: 'I killed the process, removed the scheduled task, deleted the file and ran a full scan - all clean now.', scores: { communication: 0.3, security: 0.0 }, feedback: 'This is exactly what KB-0012 forbids when EDR is alerting: you\'ve destroyed the evidence and can\'t prove the box is actually clean or whether credentials were stolen.' },
    { id: 'r_reboot', text: 'Let me just reboot it - that usually clears these things up.', scores: { communication: 0.3, security: 0.1 }, feedback: 'A reboot wipes memory evidence and may detonate persistence. Preserve, don\'t reboot.' },
    { id: 'r_adware', text: 'Looks like the same pop-up junk we usually clean at the desk - I\'ll handle it here.', scores: { communication: 0.3, security: 0.1, process: 0.1 }, feedback: 'The tell that it is NOT adware is the EDR alert plus AppData persistence and a malicious C2. That is a SOC escalation.' },
  ],
  notesRubric: [
    { label: 'the STOP signals (EDR alert, AppData persistence, malicious C2)', pattern: /edr alert|halberd|appdata|persistence|scheduled task|c2|update-cdn-sync|185\.242\.7\.31|unsigned/i },
    { label: 'that evidence was preserved (not killed / not rebooted)', pattern: /preserv|did not (kill|clean|reboot)|left (it )?(running|as-?is)|do not reboot|evidence intact/i },
    { label: 'the escalation to Security with details + possible credential theft', pattern: /escalat|security|soc|p2|credential|reset password.*soc|isolate/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'soc', category: 'Endpoint - Malware (EDR alert)', resolutionCode: 'Preserved host; escalated to Security (SOC) P2' },
  categoryAccept: ['malware', 'endpoint', 'edr', 'security'],
  resolutionCodeAccept: ['escalate', 'soc', 'security', 'preserve', 'edr'],
  hints: [
    'Read KB-0012 and check Halberd EDR first - unlike the adware ticket, EDR is ALERTING on this host.',
    'The process runs unsigned from AppData\\Roaming and installed a logon scheduled task - that is persistence, not a PUP in Program Files.',
    'It beacons to update-cdn-sync.net, which Threat Intel rates malicious. This is a STOP.',
    'Do NOT kill it, delete it, scan it, or reboot - preserve the host and escalate to Security as P2.',
  ],
  debrief: 'This is the mirror image of the adware ticket, and KB-0012 is the hinge. There, EDR was silent, the PUP sat signed in Program Files, and SD cleaned it. Here EDR is alerting, an unsigned binary runs from AppData with scheduled-task persistence and beacons to a malicious C2, and the user may have typed credentials while infected. The competent move is restraint: killing the process or rebooting feels productive but destroys the exact volatile evidence Security needs, and cannot prove the machine is clean. Preserve, document, and escalate to SOC as P2.',
};

// ---------------------------------------------------------------------------
// SD2-12  BitLocker recovery-key request - verify identity FIRST
// ---------------------------------------------------------------------------
const sd2_12: Scenario = {
  id: 'sd2-12',
  tier: 'sd2',
  title: 'Laptop stuck on the BitLocker recovery screen',
  category: 'Endpoint',
  difficulty: 2,
  estMinutes: 10,
  objective: 'Retrieve an escrowed BitLocker recovery key for a stranded user - but only after verifying identity per KB-0001, and never by an insecure channel.',
  intake: {
    kind: 'ticket', number: 'INC457722', subject: 'Blue "BitLocker recovery" screen asking for a 48-digit key',
    body: 'Sarah Turner (HR Business Partner) calls: her laptop DEN-LT-1050 booted to a blue BitLocker recovery screen this morning after "an update" and wants the recovery key to get in. She sounds rushed - has a 9:30 interview to run.',
    requester: 'sturner', channel: 'phone', priority: 'P3', category: 'Endpoint', openedAt: ago(15), affectedHost: 'DEN-LT-1050',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const h = host(w, 'DEN-LT-1050');
    // A firmware/TPM update changed the boot measurements and tripped BitLocker into
    // recovery mode. The key is escrowed in AD; the fix is to read it out - after verifying.
    h.bitlocker = 'on';
    h.notes = 'BitLocker: OS volume protected, key escrowed in AD. Recovery Key ID 9F2C4A18. Recovery Key: 481920-337145-208866-591043-770238-114509-663827-902551. Recovery triggered by a UEFI firmware update on ' + daysAgo(0) + ' that changed TPM PCR measurements (expected, benign).';
    addEvent(h, { id: 24620, level: 'Information', source: 'BitLocker-API', log: 'System', message: 'BitLocker recovery was triggered for the OS volume after a platform (UEFI firmware) change altered the TPM validation profile. Recovery key required to unlock. This is expected after firmware updates.', time: ago(30) });
    addEvent(h, { id: 1, level: 'Information', source: 'Microsoft-Windows-UEFI', log: 'System', message: 'System firmware was updated to version 1.28.0. A one-time BitLocker recovery prompt on next boot is expected.', time: ago(60 * 20) });
  },
  contactWith: 'sturner',
  contact: [
    { id: 'empid', question: 'Before I read out a recovery key I have to verify you - what is your employee ID?', answer: '"E10110."', purpose: 'verify' },
    { id: 'callback', question: 'And I\'ll confirm by calling you back on the number we have on record.', answer: 'Callback to the desk number on record reaches Sarah. Verified.', purpose: 'verify' },
    { id: 'screen', question: 'What exactly is on screen - is there a "Recovery key ID" shown?', answer: '"Yes, it shows Recovery key ID 9F2C4A18 and a box for the 48-digit key."', purpose: 'clarify', reveals: 'keyid-matches' },
    { id: 'change', question: 'Did anything change right before - an update or a BIOS message?', answer: '"It said something about a firmware update last night, then this screen this morning."', purpose: 'clarify', reveals: 'firmware' },
    { id: 'text', question: '(Caller asks) "Can you just text or email me the key so I can hurry?"', answer: 'She is in a rush and asks you to text the key to her personal phone.', purpose: 'red_flag', reveals: 'insecure-channel' },
    { id: 'weekend', question: 'Big interview day for HR?', answer: '"Always this time of year. Can we hurry?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the identity-verification SOP (KB-0001)', match: { tool: 'kb', action: 'read', target: 'KB-0001' }, hint: 'A recovery key unlocks the whole disk - verify per KB-0001 before handing it over.' },
    { id: 'computer', label: 'Looked up the escrowed recovery key and confirmed the Key ID matches', match: [{ tool: 'directory', action: 'view_computer', target: 'DEN-LT-1050' }, { tool: 'rdp', action: 'view_system', target: 'DEN-LT-1050' }], hint: 'The recovery key is escrowed - match the Recovery Key ID she reads you against the record.' },
  ],
  required: [
    { id: 'verify_id', label: 'Verified the employee ID', match: { tool: 'ticket', action: 'contact', target: 'empid' }, skill: 'security' },
    { id: 'verify_2', label: 'Verified a second factor (callback on record)', match: { tool: 'ticket', action: 'contact', target: 'callback' }, skill: 'security' },
    { id: 'give_key', label: 'Provided the recovery key AFTER verifying, via the phone call', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'technical', after: 'verify_2' },
  ],
  forbidden: [
    { id: 'key_no_verify', label: 'Read out the recovery key without verifying identity', why: 'A BitLocker recovery key unlocks the entire disk. Handing it out on an unverified call is a textbook social-engineering win - KB-0001 requires two verification factors before ANY account/device action.', match: { tool: 'ticket', action: 'reply', target: 'r_giveearly' }, skill: 'security', penalty: 0.5 },
    { id: 'insecure_channel', label: 'Agreed to text / email the key to a personal number', why: 'Sensitive secrets go over the verified voice call only, never SMS or personal email - that channel can be attacker-controlled and leaves the key sitting in a message store.', match: { tool: 'ticket', action: 'reply', target: 'r_text' }, skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Thanks - I\'ve verified you with your employee ID and a callback to your number on record. This recovery screen is expected: last night\'s firmware update changed the secure-boot measurements, so BitLocker is asking for the key once. The Recovery Key ID you see (9F2C4A18) matches our record. I\'ll read you the 48-digit key now over this call - type it in and it\'ll boot normally, and it won\'t ask again. I won\'t text or email it; the phone is the only channel we use for keys.', scores: { communication: 1, security: 1, technical: 1 }, feedback: 'Verifies first, matches the Key ID, explains the benign cause, and delivers the key on the secure channel only.' },
    { id: 'r_giveearly', text: 'Sure, no problem - the key is 481920-337145-208866... let me read the rest.', scores: { communication: 0.3, security: 0.0 }, feedback: 'You gave up a full-disk unlock key to an unverified caller. Verify per KB-0001 first, every time.' },
    { id: 'r_text', text: 'You\'re in a hurry - I\'ll text the key to your mobile so you have it handy.', scores: { communication: 0.3, security: 0.0 }, feedback: 'Never send a recovery key by SMS or personal email. Read it on the verified call.' },
    { id: 'r_refuse', text: 'We can\'t give out BitLocker keys - you\'ll need to bring the laptop to the IT desk.', scores: { communication: 0.4, security: 0.5, process: 0.3 }, feedback: 'Overly rigid - once identity is verified, providing the escrowed key by phone is exactly the right, faster service.' },
  ],
  notesRubric: [
    { label: 'the verification performed (two factors per KB-0001)', pattern: /verif|employee id|e10110|callback|kb-0001|two factor/i },
    { label: 'the cause (firmware/TPM change tripped BitLocker recovery - benign)', pattern: /firmware|uefi|tpm|pcr|update|recovery (mode|screen)|benign|expected/i },
    { label: 'the secure delivery (key ID matched; read by phone only, not text/email)', pattern: /key id|9f2c4a18|by phone|voice call|not (text|email)|secure channel/i },
  ],
  closure: { disposition: 'resolve', category: 'Endpoint - BitLocker Recovery', resolutionCode: 'Verified identity; provided escrowed recovery key by phone' },
  categoryAccept: ['bitlocker', 'endpoint', 'recovery'],
  resolutionCodeAccept: ['bitlocker', 'recovery key', 'verified', 'key'],
  hints: [
    'A recovery key unlocks the whole disk - read KB-0001 and verify identity with TWO factors first.',
    'Match the Recovery Key ID she reads you (9F2C4A18) against the escrowed record before giving the key.',
    'The cause is benign: a firmware update changed TPM measurements, so BitLocker asks for the key once.',
    'Provide the key only over the verified phone call - never text or email it, no matter how rushed she is.',
  ],
  debrief: 'The pressure here is time and politeness, and the trap is skipping verification because the caller sounds legitimate and is in a hurry. A BitLocker recovery key is a full-disk unlock; giving it to an unverified caller, or over SMS/personal email, is precisely how social engineers pry laptops open. KB-0001\'s two-factor check is non-negotiable. Once verified, the rest is easy: the recovery was a benign side effect of a firmware update, the Key ID matches, and reading the escrowed key over the verified call gets her working in a minute.',
};

// ---------------------------------------------------------------------------
// SD2-13  Failing disk (SMART errors) - back up, swap from stock, migrate
// ---------------------------------------------------------------------------
const sd2_13: Scenario = {
  id: 'sd2-13',
  tier: 'sd2',
  title: 'Laptop freezing with disk errors in the log',
  category: 'Hardware',
  difficulty: 2,
  estMinutes: 12,
  objective: 'Recognise a dying disk from SMART/event-log warnings, protect the user\'s data by backing up BEFORE anything destructive, and replace the drive/laptop from stock with a proper asset hand-off.',
  intake: {
    kind: 'ticket', number: 'INC457723', subject: 'My laptop keeps freezing and makes a clicking noise',
    body: 'Emailed in. Raj Singh (Legal Counsel, DEN-LT-1080): the laptop freezes for minutes at a time, throws "delayed write failed" popups, and sometimes clicks. It\'s getting worse. He has case files on it he is worried about losing.',
    requester: 'rsingh', channel: 'email', priority: 'P3', category: 'Hardware', openedAt: ago(60), affectedHost: 'DEN-LT-1080',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const h = host(w, 'DEN-LT-1080');
    // Predictive-failure SMART + disk I/O errors. Physical failure -> back up and replace.
    const disk = h.devices.find((d) => d.class === 'Network adapters'); // placeholder; add a disk device below
    h.devices.push({ name: 'Samsung PM9A1 NVMe 512GB', class: 'Disk drives', status: 'error', driver: '10.0.26100.1', error: 'SMART predictive failure reported (threshold exceeded).' });
    addEvent(h, { id: 52, level: 'Warning', source: 'disk', log: 'System', message: 'The driver has detected that device \\Device\\Harddisk0\\DR0 is reporting a SMART predictive failure. Back up data and replace the drive.', time: ago(40) });
    addEvent(h, { id: 7, level: 'Error', source: 'disk', log: 'System', message: 'The device \\Device\\Harddisk0\\DR0 has a bad block.', time: ago(35) });
    addEvent(h, { id: 51, level: 'Warning', source: 'disk', log: 'System', message: 'An error was detected on device \\Device\\Harddisk0\\DR0 during a paging operation.', time: ago(33) });
    addEvent(h, { id: 140, level: 'Warning', source: 'Ntfs', log: 'System', message: 'The system failed to flush data to the transaction log. Corruption may occur in volume C:.', time: ago(30) });
    // Red herring: a benign successful Windows Update note.
    addEvent(h, { id: 19, level: 'Information', source: 'WindowsUpdateClient', log: 'System', message: 'Installation Successful: Windows successfully installed a cumulative update.', time: daysAgo(6) });
    void disk;
  },
  contactWith: 'rsingh',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID before I remote in and arrange a swap, please.', answer: '"E10150."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll confirm on the desk number on record before we proceed.', answer: 'Callback to the number on record reaches Raj. Verified.', purpose: 'verify' },
    { id: 'backup', question: 'Are your case files in OneDrive / the H: drive, or only local on this laptop?', answer: '"Some are in OneDrive but a few folders are only on the laptop, in Documents."', purpose: 'clarify', reveals: 'local-data' },
    { id: 'when', question: 'When did the freezing and clicking start, and is it getting worse?', answer: '"About a week ago, and definitely worse the last two days."', purpose: 'clarify', reveals: 'degrading' },
    { id: 'travel', question: 'Do you need it for anything today, or can we get you a replacement from stock?', answer: '"I have depositions tomorrow, so sooner is better, but I mostly need my files."', purpose: 'clarify', reveals: 'urgency' },
    { id: 'lunch', question: 'How\'s the caseload this quarter?', answer: '"Heavy. Can we focus on the laptop?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the hardware-replacement SOP (KB-0021)', match: { tool: 'kb', action: 'read', target: 'KB-0021' }, hint: 'KB-0021 covers asset updates and swapping from stock.' },
    { id: 'events', label: 'Read the System log and found the SMART predictive-failure / bad-block errors', match: [{ tool: 'rdp', action: 'view_events', target: 'DEN-LT-1080', params: { log: 'System' } }, { tool: 'rdp', action: 'view_events', target: 'DEN-LT-1080' }], hint: 'The System log names a SMART predictive failure and bad blocks - that is physical, not software.' },
    { id: 'devices', label: 'Checked Device Manager: the disk drive is in an error state', match: { tool: 'rdp', action: 'view_devices', target: 'DEN-LT-1080' }, weight: 0.5 },
    { id: 'stock', label: 'Found a replacement laptop in stock', match: { tool: 'assets', action: 'search', params: { q: /stock|latitude|laptop/i } }, hint: 'There are imaged laptops in the Denver IT stockroom.' },
  ],
  required: [
    { id: 'backup', label: 'Backed up / preserved the user\'s local data before doing anything destructive', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'technical' },
    { id: 'replace', label: 'Assigned/shipped a replacement laptop from stock to the user', match: [{ tool: 'assets', action: 'assign', target: /kd-0500[12]/, params: { user: /rsingh/i } }, { tool: 'assets', action: 'assign', target: /kd-0500[12]/ }, { tool: 'assets', action: 'ship', params: { user: /rsingh/i } }], skill: 'technical', after: 'backup' },
    { id: 'retire_old', label: 'Marked the failing device for repair/retirement in the asset record', match: { tool: 'assets', action: 'set_status', params: { status: /repair|retired/i } }, skill: 'documentation', weight: 0.5 },
  ],
  forbidden: [
    { id: 'wipe_first', label: 'Wiped / reimaged the failing disk before backing up the data', why: 'The disk is physically failing and holds local-only case files. Wiping or reimaging first risks permanent data loss the instant the dying drive gives out. Back up (or pull the drive to copy) BEFORE anything destructive.', match: [{ tool: 'assets', action: 'remote_wipe' }, { tool: 'rdp', action: 'reboot', target: 'DEN-LT-1080' }], skill: 'technical', penalty: 0.4, unlessAfter: 'backup' },
    { id: 'chkdsk_repair', label: 'Ran a heavy repair/scan on the dying disk instead of replacing it', why: 'chkdsk /r or sfc on a drive throwing SMART predictive failure hammers the failing media and can be the final straw. This is hardware - replace it, don\'t try to software-repair it.', match: [{ tool: 'terminal', action: 'sfc', target: 'DEN-LT-1080' }, { tool: 'rdp', action: 'run_scan', target: 'DEN-LT-1080' }], skill: 'technical', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Your laptop\'s drive is physically failing - the log shows a SMART predictive failure and bad blocks, which is why it freezes and clicks. First priority is your files: I\'m backing up your local Documents folders now (the OneDrive ones are already safe) before anything else, because a dying drive can quit without warning. Then I\'ll hand you an imaged replacement laptop from stock and migrate your data and profile onto it, and mark the old unit for repair. You\'ll be set well before tomorrow\'s depositions.', scores: { communication: 1, technical: 1 }, feedback: 'Diagnoses hardware from the log, protects data first, then swaps from stock with a clean asset hand-off.' },
    { id: 'r_reimage', text: 'Sounds like Windows is corrupted - I\'ll reimage the laptop and it\'ll be fresh.', scores: { communication: 0.3, technical: 0.1 }, feedback: 'Reimaging a SMART-failing drive can destroy the only copy of his local case files, and it won\'t fix failing hardware anyway.' },
    { id: 'r_chkdsk', text: 'Let me run chkdsk /r and sfc to repair the disk - that usually fixes freezing.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'Those pound a dying drive and can finish it off. The errors are physical; replace the drive, don\'t repair it.' },
    { id: 'r_wait', text: 'Try restarting it a few times and let me know if it keeps happening.', scores: { communication: 0.2, technical: 0.1 }, feedback: 'The failure is progressive; waiting risks total data loss before his depositions.' },
  ],
  notesRubric: [
    { label: 'the diagnosis (SMART predictive failure / bad blocks = failing disk)', pattern: /smart|predictive failure|bad block|disk (failing|failure)|hardware|\\device\\harddisk/i },
    { label: 'data protected first (backup before destructive steps)', pattern: /back ?up|backed up|preserve|copy.*(data|files)|onedrive|before (wip|reimag|swap)|migrat/i },
    { label: 'the replacement and asset update (stock swap, old unit repair/retired)', pattern: /stock|replace|swap|new laptop|assign|ship|repair|retire|asset/i },
  ],
  closure: { disposition: 'resolve', category: 'Hardware - Disk Failure', resolutionCode: 'Backed up data; replaced failing drive/laptop from stock' },
  categoryAccept: ['hardware', 'disk', 'drive'],
  resolutionCodeAccept: ['disk', 'drive', 'replace', 'backup', 'stock', 'smart'],
  hints: [
    'Read the System event log - a SMART "predictive failure" and bad-block errors point at a dying disk, not software.',
    'Protect the data FIRST: back up his local-only Documents before anything destructive; OneDrive files are already safe.',
    'Swap in an imaged laptop from the Denver stockroom (KD-05001/05002) and migrate his data.',
    'Update the asset record: assign the new unit to him and mark the old one for repair. Do not chkdsk/reimage the failing drive.',
  ],
  debrief: 'Freezing plus a clicking drive plus "delayed write failed" is a hardware death rattle, and the event log confirms it with a SMART predictive failure and bad blocks. The one irreversible mistake is treating it as software - reimaging or running chkdsk /r - because both can push the failing drive over the edge and take his local-only case files with it. The disciplined order is data first: back up, then replace from stock, migrate, and update the asset record. Hardware that reports SMART failures gets replaced, not repaired.',
};

// ---------------------------------------------------------------------------
// SD2-14  Temp/roaming profile corruption - "my desktop is empty"
// ---------------------------------------------------------------------------
const sd2_14: Scenario = {
  id: 'sd2-14',
  tier: 'sd2',
  title: '"All my files and desktop are gone!"',
  category: 'Windows',
  difficulty: 3,
  estMinutes: 12,
  objective: 'Recognise a temporary-profile logon from the event log, reassure the panicking user their data is intact, and fix the corrupted user profile instead of reimaging and destroying it.',
  intake: {
    kind: 'ticket', number: 'INC457724', subject: 'My desktop is completely empty and all my files disappeared',
    body: 'Chat from Pat Cole (Receptionist, DEN-WS-2001): "I logged in and my desktop is blank, default wallpaper, none of my files, Outlook wants setup again. Did I get hacked? Did everything get deleted?" Very upset.',
    requester: 'pcole', channel: 'chat', priority: 'P2', category: 'Windows', openedAt: ago(18), affectedHost: 'DEN-WS-2001',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const h = host(w, 'DEN-WS-2001');
    // User Profile Service loaded a TEMPORARY profile because the real one failed to load.
    // The real profile (and all data) is intact on disk under C:\Users\pcole.
    addEvent(h, { id: 1511, level: 'Warning', source: 'User Profile Service', log: 'Application', message: 'Windows cannot find the local profile and is logging you on with a temporary profile. Changes made will be lost when you log off.', time: ago(20) });
    addEvent(h, { id: 1515, level: 'Warning', source: 'User Profile Service', log: 'Application', message: 'Windows has backed up this user profile. Windows will automatically try to use the backup profile the next time this user logs on.', time: ago(20) });
    addEvent(h, { id: 1508, level: 'Error', source: 'User Profile Service', log: 'Application', message: 'Windows was unable to load the registry. This problem is often caused by insufficient memory or insufficient security rights. DETAIL - The process cannot access the file (NTUSER.DAT) because it is being used by another process.', time: ago(21) });
    addEvent(h, { id: 1500, level: 'Error', source: 'User Profile Service', log: 'Application', message: 'Windows cannot log you on because your profile cannot be loaded. Loaded a temporary profile (.bak profile present in ProfileList).', time: ago(21) });
    // The real profile data is still there on disk.
    h.files.push({ path: 'C:\\Users\\pcole\\Documents\\ (intact, 3.1 GB)', size: 3100000000, modified: ago(60 * 26) });
    h.files.push({ path: 'C:\\Users\\pcole\\Desktop\\ (intact, 42 items)', size: 88000000, modified: ago(60 * 26) });
    h.files.push({ path: 'C:\\Users\\pcole.DEN-WS-2001.bak\\ (backup profile registry hive)', size: 210000000, modified: ago(21) });
    // Red herring: base benign 10016 DCOM warning is present.
  },
  contactWith: 'pcole',
  contact: [
    { id: 'empid', question: 'I can help - first, confirm your employee ID so I can remote in.', answer: '"E10170."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll confirm on your desk number on record before I connect.', answer: 'Callback to the number on record reaches Pat. Verified.', purpose: 'verify' },
    { id: 'when', question: 'Did anything happen right before - a bad shutdown, power loss, or a message about disk space?', answer: '"The PC lost power during a storm yesterday and it did a weird restart this morning."', purpose: 'clarify', reveals: 'dirty-shutdown' },
    { id: 'temp', question: 'Does anything mention a "temporary profile" or "changes will be lost"?', answer: '"Yes! There\'s a little bubble that says I\'m signed in with a temporary profile."', purpose: 'clarify', reveals: 'temp-profile' },
    { id: 'hacked', question: 'To reassure you - did you get any ransom message, or emails asking for money?', answer: '"No, no ransom or anything. Just everything looks blank and default."', purpose: 'clarify', reveals: 'not-ransomware' },
    { id: 'weather', question: 'Busy front desk this morning?', answer: '"Always. I just want my files back."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'events', label: 'Read the Application log and found the User Profile Service temp-profile errors (1511/1508/1500)', match: [{ tool: 'rdp', action: 'view_events', target: 'DEN-WS-2001', params: { log: 'Application' } }, { tool: 'rdp', action: 'view_events', target: 'DEN-WS-2001' }], hint: 'User Profile Service events 1511/1515/1508/1500 mean a temporary profile loaded - not deleted data.' },
    { id: 'files', label: 'Confirmed the real profile data is intact under C:\\Users\\pcole (and the .bak profile exists)', match: { tool: 'rdp', action: 'view_files', target: 'DEN-WS-2001' }, hint: 'Check the disk - is C:\\Users\\pcole (and a .bak profile) still there? The data is not gone.' },
    { id: 'kb', label: 'Consulted the terminal/quick reference (KB-0019)', match: { tool: 'kb', action: 'read', target: 'KB-0019' }, weight: 0.5 },
  ],
  required: [
    { id: 'fix', label: 'Fixed the corrupted profile and restored the user\'s real profile/data', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'reimage', label: 'Reimaged / wiped the machine', why: 'A reimage destroys the intact local profile - the exact data the user is panicking about - to "fix" a problem that is just a corrupt profile pointer. The real profile and files are still on the disk; repair the profile instead.', match: { tool: 'ticket', action: 'reply', target: 'r_reimage' }, skill: 'technical', penalty: 0.4 },
    { id: 'delete_profile', label: 'Deleted the profile / cleared the .bak while logged into the temp profile', why: 'Deleting the profile folder or the backup hive before recovering it can turn a fixable temp-profile into real data loss. Rename/repair carefully; never delete the only copy.', match: [{ tool: 'rdp', action: 'quarantine_file', target: 'DEN-WS-2001' }], skill: 'technical', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Good news first: nothing is deleted and you are not hacked. Yesterday\'s power loss corrupted the pointer to your Windows profile, so this morning Windows logged you into a blank TEMPORARY profile - that\'s why everything looks default. Your real desktop and files are all still on the machine (I can see them under your user folder). I\'ll fix the profile: correct the profile registry entry / swap in the good backup hive, then have you sign out and back in, and your desktop, files and Outlook will all come back exactly as they were. Please don\'t save anything new to the desktop until we\'re done, since temp-profile changes get discarded.', scores: { communication: 1, technical: 1 }, feedback: 'Reassures accurately, names the real cause (temp profile after a dirty shutdown), and repairs the profile rather than nuking it.' },
    { id: 'r_reimage', text: 'Your profile\'s corrupted - safest is to reimage the PC and set you back up fresh.', scores: { communication: 0.3, technical: 0.1 }, feedback: 'A reimage would destroy the intact profile and files still sitting on the disk. Repair the profile instead.' },
    { id: 'r_scare', text: 'It looks like your files may be gone - this could be malware; I\'ll escalate to Security.', scores: { communication: 0.2, technical: 0.1, process: 0.1 }, feedback: 'No compromise signs, and the data isn\'t gone. The log clearly shows a temporary profile - fix it, don\'t alarm the user.' },
    { id: 'r_newuser', text: 'Let\'s just make you a brand-new profile and start over.', scores: { communication: 0.4, technical: 0.3 }, feedback: 'A fresh profile leaves all her real data stranded; recover the existing profile so nothing is lost.' },
  ],
  notesRubric: [
    { label: 'the cause (temporary profile loaded after profile/registry corruption)', pattern: /temp(orary)? profile|profile (corrupt|load|service)|1511|1508|ntuser|\.bak|profilelist/i },
    { label: 'that the data is intact (not deleted, not compromised)', pattern: /intact|not deleted|still (there|on disk)|c:\\users\\pcole|not (hacked|compromise|ransom)|data safe/i },
    { label: 'the fix (repair/restore the profile + re-logon, no reimage)', pattern: /repair|restore.*profile|fix.*profile|backup hive|rename|sign ?out|re-?logon|no reimage/i },
  ],
  closure: { disposition: 'resolve', category: 'Windows - User Profile', resolutionCode: 'Repaired corrupt user profile; data restored' },
  categoryAccept: ['user profile', 'windows', 'profile'],
  resolutionCodeAccept: ['profile', 'temp profile', 'repair', 'restore'],
  hints: [
    'Read the Application log - User Profile Service events 1511/1515/1508/1500 mean Windows loaded a TEMPORARY profile.',
    'Check the disk: C:\\Users\\pcole (and a .bak profile) is still there. The data is not deleted and there is no malware.',
    'The likely trigger was yesterday\'s power loss corrupting the profile/registry pointer.',
    'Repair the profile (fix ProfileList / restore the good hive) and re-logon. Do NOT reimage - that would destroy the intact data.',
  ],
  debrief: 'An empty desktop reads like catastrophe - deleted files, or a hack - and the two tempting wrong turns are to reimage (which really would destroy the data) or to escalate it as malware. The event log tells the calm truth: a corrupted profile made Windows fall back to a temporary profile, so the user sees defaults while their real profile sits intact on disk, complete with a .bak hive. The skill is half technical (repair the ProfileList/hive and re-logon) and half communication (reassure a panicking user with evidence that nothing is lost) - and never reaching for the reimage that would make the fear come true.',
};

// ---------------------------------------------------------------------------
// SD2-15  Recurring lockout every few minutes - a task with the OLD password
// ---------------------------------------------------------------------------
const sd2_15: Scenario = {
  id: 'sd2-15',
  tier: 'sd2',
  title: 'Account locks out again within minutes of every unlock',
  category: 'Identity',
  difficulty: 4,
  estMinutes: 14,
  objective: 'Stop treating a recurring lockout by unlocking on a loop; find the real source - a scheduled task/service still running as the user with the OLD password - and fix it.',
  intake: {
    kind: 'ticket', number: 'INC457725', subject: 'You unlock me and I\'m locked again five minutes later',
    body: 'Tanya Martin (Executive Assistant) calls: her account keeps locking. SD1 has unlocked it three times this morning and it re-locks within minutes. She changed her password two days ago. She can barely get any work done.',
    requester: 'tmartin', channel: 'phone', priority: 'P3', category: 'Identity', openedAt: ago(26), affectedHost: 'DEN-LT-1005',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const u = findUser(w, 'tmartin')!;
    u.passwordLastSet = ago(60 * 48); // changed 2 days ago
    lockOut(w, 'tmartin', 5);
    // A scheduled task on her laptop still runs as her with the OLD password, hammering AD
    // every few minutes and re-locking the account. This is the real root cause.
    u.recentSignIns = [
      { time: ago(4), ip: '10.10.20.15', location: 'Denver, US', app: 'Kerberos (scheduled task) DEN-LT-1005', result: 'failure', reason: 'bad password (old credential)', device: 'DEN-LT-1005' },
      { time: ago(9), ip: '10.10.20.15', location: 'Denver, US', app: 'Kerberos (scheduled task) DEN-LT-1005', result: 'failure', reason: 'bad password (old credential)', device: 'DEN-LT-1005' },
      { time: ago(14), ip: '10.10.20.15', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1005', mfa: 'satisfied' },
      { time: ago(19), ip: '10.10.20.15', location: 'Denver, US', app: 'Kerberos (scheduled task) DEN-LT-1005', result: 'failure', reason: 'bad password (old credential)', device: 'DEN-LT-1005' },
    ];
    const h = host(w, 'DEN-LT-1005');
    h.scheduledTasks.push({ name: 'ExecCalendarSync', path: '\\', action: 'C:\\Tools\\CalSync\\calsync.exe --run', trigger: 'Every 5 minutes (runs as KESTREL\\tmartin, stored password)', author: 'KESTREL\\tmartin' });
    addEvent(h, { id: 4625, level: 'Audit Failure', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'An account failed to log on. Account: tmartin. Logon Type: 4 (Batch/Scheduled Task). Failure Reason: bad password. Process: Task Scheduler (ExecCalendarSync).', time: ago(4) });
    addEvent(h, { id: 4625, level: 'Audit Failure', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'An account failed to log on. Account: tmartin. Logon Type: 4 (Batch/Scheduled Task). Failure Reason: bad password. Process: Task Scheduler (ExecCalendarSync).', time: ago(9) });
    // DC-side lockout event pointing at the caller computer.
    addLog(w, { time: ago(3), source: 'auth', host: 'DEN-DC01', user: 'tmartin', srcIp: '10.10.20.15', action: 'lockout', message: '4740 Account tmartin locked out. Caller Computer: DEN-LT-1005. Repeated 4625 batch-logon failures.', fields: { eventId: 4740, caller: 'DEN-LT-1005' } });
    // Red herring: her phone mail app is fine (updated) - a benign successful mobile sign-in.
    addLog(w, { time: ago(40), source: 'cloud', user: 'tmartin', srcIp: '10.10.20.15', action: 'signin', message: 'WorkSuite mobile mail sign-in success tmartin (new password already updated on phone)', fields: { result: 'success', app: 'Mail-Mobile' } });
  },
  contactWith: 'tmartin',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10005."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll confirm on the desk number on record before making changes.', answer: 'Callback to the number on record reaches Tanya. Verified.', purpose: 'verify' },
    { id: 'changed', question: 'You changed your password two days ago - did you update it everywhere (phone, saved logons, any scripts)?', answer: '"I updated my phone. I don\'t know about scripts - there\'s a calendar sync thing IT set up ages ago."', purpose: 'clarify', reveals: 'calsync' },
    { id: 'pattern', question: 'Roughly how many minutes after an unlock does it re-lock?', answer: '"Like five minutes, every time. Clockwork."', purpose: 'clarify', reveals: 'every-5-min' },
    { id: 'where', question: 'Is it always your work laptop, or do you sign in on other devices too?', answer: '"Just the laptop and my phone. The phone works fine now though."', purpose: 'clarify', reveals: 'phone-ok' },
    { id: 'coffee', question: 'How are the execs treating you this week?', answer: '"Busy as ever. Can we fix the lockouts?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the password/lockout SOP (KB-0002)', match: { tool: 'kb', action: 'read', target: 'KB-0002' }, hint: 'KB-0002 lists the common lockout sources - a scheduled task running as the user is one.' },
    { id: 'signins', label: 'Reviewed sign-ins: repeated batch/scheduled-task failures with the OLD credential from her own PC', match: { tool: 'directory', action: 'view_signins', target: 'tmartin' }, hint: 'The failures are logon type 4 (batch/scheduled task) from her own device, not an external attacker.' },
    { id: 'tasks', label: 'Found the scheduled task running as her (ExecCalendarSync, every 5 min)', match: [{ tool: 'rdp', action: 'view_tasks', target: 'DEN-LT-1005' }, { tool: 'terminal', action: 'schtasks', target: 'DEN-LT-1005' }], hint: 'Look for a task/service that runs AS her account with a stored password.' },
    { id: 'events', label: 'Confirmed the 4625 batch-logon failures / 4740 lockout in the logs', match: [{ tool: 'rdp', action: 'view_events', target: 'DEN-LT-1005', params: { log: 'Security' } }, { tool: 'terminal', action: 'net_user', target: 'DEN-LT-1005' }], weight: 0.5 },
  ],
  required: [
    { id: 'fix_task', label: 'Fixed the culprit task (deleted it or updated its stored credential)', match: [{ tool: 'rdp', action: 'delete_task', target: 'DEN-LT-1005', params: { task: /calendarsync|calsync|exec/i } }, { tool: 'rdp', action: 'delete_task', target: 'DEN-LT-1005' }], skill: 'technical' },
    { id: 'unlock', label: 'Unlocked the account once the source was fixed', match: { tool: 'directory', action: 'unlock', target: 'tmartin' }, skill: 'technical', after: 'fix_task' },
  ],
  forbidden: [
    { id: 'loop_unlock', label: 'Just unlocked (again) and closed without finding the source', why: 'Unlocking without killing the task that keeps failing with the old password is what SD1 already did three times - it re-locks in five minutes. Fix the source, then unlock.', match: { tool: 'ticket', action: 'reply', target: 'r_unlock' }, skill: 'process', penalty: 0.4 },
    { id: 'reset_pw', label: 'Reset her password to "fix" it', why: 'Her password is fine (her phone works with the new one). Resetting it does not stop a task that stores the OLD password from hammering AD, and only restarts the expiry clock. Find and fix the task.', match: { tool: 'directory', action: 'reset_password', target: 'tmartin' }, skill: 'technical', penalty: 0.3 },
    { id: 'escalate_soc', label: 'Escalated as an account attack', why: 'Every failure is a logon type 4 (batch/scheduled task) from her own laptop with the old credential - a classic self-inflicted lockout, not an external attack. Escalating to Security cries wolf.', match: { tool: 'ticket', action: 'reply', target: 'r_soc' }, skill: 'process', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Found why the unlocks don\'t stick: a scheduled task on your laptop, "ExecCalendarSync", runs every five minutes AS your account with your OLD password saved in it. Since you changed your password two days ago, every run fails and trips the lockout - that\'s the five-minute clockwork. Your password itself is fine, which is why your phone works. I\'ve fixed the task (removed/updated its stored credential) so it stops using the old password, and now that the source is gone I\'ve unlocked your account. It should stay unlocked. If you still need that calendar sync, we\'ll set it up properly with a service account.', scores: { communication: 1, technical: 1, process: 1 }, feedback: 'Identifies the batch-logon source, fixes it BEFORE unlocking, and rules out compromise correctly.' },
    { id: 'r_unlock', text: 'I\'ve unlocked you again - you should be good now.', scores: { communication: 0.3, process: 0.1 }, feedback: 'This is the loop SD1 was stuck in. Without fixing the task, it re-locks in minutes.' },
    { id: 'r_reset', text: 'Let me reset your password - that usually clears repeated lockouts.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'The password is fine (phone works). A stored-old-password task will keep locking you regardless of a reset.' },
    { id: 'r_soc', text: 'Someone must be trying to brute-force your account - escalating to Security.', scores: { communication: 0.3, process: 0.1 }, feedback: 'The failures are batch logons from your own laptop with the old password - self-inflicted, not an attacker.' },
  ],
  notesRubric: [
    { label: 'the root cause (scheduled task/service running as her with the OLD password)', pattern: /scheduled task|calsync|calendarsync|service|old password|stored credential|logon type 4|batch/i },
    { label: 'that it is not a password reset or an attack (phone works; failures from her own PC)', pattern: /phone works|password (is )?fine|own (pc|laptop|device)|not (an )?attack|not compromise|self-?inflicted/i },
    { label: 'the fix order (fix/remove the task, THEN unlock)', pattern: /(remov|delet|updat|fix).*(task|credential).*(unlock|then)|fixed.*before.*unlock|then unlock/i },
  ],
  closure: { disposition: 'resolve', category: 'Identity - Recurring Lockout', resolutionCode: 'Fixed scheduled task with stale credential; unlocked account' },
  categoryAccept: ['recurring lockout', 'identity', 'lockout'],
  resolutionCodeAccept: ['lockout', 'scheduled task', 'credential', 'unlock', 'task'],
  hints: [
    'Don\'t just unlock again - that\'s the loop SD1 is stuck in. Find WHY it keeps locking.',
    'Read her sign-ins: the failures are logon type 4 (batch/scheduled task) from her own laptop with the old credential.',
    'Check scheduled tasks/services on DEN-LT-1005 - "ExecCalendarSync" runs every 5 minutes as her with a stored (old) password.',
    'Fix the task (remove it or update the stored password) FIRST, then unlock. Do not reset her password or escalate to Security.',
  ],
  debrief: 'A recurring lockout is a diagnosis problem disguised as a repetitive chore. Unlocking again and again - which is what SD1 did - never works because something keeps presenting the old password. The sign-in log is the key: the failures are logon type 4 (batch/scheduled task) from her own machine, right after her password change, which points straight at a task that cached the old credential. The two false trails are resetting the password (fine already, per her phone) and escalating as an attack (it\'s self-inflicted). Kill or re-credential the task first, then the unlock finally sticks.',
};

// ---------------------------------------------------------------------------
// SD2-16  Local hosts-file tampering / DNS redirect - a security concern
// ---------------------------------------------------------------------------
const sd2_16: Scenario = {
  id: 'sd2-16',
  tier: 'sd2',
  title: 'Bank/login site looks wrong on a remote laptop',
  category: 'Security',
  difficulty: 4,
  estMinutes: 14,
  objective: 'Trace a "the site looks wrong" report to rogue entries in the local hosts file redirecting a login domain to an attacker IP - recognise it as a possible compromise, and escalate to Security rather than quietly deleting the lines and closing.',
  intake: {
    kind: 'ticket', number: 'INC457726', subject: 'Our login page looks off and my browser warns about the certificate',
    body: 'Portal ticket from Hana Sato (Account Executive, remote - Seattle, DEN-LT-1062): the WorkSuite login page "looks slightly wrong" and throws a certificate warning, but only on her laptop; her phone is fine. She wonders if she should just click through to log in.',
    requester: 'hsato', channel: 'portal', priority: 'P3', category: 'Network', openedAt: ago(35), affectedHost: 'DEN-LT-1062',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const h = host(w, 'DEN-LT-1062');
    // Rogue static entries in the hosts file redirect the SSO/login domain (and a bank) to
    // an attacker IP. Local override -> DNS is bypassed, cert doesn't match -> phishing/MITM.
    h.files.push({ path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', size: 3600, modified: ago(60 * 30), signed: false, suspicious: true });
    h.notes = 'hosts file contains non-default entries:\n  45.137.22.90   login.worksuite-mail.net\n  45.137.22.90   accounts.kestreldynamics.com\n  45.137.22.90   onlinebanking.firstsummit-bank.com\n(These override DNS and point corporate/bank logins at an external IP.)';
    addEvent(h, { id: 1014, level: 'Warning', source: 'DNS Client Events', log: 'System', message: 'Name resolution for login.worksuite-mail.net was satisfied by a static hosts-file entry (45.137.22.90), bypassing configured DNS servers.', time: ago(40) });
    // The endpoint resolves the login domain to the attacker IP; intel flags it malicious.
    addLog(w, { time: ago(34), source: 'web', host: 'DEN-LT-1062', user: 'hsato', domain: 'login.worksuite-mail.net', url: 'https://login.worksuite-mail.net/', action: 'cert_error', message: 'TLS certificate mismatch: presented CN=*.credphish-proxy.io for login.worksuite-mail.net at 45.137.22.90 (hosts-file override).' });
    w.intel.push({ indicator: '45.137.22.90', type: 'ip', verdict: 'malicious', source: 'AbuseCH', tags: ['phishing', 'reverse-proxy', 'aitm'], firstSeen: daysAgo(10), detail: 'Adversary-in-the-middle credential-proxy host. Seen impersonating SSO/login portals to harvest credentials and session cookies.' });
    // Red herring: benign DNS Client informational about cache.
    addEvent(h, { id: 1013, level: 'Information', source: 'DNS Client Events', log: 'System', message: 'The DNS resolver cache was flushed. (Routine; unrelated.)', time: ago(200) });
  },
  contactWith: 'hsato',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10122."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll confirm on the desk number on record before I remote in.', answer: 'Callback to the number on record reaches Hana. Verified.', purpose: 'verify' },
    { id: 'entered', question: 'Did you already type your password into that "off-looking" login page?', answer: '"I started to... I might have entered it once before the certificate warning scared me off."', purpose: 'clarify', reveals: 'possible-cred-entry' },
    { id: 'install', question: 'Did you install anything or run a "network fix" tool recently, or let anyone remote in?', answer: '"A pop-up said I needed a \'network optimizer\' to speed up my Wi-Fi last week and I ran it."', purpose: 'clarify', reveals: 'likely-dropper' },
    { id: 'scope', question: 'Is it only your laptop, and only certain sites, or everything?', answer: '"Only the laptop, and mainly the login page and my bank. Other sites seem okay."', purpose: 'clarify', reveals: 'targeted-domains' },
    { id: 'weather', question: 'How\'s Seattle this week?', answer: '"Rainy. Does that matter?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the malware/security SOP (KB-0012)', match: { tool: 'kb', action: 'read', target: 'KB-0012' }, hint: 'Credential-theft signals and unknown redirects are a STOP-and-escalate, not a quiet fix.' },
    { id: 'hosts', label: 'Found the rogue hosts-file entries redirecting login/bank domains', match: [{ tool: 'rdp', action: 'view_files', target: 'DEN-LT-1062' }, { tool: 'rdp', action: 'view_system', target: 'DEN-LT-1062' }], hint: 'Look at the hosts file - static entries pointing corporate/bank logins at an external IP.' },
    { id: 'dns', label: 'Confirmed the override with nslookup / ipconfig (resolves to the attacker IP, not DNS)', match: [{ tool: 'terminal', action: 'nslookup', target: 'DEN-LT-1062' }, { tool: 'terminal', action: 'ipconfig_all', target: 'DEN-LT-1062' }], hint: 'The login domain resolves to 45.137.22.90 via the hosts file, bypassing corporate DNS.' },
    { id: 'intel', label: 'Looked up the redirect IP (malicious AiTM proxy)', match: { tool: 'intel', action: 'lookup', target: /45\.137\.22\.90/ }, hint: 'Threat Intel rates the redirect IP as a credential-phishing proxy.' },
  ],
  required: [
    { id: 'escalate', label: 'Escalated to Security (SOC) as a possible compromise, preserving evidence', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'security' },
  ],
  forbidden: [
    { id: 'delete_close', label: 'Just deleted the hosts entries and closed the ticket', why: 'The rogue entries got there somehow (she ran a "network optimizer") and she may have entered her password into the fake page. Quietly reverting the file and closing hides a likely credential-theft compromise: SOC needs to reset credentials, hunt the dropper, and check for more. Preserve and escalate.', match: [{ tool: 'rdp', action: 'quarantine_file', target: 'DEN-LT-1062' }, { tool: 'ticket', action: 'reply', target: 'r_fixclose' }], skill: 'security', penalty: 0.5 },
    { id: 'clickthrough', label: 'Told her it\'s fine to click through the certificate warning', why: 'The cert warning is the one control catching this redirect. Telling her to proceed walks her straight into the credential-harvesting proxy.', match: { tool: 'ticket', action: 'reply', target: 'r_clickthrough' }, skill: 'security', penalty: 0.5 },
    { id: 'set_dns', label: 'Changed DNS settings as if it were a DNS misconfiguration', why: 'This is not a DNS-server problem - the hosts file is overriding DNS locally. Fiddling with DNS settings misreads a security incident as a config glitch.', match: { tool: 'rdp', action: 'set_dns', target: 'DEN-LT-1062' }, skill: 'investigation', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Please stop and do NOT log in or click through that warning - this is a security issue, not a glitch. Your laptop\'s local "hosts" file has been tampered with: it forces our login page and your bank to an external server (45.137.22.90) that Threat Intel flags as a credential-phishing proxy, which is why the page looks off and the certificate doesn\'t match. That "network optimizer" you ran is the likely source. Because you may have entered your password and this looks like a compromise, I\'m preserving the machine as-is and escalating to Security as P2 right now - they\'ll reset your credentials, review your sign-ins, and clean the machine. Don\'t use it for logins until they clear it.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Reads the tampered hosts + malicious IP + possible cred entry as a compromise, preserves evidence, and escalates.' },
    { id: 'r_fixclose', text: 'I removed the bad lines from your hosts file - all fixed, closing the ticket.', scores: { communication: 0.3, security: 0.1 }, feedback: 'You reverted the symptom but ignored how it got there and that she may have been phished. This needs SOC, not a quiet close.' },
    { id: 'r_clickthrough', text: 'It\'s probably just a certificate hiccup - go ahead and click "proceed" to log in.', scores: { communication: 0.2, security: 0.0 }, feedback: 'That sends her into the credential-harvesting proxy. Never coach past a warning that\'s catching a real redirect.' },
    { id: 'r_dns', text: 'Looks like a DNS problem - I\'ll switch your DNS servers and flush the cache.', scores: { communication: 0.3, security: 0.1, investigation: 0.1 }, feedback: 'The hosts file overrides DNS locally; this is tampering, not a DNS-server misconfig. Escalate it as security.' },
  ],
  notesRubric: [
    { label: 'the finding (rogue hosts-file entries redirecting login/bank to a malicious IP)', pattern: /hosts file|hosts-file|45\.137\.22\.90|redirect|override|static entr|login\.worksuite|bank/i },
    { label: 'the compromise judgment (possible credential theft; dropper; preserve)', pattern: /compromise|credential|phish|aitm|proxy|optimizer|dropper|preserv|do ?n(o|')t (log ?in|click)/i },
    { label: 'the escalation to Security (not a quiet delete-and-close, not DNS)', pattern: /escalat|security|soc|p2|not (a )?dns|not delete|reset (her )?credential/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'soc', category: 'Security - Host File Tampering', resolutionCode: 'Preserved evidence; escalated to Security (possible AiTM compromise)' },
  categoryAccept: ['host file tampering', 'security', 'host file', 'tampering'],
  resolutionCodeAccept: ['escalate', 'soc', 'security', 'hosts', 'tampering', 'compromise'],
  hints: [
    'The clue: only her laptop is affected and only the login/bank sites - a local override, not a site outage.',
    'Read the hosts file (and nslookup): corporate login and her bank resolve to 45.137.22.90, bypassing DNS.',
    'Threat Intel rates that IP a credential-phishing proxy, and she ran a "network optimizer" and may have entered her password.',
    'This is a possible compromise: do NOT just delete the lines and close, and do NOT tell her to click through. Preserve and escalate to Security.',
  ],
  debrief: 'A "the site looks a little off" ticket hides a serious attack: someone (via the fake "network optimizer") wrote entries into the local hosts file so that corporate and bank logins resolve to an adversary-in-the-middle proxy, which is why the page looks wrong and the certificate fails. The tempting Tier-2 reflex is to delete the offending lines and close - technically it "fixes" the redirect, but it erases evidence and ignores that credentials may already be stolen and that a dropper put them there. The correct move treats the hosts-file tampering plus a malicious IP plus possible credential entry as a compromise: preserve the machine, warn the user off logging in, and escalate to Security to reset credentials and hunt the root cause.',
};

// ---------------------------------------------------------------------------
// SD2-17  SSO / federation login loop - escalate to Identity
// ---------------------------------------------------------------------------
const sd2_17: Scenario = {
  id: 'sd2-17',
  tier: 'sd2',
  title: 'Cloud apps bounce in an endless SSO login loop',
  category: 'Identity',
  difficulty: 3,
  estMinutes: 12,
  objective: 'Distinguish a browser/desktop problem from an identity-provider (SSO/federation) fault, and escalate to the Identity team with evidence instead of resetting passwords or reimaging.',
  intake: {
    kind: 'ticket', number: 'INC457727', subject: 'Every cloud app just keeps sending me back to the login page',
    body: 'IM from Tom Brandt (VP Operations, WIC-WS-3020): clicking any cloud app (WorkSuite, the ERP portal, the travel tool) bounces him through the SSO sign-in and right back to sign-in, forever. His Windows login and network are fine. He already cleared cache and tried another browser and his phone - same loop everywhere.',
    requester: 'tbrandt', channel: 'im', priority: 'P2', category: 'Application', openedAt: ago(24), affectedHost: 'WIC-WS-3020',
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const u = findUser(w, 'tbrandt')!;
    // The IdP/federation is failing to issue a valid assertion for him across ALL relying-party
    // apps and ALL devices -> not a desktop/browser problem. Identity-team territory.
    u.recentSignIns = [
      { time: ago(10), ip: '10.20.10.50', location: 'Wichita, US', app: 'WorkSuite SSO (SAML)', result: 'failure', reason: 'assertion rejected - AudienceRestriction / federation mapping', device: 'WIC-WS-3020', mfa: 'satisfied' },
      { time: ago(12), ip: '10.20.10.50', location: 'Wichita, US', app: 'ERP portal (SSO)', result: 'failure', reason: 'SSO redirect loop - no valid session token issued', device: 'WIC-WS-3020', mfa: 'satisfied' },
      { time: ago(15), ip: '198.51.100.77', location: 'Wichita, US', app: 'WorkSuite SSO (SAML, mobile)', result: 'failure', reason: 'assertion rejected - federation mapping', device: 'iPhone', mfa: 'satisfied' },
      { time: ago(60 * 26), ip: '10.20.10.50', location: 'Wichita, US', app: 'Windows Sign-in', result: 'success', device: 'WIC-WS-3020', mfa: 'satisfied' },
    ];
    addLog(w, { time: ago(10), source: 'cloud', user: 'tbrandt', srcIp: '10.20.10.50', action: 'sso_fail', message: 'SAML assertion for tbrandt rejected by relying party: NameID/immutableId mismatch after IdP federation change. MFA satisfied but no session issued. Redirect loop.', fields: { result: 'failure', app: 'SSO', mfa: 'satisfied' } });
    addLog(w, { time: ago(12), source: 'cloud', user: 'tbrandt', srcIp: '10.20.10.50', action: 'sso_fail', message: 'ERP portal SSO: user returned to IdP without a valid token (loop). Federation metadata / claim mapping suspected.', fields: { result: 'failure', app: 'ERP', mfa: 'satisfied' } });
    // Red herring: his desktop is healthy - a benign successful local logon and no host errors.
    const h = host(w, 'WIC-WS-3020');
    addEvent(h, { id: 4624, level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'An account was successfully logged on. Account: tbrandt. Logon Type: 2 (Interactive). (Desktop login is fine.)', time: ago(60 * 26) });
  },
  contactWith: 'tbrandt',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10003."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll confirm on the desk number on record before we dig in.', answer: 'Callback to the number on record reaches Tom. Verified.', purpose: 'verify' },
    { id: 'devices', question: 'You said you tried another browser and your phone - did the loop happen on ALL of them?', answer: '"Yes - Chrome, Edge, and my iPhone. Same loop every time, every app."', purpose: 'clarify', reveals: 'all-devices' },
    { id: 'apps', question: 'Is it every SSO app, or just one?', answer: '"Every single one that makes me sign in through the company portal."', purpose: 'clarify', reveals: 'all-apps' },
    { id: 'change', question: 'Did you get any notice about a sign-in or identity system change recently?', answer: '"There was an email that IT was \'upgrading single sign-on\' over the weekend."', purpose: 'clarify', reveals: 'sso-change' },
    { id: 'coffee', question: 'How\'s the plant expansion going?', answer: '"On schedule. Can we get me back into my apps?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Checked the escalation matrix - Identity owns SSO/federation (KB-0004)', match: { tool: 'kb', action: 'read', target: 'KB-0004' }, hint: 'KB-0004: SSO/federation and identity-provider issues belong to the Identity team.' },
    { id: 'signins', label: 'Reviewed sign-ins: SSO/SAML assertions rejected across all apps and devices, MFA satisfied', match: { tool: 'directory', action: 'view_signins', target: 'tbrandt' }, hint: 'The failures are SSO assertion/federation rejections, not password failures - and MFA passes.' },
    { id: 'account', label: 'Confirmed the account itself is healthy (enabled, not locked, Windows login works)', match: [{ tool: 'directory', action: 'view', target: 'tbrandt' }, { tool: 'rdp', action: 'view_events', target: 'WIC-WS-3020', params: { log: 'Security' } }], weight: 0.5 },
  ],
  required: [
    { id: 'escalate', label: 'Escalated to the Identity team with the SSO/federation evidence', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'reset_pw', label: 'Reset his password to fix the loop', why: 'This is not a credential failure - MFA is satisfied and Windows login works. The IdP is rejecting the SSO assertion. A password reset does nothing for a federation/claim-mapping problem and just disrupts him further.', match: { tool: 'directory', action: 'reset_password', target: 'tbrandt' }, skill: 'technical', penalty: 0.3 },
    { id: 'reimage', label: 'Reimaged / rebuilt the desktop as a fix', why: 'The loop happens on every device including his phone, so the desktop is not the cause. Reimaging is a heavy, pointless fix for an identity-provider issue.', match: [{ tool: 'rdp', action: 'reboot', target: 'WIC-WS-3020' }, { tool: 'ticket', action: 'reply', target: 'r_reimage' }], skill: 'efficiency', penalty: 0.3 },
    { id: 'soc', label: 'Escalated to Security as a compromise', why: 'Failed SSO can look alarming, but MFA is satisfied and the failures are federation-mapping rejections following a planned SSO upgrade - a configuration fault owned by Identity, not an attack.', match: { tool: 'ticket', action: 'reply', target: 'r_soc' }, skill: 'process', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'This isn\'t your PC or your password - your Windows login and MFA both work fine. The problem is our single sign-on: after the weekend SSO upgrade, the identity provider is rejecting your sign-in assertion (a federation/claim-mapping mismatch), so every app sends you back to the login page in a loop. That\'s exactly why it happens in every browser and on your phone too. Fixing federation is the Identity team\'s area, so I\'m escalating to them as P2 with your failed SSO sign-ins and the assertion errors, and flagging the timing with the SSO change. I\'ll keep you posted; in the meantime the loop will persist, so no need to keep retrying.', scores: { communication: 1, process: 1 }, feedback: 'Correctly rules out desktop/password, identifies a federation fault, and escalates to Identity with evidence.' },
    { id: 'r_reset', text: 'Let me reset your password - login loops usually clear after a fresh password.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'MFA passes and Windows login works; the assertion is being rejected. A reset does nothing for federation.' },
    { id: 'r_reimage', text: 'Your browser profile is probably corrupt - I\'ll reimage the laptop to be safe.', scores: { communication: 0.3, technical: 0.1 }, feedback: 'It loops on his phone too, so the desktop isn\'t the cause. This is an IdP problem.' },
    { id: 'r_soc', text: 'Repeated failed sign-ins look like an attack - escalating to Security.', scores: { communication: 0.3, process: 0.2 }, feedback: 'MFA is satisfied and these are federation-mapping rejections right after a planned SSO change - a config issue for Identity, not SOC.' },
  ],
  notesRubric: [
    { label: 'the finding (SSO/SAML assertion rejected across all apps and devices; MFA ok)', pattern: /sso|saml|assertion|federation|claim|redirect loop|all (apps|devices)|mfa (ok|satisfied|pass)/i },
    { label: 'ruling out desktop/password (phone loops too; Windows login works)', pattern: /phone|another (browser|device)|not (the )?(desktop|browser|password)|windows login (works|fine)/i },
    { label: 'the escalation to Identity with evidence (and the SSO-change timing)', pattern: /identity team|identity|escalat|sso (upgrade|change)|federation|kb-0004|evidence/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'identity', category: 'Identity - SSO', resolutionCode: 'Escalated to Identity team - SSO/federation assertion failure' },
  categoryAccept: ['sso', 'identity', 'federation'],
  resolutionCodeAccept: ['sso', 'identity', 'federation', 'escalate'],
  hints: [
    'Ask what the trainee already knows: the loop happens on every app AND his phone - that rules out his desktop and browser.',
    'His sign-ins show SSO/SAML assertions rejected with MFA satisfied - a federation/claim-mapping problem, not a password failure.',
    'KB-0004 puts SSO/federation squarely with the Identity team.',
    'Escalate to Identity with the evidence (note the weekend SSO upgrade). Do not reset his password, reimage, or call it a compromise.',
  ],
  debrief: 'A login loop tempts three desktop-shaped fixes - reset the password, reimage the machine, or panic to Security - and all three miss the layer the fault lives in. The evidence rules the endpoint out immediately: it loops on every app and every device, including his phone, while his Windows login and MFA both succeed. The sign-in log shows the identity provider rejecting his SSO assertion after a planned federation upgrade - a claim-mapping/config problem. That belongs to the Identity team, and the right Tier-2 move is a clean, evidence-backed escalation to them, not thrashing the endpoint or the password.',
};

// ---------------------------------------------------------------------------
// SD2-18  Print spooler crashed for a whole site - fix it on the print server
// ---------------------------------------------------------------------------
const sd2_18: Scenario = {
  id: 'sd2-18',
  tier: 'sd2',
  title: 'Nobody in Denver can print',
  category: 'Printers',
  difficulty: 2,
  estMinutes: 11,
  objective: 'Scope a site-wide print outage to a crashed Spooler service on the print server, restart it and clear the stuck queues per KB-0008 - rather than chasing it on each user\'s PC or escalating it as a network outage.',
  intake: {
    kind: 'ticket', number: 'INC457728', subject: 'Printing is down for the whole Denver office',
    body: 'Emailed by Rachel Okafor (CFO) on behalf of several teams: nobody in Denver can print - jobs just sit in the queue and nothing comes out, across multiple printers and floors. Started about half an hour ago. Wichita seems unaffected.',
    requester: 'rokafor', channel: 'email', priority: 'P3', category: 'Printers', openedAt: ago(30),
  },
  priorityExpected: 'P2',
  setup: (w) => {
    const ps = w.servers.find((s) => s.id === 'DEN-PRINT01')!;
    // The Spooler service on the print server crashed; every Denver queue is stuck with jobs.
    const spooler = ps.services.find((s) => s.name === 'Spooler');
    if (spooler) { spooler.status = 'failed'; }
    ps.events.push(
      { id: 7034, time: ago(28), level: 'Error', source: 'Service Control Manager', log: 'System', message: 'The Print Spooler service terminated unexpectedly. It has done this 1 time(s).' },
      { id: 7031, time: ago(28), level: 'Error', source: 'Service Control Manager', log: 'System', message: 'The Print Spooler service terminated unexpectedly. Recovery action (restart) was NOT taken.' },
      { id: 372, time: ago(27), level: 'Error', source: 'PrintService', log: 'System', message: 'The print spooler failed to process a job and the service stopped; queued documents are held.' },
    );
    if (ps.printQueues) {
      for (const q of ps.printQueues) {
        if (q.name.startsWith('DEN-')) { q.status = 'error'; q.jobs = 6 + (q.name.length % 5); q.error = 'Spooler stopped - jobs held'; }
      }
    }
    // Red herring: one Denver printer also happens to be low on toner (a real but separate P4).
    if (ps.printQueues) {
      const copier = ps.printQueues.find((q) => q.name === 'DEN-PRN-2F-Copier');
      if (copier) { copier.error = 'Spooler stopped - jobs held (note: also low toner - separate facilities item)'; }
    }
  },
  contactWith: 'rokafor',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10002."', purpose: 'verify' },
    { id: 'scope', question: 'Is it every printer in Denver or one specific device?', answer: '"Every printer people have tried on multiple floors. All of Denver, as far as I can tell."', purpose: 'clarify', reveals: 'site-wide' },
    { id: 'wichita', question: 'Have you heard whether Wichita can still print?', answer: '"Someone in Wichita said theirs is fine."', purpose: 'clarify', reveals: 'denver-only' },
    { id: 'when', question: 'Roughly when did it start, and did anything change?', answer: '"About half an hour ago. Nobody did anything that I know of."', purpose: 'clarify', reveals: 'sudden' },
    { id: 'coffee', question: 'How\'s quarter-end in Finance?', answer: '"Hectic - which is why we need to print. Please hurry."', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the printer troubleshooting SOP (KB-0008)', match: { tool: 'kb', action: 'read', target: 'KB-0008' }, hint: 'KB-0008: whole-queue problems are checked and fixed on the print server, per-user problems on the PC.' },
    { id: 'services', label: 'Found the Spooler service failed on the print server (DEN-PRINT01)', match: [{ tool: 'server', action: 'view_services', target: 'DEN-PRINT01' }, { tool: 'server', action: 'view', target: 'DEN-PRINT01' }], hint: 'Site-wide = look at the print SERVER. Is the Spooler running there?' },
    { id: 'queues', label: 'Saw every Denver queue stuck with held jobs', match: { tool: 'server', action: 'view_print_queues', target: 'DEN-PRINT01' }, hint: 'All Denver queues in error with jobs piled up points at the server\'s spooler, not the printers.' },
    { id: 'events', label: 'Read the server events showing the Spooler crash (7034/7031)', match: { tool: 'server', action: 'view_events', target: 'DEN-PRINT01' }, weight: 0.5 },
  ],
  required: [
    { id: 'restart', label: 'Restarted the Spooler service on the print server', match: [{ tool: 'server', action: 'restart_service', target: 'DEN-PRINT01', params: { service: /spooler/i } }, { tool: 'server', action: 'start_service', target: 'DEN-PRINT01', params: { service: /spooler/i } }], skill: 'technical' },
    { id: 'clear', label: 'Cleared/resumed the stuck queues', match: [{ tool: 'server', action: 'clear_queue', target: 'DEN-PRINT01' }, { tool: 'server', action: 'resume_queue', target: 'DEN-PRINT01' }], skill: 'technical', after: 'restart', weight: 0.5 },
  ],
  forbidden: [
    { id: 'perpc', label: 'Chased it on each user\'s PC (restarted the client Spooler / re-added printers)', why: 'The whole site is down at once - that is the server\'s spooler, not dozens of PCs. Restarting the client Spooler on individual machines is per-user troubleshooting (KB-0008) and wastes time on a site-wide server issue.', match: [{ tool: 'rdp', action: 'restart_service' }, { tool: 'terminal', action: 'sc_start' }], skill: 'process', penalty: 0.3 },
    { id: 'reboot_server', label: 'Rebooted the entire print server as the first move', why: 'A full server reboot is a heavy hammer that disrupts anything else the server does; restarting just the Spooler service and clearing the queues fixes it far faster and more surgically.', match: { tool: 'server', action: 'reboot', target: 'DEN-PRINT01' }, skill: 'efficiency', penalty: 0.2 },
    { id: 'escalate_net', label: 'Escalated to the Network team as a site outage', why: 'The network is fine and Wichita prints normally - only Denver printing is down, and the server event log shows the Spooler crashed. This is a print-server service fix, not a network outage.', match: { tool: 'ticket', action: 'reply', target: 'r_network' }, skill: 'process', penalty: 0.2 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Found it: the Print Spooler service on the Denver print server (DEN-PRINT01) crashed about half an hour ago - the server log shows it terminated and didn\'t auto-restart, which is why every Denver queue is stuck holding jobs while Wichita (a different server) is fine. I restarted the Spooler service and cleared the held queues, and jobs are flowing again now - your pending documents should print shortly. Separately, the 2F copier is low on toner, so I\'ve logged a quick facilities item for that. I\'ll also set the Spooler to auto-restart on failure so a single crash doesn\'t take printing down site-wide again.', scores: { communication: 1, technical: 1, process: 1 }, feedback: 'Scopes it to the server\'s Spooler, restarts and clears queues, separates the toner red herring, and prevents recurrence.' },
    { id: 'r_perpc', text: 'I\'ll restart the print spooler on each affected PC and re-add the printers.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'Per-PC troubleshooting for a whole-site outage. The crash is on the server\'s spooler; fix it there.' },
    { id: 'r_network', text: 'Printing\'s down for the whole office - this is a network outage, escalating to Network.', scores: { communication: 0.3, process: 0.2 }, feedback: 'The network is up and Wichita prints fine. The server log shows the Spooler crashed - restart it.' },
    { id: 'r_reboot', text: 'I\'ll reboot the whole print server to clear it.', scores: { communication: 0.4, technical: 0.4, efficiency: 0.2 }, feedback: 'A full reboot is overkill and disruptive; restart the Spooler service and clear the queues instead.' },
  ],
  notesRubric: [
    { label: 'the cause (Spooler service crashed on the print server)', pattern: /spooler|print spooler|7034|7031|service (crash|fail|stop|terminat)|den-print01/i },
    { label: 'the scope (whole Denver site, Wichita fine = server, not network/PC)', pattern: /site-?wide|whole (site|office|denver)|all (queues|printers)|wichita (fine|unaffect)|server|not (a )?(network|per-?pc)/i },
    { label: 'the fix (restart the Spooler service + clear the stuck queues)', pattern: /restart(ed)? (the )?spooler|start.*spooler|clear.*queue|resume.*queue|flush.*queue/i },
  ],
  closure: { disposition: 'resolve', category: 'Printers - Spooler (server)', resolutionCode: 'Restarted print server Spooler; cleared stuck queues' },
  categoryAccept: ['spooler', 'printers', 'printer', 'print'],
  resolutionCodeAccept: ['spooler', 'restart', 'queue', 'print'],
  hints: [
    'Scope it first: all of Denver at once, Wichita fine - that points at the Denver print SERVER, not PCs or the network.',
    'Check DEN-PRINT01: the Spooler service has failed and every Denver queue is stuck with held jobs (server events 7034/7031).',
    'Restart the Spooler service on the server and clear/resume the stuck queues (KB-0008).',
    'Don\'t chase it PC-by-PC, don\'t reboot the whole server, and don\'t escalate it as a network outage. (The 2F toner is a separate P4.)',
  ],
  debrief: 'The scope test does the heavy lifting: an entire site losing printing at once, while the other site is fine, is a server-side failure, not dozens of coincidental PC problems or a network outage. The print server\'s event log names it outright - the Spooler service crashed and did not auto-restart, so every Denver queue backed up. KB-0008 says whole-queue issues are handled on the server, and the fix is quick and surgical: restart the Spooler service and clear the held queues, rather than rebooting the whole server or touching each workstation. A good tech also spots the low-toner note as an unrelated facilities item and sets the service to auto-restart to prevent a repeat.',
};

// ---------------------------------------------------------------------------
// SD2-19  802.1x Wi-Fi won't reconnect after a password change (stale creds)
// ---------------------------------------------------------------------------
const sd2_19: Scenario = {
  id: 'sd2-19',
  tier: 'sd2',
  title: 'Corporate Wi-Fi won\'t reconnect after a password change',
  category: 'Networking',
  difficulty: 3,
  estMinutes: 11,
  objective: 'Recognise that 802.1x corporate Wi-Fi authenticates with domain credentials, so a stored profile keeps the OLD password after a reset - update/reconnect it instead of resetting the password again or blaming the access points.',
  intake: {
    kind: 'ticket', number: 'INC457729', subject: 'Can\'t get on the office Wi-Fi since I changed my password',
    body: 'Texted in (SMS-to-ticket): Jenna Morales (AP Specialist, DEN-LT-1041) changed her password this morning and now the Kestrel-Corp Wi-Fi won\'t connect - "can\'t connect to this network". Wired at her desk works, and coworkers\' Wi-Fi is fine. Webmail works with the new password.',
    requester: 'jmorales', channel: 'sms', priority: 'P3', category: 'Network', openedAt: ago(25), affectedHost: 'DEN-LT-1041',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const u = findUser(w, 'jmorales')!;
    u.passwordLastSet = ago(60 * 3); // changed ~3h ago
    // Webmail with the NEW password works; only the 802.1x Wi-Fi profile still has the OLD one.
    u.recentSignIns = [
      { time: ago(10), ip: '10.10.20.41', location: 'Denver, US', app: 'WorkSuite Mail (browser)', result: 'success', device: 'DEN-LT-1041', mfa: 'satisfied' },
      { time: ago(12), ip: '10.10.10.5', location: 'Denver, US', app: '802.1x Wi-Fi (RADIUS/PEAP) Kestrel-Corp', result: 'failure', reason: 'bad credentials (stored profile - old password)', device: 'DEN-LT-1041' },
      { time: ago(18), ip: '10.10.10.5', location: 'Denver, US', app: '802.1x Wi-Fi (RADIUS/PEAP) Kestrel-Corp', result: 'failure', reason: 'bad credentials (stored profile - old password)', device: 'DEN-LT-1041' },
    ];
    const h = host(w, 'DEN-LT-1041');
    h.network.ssid = 'Kestrel-Corp';
    addEvent(h, { id: 12013, level: 'Warning', source: 'Wlan-AutoConfig', log: 'System', message: 'Wireless 802.1X authentication failed for SSID Kestrel-Corp. Reason: Explicit Eap failure received (bad credentials). The stored network profile is using cached credentials.', time: ago(12) });
    addEvent(h, { id: 11006, level: 'Error', source: 'OneX', log: 'System', message: 'Onex 802.1X Authentication failed (SSID Kestrel-Corp). The credentials provided by the wireless profile were rejected by the RADIUS server.', time: ago(12) });
    addLog(w, { time: ago(12), source: 'auth', host: 'DEN-DC01', user: 'jmorales', srcIp: '10.10.10.5', action: 'reject', message: 'RADIUS reject user=jmorales NAS=WAP-Denver EAP=PEAP reason=bad-password (stale Wi-Fi profile credential)', fields: { eventId: 4625 } });
    // Red herring: a benign old Wi-Fi driver warning from long ago.
    addEvent(h, { id: 6062, level: 'Warning', source: 'Wlan-AutoConfig', log: 'System', message: 'The wireless adapter reset once last week (driver power-management). Benign; unrelated.', time: daysAgo(7) });
  },
  contactWith: 'jmorales',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10105."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll confirm on the desk number on record before we change anything.', answer: 'Callback to the number on record reaches Jenna. Verified.', purpose: 'verify' },
    { id: 'webmail', question: 'You said webmail works - with the NEW password, in a browser?', answer: '"Yes, the new password logs me into webmail fine. It\'s only the Wi-Fi that won\'t connect."', purpose: 'clarify', reveals: 'new-pw-works' },
    { id: 'others', question: 'Are coworkers on Kestrel-Corp Wi-Fi okay, or is the Wi-Fi down for the area?', answer: '"The person next to me is on Wi-Fi fine. It\'s just my laptop."', purpose: 'clarify', reveals: 'single-host' },
    { id: 'wired', question: 'Does your wired dock connection work in the meantime?', answer: '"Yes, when I\'m docked the cable works. It\'s just Wi-Fi when I\'m in meetings."', purpose: 'clarify', reveals: 'workaround' },
    { id: 'lunch', question: 'How\'s the AP team this week?', answer: '"Slammed. Can we sort the Wi-Fi?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the VPN/remote & cached-credentials SOP (KB-0011)', match: { tool: 'kb', action: 'read', target: 'KB-0011' }, hint: 'Same class of problem as VPN after a reset: the stored profile cached the old password.' },
    { id: 'signins', label: 'Reviewed sign-ins: 802.1x/RADIUS Wi-Fi fails with the old credential; webmail with the new password works', match: { tool: 'directory', action: 'view_signins', target: 'jmorales' }, hint: 'Does anything succeed with the new password? What is failing - and with what reason?' },
    { id: 'events', label: 'Read the System log: Wlan-AutoConfig / OneX 802.1x auth failure (stored profile creds)', match: [{ tool: 'rdp', action: 'view_events', target: 'DEN-LT-1041', params: { log: 'System' } }, { tool: 'rdp', action: 'view_events', target: 'DEN-LT-1041' }], hint: 'The wireless log names an 802.1x credential rejection from the stored profile.' },
    { id: 'net', label: 'Checked the adapter/SSID (Kestrel-Corp, others fine)', match: [{ tool: 'rdp', action: 'view_network', target: 'DEN-LT-1041' }, { tool: 'terminal', action: 'ipconfig_all', target: 'DEN-LT-1041' }], weight: 0.5 },
  ],
  required: [
    { id: 'guide', label: 'Guided updating the stored Wi-Fi credentials (forget/reconnect with the new password)', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'technical' },
  ],
  forbidden: [
    { id: 'reset_pw', label: 'Reset her password again', why: 'The password is fine - webmail proves it works. Resetting it again does not update the credential stored in the Wi-Fi profile and only restarts the expiry clock.', match: { tool: 'directory', action: 'reset_password', target: 'jmorales' }, skill: 'technical', penalty: 0.3 },
    { id: 'escalate_net', label: 'Escalated to the Network team as a Wi-Fi/AP outage', why: 'Coworkers on Kestrel-Corp are fine and only her laptop fails, with a credential-rejection reason. The access points are healthy; this is a stale stored credential on one device, not a network outage.', match: { tool: 'ticket', action: 'reply', target: 'r_network' }, skill: 'process', penalty: 0.25 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Your account and new password are fine - that\'s why webmail works and your wired connection is okay. Our Kestrel-Corp Wi-Fi uses 802.1x, which signs in with your domain password, and your saved Wi-Fi profile still has the OLD password from before this morning\'s change - so the access point keeps rejecting it. The fix is to update the stored credential: "forget" the Kestrel-Corp network and reconnect, entering your NEW password (or update the saved credentials in the Wi-Fi profile). I\'ll walk you through it now; once it reconnects it\'ll stay working. Use the wired dock in the meantime.', scores: { communication: 1, technical: 1 }, feedback: 'Names the 802.1x cached-credential cause, proves it is not the password or the APs, and gives the exact fix.' },
    { id: 'r_reset', text: 'Let me reset your password again - that should let the Wi-Fi reconnect.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'The password is fine (webmail works). A reset doesn\'t touch the old password saved in the Wi-Fi profile.' },
    { id: 'r_network', text: 'The office Wi-Fi must be having problems - escalating to the Network team.', scores: { communication: 0.3, process: 0.2 }, feedback: 'Coworkers are on Wi-Fi fine and only her device fails with a credential rejection. The APs are healthy.' },
    { id: 'r_driver', text: 'Probably a Wi-Fi driver glitch - let me reinstall the wireless driver.', scores: { communication: 0.3, technical: 0.2 }, feedback: 'The adapter authenticates fine otherwise; the failure reason is a bad stored credential, not the driver.' },
  ],
  notesRubric: [
    { label: 'the cause (802.1x Wi-Fi profile cached the OLD domain password)', pattern: /802\.1x|8021x|stored (profile|credential)|cached|old password|peap|radius|wlan|onex/i },
    { label: 'the proof it is not the password or the APs (webmail works; coworkers fine; single host)', pattern: /webmail|new password works|coworkers|others (fine|ok)|single (host|device)|only (her|one)|not (the )?(ap|access point|network)/i },
    { label: 'the fix (forget/reconnect the network with the new password / update stored creds)', pattern: /forget|reconnect|re-?enter|update.*(credential|password)|new password|profile/i },
  ],
  closure: { disposition: 'resolve', category: 'Network - 802.1x Wi-Fi', resolutionCode: 'Updated stored Wi-Fi credentials; reconnected to Kestrel-Corp' },
  categoryAccept: ['802.1x', 'wi-fi', 'wifi', 'network'],
  resolutionCodeAccept: ['wi-fi', 'wifi', '802.1x', 'credential', 'reconnect', 'profile'],
  hints: [
    'This is the Wi-Fi cousin of the VPN-after-reset problem (KB-0011): the stored profile cached the old password.',
    'Kestrel-Corp is 802.1x, so it authenticates with her domain password - and her saved profile still has the old one.',
    'Proof it is not the password or the APs: webmail works with the new password, and coworkers\' Wi-Fi is fine.',
    'Fix: forget the network and reconnect with the new password (or update the saved credential). Don\'t reset the password again or escalate to Network.',
  ],
  debrief: 'Enterprise Wi-Fi (802.1x/PEAP) authenticates with the user\'s domain credentials, so a password change strands any device whose saved Wi-Fi profile still holds the old password - the access point keeps rejecting it. The signals that keep this at the desk are the same as the VPN cached-credential case: webmail works with the new password (so the account is fine), coworkers connect normally (so the APs are fine), and only her device fails with a credential-rejection reason. The fix is to refresh the stored credential - forget and reconnect with the new password. Resetting the password again or escalating to Network both miss that the fault is one stale cached secret on a single laptop.',
};

// ---------------------------------------------------------------------------
// SD2-20  USB peripheral blocked by device-control policy - route the exception
// ---------------------------------------------------------------------------
const sd2_20: Scenario = {
  id: 'sd2-20',
  tier: 'sd2',
  title: 'New USB headset blocked by device-control policy',
  category: 'Access',
  difficulty: 3,
  estMinutes: 11,
  objective: 'Get a legitimate blocked peripheral working the right way - through the device-control exception/approval process - without disabling the security policy, even under executive pressure.',
  intake: {
    kind: 'ticket', number: 'INC457730', subject: 'My new USB headset says it\'s blocked - please just turn the block off',
    body: 'Portal ticket from Diane Vance (CEO, DEN-LT-1001): "I plugged in a new USB headset for my calls and Windows says it\'s been blocked by IT policy. Can you just disable whatever is blocking USB devices on my laptop? I have back-to-back calls."',
    requester: 'dvance', channel: 'portal', priority: 'P3', category: 'Access', openedAt: ago(30), affectedHost: 'DEN-LT-1001',
  },
  priorityExpected: 'P3',
  setup: (w) => {
    const h = host(w, 'DEN-LT-1001');
    // A legitimate peripheral blocked by USB device-control policy. The right path is an
    // exception/approval, NOT disabling the policy (which protects against USB data theft/malware).
    h.devices.push({ name: 'Jabra Evolve2 USB Headset', class: 'Audio/USB devices', status: 'error', driver: 'n/a', error: 'Device blocked by device-control policy (USB peripheral not on the approved list). Halberd Device Control.' });
    addEvent(h, { id: 3004, level: 'Warning', source: 'Halberd Device Control', log: 'Application', message: 'USB device blocked by policy: VID_0B0E&PID_2470 (Jabra Evolve2 headset). Reason: device class not in the approved allowlist. Submit an exception to allow.', time: ago(28) });
    // Show the policy is applied broadly (a real control), and that an approval process exists.
    h.notes = 'Device-control policy "USB-Peripheral-Allowlist" (Halberd) is enforced fleet-wide. Audio headsets require a one-line exception approved by the Security team; approved VIDs are auto-allowed thereafter. Disabling the policy on a machine is out of scope for the Service Desk.';
    w.chat.push({ id: 'ch-dv', with: 'dvance', messages: [
      { from: 'dvance', time: ago(20), text: 'Any update? I really just need the USB block turned off so my headset works before my next call.' },
    ] });
    // Red herring: her built-in audio works fine (she has a workaround for now).
    const audio = h.devices.find((d) => d.class === 'Sound, video and game controllers');
    if (audio) { audio.status = 'ok'; }
  },
  contactWith: 'dvance',
  contact: [
    { id: 'empid', question: 'Confirm your employee ID, please.', answer: '"E10001."', purpose: 'verify' },
    { id: 'callback', question: 'I\'ll confirm on the desk number on record before I make any change.', answer: 'Callback to the number on record reaches Diane. Verified.', purpose: 'verify' },
    { id: 'device', question: 'What exactly is the device - make and model?', answer: '"A Jabra Evolve2 USB headset, brand new, for my calls."', purpose: 'clarify', reveals: 'legit-peripheral' },
    { id: 'need', question: 'Is your built-in audio working so you can take calls while I sort this?', answer: '"The laptop speakers and mic work, yes, but I want the headset for privacy on calls."', purpose: 'clarify', reveals: 'workaround-exists' },
    { id: 'source', question: 'Just to be safe - is it a normal retail headset, not something someone handed you or found?', answer: '"Bought new from the approved office supplier. Nothing sketchy."', purpose: 'clarify', reveals: 'trusted-source' },
    { id: 'coffee', question: 'How was the board offsite?', answer: '"Fine. Can we get my headset working?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the approval SOP for exceptions to security controls (KB-0006)', match: { tool: 'kb', action: 'read', target: 'KB-0006' }, hint: 'Exceptions to security controls follow an approval path - who signs off, and is the requester\'s seniority enough?' },
    { id: 'esc', label: 'Checked the escalation matrix - security controls are owned by Security (KB-0004)', match: { tool: 'kb', action: 'read', target: 'KB-0004' }, weight: 0.5 },
    { id: 'device', label: 'Confirmed the device is blocked by the device-control policy (not a driver fault)', match: [{ tool: 'rdp', action: 'view_devices', target: 'DEN-LT-1001' }, { tool: 'rdp', action: 'view_system', target: 'DEN-LT-1001' }], hint: 'Device Manager / the block event shows the device is blocked by policy, with a VID/PID and an exception path.' },
  ],
  required: [
    { id: 'route', label: 'Declined to disable the policy and routed a device-control exception for approval', match: { tool: 'ticket', action: 'reply', target: 'r_best' }, skill: 'security' },
  ],
  forbidden: [
    { id: 'disable_policy', label: 'Disabled the device-control policy / service to unblock it', why: 'Device control stops USB-borne malware and data theft fleet-wide. Turning it off - even on one laptop, even for the CEO - removes that protection and is not the Service Desk\'s call. Route an exception for the specific device instead.', match: [{ tool: 'rdp', action: 'disable_service', target: 'DEN-LT-1001' }, { tool: 'rdp', action: 'stop_service', target: 'DEN-LT-1001' }, { tool: 'ticket', action: 'reply', target: 'r_disable' }], skill: 'security', penalty: 0.5 },
    { id: 'force_enable', label: 'Force-enabled the blocked device to bypass the policy', why: 'Forcing the device on locally is just another way of bypassing the control without the approval that lets Security allowlist the specific hardware. Use the exception process, not an override.', match: { tool: 'rdp', action: 'enable_device', target: 'DEN-LT-1001', params: { device: /jabra|headset|usb/i } }, skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'I can get your headset working, but I can\'t switch off the USB device-control policy - that\'s the control that stops malicious or data-stealing USB devices across the whole fleet, and disabling it (even just on your laptop) isn\'t something the desk can do. The right, fast path is an exception for this specific headset: I\'ve submitted a device-control exception to Security for the Jabra Evolve2 (its device ID), which allowlists that model - usually approved quickly. The moment it\'s approved your headset will work, and that model will be pre-approved company-wide. In the meantime your built-in mic and speakers work for your calls. I\'ll flag it as urgent given your schedule.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Holds the security line, explains why, and routes a fast, correctly-approved exception for the specific device.' },
    { id: 'r_disable', text: 'No problem - I\'ll disable the USB device-control policy on your laptop so the headset works.', scores: { communication: 0.4, security: 0.0, process: 0.1 }, feedback: 'Disabling the control removes protection against USB malware/data theft and is out of the desk\'s scope - exactly what an exception process exists to avoid.' },
    { id: 'r_force', text: 'I\'ll just force-enable the device in Device Manager to get around the block.', scores: { communication: 0.4, security: 0.1 }, feedback: 'That bypasses the control without approval. Route the exception so Security allowlists the specific hardware.' },
    { id: 'r_flat', text: 'Sorry, USB devices are blocked by policy - nothing I can do.', scores: { communication: 0.3, security: 0.5, process: 0.3 }, feedback: 'The security answer is right but the service is poor: there IS an approved path - submit the exception for her headset.' },
  ],
  notesRubric: [
    { label: 'the finding (legit peripheral blocked by device-control policy, not a driver fault)', pattern: /device[- ]control|blocked by policy|allowlist|usb (policy|block)|halberd|vid_|not a driver/i },
    { label: 'the decision (do NOT disable the policy; least privilege / security control)', pattern: /not disable|don'?t disable|keep the (policy|control)|not (the )?desk|out of scope|security control|least privilege/i },
    { label: 'the correct path (submit an exception/approval for the specific device to Security)', pattern: /exception|approval|allowlist (the )?device|submit.*(security|exception)|route|specific (device|headset)/i },
  ],
  closure: { disposition: 'pending', category: 'Access - Device Control', resolutionCode: 'Submitted device-control exception for approval; policy left enforced' },
  categoryAccept: ['device control', 'access', 'device'],
  resolutionCodeAccept: ['device control', 'exception', 'approval', 'allowlist', 'pending'],
  hints: [
    'This is a policy decision, not a driver fix - Device Manager shows the headset blocked by the device-control policy, with an exception path.',
    'Read KB-0006/KB-0004: exceptions to security controls go through approval (Security), and the desk does not disable the control.',
    'Do NOT disable the device-control policy/service or force-enable the device - even for the CEO.',
    'Submit a device-control exception for the specific headset (its VID/PID) to Security; flag it urgent. Built-in audio is the interim workaround.',
  ],
  debrief: 'The pressure is seniority and urgency - the CEO wants the USB block simply turned off - but the ask, as written, is to disable a fleet-wide security control that exists to stop USB-borne malware and data exfiltration. That is neither the Service Desk\'s call nor the right fix. The skilled response separates the legitimate need (a real headset from a trusted source) from the dangerous method (killing the policy): keep the control enforced and route a device-control exception that allowlists the specific device through Security\'s approval. Disabling the policy or force-enabling the device both bypass the control; the exception process gets her working quickly and safely, and the built-in audio covers her in the meantime.',
};

export const SD2_SCENARIOS_C: Scenario[] = [
  sd2_11, sd2_12, sd2_13, sd2_14, sd2_15, sd2_16, sd2_17, sd2_18, sd2_19, sd2_20,
];
