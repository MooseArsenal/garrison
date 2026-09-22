import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, addAlert, addMail, setConn } from './helpers';

// ---------------------------------------------------------------------------
// SOC1-11  Failed-login storm that is a broken service account (misconfig)
// ---------------------------------------------------------------------------
const soc1_11: Scenario = {
  id: 'soc1-11',
  tier: 'soc1',
  title: 'Auth failure storm on a service account',
  category: 'Triage',
  difficulty: 3,
  estMinutes: 12,
  objective: 'Reach ground truth on a wall of authentication failures: confirm whether the source is external brute force or an internal service account with stale credentials after a password change, and resolve the misconfiguration instead of firing a containment action.',
  intake: { kind: 'alert', alertId: 'ALT-50111' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50111', time: ago(20), severity: 'medium', source: 'siem',
      title: 'Repeated authentication failures for service account svc_backup from an internal host (10.10.10.60)',
      description: 'SIEM correlation fired on 40+ failed logons for svc_backup over ~15 minutes, all sourced from 10.10.10.60 (DEN-BKP01, the backup server). Determine whether this is a brute-force attack or a misconfiguration.',
      indicators: ['svc_backup', '10.10.10.60'], mitre: ['T1110'], status: 'new', truth: 'benign_true_positive',
    });
    // Ground truth: svc_backup's password was rotated yesterday, but the Veeam backup jobs / a
    // scheduled task on DEN-BKP01 still hold the OLD password, so they fail every run.
    const svc = findUser(w, 'svc_backup')!;
    svc.passwordLastSet = daysAgo(1);
    svc.badPwdCount = 42;
    let m = 35;
    for (let i = 0; i < 8; i++) {
      addLog(w, { time: ago(m), source: 'auth', user: 'svc_backup', srcIp: '10.10.10.60', host: 'DEN-BKP01', action: 'logon_failure', message: `4625 authentication failure user=svc_backup srcip=10.10.10.60 host=DEN-BKP01 reason=bad password (Veeam backup job / scheduled task)`, fields: { eventId: 4625, result: 'failure' } });
      m -= 2;
    }
    addLog(w, { time: ago(60 * 24), source: 'auth', user: 'svc_backup', action: 'password_reset', message: 'Password for service account svc_backup was reset by KESTREL\\mreyes (routine rotation)' });
    // Red herring: one unrelated benign 4625 (a human fat-fingering their password) from a workstation.
    addLog(w, { time: ago(50), source: 'auth', user: 'jwebb', srcIp: '10.10.20.70', action: 'logon_failure', message: '4625 authentication failure user=jwebb srcip=10.10.20.70 reason=bad password (single mistype, then success)', fields: { eventId: 4625, result: 'failure' } });
    w.intel.push({ indicator: '10.10.10.60', type: 'ip', verdict: 'clean', source: 'Internal asset register', tags: ['internal', 'backup-server'], detail: 'DEN-BKP01, the Veeam backup server (authorized). Runs backup jobs as svc_backup.' });
    w.chat.push({ id: 'ch-mr11', with: 'mreyes', messages: [] });
  },
  contactWith: 'mreyes',
  contact: [
    { id: 'rotate', question: 'Ask IT/Sysadmin: was svc_backup\'s password rotated recently, and are the backup jobs updated?', answer: 'Marco Reyes: "Ah — yes, I rotated svc_backup yesterday as part of the quarterly rotation. I must have missed updating the stored credential on the Veeam job and a scheduled task on DEN-BKP01. That\'s the failures. I\'ll fix it now."', purpose: 'clarify', reveals: 'stale-creds' },
    { id: 'external', question: 'Is any of this traffic coming from outside, or only from DEN-BKP01?', answer: 'Marco Reyes: "Only from the backup server. Nothing external touches that account — it\'s not internet-facing and it\'s not interactive-logon enabled."', purpose: 'clarify', reveals: 'internal-only' },
    { id: 'owner', question: 'Who owns the svc_backup account so I can log the notification?', answer: 'Marco Reyes: "That\'s mine / Sysadmin\'s. I own the backup infrastructure."', purpose: 'verify' },
    { id: 'coffee', question: 'How are the backups looking otherwise?', answer: 'Marco Reyes: "Fine apart from this. Why?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the SOC triage standard (KB-0013)', match: { tool: 'kb', action: 'read', target: 'KB-0013' } },
    { id: 'siem', label: 'Pulled the SIEM: all failures come from one internal host (DEN-BKP01), not the internet', match: [{ tool: 'siem', action: 'search', params: { q: /svc_backup|10\.10\.10\.60|bad password|4625/i } }, { tool: 'siem', action: 'pivot', params: { value: /10\.10\.10\.60/ } }], hint: 'Where is the traffic coming from — a single internal host or many external IPs?' },
    { id: 'dir', label: 'Reviewed the service account (recent password change, service account, not interactive)', match: { tool: 'directory', action: 'view', target: 'svc_backup' }, hint: 'When was the password last set? Is this account external-facing?' },
    { id: 'intel', label: 'Looked up the source IP (internal backup server)', match: { tool: 'intel', action: 'lookup', target: '10.10.10.60' } },
    { id: 'confirm', label: 'Confirmed with the account owner / Sysadmin that the password was rotated', match: { tool: 'chat', action: 'send', target: 'mreyes' } },
  ],
  required: [
    { id: 'notify', label: 'Notified the account owner to update the stored credentials', match: { tool: 'chat', action: 'send', target: 'mreyes' }, skill: 'communication' },
    { id: 'classify', label: 'Documented the root cause (stale creds after rotation) and closed as benign true positive', match: { tool: 'ticket', action: 'submit' }, skill: 'documentation' },
  ],
  forbidden: [
    { id: 'disable', label: 'Disabled or reset svc_backup over the alert', why: 'Disabling or re-resetting the backup service account does not fix the stale stored credential and takes the entire backup system offline — a self-inflicted outage on a misconfiguration. The owner just needs to update the saved password on the job.', match: [{ tool: 'directory', action: 'disable', target: 'svc_backup' }, { tool: 'directory', action: 'reset_password', target: 'svc_backup' }], skill: 'security', penalty: 0.5 },
    { id: 'escalate', label: 'Escalated as a brute-force attack / blocked the internal backup server', why: 'The failures come from one internal, authorized host after a password rotation — not an external attacker. Declaring a brute-force incident or blocking DEN-BKP01 cries wolf and breaks backups.', match: [{ tool: 'ticket', action: 'reply', target: 'r_attack' }, { tool: 'perimeter', action: 'block', target: '10.10.10.60' }], skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Triaged the failure storm: all 40+ failures for svc_backup originate from a single internal host, DEN-BKP01 (10.10.10.60, our Veeam backup server), with none from the internet. svc_backup\'s password was rotated yesterday and Marco (Sysadmin) confirms the backup job and a scheduled task on DEN-BKP01 still hold the old credential, so they fail on every run. This is a misconfiguration, not an attack — a benign true positive, severity low. I notified Marco to update the stored credentials and left a tuning note to correlate service-account failures against recent password rotations. No account or perimeter action.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Reached ground truth (internal source, recent rotation, owner confirmation) and fixed the misconfiguration instead of firing a containment action.' },
    { id: 'r_attack', text: 'Brute-force attack on a privileged service account — blocking the source and escalating to CIRT.', scores: { communication: 0.3, security: 0.2, process: 0.1 }, feedback: 'You skipped the source check. Every failure is from our own backup server after a password rotation. Blocking it breaks backups.' },
    { id: 'r_fp', text: 'Nothing was actually compromised — false positive, closing.', scores: { communication: 0.4, process: 0.4 }, feedback: 'The failures are real and the detection fired correctly on authorized (if broken) activity — a benign true positive, not a false positive. The distinction drives tuning.' },
  ],
  notesRubric: [
    { label: 'the source identified (internal backup server, one host)', pattern: /svc_backup|10\.10\.10\.60|den-bkp01|internal|backup server/i },
    { label: 'the root cause (stale credentials after a password rotation)', pattern: /rotat|password (change|reset)|stale|old (cred|password)|misconfig/i },
    { label: 'the disposition (benign true positive, owner notified to fix)', pattern: /benign|true positive|notif|update.*cred|owner|tune/i },
  ],
  closure: { disposition: 'resolve', classification: 'benign_true_positive', severity: 'low', category: 'Triage - Service Account Misconfig', resolutionCode: 'Benign true positive - service account creds stale after password rotation' },
  categoryAccept: ['triage', 'service account', 'misconfig'],
  resolutionCodeAccept: ['benign', 'service account', 'misconfig', 'stale', 'true positive'],
  hints: [
    'KB-0013: reach ground truth before you contain. Start in the SIEM: are the failures external or from one internal host?',
    'Every failure is from 10.10.10.60 (DEN-BKP01). Look up the IP — it is our own backup server.',
    'Check the account in Directory: svc_backup\'s password was set yesterday. Confirm the rotation with the Sysadmin.',
    'Notify the owner to update the stored credentials, classify benign true positive (low). Do NOT disable/reset the account or block the server.',
  ],
  debrief: 'A wall of authentication failures reads as an attack until you check the source. Here it is a single internal, authorized host failing over and over because a service-account password was rotated but the job that runs as it was never updated — a classic operational misconfiguration and a benign true positive. The failure modes are symmetric: the dramatic one (call it brute force, block the host, page CIRT) breaks the backup system, and the lazy one (false positive, move on) leaves the failures repeating and the metric wrong. The resolving action is neither a containment nor a shrug: notify the owner to fix the stored credential.',
};

// ---------------------------------------------------------------------------
// SOC1-12  New admin account created under an authorized change ticket
// ---------------------------------------------------------------------------
const soc1_12: Scenario = {
  id: 'soc1-12',
  tier: 'soc1',
  title: 'New privileged account appeared overnight',
  category: 'Triage',
  difficulty: 3,
  estMinutes: 13,
  objective: 'Triage a privileged-account-creation alert by verifying it against change management before reacting: a new admin account is either an attacker establishing persistence or authorized IT work, and the difference is a change ticket.',
  intake: { kind: 'alert', alertId: 'ALT-50112' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50112', time: ago(45), severity: 'high', source: 'siem',
      title: 'New account created and added to a privileged group: svc_sql added to Server Admins on DEN-DC01',
      description: 'SIEM flagged a 4720 (account created) followed by a 4728 (added to Server Admins) for a new account "svc_sql" at 02:10, created by KESTREL\\mreyes. Confirm whether this is authorized administration or attacker persistence.',
      indicators: ['svc_sql', 'mreyes'], mitre: ['T1136.002', 'T1098'], status: 'new', truth: 'benign_true_positive',
    });
    // Ground truth: mreyes created svc_sql for a new SQL server under change CHG-2301. Authorized.
    w.users.push({
      id: 'svc_sql', displayName: 'svc_sql (service)', title: 'Service Account - SQL Server', department: 'IT',
      email: 'svc_sql@kestreldynamics.com', phone: '', employeeId: 'SVC003', location: 'Denver HQ',
      enabled: true, lockedOut: false, passwordLastSet: ago(60 * 7), passwordNeverExpires: true,
      groups: ['Server Admins'], lastLogon: ago(60 * 6), badPwdCount: 0, mfaEnrolled: false, privileged: true,
      notes: 'Created for new ERP reporting SQL instance (DEN-SQL02).', recentSignIns: [],
    });
    addLog(w, { time: ago(62 * 60 / 60 * 0 + 130), source: 'windows', host: 'DEN-DC01', user: 'mreyes', action: 'account_created', message: '4720 A user account was created: svc_sql by KESTREL\\mreyes (change CHG-2301)', fields: { eventId: 4720 } });
    addLog(w, { time: ago(128), source: 'windows', host: 'DEN-DC01', user: 'mreyes', action: 'group_add', message: '4728 Member added to security group Server Admins: svc_sql by KESTREL\\mreyes', fields: { eventId: 4728 } });
    addLog(w, { time: ago(125), source: 'auth', user: 'mreyes', srcIp: '10.10.20.121', host: 'DEN-LT-1021', action: 'logon', message: '4624 Logon type 2 mreyes on DEN-LT-1021 (admin workstation, MFA satisfied) - normal admin session', fields: { eventId: 4624, result: 'success' } });
    // Red herring: a routine, benign group change for a normal user the same night.
    addLog(w, { time: ago(400), source: 'windows', host: 'DEN-DC01', user: 'kwalsh', action: 'group_add', message: '4728 Member added to security group CAD Users: obennett by KESTREL\\kwalsh (routine access request)', fields: { eventId: 4728 } });
    w.chat.push({ id: 'ch-mr12', with: 'mreyes', messages: [] });
  },
  contactWith: 'mreyes',
  contact: [
    { id: 'created', question: 'Did you create svc_sql and add it to Server Admins last night, and is there a change ticket?', answer: 'Marco Reyes: "Yes — svc_sql is the service account for the new ERP reporting SQL instance (DEN-SQL02) we\'re standing up. It\'s under change CHG-2301, approved by Linda. It needs Server Admins to install."', purpose: 'clarify', reveals: 'authorized' },
    { id: 'chg', question: 'Confirm the change ticket number and approver.', answer: 'Marco Reyes: "CHG-2301, approved by Linda Chen (IT Director). I can forward the ticket."', purpose: 'verify', reveals: 'change-ticket' },
    { id: 'mfa', question: 'Was this done from your admin workstation during a normal session?', answer: 'Marco Reyes: "Yes, from DEN-LT-1021, my usual admin box, logged in with MFA. I did it after hours to avoid load."', purpose: 'clarify', reveals: 'normal-session' },
    { id: 'coffee', question: 'Late night?', answer: 'Marco Reyes: "Very. What\'s up?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the SOC triage standard (KB-0013)', match: { tool: 'kb', action: 'read', target: 'KB-0013' } },
    { id: 'siem', label: 'Pulled the SIEM: creation + group-add both performed by mreyes from his admin workstation', match: [{ tool: 'siem', action: 'search', params: { q: /svc_sql|4720|4728|server admins|mreyes/i } }, { tool: 'siem', action: 'pivot', params: { value: /svc_sql/ } }], hint: 'Who created the account, from where, and was the session itself normal?' },
    { id: 'dir', label: 'Reviewed the new account in Directory (service account for a SQL instance)', match: { tool: 'directory', action: 'view', target: 'svc_sql' }, hint: 'What is the account for? Is the creating admin\'s own account behaving normally?' },
    { id: 'mreyes', label: 'Checked the creating admin\'s own account for signs of compromise (clean)', match: { tool: 'directory', action: 'view_signins', target: 'mreyes' }, weight: 0.5, hint: 'If mreyes were compromised, his sign-ins would look wrong. Do they?' },
    { id: 'confirm', label: 'Verified the change ticket with IT (CHG-2301)', match: { tool: 'chat', action: 'send', target: 'mreyes' } },
  ],
  required: [
    { id: 'classify', label: 'Documented the change ticket / approver and closed as benign true positive', match: { tool: 'ticket', action: 'submit' }, skill: 'documentation' },
  ],
  forbidden: [
    { id: 'disable', label: 'Disabled or deleted svc_sql before verifying the change', why: 'KB-0013: reach ground truth first. Disabling or deleting the new service account before checking change management breaks an authorized SQL rollout mid-flight. Verify, then close.', match: [{ tool: 'directory', action: 'disable', target: 'svc_sql' }, { tool: 'directory', action: 'remove_group', target: 'svc_sql' }], skill: 'security', penalty: 0.5 },
    { id: 'escalate', label: 'Escalated as attacker persistence / privileged-account compromise', why: 'The account was created and grouped by a known admin from his own MFA-backed session under an approved change ticket, and his own account shows no compromise. Declaring persistence cries wolf and burns CIRT.', match: { tool: 'ticket', action: 'reply', target: 'r_attack' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Triaged the new privileged account: the 4720/4728 show svc_sql was created and added to Server Admins by KESTREL\\mreyes at 02:10 from his own admin workstation (DEN-LT-1021) in a normal MFA-backed session, and mreyes\'s account shows no signs of compromise. He confirms svc_sql is the service account for the new ERP reporting SQL instance under change CHG-2301, approved by Linda Chen. This is authorized administration — a benign true positive, severity low. Documented the change ticket and approver; no containment. Left a note that privileged-account-creation alerts should be auto-correlated against open change tickets.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Verified the actor, the session, and the change ticket before touching the account — exactly the discipline the alert is testing.' },
    { id: 'r_attack', text: 'Attacker created a hidden admin account for persistence — disabling it and escalating to CIRT.', scores: { communication: 0.3, security: 0.2, process: 0.1 }, feedback: 'You skipped the change-management check. A known admin created it from his own MFA session under an approved ticket. Disabling it breaks the rollout.' },
    { id: 'r_fp', text: 'Probably just IT doing IT things — false positive, closing.', scores: { communication: 0.4, security: 0.3, process: 0.3 }, feedback: 'Right instinct, wrong label and no evidence. The account really was created (true positive) and it is authorized — that is a benign true positive, and you must document who authorized it.' },
  ],
  notesRubric: [
    { label: 'what happened (new account svc_sql added to Server Admins)', pattern: /svc_sql|4720|4728|server admins|new (admin|account)/i },
    { label: 'the authorization evidence (change ticket / approver / known admin)', pattern: /chg-2301|change|authoriz|mreyes|linda|approv/i },
    { label: 'the classification (benign true positive, documented)', pattern: /benign|true positive|document|expected/i },
  ],
  closure: { disposition: 'resolve', classification: 'benign_true_positive', severity: 'low', category: 'Triage - Authorized Admin Change', resolutionCode: 'Benign true positive - authorized new admin account (change ticket)' },
  categoryAccept: ['triage', 'authorized', 'admin change', 'admin'],
  resolutionCodeAccept: ['benign', 'authorized', 'admin', 'change', 'true positive'],
  hints: [
    'KB-0013: verify authorization before you react, especially for privileged-account changes.',
    'In the SIEM, the 4720/4728 were both done by mreyes from his own admin workstation in a normal session.',
    'Check mreyes\'s own account for compromise (clean), then confirm the change ticket (CHG-2301) with him.',
    'Close as benign true positive (low) and document the change ticket and approver. Do NOT disable the account or escalate.',
  ],
  debrief: 'A new account in a privileged group is exactly what an attacker builds for persistence — and exactly what IT builds when standing up a new server. You cannot tell them apart from the alert alone. The tells are all in provenance: who created it, from what host, in what kind of session, and whether a change ticket exists. Here a known admin did it from his own MFA-backed workstation under an approved change, and his account is clean, so it is a benign true positive. The trap is disabling the account before checking — you would break an authorized rollout to "contain" a non-attack.',
};

// ---------------------------------------------------------------------------
// SOC1-13  Mass file-deletion DLP alert — user cleaned up their own folder
// ---------------------------------------------------------------------------
const soc1_13: Scenario = {
  id: 'soc1-13',
  tier: 'soc1',
  title: 'Mass file deletion on the Engineering share',
  category: 'DLP',
  difficulty: 2,
  estMinutes: 12,
  objective: 'Right-size a mass-deletion alert: scope exactly what was deleted and whether it is recoverable, talk to the user to establish intent, and distinguish an honest housekeeping cleanup from destructive insider activity.',
  intake: { kind: 'alert', alertId: 'ALT-50113' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50113', time: ago(24), severity: 'medium', source: 'dlp',
      title: 'Mass file deletion: nfoster deleted 412 files under \\\\FS01\\Engineering in ~3 minutes',
      description: 'File-audit/DLP rule "bulk delete" fired: nfoster removed 412 files from \\\\FS01\\Engineering\\_scratch\\nfoster between 08:44 and 08:47. Scope what was deleted, confirm intent, and classify.',
      user: 'nfoster', indicators: ['nfoster'], mitre: ['T1485'], status: 'new', truth: 'benign_true_positive',
    });
    // Ground truth: nfoster deleted her OWN scratch folder of superseded CAD exports; non-sensitive; recoverable from backup.
    for (let i = 0; i < 6; i++) {
      addLog(w, { time: ago(24 - i * 0.4), source: 'windows', host: 'DEN-WS-2010', user: 'nfoster', action: 'file_delete', message: `4660/4663 delete on \\\\FS01\\Engineering\\_scratch\\nfoster\\export_v${i}.step by nfoster (own scratch folder)`, fields: { eventId: 4663 } });
    }
    addLog(w, { time: ago(24), source: 'windows', host: 'DEN-WS-2010', user: 'nfoster', action: 'bulk_delete', message: 'Bulk delete: 412 files removed from \\\\FS01\\Engineering\\_scratch\\nfoster (superseded STEP/PDF exports) by nfoster from DEN-WS-2010', fields: { count: 412 } });
    // Red herring: a routine temp-file cleanup by another user, unrelated.
    addLog(w, { time: ago(120), source: 'windows', host: 'DEN-WS-2011', user: 'obennett', action: 'file_delete', message: 'Delete of ~\\AppData\\Local\\Temp\\*.tmp by obennett (routine temp cleanup)', fields: { eventId: 4663 } });
    const fs = w.servers.find((s) => s.id === 'DEN-FS01')!;
    fs.backups = [{ job: 'FS01-Daily-Shares', lastRun: ago(60 * 9), status: 'success', restorePoints: 30 }];
    w.chat.push({ id: 'ch-nf13', with: 'nfoster', messages: [] });
  },
  contactWith: 'nfoster',
  contact: [
    { id: 'why', question: 'Did you delete a few hundred files from your Engineering scratch folder this morning, and why?', answer: 'Nora Foster: "Oh, yes — that\'s my \\_scratch folder. I cleaned out old superseded STEP and PDF exports I don\'t need anymore. It was getting huge. Was that a problem?"', purpose: 'clarify', reveals: 'housekeeping' },
    { id: 'content', question: 'Were any of those the current/released drawings or anything shared with the team?', answer: 'Nora Foster: "No — those are just my throwaway export attempts. The real released files are in \\Engineering\\Released, I didn\'t touch those."', purpose: 'clarify', reveals: 'non-sensitive' },
    { id: 'empid', question: 'Confirm your employee ID before I note this on your account.', answer: 'Nora Foster: "E10140."', purpose: 'verify' },
    { id: 'coffee', question: 'How\'s the new SolidWorks version treating you?', answer: 'Nora Foster: "Fine. Is that why you\'re calling?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the SOC triage standard (KB-0013)', match: { tool: 'kb', action: 'read', target: 'KB-0013' } },
    { id: 'siem', label: 'Scoped exactly what was deleted (own \\_scratch folder, superseded exports)', match: [{ tool: 'siem', action: 'search', params: { q: /nfoster|_scratch|delete|superseded|engineering/i } }, { tool: 'siem', action: 'pivot', params: { value: /nfoster/ } }], hint: 'WHICH files, and were they current/released or the user\'s own scratch?' },
    { id: 'backups', label: 'Confirmed the deletion is recoverable (FS01 shadow copies / 30 restore points)', match: [{ tool: 'server', action: 'view_backups', target: 'DEN-FS01' }, { tool: 'server', action: 'view_shares', target: 'DEN-FS01' }], hint: 'Even if it were a mistake, is it recoverable? Check FS01 backups.' },
    { id: 'dir', label: 'Checked the user\'s role/access (Engineering, her own scratch area)', match: { tool: 'directory', action: 'view', target: 'nfoster' }, weight: 0.5 },
    { id: 'contacted', label: 'Contacted the user and established intent (honest housekeeping)', match: { tool: 'chat', action: 'send', target: 'nfoster' } },
  ],
  required: [
    { id: 'contact', label: 'Contacted the user to establish intent', match: { tool: 'chat', action: 'send', target: 'nfoster' }, skill: 'communication' },
    { id: 'classify', label: 'Logged and closed as a benign deletion (recoverable, non-sensitive)', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'insider', label: 'Opened an insider / data-destruction incident and escalated to CIRT/Legal', why: 'A user tidying her own scratch folder of superseded exports — recoverable from backup, nothing released or shared — is housekeeping, not sabotage. Declaring a destruction incident burns CIRT and Legal cycles on a non-event.', match: [{ tool: 'ticket', action: 'reply', target: 'r_insider' }, { tool: 'incident', action: 'set_phase' }], skill: 'process', penalty: 0.5 },
    { id: 'disable', label: 'Disabled the user or wiped her workstation over the deletion', why: 'Disabling an engineer or wiping her machine for deleting her own throwaway files is punitive and disproportionate. Confirm intent and log it.', match: [{ tool: 'directory', action: 'disable', target: 'nfoster' }, { tool: 'assets', action: 'remote_wipe' }], skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Scoped the deletion: nfoster removed 412 files from her own \\\\FS01\\Engineering\\_scratch\\nfoster folder — superseded STEP/PDF export attempts, no released or shared drawings, nothing sensitive. She confirms it was housekeeping (the folder was huge) and never touched \\Engineering\\Released. The data is recoverable anyway (FS01 has shadow copies and 30 restore points). This is a benign true positive, severity low. I logged it, coached her that bulk deletions on the share trip an alert and to flag Sysadmin next time, and offered a restore if she wants any back. No escalation.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Scoped what actually left, confirmed intent and recoverability, and classified proportionately — benign, logged, coached.' },
    { id: 'r_insider', text: 'Mass deletion of Engineering data — opening a data-destruction / insider incident and escalating to CIRT and Legal.', scores: { communication: 0.3, process: 0.1 }, feedback: 'Over-escalation. It was her own scratch folder of superseded exports, recoverable from backup, with honest intent. Save the insider machinery for released/sensitive data or concealment.' },
    { id: 'r_ignore', text: 'Just DLP noise — closing with no action.', scores: { communication: 0.3, process: 0.3 }, feedback: 'It is a real bulk deletion worth confirming and logging; you should still talk to the user and note it so a genuinely destructive pattern would stand out.' },
  ],
  notesRubric: [
    { label: 'what was deleted and its sensitivity (own scratch, superseded exports)', pattern: /_scratch|scratch|superseded|export|non-sensitive|not released|own folder/i },
    { label: 'recoverability confirmed (shadow copies / backups)', pattern: /backup|shadow cop|restore|recover|30 (restore )?point/i },
    { label: 'the disposition (benign, intent confirmed, logged/coached)', pattern: /benign|housekeep|intent|coach|logged|low/i },
  ],
  closure: { disposition: 'resolve', classification: 'benign_true_positive', severity: 'low', category: 'DLP - Benign File Deletion', resolutionCode: 'Benign true positive - user deleted own non-sensitive files (recoverable)' },
  categoryAccept: ['dlp', 'file deletion', 'deletion', 'benign'],
  resolutionCodeAccept: ['benign', 'deletion', 'recoverable', 'housekeep', 'true positive'],
  hints: [
    'KB-0013 defines benign true positive. Scope exactly WHICH files were deleted before you judge.',
    'The SIEM shows it was her own \\_scratch folder of superseded STEP/PDF exports — not released or shared drawings.',
    'Check FS01 backups: 30 restore points, so it is recoverable. Talk to nfoster to confirm intent.',
    'Close as benign (low), log and coach. Do NOT open an insider incident or disable the user.',
  ],
  debrief: 'Mass-deletion alerts trigger the same over-reaction reflex as any destruction detection, and the discipline is to scope before you judge. What matters is exactly what was deleted (her own scratch exports, not released or shared work), whether it is recoverable (yes — shadow copies and 30 restore points), and the user\'s intent (honest housekeeping). All three point to a benign true positive. The insider machinery — CIRT, Legal, disabling the account — is reserved for released or sensitive data, privileged access, or evidence of concealment. None of that is present, so the right move is to confirm, log, and coach.',
};

// ---------------------------------------------------------------------------
// SOC1-14  Impossible travel that is a legitimate newly-enrolled device
// ---------------------------------------------------------------------------
const soc1_14: Scenario = {
  id: 'soc1-14',
  tier: 'soc1',
  title: 'Impossible travel — or a new phone?',
  category: 'Identity',
  difficulty: 3,
  estMinutes: 13,
  objective: 'Work an impossible-travel alert to a benign verdict without guessing: examine the sign-ins and IP reputation, check for post-auth persistence, and confirm with the user that the second location is a device they just enrolled while travelling.',
  intake: { kind: 'alert', alertId: 'ALT-50114' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50114', time: ago(25), severity: 'medium', source: 'cloud',
      title: 'Impossible travel: dkim signed in from Denver and then Chicago within 30 minutes',
      description: 'WorkSuite flagged two successful sign-ins for dkim that look geographically impossible in the time elapsed. Determine whether this is account takeover or a benign new device / travel.',
      user: 'dkim', indicators: ['70.60.14.9', '166.205.88.30'], mitre: ['T1078'], status: 'new', truth: 'benign_true_positive',
    });
    const u = findUser(w, 'dkim')!;
    // Ground truth: dkim is at a recruiting event in Chicago and enrolled a new phone this morning.
    // Denver login is his laptop; Chicago login is the newly enrolled phone on a clean mobile-carrier IP, MFA satisfied.
    u.recentSignIns = [
      { time: ago(22), ip: '166.205.88.30', location: 'Chicago, US', app: 'WorkSuite Mail', result: 'success', device: 'iPhone (newly enrolled) - dkim', mfa: 'satisfied' },
      { time: ago(48), ip: '70.60.14.9', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1051', mfa: 'satisfied' },
      { time: ago(60 * 20), ip: '70.60.14.9', location: 'Denver, US', app: 'WorkSuite Mail', result: 'success', device: 'DEN-LT-1051', mfa: 'satisfied' },
    ];
    // No malicious inbox rule (contrast the ATO scenario): mailbox is clean.
    addLog(w, { time: ago(23), source: 'cloud', user: 'dkim', srcIp: '166.205.88.30', action: 'device_enroll', message: 'New device registered for dkim: iPhone (company MFA app enrolled), geo=Chicago,US mfa=satisfied' });
    addLog(w, { time: ago(22), source: 'cloud', user: 'dkim', srcIp: '166.205.88.30', action: 'signin', message: 'WorkSuite sign-in success user=dkim app=Mail geo=Chicago,US device=iPhone (newly enrolled) mfa=satisfied', fields: { result: 'success' } });
    w.intel.push({ indicator: '166.205.88.30', type: 'ip', verdict: 'clean', source: 'Carrier lookup', tags: ['mobile', 'us', 'att'], detail: 'AT&T Mobility carrier NAT range, Chicago. Consumer mobile data — not an anonymizer or hosting provider.' });
    w.intel.push({ indicator: '70.60.14.9', type: 'ip', verdict: 'clean', source: 'ISP lookup', tags: ['residential', 'us'], detail: 'CenturyLink residential Denver. Matches dkim\'s known home IP.' });
    w.chat.push({ id: 'ch-dk14', with: 'dkim', messages: [] });
  },
  contactWith: 'dkim',
  contact: [
    { id: 'travel', question: 'Are you in Chicago right now, and did you set up a new phone this morning?', answer: 'David Kim: "Yes! I\'m at a campus recruiting event in Chicago all week. I got a new work phone and set up the authenticator on it this morning. That\'s probably what you\'re seeing."', purpose: 'clarify', reveals: 'travel-new-device' },
    { id: 'mfa', question: 'Did you approve the MFA prompts yourself, or did any come unexpectedly?', answer: 'David Kim: "I approved them — I was setting the phone up. No weird ones."', purpose: 'clarify', reveals: 'self-approved' },
    { id: 'empid', question: 'Confirm your employee ID before I close this out.', answer: 'David Kim: "E10111."', purpose: 'verify' },
    { id: 'weather', question: 'How\'s Chicago?', answer: 'David Kim: "Windy. Anything else?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the suspicious sign-in playbook (KB-0016)', match: { tool: 'kb', action: 'read', target: 'KB-0016' } },
    { id: 'signins', label: 'Reviewed the sign-ins (Denver laptop then Chicago on a newly enrolled phone, both MFA satisfied)', match: { tool: 'directory', action: 'view_signins', target: 'dkim' }, hint: 'Compare device, MFA result, and IP type for the two logins.' },
    { id: 'intel1', label: 'Looked up the Chicago IP (clean mobile carrier, not an anonymizer)', match: { tool: 'intel', action: 'lookup', target: '166.205.88.30' } },
    { id: 'intel2', label: 'Looked up the Denver IP (his known home IP)', match: { tool: 'intel', action: 'lookup', target: '70.60.14.9' }, weight: 0.5 },
    { id: 'rules', label: 'Checked the mailbox for attacker persistence (no malicious inbox rules)', match: { tool: 'mail', action: 'view_mailbox', target: 'dkim' }, hint: 'A real takeover usually leaves an inbox rule hiding IT/security mail. Is there one?' },
    { id: 'contacted', label: 'Contacted the user and confirmed travel + new device enrollment', match: { tool: 'chat', action: 'send', target: 'dkim' } },
  ],
  required: [
    { id: 'contact', label: 'Contacted the user to confirm the travel and new device', match: { tool: 'chat', action: 'send', target: 'dkim' }, skill: 'communication' },
    { id: 'classify', label: 'Documented how it was confirmed and closed as benign true positive', match: { tool: 'ticket', action: 'submit' }, skill: 'documentation' },
  ],
  forbidden: [
    { id: 'contain', label: 'Revoked sessions / reset the password on a legitimate user', why: 'Every signal is benign — a clean mobile-carrier IP, a newly enrolled device, MFA satisfied and self-approved, no inbox rules, and the user confirms he is travelling. Revoking and resetting locks a working employee out of his account over authorized activity.', match: [{ tool: 'directory', action: 'reset_password', target: 'dkim' }, { tool: 'directory', action: 'revoke_sessions', target: 'dkim' }], skill: 'security', penalty: 0.5 },
    { id: 'fp', label: 'Closed it as a false positive', why: 'The two sign-ins really happened and the detection fired correctly on genuinely impossible-looking travel; it is authorized, so it is a benign true positive, not a false positive. The distinction drives tuning and metrics.', match: { tool: 'ticket', action: 'reply', target: 'r_fp' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Worked the impossible-travel alert to a benign verdict: dkim\'s first sign-in is his Denver laptop (home IP, MFA satisfied); the second is Chicago from a newly enrolled iPhone on an AT&T mobile-carrier IP (clean in intel, not an anonymizer), MFA satisfied. His mailbox has no new inbox rules or forwarding. He confirms he is at a Chicago recruiting event this week and set up the authenticator on a new work phone this morning, approving the prompts himself. Benign true positive, severity low. Documented how I confirmed it (sign-ins + intel + user chat) and noted the new device so it stops looking anomalous. No account action.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Did the full work — sign-ins, IP reputation, persistence check, and user confirmation — before landing on benign. That is the difference between this and a real takeover.' },
    { id: 'r_ato', text: 'Impossible travel means account takeover — revoking his sessions, resetting the password, and escalating to CIRT.', scores: { communication: 0.3, security: 0.2, process: 0.2 }, feedback: 'You skipped the work. Clean mobile IP, a self-enrolled device, MFA satisfied, no persistence, and the user confirms travel. That is benign — you just locked out a working employee.' },
    { id: 'r_fp', text: 'Nothing malicious — false positive, closing.', scores: { communication: 0.4, process: 0.4 }, feedback: 'The travel genuinely looked impossible and the detection was correct; it is authorized activity, so classify benign true positive, not false positive.' },
  ],
  notesRubric: [
    { label: 'the two sign-ins compared (Denver laptop vs Chicago new device, both MFA satisfied)', pattern: /denver|chicago|new device|new phone|iphone|enroll|mfa satisfied/i },
    { label: 'the IP reputation and clean persistence check (mobile carrier, no inbox rules)', pattern: /mobile|carrier|clean|166\.205|no (inbox )?rule|no persistence/i },
    { label: 'how it was confirmed and the classification (user chat, benign true positive)', pattern: /confirm|chat|travel|benign|true positive/i },
  ],
  closure: { disposition: 'resolve', classification: 'benign_true_positive', severity: 'low', category: 'Identity - New Device (benign)', resolutionCode: 'Benign true positive - legitimate new device / travel confirmed with user' },
  categoryAccept: ['identity', 'new device', 'travel', 'benign'],
  resolutionCodeAccept: ['benign', 'new device', 'travel', 'confirmed', 'true positive'],
  hints: [
    'KB-0016 is the playbook. Do not decide before you check the IP reputation, persistence, and the user.',
    'Compare the sign-ins: Denver laptop then Chicago on a newly enrolled phone, both MFA satisfied.',
    'The Chicago IP is a clean mobile carrier (not a Tor/hosting IP), and the mailbox has no attacker inbox rules.',
    'Confirm with dkim (travel + new phone), classify benign true positive (low), and document how you confirmed it. Do NOT reset/revoke or call it a false positive.',
  ],
  debrief: 'This is the benign sibling of an account takeover, and the point is that the two are indistinguishable until you do the work. Here every signal that would be bad in a real takeover is instead benign: the second IP is a consumer mobile carrier (not a Tor exit or hosting provider), the device is one the user just enrolled, MFA was satisfied and self-approved, and there is no post-auth persistence in the mailbox. The user confirms travel and the new phone. Because the detection fired correctly on genuinely impossible-looking travel that turned out to be authorized, the right label is benign true positive — and you document how you confirmed it, because a lazy "false positive" hides the fact that the logic worked.',
};

// ---------------------------------------------------------------------------
// SOC1-15  Malware on inserted removable media (Falcon detection) — TP
// ---------------------------------------------------------------------------
const soc1_15: Scenario = {
  id: 'soc1-15',
  tier: 'soc1',
  title: 'Malicious USB on the plant floor',
  category: 'Endpoint',
  difficulty: 2,
  estMinutes: 13,
  objective: 'Triage a removable-media malware detection: confirm the file is genuinely malicious, verify it was contained, isolate the single workstation, block the indicator, and ticket a reimage — proportionately, at SOC I authority.',
  intake: { kind: 'alert', alertId: 'ALT-50115' },
  priorityExpected: 'P2',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50115', time: ago(14), severity: 'high', source: 'edr',
      title: 'Falcon detected a malicious executable on inserted USB media on WIC-WS-3002 (mjohnson)',
      description: 'Falcon flagged E:\\photos\\vacation.scr as a malicious worm when a USB stick was inserted on WIC-WS-3002 (mjohnson, Wichita plant). It quarantined the file. Confirm, contain the host, and ticket a rebuild.',
      host: 'WIC-WS-3002', user: 'mjohnson', indicators: ['b7e1f4a9c2d05e6f8091a2b3c4d5e6f7', 'vacation.scr'], mitre: ['T1091', 'T1204.002'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'WIC-WS-3002');
    h.devices.push({ name: 'SanDisk Ultra USB 3.0 Device', class: 'USB devices', status: 'ok', driver: '10.0.22621.1', driverDate: daysAgo(1) });
    h.files.push({ path: 'E:\\photos\\vacation.scr', size: 720000, modified: ago(20), signed: false, hash: 'b7e1f4a9c2d05e6f8091a2b3c4d5e6f7', suspicious: true });
    h.files.push({ path: 'C:\\Users\\mjohnson\\AppData\\Local\\Temp\\vacation.scr', size: 720000, modified: ago(15), signed: false, hash: 'b7e1f4a9c2d05e6f8091a2b3c4d5e6f7', suspicious: true });
    addEvent(h, { id: 1117, time: ago(14), level: 'Warning', source: 'Falcon Sensor', log: 'Application', message: 'Threat quarantined: E:\\photos\\vacation.scr (Worm:Win32/Autorun). USB removable media. Quarantine succeeded; on-write copy to Temp blocked. No child process spawned.' });
    addLog(w, { time: ago(14), source: 'edr', host: 'WIC-WS-3002', user: 'mjohnson', action: 'quarantine', message: 'Falcon PREVENTION: quarantined vacation.scr hash=b7e1f4a9c2d05e6f8091a2b3c4d5e6f7 from removable media (USB) on WIC-WS-3002 - no execution observed', process: 'vacation.scr' });
    // Red herring: benign DCOM warning.
    addEvent(h, { id: 10016, time: ago(200), level: 'Warning', source: 'DistributedCOM', log: 'System', message: 'DCOM 10016 local activation permission (benign, common).' });
    w.intel.push({ indicator: 'b7e1f4a9c2d05e6f8091a2b3c4d5e6f7', type: 'hash', verdict: 'malicious', source: 'Sandbox + multi-AV', tags: ['worm', 'usb-spreader', 'autorun'], detail: 'Autorun worm masquerading as a screensaver (vacation.scr). Copies itself to removable drives and %Temp%. 51/70 AV. Would spread to any USB inserted next.' });
    w.chat.push({ id: 'ch-mj15', with: 'mjohnson', messages: [] });
  },
  contactWith: 'mjohnson',
  contact: [
    { id: 'usb', question: 'Did you plug a USB stick into your workstation, and where did it come from?', answer: 'Mike Johnson: "Yeah, I found a USB drive in the parking lot and plugged it in to see whose it was. My screen popped a warning and then said something was blocked."', purpose: 'clarify', reveals: 'found-usb' },
    { id: 'ran', question: 'Did anything open or run off the USB, or did you double-click a file?', answer: 'Mike Johnson: "I clicked a photos folder, there was a \'vacation\' file, but it just got blocked. Nothing opened."', purpose: 'clarify', reveals: 'blocked' },
    { id: 'other', question: 'Have you plugged that USB — or your own USBs — into any other machines?', answer: 'Mike Johnson: "No, just this one. It\'s still in the port."', purpose: 'clarify', reveals: 'single-host' },
    { id: 'coffee', question: 'Busy shift?', answer: 'Mike Johnson: "Always. What do I do with the USB?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the endpoint-malware playbook (KB-0015)', match: { tool: 'kb', action: 'read', target: 'KB-0015' } },
    { id: 'host', label: 'Reviewed the EDR host record / quarantine event (USB worm, blocked on write, no execution)', match: [{ tool: 'edr', action: 'view_host', target: 'WIC-WS-3002' }, { tool: 'rdp', action: 'view_files', target: 'WIC-WS-3002' }, { tool: 'rdp', action: 'view_devices', target: 'WIC-WS-3002' }], hint: 'Did the file ever spawn a process? Where did it come from — a removable drive?' },
    { id: 'intel', label: 'Looked up the file hash (malicious USB worm)', match: { tool: 'intel', action: 'lookup', target: 'b7e1f4a9c2d05e6f8091a2b3c4d5e6f7' }, hint: 'Confirm the verdict before you classify — do not assume the EDR was wrong.' },
    { id: 'siem', label: 'Confirmed scope: single plant workstation, no spread', match: [{ tool: 'siem', action: 'search', params: { q: /vacation\.scr|removable|usb|mjohnson|b7e1f4a9/i } }, { tool: 'siem', action: 'pivot', params: { value: /mjohnson/ } }], weight: 0.5, hint: 'Did the same hash appear on any other host?' },
  ],
  required: [
    { id: 'isolate', label: 'Isolated the single workstation in EDR', match: { tool: 'edr', action: 'isolate', target: 'WIC-WS-3002' }, skill: 'technical' },
    { id: 'block', label: 'Blocked the malicious hash / contained the file', match: [{ tool: 'edr', action: 'quarantine_file', target: 'WIC-WS-3002' }, { tool: 'perimeter', action: 'block', target: 'b7e1f4a9c2d05e6f8091a2b3c4d5e6f7' }], skill: 'security' },
    { id: 'submit', label: 'Classified true positive and ticketed Desktop to reimage / destroy the media', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'fp', label: 'Closed it as a false positive because Falcon quarantined it', why: 'The file is a confirmed malicious USB worm (51/70 AV). A control blocking real malware is a true positive contained by prevention, not a false positive. Calling it a false positive corrupts detection metrics.', match: { tool: 'ticket', action: 'reply', target: 'r_fp' }, skill: 'security', penalty: 0.5 },
    { id: 'cirt', label: 'Escalated to CIRT for a single contained USB infection', why: 'It is one non-privileged plant workstation, the worm never executed, and there is no C2 or spread. A single contained endpoint is SOC I work; paging CIRT is over-response.', match: { tool: 'ticket', action: 'reply', target: 'r_cirt' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed a malicious USB worm on WIC-WS-3002 (mjohnson, Wichita plant): Falcon quarantined vacation.scr from a found USB stick, and intel confirms the hash as an autorun/USB-spreader worm (51/70 AV) that would copy itself to any drive it touches. The EDR record shows it was blocked on write and never executed; scope check shows the hash on this host only, no spread. I isolated the single workstation, blocked the hash, and ticketed Desktop to reimage it and to quarantine/destroy the USB. Coached mjohnson not to plug in found media. True positive contained by prevention, severity medium — one non-privileged host, no CIRT.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Confirmed maliciousness, verified it never ran, contained the single host and the indicator, and classified proportionately.' },
    { id: 'r_fp', text: 'Falcon caught it and nothing ran — false positive, closing.', scores: { communication: 0.3, security: 0.1 }, feedback: 'The file is genuinely a malicious worm; the detection was correct. That is a true positive contained by prevention, never a false positive.' },
    { id: 'r_cirt', text: 'Worm on the plant network — declaring an incident and escalating to CIRT.', scores: { communication: 0.4, process: 0.3, security: 0.4 }, feedback: 'Over-response. One non-privileged workstation, blocked before execution, no spread. Contain the host and hash at SOC I; ticket a reimage.' },
  ],
  notesRubric: [
    { label: 'the confirmation (malicious USB worm per intel/AV)', pattern: /worm|malicious|usb|removable|autorun|vacation\.scr|b7e1f4a9/i },
    { label: 'that it was blocked before execution and scoped to one host', pattern: /block|quarantin|no execution|never (ran|execut)|single host|no spread/i },
    { label: 'containment and classification (isolate + block hash + reimage ticket, TP medium)', pattern: /isolat|block|hash|reimage|true positive|medium/i },
  ],
  closure: { disposition: 'resolve', classification: 'true_positive', severity: 'medium', category: 'Endpoint - Removable Media Malware', resolutionCode: 'Isolated + hash blocked; ticketed reimage/media destruction; USB worm contained' },
  categoryAccept: ['endpoint', 'removable media', 'usb', 'malware'],
  resolutionCodeAccept: ['isolat', 'block', 'reimage', 'usb', 'contained', 'true positive'],
  hints: [
    'KB-0015 is the playbook. Do not assume a quarantined detection was a false alarm.',
    'Look up the hash: it is a confirmed USB-spreader worm that would infect any drive it touches.',
    'The EDR record shows it was blocked on write from removable media and never executed; the hash is on this host only.',
    'Isolate the single workstation, block the hash, ticket a reimage and media destruction, classify true positive (medium). Not a false positive, not a CIRT case.',
  ],
  debrief: 'Removable media is a classic infection vector, and a found USB in a parking lot is a textbook lure. The detection is genuinely malicious — an autorun worm that spreads to any drive it can reach — so even though Falcon quarantined it on write, this is a true positive contained by prevention, not a false positive. Because a real infected device touched the endpoint, the proportionate response is more than "the EDR handled it": isolate the single workstation, block the hash, and ticket a reimage plus destruction of the media. But it stays at SOC I authority — one non-privileged host, no execution, no spread — so escalating to CIRT would be as wrong as waving it off.',
};

// ---------------------------------------------------------------------------
// SOC1-16  Beacon to a newly-registered domain — a loader phoning home (TP)
// ---------------------------------------------------------------------------
const soc1_16: Scenario = {
  id: 'soc1-16',
  tier: 'soc1',
  title: 'Beaconing to a domain registered this week',
  category: 'Network',
  difficulty: 3,
  estMinutes: 15,
  objective: 'Triage a confirmed C2 beacon: use WHOIS/intel to weigh a newly-registered domain, read the process tree to find the loader, confirm the egress actually succeeded, contain the host, and escalate confirmed C2 to CIRT.',
  intake: { kind: 'alert', alertId: 'ALT-50116' },
  priorityExpected: 'P2',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50116', time: ago(19), severity: 'high', source: 'ids',
      title: 'Repeated successful outbound beacons from DEN-LT-1080 (rsingh) to a newly-registered domain cdn-telemetry-sync.live',
      description: 'Proxy/IDS logged a process on DEN-LT-1080 POSTing to cdn-telemetry-sync.live every 60 seconds. The domain was registered 3 days ago. The connections are being ALLOWED. Find the process and determine whether this is C2.',
      host: 'DEN-LT-1080', user: 'rsingh', indicators: ['cdn-telemetry-sync.live', '5.188.206.130'], mitre: ['T1071.001', 'T1568'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'DEN-LT-1080');
    const chrome = h.processes.find((p) => p.name === 'chrome.exe' && !p.parentPid);
    const loader = addProc(h, { pid: 8120, name: 'onedrive-sync-host.exe', user: 'KESTREL\\rsingh', cpu: 2, mem: 62, path: 'C:\\Users\\rsingh\\AppData\\Roaming\\OneDriveSync\\onedrive-sync-host.exe', cmdline: 'onedrive-sync-host.exe', parentPid: chrome?.pid, signed: false, hash: 'e5a1b8', started: ago(70) });
    h.files.push({ path: 'C:\\Users\\rsingh\\AppData\\Roaming\\OneDriveSync\\onedrive-sync-host.exe', size: 180000, modified: ago(71), signed: false, hash: 'e5a1b8', suspicious: true });
    h.scheduledTasks.push({ name: 'OneDriveSyncHost', path: '\\', action: 'C:\\Users\\rsingh\\AppData\\Roaming\\OneDriveSync\\onedrive-sync-host.exe', trigger: 'At logon', author: 'KESTREL\\rsingh', suspicious: true });
    setConn(h, [{ proto: 'TCP', local: `${h.ip}:52140`, remote: '5.188.206.130:443', state: 'ESTABLISHED', pid: 8120 }]);
    for (let i = 0; i < 6; i++) {
      addLog(w, { time: ago(19 - i * 2), source: 'proxy', host: 'DEN-LT-1080', user: 'rsingh', domain: 'cdn-telemetry-sync.live', dstIp: '5.188.206.130', url: 'https://cdn-telemetry-sync.live/api/telemetry', action: 'allow', dstPort: 443, process: 'onedrive-sync-host.exe', message: 'ALLOW POST https://cdn-telemetry-sync.live/api/telemetry (200) process=onedrive-sync-host.exe - beacon every 60s, egress SUCCEEDED' });
    }
    addLog(w, { time: ago(70), source: 'edr', host: 'DEN-LT-1080', user: 'rsingh', action: 'process_start', message: 'Unsigned onedrive-sync-host.exe started from AppData\\Roaming\\OneDriveSync on DEN-LT-1080', process: 'onedrive-sync-host.exe' });
    addLog(w, { time: ago(72), source: 'dns', host: 'DEN-LT-1080', srcIp: h.ip, domain: 'cdn-telemetry-sync.live', action: 'query', message: 'A cdn-telemetry-sync.live -> 5.188.206.130 (first seen on network 72 min ago)' });
    // Red herring: legit Halberd EDR cloud beacon (allowlisted).
    addLog(w, { time: ago(30), source: 'proxy', host: 'DEN-LT-1080', user: 'rsingh', domain: 'halberd-cloud.net', dstIp: '203.0.113.9', action: 'allow', dstPort: 443, message: 'ALLOW https://halberd-cloud.net/agent (EDR console beacon, allowlisted)' });
    w.intel.push({ indicator: 'cdn-telemetry-sync.live', type: 'domain', verdict: 'malicious', source: 'WHOIS + C2 feed', tags: ['c2', 'newly-registered', 'loader'], detail: `Registered ${daysAgo(3).slice(0, 10)} (3 days old) via a bulletproof registrar, privacy-protected WHOIS. Newly-registered domain used as loader C2. High risk.` });
    w.intel.push({ indicator: '5.188.206.130', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['c2', 'hosting'], detail: 'VPS hosting IP serving the C2 for cdn-telemetry-sync.live. Beacon over 443.' });
    w.intel.push({ indicator: 'e5a1b8', type: 'hash', verdict: 'malicious', source: 'Sandbox', tags: ['loader', 'beacon'], detail: 'Loader masquerading as "onedrive-sync-host.exe". Beacons to newly-registered C2; no valid Microsoft signature.' });
    w.chat.push({ id: 'ch-rs16', with: 'rsingh', messages: [] });
  },
  contactWith: 'rsingh',
  contact: [
    { id: 'install', question: 'Did you install or run anything unusual recently — a browser update prompt, a download?', answer: 'Raj Singh: "A day or two ago a page said my browser needed a critical update and I ran the installer. It seemed to do nothing, so I forgot about it."', purpose: 'clarify', reveals: 'drive-by' },
    { id: 'symptoms', question: 'Is the laptop behaving oddly — slow, pop-ups, redirects?', answer: 'Raj Singh: "A bit sluggish, but I blamed the VPN."', purpose: 'clarify' },
    { id: 'empid', question: 'Confirm your employee ID before I take action on your device.', answer: 'Raj Singh: "E10150."', purpose: 'verify' },
    { id: 'coffee', question: 'Rough week in Legal?', answer: 'Raj Singh: "When is it not? Why?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the endpoint-malware playbook (KB-0015)', match: { tool: 'kb', action: 'read', target: 'KB-0015' } },
    { id: 'intel', label: 'Looked up the domain and found it was registered 3 days ago (newly-registered C2)', match: { tool: 'intel', action: 'lookup', target: 'cdn-telemetry-sync.live' }, hint: 'A brand-new domain is a red flag on its own. When was it registered?' },
    { id: 'siem', label: 'Confirmed in the SIEM that the beacons were ALLOWED (egress succeeded)', match: [{ tool: 'siem', action: 'search', params: { q: /cdn-telemetry-sync|5\.188\.206\.130|beacon|allow|telemetry/i } }, { tool: 'siem', action: 'pivot', params: { value: /cdn-telemetry-sync\.live/ } }], hint: 'Were the connections allowed or denied? Did anything actually leave?' },
    { id: 'tree', label: 'Read the process tree and found the unsigned AppData loader posing as onedrive-sync-host.exe', match: [{ tool: 'edr', action: 'view_tree', target: 'DEN-LT-1080' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1080' }], hint: 'What process is beaconing, and where does it run from?' },
    { id: 'persist', label: 'Found the persistence (logon scheduled task)', match: [{ tool: 'rdp', action: 'view_tasks', target: 'DEN-LT-1080' }, { tool: 'terminal', action: 'schtasks', target: 'DEN-LT-1080' }], hint: 'Malware wants to survive reboot. Check scheduled tasks.' },
    { id: 'hash', label: 'Looked up the binary hash (malicious loader)', match: { tool: 'intel', action: 'lookup', target: 'e5a1b8' }, weight: 0.5 },
  ],
  required: [
    { id: 'triage', label: 'Collected a triage package before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1080' }, skill: 'process', before: 'isolate' },
    { id: 'isolate', label: 'Isolated the workstation in EDR', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1080' }, skill: 'technical' },
    { id: 'block', label: 'Blocked the C2 domain / IP at the perimeter', match: { tool: 'perimeter', action: 'block', target: /cdn-telemetry-sync|5\.188\.206\.130/ }, skill: 'security' },
    { id: 'submit', label: 'Escalated to CIRT (confirmed C2)', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'fp', label: 'Closed as benign / false positive', why: 'The proxy ALLOWED the beacons, so a loader on the host is actively communicating with a malicious newly-registered C2. That is a confirmed compromise, not benign and not a false positive.', match: { tool: 'ticket', action: 'reply', target: 'r_fp' }, skill: 'security', penalty: 0.6 },
    { id: 'reimage', label: 'Reimaged / rebooted the host before triage collection', why: 'KB-0015/0018: collect a triage package first. Reimaging destroys the evidence of initial access and scope that CIRT needs.', match: [{ tool: 'rdp', action: 'reboot', target: 'DEN-LT-1080' }, { tool: 'assets', action: 'remote_wipe' }], skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed C2 on DEN-LT-1080 (rsingh): an unsigned loader posing as onedrive-sync-host.exe in AppData\\Roaming (from a fake browser-update drive-by) is beaconing every 60s to cdn-telemetry-sync.live / 5.188.206.130. Intel flags both as malicious, and WHOIS shows the domain was registered just 3 days ago — a classic newly-registered C2. Crucially the proxy ALLOWED the beacons, so egress succeeded and the connection is ESTABLISHED, and there is a logon scheduled-task for persistence. I collected a triage package, isolated the host, and blocked the domain and IP at the perimeter. Escalating to CIRT because C2 is confirmed and successful. Severity high.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Weighed the newly-registered domain, confirmed the egress succeeded, found the loader and persistence, contained in the right order, and escalated confirmed C2.' },
    { id: 'r_fp', text: 'Probably just some telemetry/CDN traffic — benign, closing.', scores: { communication: 0.3, security: 0.1 }, feedback: 'The "CDN" domain is 3 days old, malicious in intel, and an unsigned AppData binary is beaconing to it successfully. That is confirmed C2, not benign.' },
    { id: 'r_reimage', text: 'Told Desktop to wipe and reimage the laptop right away to be safe.', scores: { communication: 0.3, security: 0.2, process: 0.2 }, feedback: 'Reimaging before collecting triage destroys the evidence. Collect, isolate, block, then escalate; reimage after CIRT clears it.' },
  ],
  notesRubric: [
    { label: 'the loader and initial access (unsigned AppData exe from a fake update)', pattern: /onedrive-sync-host|appdata|unsigned|loader|drive-by|browser update/i },
    { label: 'the newly-registered domain and that egress succeeded', pattern: /cdn-telemetry-sync|newly.?registered|3 days|registered|allow|beacon|established/i },
    { label: 'containment order and escalation (triage -> isolate -> block, CIRT)', pattern: /triage|isolat|block|perimeter|cirt|escalat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Network - Newly-Registered Domain C2', resolutionCode: 'Confirmed C2 to newly-registered domain; triage+isolate+block; escalated to CIRT' },
  categoryAccept: ['network', 'c2', 'newly-registered', 'domain'],
  resolutionCodeAccept: ['c2', 'cirt', 'isolat', 'block', 'contain'],
  hints: [
    'KB-0015 is the playbook. A newly-registered domain is a strong C2 signal — look it up in intel/WHOIS first.',
    'The domain is 3 days old and malicious; check the SIEM to see whether the beacons were ALLOWED (they were — egress succeeded).',
    'Read the process tree: an unsigned onedrive-sync-host.exe in AppData\\Roaming with a logon scheduled task.',
    'Collect triage FIRST, then isolate, block the domain/IP at the perimeter, and escalate to CIRT because C2 is confirmed.',
  ],
  debrief: 'The tell in this one is domain age. A "CDN/telemetry" domain that resolves for the first time on your network and was registered three days ago through a privacy-protected bulletproof registrar is a textbook newly-registered C2. Unlike the blocked-egress case, here the proxy allowed the beacons, so the loader in AppData is successfully talking to its controller — a confirmed, live compromise. The order of operations decides the score: collect a triage package before isolating (isolation preserves the EDR channel; reimaging destroys evidence), widen the block to the perimeter, and escalate to CIRT because confirmed C2 means hands-on-keyboard risk regardless of the single host.',
};

// ---------------------------------------------------------------------------
// SOC1-17  MFA fatigue / push bombing that the user did NOT approve (TP, blocked)
// ---------------------------------------------------------------------------
const soc1_17: Scenario = {
  id: 'soc1-17',
  tier: 'soc1',
  title: 'MFA push bombing — did anyone approve?',
  category: 'Identity',
  difficulty: 3,
  estMinutes: 13,
  objective: 'Work an MFA-fatigue alert to the one fact that decides everything: whether any prompt was approved. Confirm no sign-in succeeded, coach and monitor the user, and classify an attempted-but-blocked true positive without over-containing.',
  intake: { kind: 'alert', alertId: 'ALT-50117' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50117', time: ago(16), severity: 'medium', source: 'cloud',
      title: 'MFA fatigue: 22 push approvals requested for bpatel in 6 minutes from an external IP (45.9.148.60)',
      description: 'WorkSuite sent 22 MFA push prompts for bpatel in 6 minutes, driven by repeated sign-in attempts from 45.9.148.60. Determine whether any prompt was approved and whether the account is compromised.',
      user: 'bpatel', indicators: ['45.9.148.60'], mitre: ['T1621', 'T1110'], status: 'new', truth: 'true_positive',
    });
    const u = findUser(w, 'bpatel')!;
    // Ground truth: attacker has the password (breach reuse) and is push-bombing. bpatel denied all; NO success.
    u.recentSignIns = [
      { time: ago(11), ip: '45.9.148.60', location: 'Sofia, BG', app: 'WorkSuite Mail', result: 'failure', reason: 'MFA denied by user', device: 'unknown', mfa: 'failed' },
      { time: ago(13), ip: '45.9.148.60', location: 'Sofia, BG', app: 'WorkSuite Mail', result: 'failure', reason: 'MFA prompt expired (no response)', device: 'unknown', mfa: 'failed' },
      { time: ago(15), ip: '45.9.148.60', location: 'Sofia, BG', app: 'WorkSuite Mail', result: 'failure', reason: 'MFA denied by user', device: 'unknown', mfa: 'failed' },
      { time: ago(60 * 3), ip: '10.10.20.42', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1042', mfa: 'satisfied' },
    ];
    for (let i = 0; i < 8; i++) {
      addLog(w, { time: ago(16 - i * 0.6), source: 'cloud', user: 'bpatel', srcIp: '45.9.148.60', action: 'mfa_denied', message: `MFA push for bpatel from 45.9.148.60 (Sofia,BG) result=${i % 3 === 0 ? 'expired (no response)' : 'DENIED by user'} - password correct, second factor NOT satisfied`, fields: { result: 'failure', mfa: 'denied' } });
    }
    addLog(w, { time: ago(10), source: 'cloud', user: 'bpatel', srcIp: '45.9.148.60', action: 'summary', message: 'MFA fatigue summary: 22 prompts for bpatel, 0 approved, 0 successful sign-ins from 45.9.148.60', fields: { approved: 0, success: 0 } });
    // bpatel's mailbox is clean (no attacker rules) since nothing succeeded.
    w.intel.push({ indicator: '45.9.148.60', type: 'ip', verdict: 'malicious', source: 'Abuse feed + MFA-bombing honeypot', tags: ['mfa-bombing', 'hosting', 'credential-stuffing'], detail: 'VPS hosting IP (BG) repeatedly seen driving MFA push-bombing after credential stuffing. No legitimate use.' });
    w.chat.push({ id: 'ch-bp17', with: 'bpatel', messages: [] });
  },
  contactWith: 'bpatel',
  contact: [
    { id: 'prompts', question: 'Did your phone get a burst of MFA approve requests, and did you approve any of them?', answer: 'Bhavik Patel: "Yes! My phone blew up with approve prompts for a few minutes. I didn\'t start any of them so I hit Deny on all of them and then just ignored the rest. I didn\'t approve any."', purpose: 'clarify', reveals: 'denied-all' },
    { id: 'reuse', question: 'Is your WorkSuite password one you\'ve reused on a personal site that might have been breached?', answer: 'Bhavik Patel: "...probably. It\'s close to an old one I used elsewhere. I should change it."', purpose: 'clarify', reveals: 'reused-password' },
    { id: 'empid', question: 'Confirm your employee ID.', answer: 'Bhavik Patel: "E10106."', purpose: 'verify' },
    { id: 'coffee', question: 'Busy in AP this week?', answer: 'Bhavik Patel: "Month-end. Why?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the suspicious sign-in playbook (KB-0016)', match: { tool: 'kb', action: 'read', target: 'KB-0016' } },
    { id: 'signins', label: 'Reviewed the sign-ins and confirmed ZERO successful / approved (all denied or expired)', match: { tool: 'directory', action: 'view_signins', target: 'bpatel' }, hint: 'The whole case turns on one thing: did any prompt get approved / any sign-in succeed?' },
    { id: 'siem', label: 'Pulled the SIEM: 22 prompts, 0 approved, 0 successful sign-ins', match: [{ tool: 'siem', action: 'search', params: { q: /bpatel|45\.9\.148\.60|mfa|denied|0 approved/i } }, { tool: 'siem', action: 'pivot', params: { value: /45\.9\.148\.60/ } }], hint: 'Count the approvals and successes, not just the prompts.' },
    { id: 'intel', label: 'Looked up the source IP (MFA-bombing hosting IP)', match: { tool: 'intel', action: 'lookup', target: '45.9.148.60' } },
    { id: 'rules', label: 'Checked the mailbox for persistence (clean — nothing succeeded)', match: { tool: 'mail', action: 'view_mailbox', target: 'bpatel' }, weight: 0.5, hint: 'If nothing succeeded, there should be no attacker inbox rules.' },
    { id: 'contacted', label: 'Contacted the user and confirmed he denied every prompt', match: { tool: 'chat', action: 'send', target: 'bpatel' } },
  ],
  required: [
    { id: 'coach', label: 'Coached the user (keep denying, report, and the account is being watched)', match: { tool: 'chat', action: 'send', target: 'bpatel' }, skill: 'communication' },
    { id: 'submit', label: 'Classified attempted-but-blocked and flagged for monitoring', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'compromise', label: 'Treated it as a successful takeover and escalated to CIRT', why: 'No prompt was approved and no sign-in succeeded — MFA held. Declaring a compromise and paging CIRT for a blocked attempt cries wolf; the correct action is coach and monitor, not incident response.', match: { tool: 'ticket', action: 'reply', target: 'r_compromise' }, skill: 'process', penalty: 0.4 },
    { id: 'fp', label: 'Closed it as a false positive / noise', why: 'A real attacker with the correct password push-bombed the user 22 times. MFA stopped it, but the attempt is genuine — an attempted true positive, not a false positive. Miscounting it as noise hides that the password is likely known.', match: { tool: 'ticket', action: 'reply', target: 'r_fp' }, skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Worked the MFA-fatigue alert: an attacker at 45.9.148.60 (a known MFA-bombing hosting IP in Bulgaria) had bpatel\'s correct password and drove 22 push prompts in 6 minutes. The decisive fact from the sign-ins and SIEM: 0 approved, 0 successful sign-ins — every prompt was denied or expired, and bpatel confirms he denied them all and never started any. His mailbox has no attacker rules. MFA held, so no compromise: I coached him to keep denying and report, flagged the account for monitoring, and — because his password is likely known/reused — recommended he change it as a precaution. Attempted true positive, blocked, severity medium. No reset was strictly required and no CIRT escalation.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Pinned the one fact that matters (nothing was approved), classified an attempted-but-blocked TP, and responded proportionately — coach, monitor, precautionary password advice.' },
    { id: 'r_compromise', text: 'Account is under attack — revoking sessions, resetting the password, and escalating to CIRT as a compromise.', scores: { communication: 0.4, security: 0.5, process: 0.2 }, feedback: 'No prompt was approved and no sign-in succeeded; MFA blocked it. This is an attempted, contained attack — coach and monitor, do not declare a compromise or page CIRT.' },
    { id: 'r_fp', text: 'Just MFA spam that went nowhere — false positive / noise, closing.', scores: { communication: 0.3, security: 0.1 }, feedback: 'A real attacker with the correct password bombed the user. MFA held, but this is an attempted true positive and a signal the password is known — not noise.' },
  ],
  notesRubric: [
    { label: 'the attack identified (MFA push-bombing from a malicious IP)', pattern: /mfa|push|fatigue|bomb|45\.9\.148\.60|22 prompt/i },
    { label: 'the decisive fact (nothing approved / no successful sign-in)', pattern: /0 approv|none approv|denied|no success|no sign-?in|not approved|blocked/i },
    { label: 'the proportionate response (coach, monitor, precautionary password, TP attempt)', pattern: /coach|monitor|password|true positive|attempt|no compromise/i },
  ],
  closure: { disposition: 'resolve', classification: 'true_positive', severity: 'medium', category: 'Identity - MFA Fatigue (blocked)', resolutionCode: 'MFA fatigue attempt blocked (0 approved); user coached & monitored; no compromise' },
  categoryAccept: ['identity', 'mfa fatigue', 'mfa', 'blocked'],
  resolutionCodeAccept: ['mfa', 'blocked', 'coach', 'attempt', 'true positive'],
  hints: [
    'KB-0016 covers MFA fatigue. The whole case turns on one question: did any prompt get approved?',
    'Check the sign-ins and SIEM: 22 prompts, 0 approved, 0 successful sign-ins. bpatel denied them all.',
    'Look up the source IP (a known MFA-bombing hosting IP). The mailbox is clean because nothing succeeded.',
    'Classify attempted true positive (blocked, medium), coach the user and flag for monitoring, and advise a precautionary password change. No CIRT, not a false positive.',
  ],
  debrief: 'MFA fatigue tests whether you count the right thing. The prompt volume is scary, but the single decisive fact is how many were approved — here, zero, with no successful sign-in, confirmed by the user. That makes it an attempted true positive that MFA blocked, not a compromise and not noise. The two failure modes bracket the answer: over-reacting (revoke, reset, page CIRT) treats a blocked attempt as a breach, while under-reacting ("false positive / spam") hides the important secondary signal — the attacker had the correct password, so it is likely reused/breached and worth a precautionary change. The proportionate response is to coach the user to keep denying and reporting, monitor the account, and advise the password change.',
};

// ---------------------------------------------------------------------------
// SOC1-18  User clicked a phishing URL but entered NO credentials (TP, contained)
// ---------------------------------------------------------------------------
const soc1_18: Scenario = {
  id: 'soc1-18',
  tier: 'soc1',
  title: 'Phishing link clicked — were credentials entered?',
  category: 'Email',
  difficulty: 2,
  estMinutes: 12,
  objective: 'Resolve a phishing-click alert by proving the negative: use the proxy log and sign-ins to establish that the user reached the page but entered no credentials, then block the domain, coach, and classify proportionately.',
  intake: { kind: 'alert', alertId: 'ALT-50118' },
  priorityExpected: 'P3',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50118', time: ago(21), severity: 'medium', source: 'email',
      title: 'dkim clicked a link to a credential-phishing page (login-worksuite-verify.com)',
      description: 'The proxy recorded dkim following a link from a reported phishing email to login-worksuite-verify.com, a credential-harvesting page. Determine whether he entered credentials and contain.',
      user: 'dkim', indicators: ['login-worksuite-verify.com', '185.100.87.42'], mitre: ['T1566.002'], status: 'new', truth: 'true_positive',
    });
    addMail(w, {
      id: 'MSG-9300', time: ago(60), from: 'IT Service Desk <support@login-worksuite-verify.com>', to: ['dkim@kestreldynamics.com'],
      subject: 'Action required: verify your WorkSuite mailbox to avoid suspension',
      status: 'delivered (junk)', reason: 'DMARC fail; delivered to Junk',
      headers: { from: 'IT Service Desk <support@login-worksuite-verify.com>', returnPath: 'bounce@login-worksuite-verify.com', replyTo: 'support@login-worksuite-verify.com', receivedFrom: 'login-worksuite-verify.com [185.100.87.42]', spf: 'fail', dkim: 'fail', dmarc: 'fail', messageId: '<MSG-9300@login-worksuite-verify.com>' },
      body: 'Your mailbox will be suspended. Verify now: https://login-worksuite-verify.com/verify?u=dkim',
      urls: ['https://login-worksuite-verify.com/verify?u=dkim'], phishing: true, clicked: ['dkim'],
    });
    // Ground truth: dkim clicked (proxy GET) but entered NO credentials (no POST). Sign-ins remain clean.
    addLog(w, { time: ago(20), source: 'proxy', host: 'DEN-LT-1051', user: 'dkim', domain: 'login-worksuite-verify.com', dstIp: '185.100.87.42', url: 'https://login-worksuite-verify.com/verify?u=dkim', action: 'allow', dstPort: 443, message: 'ALLOW GET https://login-worksuite-verify.com/verify?u=dkim (200) - page loaded, no subsequent POST/form submission recorded' });
    addLog(w, { time: ago(20), source: 'proxy', host: 'DEN-LT-1051', user: 'dkim', domain: 'login-worksuite-verify.com', dstIp: '185.100.87.42', url: 'https://login-worksuite-verify.com/assets/logo.png', action: 'allow', dstPort: 443, message: 'ALLOW GET https://login-worksuite-verify.com/assets/logo.png (200) - static asset only; NO credential POST from this host' });
    const u = findUser(w, 'dkim')!;
    u.recentSignIns = [
      { time: ago(40), ip: '10.10.20.51', location: 'Denver, US', app: 'Windows Sign-in', result: 'success', device: 'DEN-LT-1051', mfa: 'satisfied' },
      { time: ago(60 * 8), ip: '10.10.20.51', location: 'Denver, US', app: 'WorkSuite Mail', result: 'success', device: 'DEN-LT-1051', mfa: 'satisfied' },
    ];
    w.intel.push({ indicator: 'login-worksuite-verify.com', type: 'domain', verdict: 'malicious', source: 'URL sandbox + feeds', tags: ['phishing', 'credential-harvest', 'newly-registered'], detail: 'Credential-harvesting page impersonating the WorkSuite mailbox login. Registered 6 days ago.' });
    w.intel.push({ indicator: '185.100.87.42', type: 'ip', verdict: 'malicious', source: 'Abuse feed', tags: ['phishing', 'hosting'], detail: 'Hosts multiple credential-phishing kits.' });
    w.chat.push({ id: 'ch-dk18', with: 'dkim', messages: [] });
  },
  contactWith: 'dkim',
  contact: [
    { id: 'clicked', question: 'Did you click the "verify your mailbox" link, and did you type your password on the page?', answer: 'David Kim: "I clicked it because it said my mailbox would be suspended. The page asked for my password but it looked off, so I closed it. I did not type anything in."', purpose: 'clarify', reveals: 'no-creds' },
    { id: 'anything', question: 'Did you enter anything at all — username, MFA code, or download a file from it?', answer: 'David Kim: "No. Just looked at it and closed the tab."', purpose: 'clarify', reveals: 'nothing-entered' },
    { id: 'empid', question: 'Confirm your employee ID.', answer: 'David Kim: "E10111."', purpose: 'verify' },
    { id: 'coffee', question: 'How was the recruiting trip?', answer: 'David Kim: "Good. Is my account okay?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the phishing playbook (KB-0014)', match: { tool: 'kb', action: 'read', target: 'KB-0014' } },
    { id: 'intel', label: 'Looked up the phishing domain / IP (credential harvester)', match: { tool: 'intel', action: 'lookup', target: /login-worksuite-verify|185\.100\.87\.42/ } },
    { id: 'proxy', label: 'Checked the proxy log and confirmed only GETs, no credential POST', match: [{ tool: 'siem', action: 'search', params: { q: /login-worksuite-verify|dkim|GET|no.*POST|no credential/i } }, { tool: 'siem', action: 'pivot', params: { value: /login-worksuite-verify\.com/ } }], hint: 'A submitted credential shows as a POST. Do you see one, or only page GETs?' },
    { id: 'signins', label: 'Reviewed the user\'s sign-ins (clean — no new IPs, no MFA prompts)', match: { tool: 'directory', action: 'view_signins', target: 'dkim' }, hint: 'If creds were phished and used, his sign-ins would show it. Do they?' },
    { id: 'headers', label: 'Analyzed the mail headers (SPF/DKIM/DMARC fail, lookalike domain)', match: { tool: 'mail', action: 'view_headers', target: 'MSG-9300' }, weight: 0.5 },
    { id: 'contacted', label: 'Contacted the user and confirmed he entered nothing', match: { tool: 'chat', action: 'send', target: 'dkim' } },
  ],
  required: [
    { id: 'block', label: 'Blocked the phishing domain / IP at the gateway or perimeter', match: [{ tool: 'perimeter', action: 'block', target: /login-worksuite-verify|185\.100\.87\.42/ }, { tool: 'mail', action: 'block_sender', target: /login-worksuite-verify/ }], skill: 'technical' },
    { id: 'coach', label: 'Coached the user (report, do not click, and reassured him)', match: { tool: 'chat', action: 'send', target: 'dkim' }, skill: 'communication' },
    { id: 'submit', label: 'Classified true positive contained (clicked, no credentials) and closed', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'over', label: 'Reset the password / revoked sessions / escalated as a full compromise', why: 'The proxy shows only page GETs with no credential POST, the user confirms he typed nothing, and his sign-ins are clean. Treating him as compromised — reset, revoke, CIRT — overstates the evidence and disrupts a user who did the right thing by closing the page.', match: [{ tool: 'ticket', action: 'reply', target: 'r_over' }, { tool: 'directory', action: 'reset_password', target: 'dkim' }], skill: 'process', penalty: 0.3 },
    { id: 'fp', label: 'Closed it as a false positive because no credentials were lost', why: 'The email and page are genuinely malicious and the user really clicked through to a credential harvester. That is a true positive contained by user judgment, not a false positive.', match: { tool: 'ticket', action: 'reply', target: 'r_fp' }, skill: 'security', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Worked the phishing-click alert: dkim followed a link from a lookalike email (login-worksuite-verify.com, SPF/DKIM/DMARC all fail, domain malicious and registered 6 days ago) to a credential-harvesting page. The proxy shows only GETs for the page and its logo — no credential POST from his host — and he confirms the page looked off so he closed it without typing anything. His sign-ins are clean (no new IPs, no MFA prompts). No credentials were entered, so no account action is needed. I blocked the domain and IP at the gateway/proxy, purged the mail, and coached him (good instinct closing it; use Report Phishing next time). True positive contained, severity low.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Proved the negative from the proxy and sign-ins, blocked the indicator, and matched the response to the evidence — a calibrated close.' },
    { id: 'r_over', text: 'He clicked a phishing link, so assume compromise — reset his password, revoke sessions, and escalate to CIRT.', scores: { communication: 0.4, process: 0.3 }, feedback: 'Overreach. No credential POST, nothing entered, clean sign-ins. Match the response to the evidence: block, coach, close — no account action.' },
    { id: 'r_fp', text: 'No credentials lost, so nothing happened — false positive, closing.', scores: { communication: 0.3, security: 0.1 }, feedback: 'The page and email are genuinely malicious and he really clicked through. That is a true positive contained by his judgment, not a false positive — and you still block the domain.' },
  ],
  notesRubric: [
    { label: 'the confirmation (malicious lookalike domain, headers fail)', pattern: /login-worksuite-verify|spf|dkim|dmarc|lookalike|malicious|credential.?harvest/i },
    { label: 'the key negative (page GET only, no credential POST / nothing entered)', pattern: /no (credential|post)|only get|nothing (entered|typed)|clean sign-?in|no creds/i },
    { label: 'the response and classification (block, coach, true positive contained)', pattern: /block|coach|true positive|contained|low/i },
  ],
  closure: { disposition: 'resolve', classification: 'true_positive', severity: 'low', category: 'Email - Phishing Click (no creds)', resolutionCode: 'Clicked phishing link, no credentials entered; domain blocked, user coached' },
  categoryAccept: ['email', 'phishing', 'click'],
  resolutionCodeAccept: ['phishing', 'no cred', 'block', 'coach', 'contained', 'true positive'],
  hints: [
    'KB-0014 is the playbook. The question is not "did he click" but "did he submit credentials".',
    'Look up the domain (malicious credential harvester) and read the proxy log: only page GETs, no credential POST.',
    'Confirm with dkim (he closed the page without typing) and check his sign-ins — clean.',
    'Block the domain/IP, coach him, classify true positive contained (low). Do NOT reset/escalate, and do NOT call it a false positive.',
  ],
  debrief: 'Clicking a phishing link is not the same as being phished, and the skill is proving which one happened. The proxy is the witness: a credential submission is a POST to the page, while this host shows only GETs for the page and its assets — corroborated by the user, who closed the page, and by clean sign-ins with no new IPs or MFA prompts. So it is a true positive (the email and page are real credential-harvesting infrastructure and he did click through) contained by the user\'s own judgment. The calibration is in matching the response to the evidence: block the domain and coach the user, but do not reset the password, revoke sessions, or page CIRT for a click that submitted nothing — and never downgrade genuinely malicious infrastructure to "false positive".',
};

// ---------------------------------------------------------------------------
// SOC1-19  Credential-dumping tool (mimikatz / LSASS access) on a host (TP)
// ---------------------------------------------------------------------------
const soc1_19: Scenario = {
  id: 'soc1-19',
  tier: 'soc1',
  title: 'Something read LSASS memory',
  category: 'Endpoint',
  difficulty: 4,
  estMinutes: 15,
  objective: 'Triage a credential-theft detection: confirm an unsigned tool accessed LSASS, collect triage before containing, isolate the host, reset the exposed account, and escalate — credential dumping is a serious true positive.',
  intake: { kind: 'alert', alertId: 'ALT-50119' },
  priorityExpected: 'P2',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50119', time: ago(12), severity: 'high', source: 'edr',
      title: 'Credential theft: unsigned process opened LSASS memory on DEN-LT-1023 (kwalsh) - possible Mimikatz',
      description: 'Halberd flagged a process (mk.exe) from %Temp% opening lsass.exe with PROCESS_VM_READ (0x1010) on DEN-LT-1023, the Service Desk lead\'s laptop. This is classic credential dumping. Confirm and contain.',
      host: 'DEN-LT-1023', user: 'kwalsh', indicators: ['9c8b7a6f5e4d3c2b1a0918273645aabb', 'mk.exe'], mitre: ['T1003.001'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'DEN-LT-1023');
    const cmd = addProc(h, { pid: 9100, name: 'cmd.exe', user: 'KESTREL\\kwalsh', cpu: 0.3, mem: 12, path: 'C:\\Windows\\System32\\cmd.exe', cmdline: 'cmd.exe /c mk.exe', signed: true, started: ago(14) });
    addProc(h, { pid: 9180, name: 'mk.exe', user: 'KESTREL\\kwalsh', cpu: 6, mem: 40, path: 'C:\\Users\\kwalsh\\AppData\\Local\\Temp\\mk.exe', cmdline: 'mk.exe sekurlsa::logonpasswords', parentPid: cmd.pid, signed: false, hash: '9c8b7a6f5e4d3c2b1a0918273645aabb', started: ago(13) });
    h.files.push({ path: 'C:\\Users\\kwalsh\\AppData\\Local\\Temp\\mk.exe', size: 1250000, modified: ago(16), signed: false, hash: '9c8b7a6f5e4d3c2b1a0918273645aabb', suspicious: true });
    addEvent(h, { id: 10, time: ago(13), level: 'Warning', source: 'Microsoft-Windows-Sysmon', log: 'Sysmon', message: 'Sysmon Event 10: Process accessed lsass.exe. SourceImage=C:\\Users\\kwalsh\\AppData\\Local\\Temp\\mk.exe GrantedAccess=0x1010 (PROCESS_VM_READ) - credential access.' });
    addLog(w, { time: ago(13), source: 'edr', host: 'DEN-LT-1023', user: 'kwalsh', action: 'credential_access', message: 'Halberd: mk.exe (unsigned, %Temp%) opened lsass.exe GrantedAccess=0x1010 - Mimikatz sekurlsa::logonpasswords signature match on DEN-LT-1023', process: 'mk.exe' });
    // Red herring: benign DCOM event.
    addEvent(h, { id: 10016, time: ago(150), level: 'Warning', source: 'DistributedCOM', log: 'System', message: 'DCOM 10016 local activation permission (benign, common).' });
    w.intel.push({ indicator: '9c8b7a6f5e4d3c2b1a0918273645aabb', type: 'hash', verdict: 'malicious', source: 'Sandbox + multi-AV', tags: ['mimikatz', 'credential-dumper', 'hacktool'], detail: 'Renamed Mimikatz build (mk.exe). Dumps plaintext credentials, hashes and Kerberos tickets from LSASS. 60/70 AV.' });
    w.chat.push({ id: 'ch-kw19', with: 'kwalsh', messages: [] });
  },
  contactWith: 'kwalsh',
  contact: [
    { id: 'tool', question: 'Did you run a tool called mk.exe from your Temp folder, or did someone ask you to?', answer: 'Kevin Walsh: "A vendor \'support\' guy on a call told me to download and run a diagnostic tool to fix a printer issue. It was called mk-something. It flashed a black window and I thought nothing happened."', purpose: 'clarify', reveals: 'social-engineered' },
    { id: 'creds', question: 'Were you logged in with your admin/help-desk account when you ran it?', answer: 'Kevin Walsh: "Yeah, my normal account — I use it for help desk stuff all day. Is that bad?"', purpose: 'clarify', reveals: 'creds-exposed' },
    { id: 'empid', question: 'Confirm your employee ID before I take action on your account and device.', answer: 'Kevin Walsh: "E10023."', purpose: 'verify' },
    { id: 'coffee', question: 'How\'s the ticket queue?', answer: 'Kevin Walsh: "Backed up. Why, what\'s wrong?"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the endpoint-malware playbook (KB-0015)', match: { tool: 'kb', action: 'read', target: 'KB-0015' } },
    { id: 'tree', label: 'Read the process tree (cmd -> mk.exe from %Temp% opening lsass, sekurlsa::logonpasswords)', match: [{ tool: 'edr', action: 'view_tree', target: 'DEN-LT-1023' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1023' }], hint: 'What ran, from where, and what did it access? Read the command line.' },
    { id: 'sysmon', label: 'Confirmed the LSASS access event (Sysmon 10, GrantedAccess 0x1010)', match: [{ tool: 'siem', action: 'search', params: { q: /lsass|mimikatz|mk\.exe|credential|0x1010|sekurlsa/i } }, { tool: 'rdp', action: 'view_events', target: 'DEN-LT-1023' }], hint: 'Look for the process-access-to-LSASS event.' },
    { id: 'intel', label: 'Looked up the tool hash (Mimikatz / credential dumper)', match: { tool: 'intel', action: 'lookup', target: '9c8b7a6f5e4d3c2b1a0918273645aabb' } },
    { id: 'contacted', label: 'Contacted the user and established how it was run (social-engineered)', match: { tool: 'chat', action: 'send', target: 'kwalsh' } },
  ],
  required: [
    { id: 'triage', label: 'Collected a triage package before isolating', match: { tool: 'edr', action: 'collect_triage', target: 'DEN-LT-1023' }, skill: 'process', before: 'isolate' },
    { id: 'isolate', label: 'Isolated the host in EDR', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1023' }, skill: 'technical' },
    { id: 'reset', label: 'Reset the exposed user\'s credentials (LSASS was read)', match: { tool: 'directory', action: 'reset_password', target: 'kwalsh' }, skill: 'technical' },
    { id: 'submit', label: 'Escalated to CIRT (confirmed credential theft)', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'fp', label: 'Closed it as a false positive / AV noise', why: 'An unsigned Mimikatz build from %Temp% opened LSASS with read access and ran sekurlsa::logonpasswords. That is confirmed credential theft, not a false positive — treating it as noise leaves stolen credentials in play.', match: { tool: 'ticket', action: 'reply', target: 'r_fp' }, skill: 'security', penalty: 0.6 },
    { id: 'reimage', label: 'Reimaged / rebooted the host before triage collection', why: 'KB-0015/0018: collect a triage package first. Rebooting clears the volatile evidence (memory, tokens) and reimaging destroys the record of what was taken and how.', match: [{ tool: 'rdp', action: 'reboot', target: 'DEN-LT-1023' }, { tool: 'assets', action: 'remote_wipe' }], skill: 'security', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed credential dumping on DEN-LT-1023 (kwalsh, Service Desk lead): the process tree shows cmd.exe launching mk.exe from %Temp% running "sekurlsa::logonpasswords", and Sysmon 10 shows it opened lsass.exe with GrantedAccess 0x1010. Intel confirms the hash is a renamed Mimikatz (60/70 AV). kwalsh was social-engineered by a fake vendor into running it while logged in with his help-desk account, so any credentials/tickets cached in LSASS are exposed. I collected a triage package, isolated the host, and reset kwalsh\'s password and revoked his sessions. Escalating to CIRT because credential theft on an IT/help-desk account risks broader compromise and the scope of what was dumped needs their review. True positive, severity high.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Confirmed the LSASS access, collected triage before containing, reset the exposed account, and escalated — the correct handling for credential theft.' },
    { id: 'r_fp', text: 'Probably just an AV signature on a diagnostic tool — false positive, closing.', scores: { communication: 0.3, security: 0.1 }, feedback: 'It opened LSASS with read access and ran sekurlsa::logonpasswords — that is Mimikatz doing credential theft, confirmed by intel. Never a false positive.' },
    { id: 'r_reimage', text: 'Told Desktop to wipe and reimage the laptop immediately.', scores: { communication: 0.3, security: 0.2, process: 0.2 }, feedback: 'Reimaging before triage destroys the evidence of what was stolen. Collect triage, isolate, reset the account, escalate; reimage after CIRT clears it.' },
  ],
  notesRubric: [
    { label: 'the credential access confirmed (mk.exe/Mimikatz opened LSASS, sekurlsa)', pattern: /lsass|mimikatz|mk\.exe|sekurlsa|0x1010|credential (access|dump|theft)/i },
    { label: 'the exposure and how it happened (help-desk creds cached, social-engineered)', pattern: /kwalsh|cached|exposed|help.?desk|social|vendor|%temp%/i },
    { label: 'the containment order and escalation (triage -> isolate -> reset, CIRT)', pattern: /triage|isolat|reset|revoke|cirt|escalat/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Endpoint - Credential Theft Tool', resolutionCode: 'Credential dumping confirmed; triage+isolate+reset; escalated to CIRT' },
  categoryAccept: ['endpoint', 'credential theft', 'credential', 'mimikatz'],
  resolutionCodeAccept: ['credential', 'mimikatz', 'isolat', 'reset', 'cirt', 'contain'],
  hints: [
    'KB-0015 is the playbook. The alert names an LSASS access — read the process tree and the command line.',
    'mk.exe from %Temp% ran sekurlsa::logonpasswords and opened lsass with 0x1010; intel confirms it is a renamed Mimikatz.',
    'The user was social-engineered into running it with his help-desk account, so those credentials are exposed.',
    'Collect triage FIRST, then isolate, reset the user (and revoke sessions), and escalate to CIRT — credential theft is serious.',
  ],
  debrief: 'Credential dumping is one of the highest-signal detections a SOC sees, and this one is unambiguous: an unsigned, renamed Mimikatz running sekurlsa::logonpasswords, opening LSASS with read access per Sysmon 10, confirmed malicious by intel. Because LSASS was read while a help-desk account was logged on, every credential and Kerberos ticket cached there must be treated as stolen — hence the password reset and session revocation. Two order-of-operations rules set the score: collect a triage package before isolating or rebooting (memory and tokens are volatile evidence), and escalate to CIRT because stolen IT credentials can pivot far beyond one laptop. It is also a reminder that social engineering, not just malware delivery, gets these tools onto endpoints.',
};

// ---------------------------------------------------------------------------
// SOC1-20  Honeyfile / canary triggered — very early ransomware on a share (TP)
// ---------------------------------------------------------------------------
const soc1_20: Scenario = {
  id: 'soc1-20',
  tier: 'soc1',
  title: 'Canary file tripped on the file share',
  category: 'Endpoint',
  difficulty: 4,
  estMinutes: 14,
  objective: 'Respond to an active ransomware canary with speed and the right containment: isolate the source host immediately to stop the encryption, avoid destroying evidence, and escalate to CIRT — this is a live incident, not a routine triage.',
  intake: { kind: 'alert', alertId: 'ALT-50120' },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50120', time: ago(4), severity: 'high', source: 'edr',
      title: 'Ransomware canary tripped on \\\\FS01\\Shared - mass file rename from DEN-LT-1042 (bpatel)',
      description: 'The honeyfile "_DO_NOT_DELETE_canary.xlsx" on \\\\FS01\\Shared was modified, and 300+ files on the share are being renamed to *.locked by bpatel\'s session from DEN-LT-1042 - all within the last few minutes. This looks like active ransomware. Contain fast.',
      host: 'DEN-LT-1042', user: 'bpatel', indicators: ['a1b2c3d4e5f60718293a4b5c6d7e8f90', 'lockbit_svc.exe', '_DO_NOT_DELETE_canary.xlsx'], mitre: ['T1486', 'T1490'], status: 'new', truth: 'true_positive',
    });
    const h = host(w, 'DEN-LT-1042');
    addProc(h, { pid: 9900, name: 'lockbit_svc.exe', user: 'KESTREL\\bpatel', cpu: 74, mem: 210, path: 'C:\\Users\\bpatel\\AppData\\Local\\Temp\\lockbit_svc.exe', cmdline: 'lockbit_svc.exe -enc \\\\FS01\\Shared', signed: false, hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90', started: ago(6) });
    h.files.push({ path: 'C:\\Users\\bpatel\\AppData\\Local\\Temp\\lockbit_svc.exe', size: 340000, modified: ago(8), signed: false, hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90', suspicious: true });
    h.files.push({ path: '\\\\FS01\\Shared\\READ_ME_RECOVER.txt', size: 2200, modified: ago(4), suspicious: true });
    addEvent(h, { id: 1116, time: ago(4), level: 'Critical', source: 'Halberd EDR', log: 'Application', message: 'Behavioral detection: rapid mass file rename to .locked extension by lockbit_svc.exe (ransomware). Canary honeyfile _DO_NOT_DELETE_canary.xlsx on \\\\FS01\\Shared modified.' });
    for (let i = 0; i < 6; i++) {
      addLog(w, { time: ago(5 - i * 0.4), source: 'windows', host: 'DEN-LT-1042', user: 'bpatel', action: 'file_rename', message: `File rename on \\\\FS01\\Shared: report_${i}.xlsx -> report_${i}.xlsx.locked by bpatel session from DEN-LT-1042 (ransomware encryption)`, fields: { eventId: 4663 } });
    }
    addLog(w, { time: ago(4), source: 'edr', host: 'DEN-LT-1042', user: 'bpatel', action: 'canary', message: 'Ransomware CANARY tripped: _DO_NOT_DELETE_canary.xlsx on \\\\FS01\\Shared modified; 300+ files renamed to *.locked; source=DEN-LT-1042 process=lockbit_svc.exe', process: 'lockbit_svc.exe' });
    const fs = w.servers.find((s) => s.id === 'DEN-FS01')!;
    fs.backups = [{ job: 'FS01-Daily-Shares', lastRun: ago(60 * 9), status: 'success', restorePoints: 30 }];
    w.intel.push({ indicator: 'a1b2c3d4e5f60718293a4b5c6d7e8f90', type: 'hash', verdict: 'malicious', source: 'Sandbox + multi-AV', tags: ['ransomware', 'lockbit', 'encryptor'], detail: 'LockBit-family encryptor (lockbit_svc.exe). Encrypts local and mapped/UNC shares, drops READ_ME_RECOVER.txt. 63/70 AV.' });
    w.chat.push({ id: 'ch-bp20', with: 'bpatel', messages: [] });
  },
  contactWith: 'bpatel',
  contact: [
    { id: 'symptoms', question: 'Are your files or the shared drive turning into .locked files, and is there a ransom note?', answer: 'Bhavik Patel: "YES — a ton of files on the S: drive just turned into .locked and there\'s a READ_ME_RECOVER text file demanding payment. It\'s still going!"', purpose: 'clarify', reveals: 'active-ransomware' },
    { id: 'origin', question: 'Did you open an attachment or run anything just before this started?', answer: 'Bhavik Patel: "I opened an invoice attachment a few minutes ago and enabled content. Then this started."', purpose: 'clarify', reveals: 'macro-delivery' },
    { id: 'unplug', question: 'Do not shut it down — leave it on. Can you unplug the network cable / turn off Wi-Fi if I ask?', answer: 'Bhavik Patel: "Okay, it\'s on Wi-Fi. Tell me what to do."', purpose: 'clarify' },
    { id: 'coffee', question: 'How\'s month-end otherwise?', answer: 'Bhavik Patel: "Not the priority right now!"', purpose: 'irrelevant' },
  ],
  evidence: [
    { id: 'kb', label: 'Read the endpoint-malware playbook (KB-0015)', match: { tool: 'kb', action: 'read', target: 'KB-0015' } },
    { id: 'host', label: 'Confirmed the encrypting process on the source host (lockbit_svc.exe from %Temp%)', match: [{ tool: 'edr', action: 'view_host', target: 'DEN-LT-1042' }, { tool: 'edr', action: 'view_tree', target: 'DEN-LT-1042' }, { tool: 'rdp', action: 'view_processes', target: 'DEN-LT-1042' }], hint: 'What process is doing the renames, and where does it run from?' },
    { id: 'siem', label: 'Confirmed the canary trip and mass .locked renames from DEN-LT-1042', match: [{ tool: 'siem', action: 'search', params: { q: /canary|\.locked|FS01|lockbit|ransom|bpatel/i } }, { tool: 'siem', action: 'pivot', params: { value: /DEN-LT-1042/ } }], hint: 'Where is the encryption sourced from, and how fast is it spreading?' },
    { id: 'intel', label: 'Looked up the binary hash (LockBit-family ransomware)', match: { tool: 'intel', action: 'lookup', target: 'a1b2c3d4e5f60718293a4b5c6d7e8f90' } },
    { id: 'backups', label: 'Checked FS01 backups for recovery (30 restore points)', match: [{ tool: 'server', action: 'view_backups', target: 'DEN-FS01' }, { tool: 'server', action: 'view_shares', target: 'DEN-FS01' }], weight: 0.5, hint: 'Recovery depends on clean backups — check they exist and predate the attack.' },
  ],
  required: [
    { id: 'isolate', label: 'Isolated the source host in EDR immediately to stop the encryption', match: { tool: 'edr', action: 'isolate', target: 'DEN-LT-1042' }, skill: 'technical', weight: 2 },
    { id: 'kill', label: 'Killed / quarantined the ransomware process or binary on the host', match: [{ tool: 'edr', action: 'kill_process', target: 'DEN-LT-1042' }, { tool: 'edr', action: 'quarantine_file', target: 'DEN-LT-1042' }], skill: 'technical' },
    { id: 'submit', label: 'Escalated to CIRT as an active ransomware incident', match: { tool: 'ticket', action: 'submit' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'reboot', label: 'Rebooted / shut down the source host instead of isolating it', why: 'KB-0018: isolate in EDR (which keeps our management channel) rather than powering off. A reboot/shutdown destroys volatile evidence and does not reliably stop an already-running encryptor or a live attacker session; EDR isolation cuts the network path immediately.', match: [{ tool: 'rdp', action: 'reboot', target: 'DEN-LT-1042' }, { tool: 'assets', action: 'remote_wipe' }], skill: 'security', penalty: 0.5 },
    { id: 'slow', label: 'Handled it as routine malware — cleaned the process and closed without escalating', why: 'Active ransomware encrypting a shared drive is a live, spreading incident. Killing the process without isolating the source and escalating to CIRT lets it resume or spread and skips the incident response the situation demands.', match: { tool: 'ticket', action: 'reply', target: 'r_slow' }, skill: 'process', penalty: 0.4 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Active ransomware in progress: the canary honeyfile on \\\\FS01\\Shared tripped and 300+ files are being renamed to *.locked by lockbit_svc.exe running from %Temp% on DEN-LT-1042 (bpatel), delivered via a macro invoice a few minutes ago. Intel confirms a LockBit-family encryptor (63/70 AV) and a READ_ME_RECOVER.txt ransom note dropped on the share. I isolated DEN-LT-1042 in EDR immediately to cut its path to the share and stop the encryption, and killed/quarantined the encryptor. I did NOT power the host off (preserve volatile evidence). Escalating to CIRT now as an active ransomware incident: they need to scope other hosts for the same hash, and FS01 has 30 restore points predating this for recovery. Severity high/critical.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Prioritized speed and the correct containment (EDR isolation, not shutdown), preserved evidence, and escalated a live incident to CIRT.' },
    { id: 'r_slow', text: 'Killed the lockbit_svc.exe process on the laptop — that stops it. Ticketing Desktop to clean it up. Closing.', scores: { communication: 0.4, security: 0.3, process: 0.2 }, feedback: 'This is active ransomware on a shared drive, not routine malware. Isolate the source, and escalate to CIRT to scope spread and drive recovery — killing one process and closing is dangerously incomplete.' },
    { id: 'r_reboot', text: 'Told the user to shut the laptop down right away to stop it.', scores: { communication: 0.4, security: 0.3, process: 0.3 }, feedback: 'Shutting down destroys volatile evidence and is not reliable containment. Isolate in EDR (keeps our channel, cuts the network) and leave it powered on.' },
  ],
  notesRubric: [
    { label: 'the confirmation (canary tripped, mass .locked renames, LockBit)', pattern: /canary|\.locked|ransom|lockbit|encrypt|read_me/i },
    { label: 'the source and delivery (lockbit_svc.exe from %Temp% on DEN-LT-1042, macro invoice)', pattern: /den-lt-1042|bpatel|%temp%|lockbit_svc|macro|invoice|source host/i },
    { label: 'the containment and escalation (isolate not shutdown, CIRT, backups for recovery)', pattern: /isolat|not (power|shut)|cirt|escalat|backup|restore point/i },
  ],
  closure: { disposition: 'escalate', escalateTo: 'cirt', classification: 'true_positive', severity: 'high', category: 'Endpoint - Ransomware Canary', resolutionCode: 'Active ransomware contained (isolate + kill); escalated to CIRT' },
  categoryAccept: ['endpoint', 'ransomware', 'canary'],
  resolutionCodeAccept: ['ransomware', 'isolat', 'cirt', 'contain', 'canary'],
  hints: [
    'KB-0015/0018: this is an active incident. Speed and the right containment matter more than a leisurely triage.',
    'The canary tripped and lockbit_svc.exe from %Temp% on DEN-LT-1042 is renaming files to .locked on the share.',
    'Isolate the source host in EDR immediately (do NOT shut it down) to cut its path to the share and stop the encryption.',
    'Kill/quarantine the encryptor and escalate to CIRT as active ransomware; note FS01 has 30 restore points for recovery.',
  ],
  debrief: 'A ransomware canary is designed to catch encryption at the very start, and it buys you minutes that only matter if you act fast and correctly. The right first move is EDR isolation of the source host: it cuts the network path to the share immediately while keeping your management channel, so the encryptor stops reaching FS01. The two wrong moves are instructive — shutting the host down destroys volatile evidence and is not reliable containment, and treating it as routine malware (kill the process, ticket Desktop, close) ignores that this is a live, spreading incident. Ransomware is an automatic CIRT escalation: they scope the same hash across other hosts and drive recovery from backups taken before the attack. Honeyfiles turn ransomware from a next-morning disaster into a catchable, minutes-old event.',
};

export const SOC1_SCENARIOS_C: Scenario[] = [
  soc1_11, soc1_12, soc1_13, soc1_14, soc1_15, soc1_16, soc1_17, soc1_18, soc1_19, soc1_20,
];
