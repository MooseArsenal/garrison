import type { Scenario } from '../engine/types';
import { ago, daysAgo, findUser } from '../engine/world';
import { host, addEvent, addProc, addLog, addAlert, setConn } from './helpers';

// ---------------------------------------------------------------------------
// CIRT-09  Double-extortion ransomware (encryption + stolen-data leak threat)
// ---------------------------------------------------------------------------
const cirt_09: Scenario = {
  id: 'cirt-09',
  tier: 'cirt',
  title: 'Double-extortion ransomware: data stolen, then encrypted',
  category: 'Ransomware - Double Extortion',
  difficulty: 5,
  estMinutes: 26,
  objective: 'Command a double-extortion ransomware SEV1: contain and restore from a verified-clean backup, but recognize that the pre-encryption data theft makes this a likely reportable breach - engage Legal early and route every external notification through them, never all-staff or the regulator/customers directly.',
  intake: {
    kind: 'incident', number: 'IR-2026-027', title: 'Ransomware on DEN-APP01 with a data-leak extortion demand',
    declaredBy: 'agrant', summary: 'The ERP application/SQL server DEN-APP01 has been encrypted and a ransom note threatens to publish 42GB of exfiltrated data on a leak site in 72 hours. Logs show a large outbound transfer BEFORE encryption, so this is double extortion (steal-then-encrypt), not just encryption.',
    severity: 'SEV1', openedAt: ago(15), relatedAlerts: ['ALT-50151'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50151', time: ago(18), severity: 'critical', source: 'edr',
      title: 'Mass encryption + prior 42GB exfil on DEN-APP01 (ERP/SQL)',
      description: 'enc.exe encrypting E:\\ERP on DEN-APP01 as svc_scanner. Ransom note LEAK-NOTICE.txt links a Tor leak site and claims 42GB of Finance/HR data was already stolen. A 42GB outbound transfer to 91.242.217.30 preceded encryption.',
      host: 'DEN-APP01', user: 'svc_scanner', indicators: ['91.242.217.30', 'enc.exe', 'svc_scanner'], mitre: ['T1486', 'T1567', 'T1078.002'], status: 'in progress', truth: 'true_positive',
    });
    const app = w.servers.find((s) => s.id === 'DEN-APP01')!;
    app.status = 'degraded';
    app.processes = [{ pid: 7420, name: 'enc.exe', user: 'KESTREL\\svc_scanner', cpu: 92, mem: 260, path: 'C:\\Windows\\Temp\\enc.exe', cmdline: 'enc.exe -enc E:\\ERP', signed: false, hash: 'ab41...c7', started: ago(18) }];
    // The exfil happened BEFORE encryption - this is what makes it double extortion / a breach.
    addLog(w, { time: ago(60 * 5), source: 'edr', host: 'DEN-APP01', user: 'svc_scanner', action: 'collection', message: 'svc_scanner staged and archived E:\\ERP\\exports (Finance + HR extracts) into C:\\Windows\\Temp\\arc.7z', process: 'powershell.exe' });
    addLog(w, { time: ago(60 * 3), source: 'firewall', host: 'DEN-APP01', srcIp: '10.10.10.40', dstIp: '91.242.217.30', dstPort: 443, action: 'allow', message: 'Large outbound transfer 42.1GB DEN-APP01 -> 91.242.217.30 (exfil to leak-site infrastructure)' });
    addLog(w, { time: ago(20), source: 'edr', host: 'DEN-APP01', user: 'svc_scanner', action: 'exec', message: 'enc.exe written to C:\\Windows\\Temp and executed (encryptor)', process: 'enc.exe' });
    // Patient zero: engineering workstation beaconing, attacker pivoted with svc_scanner.
    addLog(w, { time: ago(60 * 44), source: 'firewall', host: 'DEN-WS-2010', srcIp: '10.10.21.10', dstIp: '91.242.217.30', dstPort: 443, action: 'allow', message: 'C2 beacon from patient-zero DEN-WS-2010 (nfoster) -> 91.242.217.30' });
    addLog(w, { time: ago(60 * 20), source: 'auth', host: 'DEN-APP01', user: 'svc_scanner', srcIp: '10.10.21.10', action: 'logon', message: '4624 Logon type 3 svc_scanner from DEN-WS-2010 - lateral movement to the ERP server' });
    // Clean restore point: APP01-SQL-Full 10h ago predates encryption (18 min ago). Offsite immutable copy exists.
    const bkp = w.servers.find((s) => s.id === 'DEN-BKP01')!;
    bkp.backups = [
      { job: 'APP01-SQL-Full', lastRun: ago(60 * 10), status: 'success', restorePoints: 14 },
      { job: 'Offsite-Immutable-Copy', lastRun: ago(60 * 26), status: 'success', restorePoints: 30 },
      { job: 'FS01-Daily-Shares', lastRun: ago(60 * 9), status: 'success', restorePoints: 30 },
    ];
    w.intel.push({ indicator: '91.242.217.30', type: 'ip', verdict: 'malicious', source: 'C2/leak-site feed', tags: ['c2', 'ransomware', 'exfil'], detail: 'Infrastructure tied to a double-extortion affiliate leak site.' });
    w.intel.push({ indicator: 'enc.exe', type: 'hash', verdict: 'malicious', source: 'sandbox', tags: ['ransomware', 'encryptor'], detail: 'Custom encryptor with a paired stealer stage. ab41...c7.' });
    w.chat.push({ id: 'ch-rsingh9', with: 'rsingh', messages: [] });
  },
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'kb18', label: 'Reviewed the IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'exfil', label: 'Confirmed data was exfiltrated BEFORE encryption (the breach)', match: [{ tool: 'siem', action: 'search', params: { q: /exfil|42gb|91\.242\.217\.30|arc\.7z|transfer/i } }, { tool: 'siem', action: 'pivot', params: { value: /91\.242\.217\.30/ } }], hint: 'A ransom note that threatens to leak data means data left first. Find the outbound transfer.' },
    { id: 'patient0', label: 'Traced the intrusion to patient zero and the compromised svc_scanner', match: [{ tool: 'siem', action: 'search', params: { q: /svc_scanner|den-ws-2010|lateral|beacon/i } }, { tool: 'edr', action: 'view_host', target: 'DEN-APP01' }], hint: 'Where did svc_scanner log in from before it reached the ERP server?' },
    { id: 'backups', label: 'Identified a clean restore point taken before encryption', match: { tool: 'server', action: 'view_backups', target: 'DEN-BKP01' }, hint: 'The APP01-SQL backup 10h ago predates the encryption 18 min ago.' },
  ],
  required: [
    { id: 'isolate_app', label: 'Isolated DEN-APP01 to stop encryption', match: [{ tool: 'edr', action: 'isolate', target: 'DEN-APP01' }, { tool: 'incident', action: 'set_phase', params: { phase: /contain/i } }], skill: 'technical' },
    { id: 'isolate_p0', label: 'Isolated patient zero (DEN-WS-2010)', match: { tool: 'edr', action: 'isolate', target: 'DEN-WS-2010' }, skill: 'technical' },
    { id: 'disable_svc', label: 'Disabled/rotated the compromised service account', match: [{ tool: 'directory', action: 'disable', target: 'svc_scanner' }, { tool: 'incident', action: 'reset_service_account', target: 'svc_scanner' }], skill: 'technical' },
    { id: 'triage', label: 'Collected a triage package before any rebuild', match: [{ tool: 'edr', action: 'collect_triage', target: 'DEN-APP01' }, { tool: 'incident', action: 'collect_triage' }], skill: 'investigation', after: 'isolate_app' },
    { id: 'restore', label: 'Restored from the clean pre-encryption backup', match: [{ tool: 'server', action: 'restore', target: 'DEN-BKP01' }, { tool: 'incident', action: 'restore_backup', target: 'DEN-APP01' }], skill: 'technical', after: 'triage' },
    { id: 'notify_leadership', label: 'Notified the IT Director/CISO and executives (SEV1)', match: [{ tool: 'incident', action: 'notify', target: 'it_director' }, { tool: 'incident', action: 'notify', target: 'executives' }], skill: 'process' },
    { id: 'notify_legal', label: 'Engaged Legal early (data theft = likely reportable breach)', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'wipe', label: 'Reimaged/rebooted the server before collecting evidence', why: 'KB-0018: preserve first. Reimaging before triage destroys the record of what was stolen - which you need for the breach determination in a double-extortion case.', match: [{ tool: 'incident', action: 'reimage', target: 'DEN-APP01' }, { tool: 'server', action: 'reboot', target: 'DEN-APP01' }], skill: 'security', penalty: 0.4, unlessAfter: 'triage' },
    { id: 'notify_all', label: 'Sent an all-staff notice during active response', why: 'KB-0017: never broadcast all-staff before containment - it tips off the actor and pre-empts Legal on messaging.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
    { id: 'ext_direct', label: 'Notified the regulator / customers directly', why: 'KB-0017: even though stolen data likely makes this reportable, Legal owns and times the regulator and customer notification. You supply the scope of what was taken; you do not make the external notice.', match: [{ tool: 'incident', action: 'notify', target: 'regulator' }, { tool: 'incident', action: 'notify', target: 'customers' }], skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Double-extortion ransomware on DEN-APP01, contained and recovering. Patient zero DEN-WS-2010 (nfoster) was beaconing to 91.242.217.30; the attacker pivoted with the over-privileged svc_scanner account, staged Finance/HR extracts and exfiltrated 42GB BEFORE running the encryptor (enc.exe from C:\\Windows\\Temp). Actions in order: isolated APP01 and patient zero in EDR (not power-off, to preserve evidence), disabled and rotated svc_scanner, collected triage, then restored from the SQL backup that predates encryption; the offsite immutable copy is our fallback. Critically, this is not just an encryption event - regulated data left the building, so I engaged Legal immediately as a likely reportable breach; Legal owns any regulator/customer notice and the ransom/leak-site decision. Notified the IT Director/CISO and execs. No all-staff. Next: rotate every credential the attacker could have seen and monitor for re-entry.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Contained and restored from a clean point, and correctly treated the pre-encryption exfil as a breach routed through Legal.' },
    { id: 'r_encrypt_only', text: 'Restored from the latest backup and got the ERP back up. The leak threat is just a scare tactic, so no breach reporting needed.', scores: { communication: 0.3, security: 0.2, process: 0.2 }, feedback: 'The logs show 42GB actually left before encryption - that is a real breach, and "latest backup" risks restoring a compromised state. Preserve, restore from a verified-clean point, and let Legal make the breach call.' },
    { id: 'r_broadcast', text: 'Emailed all staff about the ransomware and reported the breach to the state regulator myself to stay ahead of it.', scores: { communication: 0.3, process: 0.1 }, feedback: 'All-staff during active response tips off the actor, and regulator notification is Legal\'s decision and timing - not the responder\'s.' },
  ],
  notesRubric: [
    { label: 'double extortion (exfil BEFORE encryption) identified', pattern: /exfil|42gb|stole|leak site|before encrypt|double.extortion|data theft/i },
    { label: 'containment that preserves evidence (isolate not power-off, triage)', pattern: /isolat|preserve|triage|not power|evidence/i },
    { label: 'recovery from a clean pre-encryption backup + credential rotation', pattern: /clean backup|pre-?encryption|restore point|immutable|rotate credential/i },
    { label: 'breach engaged through Legal; not all-staff/regulator direct', pattern: /legal|breach|reportable|not all.?staff|not.*regulator|via legal/i },
  ],
  closure: {
    disposition: 'resolve', severity: 'critical', category: 'Ransomware - Double Extortion', resolutionCode: 'Contained, restored from clean backup; breach routed to Legal',
    notifications: ['it_director', 'executives', 'legal'],
    notificationsForbidden: ['all_staff', 'regulator', 'customers', 'law_enforcement'],
    reportFields: [
      { label: 'timeline (beacon -> lateral -> exfil -> encryption)', pattern: /timeline|beacon|lateral|exfil|encrypt/i },
      { label: 'the data theft and its breach implication', pattern: /exfil|42gb|stolen|breach|reportable|leak/i },
      { label: 'recovery approach (clean backup point)', pattern: /backup|restore|clean|immutable|pre-?encryption/i },
      { label: 'follow-up with owners (rotate creds, monitor, notification ownership)', pattern: /rotate|monitor|legal|owner|lesson|remediat/i },
    ],
  },
  categoryAccept: ['ransomware', 'double', 'extortion'],
  resolutionCodeAccept: ['ransomware', 'contain', 'restore', 'breach', 'extortion'],
  hints: [
    'Contain first, but isolate in EDR - do not power off or wipe. Isolate APP01 and patient zero DEN-WS-2010.',
    'This is double extortion: check for a large outbound transfer BEFORE encryption (42GB to 91.242.217.30). That data theft is the breach.',
    'Restore from the SQL backup that predates encryption (10h ago), with the offsite immutable copy as fallback. Rotate svc_scanner.',
    'Because regulated data was stolen, engage Legal early as a likely reportable breach. Notify the IT Director and execs. Do NOT send all-staff or notify the regulator/customers yourself.',
  ],
  debrief: 'Double extortion changes the calculus of a ransomware response: the encryption is loud, but the quiet fact - that data was stolen before it was encrypted - is what turns an availability incident into a data breach. The technical response is the same disciplined ransomware playbook (isolate in EDR without destroying evidence, trace patient zero and the pivot account, restore from a verified-clean pre-encryption backup, rotate credentials), but the exfiltration adds a legal dimension that must be engaged early. The trap is to treat the leak threat as a bluff or to "get ahead of it" by notifying the regulator or customers yourself - both wrong. Prove whether data actually left (here 42GB did), give Legal the scope, and let Legal own the breach determination, the regulator/customer notice, and any decision about the leak site. As always, no all-staff broadcast during active response.',
};

// ---------------------------------------------------------------------------
// CIRT-10  OT / plant safety incident (Wichita) - safety first
// ---------------------------------------------------------------------------
const cirt_10: Scenario = {
  id: 'cirt-10',
  tier: 'cirt',
  title: 'Cyber incident on the Wichita plant OT network',
  category: 'OT - Plant Incident',
  difficulty: 5,
  estMinutes: 28,
  objective: 'Respond to an OT/ICS incident where safety - not data - is the priority: coordinate with plant operations before you touch anything, isolate at the IT/OT boundary without blindly powering down safety-critical controllers, and notify plant ops, executives, IT, and Legal (never all-staff or the regulator directly).',
  intake: {
    kind: 'incident', number: 'IR-2026-028', title: 'Unauthorized access + malware on Wichita plant SCADA/HMI',
    declaredBy: 'tbrandt', summary: 'The Wichita plant HMI (WIC-SCADA01) is showing abnormal setpoints and an unknown process; an engineering-workstation account reached the OT network from the corporate side. The line is still running. This is a potential safety-impacting OT incident, not just an IT one.',
    severity: 'SEV1', openedAt: ago(12), relatedAlerts: ['ALT-50161'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50161', time: ago(16), severity: 'critical', source: 'ids',
      title: 'IT->OT crossing + unknown process on WIC-SCADA01 (HMI)',
      description: 'A session from DEN-WS-2010 (corp engineering) crossed into the OT VLAN and reached WIC-SCADA01. Unknown process hmiupd.exe running; HMI setpoints modified. The safety PLC (WIC-PLC-SIS) is reporting normal but the line is live.',
      host: 'WIC-SCADA01', indicators: ['hmiupd.exe', 'DEN-WS-2010', '10.20.11.10'], mitre: ['T0883', 'T0836', 'T0855'], status: 'in progress', truth: 'true_positive',
    });
    // Add the plant OT/SCADA HMI server (not in the base world).
    w.servers.push({
      id: 'WIC-SCADA01', role: 'OT SCADA/HMI - Wichita plant floor (controls Line 1). Safety instrumented system WIC-PLC-SIS is a SEPARATE safety controller.', ip: '10.20.11.10', os: 'Windows 10 IoT LTSC', status: 'degraded',
      services: [
        { name: 'ScadaRuntime', displayName: 'Plant SCADA Runtime', status: 'running', startType: 'auto' },
        { name: 'OpcUaServer', displayName: 'OPC UA Server', status: 'running', startType: 'auto' },
        { name: 'HalberdAgent', displayName: 'Halberd EDR Agent', status: 'running', startType: 'auto' },
      ],
      disk: [{ drive: 'C:', used: 40, size: 120 }], cpu: 30, mem: 55, uptimeHours: 4200, events: [],
      processes: [
        { pid: 3300, name: 'ScadaRuntime.exe', user: 'SYSTEM', cpu: 12, mem: 220, path: 'C:\\Program Files\\PlantSCADA\\ScadaRuntime.exe', signed: true },
        { pid: 6650, name: 'hmiupd.exe', user: 'KESTREL\\nfoster', cpu: 40, mem: 90, path: 'C:\\Windows\\Temp\\hmiupd.exe', cmdline: 'hmiupd.exe --write-setpoints', signed: false, hash: 'd7c2...11', started: ago(20) },
      ],
      notes: 'Uptime years - never patched to avoid disrupting production. Line still running. Safety instrumented system (WIC-PLC-SIS) is independent; do not power it down without a coordinated safe-state.',
    });
    // The crossing from corp engineering into OT.
    addLog(w, { time: ago(60 * 6), source: 'firewall', host: 'DEN-WS-2010', srcIp: '10.10.21.10', dstIp: '10.20.11.10', dstPort: 3389, action: 'allow', message: 'IT->OT RDP crossing DEN-WS-2010 -> WIC-SCADA01 (should be denied by segmentation)' });
    addLog(w, { time: ago(20), source: 'edr', host: 'WIC-SCADA01', user: 'nfoster', action: 'exec', message: 'hmiupd.exe written to C:\\Windows\\Temp and modifying HMI setpoints', process: 'hmiupd.exe' });
    addLog(w, { time: ago(60 * 30), source: 'firewall', host: 'DEN-WS-2010', srcIp: '10.10.21.10', dstIp: '185.220.101.9', dstPort: 443, action: 'allow', message: 'C2 beacon from DEN-WS-2010 -> 185.220.101.9 (initial access into corp before the OT pivot)' });
    w.intel.push({ indicator: '185.220.101.9', type: 'ip', verdict: 'malicious', source: 'threat feed', tags: ['c2', 'ot-targeting'], detail: 'C2 tied to an intrusion set that targets manufacturing/OT.' });
    w.intel.push({ indicator: 'hmiupd.exe', type: 'hash', verdict: 'malicious', source: 'sandbox', tags: ['ics', 'setpoint-tamper'], detail: 'Tampers with HMI setpoints via OPC. d7c2...11.' });
    w.chat.push({ id: 'ch-gharris10', with: 'gharris', messages: [] }, { id: 'ch-tbrandt10', with: 'tbrandt', messages: [] });
  },
  contactWith: 'gharris',
  contact: [
    { id: 'safety', question: 'Ask the Plant Manager (gharris) the current safety state of the line', answer: 'Greg Harris (Plant Manager): "Line 1 is running but readings look off. Do NOT remote-stop anything - if you drop the HMI or the controllers uncoordinated you can leave the process in an unsafe state. We will bring it to a safe stop manually on my call. Coordinate every containment step with us."', purpose: 'verify', reveals: 'safety-first' },
    { id: 'scope', question: 'Ask which controllers are affected and whether the safety system is independent', answer: 'The HMI (WIC-SCADA01) is affected; the safety instrumented system (WIC-PLC-SIS) is a separate controller and is still reporting normal. Isolate at the IT/OT boundary, not by yanking the safety controller.', purpose: 'clarify', reveals: 'scope' },
    { id: 'boundary', question: 'Confirm how the attacker reached OT from the corporate network', answer: 'A corp engineering workstation (DEN-WS-2010) that was already compromised crossed the IT/OT boundary over RDP - segmentation that should have blocked it did not.', purpose: 'clarify', reveals: 'boundary' },
    { id: 'powerdown', question: 'Just remotely power down the SCADA server and the safety PLC to be safe', answer: '(Do NOT: blindly powering down OT/safety controllers can drive the process to an unsafe state. Containment must be coordinated with plant ops for a safe stop.)', purpose: 'red_flag' },
  ],
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'kb18', label: 'Reviewed the IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'crossing', label: 'Confirmed the IT->OT crossing from the compromised corp workstation', match: [{ tool: 'siem', action: 'search', params: { q: /it.?ot|10\.20\.11\.10|wic-scada01|den-ws-2010|crossing/i } }, { tool: 'siem', action: 'pivot', params: { value: /den-ws-2010/ } }], hint: 'How did a corporate workstation reach the plant OT VLAN?' },
    { id: 'hmi', label: 'Identified the malicious process tampering with HMI setpoints', match: [{ tool: 'server', action: 'view_processes', target: 'WIC-SCADA01' }, { tool: 'edr', action: 'view_host', target: 'WIC-SCADA01' }], hint: 'Look for an unsigned process writing setpoints on the HMI.' },
  ],
  required: [
    { id: 'coordinate', label: 'Coordinated with plant operations on safety before containment', match: { tool: 'incident', action: 'notify', target: 'plant_ops' }, skill: 'process' },
    { id: 'isolate_p0', label: 'Isolated the compromised corp workstation (the entry point)', match: { tool: 'edr', action: 'isolate', target: 'DEN-WS-2010' }, skill: 'technical' },
    { id: 'isolate_ot', label: 'Isolated the HMI at the IT/OT boundary (coordinated, not a blind power-off)', match: [{ tool: 'edr', action: 'isolate', target: 'WIC-SCADA01' }, { tool: 'perimeter', action: 'block', target: '185.220.101.9' }], skill: 'technical', after: 'coordinate' },
    { id: 'notify_leadership', label: 'Notified executives and the IT Director (SEV1, safety impact)', match: [{ tool: 'incident', action: 'notify', target: 'executives' }, { tool: 'incident', action: 'notify', target: 'it_director' }], skill: 'process' },
    { id: 'notify_legal', label: 'Engaged Legal (potential safety/regulatory dimension)', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'blind_powerdown', label: 'Remotely powered down / rebooted the SCADA or safety controller uncoordinated', why: 'Blindly dropping an OT or safety controller can leave the physical process in an unsafe state. Containment of OT is coordinated with plant operations for a safe stop - it is not a unilateral IT action.', match: [{ tool: 'server', action: 'reboot', target: 'WIC-SCADA01' }, { tool: 'incident', action: 'reimage', target: 'WIC-SCADA01' }], skill: 'security', penalty: 0.4, unlessAfter: 'coordinate' },
    { id: 'notify_all', label: 'Sent an all-staff notice during active response', why: 'KB-0017: no all-staff broadcast during an active incident - it causes panic on the plant floor and pre-empts Legal on messaging.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
    { id: 'reg_direct', label: 'Notified a regulator directly', why: 'KB-0017: any safety or environmental regulator notification is Legal\'s determination and timing, not the responder\'s.', match: [{ tool: 'incident', action: 'notify', target: 'regulator' }, { tool: 'incident', action: 'notify', target: 'customers' }], skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'OT incident on the Wichita plant, contained safely. A compromised corp engineering workstation (DEN-WS-2010, beaconing to 185.220.101.9) crossed the IT/OT boundary over RDP and reached the HMI (WIC-SCADA01), where an unsigned process (hmiupd.exe) was tampering with setpoints. Safety came first: I coordinated with the Plant Manager before any containment - the line was brought to a safe stop on their call rather than a remote power-off, and the independent safety controller (WIC-PLC-SIS) stayed up. Then I isolated the entry workstation and the HMI at the IT/OT boundary and blocked the C2. Notified plant operations, executives, the IT Director, and Legal. No all-staff and no regulator notice from me - Legal owns any external/regulatory decision. Root cause: a flat IT/OT segmentation gap and an unpatched, internet-adjacent HMI; recovery of the HMI happens in a maintenance window with plant ops.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Safety-first coordination, IT/OT boundary isolation without a blind power-off, and the right notifications.' },
    { id: 'r_powerdown', text: 'Immediately remote-powered-off the SCADA server and the safety PLC and killed the process to stop the tampering.', scores: { communication: 0.2, security: 0.2, process: 0.2 }, feedback: 'Uncoordinated power-off of OT/safety controllers can drive the process to an unsafe state. Containment of OT is coordinated with plant ops for a safe stop.' },
    { id: 'r_it_only', text: 'Treated it as a normal endpoint infection - isolated the HMI and moved on, no need to loop in plant operations.', scores: { communication: 0.3, security: 0.3, process: 0.2 }, feedback: 'OT is not just another endpoint. Plant operations own the safety state and must be coordinated with before and during containment.' },
  ],
  notesRubric: [
    { label: 'safety-first, coordinated with plant operations', pattern: /safety|plant op|coordinat|safe stop|safe state/i },
    { label: 'attack path (compromised corp host crossed IT/OT boundary to HMI)', pattern: /it.?ot|segmentation|boundary|den-ws-2010|hmi|scada|crossing/i },
    { label: 'careful containment (boundary isolation, not blind power-off)', pattern: /isolat|boundary|not power|block|coordinat/i },
    { label: 'notifications (plant ops/exec/IT/Legal, not all-staff/regulator)', pattern: /plant op|exec|it director|legal|not all.?staff|not.*regulator/i },
  ],
  closure: {
    disposition: 'resolve', severity: 'critical', category: 'OT - Plant Incident', resolutionCode: 'OT contained safely with plant ops; boundary isolated; Legal engaged',
    notifications: ['plant_ops', 'executives', 'it_director', 'legal'],
    notificationsForbidden: ['all_staff', 'regulator', 'customers'],
    reportFields: [
      { label: 'safety state and coordination with plant ops', pattern: /safety|plant op|coordinat|safe stop|line/i },
      { label: 'attack path across the IT/OT boundary', pattern: /it.?ot|boundary|segmentation|scada|hmi|crossing/i },
      { label: 'containment and recovery plan (boundary isolation, maintenance window)', pattern: /isolat|boundary|block|maintenance|recover/i },
      { label: 'root cause / lessons (segmentation, unpatched OT, owners)', pattern: /segmentation|unpatched|flat|least privilege|lesson|owner/i },
    ],
  },
  categoryAccept: ['ot', 'plant', 'scada', 'ics'],
  resolutionCodeAccept: ['ot', 'plant', 'contain', 'safety', 'scada'],
  hints: [
    'Safety, not data, is the priority. Coordinate with the Plant Manager before you contain anything - a blind remote power-off of OT/safety controllers can be dangerous.',
    'Find the path: a compromised corp workstation (DEN-WS-2010) crossed the IT/OT boundary to the HMI (WIC-SCADA01) where an unsigned process is writing setpoints.',
    'Contain carefully: isolate the entry workstation and isolate the HMI at the IT/OT boundary, block the C2 - but let plant ops bring the line to a safe stop.',
    'Notify plant operations, executives, the IT Director, and Legal. Do NOT send all-staff or notify a regulator yourself.',
  ],
  debrief: 'OT incident response inverts the IT instinct that fast containment is always right. On a plant floor the controllers move physical equipment, so an uncoordinated remote power-off or reboot - the reflex that is correct for a laptop - can drive the process into an unsafe state and hurt people. The first move is to coordinate with plant operations, who own the safety state and can bring the line to a controlled safe stop; only then do you contain, and you contain at the IT/OT boundary (isolate the entry host, cut the crossing, block the C2) while leaving independent safety instrumented systems alone. Everything else is familiar: this started as an ordinary corporate compromise that pivoted across a segmentation gap into OT, so the lessons-learned headline is IT/OT segmentation and OT patch/access hygiene. Notifications go to plant ops, executives, IT, and Legal; any safety or environmental regulator contact is Legal\'s call, and there is no all-staff broadcast.',
};

// ---------------------------------------------------------------------------
// CIRT-11  Confirmed PII breach - the regulatory-notification decision
// ---------------------------------------------------------------------------
const cirt_11: Scenario = {
  id: 'cirt-11',
  tier: 'cirt',
  title: 'Confirmed PII breach - who decides on notification?',
  category: 'Data Breach - Notification',
  difficulty: 4,
  estMinutes: 22,
  objective: 'Handle the decision phase of a confirmed personal-data breach: scope exactly what and how many records were exposed, preserve the evidence, and hand the notification timeline and regulator/customer decision to Legal - the responder scopes and preserves, Legal decides and notifies.',
  intake: {
    kind: 'incident', number: 'IR-2026-029', title: 'Confirmed exfiltration of the HR PII dataset',
    declaredBy: 'agrant', summary: 'Investigation of an earlier intrusion has confirmed that the HR share (D:\\Shares\\HR) containing SSNs and bank details for ~4,200 current and former employees was copied out to an external host. The intrusion is already contained; the open question is scope and the notification decision.',
    severity: 'SEV2', openedAt: ago(50), relatedAlerts: ['ALT-50171'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50171', time: ago(55), severity: 'high', source: 'dlp',
      title: 'Confirmed exfil of D:\\Shares\\HR PII to external host',
      description: 'DLP + firewall confirm the HR PII dataset (SSN, bank details, ~4,200 records) was archived and transferred to 45.61.136.20. Intrusion contained; determine exact scope and notification obligations.',
      host: 'DEN-FS01', indicators: ['45.61.136.20', 'D:\\Shares\\HR'], mitre: ['T1567', 'T1005'], status: 'in progress', truth: 'true_positive',
    });
    addLog(w, { time: ago(60 * 8), source: 'windows', host: 'DEN-FS01', user: 'svc_backup', action: 'collection', message: '4663 read + archive of D:\\Shares\\HR (hr_pii_2026.7z, 3.8GB) - SSN and bank detail columns' });
    addLog(w, { time: ago(60 * 7), source: 'firewall', host: 'DEN-FS01', srcIp: '10.10.10.20', dstIp: '45.61.136.20', dstPort: 443, action: 'allow', message: 'Outbound transfer 3.8GB hr_pii_2026.7z DEN-FS01 -> 45.61.136.20 (exfil of HR PII)' });
    // The HR share is the sensitive dataset; mark its record scope in notes.
    const fs = w.servers.find((s) => s.id === 'DEN-FS01')!;
    if (fs.shares) fs.shares.find((s) => s.name === 'HR')!.status = 'ok';
    fs.notes = 'HR share holds SSNs and bank details for ~4,200 current + former employees. Confirmed copied out.';
    w.intel.push({ indicator: '45.61.136.20', type: 'ip', verdict: 'malicious', source: 'exfil feed', tags: ['exfil', 'data-theft'], detail: 'Hosting IP used to receive stolen datasets.' });
    w.chat.push({ id: 'ch-rsingh11', with: 'rsingh', messages: [] }, { id: 'ch-sturner11', with: 'sturner', messages: [] });
  },
  contactWith: 'rsingh',
  contact: [
    { id: 'legal', question: 'Ask Legal (rsingh) who owns the breach-notification decision and timeline', answer: 'Raj Singh (Legal): "WE own the notification decision and the clock. Regulated PII for employees in several states triggers notification duties with specific deadlines. Get me the exact scope - what fields, how many records, which states - and preserve everything. Do NOT notify employees, regulators, or the media yourself."', purpose: 'verify', reveals: 'legal-owns' },
    { id: 'scope', question: 'Confirm the exact data elements and record count exposed', answer: 'The HR dataset had names, SSNs, and bank account details for ~4,200 current and former employees. The whole file (hr_pii_2026.7z, 3.8GB) was transferred out - treat all of it as exposed.', purpose: 'clarify', reveals: 'scope' },
    { id: 'hr', question: 'Engage HR (sturner) as the data owner for the affected-population list', answer: 'Sarah Turner (HR): "We are the data owner for employee records. We will build the affected-population list with the residency data Legal needs, and we will be ready to support affected-employee support once Legal sets the timing."', purpose: 'clarify', reveals: 'hr-owner' },
    { id: 'panic', question: 'Email all employees now that their SSNs were stolen', answer: '(Do NOT: employee/all-staff and regulator notification is Legal\'s decision and timing. A premature or inaccurate notice creates legal exposure.)', purpose: 'red_flag' },
  ],
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'kb18', label: 'Reviewed the IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'scope', label: 'Scoped exactly what data and how many records were exposed', match: [{ tool: 'siem', action: 'search', params: { q: /hr_pii|d:\\shares\\hr|45\.61\.136\.20|ssn|4663|exfil/i } }, { tool: 'server', action: 'view_shares', target: 'DEN-FS01' }], hint: 'What fields (SSN, bank), and how many records, actually left?' },
    { id: 'intel', label: 'Confirmed the destination is data-theft infrastructure', match: { tool: 'intel', action: 'lookup', target: '45.61.136.20' } },
  ],
  required: [
    { id: 'preserve', label: 'Placed a legal hold to preserve the exfil evidence', match: { tool: 'incident', action: 'legal_hold' }, skill: 'investigation' },
    { id: 'scope_incident', label: 'Recorded the scope of exposed records for Legal', match: [{ tool: 'incident', action: 'add_scope', target: /den-fs01|hr|svc_backup/i }, { tool: 'incident', action: 'add_timeline', params: { text: /.+/ } }], skill: 'investigation', after: 'preserve' },
    { id: 'notify_legal', label: 'Routed the notification decision and timeline to Legal', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
    { id: 'notify_hr', label: 'Engaged HR (the employee-data owner)', match: { tool: 'incident', action: 'notify', target: 'hr' }, skill: 'process' },
    { id: 'notify_leadership', label: 'Notified executives and the IT Director', match: [{ tool: 'incident', action: 'notify', target: 'executives' }, { tool: 'incident', action: 'notify', target: 'it_director' }], skill: 'process' },
  ],
  forbidden: [
    { id: 'reg_direct', label: 'Notified the regulator directly', why: 'KB-0017: the regulator notification decision and its statutory clock belong to Legal. The responder supplies scope; Legal decides and files.', match: { tool: 'incident', action: 'notify', target: 'regulator' }, skill: 'process', penalty: 0.4 },
    { id: 'cust_all_direct', label: 'Notified affected employees / customers / all staff directly', why: 'KB-0017: affected-user and customer notification is Legal\'s decision and timing (after containment, with clear instructions). Sending it yourself risks a premature or inaccurate notice.', match: [{ tool: 'incident', action: 'notify', target: 'affected_users' }, { tool: 'incident', action: 'notify', target: 'customers' }, { tool: 'incident', action: 'notify', target: 'all_staff' }], skill: 'process', penalty: 0.3 },
    { id: 'destroy_evidence', label: 'Wiped/reimaged the source before preserving the evidence', why: 'KB-0018: preserve first. Destroying the source before a legal hold erases the record of exactly what was taken - the very scope Legal needs to make the notification call.', match: [{ tool: 'incident', action: 'reimage', target: 'DEN-FS01' }, { tool: 'server', action: 'reboot', target: 'DEN-FS01' }], skill: 'security', penalty: 0.3, unlessAfter: 'preserve' },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Confirmed personal-data breach, scoped and handed to Legal. The HR dataset - names, SSNs, and bank details for ~4,200 current and former employees (hr_pii_2026.7z, 3.8GB) - was archived from D:\\Shares\\HR and transferred to 45.61.136.20; treat the whole file as exposed. The intrusion is already contained. I placed a legal hold and documented the exact scope (data elements, record count, timeline). This triggers notification obligations, but the decision and the statutory clock are Legal\'s: I engaged Legal with the scope and HR as the employee-data owner to build the affected-population and residency list, and briefed executives and the IT Director. I have NOT notified employees, customers, or any regulator - Legal owns that decision and timing.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Preserved, scoped precisely, and routed the notification decision to Legal with HR as data owner.' },
    { id: 'r_self_notify', text: 'Since SSNs were clearly stolen, I emailed the state regulator and all affected employees right away to meet the deadline.', scores: { communication: 0.3, process: 0.1 }, feedback: 'The notification decision and its clock are Legal\'s, not the responder\'s. Self-notifying risks a premature or inaccurate notice and legal exposure. Feed Legal the scope instead.' },
    { id: 'r_dismiss', text: 'The intrusion is already contained, so there is nothing more to do - closing it out.', scores: { communication: 0.3, security: 0.2, process: 0.2 }, feedback: 'Containment is not the end for a confirmed PII breach. You must preserve, scope precisely, and hand Legal the facts for the notification decision.' },
  ],
  notesRubric: [
    { label: 'exact scope (data elements + record count) documented', pattern: /ssn|bank|4,?200|records|pii|hr_pii|data element/i },
    { label: 'evidence preserved (legal hold) before any remediation', pattern: /legal hold|preserve|evidence|hold/i },
    { label: 'notification decision + clock owned by Legal', pattern: /legal|notification|decision|timeline|clock|deadline|owner/i },
    { label: 'HR as data owner; no direct regulator/employee/customer notice', pattern: /hr|data owner|not.*regulator|not.*employee|not.*customer|not.*direct/i },
  ],
  closure: {
    disposition: 'escalate', escalateTo: 'legal', severity: 'high', category: 'Data Breach - Notification', resolutionCode: 'Scoped & preserved; Legal owns notification decision',
    notifications: ['legal', 'executives', 'it_director'],
    notificationsForbidden: ['regulator', 'customers', 'all_staff', 'affected_users'],
    reportFields: [
      { label: 'what was exposed (data elements + record count)', pattern: /ssn|bank|records|4,?200|pii|data element/i },
      { label: 'evidence handling (legal hold, preserved scope)', pattern: /legal hold|preserve|evidence|scope/i },
      { label: 'notification decision ownership (Legal + clock)', pattern: /legal|notification|decision|timeline|clock|owner/i },
      { label: 'data owner engagement (HR) and next steps', pattern: /hr|data owner|affected|residency|next/i },
    ],
  },
  categoryAccept: ['data breach', 'breach', 'notification', 'pii'],
  resolutionCodeAccept: ['breach', 'pii', 'legal', 'notification', 'scope'],
  hints: [
    'The intrusion is contained; the job now is scope and the notification decision - do not rush to close or to notify.',
    'Scope precisely: which data elements (SSN, bank) and how many records (~4,200) actually left. Preserve it with a legal hold before touching the source.',
    'Engage HR as the employee-data owner to build the affected-population and residency list.',
    'The notification decision and its statutory clock are Legal\'s. Give Legal the scope; do NOT notify employees, customers, or any regulator yourself.',
  ],
  debrief: 'This scenario is deliberately post-containment: the intrusion is already stopped, so it isolates the judgment that trips up responders on a real personal-data breach - who decides whether, when, and whom to notify. The answer is Legal, always. Breach-notification laws attach specific obligations and deadlines to specific data elements (SSNs and financial details are the high-trigger ones) and to the residency of the affected people, and getting the timing or content wrong creates real liability. The responder\'s two jobs are to scope precisely (exact fields, exact record count, confirmed that the data actually left) and to preserve that scope with a legal hold, then to hand it to Legal with HR as the employee-data owner. The dual trap is doing Legal\'s job - self-notifying a regulator or emailing employees to "beat the clock" - or under-reacting by treating containment as the finish line. Scope and preserve; Legal decides and notifies.',
};

// ---------------------------------------------------------------------------
// CIRT-12  Cloud tenant global-admin (M365/Entra) compromise
// ---------------------------------------------------------------------------
const cirt_12: Scenario = {
  id: 'cirt-12',
  tier: 'cirt',
  title: 'Global Admin of the M365/Entra tenant is compromised',
  category: 'Cloud - Tenant Compromise',
  difficulty: 5,
  estMinutes: 26,
  objective: 'Respond to a cloud tenant compromise at the identity plane: revoke sessions and reset the Global Admin in the right order, then hunt the cloud-native persistence attackers leave behind - added admins, malicious OAuth app consents, and weakened conditional-access policies - and notify leadership and Legal without an all-staff or regulator broadcast.',
  intake: {
    kind: 'incident', number: 'IR-2026-030', title: 'Entra/M365 Global Admin (kbrooks) compromise with tenant persistence',
    declaredBy: 'agrant', summary: 'The M365/Entra Global Admin account kbrooks signed in from an anomalous IP, created a new Global Admin, granted admin-consent to an unknown OAuth app with mail-read/mail-send scopes, and modified a conditional-access policy to exclude that account from MFA. Tenant-wide persistence is likely.',
    severity: 'SEV1', openedAt: ago(22), relatedAlerts: ['ALT-50181'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50181', time: ago(26), severity: 'critical', source: 'cloud',
      title: 'Global Admin kbrooks: rogue admin + OAuth consent + CA policy change',
      description: 'kbrooks authenticated from 20.199.4.77 (anomalous), created Global Admin "svc_m365ops", admin-consented OAuth app "MailReader Pro" (Mail.Read/Mail.Send/Files.Read.All), and edited CA policy "Require MFA" to exclude the new account.',
      user: 'kbrooks', indicators: ['20.199.4.77', 'svc_m365ops', 'MailReader Pro'], mitre: ['T1078.004', 'T1098.003', 'T1528', 'T1556.009'], status: 'in progress', truth: 'true_positive',
    });
    // Create the compromised Global Admin (a cloud admin, not in the base world).
    w.users.push({
      id: 'kbrooks', displayName: 'Karen Brooks', title: 'Cloud / M365 Administrator', department: 'IT', manager: 'lchen',
      email: 'kbrooks@kestreldynamics.com', phone: '303-555-1299', employeeId: 'E10025', location: 'Denver HQ', enabled: true, lockedOut: false,
      passwordLastSet: daysAgo(35), groups: ['IT Staff', 'IT-Admins', 'Global Admins'], lastLogon: ago(22), badPwdCount: 0, mfaEnrolled: true, privileged: true,
      notes: 'M365/Entra Global Admin. MFA was enrolled but the attacker signed in from 20.199.4.77 and weakened the CA policy.',
      recentSignIns: [
        { time: ago(26), ip: '20.199.4.77', location: 'Amsterdam, NL (Azure hosting)', app: 'Azure Portal / Graph', result: 'success', device: 'unknown', mfa: 'satisfied' },
        { time: ago(60 * 22), ip: '10.10.20.36', location: 'Denver, US', app: 'M365 Admin Center', result: 'success', device: 'corp device', mfa: 'satisfied' },
      ],
    });
    // Rogue Global Admin created by the attacker.
    w.users.push({
      id: 'svc_m365ops', displayName: 'svc_m365ops (ROGUE)', title: 'Service Account', department: 'IT', email: 'svc_m365ops@kestreldynamics.com', phone: '', employeeId: 'SVC998', location: 'unknown', enabled: true, lockedOut: false,
      passwordLastSet: ago(26), passwordNeverExpires: true, groups: ['Global Admins'], lastLogon: ago(14), badPwdCount: 0, mfaEnrolled: false, privileged: true, notes: 'Created by kbrooks from 20.199.4.77. Not in HR records - attacker persistence.', recentSignIns: [],
    });
    // Cloud persistence trail.
    addLog(w, { time: ago(26), source: 'cloud', user: 'kbrooks', srcIp: '20.199.4.77', action: 'signin', message: 'Entra sign-in success kbrooks from 20.199.4.77 (Azure hosting, anomalous) app=Graph' });
    addLog(w, { time: ago(25), source: 'cloud', user: 'kbrooks', srcIp: '20.199.4.77', action: 'add_admin', message: 'Directory role assignment: svc_m365ops added to Global Administrator by kbrooks' });
    addLog(w, { time: ago(24), source: 'cloud', user: 'kbrooks', srcIp: '20.199.4.77', action: 'oauth_consent', message: 'Admin consent granted to OAuth app "MailReader Pro" scopes Mail.Read Mail.Send Files.Read.All (tenant-wide)' });
    addLog(w, { time: ago(23), source: 'cloud', user: 'kbrooks', srcIp: '20.199.4.77', action: 'ca_policy_change', message: 'Conditional Access policy "Require MFA" edited: svc_m365ops added to exclusions' });
    w.intel.push({ indicator: '20.199.4.77', type: 'ip', verdict: 'malicious', source: 'cloud threat feed', tags: ['aitm', 'token-theft', 'azure-hosting'], detail: 'Azure-hosted IP tied to AiTM/token-theft campaigns against M365 tenants.' });
    w.intel.push({ indicator: 'MailReader Pro', type: 'domain', verdict: 'malicious', source: 'app reputation', tags: ['oauth', 'illicit-consent'], detail: 'Illicit-consent OAuth app used to retain mailbox access after a password reset.' });
    w.chat.push({ id: 'ch-lchen12', with: 'lchen', messages: [] }, { id: 'ch-rsingh12', with: 'rsingh', messages: [] });
  },
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'kb18', label: 'Reviewed the IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'signin', label: 'Confirmed the anomalous Global Admin sign-in', match: [{ tool: 'directory', action: 'view_signins', target: 'kbrooks' }, { tool: 'siem', action: 'search', params: { q: /kbrooks|20\.199\.4\.77|graph|signin/i } }], hint: 'Where did the Global Admin sign in from, and does the location fit?' },
    { id: 'persistence', label: 'Found the cloud persistence (rogue admin, OAuth consent, CA change)', match: [{ tool: 'siem', action: 'search', params: { q: /svc_m365ops|oauth|mailreader|consent|conditional access|ca policy|add_admin/i } }, { tool: 'directory', action: 'view_group', target: 'Global Admins' }], hint: 'Attackers keep tenant access via added admins, OAuth app consents, and MFA/CA exclusions - check all three.' },
    { id: 'rogue', label: 'Identified the rogue Global Admin account', match: { tool: 'directory', action: 'view', target: 'svc_m365ops' } },
  ],
  required: [
    { id: 'revoke', label: 'Revoked the compromised Global Admin sessions/tokens first', match: { tool: 'directory', action: 'revoke_sessions', target: 'kbrooks' }, skill: 'technical' },
    { id: 'reset', label: 'Reset the Global Admin password and MFA after revoking', match: [{ tool: 'directory', action: 'reset_password', target: 'kbrooks' }, { tool: 'directory', action: 'reset_mfa', target: 'kbrooks' }], skill: 'technical', after: 'revoke' },
    { id: 'disable_rogue', label: 'Disabled the rogue Global Admin account', match: { tool: 'directory', action: 'disable', target: 'svc_m365ops' }, skill: 'technical' },
    { id: 'oauth', label: 'Revoked the malicious OAuth app consent (token persistence)', match: [{ tool: 'incident', action: 'add_scope', target: /mailreader|oauth|svc_m365ops/i }, { tool: 'siem', action: 'pivot', params: { value: /mailreader|20\.199\.4\.77/ } }], skill: 'security' },
    { id: 'notify_leadership', label: 'Notified the IT Director/CISO and executives (SEV1)', match: [{ tool: 'incident', action: 'notify', target: 'it_director' }, { tool: 'incident', action: 'notify', target: 'executives' }], skill: 'process' },
    { id: 'notify_legal', label: 'Engaged Legal (mailbox access = possible data exposure)', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'reset_only', label: 'Reset the password but ignored the OAuth consent and CA changes', why: 'A password reset does not evict an illicit OAuth app grant or a CA/MFA exclusion. The attacker keeps mailbox access via the app token. You must revoke the consent, remove the rogue admin, and undo the CA change. (KB-0018)', match: { tool: 'ticket', action: 'reply', target: 'r_partial' }, skill: 'security', penalty: 0.5 },
    { id: 'notify_all', label: 'Sent an all-staff notice during active response', why: 'KB-0017: no all-staff before containment - it tips the actor and pre-empts Legal on messaging.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
    { id: 'ext_direct', label: 'Notified a regulator / customers directly', why: 'KB-0017: with tenant-wide mailbox access, any regulator or customer notification is Legal\'s determination and timing, not the analyst\'s.', match: [{ tool: 'incident', action: 'notify', target: 'regulator' }, { tool: 'incident', action: 'notify', target: 'customers' }], skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Cloud tenant compromise at the Global Admin plane, contained. kbrooks signed in from 20.199.4.77 (Azure hosting, anomalous - consistent with AiTM/token theft) and established tenant persistence: created a rogue Global Admin (svc_m365ops), admin-consented a malicious OAuth app (MailReader Pro, Mail.Read/Send/Files) for token-based mailbox access, and edited the "Require MFA" conditional-access policy to exclude the rogue account. Actions in order: revoked kbrooks\'s sessions/tokens first, then reset her password and MFA; disabled the rogue admin; revoked the malicious OAuth consent and reverted the CA exclusion; and hunted for any other added admins or app grants. A password reset alone would not have evicted them - the OAuth token and CA exclusion are the real persistence. Notified the IT Director/CISO, execs, and Legal (tenant-wide mailbox access is possible data exposure). No all-staff or external notice.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Right containment order plus removal of cloud-native persistence (OAuth consent, rogue admin, CA change).' },
    { id: 'r_partial', text: 'Reset kbrooks\'s password and enabled MFA again - that locks the attacker out.', scores: { communication: 0.3, security: 0.2 }, feedback: 'Not for a tenant compromise. The illicit OAuth app token and the CA/MFA exclusion survive a password reset. Revoke the consent, remove the rogue admin, and undo the CA change.' },
    { id: 'r_broadcast', text: 'Reset everything and emailed all staff plus notified the regulator that the tenant was hacked.', scores: { communication: 0.3, process: 0.1 }, feedback: 'All-staff during active response tips the actor, and regulator notification is Legal\'s call. Contain and hand Legal the scope.' },
  ],
  notesRubric: [
    { label: 'anomalous Global Admin sign-in (token theft/AiTM)', pattern: /kbrooks|20\.199\.4\.77|anomal|aitm|token|global admin/i },
    { label: 'cloud persistence found (rogue admin, OAuth consent, CA/MFA change)', pattern: /oauth|consent|mailreader|rogue admin|svc_m365ops|conditional access|ca policy|exclusion/i },
    { label: 'containment order (revoke sessions -> reset -> remove persistence)', pattern: /revoke|reset|disable|revoke.*consent|remove.*admin/i },
    { label: 'notifications (leadership/legal, not all-staff/regulator)', pattern: /it director|ciso|legal|exec|not all.?staff|not.*regulator/i },
  ],
  closure: {
    disposition: 'resolve', severity: 'critical', category: 'Cloud - Tenant Compromise', resolutionCode: 'GA reset; rogue admin/OAuth/CA persistence removed',
    notifications: ['it_director', 'executives', 'legal'],
    notificationsForbidden: ['all_staff', 'regulator', 'customers'],
    reportFields: [
      { label: 'entry and sign-in anomaly (token theft/AiTM)', pattern: /kbrooks|20\.199\.4\.77|aitm|token|signin|anomal/i },
      { label: 'cloud persistence removed (OAuth, rogue admin, CA)', pattern: /oauth|consent|rogue|svc_m365ops|conditional access|ca policy|exclusion/i },
      { label: 'containment order (revoke, reset, disable)', pattern: /revoke|reset|disable|mfa/i },
      { label: 'root cause / follow-up (GA MFA, app-consent policy, monitoring)', pattern: /mfa|app.?consent|least privilege|conditional access|monitor|lesson|owner/i },
    ],
  },
  categoryAccept: ['cloud', 'tenant', 'm365', 'entra'],
  resolutionCodeAccept: ['cloud', 'tenant', 'oauth', 'contain', 'entra'],
  hints: [
    'Order matters in cloud identity: revoke the Global Admin\'s sessions/tokens FIRST, then reset the password and MFA.',
    'A password reset is not enough. Hunt the cloud-native persistence: added admins, malicious OAuth app consents, and conditional-access/MFA exclusions.',
    'Disable the rogue Global Admin (svc_m365ops), revoke the "MailReader Pro" OAuth consent, and revert the CA policy exclusion.',
    'Notify the IT Director/CISO, execs, and Legal (tenant-wide mailbox access = possible data exposure). No all-staff or regulator notice.',
  ],
  debrief: 'A cloud tenant compromise is an identity incident, and the lesson is that cloud persistence does not live in a password. Once an attacker reaches Global Admin - here almost certainly via token theft/AiTM, since MFA was enrolled yet the sign-in succeeded from hosting infrastructure - they plant persistence the cloud way: a second Global Admin, an OAuth application with admin-consented mail and file scopes (which keeps working via its own token after any password change), and a conditional-access edit that excludes their account from MFA. So the containment order is revoke sessions/tokens first, then reset the password and MFA, and then the part responders miss: hunt and remove every piece of tenant persistence. The recurring failure is stopping at the password reset. Because the OAuth grant gave tenant-wide mailbox access, Legal is engaged for the possible data-exposure question, while regulator and customer decisions stay with Legal and there is no all-staff broadcast.',
};

// ---------------------------------------------------------------------------
// CIRT-13  DDoS against public-facing services
// ---------------------------------------------------------------------------
const cirt_13: Scenario = {
  id: 'cirt-13',
  tier: 'cirt',
  title: 'Volumetric DDoS against public-facing services',
  category: 'Availability - DDoS',
  difficulty: 4,
  estMinutes: 20,
  objective: 'Run an availability incident: characterize the attack before you react, drive mitigation through the upstream ISP/CDN/scrubbing vendor, keep services up, and let Legal own any customer-facing message - do not null-route legitimate users, notify customers, or broadcast all-staff on your own.',
  intake: {
    kind: 'incident', number: 'IR-2026-031', title: 'Volumetric DDoS saturating the VPN concentrator and public web',
    declaredBy: 'pnguyen', summary: 'A large volumetric flood (mixed UDP/SYN, ~30 Gbps) from a global botnet is saturating our internet edge, degrading the VPN concentrator (DEN-VPN01) and public services. Remote workers are dropping. No sign of intrusion - this is availability, not compromise.',
    severity: 'SEV2', openedAt: ago(10), relatedAlerts: ['ALT-50191'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50191', time: ago(12), severity: 'high', source: 'ids',
      title: 'Volumetric DDoS ~30 Gbps against 198.51.100.10 (edge)',
      description: 'Mixed UDP amplification + SYN flood from a distributed botnet saturating the internet edge. DEN-VPN01 degraded; public web intermittently unreachable. No host compromise indicators.',
      host: 'DEN-VPN01', indicators: ['198.51.100.10'], mitre: ['T1498', 'T1498.001'], status: 'in progress', truth: 'true_positive',
    });
    const vpn = w.servers.find((s) => s.id === 'DEN-VPN01')!;
    vpn.status = 'degraded';
    // Flood evidence: many sources, high volume.
    for (let k = 0; k < 10; k++) {
      addLog(w, { time: ago(12 - k), source: 'firewall', srcIp: `45.9.${k}.${10 + k}`, dstIp: '198.51.100.10', dstPort: [53, 443, 123, 80][k % 4], action: 'allow', message: `DDoS flood ${1_000_000 + k * 50000} pps from botnet source 45.9.${k}.${10 + k} -> 198.51.100.10 (UDP/SYN)` });
    }
    addLog(w, { time: ago(11), source: 'vpn', host: 'DEN-VPN01', action: 'degraded', message: 'VPN concentrator at 98% link utilization; new sessions failing; existing sessions dropping' });
    w.intel.push({ indicator: '45.9.0.0/16', type: 'ip', verdict: 'malicious', source: 'DDoS feed', tags: ['ddos', 'botnet'], detail: 'Known booter/stresser botnet source range participating in volumetric floods.' });
    w.chat.push({ id: 'ch-pnguyen13', with: 'pnguyen', messages: [] }, { id: 'ch-rsingh13', with: 'rsingh', messages: [] });
  },
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'characterize', label: 'Characterized the attack (volume, vectors, distributed sources)', match: [{ tool: 'siem', action: 'search', params: { q: /ddos|flood|198\.51\.100\.10|pps|botnet|udp|syn/i } }, { tool: 'server', action: 'view', target: 'DEN-VPN01' }], hint: 'Is this a single source you can block, or a distributed volumetric flood that needs upstream scrubbing?' },
    { id: 'intel', label: 'Confirmed the source range is a known botnet', match: { tool: 'intel', action: 'lookup', target: '45.9.0.0/16' } },
    { id: 'no_intrusion', label: 'Confirmed there is no accompanying intrusion (availability only)', match: { tool: 'siem', action: 'pivot', params: { value: /198\.51\.100\.10/ } }, weight: 0.5, hint: 'Rule out that the DDoS is a smokescreen for a real compromise.' },
  ],
  required: [
    { id: 'scope', label: 'Characterized/scoped the attack before mitigating', match: [{ tool: 'incident', action: 'add_scope', target: /den-vpn01|198\.51\.100\.10/i }, { tool: 'incident', action: 'add_timeline', params: { text: /.+/ } }], skill: 'investigation' },
    { id: 'vendor', label: 'Engaged the upstream ISP/CDN/scrubbing vendor for mitigation', match: { tool: 'incident', action: 'notify', target: 'vendor' }, skill: 'process' },
    { id: 'mitigate', label: 'Applied edge mitigation without dropping legitimate users', match: [{ tool: 'perimeter', action: 'block', target: /45\.9/i }, { tool: 'perimeter', action: 'view_rules' }], skill: 'technical', after: 'scope' },
    { id: 'notify_leadership', label: 'Notified executives and the IT Director', match: [{ tool: 'incident', action: 'notify', target: 'executives' }, { tool: 'incident', action: 'notify', target: 'it_director' }], skill: 'process' },
  ],
  forbidden: [
    { id: 'notify_all', label: 'Sent an all-staff notice during active response', why: 'KB-0017: no all-staff broadcast during an active incident. A targeted status to the people who need it, not a company-wide blast.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
    { id: 'cust_direct', label: 'Posted a public statement / notified customers directly', why: 'KB-0017: customer-facing and public messaging is Legal\'s to own and time. A self-authored "we are under attack" notice creates exposure.', match: [{ tool: 'incident', action: 'notify', target: 'customers' }, { tool: 'incident', action: 'notify', target: 'regulator' }], skill: 'process', penalty: 0.3 },
    { id: 'blind_block', label: 'Null-routed the whole edge / blocked broad ranges before characterizing', why: 'Reacting before you characterize the flood can black-hole your own legitimate users. Scope the vectors and sources first, then apply targeted mitigation and let the upstream scrub what you cannot.', match: [{ tool: 'server', action: 'stop_service', target: 'DEN-VPN01' }, { tool: 'incident', action: 'reimage', target: 'DEN-VPN01' }], skill: 'security', penalty: 0.3, unlessAfter: 'scope' },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Volumetric DDoS, not a compromise. I characterized it first: a mixed UDP-amplification and SYN flood (~30 Gbps) from a distributed botnet (45.9.0.0/16 and others) saturating our edge at 198.51.100.10 and degrading DEN-VPN01 - and I confirmed there is no accompanying intrusion, so it is not a smokescreen. Because it is volumetric, the real fix is upstream: I engaged our ISP/CDN scrubbing vendor to filter the flood before it reaches our link, and applied targeted edge mitigation (rate-limiting and dropping the confirmed botnet ranges) without null-routing legitimate users. Notified executives and the IT Director with a factual status. Legal owns any customer-facing statement - I am not posting publicly or emailing customers myself. Services are stabilizing as scrubbing engages.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Characterized before reacting, drove mitigation upstream, kept legit users up, and left customer comms to Legal.' },
    { id: 'r_blackhole', text: 'Blocked huge inbound ranges and took the VPN concentrator offline to stop the flood.', scores: { communication: 0.3, security: 0.2, process: 0.3 }, feedback: 'That black-holes your own users and does not help against a distributed flood. Characterize first, engage upstream scrubbing, and apply targeted mitigation while keeping services up.' },
    { id: 'r_public', text: 'Emailed all staff and posted a public notice that we are under a cyberattack so customers know.', scores: { communication: 0.3, process: 0.1 }, feedback: 'No all-staff during active response, and public/customer messaging is Legal\'s to own and time.' },
  ],
  notesRubric: [
    { label: 'attack characterized (volumetric, vectors, distributed sources)', pattern: /ddos|volumetric|flood|udp|syn|gbps|pps|botnet|distributed/i },
    { label: 'ruled out an accompanying intrusion (availability only)', pattern: /no intrusion|not.*compromise|availability|smokescreen|no.*indicator/i },
    { label: 'mitigation via upstream ISP/CDN/scrubbing, keep services up', pattern: /isp|cdn|scrub|upstream|vendor|rate.?limit|keep.*up/i },
    { label: 'notifications (exec/IT/vendor; customers via Legal, not all-staff)', pattern: /exec|it director|vendor|legal|not all.?staff|not.*customer/i },
  ],
  closure: {
    disposition: 'escalate', escalateTo: 'vendor', severity: 'high', category: 'Availability - DDoS', resolutionCode: 'Characterized; upstream scrubbing engaged; services stabilizing',
    notifications: ['it_director', 'executives', 'vendor'],
    notificationsForbidden: ['all_staff', 'regulator', 'customers'],
    reportFields: [
      { label: 'attack profile (volume, vectors, sources)', pattern: /ddos|volumetric|gbps|pps|udp|syn|botnet|flood/i },
      { label: 'confirmation it is availability-only, not a compromise', pattern: /no intrusion|availability|not.*compromise|smokescreen/i },
      { label: 'mitigation approach (upstream scrubbing, targeted edge, services up)', pattern: /isp|cdn|scrub|upstream|rate.?limit|targeted|keep.*up/i },
      { label: 'comms ownership (Legal for customer/public) and follow-up', pattern: /legal|customer|public|comms|vendor|owner|follow/i },
    ],
  },
  categoryAccept: ['availability', 'ddos', 'denial'],
  resolutionCodeAccept: ['ddos', 'availability', 'scrub', 'vendor', 'mitigat'],
  hints: [
    'Characterize before you react: is this one source you can block, or a distributed volumetric flood? Confirm it is not a smokescreen for an intrusion.',
    'A ~30 Gbps volumetric flood cannot be solved at your own edge alone - engage the upstream ISP/CDN/scrubbing vendor to filter it before your link.',
    'Apply targeted edge mitigation (rate-limit, drop confirmed botnet ranges) - do NOT null-route the whole edge or take services down, which drops your own users.',
    'Notify executives, the IT Director, and the vendor. Any customer or public statement is Legal\'s - no all-staff and no direct customer/regulator notice.',
  ],
  debrief: 'A DDoS is an availability incident, and it rewards discipline over reflex. The first move is to characterize the attack - volume, vectors (here UDP amplification plus SYN flood), and whether the sources are singular or distributed - and to rule out that the flood is a smokescreen for a real intrusion. That characterization dictates the fix: a genuinely volumetric flood cannot be absorbed at your own edge, so mitigation is driven upstream through the ISP, CDN, or a scrubbing provider, with only targeted edge measures (rate-limiting, dropping confirmed botnet ranges) applied locally. The two traps are over-reacting at the edge - null-routing broad ranges or taking the service down, which finishes the attacker\'s job of denying your own users - and getting ahead of Legal on customer-facing messaging. Notify leadership and the vendor, keep services up, and let Legal own any public statement.',
};

// ---------------------------------------------------------------------------
// CIRT-14  Actively-exploited zero-day in a public-facing application
// ---------------------------------------------------------------------------
const cirt_14: Scenario = {
  id: 'cirt-14',
  tier: 'cirt',
  title: 'Zero-day being exploited in the public web app',
  category: 'Vuln - Exploited Zero-Day',
  difficulty: 5,
  estMinutes: 24,
  objective: 'Respond to an actively-exploited zero-day with no vendor patch available: apply emergency mitigation / a virtual patch to stop the bleeding, preserve evidence and hunt for exploitation before rebuilding, and notify leadership and Legal without an all-staff or regulator broadcast.',
  intake: {
    kind: 'incident', number: 'IR-2026-032', title: 'Active zero-day exploitation of DEN-WEB01 (no patch available)',
    declaredBy: 'agrant', summary: 'Our public web app on DEN-WEB01 is being actively exploited through an unauthenticated RCE zero-day; a webshell was dropped and is being used. The vendor has no patch yet. We need emergency mitigation, exploitation hunting, and evidence preservation.',
    severity: 'SEV1', openedAt: ago(14), relatedAlerts: ['ALT-50201'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50201', time: ago(18), severity: 'critical', source: 'ids',
      title: 'Unauth RCE zero-day + webshell on DEN-WEB01 (no patch)',
      description: 'Exploitation of an unauthenticated deserialization RCE (CVE pending) against the public app on DEN-WEB01 from 193.42.33.60. Webshell C:\\inetpub\\wwwroot\\uploads\\r.aspx dropped and executing commands. No vendor patch available.',
      host: 'DEN-WEB01', indicators: ['193.42.33.60', 'r.aspx'], mitre: ['T1190', 'T1505.003', 'T1059'], status: 'in progress', truth: 'true_positive',
    });
    // Add the DMZ public web server (not in the base world).
    w.servers.push({
      id: 'DEN-WEB01', role: 'DMZ public web application server (kestreldynamics.com app)', ip: '198.51.100.20', os: 'Windows Server 2022', status: 'degraded',
      services: [
        { name: 'W3SVC', displayName: 'World Wide Web Publishing Service', status: 'running', startType: 'auto' },
        { name: 'AeroPortal', displayName: 'Kestrel Aero Portal (vulnerable app)', status: 'running', startType: 'auto', suspicious: true },
        { name: 'HalberdAgent', displayName: 'Halberd EDR Agent', status: 'running', startType: 'auto' },
      ],
      disk: [{ drive: 'C:', used: 60, size: 120 }, { drive: 'E:', used: 30, size: 200 }], cpu: 35, mem: 60, uptimeHours: 300, events: [],
      processes: [
        { pid: 5200, name: 'w3wp.exe', user: 'IIS APPPOOL\\AeroPortal', cpu: 20, mem: 300, path: 'C:\\Windows\\System32\\inetsrv\\w3wp.exe', signed: true },
        { pid: 8840, name: 'cmd.exe', user: 'IIS APPPOOL\\AeroPortal', cpu: 8, mem: 20, path: 'C:\\Windows\\System32\\cmd.exe', cmdline: 'cmd.exe /c whoami & net user', parentPid: 5200, signed: true, started: ago(16) },
      ],
      backups: [{ job: 'WEB01-Daily', lastRun: ago(60 * 8), status: 'success', restorePoints: 14 }],
    });
    addLog(w, { time: ago(18), source: 'web', host: 'DEN-WEB01', srcIp: '193.42.33.60', action: 'exploit', message: 'POST /portal/api/import (deserialization RCE) from 193.42.33.60 -> 200; webshell written to uploads/r.aspx' });
    addLog(w, { time: ago(16), source: 'web', host: 'DEN-WEB01', srcIp: '193.42.33.60', action: 'webshell', message: 'GET /uploads/r.aspx?cmd=whoami from 193.42.33.60 (webshell command execution as AeroPortal app pool)' });
    addLog(w, { time: ago(15), source: 'edr', host: 'DEN-WEB01', action: 'discovery', message: 'w3wp.exe spawned cmd.exe running whoami / net user (hands-on-keyboard via webshell)', process: 'cmd.exe' });
    // A benign scanner hit (red herring) so trainees discriminate real exploitation from noise.
    addLog(w, { time: ago(60 * 3), source: 'web', host: 'DEN-WEB01', srcIp: '203.0.113.28', action: 'scan', message: 'GET /.env, /wp-login.php 404 from 203.0.113.28 (untargeted internet scan noise)' });
    w.intel.push({ indicator: '193.42.33.60', type: 'ip', verdict: 'malicious', source: 'threat feed', tags: ['exploitation', 'zero-day', 'webshell'], detail: 'Actively exploiting the pending-CVE deserialization flaw; drops .aspx webshells.' });
    w.intel.push({ indicator: 'r.aspx', type: 'hash', verdict: 'malicious', source: 'sandbox', tags: ['webshell', 'aspx'], detail: 'ASPX webshell used for post-exploitation command execution.' });
    w.chat.push({ id: 'ch-rsingh14', with: 'rsingh', messages: [] }, { id: 'ch-lchen14', with: 'lchen', messages: [] });
  },
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'kb18', label: 'Reviewed the IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'exploit', label: 'Confirmed active exploitation and the dropped webshell', match: [{ tool: 'siem', action: 'search', params: { q: /r\.aspx|193\.42\.33\.60|deserial|rce|webshell|import/i } }, { tool: 'server', action: 'view_processes', target: 'DEN-WEB01' }], hint: 'Find the exploit request and the webshell command execution (w3wp -> cmd).' },
    { id: 'hunt', label: 'Hunted for the scope of exploitation (post-exploit activity)', match: [{ tool: 'siem', action: 'pivot', params: { value: /193\.42\.33\.60|r\.aspx/ } }, { tool: 'edr', action: 'view_host', target: 'DEN-WEB01' }], hint: 'A webshell means hands-on-keyboard. What did they run after landing?' },
    { id: 'intel', label: 'Confirmed the source IP is active exploitation infrastructure', match: { tool: 'intel', action: 'lookup', target: '193.42.33.60' }, weight: 0.5 },
  ],
  required: [
    { id: 'triage', label: 'Preserved evidence (triage) before any rebuild', match: [{ tool: 'edr', action: 'collect_triage', target: 'DEN-WEB01' }, { tool: 'incident', action: 'collect_triage' }], skill: 'investigation' },
    { id: 'mitigate', label: 'Applied emergency mitigation / virtual patch to stop exploitation', match: [{ tool: 'perimeter', action: 'block', target: '193.42.33.60' }, { tool: 'server', action: 'stop_service', target: 'DEN-WEB01', params: { service: /aeroportal|w3svc/i } }], skill: 'technical', after: 'triage' },
    { id: 'isolate', label: 'Contained the server (isolate) after preserving evidence', match: { tool: 'edr', action: 'isolate', target: 'DEN-WEB01' }, skill: 'technical', after: 'triage' },
    { id: 'hunt', label: 'Hunted for the scope of exploitation across the estate', match: [{ tool: 'incident', action: 'add_scope', target: /den-web01|193\.42\.33\.60|r\.aspx/i }, { tool: 'siem', action: 'pivot', params: { value: /193\.42\.33\.60/ } }], skill: 'investigation' },
    { id: 'notify_leadership', label: 'Notified the IT Director/CISO and executives (SEV1)', match: [{ tool: 'incident', action: 'notify', target: 'it_director' }, { tool: 'incident', action: 'notify', target: 'executives' }], skill: 'process' },
    { id: 'notify_legal', label: 'Engaged Legal (public-facing app, possible data access)', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'rebuild_first', label: 'Reimaged/rebuilt the server before preserving evidence', why: 'KB-0018: preserve first. Rebuilding before triage destroys the exploit artifacts and the webshell activity you need to understand scope - and with no patch yet, a rebuilt server is re-exploitable immediately.', match: [{ tool: 'incident', action: 'reimage', target: 'DEN-WEB01' }, { tool: 'server', action: 'restore', target: 'DEN-WEB01' }], skill: 'security', penalty: 0.4, unlessAfter: 'triage' },
    { id: 'notify_all', label: 'Sent an all-staff notice during active response', why: 'KB-0017: no all-staff broadcast during an active incident - targeted, factual updates only.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
    { id: 'ext_direct', label: 'Notified a regulator / customers directly', why: 'KB-0017: with a public-facing app and possible data access, any regulator or customer notification is Legal\'s determination and timing.', match: [{ tool: 'incident', action: 'notify', target: 'regulator' }, { tool: 'incident', action: 'notify', target: 'customers' }], skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Actively-exploited zero-day on DEN-WEB01, contained. An unauthenticated deserialization RCE (CVE pending, no vendor patch) was exploited from 193.42.33.60 via POST /portal/api/import, dropping an ASPX webshell (uploads/r.aspx) that ran hands-on-keyboard commands (w3wp spawning cmd whoami/net user). Because there is no patch, I preserved evidence first (triage of the server), then applied emergency mitigation - a virtual patch/WAF rule and blocking the exploit path and source, and stopping the vulnerable app pool - and isolated the server. I hunted for scope across the estate for the webshell and the source IP to confirm it stayed contained to WEB01. Notified the IT Director/CISO, execs, and Legal (public-facing app with possible data access). No all-staff or external notice. Recovery waits on a vendor patch or a validated virtual patch before we rebuild from a known-good image and bring it back.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Preserve, virtual-patch the un-patchable, hunt for scope, and route external comms through Legal.' },
    { id: 'r_rebuild', text: 'Rebuilt the server from last night\'s backup right away to get the app back and remove the webshell.', scores: { communication: 0.3, security: 0.2, process: 0.3 }, feedback: 'Rebuilding first destroys the exploitation evidence, and with no patch the fresh server is re-exploited within minutes. Preserve, mitigate/virtual-patch, hunt, then rebuild.' },
    { id: 'r_broadcast', text: 'Emailed all staff and notified the regulator that our app was hacked and data may be gone.', scores: { communication: 0.3, process: 0.1 }, feedback: 'No all-staff during active response, and the regulator/customer decision is Legal\'s once scope is known.' },
  ],
  notesRubric: [
    { label: 'active zero-day exploitation + webshell identified', pattern: /zero.?day|rce|deserial|webshell|r\.aspx|193\.42\.33\.60|no patch/i },
    { label: 'evidence preserved before rebuild (triage first)', pattern: /triage|preserve|evidence|before.*rebuild|collect/i },
    { label: 'emergency mitigation / virtual patch (un-patchable now)', pattern: /virtual patch|waf|mitigat|block|stop.*app|rule/i },
    { label: 'hunted for scope; notifications (leadership/legal, not all-staff/regulator)', pattern: /hunt|scope|legal|it director|not all.?staff|not.*regulator/i },
  ],
  closure: {
    disposition: 'resolve', severity: 'critical', category: 'Vuln - Exploited Zero-Day', resolutionCode: 'Virtual-patched & contained; scope hunted; rebuild pending patch',
    notifications: ['it_director', 'executives', 'legal'],
    notificationsForbidden: ['all_staff', 'regulator', 'customers'],
    reportFields: [
      { label: 'the vulnerability and active exploitation (webshell)', pattern: /zero.?day|rce|deserial|webshell|r\.aspx|exploit/i },
      { label: 'evidence handling (triage before rebuild)', pattern: /triage|preserve|evidence|collect/i },
      { label: 'emergency mitigation and containment (virtual patch, isolate)', pattern: /virtual patch|waf|mitigat|block|isolat|stop/i },
      { label: 'scope hunt + recovery plan (rebuild once patched) with owners', pattern: /hunt|scope|rebuild|patch|monitor|owner|lesson/i },
    ],
  },
  categoryAccept: ['zero-day', 'zero day', 'vuln', 'exploit'],
  resolutionCodeAccept: ['zero-day', 'vuln', 'virtual patch', 'contain', 'exploit'],
  hints: [
    'There is no patch yet, so recovery cannot be "rebuild and move on" - a fresh server is re-exploited immediately. Stop the bleeding with a virtual patch/WAF rule and block the exploit path.',
    'Preserve first (KB-0018): collect triage of the server before you rebuild - you need the webshell and exploit artifacts to understand scope.',
    'A webshell means hands-on-keyboard: hunt for what the attacker ran and whether they reached anywhere beyond WEB01.',
    'Notify the IT Director/CISO, execs, and Legal (public-facing app, possible data access). No all-staff or direct regulator/customer notice.',
  ],
  debrief: 'An actively-exploited zero-day breaks the normal patch-then-move-on rhythm because there is nothing to patch yet, and that reshapes the whole response. The priority is to stop the bleeding with emergency mitigation - a virtual patch or WAF rule that blocks the exploit path, disabling the vulnerable function, and cutting the source - because a straight rebuild just hands the attacker a fresh, still-vulnerable target. Evidence still comes first: the dropped webshell and exploit artifacts are how you learn what the hands-on-keyboard attacker did and how far they reached, so triage precedes any rebuild. Then you hunt: a webshell is post-exploitation, so scope across the estate before declaring it contained. Recovery is gated on a real or validated virtual patch. The notification discipline is unchanged - leadership and Legal (public-facing app plus possible data access), no all-staff, and the regulator/customer decision belongs to Legal once scope is known.',
};

// ---------------------------------------------------------------------------
// CIRT-15  Backups destroyed just before ransomware - pivot to immutable copy
// ---------------------------------------------------------------------------
const cirt_15: Scenario = {
  id: 'cirt-15',
  tier: 'cirt',
  title: 'Attacker deleted the backups, then ran ransomware',
  category: 'Ransomware - Backup Destruction',
  difficulty: 5,
  estMinutes: 27,
  objective: 'Recover from ransomware where the attacker destroyed the primary backups first: discover the backup compromise, pivot recovery to the offsite immutable copy, rotate the backup credentials the attacker abused, and preserve evidence before rebuilding - with leadership and Legal engaged and no all-staff or regulator broadcast.',
  intake: {
    kind: 'incident', number: 'IR-2026-033', title: 'Ransomware on DEN-FS01 with primary backups deleted',
    declaredBy: 'agrant', summary: 'Ransomware has encrypted the file server DEN-FS01. On investigation, the primary backup jobs on DEN-BKP01 were deleted by the compromised backup service account shortly BEFORE the encryption - the attacker went after our recovery first. We need to find any surviving clean copy and rebuild.',
    severity: 'SEV1', openedAt: ago(16), relatedAlerts: ['ALT-50211'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50211', time: ago(20), severity: 'critical', source: 'edr',
      title: 'Backup deletion on DEN-BKP01 then encryption on DEN-FS01',
      description: 'svc_backup deleted the FS01 and SQL backup jobs and their restore points on DEN-BKP01, then a lockbit-style encryptor ran on DEN-FS01. The offsite immutable copy appears untouched (immutable retention).',
      host: 'DEN-BKP01', user: 'svc_backup', indicators: ['svc_backup', 'lock2.exe', '188.34.180.90'], mitre: ['T1490', 'T1486', 'T1078.002'], status: 'in progress', truth: 'true_positive',
    });
    // Encryptor on the file server.
    const fs = w.servers.find((s) => s.id === 'DEN-FS01')!;
    fs.status = 'degraded';
    fs.processes = [{ pid: 9210, name: 'lock2.exe', user: 'KESTREL\\svc_backup', cpu: 90, mem: 280, path: 'C:\\Windows\\Temp\\lock2.exe', cmdline: 'lock2.exe -enc D:\\Shares', signed: false, hash: 'c1f9...4d', started: ago(18) }];
    if (fs.shares) { fs.shares.find((s) => s.name === 'Finance')!.status = 'offline'; fs.shares.find((s) => s.name === 'Engineering')!.status = 'offline'; }
    // The backups: primaries destroyed (failed / 0 restore points), offsite immutable survives.
    const bkp = w.servers.find((s) => s.id === 'DEN-BKP01')!;
    bkp.backups = [
      { job: 'FS01-Daily-Shares', lastRun: ago(60 * 22), status: 'failed', restorePoints: 0 },
      { job: 'APP01-SQL-Full', lastRun: ago(60 * 22), status: 'failed', restorePoints: 0 },
      { job: 'Offsite-Immutable-Copy', lastRun: ago(60 * 26), status: 'success', restorePoints: 30 },
    ];
    bkp.notes = 'Primary backup jobs deleted by svc_backup at 08:5x (restore points purged). Offsite immutable copy uses locked retention - not deletable by svc_backup.';
    addEvent(host(w, 'DEN-LT-1021'), { id: 4624, time: ago(60 * 40), level: 'Audit Success', source: 'Microsoft-Windows-Security-Auditing', log: 'Security', message: 'placeholder' });
    // Deletion + entry trail.
    addLog(w, { time: ago(60 * 34), source: 'firewall', host: 'DEN-LT-1042', srcIp: '10.10.20.42', dstIp: '188.34.180.90', dstPort: 443, action: 'allow', message: 'C2 beacon from patient-zero DEN-LT-1042 -> 188.34.180.90' });
    addLog(w, { time: ago(60 * 26), source: 'auth', host: 'DEN-BKP01', user: 'svc_backup', srcIp: '10.10.20.42', action: 'logon', message: '4624 Logon type 3 svc_backup on DEN-BKP01 from DEN-LT-1042 - lateral movement to the backup server' });
    addLog(w, { time: ago(24), source: 'windows', host: 'DEN-BKP01', user: 'svc_backup', action: 'backup_delete', message: 'Veeam jobs FS01-Daily-Shares and APP01-SQL-Full deleted; restore points purged by svc_backup (recovery sabotage)' });
    addLog(w, { time: ago(18), source: 'edr', host: 'DEN-FS01', user: 'svc_backup', action: 'exec', message: 'lock2.exe executed on DEN-FS01 (encryptor) after backups were destroyed', process: 'lock2.exe' });
    w.intel.push({ indicator: '188.34.180.90', type: 'ip', verdict: 'malicious', source: 'C2 feed', tags: ['c2', 'ransomware'], detail: 'C2 for the affiliate that deletes backups before encrypting.' });
    w.intel.push({ indicator: 'lock2.exe', type: 'hash', verdict: 'malicious', source: 'sandbox', tags: ['ransomware'], detail: 'LockBit-style encryptor. c1f9...4d.' });
    w.chat.push({ id: 'ch-rsingh15', with: 'rsingh', messages: [] }, { id: 'ch-lchen15', with: 'lchen', messages: [] });
  },
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'kb18', label: 'Reviewed the IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'backup_destroyed', label: 'Discovered the primary backups were deleted before encryption', match: [{ tool: 'server', action: 'view_backups', target: 'DEN-BKP01' }, { tool: 'siem', action: 'search', params: { q: /backup.?delete|restore point|veeam|purge|svc_backup/i } }], hint: 'Check the backup jobs - which failed/have 0 restore points, and what still survives?' },
    { id: 'immutable', label: 'Confirmed the offsite immutable copy survived', match: [{ tool: 'server', action: 'view_backups', target: 'DEN-BKP01' }, { tool: 'siem', action: 'search', params: { q: /immutable|offsite/i } }], hint: 'Immutable/locked retention cannot be deleted by the compromised account - that is your recovery.' },
    { id: 'patient0', label: 'Traced the intrusion to patient zero and svc_backup lateral movement', match: [{ tool: 'siem', action: 'pivot', params: { value: /svc_backup|188\.34\.180\.90/ } }, { tool: 'siem', action: 'search', params: { q: /den-lt-1042|lateral|beacon/i } }] },
  ],
  required: [
    { id: 'isolate', label: 'Isolated the file server and the backup server', match: [{ tool: 'edr', action: 'isolate', target: 'DEN-FS01' }, { tool: 'edr', action: 'isolate', target: 'DEN-BKP01' }], skill: 'technical' },
    { id: 'disable_svc', label: 'Disabled/rotated the compromised backup service account', match: [{ tool: 'directory', action: 'disable', target: 'svc_backup' }, { tool: 'incident', action: 'reset_service_account', target: 'svc_backup' }], skill: 'security' },
    { id: 'triage', label: 'Preserved evidence (triage) before rebuilding', match: [{ tool: 'edr', action: 'collect_triage', target: 'DEN-FS01' }, { tool: 'incident', action: 'collect_triage' }], skill: 'investigation', after: 'isolate' },
    { id: 'restore', label: 'Recovered from the surviving offsite immutable copy', match: [{ tool: 'server', action: 'restore', target: 'DEN-BKP01', params: { job: /immutable|offsite/i } }, { tool: 'incident', action: 'restore_backup', target: 'DEN-FS01' }], skill: 'technical', after: 'triage' },
    { id: 'notify_leadership', label: 'Notified the IT Director/CISO and executives (SEV1)', match: [{ tool: 'incident', action: 'notify', target: 'it_director' }, { tool: 'incident', action: 'notify', target: 'executives' }], skill: 'process' },
    { id: 'notify_legal', label: 'Engaged Legal', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'wipe', label: 'Reimaged/rebooted a server before collecting evidence', why: 'KB-0018: preserve first. With backups already destroyed, the live systems are your only remaining evidence of how they got in and how the backups were deleted - do not wipe them before triage.', match: [{ tool: 'incident', action: 'reimage', target: 'DEN-FS01' }, { tool: 'server', action: 'reboot', target: 'DEN-BKP01' }], skill: 'security', penalty: 0.4, unlessAfter: 'triage' },
    { id: 'notify_all', label: 'Sent an all-staff notice during active response', why: 'KB-0017: no all-staff before containment - it tips off the actor and causes panic.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
    { id: 'ext_direct', label: 'Notified a regulator / customers directly', why: 'KB-0017: any regulator or customer notification is Legal\'s determination and timing, not the analyst\'s.', match: [{ tool: 'incident', action: 'notify', target: 'regulator' }, { tool: 'incident', action: 'notify', target: 'customers' }], skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Ransomware with deliberate backup destruction, contained and recovering. Patient zero DEN-LT-1042 was beaconing to 188.34.180.90; the attacker pivoted with the over-privileged svc_backup account to the backup server DEN-BKP01, DELETED the FS01 and SQL backup jobs and purged their restore points, then ran the encryptor (lock2.exe) on DEN-FS01 - they went after our recovery first. The primary backups are gone, but the offsite immutable copy (locked retention, not deletable by svc_backup) survived. Actions: isolated FS01 and BKP01, disabled and rotated svc_backup (the abused account), collected triage - the live systems are now our only evidence since the backups are gone - then recovered from the offsite immutable copy. Notified the IT Director/CISO, execs, and Legal. No all-staff. Root cause and lessons-learned headline: a backup account with standing delete rights and mutable primary backups - immutability and least privilege on backups is what saved us.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Found the backup sabotage, pivoted to the immutable copy, preserved evidence, and rotated the abused account.' },
    { id: 'r_stuck', text: 'The backups are deleted, so there is no clean restore point - we will have to consider paying to get the data back.', scores: { communication: 0.3, security: 0.2, process: 0.2 }, feedback: 'Check for a surviving offsite/immutable copy before concluding there is nothing to restore - immutable retention is not deletable by the compromised account. That is your recovery.' },
    { id: 'r_fast', text: 'Restored the immutable copy over the top immediately and reimaged both servers to get back fast.', scores: { communication: 0.3, security: 0.3, process: 0.3 }, feedback: 'Preserve first - with the backups already destroyed the live systems are your only evidence. Isolate, rotate the abused account, triage, then restore from the immutable copy.' },
  ],
  notesRubric: [
    { label: 'backup destruction discovered (deleted before encryption)', pattern: /backup.?delete|restore point|purge|deleted.*backup|before encrypt|sabotage/i },
    { label: 'surviving offsite immutable copy identified as recovery', pattern: /immutable|offsite|locked retention|surviv|clean copy/i },
    { label: 'evidence preserved + abused backup account rotated', pattern: /triage|preserve|svc_backup|rotate|disable|isolat/i },
    { label: 'notifications (leadership/legal, not all-staff/regulator)', pattern: /it director|ciso|legal|exec|not all.?staff|not.*regulator/i },
  ],
  closure: {
    disposition: 'resolve', severity: 'critical', category: 'Ransomware - Backup Destruction', resolutionCode: 'Recovered from immutable copy; backup account rotated',
    notifications: ['it_director', 'executives', 'legal'],
    notificationsForbidden: ['all_staff', 'regulator', 'customers'],
    reportFields: [
      { label: 'attack chain incl. backup deletion before encryption', pattern: /beacon|lateral|backup.?delete|restore point|encrypt|timeline/i },
      { label: 'recovery from the surviving immutable/offsite copy', pattern: /immutable|offsite|surviv|restore|clean copy/i },
      { label: 'evidence handling + credential rotation', pattern: /triage|preserve|svc_backup|rotate|disable/i },
      { label: 'root cause / lessons (immutable backups, least privilege on backup acct)', pattern: /immutab|least privilege|standing|delete rights|3-2-1|lesson|owner/i },
    ],
  },
  categoryAccept: ['ransomware', 'backup', 'destruction'],
  resolutionCodeAccept: ['ransomware', 'backup', 'immutable', 'contain', 'restore'],
  hints: [
    'Contain first: isolate the file server AND the backup server in EDR, and disable/rotate the compromised svc_backup account it abused.',
    'The attacker deleted the primary backups before encrypting - check the backup jobs for what failed/has 0 restore points AND what survived.',
    'The offsite immutable copy (locked retention) cannot be deleted by svc_backup - that is your recovery point.',
    'Preserve evidence (triage) before rebuilding - the live systems are your only evidence now. Notify the IT Director, execs, and Legal; no all-staff or direct regulator/customer notice.',
  ],
  debrief: 'Modern ransomware crews attack the recovery before the data, because an organization that can restore does not pay. Here the compromised backup account deleted the primary backup jobs and purged their restore points, then encrypted the file server - so the responder who reaches for "the last clean backup" finds nothing there. The scenario teaches two things. First, the discovery: read the backup state carefully to see both what was destroyed and, crucially, what survived - an offsite copy under immutable/locked retention cannot be deleted even by a compromised backup account, and that is the recovery. Second, the order under pressure: with the backups gone the live systems are now the only evidence, so preserve (triage) before you rebuild, and rotate the very account the attacker abused to reach the backup server. The lessons-learned headline writes itself - immutable, offsite backups and least privilege on the backup service account are exactly the controls that turned a catastrophe into a recovery. Notifications are the standard ransomware set: leadership and Legal, never all-staff or a direct regulator notice.',
};

// ---------------------------------------------------------------------------
// CIRT-16  APT long-dwell intrusion - coordinated eradication
// ---------------------------------------------------------------------------
const cirt_16: Scenario = {
  id: 'cirt-16',
  tier: 'cirt',
  title: 'APT with months of dwell time - eradicate without tipping them off',
  category: 'APT - Long Dwell',
  difficulty: 5,
  estMinutes: 28,
  objective: 'Respond to a long-dwell APT intrusion: fully scope the footprint and dwell time before acting, plan a single coordinated eradication rather than tipping the actor off with piecemeal remediation, bring in the IR retainer, and route any law-enforcement contact through Legal - no all-staff, no direct law-enforcement or regulator notice.',
  intake: {
    kind: 'incident', number: 'IR-2026-034', title: 'Suspected APT intrusion with multi-month dwell time',
    declaredBy: 'agrant', summary: 'Threat hunting found a stealthy intrusion that appears to date back ~4 months: multiple hosts with a signed-binary backdoor, a dormant admin account, scheduled-task persistence, and low-and-slow C2. This looks like a targeted APT, not a smash-and-grab. Nothing has been remediated yet.',
    severity: 'SEV1', openedAt: ago(30), relatedAlerts: ['ALT-50221'],
  },
  priorityExpected: 'P1',
  setup: (w) => {
    addAlert(w, {
      id: 'ALT-50221', time: ago(40), severity: 'critical', source: 'edr',
      title: 'Long-dwell APT: backdoor on multiple hosts + dormant admin + low-slow C2',
      description: 'Hunt uncovered a DLL-sideloaded backdoor on DEN-APP01, DEN-WS-2010 and DEN-LT-1021, a dormant admin account (svc_iis_adm) created ~4 months ago, scheduled-task persistence, and beaconing to 45.86.230.14 every ~6h. Consistent with a targeted actor. No remediation performed yet.',
      host: 'DEN-APP01', indicators: ['45.86.230.14', 'svc_iis_adm', 'wsupd.dll'], mitre: ['T1574.002', 'T1078', 'T1053.005', 'T1071'], status: 'in progress', truth: 'true_positive',
    });
    // Dormant attacker admin account, created months ago and lying low.
    w.users.push({
      id: 'svc_iis_adm', displayName: 'svc_iis_adm (APT persistence)', title: 'Service Account', department: 'IT', email: 'svc_iis_adm@kestreldynamics.com', phone: '', employeeId: 'SVC997', location: 'unknown', enabled: true, lockedOut: false,
      passwordLastSet: daysAgo(120), passwordNeverExpires: true, groups: ['Server Admins', 'IT-Admins'], lastLogon: ago(60 * 24), badPwdCount: 0, mfaEnrolled: false, privileged: true, notes: 'Created ~4 months ago; not in HR/change records. Dormant admin - APT persistence.', recentSignIns: [],
    });
    // Backdoor + persistence across several hosts.
    for (const id of ['DEN-APP01']) {
      const s = w.servers.find((sv) => sv.id === id);
      if (s) { s.processes = [{ pid: 6120, name: 'w3wp.exe', user: 'IIS APPPOOL\\ERP', cpu: 6, mem: 200, path: 'C:\\Windows\\System32\\inetsrv\\w3wp.exe', signed: true }, { pid: 7010, name: 'wsupd.exe', user: 'SYSTEM', cpu: 1, mem: 40, path: 'C:\\ProgramData\\wsupd\\wsupd.exe', cmdline: 'wsupd.exe', signed: true, hash: '77aa...e2', started: daysAgo(120) }]; }
    }
    for (const hid of ['DEN-WS-2010', 'DEN-LT-1021']) {
      const h = host(w, hid);
      addProc(h, { pid: 7010, name: 'wsupd.exe', user: 'SYSTEM', cpu: 0.6, mem: 35, path: 'C:\\ProgramData\\wsupd\\wsupd.exe', cmdline: 'rundll32 wsupd.dll,Start', signed: true, hash: '77aa...e2', started: daysAgo(115) });
      h.scheduledTasks.push({ name: 'WindowsUpdateSvc', path: '\\Microsoft\\Windows\\', action: 'rundll32.exe C:\\ProgramData\\wsupd\\wsupd.dll,Start', trigger: 'Daily 02:17 (jittered)', author: 'SYSTEM', suspicious: true });
    }
    // Low-and-slow C2 over months (a few sparse beacons).
    addLog(w, { time: daysAgo(115), source: 'firewall', host: 'DEN-APP01', srcIp: '10.10.10.40', dstIp: '45.86.230.14', dstPort: 443, action: 'allow', message: 'Low-slow C2 beacon DEN-APP01 -> 45.86.230.14 (first observed ~4 months ago)' });
    addLog(w, { time: daysAgo(40), source: 'firewall', host: 'DEN-WS-2010', srcIp: '10.10.21.10', dstIp: '45.86.230.14', dstPort: 443, action: 'allow', message: 'Low-slow C2 beacon DEN-WS-2010 -> 45.86.230.14 (~6h interval, jittered)' });
    addLog(w, { time: ago(60 * 10), source: 'firewall', host: 'DEN-LT-1021', srcIp: '10.10.20.121', dstIp: '45.86.230.14', dstPort: 443, action: 'allow', message: 'Low-slow C2 beacon DEN-LT-1021 -> 45.86.230.14' });
    addLog(w, { time: daysAgo(118), source: 'auth', host: 'DEN-DC01', user: 'svc_iis_adm', action: 'account_create', message: '4720 svc_iis_adm created and added to Server Admins/IT-Admins (~4 months ago) - no change ticket' });
    w.intel.push({ indicator: '45.86.230.14', type: 'ip', verdict: 'malicious', source: 'APT feed', tags: ['apt', 'c2', 'low-slow'], detail: 'C2 attributed to a targeted intrusion set known for long dwell and DLL sideloading.' });
    w.intel.push({ indicator: 'wsupd.dll', type: 'hash', verdict: 'malicious', source: 'sandbox', tags: ['backdoor', 'sideload'], detail: 'Sideloaded backdoor masquerading as a Windows update component. 77aa...e2.' });
    w.chat.push({ id: 'ch-rsingh16', with: 'rsingh', messages: [] }, { id: 'ch-lchen16', with: 'lchen', messages: [] });
  },
  evidence: [
    { id: 'kb17', label: 'Reviewed the notification matrix (KB-0017)', match: { tool: 'kb', action: 'read', target: 'KB-0017' } },
    { id: 'kb18', label: 'Reviewed the IR lifecycle & evidence handling (KB-0018)', match: { tool: 'kb', action: 'read', target: 'KB-0018' } },
    { id: 'dwell', label: 'Established the dwell time (~4 months of low-slow C2)', match: [{ tool: 'siem', action: 'search', params: { q: /45\.86\.230\.14|low.?slow|beacon|wsupd|dwell/i } }, { tool: 'siem', action: 'pivot', params: { value: /45\.86\.230\.14/ } }], hint: 'When was the C2 first seen? APTs are measured in months, not minutes.' },
    { id: 'footprint', label: 'Mapped the full footprint (backdoor hosts, dormant admin, persistence)', match: [{ tool: 'siem', action: 'search', params: { q: /wsupd|svc_iis_adm|windowsupdatesvc|scheduled task|sideload|rundll32/i } }, { tool: 'directory', action: 'view', target: 'svc_iis_adm' }], hint: 'Find every backdoored host, the dormant admin, and each persistence mechanism before you touch anything.' },
    { id: 'account', label: 'Identified the dormant attacker admin account', match: { tool: 'directory', action: 'view_signins', target: 'svc_iis_adm' }, weight: 0.5 },
  ],
  required: [
    { id: 'scope', label: 'Fully scoped the intrusion before any remediation', match: [{ tool: 'incident', action: 'add_scope', target: /den-app01|den-ws-2010|den-lt-1021|svc_iis_adm|45\.86\.230\.14/i }, { tool: 'incident', action: 'add_timeline', params: { text: /.+/ } }], skill: 'investigation' },
    { id: 'retainer', label: 'Engaged the IR retainer / external forensics for a targeted actor', match: { tool: 'incident', action: 'engage_retainer' }, skill: 'process' },
    { id: 'triage', label: 'Collected forensic triage across affected hosts', match: [{ tool: 'edr', action: 'collect_triage', target: /den-app01|den-ws-2010|den-lt-1021/i }, { tool: 'incident', action: 'collect_triage' }], skill: 'investigation', after: 'scope' },
    { id: 'eradicate', label: 'Executed a single coordinated containment/eradication after scoping', match: [{ tool: 'edr', action: 'isolate', target: /den-app01|den-ws-2010|den-lt-1021/i }, { tool: 'directory', action: 'disable', target: 'svc_iis_adm' }], skill: 'security', after: 'scope' },
    { id: 'notify_leadership', label: 'Notified the IT Director/CISO and executives (SEV1)', match: [{ tool: 'incident', action: 'notify', target: 'it_director' }, { tool: 'incident', action: 'notify', target: 'executives' }], skill: 'process' },
    { id: 'notify_legal', label: 'Engaged Legal (owns any law-enforcement contact)', match: { tool: 'incident', action: 'notify', target: 'legal' }, skill: 'process' },
  ],
  forbidden: [
    { id: 'piecemeal', label: 'Remediated piecemeal (isolated/reimaged one host or disabled the account) before full scope', why: 'Against a targeted actor, piecemeal remediation is the classic error: reimaging one host or disabling one account while the rest of the footprint is unknown tips the actor off, and they burn their remaining access, deploy new persistence, or destroy data. Scope fully, then eradicate everything at once.', match: [{ tool: 'incident', action: 'reimage', target: /den-app01|den-ws-2010|den-lt-1021/i }, { tool: 'directory', action: 'disable', target: 'svc_iis_adm' }], skill: 'security', penalty: 0.5, unlessAfter: 'scope' },
    { id: 'le_direct', label: 'Contacted law enforcement / the regulator directly', why: 'KB-0017: law-enforcement contact (and any regulator notice) routes through Legal. For a targeted-actor case especially, the analyst feeds Legal the facts and does not make the external contact.', match: [{ tool: 'incident', action: 'notify', target: 'law_enforcement' }, { tool: 'incident', action: 'notify', target: 'regulator' }], skill: 'process', penalty: 0.4 },
    { id: 'notify_all', label: 'Sent an all-staff notice during active response', why: 'KB-0017: no all-staff broadcast - it is especially dangerous here because a leak tips off a patient, targeted actor who is watching.', match: { tool: 'incident', action: 'notify', target: 'all_staff' }, skill: 'process', penalty: 0.3 },
  ],
  replies: [
    { id: 'r_best', best: true, text: 'Targeted long-dwell APT, scoped and eradicated in one coordinated action. The intrusion dates back ~4 months: a DLL-sideloaded backdoor (wsupd.dll masquerading as a Windows update component) on DEN-APP01, DEN-WS-2010 and DEN-LT-1021, a dormant admin account (svc_iis_adm) created ~4 months ago with no change ticket, scheduled-task persistence, and low-and-slow C2 to 45.86.230.14 every ~6h. Because this is a patient targeted actor, I did NOT remediate piecemeal - that would tip them off and let them burn their remaining access or deploy new persistence. Instead I fully scoped the footprint and dwell time, engaged our IR retainer for forensics, collected triage across the affected hosts, and then executed a single coordinated eradication: simultaneous isolation of every backdoored host, disabling the dormant admin, and killing the persistence together. Notified the IT Director/CISO, execs, and Legal - Legal owns any law-enforcement contact. No all-staff, and no direct LE/regulator notice from me.', scores: { communication: 1, security: 1, process: 1 }, feedback: 'Scoped fully, engaged the retainer, and eradicated in one coordinated move rather than tipping off the actor.' },
    { id: 'r_piecemeal', text: 'As soon as I found the backdoor on DEN-APP01 I reimaged it and disabled the suspicious account to cut them off fast.', scores: { communication: 0.3, security: 0.2, process: 0.2 }, feedback: 'Against a targeted actor this is the classic mistake: piecemeal remediation tips them off before you know the full footprint, and they dig back in with new persistence. Scope everything first, then eradicate at once.' },
    { id: 'r_le', text: 'Scoped it, then called the FBI directly and emailed all staff to be transparent about the APT.', scores: { communication: 0.3, process: 0.1 }, feedback: 'Law-enforcement contact routes through Legal, and an all-staff notice tips off a patient actor who is watching. Feed Legal the facts.' },
  ],
  notesRubric: [
    { label: 'dwell time + full footprint established (months, multiple hosts)', pattern: /dwell|4 month|months|footprint|multiple host|low.?slow|backdoor|svc_iis_adm/i },
    { label: 'coordinated eradication, NOT piecemeal (do not tip off the actor)', pattern: /coordinat|all at once|simultaneous|not piecemeal|tip.*off|before.*eradicat|scope.*first/i },
    { label: 'IR retainer / forensics engaged + evidence preserved', pattern: /retainer|forensic|external|triage|preserve|image/i },
    { label: 'notifications (leadership/legal; LE via Legal, not all-staff/direct)', pattern: /it director|ciso|legal|exec|law enforcement.*legal|via legal|not all.?staff|not.*direct/i },
  ],
  closure: {
    disposition: 'resolve', severity: 'critical', category: 'APT - Long Dwell', resolutionCode: 'Scoped fully; coordinated eradication; retainer/Legal engaged',
    notifications: ['it_director', 'executives', 'legal'],
    notificationsForbidden: ['all_staff', 'law_enforcement', 'regulator', 'customers'],
    reportFields: [
      { label: 'dwell time and full footprint (hosts, account, persistence)', pattern: /dwell|month|footprint|backdoor|svc_iis_adm|persistence|host/i },
      { label: 'why coordinated eradication over piecemeal', pattern: /coordinat|piecemeal|tip.*off|simultaneous|all at once|scope.*first/i },
      { label: 'forensics/retainer and evidence handling', pattern: /retainer|forensic|triage|preserve|external/i },
      { label: 'notification ownership (Legal owns LE) and follow-up', pattern: /legal|law enforcement|via legal|monitor|owner|lesson|follow/i },
    ],
  },
  categoryAccept: ['apt', 'long dwell', 'dwell', 'targeted'],
  resolutionCodeAccept: ['apt', 'dwell', 'coordinated', 'eradicat', 'contain'],
  hints: [
    'This is a patient, targeted actor - not a smash-and-grab. Do NOT remediate piecemeal; that tips them off.',
    'Establish the dwell time (~4 months of low-slow C2) and map the FULL footprint first: every backdoored host, the dormant admin account, and each persistence mechanism.',
    'Engage the IR retainer/external forensics and collect triage, then plan a single coordinated eradication - isolate all hosts, disable the account, and kill persistence together.',
    'Notify the IT Director/CISO, execs, and Legal. Law-enforcement contact routes through Legal - do NOT call LE or the regulator yourself, and no all-staff notice.',
  ],
  debrief: 'A long-dwell APT is the discipline exam: the instinct that serves you in a fast ransomware case - contain the moment you find something - is exactly what loses this one. A targeted actor who has been resident for months has redundant persistence you have not found yet and is watching for signs of discovery, so remediating piecemeal (reimaging the first backdoored host, disabling the first suspicious account) tips them off and they burn their remaining access, deploy fresh persistence, or turn destructive. The correct sequence is to scope completely first - establish dwell time and enumerate every implant, persistence mechanism, and account across the estate, quietly - bring in the IR retainer for the forensic depth these cases demand, preserve evidence, and then execute a single coordinated eradication that removes all of it at once so the actor loses every foothold simultaneously. The notification rules matter more than usual: no all-staff, because a leak reaches a patient adversary, and law-enforcement contact - often relevant for a nation-state-grade actor - routes through Legal, never directly from the analyst.',
};

export const CIRT_SCENARIOS_C: Scenario[] = [
  cirt_09, cirt_10, cirt_11, cirt_12, cirt_13, cirt_14, cirt_15, cirt_16,
];
