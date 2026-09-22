import type { Tier } from '../engine/types';

export interface DocField {
  key: string;
  label: string;
  help: string;        // what goes here (teaches a beginner)
  placeholder: string; // a concrete example
  rows?: number;
}

// The work-notes template a real analyst fills in, by role. The fields are
// concatenated (label: value) into the graded work notes, so the same content
// scores the same — but a newcomer is shown *what* to document and why.
const SERVICE_DESK: DocField[] = [
  { key: 'summary', label: 'Summary', help: 'One line: what the user reported and how it ended.', placeholder: 'AP user locked out before payroll; verified, unlocked and reset — root cause was a saved password on her phone.' },
  { key: 'verification', label: 'Identity verification', help: 'For ANY account change, how you confirmed who you were dealing with — two factors.', placeholder: 'Employee ID E10105 + callback to the number on record.' },
  { key: 'cause', label: 'Cause / diagnosis', help: 'The real root cause you found, not just the symptom.', placeholder: 'Old password cached in the iPhone mail app kept locking the account.' },
  { key: 'action', label: 'Action taken', help: 'What you actually did to fix it or move it forward.', placeholder: 'Unlocked account; reset password with must-change; had her update the saved password on her phone.' },
  { key: 'outcome', label: 'Outcome / next steps', help: 'Resolved, or who it went to and what they need.', placeholder: 'Resolved and confirmed she could log in. No further action.', rows: 2 },
];

const SOC: DocField[] = [
  { key: 'summary', label: 'Summary', help: 'One line: what the alert was and your verdict.', placeholder: 'IDS scan alert from 10.10.10.70 — authorized weekly Nessus scan, benign true positive.' },
  { key: 'evidence', label: 'Evidence reviewed', help: 'The artifacts you actually checked — SIEM queries, process tree, mail headers, sign-ins, intel lookups.', placeholder: 'Splunk auth+proxy for the host; Falcon process tree; VirusTotal on the IP and hash; user sign-in log.' },
  { key: 'findings', label: 'Findings / indicators', help: 'What you concluded, with the IOCs — IPs, domains, hashes, users, hosts.', placeholder: 'WINWORD → powershell -enc → update-svc.exe (AppData) beaconing to 45.146.164.90 (Cobalt Strike C2). Single host, no lateral movement.' },
  { key: 'actions', label: 'Actions / containment', help: 'What you did to contain — isolate, reset, block, purge — or why none was needed.', placeholder: 'Collected triage, network-contained the host, reset the user, blocked the C2 at the perimeter.' },
  { key: 'rationale', label: 'Classification rationale', help: 'Why true / false / benign positive, and the severity you set.', placeholder: 'True positive, high — confirmed C2 execution. Not benign: no change ticket, unsigned dropper.' },
  { key: 'next', label: 'Next steps / handoff', help: 'Who you escalated to and what they need, or the tuning you requested.', placeholder: 'Escalated to CIRT with the triage package and IOCs; ticket to Desktop to reimage after release.', rows: 2 },
];

export function docTemplate(tier: Tier): DocField[] {
  return tier === 'soc1' || tier === 'soc2' || tier === 'cirt' ? SOC : SERVICE_DESK;
}

// The incident report a CIRT lead compiles — the structure of a real IR writeup.
export const REPORT_FIELDS: DocField[] = [
  { key: 'timeline', label: 'Timeline', help: 'Key events with times: initial access → what happened → detection → your actions.', placeholder: '~03:14 rogue admin created; 04:00 mass encryption on FS01; 09:20 detected; 09:35 contained.', rows: 3 },
  { key: 'rootcause', label: 'Root cause', help: 'How they got in and the weakness that let it happen.', placeholder: 'Phished credentials on a contractor laptop → over-privileged svc_backup (no MFA) used to reach the file server.' },
  { key: 'containment', label: 'Containment & recovery', help: 'How you contained it and how you recovered — the clean restore point, credentials rotated.', placeholder: 'Isolated FS01 + patient zero; restored shares from the 9h-old pre-encryption backup; rotated all privileged creds + KRBTGT ×2.', rows: 2 },
  { key: 'followup', label: 'Follow-up actions (with owners)', help: 'Remediation and lessons learned — each with a named owner.', placeholder: 'Enforce MFA on service accounts (Identity); tiered-admin model (Sysadmin); phishing refresher (Security).', rows: 2 },
];

/** Combine filled fields into the graded free-text string. */
export function combineDoc(fields: DocField[], values: Record<string, string>): string {
  return fields
    .filter((f) => (values[f.key] ?? '').trim())
    .map((f) => `${f.label}: ${values[f.key].trim()}`)
    .join('\n');
}
