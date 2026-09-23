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
  { key: 'contact', label: 'Who you spoke to', help: 'Who you contacted and how — and, for any account change, how you verified them (two factors).', placeholder: 'Jenna Morales (Accounts Payable), by phone. Verified: employee ID E10105 + callback to the number on record.', rows: 2 },
  { key: 'reported', label: 'What was discussed / reported', help: "The problem in the caller's own words, plus the key details you got by asking.", placeholder: 'Locked out right before payroll. The failed logins came from her own laptop and iPhone — not a strange IP.', rows: 2 },
  { key: 'found', label: 'What you found', help: 'Your diagnosis — the real cause, not just the symptom.', placeholder: 'Old password still saved in her iPhone mail app kept re-locking the account.', rows: 2 },
  { key: 'actions', label: 'What actions you took', help: 'The steps you actually performed to fix it or move it forward.', placeholder: 'Unlocked the account; reset the password (must change at next logon); had her update the saved password on her phone.', rows: 2 },
  { key: 'outcome', label: 'Outcome / next steps', help: 'Resolved and confirmed, or who it was escalated to and what they need.', placeholder: 'Resolved; confirmed she could log back in. No further action.', rows: 2 },
];

const SOC: DocField[] = [
  { key: 'summary', label: 'Summary & verdict', help: 'One line: what the alert was and your classification.', placeholder: 'IDS scan alert from 10.10.10.70 — an authorized weekly Nessus scan. Benign true positive.', rows: 2 },
  { key: 'evidence', label: 'What you checked (and who you contacted)', help: 'The artifacts you reviewed — SIEM queries, process tree, headers, sign-ins, intel — and anyone you confirmed with.', placeholder: 'Splunk auth+proxy for the host; Falcon process tree; VirusTotal on the IP/hash; confirmed the scan with the security team (change CHG-2291).', rows: 3 },
  { key: 'findings', label: 'What you found (indicators)', help: 'Your conclusion, with the IOCs — IPs, domains, hashes, users, hosts.', placeholder: 'WINWORD → powershell -enc → update-svc.exe (AppData) beaconing to 45.146.164.90 (Cobalt Strike C2). Single host, no lateral movement.', rows: 3 },
  { key: 'actions', label: 'What actions you took (containment)', help: 'What you did to contain — isolate, reset, block, purge — or why none was needed.', placeholder: 'Collected triage, network-contained the host, reset the user, blocked the C2 at the perimeter.', rows: 2 },
  { key: 'rationale', label: 'Why (classification rationale)', help: 'Why true / false / benign positive, and the severity you set.', placeholder: 'True positive, high — confirmed C2 execution; not benign (no change ticket, unsigned dropper).', rows: 2 },
  { key: 'next', label: 'Next steps / handoff', help: 'Who you escalated to and what they need, or the tuning you requested.', placeholder: 'Escalated to CIRT with the triage package and IOCs; ticketed Desktop to reimage after release.', rows: 2 },
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
