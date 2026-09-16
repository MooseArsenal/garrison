import type { Proc } from '../engine/types';

// Locations where a *running executable* is a genuine red flag. Note this
// deliberately excludes AppData\Local\... — OneDrive, Teams, Chrome and other
// legitimate per-user apps install and run from there, so flagging it produces
// constant false positives. Roaming, Temp and Public are the ones that matter.
export const USER_WRITABLE_EXEC = /\\(AppData\\Roaming|Temp|Public)\\/i;

// Living-off-the-land binaries and Office apps: not suspicious by themselves,
// but the parents/children worth surfacing so an initial-access chain is visible.
export const LOLBIN_OR_OFFICE = /winword|excel|powerpnt|outlook|powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin/i;

/** True when a process should be highlighted as suspicious. */
export function suspiciousProc(p: Proc): boolean {
  return p.signed === false || (!!p.path && USER_WRITABLE_EXEC.test(p.path));
}

/** True when a process is worth showing as a tree root (suspicious, or a
 *  LOLBin/Office process that may anchor a chain). */
export function interestingProc(p: Proc): boolean {
  return suspiciousProc(p) || LOLBIN_OR_OFFICE.test(p.name);
}
