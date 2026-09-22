// Link-based assignments (no backend). A teacher encodes an assignment into a
// URL (#assign=<code>); a student works it and encodes a completion receipt
// they send back; the teacher's gradebook decodes pasted receipts. All state
// lives in the URL/clipboard and the browser — nothing is stored server-side.
// Receipts are self-reported (practice-grade), not a verified credential.

export interface Assignment {
  v: 1;
  title: string;
  from: string;        // instructor name
  note?: string;       // instructions / due date
  pass: number;        // passing score (0-100)
  items: string[];     // ordered scenario ids
  pathId?: string;     // optional source learning path (recommended reading)
  created: string;     // ISO date
}

export interface Receipt {
  v: 1;
  a: string;           // assignment title
  by: string;          // student name
  at: string;          // ISO date
  pass: number;
  results: { id: string; score: number; passed: boolean; attempts: number }[];
}

function b64urlEncode(obj: unknown): string {
  const json = JSON.stringify(obj);
  const b64 = btoa(unescape(encodeURIComponent(json)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode<T>(code: string): T | null {
  try {
    const b64 = code.trim().replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(escape(atob(b64)));
    return JSON.parse(json) as T;
  } catch { return null; }
}

export const encodeAssignment = (a: Assignment): string => b64urlEncode(a);
export function decodeAssignment(code: string): Assignment | null {
  const a = b64urlDecode<Assignment>(code);
  return a && a.v === 1 && Array.isArray(a.items) && a.items.length > 0 ? a : null;
}

export const encodeReceipt = (r: Receipt): string => b64urlEncode(r);
export function decodeReceipt(code: string): Receipt | null {
  const r = b64urlDecode<Receipt>(code);
  return r && r.v === 1 && Array.isArray(r.results) ? r : null;
}

export function assignmentLink(a: Assignment): string {
  const base = typeof location !== 'undefined' ? location.origin + location.pathname : '';
  return `${base}#assign=${encodeAssignment(a)}`;
}
