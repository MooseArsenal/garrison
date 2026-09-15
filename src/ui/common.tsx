import React, { createContext, useCallback, useContext, useState } from 'react';

// ---------------- Toasts ----------------
type ToastKind = 'good' | 'bad' | 'info';
interface Toast { id: number; text: string; kind: ToastKind; }
const ToastCtx = createContext<(text: string, kind?: ToastKind) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, kind: ToastKind = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3200);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts">
        {toasts.map((t) => <div key={t.id} className={`toast ${t.kind}`}>{t.text}</div>)}
      </div>
    </ToastCtx.Provider>
  );
}

// ---------------- Modal ----------------
export function Modal({ title, children, onClose, footer, wide }: { title: React.ReactNode; children: React.ReactNode; onClose: () => void; footer?: React.ReactNode; wide?: boolean }) {
  return (
    <div className="modal-back" onClick={onClose}>
      <div className="modal" style={wide ? { maxWidth: 820 } : undefined} onClick={(e) => e.stopPropagation()}>
        <div className="mh between"><h3>{title}</h3><button className="btn ghost sm" onClick={onClose}>✕</button></div>
        <div className="mb">{children}</div>
        {footer && <div className="mf">{footer}</div>}
      </div>
    </div>
  );
}

// ---------------- Small bits ----------------
export function Chip({ children }: { children: React.ReactNode }) { return <span className="chip">{children}</span>; }
export function Pri({ p }: { p: string }) { return <span className={`pri ${p}`}>{p}</span>; }
export function Sev({ s }: { s: string }) { return <span className={`sev ${s}`}>{s}</span>; }
export function Verdict({ v }: { v: string }) { return <span className={`verdict ${v}`}>{v}</span>; }
export function Diff({ n }: { n: number }) {
  return <span className="diff">{[1, 2, 3, 4, 5].map((i) => <i key={i} className={i <= n ? 'on' : ''} />)}</span>;
}

export function SearchBar({ value, onChange, placeholder, onEnter }: { value: string; onChange: (v: string) => void; placeholder?: string; onEnter?: () => void }) {
  return (
    <div className="searchbar">
      <input value={value} placeholder={placeholder ?? 'Search…'} onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter') onEnter?.(); }} autoFocus />
    </div>
  );
}

export function Tabs<T extends string>({ tabs, active, onChange }: { tabs: { id: T; label: string }[]; active: T; onChange: (t: T) => void }) {
  return (
    <div className="tabs">
      {tabs.map((t) => (
        <button key={t.id} className={active === t.id ? 'active' : ''} onClick={() => onChange(t.id)}>{t.label}</button>
      ))}
    </div>
  );
}

export function scoreColor(n: number): string {
  if (n >= 85) return 'var(--green)';
  if (n >= 70) return 'var(--accent)';
  if (n >= 50) return 'var(--amber)';
  return 'var(--red)';
}
