import React, { useState } from 'react';
import { useSession, usePersisted } from '../../engine/session';
import { Verdict } from '../common';

export function Intel() {
  const { world, act } = useSession();
  const [q, setQ] = useState('');
  const [looked, setLooked] = usePersisted<string[]>('intel.looked', []);

  function lookup(indicator: string) {
    const ind = indicator.trim();
    if (!ind) return;
    act({ tool: 'intel', action: 'lookup', target: ind, label: `Threat-intel lookup: ${ind}` });
    setLooked(looked.includes(ind) ? looked : [ind, ...looked]);
  }

  const rec = (ind: string) => world.intel.find((r) => r.indicator.toLowerCase() === ind.toLowerCase() || (r.indicator.includes('/') && ind.startsWith(r.indicator.split('/')[0].split('.').slice(0, 3).join('.'))));

  // VirusTotal-style detection ratio, derived deterministically from the verdict.
  function ratio(indicator: string, verdict: string): { flagged: number; engines: number } {
    const engines = 72;
    let base = verdict === 'malicious' ? 48 : verdict === 'suspicious' ? 12 : 0;
    if (base > 0) { let h = 0; for (const c of indicator) h = (h * 31 + c.charCodeAt(0)) & 0xffff; base += (h % 11) - 5; }
    return { flagged: Math.max(0, Math.min(engines, base)), engines };
  }

  return (
    <div>
      <div className="searchbar">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search an IP, domain, URL, or file hash…" onKeyDown={(e) => { if (e.key === 'Enter') { lookup(q); } }} autoFocus />
        <button className="btn" onClick={() => lookup(q)}>Look up</button>
      </div>
      {looked.length === 0 && <div className="empty">Look up any indicator you find (source IPs, domains, hashes, URLs). The detection ratio and community notes drive your verdict.</div>}
      {looked.map((ind) => {
        const r = rec(ind);
        const v = r?.verdict ?? 'unknown';
        const { flagged, engines } = ratio(ind, v);
        return (
          <div key={ind} className="card">
            <div className="between">
              <span className="mono">{ind}</span>
              <span className={`vt-ratio ${flagged > 0 ? 'mal' : 'clean'}`}>{flagged} / {engines} security vendors flagged this</span>
            </div>
            <div className="flex wrap mt"><Verdict v={v} />{r && <><span className="tag">{r.type}</span><span className="tag">first seen: {r.firstSeen ?? 'n/a'}</span></>}</div>
            {r ? (
              <>
                <div className="small dim mt">{r.detail}</div>
                <div className="flex wrap mt"><span className="tag">reported by: {r.source}</span>{r.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>
              </>
            ) : <div className="small dim mt">No community reputation. 0 detections is not proof of safety — correlate with behavior in Splunk/Falcon.</div>}
          </div>
        );
      })}
    </div>
  );
}
