import React from 'react';
import { useSession, usePersisted } from '../../engine/session';
import { fmt } from '../../engine/world';
import { runSpl, SPL_EXAMPLES, type SplResult } from '../../engine/spl';

// Splunk-style search: an SPL query bar, a results table for events, and a
// stats/table view when the pipeline aggregates. Emits the same siem/search
// and siem/pivot actions the grader expects.
export function Siem() {
  const { world, act } = useSession();
  const [q, setQ] = usePersisted('spl.q', '');
  const [ran, setRan] = usePersisted('spl.ran', '');

  const result: SplResult | null = ran ? runSpl(world.logs, ran) : null;

  function run(query: string) {
    const query2 = query.trim();
    setRan(query2);
    if (query2) act({ tool: 'siem', action: 'search', params: { q: query2 }, label: `Splunk search: ${query2}` });
  }

  const badRe = /c2|beacon|malicious|dcsync|lsass|encrypt|ransom|tor|creddump|reject|lock\.exe|update-svc|203\.0\.113\.55|45\.146|185\.220/i;

  return (
    <div>
      <div className="spl-bar">
        <span className="spl-prompt">index=*</span>
        <input className="spl-input" value={q} placeholder='SPL: e.g.  index=auth user=sturner | stats count by src_ip'
          onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') run(q); }} autoFocus />
        <button className="btn primary sm" onClick={() => run(q)}>Search</button>
      </div>
      <div className="spl-examples">
        <span className="tiny dim">Try:</span>
        {SPL_EXAMPLES.map((ex) => <button key={ex} className="spl-ex" onClick={() => { setQ(ex); run(ex); }}>{ex}</button>)}
      </div>

      {!result && <div className="empty">Enter an SPL query. Fields: index, sourcetype, host, user, src_ip, dest_ip, dest_port, domain, url, action, process, message. Commands: search, where, stats, table, fields, sort, head, dedup, top, rename.</div>}
      {result?.error && <div className="card" style={{ borderColor: '#5a2b34', color: 'var(--red)' }}>{result.error}</div>}

      {result && !result.error && (
        <div>
          <div className="small dim mb">{result.kind === 'events' ? `${result.rows.length} events` : `${result.eventCount} matching events → ${result.rows.length} rows`}</div>
          {result.kind === 'table' ? (
            <table className="data">
              <thead><tr>{result.columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
              <tbody>
                {result.rows.map((r, i) => (
                  <tr key={i}>{result.columns.map((c) => (
                    <td key={c} className="mono tiny">{c === '_time' ? fmt(String(r[c])) : <Pivot text={String(r[c] ?? '')} onPivot={(v) => { const nq = `${v}`; setQ(nq); }} />}</td>
                  ))}</tr>
                ))}
              </tbody>
            </table>
          ) : (
            <table className="data">
              <thead><tr><th>_time</th><th>index</th><th>host</th><th>user</th><th>src_ip</th><th>dest</th><th>_raw</th></tr></thead>
              <tbody>
                {result.rows.slice(0, 200).map((r, i) => (
                  <tr key={i} className={badRe.test(String(r._raw)) ? 'bad' : ''}>
                    <td className="mono nowrap tiny">{fmt(String(r._time))}</td>
                    <td><Pivot text={String(r.index ?? '')} onPivot={(v) => setQ(`index=${v}`)} /></td>
                    <td className="mono tiny">{r.host ? <Pivot text={String(r.host)} onPivot={(v) => setQ(`host=${v}`)} /> : '—'}</td>
                    <td className="tiny">{r.user ? <Pivot text={String(r.user)} onPivot={(v) => setQ(`user=${v}`)} /> : '—'}</td>
                    <td className="mono tiny">{r.src_ip ? <Pivot text={String(r.src_ip)} onPivot={(v) => setQ(`src_ip=${v}`)} /> : '—'}</td>
                    <td className="mono tiny">{r.dest_ip ?? r.domain ?? (r.dest_port ? ':' + r.dest_port : '—')}</td>
                    <td className="tiny">{String(r._raw ?? '')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );

  function Pivot({ text, onPivot }: { text: string; onPivot: (v: string) => void }) {
    if (!text) return <span>—</span>;
    return <button className="spl-pivot" title="pivot" onClick={() => { onPivot(text); act({ tool: 'siem', action: 'pivot', params: { value: text }, label: `Pivoted on ${text}` }); }}>{text}</button>;
  }
}
