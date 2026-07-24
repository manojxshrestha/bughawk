import { memo, useMemo, useState } from 'react';
import { decodeJwt, extractJwts } from '../../lib/jwt.js';

const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const JwtDecoderTab = memo(function JwtDecoderTab() {
  const [input, setInput] = useState('');
  const [mode, setMode] = useState('single'); // 'single' | 'batch'

  const result = useMemo(() => {
    if (!input.trim()) return { type: 'empty' };
    if (mode === 'batch') {
      const tokens = extractJwts(input);
      return { type: 'batch', tokens };
    }
    const r = decodeJwt(input.trim());
    if (!r) return { type: 'error', text: 'Not a valid JWT (needs at least header.payload)' };
    return { type: 'single', ...r };
  }, [input, mode]);

  return (
    <div className="jwt-wrap">
      <style>{styles}</style>
      <header className="jwt-head">
        <div>
          <h1> JWT Decoder</h1>
          <p>Paste a JWT to decode header &amp; payload, or switch to batch to scan text for tokens</p>
        </div>
        <div className="jwt-mode">
          <button className={`jwt-mode-btn${mode === 'single' ? ' on' : ''}`} onClick={() => setMode('single')}>Single</button>
          <button className={`jwt-mode-btn${mode === 'batch' ? ' on' : ''}`} onClick={() => setMode('batch')}>Batch</button>
        </div>
      </header>

      <textarea
        className="jwt-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        spellCheck="false"
        wrap="off"
        placeholder={mode === 'single' ? 'Paste a JWT token here...' : 'Paste JS/text here — all JWTs will be extracted and analyzed...'}
      />

      <div className="jwt-results">
        {result.type === 'empty' && (
          <div className="jwt-empty">Enter a JWT token above to decode it.</div>
        )}
        {result.type === 'error' && (
          <div className="jwt-error">{result.text}</div>
        )}
        {result.type === 'batch' && (
          <BatchResults tokens={result.tokens} />
        )}
        {result.type === 'single' && (
          <SingleResult data={result} />
        )}
      </div>
    </div>
  );
});

function SingleResult({ data }) {
  const { header, payload, signature, issues, recommendations, raw } = data;
  return (
    <>
      <div className="jwt-summary">
        <div className="jwt-summary-row">
          <span>Algorithm</span><code className="mono">{data.alg || '—'}</code>
        </div>
        <div className="jwt-summary-row">
          <span>Type</span><code className="mono">{data.typ || '—'}</code>
        </div>
        {data.iss && <div className="jwt-summary-row"><span>Issuer</span><code className="mono">{data.iss}</code></div>}
        {data.sub && <div className="jwt-summary-row"><span>Subject</span><code className="mono">{data.sub}</code></div>}
        {data.aud && <div className="jwt-summary-row"><span>Audience</span><code className="mono">{Array.isArray(data.aud) ? data.aud.join(', ') : data.aud}</code></div>}
        {data.exp && <div className="jwt-summary-row"><span>Expires</span><code className="mono">{new Date(data.exp * 1000).toISOString()} {data.expired ? '(expired)' : ''}</code></div>}
        {data.nbf && <div className="jwt-summary-row"><span>Not Before</span><code className="mono">{new Date(data.nbf * 1000).toISOString()}</code></div>}
        <div className="jwt-summary-row">
          <span>Signature</span><code className="mono">{signature ? `${signature.slice(0, 24)}...` : '— (unsafe: no signature part)'}</code>
        </div>
        <div className="jwt-summary-row">
          <span>Parts</span><code className="mono">{raw.header.length}.{raw.payload.length}{raw.signature ? `.${raw.signature.length}` : ''}</code>
        </div>
      </div>

      {issues.length > 0 && (
        <div className="jwt-section">
          <h3>Security Issues ({issues.length})</h3>
          {issues.map((iss, i) => (
            <div key={i} className={`jwt-issue sev-${iss.severity}`}>
              <span className={`jwt-issue-sev sev-pill sev-${iss.severity}`}>{iss.severity}</span>
              <span>{iss.text}</span>
            </div>
          ))}
        </div>
      )}

      {recommendations.length > 0 && (
        <div className="jwt-section">
          <h3>Recommendations</h3>
          {recommendations.map((r, i) => (
            <div key={i} className="jwt-rec">{r}</div>
          ))}
        </div>
      )}

      <div className="jwt-section">
        <h3>Header</h3>
        <pre className="jwt-json">{JSON.stringify(header, null, 2)}</pre>
      </div>
      <div className="jwt-section">
        <h3>Payload</h3>
        <pre className="jwt-json">{JSON.stringify(payload, null, 2)}</pre>
      </div>
    </>
  );
}

function BatchResults({ tokens }) {
  const bySeverity = (sev) => tokens.filter((t) => t.issues.some((i) => i.severity === sev));
  const critical = bySeverity('critical');
  const high = bySeverity('high');
  const s = (set) => set.length > 0 ? `${set.length} ` : '';
  return (
    <>
      <div className="jwt-section">
        <h3>Found {tokens.length} JWT token{tokens.length !== 1 ? 's' : ''}</h3>
        {tokens.length > 0 && (
          <div className="jwt-summary" style={{ marginTop: 8 }}>
            {critical.length > 0 && <span className="sev-pill sev-critical">{s(critical)}critical</span>}
            {high.length > 0 && <span className="sev-pill sev-high">{s(high)}high</span>}
          </div>
        )}
      </div>
      {tokens.map((t, i) => {
        const highest = t.issues.reduce((m, iss) => Math.max(m, SEV_ORDER[iss.severity] || 0), 0);
        return (
          <details key={i} className="jwt-batch-item" open={t.issues.some((iss) => iss.severity === 'critical' || iss.severity === 'high')}>
            <summary className="jwt-batch-summary">
              <span className={`sev-dot sev-${Object.keys(SEV_ORDER).find((k) => SEV_ORDER[k] === highest) || 'info'}`} />
              <code className="mono">{t.alg}</code>
              <span className="jwt-batch-sub">{t.sub ? `sub: ${t.sub}` : ''}</span>
              <code className="jwt-batch-token">{t.token.slice(0, 48)}...</code>
            </summary>
            <div className="jwt-batch-body">
              {t.issues.filter((iss) => iss.severity !== 'info').map((iss, j) => (
                <div key={j} className={`jwt-issue sev-${iss.severity}`}>
                  <span className={`jwt-issue-sev sev-pill sev-${iss.severity}`}>{iss.severity}</span>
                  <span>{iss.text}</span>
                </div>
              ))}
              <pre className="jwt-json" style={{ marginTop: 8 }}>{JSON.stringify(t.payload, null, 2)}</pre>
            </div>
          </details>
        );
      })}
    </>
  );
}

const styles = `
.jwt-wrap { padding: var(--sp-5); max-width: 900px; font-family: var(--font-body); color: var(--text-primary); }
.jwt-head { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--sp-4); margin-bottom: var(--sp-4); flex-wrap: wrap; }
.jwt-head h1 { margin: 0; font-family: var(--font-display); font-size: 22px; }
.jwt-head p { margin: 2px 0 0; font-size: 13px; color: var(--text2); }
.jwt-mode { display: flex; gap: 4px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 3px; }
.jwt-mode-btn { background: none; border: none; color: var(--text2); padding: 6px 14px; border-radius: var(--radius-sm); font-size: 12px; cursor: pointer; font-weight: 600; }
.jwt-mode-btn.on { background: var(--accent-primary-dim); color: var(--accent-primary-bright); }
.jwt-input { width: 100%; box-sizing: border-box; min-height: 100px; padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--border); background: var(--bg-base); color: var(--text-primary); font-family: var(--font-data); font-size: 13px; outline: none; resize: vertical; white-space: pre; overflow-wrap: break-word; margin-bottom: var(--sp-4); }
.jwt-input:focus { border-color: var(--border-active); }
.jwt-results { display: flex; flex-direction: column; gap: var(--sp-4); }
.jwt-empty, .jwt-error { padding: 24px; text-align: center; color: var(--text2); font-size: 14px; background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius); }
.jwt-error { color: var(--sev-high); }
.jwt-summary { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius); padding: var(--sp-4); display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 8px; }
.jwt-summary-row { display: flex; flex-direction: column; gap: 2px; }
.jwt-summary-row > span { font-size: 11px; text-transform: uppercase; letter-spacing: 0.3px; color: var(--text3); }
.jwt-summary-row > code { font-size: 13px; word-break: break-all; }
.jwt-section { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius); padding: var(--sp-4); }
.jwt-section h3 { margin: 0 0 10px; font-size: 14px; }
.jwt-json { margin: 0; padding: 12px; background: var(--bg-base); border: 1px solid var(--border); border-radius: var(--radius-sm); font-family: var(--font-data); font-size: 12px; color: var(--text-primary); white-space: pre-wrap; word-break: break-all; overflow: auto; max-height: 400px; }
.jwt-issue { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-top: 1px solid var(--border); font-size: 13px; }
.jwt-issue:first-child { border-top: none; }
.jwt-issue-sev { flex-shrink: 0; }
.jwt-rec { padding: 6px 0; font-size: 13px; color: var(--accent-primary-bright); }
.jwt-rec::before { content: '→ '; }
.jwt-batch-item { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
.jwt-batch-summary { display: flex; align-items: center; gap: 10px; padding: 10px var(--sp-4); cursor: pointer; font-size: 13px; }
.jwt-batch-summary::-webkit-details-marker { display: none; }
.jwt-batch-sub { color: var(--text2); font-size: 12px; flex: 1; }
.jwt-batch-token { color: var(--text3); font-size: 11px; font-family: var(--font-data); }
.jwt-batch-body { padding: 0 var(--sp-4) var(--sp-4); }
.sev-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.sev-dot.sev-critical { background: var(--sev-critical); }
.sev-dot.sev-high { background: var(--sev-high); }
.sev-dot.sev-medium { background: var(--sev-medium); }
.sev-dot.sev-low { background: var(--sev-low); }
.sev-dot.sev-info { background: var(--sev-info); }
.sev-pill { font-size: 10px; font-weight: 800; padding: 2px 7px; border-radius: 999px; text-transform: uppercase; border: 1px solid; line-height: 1.4; display: inline-block; }
.sev-pill.sev-critical { color: var(--sev-critical); border-color: var(--sev-critical); }
.sev-pill.sev-high { color: var(--sev-high); border-color: var(--sev-high); }
.sev-pill.sev-medium { color: var(--sev-medium); border-color: var(--sev-medium); }
.sev-pill.sev-low { color: var(--sev-low); border-color: var(--sev-low); }
.sev-pill.sev-info { color: var(--sev-info); border-color: var(--sev-info); }
`;

export default JwtDecoderTab;
