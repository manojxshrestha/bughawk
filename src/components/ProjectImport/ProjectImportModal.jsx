import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import JSZip from 'jszip';
import { classifyFile, classifyByContent, parseContent } from '../../lib/project-import.js';
import { get, set, KEYS } from '../../lib/storage.js';

const TAB_LABELS = {
  subdomains: 'Subdomains',
  urlparser: 'URL Parser',
  findings: 'Findings',
  ports: 'Port Scan',
  jsrecon: 'JS Recon',
};

export default function ProjectImportModal({ activeProjectId, onNavigate, onClose, onToast }) {
  const [zipFile, setZipFile] = useState(null);
  const [extracting, setExtracting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [files, setFiles] = useState([]);
  const [checked, setChecked] = useState({});
  const inputRef = useRef(null);

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // When a zip is selected, extract and classify.
  const onFilePick = useCallback(async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setZipFile(file);
    setExtracting(true);
    try {
      const data = await file.arrayBuffer();
      const zip = await JSZip.loadAsync(data);
      const results = [];
      const filePromises = [];
      zip.forEach((relativePath, entry) => {
        if (entry.dir) return;
        filePromises.push((async () => {
          const name = relativePath.split('/').pop();
          const text = await entry.async('string');
          let matched = classifyFile(name);
          if (!matched && text.length > 0) {
            matched = classifyByContent(text);
          }
          if (!matched) return;
          const parsed = parseContent(text, matched.parser);
          results.push({
            name,
            path: relativePath,
            matched,
            text,
            parsed,
            lineCount: text.split('\n').filter(Boolean).length,
            itemCount: parsed?.findings?.length || parsed?.entries?.length || parsed?.urls?.length || parsed?.content?.length || 0,
          });
        })());
      });
      await Promise.all(filePromises);
      results.sort((a, b) => a.name.localeCompare(b.name));
      setFiles(results);
      setChecked(Object.fromEntries(results.map((r) => [r.name, true])));
    } catch (err) {
      onToast(`Failed to extract zip: ${err.message}`);
    } finally {
      setExtracting(false);
    }
  }, [onToast]);

  const toggleFile = (name) => setChecked((c) => ({ ...c, [name]: !c[name] }));

  const grouped = useMemo(() => {
    const map = {};
    for (const f of files) {
      if (!checked[f.name]) continue;
      const tab = f.matched.tab;
      if (!map[tab]) map[tab] = [];
      map[tab].push(f);
    }
    return map;
  }, [files, checked]);

  const importAll = useCallback(async () => {
    if (!activeProjectId) { onToast('No active project'); return; }
    setImporting(true);
    const summary = [];
    try {
      for (const [tab, tabFiles] of Object.entries(grouped)) {
        if (tab === 'subdomains') {
          const hosts = [];
          for (const f of tabFiles) {
            if (f.parsed) hosts.push(...f.parsed);
          }
          const unique = [...new Set(hosts.filter(Boolean))].map((h) => ({
            host: h.toLowerCase(),
            status: 'unknown',
            tech: [],
          }));
          if (unique.length > 0) {
            await set(KEYS.subdomains(activeProjectId), unique);
            summary.push(`${unique.length} subdomains`);
          }
        } else if (tab === 'urlparser') {
          const urls = [];
          for (const f of tabFiles) {
            if (f.parsed?.urls) urls.push(...f.parsed.urls);
          }
          const unique = [...new Set(urls.filter(Boolean))];
          if (unique.length > 0) {
            const sessions = await get(KEYS.urlSessions(activeProjectId), []);
            const now = new Date().toLocaleString();
            sessions.push({
              id: `import-${Date.now()}`,
              name: `Imported — ${tabFiles.map((f) => f.name).join(', ') || now}`,
              date: now,
              source: 'import',
              rawInput: unique.join('\n'),
            });
            await set(KEYS.urlSessions(activeProjectId), sessions);
            summary.push(`${unique.length} URLs`);
          }
        } else if (tab === 'ports') {
          const entries = [];
          for (const f of tabFiles) {
            if (f.parsed?.entries) entries.push(...f.parsed.entries);
          }
          if (entries.length > 0) {
            await set(KEYS.ports(activeProjectId), entries);
            summary.push(`${entries.length} hosts (ports)`);
          }
        } else if (tab === 'findings') {
          const findings = [];
          for (const f of tabFiles) {
            if (f.parsed?.findings) findings.push(...f.parsed.findings);
          }
          if (findings.length > 0) {
            const existing = await get(KEYS.nucleiFindings(activeProjectId), []);
            await set(KEYS.nucleiFindings(activeProjectId), [...existing, ...findings]);
            summary.push(`${findings.length} findings`);
          }
        } else if (tab === 'jsrecon') {
          const sources = [];
          for (const f of tabFiles) {
            if (f.parsed?.content) sources.push({ name: f.name, content: f.parsed.content });
          }
          if (sources.length > 0) {
            const existing = await get(KEYS.jsRecon(activeProjectId), []);
            await set(KEYS.jsRecon(activeProjectId), [...existing, ...sources]);
            summary.push(`${sources.length} JS files`);
          }
        }
      }
      const msg = summary.length > 0 ? `Imported: ${summary.join(', ')}` : 'No files matched';
      onToast(msg);
      onClose();
      if (Object.keys(grouped).length > 0) {
        onNavigate(Object.keys(grouped)[0]);
      }
    } catch (err) {
      onToast(`Import failed: ${err.message}`);
    } finally {
      setImporting(false);
    }
  }, [activeProjectId, grouped, onNavigate, onClose, onToast]);

  const hasChecked = Object.values(checked).some(Boolean);

  return (
    <div className="modal-overlay" onMouseDown={(e) => { if (e.target === e.currentTarget && !importing) onClose(); }}>
      <div className="modal modal-lg" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">Import Project</span>
          <button className="modal-close" onClick={onClose} disabled={importing}>x</button>
        </div>

        {!zipFile ? (
          <div className="modal-body">
            <div className="import-zone" onClick={() => inputRef.current?.click()}>
              <div className="import-zone-icon">+</div>
              <div className="import-zone-text">Select a .zip file containing your recon outputs</div>
              <div className="import-zone-hint">subdomains.txt, urls.txt, nuclei JSONL, nmap XML/GNMAP, JS files, scope, …</div>
              <input ref={inputRef} type="file" accept=".zip" onChange={onFilePick} hidden />
            </div>
          </div>
        ) : extracting ? (
          <div className="modal-body"><div className="import-loading">Extracting and classifying files…</div></div>
        ) : files.length === 0 ? (
          <div className="modal-body">
            <div className="import-empty">No recognizable files found in the zip.</div>
            <div className="modal-footer">
              <button className="btn btn-ghost" onClick={() => { setZipFile(null); setFiles([]); }}>Try another</button>
            </div>
          </div>
        ) : (
          <>
            <div className="modal-body">
              <div className="import-summary">{files.length} file(s) detected</div>
              <div className="import-table-wrap">
                {Object.entries(grouped).map(([tab, tabFiles]) => (
                  <div key={tab} className="import-group">
                    <div className="import-group-head">{TAB_LABELS[tab] || tab}</div>
                    {tabFiles.map((f) => (
                      <label key={f.name} className="import-row">
                        <input type="checkbox" checked={!!checked[f.name]} onChange={() => toggleFile(f.name)} disabled={importing} />
                        <span className="import-fname">{f.name}</span>
                        <span className="import-count">{f.itemCount.toLocaleString()}</span>
                        <span className="import-label">{f.matched.label}</span>
                      </label>
                    ))}
                  </div>
                ))}
                {/* Unchecked files */}
                {files.filter((f) => !checked[f.name]).length > 0 && (
                  <details className="import-ignored">
                    <summary className="import-ignored-sum">Ignored ({files.filter((f) => !checked[f.name]).length})</summary>
                    {files.filter((f) => !checked[f.name]).map((f) => (
                      <label key={f.name} className="import-row muted">
                        <input type="checkbox" checked={false} onChange={() => toggleFile(f.name)} disabled={importing} />
                        <span className="import-fname">{f.name}</span>
                        <span className="import-count">{f.itemCount.toLocaleString()}</span>
                        <span className="import-label">{f.matched.label}</span>
                      </label>
                    ))}
                  </details>
                )}
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-ghost" onClick={() => { setZipFile(null); setFiles([]); }} disabled={importing}>Back</button>
              <button className="btn btn-primary" onClick={importAll} disabled={importing || !hasChecked}>
                {importing ? 'Importing…' : `Import (${Object.values(grouped).flat().length} files)`}
              </button>
            </div>
          </>
        )}
      </div>

      <style>{`
.import-zone {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 24px;
  border: 2px dashed var(--border);
  border-radius: var(--radius-lg);
  cursor: pointer;
  transition: border-color .15s, background .15s;
}
.import-zone:hover { border-color: var(--accent-primary-bright); background: var(--surface-hover); }
.import-zone-icon { font-size: 32px; width: 64px; height: 64px; display: flex; align-items: center; justify-content: center; border-radius: 50%; background: var(--accent-primary-bright); color: #fff; margin-bottom: 12px; font-weight: 700; }
.import-zone-text { font-weight: 600; font-size: 15px; color: var(--text-primary); }
.import-zone-hint { font-size: 12px; color: var(--text2); margin-top: 4px; }
.import-loading { padding: 40px; text-align: center; color: var(--text2); }
.import-empty { padding: 40px; text-align: center; color: var(--text2); }
.import-summary { font-weight: 600; font-size: 13px; color: var(--text2); margin-bottom: var(--sp-3); text-transform: uppercase; letter-spacing: .5px; }
.import-table-wrap { max-height: 360px; overflow-y: auto; display: flex; flex-direction: column; gap: var(--sp-3); }
.import-group { border: 1px solid var(--border); border-radius: var(--radius-md); overflow: hidden; }
.import-group-head { padding: 8px 12px; font-size: 12px; font-weight: 600; background: var(--surface); border-bottom: 1px solid var(--border); color: var(--text-primary); text-transform: uppercase; letter-spacing: .4px; }
.import-row { display: flex; align-items: center; gap: var(--sp-2); padding: 6px 12px; font-size: 13px; cursor: pointer; transition: background .1s; }
.import-row:hover { background: var(--surface-hover); }
.import-row.muted { opacity: .55; }
.import-row input { accent-color: var(--accent-primary); }
.import-fname { font-family: var(--font-data); min-width: 0; word-break: break-all; flex: 1; }
.import-count { font-size: 11px; font-weight: 600; color: var(--text2); white-space: nowrap; min-width: 48px; text-align: right; }
.import-label { font-size: 11px; color: var(--text2); background: var(--surface); padding: 1px 8px; border-radius: 999px; white-space: nowrap; }
.import-ignored { border: 1px solid var(--border); border-radius: var(--radius-md); }
.import-ignored-sum { padding: 8px 12px; font-size: 12px; cursor: pointer; color: var(--text2); }
`}</style>
    </div>
  );
}
