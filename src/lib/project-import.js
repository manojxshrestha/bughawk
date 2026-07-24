// File-name patterns and content parsers for project zip import.
// Each pattern maps a file name regex to a destination tab and a parser.

export const PATTERNS = [
  // Subdomains → SubdomainTab
  { match: /^subs\.txt$/i, tab: 'subdomains', label: 'CTFR Subdomains', parser: 'hostlist' },
  { match: /^live\.txt$/i, tab: 'subdomains', label: 'Live Hosts', parser: 'hostlist' },
  { match: /^https?-subs\.txt$/i, tab: 'subdomains', label: 'HTTPS Subdomains', parser: 'hostlist' },
  { match: /^alive-domains?\.txt$/i, tab: 'subdomains', label: 'Alive Domains', parser: 'hostlist' },

  // URL lists → URL Parser
  { match: /^crawledurls?\.txt$/i, tab: 'urlparser', label: 'Crawled URLs', parser: 'urllist' },
  { match: /^waygauurls?\.txt$/i, tab: 'urlparser', label: 'Waymore+GAU URLs', parser: 'urllist' },
  { match: /^merged-crawl\.txt$/i, tab: 'urlparser', label: 'Merged Crawl', parser: 'urllist' },
  { match: /^cleansubskatanaurls?\.txt$/i, tab: 'urlparser', label: 'Katana URLs', parser: 'urllist' },
  { match: /^hakcrawlurls?\.txt$/i, tab: 'urlparser', label: 'Hakrawler URLs', parser: 'urllist' },
  { match: /^alivesubsurls?\.txt$/i, tab: 'urlparser', label: 'Alive Subs URLs', parser: 'urllist' },

  // Nuclei → Findings
  { match: /^nuclei-output[\d]*\.txt$/i, tab: 'findings', label: 'Nuclei Results', parser: 'nuclei' },

  // Nmap GNMAP → Port Scan
  { match: /\.gnmap$/i, tab: 'ports', label: 'Nmap Scan', parser: 'gnmap' },

  // Cariddi → Findings
  { match: /^cariddi\.txt$/i, tab: 'findings', label: 'Cariddi Results', parser: 'cariddi' },
];

export function classifyFile(fileName) {
  for (const p of PATTERNS) {
    if (p.match.test(fileName)) return p;
  }
  return null;
}

export function parseContent(text, parser) {
  switch (parser) {
    case 'hostlist':
      return parseHostlist(text);
    case 'urllist':
      return { type: 'urllist', urls: parseHostlist(text) };
    case 'nuclei':
      return parseNucleiLines(text);
    case 'gnmap':
      return parseGnmap(text);
    case 'cariddi':
      return parseCariddi(text);
    default:
      return null;
  }
}

// One host or URL per line, blank-line-tolerant.
function parseHostlist(text) {
  return (text || '').split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

function parseNucleiLines(text) {
  const findings = [];
  for (const line of (text || '').split('\n')) {
    const s = line.trim();
    if (!s) continue;
    if (s[0] === '{') {
      try {
        const o = JSON.parse(s);
        const host = hostOf(o.host || o['matched-at'] || o.matched || o.url || '');
        findings.push({
          host,
          name: (o.info?.name) || o['template-id'] || o.templateID || 'finding',
          severity: (o.info?.severity || o.severity || 'info').toLowerCase(),
          url: o['matched-at'] || o.matched || o.url || '',
          templateId: o['template-id'] || o.templateID || '',
          extract: o.extracted_results?.join(', ') || '',
        });
      } catch { /* skip unparseable */ }
    } else {
      findings.push({ host: s, name: s, severity: 'info', url: '', templateId: '', extract: '' });
    }
  }
  return { type: 'nuclei', findings };
}

function hostOf(raw) {
  try { return new URL(raw).hostname; } catch { /* not a URL */ }
  return String(raw || '').replace(/^[a-z]+:\/\//i, '').split('/')[0].split(':')[0].toLowerCase();
}

function parseGnmap(text) {
  const entries = [];
  for (const line of (text || '').split('\n')) {
    const s = line.trim();
    if (!s || s.startsWith('#')) continue;
    const hostMatch = s.match(/Host:\s*([0-9.]+)/i);
    if (!hostMatch) continue;
    const ip = hostMatch[1];
    const ports = [...s.matchAll(/(\d+)\/open\/([a-z]+)\/\/\//gi)];
    if (ports.length === 0) continue;
    entries.push({ ip, ports: ports.map((p) => ({ port: parseInt(p[1], 10), service: p[2] })) });
  }
  return { type: 'gnmap', entries };
}

function parseCariddi(text) {
  const findings = [];
  for (const line of (text || '').split('\n')) {
    const s = line.trim();
    if (!s) continue;
    const sep = s.indexOf(' ');
    if (sep === -1) continue;
    const url = s.slice(0, sep).trim();
    const rest = s.slice(sep + 1).trim();
    const sevMatch = rest.match(/\[(critical|high|medium|low|info)\]/i);
    const severity = sevMatch ? sevMatch[1].toLowerCase() : 'medium';
    const description = rest.replace(/\[.*?\]/g, '').trim() || rest;
    findings.push({ url, severity, description });
  }
  return { type: 'cariddi', findings };
}
