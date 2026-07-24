export const PATTERNS = [
  // Subdomains
  { match: /subdomain/i, tab: 'subdomains', label: 'Subdomains', parser: 'hostlist' },
  { match: /^subs\.txt$/i, tab: 'subdomains', label: 'Subdomains', parser: 'hostlist' },
  { match: /^live\.txt$/i, tab: 'subdomains', label: 'Live Hosts', parser: 'hostlist' },
  { match: /[-.]?alive/i, tab: 'subdomains', label: 'Alive Hosts', parser: 'hostlist' },
  { match: /^all\.txt$/i, tab: 'subdomains', label: 'All Hosts', parser: 'hostlist' },
  { match: /^hosts?\.txt$/i, tab: 'subdomains', label: 'Hosts', parser: 'hostlist' },
  { match: /^resolved\.txt$/i, tab: 'subdomains', label: 'Resolved Hosts', parser: 'hostlist' },
  { match: /^domains?\.txt$/i, tab: 'subdomains', label: 'Domains', parser: 'hostlist' },
  { match: /^https?-subs/i, tab: 'subdomains', label: 'HTTPS Subdomains', parser: 'hostlist' },
  { match: /^webservers?\.txt$/i, tab: 'subdomains', label: 'Web Servers', parser: 'hostlist' },

  // URL lists
  { match: /url/i, tab: 'urlparser', label: 'URLs', parser: 'urllist' },
  { match: /crawl/i, tab: 'urlparser', label: 'Crawled URLs', parser: 'urllist' },
  { match: /gau/i, tab: 'urlparser', label: 'GAU URLs', parser: 'urllist' },
  { match: /katana/i, tab: 'urlparser', label: 'Katana Output', parser: 'urllist' },
  { match: /wayback|waymore|waygau/i, tab: 'urlparser', label: 'Wayback URLs', parser: 'urllist' },
  { match: /hakrawler|hakcrawl/i, tab: 'urlparser', label: 'Hakrawler URLs', parser: 'urllist' },
  { match: /^endpoints?\.txt$/i, tab: 'urlparser', label: 'Endpoints', parser: 'urllist' },
  { match: /^allurls?\.txt$/i, tab: 'urlparser', label: 'All URLs', parser: 'urllist' },
  { match: /^merged-crawl/i, tab: 'urlparser', label: 'Merged Crawl', parser: 'urllist' },

  // Nuclei
  { match: /nuclei/i, tab: 'findings', label: 'Nuclei Results', parser: 'nuclei' },

  // Nmap / port scan
  { match: /\.gnmap$/i, tab: 'ports', label: 'Nmap GNMAP', parser: 'gnmap' },
  { match: /\.nmap$/i, tab: 'ports', label: 'Nmap Output', parser: 'gnmap' },
  { match: /^nmap/i, tab: 'ports', label: 'Nmap Scan', parser: 'gnmap' },
  { match: /masscan/i, tab: 'ports', label: 'Masscan Output', parser: 'gnmap' },

  // Cariddi
  { match: /cariddi/i, tab: 'findings', label: 'Cariddi Results', parser: 'cariddi' },

  // Scope
  { match: /scope/i, tab: 'subdomains', label: 'Scope', parser: 'hostlist' },

  // JS files
  { match: /\.js$/i, tab: 'jsrecon', label: 'JS File', parser: 'jsfile' },
];

export function classifyFile(fileName) {
  for (const p of PATTERNS) {
    if (p.match.test(fileName)) return p;
  }
  return null;
}

export function classifyByContent(text) {
  const lines = (text || '').split('\n').map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return null;

  // XML → try nmap
  if (/^\s*</.test(lines[0])) {
    const hasNmap = /<nmaprun/i.test(text) || /<host/i.test(text);
    if (hasNmap) return { tab: 'ports', label: 'Nmap XML', parser: 'xml' };
  }

  // JSONL → try nuclei
  if (lines[0][0] === '{') {
    const jsonCount = lines.filter((l) => { try { const o = JSON.parse(l); return o && (o['template-id'] || o.info?.name); } catch { return false; } }).length;
    if (jsonCount >= lines.length * 0.5) return { tab: 'findings', label: 'Nuclei JSONL', parser: 'nuclei' };
  }

  // Cariddi format: "url [severity] description"
  if (/^https?:\/\/\S+\s+\[/i.test(lines[0])) return { tab: 'findings', label: 'Cariddi Results', parser: 'cariddi' };

  // GNMAP format
  if (/^Host:\s*[0-9.]+/.test(lines[0])) return { tab: 'ports', label: 'Nmap GNMAP', parser: 'gnmap' };

  // Detect URL vs host list
  const urlCount = lines.filter((l) => /^https?:\/\//i.test(l)).length;
  const hostCount = lines.filter((l) => {
    if (/^https?:\/\//i.test(l)) return false;
    return /^[a-z0-9][-a-z0-9.]*\.[a-z]{2,}/i.test(l) || /^[0-9.]+$/.test(l);
  }).length;
  const threshold = Math.max(1, lines.length * 0.4);

  if (urlCount >= threshold) return { tab: 'urlparser', label: 'URLs (auto)', parser: 'urllist' };
  if (hostCount >= threshold) return { tab: 'subdomains', label: 'Hosts (auto)', parser: 'hostlist' };

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
    case 'xml':
      return parseNmapXml(text);
    case 'cariddi':
      return parseCariddi(text);
    case 'jsfile':
      return { type: 'jsfile', content: text };
    default:
      return null;
  }
}

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

function parseNmapXml(text) {
  const entries = [];
  const hostRegex = /<host[^>]*>[\s\S]*?<\/host>/gi;
  let hostMatch;
  while ((hostMatch = hostRegex.exec(text)) !== null) {
    const block = hostMatch[0];
    const ipMatch = block.match(/<address\s+addr="([0-9.]+)"\s+addrtype="ipv4"/i);
    if (!ipMatch) continue;
    const ip = ipMatch[1];
    const portRegex = /<port\s+protocol="[^"]*"\s+portid="(\d+)">[\s\S]*?<state\s+state="open"[^>]*\/>[\s\S]*?(?:<service\s+name="([^"]*)"[^>]*\/>)?/gi;
    const ports = [];
    let portMatch;
    while ((portMatch = portRegex.exec(block)) !== null) {
      ports.push({ port: parseInt(portMatch[1], 10), service: portMatch[2] || 'unknown' });
    }
    if (ports.length > 0) entries.push({ ip, ports });
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
