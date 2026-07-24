import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyFile, parseContent, PATTERNS } from './project-import.js';

test('classifies subs.txt as subdomains', () => {
  const r = classifyFile('subs.txt');
  assert.equal(r.tab, 'subdomains');
  assert.equal(r.parser, 'hostlist');
});

test('classifies nuclei-output.txt as findings', () => {
  const r = classifyFile('nuclei-output.txt');
  assert.equal(r.tab, 'findings');
  assert.equal(r.parser, 'nuclei');
});

test('classifies crawledurls.txt as urlparser', () => {
  const r = classifyFile('crawledurls.txt');
  assert.equal(r.tab, 'urlparser');
  assert.equal(r.parser, 'urllist');
});

test('classifies nmap-scan.gnmap as ports', () => {
  const r = classifyFile('nmap-scan.gnmap');
  assert.equal(r.tab, 'ports');
  assert.equal(r.parser, 'gnmap');
});

test('classifies cariddi.txt as findings', () => {
  const r = classifyFile('cariddi.txt');
  assert.equal(r.tab, 'findings');
  assert.equal(r.parser, 'cariddi');
});

test('classifies live.txt', () => {
  assert.equal(classifyFile('live.txt').tab, 'subdomains');
});

test('classifies https-subs.txt', () => {
  assert.equal(classifyFile('https-subs.txt').tab, 'subdomains');
  assert.equal(classifyFile('http-subs.txt').tab, 'subdomains');
});

test('classifies alive-domains.txt', () => {
  assert.equal(classifyFile('alive-domains.txt').tab, 'subdomains');
  assert.equal(classifyFile('alive-domain.txt').tab, 'subdomains');
});

test('returns null for unknown files', () => {
  assert.equal(classifyFile('readme.md'), null);
  assert.equal(classifyFile('output.html'), null);
  assert.equal(classifyFile('notes.txt'), null);
});

test('parseContent hostlist handles one-per-line', () => {
  const r = parseContent('example.com\napi.example.com\n', 'hostlist');
  assert.deepEqual(r, ['example.com', 'api.example.com']);
});

test('parseContent hostlist ignores blanks and comments', () => {
  const r = parseContent('# comment\n\nexample.com\n\n', 'hostlist');
  assert.deepEqual(r, ['example.com']);
});

test('parseContent urllist extracts URLs', () => {
  const r = parseContent('https://example.com/api\nhttps://example.com/login\n', 'urllist');
  assert.equal(r.type, 'urllist');
  assert.equal(r.urls.length, 2);
});

test('parseContent gnmap extracts hosts and ports', () => {
  const gnmap = `Host: 192.168.1.1 ()\tPorts: 22/open/tcp///, 80/open/tcp///
Host: 10.0.0.1 ()\tPorts: 443/open/tcp///`;
  const r = parseContent(gnmap, 'gnmap');
  assert.equal(r.type, 'gnmap');
  assert.equal(r.entries.length, 2);
  assert.equal(r.entries[0].ip, '192.168.1.1');
  assert.equal(r.entries[0].ports.length, 2);
  assert.equal(r.entries[0].ports[0].port, 22);
  assert.equal(r.entries[0].ports[0].service, 'tcp');
});

test('parseContent gnmap handles empty lines', () => {
  const r = parseContent('# comment\n\n', 'gnmap');
  assert.equal(r.entries.length, 0);
});

test('parseContent nuclei handles JSONL format', () => {
  const line = JSON.stringify({
    host: 'https://example.com',
    'matched-at': 'https://example.com/.env',
    'template-id': 'env-file',
    info: { name: 'Env File Exposure', severity: 'high' },
    extracted_results: ['DB_PASSWORD=secret'],
  });
  const r = parseContent(line, 'nuclei');
  assert.equal(r.type, 'nuclei');
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].name, 'Env File Exposure');
  assert.equal(r.findings[0].severity, 'high');
  assert.equal(r.findings[0].templateId, 'env-file');
});

test('parseContent nuclei handles plaintext fallback', () => {
  const r = parseContent('example.com:443\n', 'nuclei');
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].host, 'example.com:443');
});

test('parseContent cariddi parses severity tags', () => {
  const r = parseContent(
    'https://example.com/.env [high] Configuration file exposed\n' +
    'https://example.com/admin [medium] Admin panel\n',
    'cariddi',
  );
  assert.equal(r.type, 'cariddi');
  assert.equal(r.findings.length, 2);
  assert.equal(r.findings[0].severity, 'high');
  assert.equal(r.findings[1].severity, 'medium');
});

test('classifyFile matches waygauurls.txt variations', () => {
  assert.ok(classifyFile('waygauurls.txt'));
  assert.ok(classifyFile('waygauurls.txt')); // singular
});

test('every pattern has a unique match regex among patterns that share a parser', () => {
  for (const p of PATTERNS) {
    assert.ok(p.match, `Pattern missing regex: ${p.label}`);
    assert.ok(p.parser, `Pattern missing parser: ${p.label}`);
    assert.ok(p.label, `Pattern missing label: ${p.match}`);
    assert.ok(p.tab, `Pattern missing tab: ${p.match}`);
  }
});
