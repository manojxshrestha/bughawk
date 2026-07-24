import { describe, it } from 'node:test';
import assert from 'node:assert';
import { diffUrls, paramKeys, sessionSignature } from './diff.js';

const makeResult = (url, cats = []) => ({ url, categories: cats });

describe('diffUrls', () => {
  const prev = [
    makeResult('https://example.com/api/users?id=1'),
    makeResult('https://example.com/api/users?id=2'),
    makeResult('https://example.com/login'),
    makeResult('https://example.com/admin'),
  ];

  const curr = [
    makeResult('https://example.com/api/users?id=1'),
    makeResult('https://example.com/api/users?id=3'),
    makeResult('https://example.com/login'),
    makeResult('https://example.com/logout'),
  ];

  it('detects added URLs', () => {
    const d = diffUrls(prev, curr);
    assert.equal(d.stats.added, 2);
    assert.ok(d.added.some((r) => r.url === 'https://example.com/logout'));
    assert.ok(d.added.some((r) => r.url === 'https://example.com/api/users?id=3'));
  });

  it('detects removed URLs', () => {
    const d = diffUrls(prev, curr);
    assert.equal(d.stats.removed, 2);
    assert.ok(d.removed.some((r) => r.url === 'https://example.com/admin'));
    assert.ok(d.removed.some((r) => r.url === 'https://example.com/api/users?id=2'));
  });

  it('tracks added/removed by base URL group', () => {
    const d = diffUrls(prev, curr);
    const base = 'https://example.com/api/users';
    assert.equal((d.addedByBase[base] || []).length, 1);
    assert.equal((d.removedByBase[base] || []).length, 1);
  });

  it('finds new endpoints (path identity)', () => {
    const d = diffUrls(prev, curr);
    assert.ok(d.newEndpoints.some((p) => p.includes('/logout')));
  });

  it('finds gone endpoints', () => {
    const d = diffUrls(prev, curr);
    assert.ok(d.goneEndpoints.some((p) => p.includes('/admin')));
  });

  it('handles empty inputs', () => {
    const d = diffUrls([], []);
    assert.equal(d.stats.added, 0);
    assert.equal(d.stats.removed, 0);
  });

  it('handles null/undefined inputs', () => {
    assert.doesNotThrow(() => diffUrls(null, undefined));
  });
});

describe('paramKeys', () => {
  it('extracts keys from URL query', () => {
    const keys = paramKeys('https://ex.com/?a=1&b=2&a=3');
    assert.deepEqual(keys, ['a', 'b']);
  });

  it('returns empty for URL without params', () => {
    assert.deepEqual(paramKeys('https://ex.com/'), []);
  });

  it('handles malformed URLs gracefully', () => {
    assert.deepEqual(paramKeys('not a url'), []);
  });
});

describe('sessionSignature', () => {
  it('computes URLs, param keys, and paths', () => {
    const r = [
      makeResult('https://ex.com/api/users?id=1&role=admin'),
      makeResult('https://ex.com/login?redirect=/home'),
    ];
    const sig = sessionSignature(r);
    assert.equal(sig.urlCount, 2);
    assert.ok(sig.paramKeys.includes('id'));
    assert.ok(sig.paramKeys.includes('role'));
    assert.ok(sig.paramKeys.includes('redirect'));
    assert.ok(sig.paths.includes('api'));
    assert.ok(sig.paths.includes('login'));
  });

  it('handles empty results', () => {
    const sig = sessionSignature([]);
    assert.equal(sig.urlCount, 0);
    assert.deepEqual(sig.urls, []);
    assert.deepEqual(sig.paramKeys, []);
  });
});
