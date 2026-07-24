import { describe, it } from 'node:test';
import assert from 'node:assert';
import { decodeJwt, extractJwts } from './jwt.js';

const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function makeToken(header, payload, sig) {
  return `${b64u(header)}.${b64u(payload)}.${sig || 'fakesig'}`;
}

describe('decodeJwt', () => {
  it('decodes a valid JWT', () => {
    const t = makeToken({ alg: 'RS256' }, { sub: '123', name: 'test', exp: 9999999999 });
    const r = decodeJwt(t);
    assert.ok(r);
    assert.equal(r.alg, 'RS256');
    assert.equal(r.sub, '123');
    assert.equal(r.expired, false);
  });

  it('returns null for non-JWT input', () => {
    assert.equal(decodeJwt(null), null);
    assert.equal(decodeJwt(''), null);
    assert.equal(decodeJwt('not.a.jwt'), null);
  });

  it('returns null for unparseable base64', () => {
    assert.equal(decodeJwt('!!!.!!!.!!!'), null);
  });

  it('flags alg:none as critical', () => {
    const t = makeToken({ alg: 'none' }, { sub: '1' });
    const r = decodeJwt(t);
    assert.ok(r.issues.some((i) => i.severity === 'critical' && i.text.includes('alg:none')));
  });

  it('flags expired token', () => {
    const t = makeToken({ alg: 'RS256' }, { sub: '1', exp: 100000 }); // year 1973
    const r = decodeJwt(t);
    assert.ok(r.expired);
    assert.ok(r.issues.some((i) => i.severity === 'high' && i.text.includes('expired')));
  });

  it('flags missing exp', () => {
    const t = makeToken({ alg: 'RS256' }, { sub: '1' });
    const r = decodeJwt(t);
    assert.ok(r.issues.some((i) => i.text.includes('no exp')));
  });

  it('flags embedded jwk as critical', () => {
    const t = makeToken({ alg: 'RS256', jwk: { kty: 'RSA', n: '...' } }, { sub: '1' });
    const r = decodeJwt(t);
    assert.ok(r.issues.some((i) => i.severity === 'critical' && i.text.includes('jwk')));
  });

  it('flags jku as high', () => {
    const t = makeToken({ alg: 'RS256', jku: 'https://evil.com/jwks' }, { sub: '1' });
    const r = decodeJwt(t);
    assert.ok(r.issues.some((i) => i.severity === 'high' && i.text.includes('jku')));
  });

  it('flags HS algorithm', () => {
    const t = makeToken({ alg: 'HS256' }, { sub: '1' });
    const r = decodeJwt(t);
    assert.ok(r.issues.some((i) => i.severity === 'high' && i.text.includes('HS')));
  });

  it('flags kid injection surface', () => {
    const t = makeToken({ alg: 'RS256', kid: '../../../etc/passwd' }, { sub: '1' });
    const r = decodeJwt(t);
    assert.ok(r.issues.some((i) => i.severity === 'medium' && i.text.includes('kid')));
  });

  it('handles token with only header (2-part)', () => {
    const t = `${b64u({ alg: 'RS256' })}.${b64u({})}`;
    const r = decodeJwt(t);
    assert.ok(r);
    assert.equal(r.alg, 'RS256');
  });

  it('returns recommendations for fixable issues', () => {
    const t = makeToken({ alg: 'none' }, {});
    const r = decodeJwt(t);
    assert.ok(r.recommendations.length > 0);
  });
});

describe('extractJwts', () => {
  it('finds JWTs in a blob of text', () => {
    const t1 = makeToken({ alg: 'RS256' }, { sub: 'user' });
    const t2 = makeToken({ alg: 'none' }, { sub: 'admin' });
    const text = `some text ${t1} more text ${t2} end`;
    const results = extractJwts(text);
    assert.equal(results.length, 2);
    assert.ok(results[0].issues);
  });

  it('deduplicates identical tokens', () => {
    const t = makeToken({ alg: 'RS256' }, { sub: 'u' });
    const results = extractJwts(`${t} ${t} ${t}`);
    assert.equal(results.length, 1);
  });

  it('returns empty for no tokens', () => {
    assert.deepEqual(extractJwts(null), []);
    assert.deepEqual(extractJwts(''), []);
    assert.deepEqual(extractJwts('no tokens here'), []);
  });
});
