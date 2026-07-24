// JWT decode and analysis engine. Pure — no DOM, no network, testable in Node.

function b64urlDecode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try { return atob(s); } catch { return ''; }
}

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

// Decode a JWT token. Returns null if it isn't parseable.
// Otherwise returns { header, payload, alg, exp, expired, iss, sub, issues[] }.
export function decodeJwt(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;

  const rawHeader = b64urlDecode(parts[0]);
  const rawPayload = b64urlDecode(parts[1]);
  const header = tryJson(rawHeader);
  const payload = tryJson(rawPayload);
  if (!header && !payload) return null;

  const alg = header?.alg || null;
  const typ = header?.typ || null;
  const kid = header?.kid || null;
  const jku = header?.jku || null;
  const jwk = header?.jwk || null;

  const issues = [];
  const recommendations = [];

  // Header checks
  if (alg && /^none$/i.test(alg)) {
    issues.push({ severity: 'critical', text: 'alg:none — signature verification disabled' });
    recommendations.push('Reject tokens with alg:none');
  }
  if (alg && /^hs/i.test(alg)) {
    issues.push({ severity: 'high', text: `HS${alg.slice(2)} — symmetric algorithm; forgeable if secret is weak` });
    recommendations.push('Use RS256/ES256 instead of HS*');
  }
  if (kid) {
    issues.push({ severity: 'medium', text: 'kid present — possible injection (path traversal, SQLi)' });
    recommendations.push('Validate kid against an allowlist');
  }
  if (jku) {
    issues.push({ severity: 'high', text: 'jku present — possible SSRF to attacker-hosted JWKS' });
    recommendations.push('Restrict jku to trusted URLs');
  }
  if (jwk) {
    issues.push({ severity: 'critical', text: 'jwk embedded in header — attacker can forge their own key' });
    recommendations.push('Do not trust embedded jwk');
  }

  // Payload checks
  let expired = false;
  if (payload && typeof payload.exp === 'number') {
    expired = payload.exp * 1000 < Date.now();
    issues.push({
      severity: expired ? 'high' : 'info',
      text: expired ? 'token is expired' : 'token is still valid',
    });
  } else {
    issues.push({ severity: 'medium', text: 'no exp claim — token never expires' });
    recommendations.push('Add exp claim');
  }

  if (payload && typeof payload.nbf === 'number' && payload.nbf * 1000 > Date.now()) {
    issues.push({ severity: 'info', text: 'nbf is in the future — token not yet active' });
  }
  if (payload && typeof payload.iat === 'number') {
    const age = (Date.now() - payload.iat * 1000) / 1000;
    if (age > 86400 * 365) {
      issues.push({ severity: 'low', text: 'iat is over a year old' });
    }
  }

  if (payload && payload.aud && Array.isArray(payload.aud) && payload.aud.length > 1) {
    issues.push({ severity: 'low', text: 'multiple audience values — possible audience confusion' });
  }

  return {
    header,
    payload,
    signature: parts[2] || null,
    alg,
    typ,
    exp: payload?.exp ?? null,
    expired,
    nbf: payload?.nbf ?? null,
    iss: payload?.iss ?? null,
    sub: payload?.sub ?? null,
    aud: payload?.aud ?? null,
    raw: {
      header: parts[0],
      payload: parts[1],
      signature: parts[2] || null,
    },
    issues,
    recommendations,
  };
}

// Extract all JWT tokens from a block of text (e.g. paste from JS Recon).
const JWT_RE = /ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]+)?/g;

export function extractJwts(text) {
  if (!text) return [];
  const seen = new Set();
  const results = [];
  let m;
  while ((m = JWT_RE.exec(text)) !== null) {
    if (seen.has(m[0])) continue;
    seen.add(m[0]);
    const decoded = decodeJwt(m[0]);
    if (decoded) results.push({ token: m[0], ...decoded });
  }
  return results;
}
