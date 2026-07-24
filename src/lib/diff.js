// Diff engine for URL results. Pure functions, no DOM, testable in Node.
// Compares two sets of parsed URL results and returns added/removed items.

// Extract a URL identity (scheme + host + pathname, ignoring query/fragment).
function urlIdentity(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`;
  } catch {
    return url;
  }
}

// Normalize a URL to its parameter-less base for grouping.
function urlBase(url) {
  try {
    const u = new URL(url);
    u.search = '';
    u.hash = '';
    return u.href.replace(/\/+$/, '');
  } catch {
    return url;
  }
}

// Extract parameter keys from a URL.
export function paramKeys(url) {
  try {
    const u = new URL(url);
    return [...new Set(new URLSearchParams(u.search).keys())].sort();
  } catch {
    return [];
  }
}

// Compare two URL result arrays. Returns added/removed with per-group breakdown.
export function diffUrls(prevResults, currResults) {
  const prev = prevResults || [];
  const curr = currResults || [];

  const prevUrls = new Set(prev.map((r) => r.url));
  const currUrls = new Set(curr.map((r) => r.url));

  const added = curr.filter((r) => !prevUrls.has(r.url));
  const removed = prev.filter((r) => !currUrls.has(r.url));

  // Group added by URL base (path without params)
  const addedByBase = {};
  for (const r of added) {
    const base = urlBase(r.url);
    if (!addedByBase[base]) addedByBase[base] = [];
    addedByBase[base].push(r);
  }

  const removedByBase = {};
  for (const r of removed) {
    const base = urlBase(r.url);
    if (!removedByBase[base]) removedByBase[base] = [];
    removedByBase[base].push(r);
  }

  // Param-level diff: for URLs that exist in both, compare their params
  const commonUrls = [...prevUrls].filter((u) => currUrls.has(u));
  const paramChanges = [];
  for (const url of commonUrls) {
    const prevParams = paramKeys(url);
    const currEntry = curr.find((r) => r.url === url);
    const currParams = currEntry ? paramKeys(currEntry.url) : prevParams;
    const addedParams = currParams.filter((p) => !prevParams.includes(p));
    const removedParams = prevParams.filter((p) => !currParams.includes(p));
    if (addedParams.length || removedParams.length) {
      paramChanges.push({ url, addedParams, removedParams });
    }
  }

  // Endpoint-level diff: count unique path identities
  const prevPaths = new Set(prev.map((r) => urlIdentity(r.url)));
  const currPaths = new Set(curr.map((r) => urlIdentity(r.url)));
  const newEndpoints = [...currPaths].filter((p) => !prevPaths.has(p));
  const goneEndpoints = [...prevPaths].filter((p) => !currPaths.has(p));

  return {
    added,
    removed,
    addedByBase,
    removedByBase,
    paramChanges,
    newEndpoints,
    goneEndpoints,
    stats: {
      totalPrev: prev.length,
      totalCurr: curr.length,
      added: added.length,
      removed: removed.length,
      changed: paramChanges.length,
      changedParams: paramChanges.length,
      newEndpoints: newEndpoints.length,
      goneEndpoints: goneEndpoints.length,
    },
  };
}

// Compute a lightweight signature for persisted snapshots.
export function sessionSignature(results) {
  const urls = (results || []).map((r) => r.url).filter(Boolean);
  const paramSet = new Set();
  const pathSet = new Set();
  for (const r of results || []) {
    for (const k of paramKeys(r.url)) paramSet.add(k);
    try {
      const u = new URL(r.url);
      u.pathname.split('/').filter(Boolean).forEach((seg) => {
        if (seg.length > 1 && !/^\d+$/.test(seg)) pathSet.add(seg);
      });
    } catch { /* skip */ }
  }
  return {
    urlCount: urls.length,
    urls, // full URL list for identity checks
    paramKeys: [...paramSet].sort(),
    paths: [...pathSet].sort(),
  };
}
