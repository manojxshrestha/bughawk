const MAX = 25 * 1024 * 1024;

export default async (req) => {
  const url = new URL(req.url);
  const target = url.searchParams.get('url');

  if (!target || !/^https?:\/\//i.test(target)) {
    return new Response('bad url', { status: 400 });
  }

  try {
    const r = await fetch(target, {
      redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (jsrecon)' },
    });
    const buf = await r.arrayBuffer();
    if (buf.byteLength > MAX) {
      return new Response('too large', { status: 413 });
    }
    return new Response(buf, {
      status: r.ok ? 200 : r.status,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  } catch (e) {
    return new Response('fetch failed: ' + e.message, { status: 502 });
  }
};

export const config = { path: '/__jsproxy' };
