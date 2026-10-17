// Threat Recap push subscriptions: a tiny store on Cloudflare Workers + KV.
// The site posts a browser's push subscription here; the GitHub update job reads the list (with a secret
// token) and sends the alerts itself. Nothing else is stored: no IP addresses, no accounts.
//
//   POST /subscribe      { subscription, topics: ["zeroday","kev","stack"], vendors: ["Fortinet", ...] }
//   POST /unsubscribe    { subscription }
//   GET  /subscriptions          (Authorization: Bearer ADMIN_TOKEN)  -> the list, for the update job
//   DELETE /subscriptions/<id>   (Authorization: Bearer ADMIN_TOKEN)  -> remove an expired one

const TOPICS = ['zeroday', 'kev', 'stack'];
// Only real browser push services, so the store can't be used to make the update job call arbitrary URLs.
const PUSH_HOSTS = /^(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|web\.push\.apple\.com|[a-z0-9-]+\.notify\.windows\.com)$/i;

const allowed = env => (env.ALLOWED_ORIGINS || 'https://hvvix.github.io').split(',').map(s => s.trim());
const cors = (env, origin) => ({
  'access-control-allow-origin': allowed(env).includes(origin) ? origin : allowed(env)[0],
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
  'access-control-max-age': '86400',
  vary: 'origin',
});
const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
async function idOf(endpoint) {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url), origin = req.headers.get('origin') || '';
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors(env, origin) });

    if (req.method === 'POST' && (url.pathname === '/subscribe' || url.pathname === '/unsubscribe')) {
      const h = cors(env, origin);
      if (!allowed(env).includes(origin)) return json({ error: 'origin not allowed' }, 403, h);
      const text = await req.text();
      if (text.length > 4000) return json({ error: 'too large' }, 413, h);
      let body; try { body = JSON.parse(text); } catch { return json({ error: 'bad json' }, 400, h); }
      const sub = body.subscription || {};
      let host; try { host = new URL(sub.endpoint).hostname; } catch { return json({ error: 'bad endpoint' }, 400, h); }
      if (!PUSH_HOSTS.test(host)) return json({ error: 'unknown push service' }, 400, h);
      const id = await idOf(sub.endpoint);
      if (url.pathname === '/unsubscribe') { await env.SUBS.delete(id); return json({ ok: true }, 200, h); }
      if (!sub.keys?.p256dh || !sub.keys?.auth) return json({ error: 'missing keys' }, 400, h);
      const topics = [...new Set((body.topics || []).filter(t => TOPICS.includes(t)))];
      const vendors = (body.vendors || []).filter(v => typeof v === 'string' && v.length <= 60).slice(0, 60);
      if (!topics.length) { await env.SUBS.delete(id); return json({ ok: true, removed: true }, 200, h); }
      await env.SUBS.put(id, JSON.stringify({ sub: { endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } }, topics, vendors, at: Date.now() }));
      return json({ ok: true }, 200, h);
    }

    const authed = env.ADMIN_TOKEN && req.headers.get('authorization') === `Bearer ${env.ADMIN_TOKEN}`;
    if (url.pathname === '/subscriptions' && req.method === 'GET') {
      if (!authed) return json({ error: 'unauthorized' }, 401);
      const out = []; let cursor;
      do {
        const page = await env.SUBS.list({ cursor });
        for (const k of page.keys) { const v = await env.SUBS.get(k.name, 'json'); if (v) out.push({ id: k.name, ...v }); }
        cursor = page.list_complete ? null : page.cursor;
      } while (cursor);
      return json(out);
    }
    if (url.pathname.startsWith('/subscriptions/') && req.method === 'DELETE') {
      if (!authed) return json({ error: 'unauthorized' }, 401);
      await env.SUBS.delete(url.pathname.split('/').pop());
      return json({ ok: true });
    }
    if (url.pathname === '/') return new Response('Threat Recap push service', { headers: { 'content-type': 'text/plain' } });
    return json({ error: 'not found' }, 404);
  },
};
