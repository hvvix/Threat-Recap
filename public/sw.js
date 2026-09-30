// Offline support. Network-first for everything so a new deploy is picked up
// immediately; the cache is only used when the network is unavailable.
const CACHE = 'tr-v4';
const SHELL = ['./', 'index.html', 'style.css', 'app.js', 'icon.svg', 'manifest.webmanifest', 'onthisday.json', 'favicon.ico'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL).catch(() => {})).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE && k !== 'cih-state').map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  const key = url.pathname.endsWith('/') ? url.pathname + 'index.html' : url.pathname;
  e.respondWith(fetch(e.request).then(r => {
    if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(key, copy)); }
    return r;
  }).catch(() => caches.match(key).then(r => r || caches.match(url.pathname)).then(r => r || Response.error())));
});

// ---- Notifications ----
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = new URL(e.notification.data?.url || './', self.registration.scope).href;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    const open = list.find(c => c.url.startsWith(self.registration.scope));
    if (open && url.startsWith(self.registration.scope)) return open.focus().then(c => c.navigate?.(url));
    return self.clients.openWindow(url);
  }));
});

// Installed-app background check (Chromium periodic sync, roughly hourly).
// The page stores notification choices and what it has already seen in Cache Storage.
self.addEventListener('periodicsync', e => { if (e.tag === 'cih-check') e.waitUntil(backgroundCheck()); });
async function backgroundCheck() {
  const stateCache = await caches.open('cih-state');
  const res = await stateCache.match('state.json'); if (!res) return;
  const st = await res.json(); if (!st.notify?.on) return;
  const clientsOpen = await self.clients.matchAll({ type: 'window' });
  if (clientsOpen.some(c => c.visibilityState === 'visible')) return; // the open page notifies itself
  const [news, cves] = await Promise.all([fetch('data/news.json', { cache: 'no-cache' }).then(r => r.json()), fetch('data/cves.json', { cache: 'no-cache' }).then(r => r.json())]);
  const known = new Set(st.known || []), knownKev = new Set(st.kev || []);
  const fresh = news.stories.filter(s => !known.has(s.id) && !s.b && !s.so);
  const words = (st.stack?.keywords || []).map(k => k.toLowerCase());
  const mine = s => (st.stack?.vendors || []).some(v => s.ve.includes(v)) || words.some(w => `${s.t} ${s.x}`.toLowerCase().includes(w));
  const out = [];
  if (st.notify.zeroday) for (const s of fresh.filter(s => s.tg.includes('zeroday')).slice(0, 2)) out.push(['Zero-day: ' + s.s, s.t, s.u]);
  if (st.notify.kev) { const n = (cves.kev || []).filter(k => !knownKev.has(k.id)); if (n.length) out.push([`${n.length} new actively exploited CVE${n.length > 1 ? 's' : ''} (CISA KEV)`, n.slice(0, 3).map(k => `${k.id} ${k.v} ${k.p}`).join('\n'), `./?tab=cves#${n[0].id}`]); }
  if (st.notify.stack) for (const s of fresh.filter(mine).slice(0, 2)) out.push(['Your stack: ' + s.s, s.t, s.u]);
  for (const [title, body, url] of out.slice(0, 4)) await self.registration.showNotification(title, { body, icon: 'icon.svg', badge: 'icon.svg', data: { url }, tag: url });
  st.known = news.stories.slice(0, 1500).map(s => s.id); st.kev = (cves.kev || []).map(k => k.id);
  await stateCache.put('state.json', new Response(JSON.stringify(st), { headers: { 'content-type': 'application/json' } }));
}
