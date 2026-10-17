#!/usr/bin/env node
// Sends Web Push alerts after a build: newly exploited CVEs (CISA KEV), zero-days covered by several
// outlets, and stories about each subscriber's own vendors. Subscriptions come from the push Worker
// (push/worker.js). Remembers what it already sent in cache/push-state.json.
//
//   PUSH_API            https://threat-recap-push.<you>.workers.dev
//   PUSH_ADMIN_TOKEN    the Worker's ADMIN_TOKEN
//   VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY   from `npx web-push generate-vapid-keys`
//   SITE_URL            optional, for links (defaults to the GitHub Pages address)

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const STATE = path.join(ROOT, 'cache', 'push-state.json');
const DAY = 864e5;
const { PUSH_API, PUSH_ADMIN_TOKEN, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY } = process.env;
const SITE = (process.env.SITE_URL || 'https://hvvix.github.io/Threat-Recap/').replace(/\/?$/, '/');
const log = (...a) => console.log('[push]', ...a);
const readJSON = async (f, d) => { try { return JSON.parse(await fs.readFile(f, 'utf8')); } catch { return d; } };

if (!PUSH_API || !PUSH_ADMIN_TOKEN || !VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) { log('not configured; skipping'); process.exit(0); }
const webpush = (await import('web-push')).default;
webpush.setVapidDetails('https://github.com/hvvix/Threat-Recap', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

const news = await readJSON(path.join(ROOT, 'public', 'data', 'news.json'), { stories: [] });
const cves = await readJSON(path.join(ROOT, 'public', 'data', 'cves.json'), { kev: [] });
const state = await readJSON(STATE, null);
const kevNow = (cves.kev || []).map(k => k.id);
const recent = news.stories.filter(s => !s.b && !s.so && Date.now() - s.d < DAY);

// First run: remember what exists so nobody gets a burst of old alerts.
if (!state) {
  await fs.mkdir(path.dirname(STATE), { recursive: true });
  await fs.writeFile(STATE, JSON.stringify({ kev: kevNow, stories: recent.map(s => s.id), at: Date.now() }));
  log(`first run: recorded ${kevNow.length} KEV entries and ${recent.length} stories; nothing sent`);
  process.exit(0);
}
const sentKev = new Set(state.kev), sentStories = new Set(state.stories);
const newKev = (cves.kev || []).filter(k => !sentKev.has(k.id));
const fresh = recent.filter(s => !sentStories.has(s.id));
const zeroDays = fresh.filter(s => s.tg.includes('zeroday') && s.r.length >= 1).sort((a, b) => b.r.length - a.r.length);

// One message per topic; each subscriber gets at most 3 per run.
const msg = {};
if (newKev.length) msg.kev = {
  title: newKev.length === 1 ? `Newly exploited: ${newKev[0].v} ${newKev[0].p}` : `${newKev.length} newly exploited vulnerabilities`,
  body: newKev.slice(0, 3).map(k => `${k.id} · ${k.v} ${k.p}`).join('\n') + (newKev.some(k => k.rw) ? '\nUsed in ransomware campaigns' : ''),
  url: `${SITE}?tab=cves#${newKev[0].id}`, tag: `kev-${newKev[0].id}`,
};
if (zeroDays.length) msg.zeroday = {
  title: `Zero-day: ${zeroDays[0].t.slice(0, 90)}`,
  body: `${zeroDays[0].s} and ${zeroDays[0].r.length} other outlet${zeroDays[0].r.length > 1 ? 's' : ''}${zeroDays.length > 1 ? ` · +${zeroDays.length - 1} more zero-day stor${zeroDays.length > 2 ? 'ies' : 'y'}` : ''}`,
  url: zeroDays[0].u, tag: `zd-${zeroDays[0].id}`,
};
function stackMsg(vendors) {
  const v = new Set(vendors.map(x => x.toLowerCase()));
  const mine = fresh.filter(s => s.ve.some(x => v.has(x.toLowerCase()))).sort((a, b) => b.r.length - a.r.length);
  if (!mine.length) return null;
  const who = mine[0].ve.find(x => v.has(x.toLowerCase()));
  return { title: `Your stack · ${who}: ${mine[0].t.slice(0, 80)}`, body: mine.length > 1 ? `+${mine.length - 1} more stor${mine.length > 2 ? 'ies' : 'y'} about your vendors` : mine[0].s, url: mine[0].u, tag: `stack-${mine[0].id}` };
}

let subs = [];
if (Object.keys(msg).length || fresh.some(s => s.ve.length)) {
  const r = await fetch(`${PUSH_API}/subscriptions`, { headers: { authorization: `Bearer ${PUSH_ADMIN_TOKEN}` } });
  if (!r.ok) { log(`could not read subscriptions: HTTP ${r.status}`); process.exit(0); }
  subs = await r.json();
}
let sent = 0, removed = 0, failed = 0;
for (const s of subs) {
  const out = [];
  if (s.topics.includes('kev') && msg.kev) out.push(msg.kev);
  if (s.topics.includes('zeroday') && msg.zeroday) out.push(msg.zeroday);
  if (s.topics.includes('stack') && s.vendors?.length) { const m = stackMsg(s.vendors); if (m) out.push(m); }
  for (const m of out.slice(0, 3)) {
    try { await webpush.sendNotification(s.sub, JSON.stringify(m), { TTL: 6 * 3600, urgency: m.tag.startsWith('kev') || m.tag.startsWith('zd') ? 'high' : 'normal' }); sent++; }
    catch (e) {
      // 404/410: the browser dropped the subscription (app uninstalled, permission revoked). Remove it.
      if (e.statusCode === 404 || e.statusCode === 410) { await fetch(`${PUSH_API}/subscriptions/${s.id}`, { method: 'DELETE', headers: { authorization: `Bearer ${PUSH_ADMIN_TOKEN}` } }); removed++; break; }
      failed++; log(`send failed (${e.statusCode || e.message})`);
    }
  }
}
// Remember everything seen in the last couple of days (older ids can be dropped).
const keepIds = news.stories.filter(s => Date.now() - s.d < 2 * DAY).map(s => s.id);
await fs.writeFile(STATE, JSON.stringify({ kev: kevNow, stories: [...new Set([...keepIds.filter(id => sentStories.has(id)), ...fresh.map(s => s.id)])], at: Date.now() }));
log(`${subs.length} subscribers · new: ${newKev.length} KEV, ${zeroDays.length} zero-day, ${fresh.length} stories · sent ${sent}, removed ${removed}, failed ${failed}`);
