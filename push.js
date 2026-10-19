#!/usr/bin/env node
// Sends Web Push alerts after a build. Subscribers pick topics in Settings → Notifications:
//   kev      newly exploited CVEs (CISA KEV)
//   zeroday  zero-days covered by several outlets
//   stack    stories about the subscriber's own vendors
//   breach   breaches of 1 million+ records
//   exploit  public exploit code for a critical (CVSS 9+) or actively exploited CVE
//   country  ransomware claims and Hackmanac alerts naming a victim in the subscriber's country
//   major    stories covered by 5+ outlets
// Subscriptions come from the push Worker (push/worker.js). What was already sent is remembered in
// cache/push-state.json, so each item is pushed once.
//
//   PUSH_API            https://threat-recap-push.<you>.workers.dev
//   PUSH_ADMIN_TOKEN    the Worker's ADMIN_TOKEN
//   VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY   from `npx web-push generate-vapid-keys`
//   SITE_URL            optional, for links (defaults to the GitHub Pages address)
//   node push.js --test sends a test message to every subscriber

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const STATE = path.join(ROOT, 'cache', 'push-state.json');
const DAY = 864e5;
const PER_RUN = 4;                         // most alerts one subscriber gets from one update
const { PUSH_API, PUSH_ADMIN_TOKEN, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY } = process.env;
const SITE = (process.env.SITE_URL || 'https://hvvix.github.io/Threat-Recap/').replace(/\/?$/, '/');
const log = (...a) => console.log('[push]', ...a);
const readJSON = async (f, d) => { try { return JSON.parse(await fs.readFile(f, 'utf8')); } catch { return d; } };
const auth = { authorization: `Bearer ${PUSH_ADMIN_TOKEN}` };
const cut = (s, n) => (s.length > n ? s.slice(0, n - 1).replace(/\s+\S*$/, '') + '…' : s);
const fmtCount = n => n >= 1e9 ? `${+(n / 1e9).toFixed(1)}B` : `${+(n / 1e6).toFixed(1)}M`;

if (!PUSH_API || !PUSH_ADMIN_TOKEN || !VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) { log('not configured; skipping'); process.exit(0); }
const webpush = (await import('web-push')).default;
webpush.setVapidDetails('https://github.com/hvvix/Threat-Recap', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

async function subscribers() {
  const r = await fetch(`${PUSH_API}/subscriptions`, { headers: auth });
  if (!r.ok) throw new Error(`could not read subscriptions: HTTP ${r.status}`);
  return r.json();
}
// Returns false when the subscription is gone (it's then removed from the Worker).
async function send(s, msg, urgency = 'normal') {
  try { await webpush.sendNotification(s.sub, JSON.stringify(msg), { TTL: 6 * 3600, urgency }); return true; }
  catch (e) {
    if (e.statusCode === 404 || e.statusCode === 410) { await fetch(`${PUSH_API}/subscriptions/${s.id}`, { method: 'DELETE', headers: auth }); return false; }
    log(`send failed (${e.statusCode || e.message})`); return true;
  }
}

// `node push.js --test`: a test message to every subscriber.
if (process.argv.includes('--test')) {
  const subs = await subscribers();
  let ok = 0, gone = 0;
  for (const s of subs) (await send(s, { title: 'Push alerts are working ✅', body: 'This is a test from Threat Recap. Real alerts arrive after updates, when there is something new.', url: SITE, tag: 'test' })) ? ok++ : gone++;
  log(`test push: ${subs.length} subscribers, delivered ${ok}, removed ${gone} expired`);
  process.exit(0);
}

const news = await readJSON(path.join(ROOT, 'public', 'data', 'news.json'), { stories: [] });
const cves = await readJSON(path.join(ROOT, 'public', 'data', 'cves.json'), { kev: [], info: {}, poc: {}, kevIndex: {} });
const rw = await readJSON(path.join(ROOT, 'public', 'data', 'ransomware.json'), { recent: [] });
const live = news.stories.filter(s => !s.b && !s.so);
const recent = live.filter(s => Date.now() - s.d < DAY);

// What exists right now, per topic (ids are what get remembered).
const now = {
  kev: (cves.kev || []).map(k => k.id),
  stories: recent.map(s => s.id),
  pocs: Object.entries(cves.poc || {}).filter(([id, p]) => p.n && ((cves.info?.[id]?.s ?? 0) >= 9 || cves.kevIndex?.[id])).map(([id]) => id),
  major: live.filter(s => Date.now() - s.d < 2 * DAY && s.r.length + 1 >= 5).map(s => s.id),
  claims: (rw.recent || []).filter(v => Date.now() - v.d < DAY).map(v => `${v.g}|${v.t}`),
};
const state = await readJSON(STATE, null);
// First run, or a topic added since the last run: remember what exists without sending, so nobody
// gets a burst of old alerts.
const known = {};
for (const k of Object.keys(now)) known[k] = state?.[k] ? new Set(state[k]) : null;
if (!state) log('first run: recording current items; nothing sent');

const isNew = (k, id) => known[k] && !known[k].has(id);
const newKev = (cves.kev || []).filter(k => isNew('kev', k.id));
const fresh = recent.filter(s => isNew('stories', s.id));
const zeroDays = fresh.filter(s => s.tg.includes('zeroday') && s.r.length >= 1).sort((a, b) => b.r.length - a.r.length);
const bigBreaches = fresh.filter(s => s.tg.includes('breach') && s.rc >= 1e6).sort((a, b) => b.rc - a.rc);
const newPocs = now.pocs.filter(id => isNew('pocs', id)).sort((a, b) => (cves.info?.[b]?.s ?? 0) - (cves.info?.[a]?.s ?? 0));
const majors = live.filter(s => now.major.includes(s.id) && isNew('major', s.id)).sort((a, b) => b.r.length - a.r.length);
const newClaims = (rw.recent || []).filter(v => Date.now() - v.d < DAY && isNew('claims', `${v.g}|${v.t}`));

// Country names in Hackmanac titles ("Victim (Saudi Arabia): …") → ISO codes.
const names = (() => {
  const m = { uae: 'AE', usa: 'US', us: 'US', uk: 'GB', 'south korea': 'KR', russia: 'RU', turkey: 'TR', 'türkiye': 'TR', taiwan: 'TW', vietnam: 'VN', 'czech republic': 'CZ' };
  const dn = new Intl.DisplayNames(['en'], { type: 'region' }), A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  for (const a of A) for (const b of A) { try { const n = dn.of(a + b); if (n && n !== a + b) m[n.toLowerCase()] = a + b; } catch {} }
  return m;
})();
const countryOf = s => { const m = s.t.match(/\(([^)]{2,40})\)/); return m ? names[m[1].toLowerCase().trim()] : null; };
const countryName = c => { try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(c); } catch { return c; } };
const newAlerts = fresh.filter(s => s.s === 'Hackmanac Alerts' && !/^Hack Tuesday/i.test(s.t));

// Messages that are the same for everyone who picked the topic.
const shared = {};
if (newKev.length) shared.kev = { m: {
  title: newKev.length === 1 ? `Newly exploited: ${newKev[0].v} ${newKev[0].p}` : `${newKev.length} newly exploited vulnerabilities`,
  body: newKev.slice(0, 3).map(k => `${k.id} · ${k.v} ${k.p}`).join('\n') + (newKev.some(k => k.rw) ? '\nUsed in ransomware campaigns' : ''),
  url: `${SITE}?tab=cves#${newKev[0].id}`, tag: `kev-${newKev[0].id}` }, urgency: 'high' };
if (zeroDays.length) shared.zeroday = { m: {
  title: `Zero-day: ${cut(zeroDays[0].t, 90)}`,
  body: `${zeroDays[0].s} and ${zeroDays[0].r.length} other outlet${zeroDays[0].r.length > 1 ? 's' : ''}${zeroDays.length > 1 ? ` · +${zeroDays.length - 1} more` : ''}`,
  url: zeroDays[0].u, tag: `zd-${zeroDays[0].id}` }, urgency: 'high' };
if (newPocs.length) { const id = newPocs[0], i = cves.info?.[id] || {}, k = (cves.kev || []).find(x => x.id === id);
  shared.exploit = { m: {
    title: `Exploit released: ${id}${i.s != null ? ` (CVSS ${i.s})` : ''}`,
    body: `${k ? `${k.v} ${k.p} · actively exploited` : cut(i.t || i.vp || 'Public proof-of-concept code is now available', 90)}${newPocs.length > 1 ? `\n+${newPocs.length - 1} more` : ''}`,
    url: `${SITE}?tab=cves#${id}`, tag: `poc-${id}` }, urgency: 'high' }; }
if (bigBreaches.length) shared.breach = { m: {
  title: `Breach: ${fmtCount(bigBreaches[0].rc)} ${bigBreaches[0].ru || 'records'}`,
  body: `${cut(bigBreaches[0].t, 110)}${bigBreaches.length > 1 ? `\n+${bigBreaches.length - 1} more large breach${bigBreaches.length > 2 ? 'es' : ''}` : ''}`,
  url: bigBreaches[0].u, tag: `breach-${bigBreaches[0].id}` } };
if (majors.length) shared.major = { m: {
  title: `Major story (${majors[0].r.length + 1} outlets)`,
  body: cut(majors[0].t, 130), url: majors[0].u, tag: `major-${majors[0].id}` } };

// Messages that depend on the subscriber's vendors or country.
function stackMsg(vendors) {
  const v = new Set(vendors.map(x => x.toLowerCase()));
  const mine = fresh.filter(s => s.ve.some(x => v.has(x.toLowerCase()))).sort((a, b) => b.r.length - a.r.length);
  if (!mine.length) return null;
  const who = mine[0].ve.find(x => v.has(x.toLowerCase()));
  return { title: `Your stack · ${who}: ${cut(mine[0].t, 80)}`, body: mine.length > 1 ? `+${mine.length - 1} more stor${mine.length > 2 ? 'ies' : 'y'} about your vendors` : mine[0].s, url: mine[0].u, tag: `stack-${mine[0].id}` };
}
function countryMsg(c) {
  const claims = newClaims.filter(v => v.c === c), alerts = newAlerts.filter(s => countryOf(s) === c);
  const n = claims.length + alerts.length; if (!n) return null;
  const first = alerts[0] ? { what: cut(alerts[0].t.replace(/\s*\([^)]*\)/, ''), 100), url: alerts[0].u } : { what: `${claims[0].g} claims ${claims[0].t}`, url: `${SITE}?tab=ransomware` };
  return { title: `Attack${n > 1 ? 's' : ''} in ${countryName(c)}${n > 1 ? ` (${n})` : ''}`, body: `${first.what}${n > 1 ? `\n+${n - 1} more` : ''}${claims.length && !alerts.length ? '\nClaimed by the attackers; unverified' : ''}`, url: first.url, tag: `country-${c}-${Date.now()}` };
}

const anything = Object.keys(shared).length || fresh.length || newClaims.length;
const subs = state && anything ? await subscribers() : [];
let sent = 0, removed = 0;
for (const s of subs) {
  const out = [];
  for (const t of ['kev', 'zeroday', 'exploit', 'breach', 'major']) if (s.topics.includes(t) && shared[t]) out.push(shared[t]);
  if (s.topics.includes('stack') && s.vendors?.length) { const m = stackMsg(s.vendors); if (m) out.push({ m }); }
  if (s.topics.includes('country') && s.country) { const m = countryMsg(s.country); if (m) out.push({ m }); }
  for (const { m, urgency } of out.slice(0, PER_RUN)) {
    if (process.env.PUSH_DEBUG) log(`  -> ${s.id.slice(0, 8)}: ${m.title}`);          // titles only, for diagnosing
    if (!(await send(s, m, urgency))) { removed++; break; }
    sent++;
  }
}

// Remember what was seen (recent items only, so the file stays small).
await fs.mkdir(path.dirname(STATE), { recursive: true });
await fs.writeFile(STATE, JSON.stringify({ ...now, at: Date.now() }));
log(`${subs.length} subscribers · new: ${newKev.length} KEV, ${zeroDays.length} zero-day, ${newPocs.length} exploits, ${bigBreaches.length} big breaches, ${majors.length} major, ${newClaims.length} claims, ${fresh.length} stories · sent ${sent}, removed ${removed}`);
