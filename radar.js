// Internet pulse: a snapshot of Cloudflare Radar (https://radar.cloudflare.com) for the "Internet pulse"
// section. Called from build.js; writes public/data/radar.json. Free API, needs a token:
//
//   CLOUDFLARE_API_TOKEN=...   a Cloudflare API token with the "Account > Radar > Read" permission
//                              (docs/SETUP.md has the steps). Without it nothing is fetched: the last
//                              snapshot (cache/radar.json) is reused for up to 3 days, then the section
//                              disappears from the site.
//
// Every part is fetched on its own, so one failing call keeps the previous copy of that part.

import fs from 'node:fs/promises';
import path from 'node:path';

const API = 'https://api.cloudflare.com/client/v4/radar';
const DAY = 864e5;
const KEEP_STALE = 3 * DAY;

const ms = v => v == null || v === '' ? null : typeof v === 'number' ? (v < 1e12 ? v * 1000 : v) : (Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(v) ? v : v + 'Z') || null);
const pct = v => Math.round(parseFloat(v) * 10) / 10;
const LABELS = { DDOS: 'DDoS protection', WAF: 'WAF', BOT_MANAGEMENT: 'Bot management', ACCESS_RULES: 'Access rules', IP_REPUTATION: 'IP reputation', API_SHIELD: 'API Shield', DATA_LOSS_PREVENTION: 'Data loss prevention' };
// API values like GOVERNMENT_DIRECTED become "Government directed"; short codes (UDP, SYN) and mixed-case names stay as they are.
const nice = v => { const s = String(v || ''); if (LABELS[s]) return LABELS[s]; if (s !== s.toUpperCase() || /^[A-Z0-9-]{2,5}$/.test(s)) return s; return s.toLowerCase().replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase()); };

async function get(token, p, params = {}) {
  const u = new URL(API + p);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  u.searchParams.set('format', 'JSON');
  const r = await fetch(u, { headers: { authorization: `Bearer ${token}`, accept: 'application/json', 'user-agent': 'ThreatRecap/1.0 (+https://github.com/)' }, signal: AbortSignal.timeout(30000) });
  const j = await r.json().catch(() => null);
  if (!r.ok || !j?.success) throw new Error(`HTTP ${r.status}${j?.errors?.[0]?.message ? ` ${j.errors[0].message}` : ''}`);
  return j.result_info ? { ...j.result, result_info: j.result_info } : j.result;   // paging totals sit beside result
}

const topList = (res, key) => (res?.top_0 || []).map(x => [x[`${key}CountryAlpha2`], x[`${key}CountryName`], pct(x.value)]).filter(x => x[0]);
const summary = res => Object.entries(res?.summary_0 || {}).map(([k, v]) => [nice(k), pct(v)]).filter(x => x[1] > 0).sort((a, b) => b[1] - a[1]);
const asnName = info => { const m = {}; for (const a of info || []) m[a.asn] = [a.org_name, a.country_code]; return m; };

// Each part: [name, fetch + reshape]
const PARTS = {
  outages: async t => (await get(t, '/annotations/outages', { dateRange: '14d', limit: 40 })).annotations.map(a => ({
    id: a.id, s: ms(a.startDate), e: ms(a.endDate), cause: nice(a.outage?.outageCause), type: nice(a.outage?.outageType), scope: a.scope || '',
    desc: a.description || '', link: a.linkedUrl || '',
    loc: (a.locationsDetails || []).map(l => [l.code, l.name]), asn: (a.asnsDetails || []).slice(0, 4).map(x => [x.asn, x.name]),
  })).sort((a, b) => b.s - a.s),
  l7Target: async t => topList(await get(t, '/attacks/layer7/top/locations/target', { dateRange: '7d', limit: 10 }), 'target'),
  l7Origin: async t => topList(await get(t, '/attacks/layer7/top/locations/origin', { dateRange: '7d', limit: 10 }), 'origin'),
  l7Industry: async t => summary(await get(t, '/attacks/layer7/summary/INDUSTRY', { dateRange: '7d', limitPerGroup: 10 })),
  l7Mitigation: async t => summary(await get(t, '/attacks/layer7/summary/MITIGATION_PRODUCT', { dateRange: '7d' })),
  l3Target: async t => topList(await get(t, '/attacks/layer3/top/locations/target', { dateRange: '7d', limit: 10 }), 'target'),
  l3Vector: async t => summary(await get(t, '/attacks/layer3/summary/VECTOR', { dateRange: '7d', limitPerGroup: 8 })),
  l3Industry: async t => summary(await get(t, '/attacks/layer3/summary/INDUSTRY', { dateRange: '7d', limitPerGroup: 10 })),
  hijacks: async t => {
    const r = await get(t, '/bgp/hijacks/events', { dateRange: '7d', minConfidence: 8, sortBy: 'TIME', sortOrder: 'DESC', per_page: 25 });
    const n = asnName(r.asn_info);
    return { total: r.result_info?.total_count ?? r.events?.length ?? 0, events: (r.events || []).map(e => ({
      id: e.id, s: ms(e.min_hijack_ts), e: ms(e.max_hijack_ts), conf: e.confidence_score, dur: e.duration,
      by: [e.hijacker_asn, n[e.hijacker_asn]?.[0] || '', e.hijacker_country || n[e.hijacker_asn]?.[1] || ''],
      victims: (e.victim_asns || []).slice(0, 3).map(a => [a, n[a]?.[0] || '']), vc: e.victim_countries || [],
      prefixes: (e.prefixes || []).slice(0, 3), np: (e.prefixes || []).length, stale: !!e.is_stale,
    })) };
  },
  leaks: async t => {
    const r = await get(t, '/bgp/leaks/events', { dateRange: '7d', sortBy: 'TIME', sortOrder: 'DESC', per_page: 25 });
    const n = asnName(r.asn_info);
    return { total: r.result_info?.total_count ?? r.events?.length ?? 0, events: (r.events || []).map(e => ({
      id: e.id, s: ms(e.min_ts ?? e.detected_ts), e: ms(e.max_ts), by: [e.leak_asn, n[e.leak_asn]?.[0] || '', n[e.leak_asn]?.[1] || ''],
      prefixes: e.prefix_count, origins: e.origin_count, peers: e.peer_count, countries: e.countries || [], done: !!e.finished,
    })) };
  },
};

export async function buildRadar({ root, log = console.log }) {
  const cacheFile = path.join(root, 'cache', 'radar.json'), out = path.join(root, 'public', 'data', 'radar.json');
  let prev = null; try { prev = JSON.parse(await fs.readFile(cacheFile, 'utf8')); } catch {}
  const token = (process.env.CLOUDFLARE_API_TOKEN || '').trim();
  const now = Date.now();
  let snap = prev;
  if (!token) log('Internet pulse: skipped (no CLOUDFLARE_API_TOKEN)');
  else {
    const parts = { ...(prev?.parts || {}) }, at = { ...(prev?.at || {}) }, failed = [];
    await Promise.all(Object.entries(PARTS).map(async ([k, fn]) => {
      try { parts[k] = await fn(token); at[k] = now; } catch (e) { failed.push(`${k} (${e.message})`); }
    }));
    log(`Internet pulse: ${Object.keys(PARTS).length - failed.length}/${Object.keys(PARTS).length} parts from Cloudflare Radar${failed.length ? '; failed: ' + failed.join(', ') : ''}`);
    if (failed.length < Object.keys(PARTS).length) snap = { generated: now, parts, at };
    // Parts that keep failing are dropped once they are older than KEEP_STALE.
    if (snap) for (const k of Object.keys(snap.parts)) if (now - (snap.at[k] || 0) > KEEP_STALE) { delete snap.parts[k]; delete snap.at[k]; }
    if (snap) await fs.writeFile(cacheFile, JSON.stringify(snap));
  }
  if (snap && Object.keys(snap.parts || {}).length && now - snap.generated < KEEP_STALE) {
    await fs.writeFile(out, JSON.stringify({ ...snap.parts, generated: snap.generated }));
    return true;
  }
  await fs.rm(out, { force: true }).catch(() => {});
  return false;
}
