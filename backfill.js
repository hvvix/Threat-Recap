#!/usr/bin/env node
// One-time backfill of this year's history into cache/archive/.
//
//   node backfill.js              news (Wayback Machine + feed paging) and all CVEs of the year
//   node backfill.js --news       news only        node backfill.js --cves   CVEs only
//   node backfill.js --only "Krebs on Security"   one source (use --force to redo a finished one)
//
// News: every feed's history is rebuilt from Wayback Machine snapshots of the feed itself.
// Walking backwards from today, it fetches a snapshot, notes the oldest item in it, then jumps
// to the newest snapshot taken before that item — so windows overlap with as few requests as
// possible. Feeds the Wayback Machine never saved fall back to WordPress-style ?paged=N.
// Requests are rate limited (about one per second) and back off when archive.org asks us to.
// Progress is saved after every source; re-running continues where it stopped.

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseFeed, fetchRaw, decodeBody, linkKey, normLink, analyse, nvdCvss, clip } from './build.js';
import { NOISE, RELEVANCE } from './taxonomy.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const ARCH = path.join(ROOT, 'cache', 'archive');
const YEAR = new Date().getUTCFullYear();
const START = Date.UTC(YEAR, 0, 1);
const NOW = Date.now();
const DAY = 864e5;
const UA = 'ThreatRecap-archive/1.0 (one-time backfill of public RSS history; polite, ~1 req/s)';
const args = process.argv.slice(2);
const want = k => args.includes(k);
const only = args.includes('--only') ? args[args.indexOf('--only') + 1] : null;
const doNews = !want('--cves') || want('--news'), doCves = !want('--news') || want('--cves');
const log = (...a) => console.log(`[${new Date().toISOString().slice(11, 19)}]`, ...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const readJSON = async (f, d) => { try { return JSON.parse(await fs.readFile(f, 'utf8')); } catch { return d; } };
const writeJSON = (f, v) => fs.writeFile(f, JSON.stringify(v));

// ---------- polite fetching ----------
let gap = 1100, last = 0;
async function gate() { const wait = last + gap - Date.now(); if (wait > 0) await sleep(wait); last = Date.now(); }
async function politeFetch(url, { timeout = 60000 } = {}) {
  for (let attempt = 0; attempt < 5; attempt++) {
    await gate();
    try {
      const r = await fetch(url, { headers: { 'user-agent': UA }, redirect: 'follow', signal: AbortSignal.timeout(timeout) });
      if (r.status === 429 || r.status >= 500) {
        gap = Math.min(gap * 1.5, 6000);
        const pause = 20000 * (attempt + 1);
        log(`  archive.org said ${r.status}; pausing ${pause / 1000}s and slowing to 1 request / ${(gap / 1000).toFixed(1)}s`);
        await sleep(pause); continue;
      }
      return r;
    } catch (e) { await sleep(5000 * (attempt + 1)); }
  }
  return null;
}
const tsMs = ts => Date.UTC(+ts.slice(0, 4), +ts.slice(4, 6) - 1, +ts.slice(6, 8), +ts.slice(8, 10) || 0, +ts.slice(10, 12) || 0);

async function snapshots(feed) {
  const u = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(feed.replace(/^https?:\/\//, ''))}&from=${YEAR}0101&output=json&fl=timestamp&filter=statuscode:200&collapse=timestamp:10`;
  const r = await politeFetch(u, { timeout: 90000 });
  if (!r?.ok) return [];
  try { return (await r.json()).slice(1).map(x => x[0]); } catch { return []; }
}

// ---------- news ----------
function keep(it, src) {
  if (!it.title || !it.link || isNaN(it.date) || it.date < START || it.date > NOW + DAY) return false;
  if (NOISE.test(it.title)) return false;
  if (src.filter && !RELEVANCE.test(`${it.title} ${it.summary}`)) return false;
  return true;
}
function compact(it, src) {
  const a = analyse({ title: it.title, summary: it.summary || '' }, src, {}, NOW);
  return { t: it.title, u: normLink(it.link), s: src.name, d: it.date, x: clip(it.summary || '', 220), cv: a.cves.slice(0, 8), tg: a.tags, ac: a.actors, ve: a.vendors, ct: a.cats, tp: a.topics };
}

async function viaWayback(src, add) {
  const snaps = await snapshots(src.feed);
  if (!snaps.length) return { method: 'none', fetched: 0 };
  let idx = snaps.length - 1, fetched = 0;
  const maxFetch = Number(process.env.MAX_SNAPSHOTS || 320);
  while (idx >= 0 && fetched < maxFetch) {
    const r = await politeFetch(`https://web.archive.org/web/${snaps[idx]}id_/${src.feed}`);
    fetched++;
    let items = [];
    if (r?.ok) { try { items = parseFeed(decodeBody(Buffer.from(await r.arrayBuffer()), r.headers.get('content-type'))); } catch {} }
    const dated = items.filter(i => !isNaN(i.date));
    for (const it of items) if (keep(it, src)) add(it);
    if (!dated.length) { idx--; continue; }
    const oldest = Math.min(...dated.map(i => i.date));
    if (oldest <= START) break;
    const target = oldest + 12 * 3600e3;               // overlap windows by half a day
    let next = -1;
    for (let i = idx - 1; i >= 0; i--) if (tsMs(snaps[i]) <= target) { next = i; break; }
    if (next < 0) break;
    idx = next;
  }
  return { method: 'wayback', fetched, snapshots: snaps.length };
}

async function viaPaging(src, add) {
  let fetched = 0, prevFirst = '';
  for (let page = 2; page <= 60; page++) {
    const u = src.feed + (src.feed.includes('?') ? '&' : '?') + 'paged=' + page;
    let items = [];
    try {
      await gate();
      const { r, buf } = await fetchRaw(u, { ua: 'Mozilla/5.0 (compatible; ThreatRecap/1.0)', timeout: 30000 });
      fetched++;
      if (!r.ok) break;
      items = parseFeed(decodeBody(buf, r.headers.get('content-type')));
    } catch { break; }
    if (!items.length || items[0].link === prevFirst) break;   // feed ignores ?paged — stop
    prevFirst = items[0].link;
    for (const it of items) if (keep(it, src)) add(it);
    const dated = items.filter(i => !isNaN(i.date));
    if (dated.length && Math.min(...dated.map(i => i.date)) < START) break;
  }
  return { method: 'paging', fetched };
}

async function backfillNews() {
  await fs.mkdir(ARCH, { recursive: true });
  const sources = (await readJSON(path.join(ROOT, 'sources.json'), [])).filter(s => s.feed && !s.bulk && s.cat !== 'tool' && s.cat !== 'social' && (!only || s.name === only));
  const progress = await readJSON(path.join(ARCH, 'coverage.json'), {});
  const months = {};                                   // 'YYYY-MM' -> Map(key -> item)
  const monthFile = m => path.join(ARCH, `news-${m}.json`);
  const load = async m => { if (!months[m]) months[m] = new Map((await readJSON(monthFile(m), [])).map(i => [linkKey(i.u), i])); return months[m]; };
  let total = 0;
  for (const [n, src] of sources.entries()) {
    if (progress[src.name]?.done && !want('--force')) continue;
    log(`(${n + 1}/${sources.length}) ${src.name}`);
    const found = new Map();
    const add = it => { const k = linkKey(it.link); if (!found.has(k)) found.set(k, it); };
    // the live feed first (newest items), then history
    try { const { r, buf } = await fetchRaw(src.feed, { timeout: 30000 }); if (r.ok) for (const it of parseFeed(decodeBody(buf, r.headers.get('content-type')))) if (keep(it, src)) add(it); } catch {}
    let res = await viaWayback(src, add);
    const earliest = () => Math.min(...[...found.values()].map(i => i.date));
    if (res.method === 'none' || (found.size && earliest() > START + 30 * DAY)) {
      const p = await viaPaging(src, add);
      res = res.method === 'none' ? p : { ...res, paging: p.fetched };
    }
    for (const it of found.values()) {
      const m = new Date(it.date).toISOString().slice(0, 7);
      (await load(m)).set(linkKey(it.link), compact(it, src));
    }
    const first = found.size ? earliest() : null;
    progress[src.name] = { done: true, items: found.size, first, ...res, at: Date.now() };
    total += found.size;
    log(`   ${found.size} items${first ? ` back to ${new Date(first).toISOString().slice(0, 10)}` : ''} via ${res.method}${res.fetched ? ` (${res.fetched} requests)` : ''}`);
    for (const [m, map] of Object.entries(months)) await writeJSON(monthFile(m), [...map.values()].sort((a, b) => b.d - a.d));
    await writeJSON(path.join(ARCH, 'coverage.json'), progress);
  }
  log(`News backfill finished: ${total} items this run.`);
}

// ---------- all CVEs of the year from NVD ----------
async function backfillCves() {
  await fs.mkdir(ARCH, { recursive: true });
  const key = process.env.NVD_API_KEY;
  const byMonth = {};
  const fmt = d => new Date(d).toISOString().replace('Z', '').slice(0, 23) + 'Z';
  for (let from = START; from < NOW; from += 110 * DAY) {
    const to = Math.min(from + 110 * DAY, NOW);
    let idx = 0, totalResults = Infinity;
    while (idx < totalResults) {
      const u = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${fmt(from)}&pubEndDate=${fmt(to)}&resultsPerPage=2000&startIndex=${idx}&noRejected`;
      let j = null;
      for (let a = 0; a < 5 && !j; a++) {
        try { const { r, buf } = await fetchRaw(u, { accept: 'application/json', timeout: 120000, headers: key ? { apiKey: key } : {} }); if (r.ok) j = JSON.parse(buf.toString('utf8')); else await sleep(15000); }
        catch { await sleep(15000); }
      }
      if (!j) { log('NVD request kept failing; stopping this range'); break; }
      totalResults = j.totalResults;
      for (const { cve } of j.vulnerabilities) {
        const desc = (cve.descriptions.find(d => d.lang === 'en') || {}).value || '';
        const sc = nvdCvss(cve.metrics);
        const p = Date.parse(cve.published + 'Z');
        (byMonth[new Date(p).toISOString().slice(0, 7)] ||= []).push({ id: cve.id, p, s: sc?.s, v: sc?.v, x: clip(desc, 200), cwe: cve.weaknesses?.[0]?.description?.[0]?.value });
      }
      log(`NVD ${new Date(from).toISOString().slice(0, 10)}…${new Date(to).toISOString().slice(0, 10)}: ${Math.min(idx + 2000, totalResults)}/${totalResults}`);
      idx += 2000;
      await sleep(key ? 1200 : 6500);
    }
  }
  for (const [m, list] of Object.entries(byMonth)) await writeJSON(path.join(ARCH, `cves-${m}.json`), list.sort((a, b) => b.p - a.p));
  log(`CVE backfill finished: ${Object.values(byMonth).reduce((a, l) => a + l.length, 0)} CVEs in ${Object.keys(byMonth).length} months.`);
}

(async () => {
  if (doCves) await backfillCves();
  if (doNews) await backfillNews();
})().catch(e => { console.error(e); process.exit(1); });
