#!/usr/bin/env node
// Threat Recap build: fetch every feed + data source, tag and cluster the
// stories, and write static JSON into public/data. No dependencies (Node 18+).
//
//   node build.js            full build
//   NVD_API_KEY=...          optional, raises NVD rate limits
//   GITHUB_TOKEN=...         optional, raises GitHub API rate limits
//   SITE_URL=https://...     optional, absolute links for sitemap/share previews
//   ANTHROPIC_API_KEY=...    optional, one-line AI "why it matters" notes (npm install first)

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CVE_RE, TAG_RULES, ACTORS, ACTOR_PATTERNS, VENDORS, ATTACK, RELEVANCE, NOISE, MALWARE_RE } from './taxonomy.js';
import { writeDigestPage } from './digest.js';
import { extractIocs, fetchArticleText, fetchPocs, fetchHibp, buildWorld, aiSummaries, aiCveExplain, fetchTenable } from './enrich.js';
import { buildIncidents, breachSize } from './incidents.js';
import { writeArchive } from './archive.js';
import { LANDMARKS } from './landmarks.js';
import { writeSite } from './site.js';
import { catRegex, PRODUCTS } from './topics.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(ROOT, 'public', 'data');
const CACHE = path.join(ROOT, 'cache');
const DAY = 864e5;
const KEEP_DAYS = 30;          // story history window
const KEEP_BULK = 60;          // newest N items kept for bulk advisory feeds
const MAX_PER_SOURCE = 150;
const SUMMARY_LEN = 260;
const NVD_KEY = process.env.NVD_API_KEY || '';
const GH_TOKEN = process.env.GITHUB_TOKEN || '';
const BOT_UA = 'Mozilla/5.0 (compatible; ThreatRecap/1.0; RSS reader; +https://github.com/)';
const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';

const log = (...a) => console.log(`[${new Date().toISOString().slice(11, 19)}]`, ...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const readJSON = async (f, dflt) => { try { return JSON.parse(await fs.readFile(f, 'utf8')); } catch { return dflt; } };
const writeJSON = (f, v) => fs.writeFile(f, JSON.stringify(v));

export async function pool(list, n, fn) {
  const out = new Array(list.length); let i = 0;
  await Promise.all(Array.from({ length: n }, async () => { while (i < list.length) { const k = i++; out[k] = await fn(list[k], k); } }));
  return out;
}

export async function fetchRaw(url, { ua = BOT_UA, accept = '*/*', timeout = 25000, headers = {} } = {}) {
  const r = await fetch(url, { headers: { 'user-agent': ua, accept, ...headers }, redirect: 'follow', signal: AbortSignal.timeout(timeout) });
  const buf = Buffer.from(await r.arrayBuffer());
  return { r, buf };
}
async function fetchJSON(url, opts = {}) {
  const { r, buf } = await fetchRaw(url, { accept: 'application/json', timeout: 90000, ...opts });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return JSON.parse(buf.toString('utf8'));
}

// ---------- feed parsing ----------
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', hellip: '…', mdash: '—', ndash: '–', rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“', copy: '©', reg: '®', trade: '™', bull: '•', middot: '·', laquo: '«', raquo: '»', eacute: 'é', egrave: 'è', uuml: 'ü', ouml: 'ö', auml: 'ä', szlig: 'ß' };
const decodeEntities = s => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
  if (e[0] === '#') { const c = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return Number.isFinite(c) && c > 0 && c < 0x110000 ? String.fromCodePoint(c) : ''; }
  return ENT[e.toLowerCase()] ?? m;
});
const unCdata = s => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
function toText(s) {
  if (!s) return '';
  s = unCdata(s);
  if (/&lt;/.test(s)) s = decodeEntities(s);             // escaped HTML inside XML
  s = s.replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<br\s*\/?>|<\/p>/gi, ' ').replace(/<[^>]+>/g, ' ');
  return decodeEntities(s).replace(/\s+/g, ' ').trim();
}
const tag = (b, name) => { const m = b.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i')); return m ? m[1] : ''; };

function parseLink(b) {
  const orig = tag(b, 'feedburner:origLink'); if (orig) return toText(orig);
  const links = [...b.matchAll(/<link\b([^>]*?)\/?>(?:([^<]*)<\/link>)?/gi)];
  for (const [, attrs] of links) {
    const href = (attrs.match(/href=["']([^"']+)/i) || [])[1]; const rel = (attrs.match(/rel=["']([^"']+)/i) || [])[1];
    if (href && (!rel || rel === 'alternate')) return decodeEntities(href);
  }
  for (const [, , text] of links) if (text && text.trim()) return toText(text);
  const guid = b.match(/<guid(?:\s[^>]*)?>([\s\S]*?)<\/guid>/i);
  if (guid && /^https?:/.test(toText(guid[1]))) return toText(guid[1]);
  const id = tag(b, 'id'); if (/^https?:/.test(toText(id))) return toText(id);
  return '';
}

function parseDate(s) {
  s = toText(s); if (!s) return NaN;
  let t = Date.parse(s);
  if (isNaN(t)) t = Date.parse(s.replace(/\b(EDT|EST|CDT|CST|PDT|PST|UT)\b/, m => ({ EDT: '-0400', EST: '-0500', CDT: '-0500', CST: '-0600', PDT: '-0700', PST: '-0800', UT: '+0000' })[m]));
  if (isNaN(t)) t = Date.parse(s.replace(/^\w+,\s*/, ''));
  return t;
}

// Preview image: media:content / media:thumbnail / image enclosure / first <img> in the item.
function feedImage(b, html) {
  const attr = (re) => { const m = b.match(re); return m ? decodeEntities(m[1]) : ''; };
  let u = attr(/<media:content[^>]+url=["']([^"']+)["'][^>]*(?:medium=["']image|type=["']image)/i) || attr(/<media:content[^>]+(?:medium=["']image|type=["']image)[^>]+url=["']([^"']+)/i)
    || attr(/<media:thumbnail[^>]+url=["']([^"']+)/i) || attr(/<enclosure[^>]+url=["']([^"']+)["'][^>]*type=["']image/i) || attr(/<enclosure[^>]+type=["']image[^>]+url=["']([^"']+)/i);
  if (!u) { const h = /&lt;img/i.test(html) ? decodeEntities(html) : html; const m = h.match(/<img[^>]+src=["']([^"']+)["']/i); if (m) u = decodeEntities(m[1]); }
  if (!u || !/^https?:\/\//i.test(u) || /(pixel|tracking|feedburner|gravatar|emoji|spacer|1x1|wp-includes|\.svg(\?|$)|share-button|icon)/i.test(u)) return '';
  return u.slice(0, 500);
}

export function parseFeed(xml) {
  const blocks = xml.match(/<(item|entry)\b[\s\S]*?<\/\1>/gi) || [];
  return blocks.map(b => {
    const rawHtml = unCdata(tag(b, 'content:encoded') || tag(b, 'content') || tag(b, 'description') || tag(b, 'summary'));
    const full = toText(rawHtml);
    const rawTitle = toText(tag(b, 'title'));
    return {
    title: rawTitle || (full.length > 140 ? full.slice(0, 140).replace(/\s+\S*$/, '') + '…' : full),
    content: full.length > 1500 ? full.slice(0, 200000) : '',
    img: feedImage(b, rawHtml),
    link: parseLink(b),
    date: parseDate(tag(b, 'pubDate') || tag(b, 'published') || tag(b, 'dc:date') || tag(b, 'updated') || tag(b, 'issued') || tag(b, 'a10:updated')),
    summary: toText(tag(b, 'description') || tag(b, 'summary') || tag(b, 'content:encoded') || tag(b, 'content'))
      .replace(/\s*The post .{0,400}? appeared first on .{0,100}$/i, '').replace(/\s*(Continue reading|Read more)\s*(»|→|\.\.\.)?\s*$/i, '').slice(0, 1200),
  }; }).filter(i => i.title && /^https?:\/\//i.test(i.link.trim())); // web links only: never javascript:, data: etc.
}

export function decodeBody(buf, contentType) {
  const head = buf.subarray(0, 300).toString('latin1');
  const cs = ((contentType || '').match(/charset=([\w-]+)/i) || head.match(/encoding=["']([\w-]+)/i) || [])[1] || 'utf-8';
  try { return new TextDecoder(cs.toLowerCase()).decode(buf); } catch { return buf.toString('utf8'); }
}

async function fetchFeed(src) {
  let lastErr = '';
  for (const ua of [BOT_UA, BROWSER_UA]) {
    try {
      const { r, buf } = await fetchRaw(src.feed, { ua, accept: 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5' });
      if (!r.ok) { lastErr = `HTTP ${r.status}`; continue; }
      const items = parseFeed(decodeBody(buf, r.headers.get('content-type')));
      if (items.length) return { items };
      lastErr = 'no items (not a feed?)';
    } catch (e) { lastErr = e.cause?.code || e.name || String(e); }
  }
  return { items: [], error: lastErr };
}

// ---------- normalisation & tagging ----------
export function normLink(u) {
  try {
    const x = new URL(u.trim());
    if (!/^https?:$/.test(x.protocol)) return '';
    for (const k of [...x.searchParams.keys()]) if (/^(utm_|fbclid|gclid|mc_|ref$|source$)/i.test(k)) x.searchParams.delete(k);
    x.hash = '';
    return x.toString();
  } catch { return ''; }
}
export const linkKey = u => normLink(u).replace(/^https?:\/\/(www\.)?/i, '').replace(/\/$/, '').toLowerCase();

export function analyse(it, src, kev, now) {
  const text = `${it.title} ${it.summary}`;
  const head = it.title;
  const cves = [...new Set((text.match(CVE_RE) || []).map(c => c.toUpperCase()))];
  const tags = new Set();
  if (src.cat === 'research') tags.add('research');
  if (src.cat === 'advisory') tags.add('advisory');
  for (const [t, re] of Object.entries(TAG_RULES)) {
    // Broad tags must hit the headline; specific ones may come from the summary.
    const scope = ['ai', 'law', 'malware', 'phishing', 'breach'].includes(t) ? head : text;
    if (re.test(scope)) tags.add(t);
  }
  if (cves.length) tags.add('vuln');
  if (cves.some(c => kev[c] && now - Date.parse(kev[c].d) < 21 * DAY)) tags.add('zeroday');
  const actors = new Set();
  for (const [name, re] of ACTORS) if (re.test(text)) actors.add(name);
  for (const re of ACTOR_PATTERNS) for (const m of text.match(re) || []) {
    const n = m.replace(/^APT ?(\d+)$/i, 'APT$1');
    if (![...actors].some(a => a.replace(/\s/g, '') === n)) actors.add(n);
  }
  if (actors.size) tags.add('apt');
  const vendors = VENDORS.filter(([, re]) => re.test(head)).map(([n]) => n);
  const attack = ATTACK.filter(([, , re]) => re.test(text)).map(([id]) => id);
  const malware = MALWARE_RE.filter(([, re]) => re.test(text)).map(([n]) => n);
  if (malware.length) tags.add('malware');
  // Technical categories: headline matches first, then summary; at most 3.
  const cats = catRegex.filter(([, re]) => re.test(head)).map(([c]) => c);
  for (const [c, re] of catRegex) if (cats.length < 3 && !cats.includes(c) && re.test(it.summary)) cats.push(c);
  const topics = PRODUCTS.filter(([, , re]) => re.test(text)).map(([n]) => n);
  return { cves, tags: [...tags], actors: [...actors].slice(0, 6), vendors: vendors.slice(0, 5), attack: attack.slice(0, 6), malware: malware.slice(0, 5), cats: cats.slice(0, 3), topics: topics.slice(0, 6) };
}

// ---------- clustering (same story from several outlets) ----------
const STOP = new Set('a an the and or of to in on for with by from at as is are was were be been has have had it its this that these those new over after amid into about via vs how why what who more than out up can could will would may might not no now just their they them our your you we us his her he she says said report reports update updates patch patches fixes fix flaw flaws vulnerability vulnerabilities security attack attacks attackers hackers hacker cyber cybersecurity data warns warning critical exploited exploit issues issue users'.split(' '));
const tokens = t => new Set(t.toLowerCase().replace(/cve-\d{4}-\d+/g, ' ').match(/[a-z0-9][a-z0-9.+-]{2,}/g)?.filter(w => !STOP.has(w)) || []);
function jaccard(a, b) { let n = 0; for (const x of a) if (b.has(x)) n++; return n / (a.size + b.size - n || 1); }

// Recurring boilerplate headlines that must never anchor a merge.
const GENERIC = /^(CISA Adds .* to Catalog|CISA Releases .* (Industrial Control Systems )?Advisories|ISC Stormcast|Week in review|This week in|Weekly Update|SANS ISC Stormcast)/i;

function cluster(items) {
  const parent = items.map((_, i) => i);
  const find = i => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  // Each cluster holds at most one item per outlet; this also stops long chains
  // of look-alike headlines ("CISA adds two KEVs…") from snowballing.
  const srcs = items.map(i => new Set([i.source]));
  const union = (a, b) => {
    a = find(a); b = find(b); if (a === b) return;
    for (const s of srcs[b]) if (srcs[a].has(s)) return;
    const [r, c] = a < b ? [a, b] : [b, a];
    parent[c] = r; for (const s of srcs[c]) srcs[r].add(s);
  };
  const tok = items.map(i => tokens(i.title));
  const order = items.map((_, i) => i).sort((a, b) => items[a].date - items[b].date);
  for (let x = 0; x < order.length; x++) {
    const i = order[x], A = items[i];
    for (let y = x + 1; y < order.length; y++) {
      const j = order[y], B = items[j];
      const gap = B.date - A.date;
      if (gap > 7 * DAY) break;
      if (A.source === B.source || A.social || B.social || GENERIC.test(A.title) || GENERIC.test(B.title)) continue;
      const cvesA = A.cves, cvesB = B.cves;
      const shareCve = cvesA.length && cvesA.length <= 3 && cvesB.length && cvesB.length <= 3 && cvesA.some(c => cvesB.includes(c));
      const sim = tok[i].size >= 3 && tok[j].size >= 3 ? jaccard(tok[i], tok[j]) : 0;
      if ((shareCve && (sim >= 0.12 || A.bulk || B.bulk)) || (gap < 3 * DAY && sim >= 0.5)) union(i, j);
    }
  }
  const groups = new Map();
  items.forEach((it, i) => { const r = find(i); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(it); });
  return [...groups.values()];
}

function toStory(group) {
  const byDate = group.sort((a, b) => a.date - b.date);
  const primary = byDate.find(i => !i.bulk && i.cat !== 'advisory') || byDate.find(i => !i.bulk) || byDate[0];
  const uniq = arr => [...new Set(arr)];
  const all = f => uniq(group.flatMap(f));
  const firstSeen = Math.min(...group.map(i => i.firstSeen));
  const id = group.slice().sort((a, b) => a.firstSeen - b.firstSeen || (a.key < b.key ? -1 : 1))[0].key;
  return {
    id: hash(id),
    t: primary.title, u: primary.link, s: primary.source, c: primary.cat, d: primary.date, f: firstSeen,
    lu: Math.max(...group.map(i => i.date)),
    x: clip(primary.summary, SUMMARY_LEN),
    tg: all(i => i.tags), cv: all(i => i.cves).slice(0, 20), ac: all(i => i.actors).slice(0, 6),
    ve: all(i => i.vendors).slice(0, 5), at: all(i => i.attack).slice(0, 6), mw: all(i => i.malware).slice(0, 5),
    ct: primary.cats?.length ? primary.cats : all(i => i.cats || []).slice(0, 3), tp: all(i => i.topics || []).slice(0, 6),
    im: primary.img || group.find(i => i.img)?.img || undefined,
    b: group.every(i => i.bulk) ? 1 : 0, so: primary.social ? 1 : 0,
    keys: group.map(i => i.key),
    r: byDate.filter(i => i !== primary).map(i => [i.source, i.title, i.link, i.date]).slice(0, 30),
  };
}
export const clip = (s, n) => (s.length > n ? s.slice(0, n).replace(/\s+\S*$/, '') + '…' : s);
function hash(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0).toString(36); }

// ---------- CVE enrichment ----------
function pickCvss(metricsList) {
  // metricsList: array of CVE-JSON-5 metric objects (cna + adp)
  const pref = ['cvssV3_1', 'cvssV4_0', 'cvssV3_0', 'cvssV2_0'];
  for (const k of pref) for (const m of metricsList) if (m?.[k]?.baseScore != null) {
    const d = m[k]; return { s: d.baseScore, v: (d.baseSeverity || sevOf(d.baseScore)).toUpperCase(), k: k.replace('cvssV', '').replace('_', '.') };
  }
  return null;
}
const sevOf = s => (s >= 9 ? 'CRITICAL' : s >= 7 ? 'HIGH' : s >= 4 ? 'MEDIUM' : s > 0 ? 'LOW' : 'NONE');
// NVD's own assessment (source nvd@nist.gov), whatever primary/secondary label it carries.
function nvdOwnScore(metrics = {}) {
  for (const k of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40']) {
    const m = (metrics[k] || []).find(x => x.source === 'nvd@nist.gov');
    if (m) return { s: m.cvssData.baseScore, v: (m.cvssData.baseSeverity || m.baseSeverity || '').toUpperCase(), k: m.cvssData.version };
  }
  return nvdCvss(metrics);
}
export function nvdCvss(metrics = {}) {
  for (const k of ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2']) {
    const arr = metrics[k]; if (!arr?.length) continue;
    const m = arr.find(x => x.type === 'Primary') || arr[0];
    const d = m.cvssData; return { s: d.baseScore, v: (d.baseSeverity || m.baseSeverity || sevOf(d.baseScore)).toUpperCase(), k: d.version };
  }
  return null;
}

async function fetchNvdRecent(days) {
  const end = new Date(), start = new Date(Date.now() - days * DAY);
  const fmt = d => d.toISOString().replace('Z', '').slice(0, 23) + 'Z';
  const out = []; let idx = 0, total = Infinity;
  while (idx < total && idx < 6000) {
    const u = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${fmt(start)}&pubEndDate=${fmt(end)}&resultsPerPage=2000&startIndex=${idx}&noRejected`;
    const j = await fetchJSON(u, { headers: NVD_KEY ? { apiKey: NVD_KEY } : {} });
    total = j.totalResults;
    for (const { cve } of j.vulnerabilities) {
      const desc = (cve.descriptions.find(d => d.lang === 'en') || {}).value || '';
      out.push({ id: cve.id, p: Date.parse(cve.published + 'Z'), x: clip(desc, 320), sc: nvdCvss(cve.metrics), cwe: cve.weaknesses?.[0]?.description?.[0]?.value });
    }
    idx += 2000; if (idx < total) await sleep(NVD_KEY ? 1000 : 6500);
  }
  return out;
}

async function lookupCveOrg(id) {
  const j = await fetchJSON(`https://cveawg.mitre.org/api/cve/${id}`, { timeout: 20000 });
  const cna = j.containers?.cna || {};
  const metrics = [...(cna.metrics || []), ...(j.containers?.adp || []).flatMap(a => a.metrics || [])];
  const desc = (cna.descriptions || []).find(d => d.lang?.startsWith('en'))?.value || '';
  const aff = cna.affected?.[0];
  return { pub: Date.parse(j.cveMetadata?.datePublished) || undefined, sc: pickCvss(metrics), x: clip(desc, 320), vp: aff ? `${aff.vendor || ''} ${aff.product || ''}`.trim() : '', t: cna.title || '', fx: fixFromCna(cna), fxck: Date.now() };
}

// "How to fix": fixed versions per product and vendor advisory links, from the CVE record.
// Affected ranges like { lessThan: "14.1-73.37" } mean "fixed in 14.1-73.37".
function fixFromCna(cna) {
  const prods = [];
  for (const a of cna.affected || []) {
    const fixed = new Set(), upto = new Set();
    for (const v of a.versions || []) {
      if (v.status === 'affected' && v.lessThan && !/^[*0]$|^n\/?a$/i.test(v.lessThan)) fixed.add(v.lessThan);
      if (v.status === 'affected' && v.lessThanOrEqual && !/^[*]$/.test(v.lessThanOrEqual)) upto.add(v.lessThanOrEqual);
      for (const c of v.changes || []) if (c.status === 'unaffected' && c.at) fixed.add(c.at);
    }
    if (fixed.size || upto.size) prods.push({ p: [a.vendor, a.product].filter(x => x && x !== 'n/a').join(' '), f: [...fixed].slice(0, 5), u: [...upto].slice(0, 3) });
  }
  const refs = (cna.references || []).filter(r => (r.tags || []).some(t => /vendor-advisory|patch|mitigation|release-notes/.test(t))).map(r => r.url);
  const adv = (refs.length ? refs : (cna.references || []).map(r => r.url).filter(u => !/nvd\.nist|cve\.org|mitre\.org|github\.com\/advisories/.test(u))).slice(0, 3);
  return prods.length || adv.length ? { p: prods.slice(0, 4), a: adv } : null;
}

async function fetchEpss(ids) {
  const out = {};
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    try {
      const j = await fetchJSON(`https://api.first.org/data/v1/epss?cve=${chunk.join(',')}&limit=100`);
      for (const d of j.data) out[d.cve] = [+(+d.epss).toFixed(4), +(+d.percentile).toFixed(3)];
    } catch (e) { log('EPSS chunk failed', e.message); }
  }
  return out;
}

// ---------- ransomware & supply chain ----------
async function fetchOgImage(url) {
  const { r, buf } = await fetchRaw(url, { ua: BROWSER_UA, accept: 'text/html', timeout: 15000 });
  if (!r.ok) return '';
  const head = buf.subarray(0, 250000).toString('utf8');
  const m = head.match(/<meta[^>]+(?:property|name)=["'](?:og:image(?::secure_url)?|twitter:image(?::src)?)["'][^>]*content=["']([^"']+)/i) || head.match(/<meta[^>]+content=["']([^"']+)["'][^>]*(?:property|name)=["'](?:og:image|twitter:image)["']/i);
  if (!m) return '';
  let u = decodeEntities(m[1]); try { u = new URL(u, url).href; } catch { return ''; }
  return /^https:\/\//.test(u) && !/(default|placeholder|logo|favicon)[^/]*\.(png|jpe?g|svg)/i.test(u) ? u.slice(0, 500) : '';
}

// Site icons: fetched once per source domain, cached, and served from our own site.
async function syncIcons(sources) {
  const dir = path.join(CACHE, 'icons'), out = path.join(ROOT, 'public', 'icons');
  await fs.mkdir(dir, { recursive: true }); await fs.mkdir(out, { recursive: true });
  const have = new Set(await fs.readdir(dir));
  const map = {};
  await pool(sources.filter(s => s.site), 8, async src => {
    const host = new URL(src.site).hostname.replace(/^www\./, '');
    const file = host.replace(/[^a-z0-9.-]/gi, '_') + '.png';
    if (!have.has(file) && !have.has(file + '.none')) {
      try {
        const { r, buf } = await fetchRaw(`https://icons.duckduckgo.com/ip3/${host}.ico`, { timeout: 15000 });
        // DDG serves a generic placeholder for unknown sites; skip tiny/failed responses
        await fs.writeFile(path.join(dir, r.ok && buf.length > 200 ? file : file + '.none'), r.ok && buf.length > 200 ? buf : '');
      } catch { return; }
    }
    try { await fs.copyFile(path.join(dir, file), path.join(out, file)); map[src.name] = file; } catch {}
  });
  return map;
}

// Country flags (SVG, from the flag-icons package) cached and served locally —
// flag emoji don't render on Windows.
async function syncFlags(codes) {
  const dir = path.join(CACHE, 'flags'), out = path.join(ROOT, 'public', 'flags');
  await fs.mkdir(dir, { recursive: true }); await fs.mkdir(out, { recursive: true });
  const have = new Set(await fs.readdir(dir));
  await pool([...codes].filter(c => /^[A-Z]{2}$/.test(c)), 8, async cc => {
    const file = cc.toLowerCase() + '.svg';
    if (!have.has(file)) {
      try { const { r, buf } = await fetchRaw(`https://cdn.jsdelivr.net/npm/flag-icons@7/flags/4x3/${file}`, { timeout: 15000 }); if (r.ok) await fs.writeFile(path.join(dir, file), buf); else return; }
      catch { return; }
    }
    await fs.copyFile(path.join(dir, file), path.join(out, file)).catch(() => {});
  });
}

async function fetchRansomware(stories = []) {
  let victims, source, totals = null, yearList = null;
  try {
    const all = await fetchJSON('https://data.ransomware.live/victims.json', { timeout: 180000 });
    const yStart = Date.UTC(new Date().getUTCFullYear(), 0, 1);
    totals = { all: all.length, ytd: 0, groupsAll: new Set(all.map(v => v.group_name)).size };
    const ytdCountries = {}, allCountries = {};
    for (const v of all) if (v.country) allCountries[v.country] = (allCountries[v.country] || 0) + 1;
    totals.countriesAll = Object.entries(allCountries).sort((a, b) => b[1] - a[1]);
    for (const v of all) { const d = Date.parse(v.discovered); if (d >= yStart) { totals.ytd++; if (v.country) ytdCountries[v.country] = (ytdCountries[v.country] || 0) + 1; } }
    totals.countriesYtd = Object.entries(ytdCountries).sort((a, b) => b[1] - a[1]);
    yearList = all.map(v => ({ t: v.post_title, g: v.group_name, d: Date.parse(v.discovered), p: Date.parse(v.published) || null, c: v.country || '', a: v.activity && v.activity !== 'Not Found' ? v.activity : '', w: v.website || '' })).filter(v => v.d >= yStart).sort((a, b) => b.d - a.d);
    const cutoff = Date.now() - 31 * DAY;
    victims = all.map(v => ({ t: v.post_title, g: v.group_name, d: Date.parse(v.discovered), p: Date.parse(v.published) || null, c: v.country || '', a: v.activity || '', w: v.website || '', x: (v.description || '').replace(/\s+/g, ' ').slice(0, 220) }))
      .filter(v => v.d > cutoff);
    source = 'ransomware.live';
  } catch (e) {
    log('ransomware.live failed, trying RansomLook:', e.message);
    const all = await fetchJSON('https://www.ransomlook.io/api/recent/500');
    victims = all.map(v => ({ t: v.post_title, g: v.group_name, d: Date.parse(v.discovered.replace(' ', 'T') + 'Z'), p: null, c: '', a: '', w: '' }));
    source = 'RansomLook';
  }
  victims.sort((a, b) => b.d - a.d);
  const count = (key, since) => {
    const m = {}; for (const v of victims) if (v.d > since && v[key]) m[v[key]] = (m[v[key]] || 0) + 1;
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  };
  const since30 = Date.now() - 30 * DAY;
  // A claimed victim "in the news": its distinctive name appears in a story from the last 30 days.
  const GENERIC_NAME = /^(the|group|company|services?|holdings?|international|systems?|solutions?|global|industries|consulting|partners|school|hospital|city|county|law|bank)$/i;
  function newsFor(v, list) {
    let name = (v.w || v.t || '').toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\.(com|net|org|co|io|gov|edu|us|uk|de|fr|it|es|br|mx|ca|au|in|jp|ch|nl|be|at|se|dk|pl|cz|pt|ar|cl|co\.uk|com\.br|com\.mx|com\.au)(\/.*)?$/, '');
    if (!v.w || /\*/.test(v.t)) name = (v.t || '').toLowerCase().replace(/\*+/g, '');
    name = name.replace(/[^a-z0-9 &'-]/g, ' ').replace(/\s+/g, ' ').trim();
    if (name.length < 6 || GENERIC_NAME.test(name)) return undefined;
    const re = new RegExp('(?<![a-z0-9])' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![a-z0-9])', 'i');
    const hit = list.find(s => !s.b && s.d > v.d - 20 * DAY && re.test(s.t + ' ' + s.x));
    return hit ? [hit.t, hit.u, hit.s] : undefined;
  }
  const daily = {};
  for (const v of victims) if (v.d > since30) { const k = new Date(v.d).toISOString().slice(0, 10); daily[k] = (daily[k] || 0) + 1; }
  return {
    generated: Date.now(), source,
    total30: victims.filter(v => v.d > since30).length,
    groups: count('g', since30).slice(0, 15), countries: count('c', since30).slice(0, 15), sectors: count('a', since30).filter(([k]) => k !== 'Not Found').slice(0, 12),
    daily: Object.entries(daily).sort(),
    countryDaily: (() => { const m = {}; for (const v of victims) if (v.d > since30 && v.c) { const k = new Date(v.d).toISOString().slice(0, 10); (m[k] ||= {})[v.c] = (m[k][v.c] || 0) + 1; } return Object.entries(m).sort(); })(),
    recent: victims.slice(0, 400).map(v => ({ ...v, n: newsFor(v, stories) })),
    all30: victims.filter(v => v.d > since30),
    year: yearList,
    totals: { ...(totals || {}), d30: victims.filter(v => v.d > since30).length, groups30: new Set(victims.filter(v => v.d > since30).map(v => v.g)).size },
    countriesAll30: count('c', since30),
    countries7: count('c', Date.now() - 7 * DAY),
    countries24: count('c', Date.now() - DAY),
    days10: (() => {
      const out = [];
      for (let i = 9; i >= 0; i--) {
        const day = new Date(Date.now() - i * DAY).toISOString().slice(0, 10);
        const vs = victims.filter(v => new Date(v.d).toISOString().slice(0, 10) === day);
        const top = key => { const m = {}; for (const v of vs) if (v[key] && v[key] !== 'Not Found') m[v[key]] = (m[v[key]] || 0) + 1; return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 3); };
        out.push({ d: day, n: vs.length, g: top('g'), c: top('c'), a: top('a') });
      }
      return out;
    })(),
  };
}

async function fetchSupplyChain() {
  const j = await fetchJSON('https://api.github.com/advisories?type=malware&per_page=100&sort=published&direction=desc',
    { headers: { accept: 'application/vnd.github+json', ...(GH_TOKEN ? { authorization: `Bearer ${GH_TOKEN}` } : {}) } });
  return j.map(a => ({ id: a.ghsa_id, s: a.summary, d: Date.parse(a.published_at), u: a.html_url,
    e: a.vulnerabilities?.[0]?.package?.ecosystem || '', p: [...new Set((a.vulnerabilities || []).map(v => v.package?.name).filter(Boolean))].slice(0, 5) }));
}

// ---------- main ----------
async function main() {
  const t0 = Date.now(), now = Date.now();
  await fs.mkdir(OUT, { recursive: true }); await fs.mkdir(CACHE, { recursive: true });
  const sources = await readJSON(path.join(ROOT, 'sources.json'), []);
  const feeds = sources.filter(s => s.feed);
  const store = await readJSON(path.join(CACHE, 'items.json'), {});       // key -> raw item
  const cveCache = await readJSON(path.join(CACHE, 'cves.json'), {});     // id -> {sc,x,vp,t,ck}

  // 1. KEV first (used for zero-day tagging)
  let kev = {}, kevList = [];
  try {
    const k = await fetchJSON('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    kevList = k.vulnerabilities.map(v => ({ id: v.cveID, v: v.vendorProject, p: v.product, n: v.vulnerabilityName, d: v.dateAdded, due: v.dueDate, rw: v.knownRansomwareCampaignUse === 'Known' ? 1 : 0, x: clip(v.shortDescription, 320),
      ra: v.requiredAction, adv: (v.notes || '').split(/\s*;\s*|\s+/).filter(u => /^https?:\/\//.test(u) && !/nvd\.nist\.gov/.test(u)).slice(0, 3) }))
      .sort((a, b) => b.d.localeCompare(a.d));
    for (const v of kevList) kev[v.id] = v;
    log(`KEV: ${kevList.length} entries`);
  } catch (e) { log('KEV failed:', e.message); }

  // 2. Feeds
  log(`Fetching ${feeds.length} feeds…`);
  const status = [];
  const results = await pool(feeds, 12, async src => {
    const { items, error } = await fetchFeed(src);
    let kept = items.filter(i => !NOISE.test(i.title) && (!src.filter || RELEVANCE.test(`${i.title} ${i.summary}`)));
    kept = kept.slice(0, src.bulk ? 60 : 80);
    status.push({ n: src.name, ok: !error, count: items.length, latest: Math.max(0, ...items.map(i => i.date || 0)) || null, err: error || undefined });
    return kept.map(i => ({ ...i, src }));
  });
  const failed = status.filter(s => !s.ok);
  log(`Feeds: ${status.length - failed.length} ok, ${failed.length} failed${failed.length ? ': ' + failed.map(f => `${f.n} (${f.err})`).join(', ') : ''}`);

  // 3. Merge into store. Undated items are only trusted from sources seen in an
  // earlier run (then an unknown link really is new); on a first run they are
  // usually an old archive, so they are skipped.
  const knownSources = new Set(Object.values(store).map(i => i.source));
  for (const it of results.flat()) {
    const key = linkKey(it.link);
    const prev = store[key];
    if (isNaN(it.date) && !prev && !knownSources.has(it.src.name)) continue;
    const date = isNaN(it.date) ? (prev?.date ?? now) : Math.min(it.date, now);
    const iocs = it.content && ['research', 'advisory'].includes(it.src.cat) ? extractIocs(it.content) : undefined;
    store[key] = { key, title: it.title, link: normLink(it.link), summary: it.summary, date, firstSeen: prev?.firstSeen ?? now,
      source: it.src.name, cat: it.src.cat, bulk: it.src.bulk ? 1 : 0, social: it.src.cat === 'social' ? 1 : 0,
      iocs: iocs !== undefined ? iocs : prev?.iocs, iocChecked: iocs !== undefined || prev?.iocChecked ? 1 : 0,
      img: it.img || prev?.img || '', imgChecked: it.img ? 1 : prev?.imgChecked || 0 };
  }
  // prune: 30 days; bulk feeds newest N; per-source cap
  const bySrc = {};
  for (const it of Object.values(store)) (bySrc[it.source] ||= []).push(it);
  for (const [, list] of Object.entries(bySrc)) {
    list.sort((a, b) => b.date - a.date);
    list.forEach((it, i) => { if (now - it.date > (it.social ? 7 : KEEP_DAYS) * DAY || i >= (it.bulk ? KEEP_BULK : it.social ? 30 : MAX_PER_SOURCE)) delete store[it.key]; });
  }
  // Research posts whose feed only has an excerpt: fetch the article once and look for IOCs.
  const needPage = Object.values(store).filter(it => it.cat === 'research' && !it.iocChecked && now - it.date < 14 * DAY).sort((a, b) => b.date - a.date).slice(0, Number(process.env.IOC_FETCHES || 30));
  await pool(needPage, 6, async it => { try { it.iocs = extractIocs(await fetchArticleText(it.link)); } catch {} it.iocChecked = 1; });
  log(`IOC scan: fetched ${needPage.length} articles; ${Object.values(store).filter(i => i.iocs).length} items with IOCs`);
  const needImg = Object.values(store).filter(it => !it.img && !it.imgChecked && !it.bulk && now - it.date < 3 * DAY).sort((a, b) => b.date - a.date).slice(0, Number(process.env.IMAGE_FETCHES || 80));
  await pool(needImg, 8, async it => { try { it.img = await fetchOgImage(it.link); } catch {} it.imgChecked = 1; });
  log(`Preview images: looked up ${needImg.length}; ${Object.values(store).filter(i => i.img).length} items have one`);
  await writeJSON(path.join(CACHE, 'items.json'), store);

  // 4. Tag + cluster
  const srcByName = Object.fromEntries(sources.map(s => [s.name, s]));
  const items = Object.values(store).filter(it => !NOISE.test(it.title)).map(it => ({ ...it, ...analyse(it, srcByName[it.source] || { cat: it.cat }, kev, now) }));
  const stories = cluster(items).map(toStory).sort((a, b) => b.d - a.d);
  log(`Stories: ${stories.length} (from ${items.length} items)`);
  const iocOut = {};
  for (const s of stories) {
    const merged = { h: new Set(), ip: new Set(), d: new Set(), u: new Set() }; let src = null;
    for (const k of s.keys) { const io = store[k]?.iocs; if (!io) continue; src ||= store[k].link; for (const f of Object.keys(merged)) for (const v of io[f]) merged[f].add(v); }
    const n = Object.values(merged).reduce((a, x) => a + x.size, 0);
    if (n) { iocOut[s.id] = { src, ...Object.fromEntries(Object.entries(merged).map(([f, v]) => [f, [...v]])) }; s.io = n; }
    delete s.keys;
  }

  // 5. CVE data
  let recent = [];
  try { recent = await fetchNvdRecent(4); log(`NVD recent: ${recent.length}`); } catch (e) { log('NVD recent failed:', e.message); }
  for (const r of recent) if (r.sc) cveCache[r.id] = { ...cveCache[r.id], sc: r.sc, x: r.x, ck: now };
  const mentioned = new Map();
  for (const s of stories) for (const c of s.cv) mentioned.set(c, (mentioned.get(c) || 0) + 1);
  const kevRecent = kevList.slice(0, 150);
  // Curated landmarks plus every CVE CISA listed as exploited since last year (candidates for the automatic picks)
  const autoYears = [new Date().getUTCFullYear() - 1, new Date().getUTCFullYear()];
  const landmarkIds = [...LANDMARKS.flatMap(l => l.cves), ...kevList.filter(k => autoYears.some(y => k.d.startsWith(String(y)))).map(k => k.id)];
  const wanted = [...new Set([...mentioned.keys(), ...kevRecent.map(k => k.id), ...landmarkIds])];
  const stale = wanted.filter(id => !cveCache[id] || (!cveCache[id].sc && now - (cveCache[id].ck || 0) > DAY));
  const budget = Number(process.env.CVE_LOOKUPS || 250);
  log(`CVE lookups: ${Math.min(stale.length, budget)} of ${stale.length} missing scores`);
  await pool(stale.slice(0, budget), 6, async id => {
    try { const r = await lookupCveOrg(id); cveCache[id] = { ...cveCache[id], ...r, ck: now }; }
    catch { cveCache[id] = { ...cveCache[id], ck: now }; }
  });
  const fixIds = [...new Set([...wanted, ...recent.filter(r => r.sc?.s >= 9).map(r => r.id)])];
  const needFix = fixIds.filter(id => !cveCache[id]?.fxck || (!cveCache[id].fx && now - cveCache[id].fxck > 3 * DAY)).slice(0, Number(process.env.FIX_LOOKUPS || 300));
  await pool(needFix, 8, async id => {
    try { const r = await lookupCveOrg(id); cveCache[id] = { ...cveCache[id], ...(cveCache[id]?.sc ? { fx: r.fx, fxck: r.fxck, vp: cveCache[id].vp || r.vp, t: cveCache[id].t || r.t, x: cveCache[id].x || r.x } : r), ck: cveCache[id]?.ck || now }; }
    catch { cveCache[id] = { ...cveCache[id], fxck: now - 2 * DAY }; }
  });
  log(`Fix info: looked up ${needFix.length}; ${fixIds.filter(id => cveCache[id]?.fx).length} of ${fixIds.length} CVEs have fixed versions or advisories`);
  await writeJSON(path.join(CACHE, 'cves.json'), cveCache);
  const pocCache = await readJSON(path.join(CACHE, 'pocs.json'), {});
  const pocIds = [...new Set([...wanted, ...recent.filter(r => r.sc?.s >= 7).map(r => r.id)])];
  const checked = await fetchPocs(pocIds, pocCache, { budget: Number(process.env.POC_LOOKUPS || 400), now });
  await writeJSON(path.join(CACHE, 'pocs.json'), pocCache);
  const poc = {}; for (const id of pocIds) if (pocCache[id]?.n) poc[id] = { n: pocCache[id].n, first: pocCache[id].first, top: pocCache[id].top };
  for (const s of stories) if (s.s === 'Exploit-DB' || s.r.some(r => r[0] === 'Exploit-DB')) for (const c of s.cv) (poc[c] ||= { n: 0, top: [] }).edb = 1;
  log(`PoC watch: checked ${checked}, ${Object.keys(poc).length} CVEs with public exploits`);
  const epss = await fetchEpss([...new Set([...wanted, ...recent.filter(r => r.sc?.s >= 7).map(r => r.id)])]);
  const info = {};
  for (const id of wanted) { const c = cveCache[id]; if (c) info[id] = { s: c.sc?.s, v: c.sc?.v, x: c.x, vp: c.vp, t: c.t }; }
  const kevIndex = Object.fromEntries(kevList.map(k => [k.id, k.d]));

  // 6. Ransomware & supply chain (independent, failures are non-fatal)
  let ransomware = null, supply = [];
  try { ransomware = await fetchRansomware(stories); log(`Ransomware: ${ransomware.total30} claims / 30d via ${ransomware.source}`); } catch (e) { log('Ransomware failed:', e.message); }
  try { supply = await fetchSupplyChain(); log(`Supply chain advisories: ${supply.length}`); } catch (e) { log('GitHub advisories failed:', e.message); }

  let plugins = [];
  try {
    const tStore = await readJSON(path.join(CACHE, 'tenable.json'), {});
    const added = await fetchTenable(tStore, { now });
    await writeJSON(path.join(CACHE, 'tenable.json'), tStore);
    plugins = Object.values(tStore).sort((a, b) => b.d - a.d || b.id - a.id);
    log(`Tenable plugins: ${added} new, ${plugins.length} in the last 30 days`);
  } catch (e) { log('Tenable failed:', e.message); }
  let hibp = [];
  let hibpAll = [];
  try { hibpAll = await fetchHibp(); hibp = hibpAll.slice(0, 60); log(`HIBP breaches: ${hibpAll.length}`); } catch (e) { log('HIBP failed:', e.message); }
  let world = await readJSON(path.join(CACHE, 'world.json'), null);
  if (!world) { try { world = await buildWorld(); await writeJSON(path.join(CACHE, 'world.json'), world); } catch (e) { log('World map failed:', e.message); } }
  const aiCache = await readJSON(path.join(CACHE, 'ai.json'), {});
  const aiNew = await aiSummaries(stories, aiCache, { log });
  if (aiNew) log(`AI summaries: ${aiNew} new`);
  await writeJSON(path.join(CACHE, 'ai.json'), aiCache);
  for (const s of stories) if (aiCache[s.id]?.t) s.ai = aiCache[s.id].t;

  // Fix map, breach sizes, developing stories, optional AI CVE explanations
  const fix = {};
  for (const id of fixIds) if (cveCache[id]?.fx) fix[id] = cveCache[id].fx;
  for (const s of stories) {
    if (!s.tg.includes('breach')) continue;
    const b = breachSize([s.t, s.x, ...s.r.map(r => r[1])].join(' . '));
    if (b) { s.rc = b.n; s.ru = b.u; }
  }
  const recentBy = Object.fromEntries(recent.map(r => [r.id, r]));
  const incidents = buildIncidents({ stories, kevList, poc, recent });
  for (const inc of incidents) for (const sid of inc.sids) { const st = stories.find(x => x.id === sid); if (st && !st.inc) st.inc = inc.id; }
  log(`Developing stories: ${incidents.length}`);
  const cveAiCache = await readJSON(path.join(CACHE, 'ai-cves.json'), {});
  const explainIds = [...new Set([...kevRecent.slice(0, 40).map(k => k.id), ...[...mentioned.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40).map(([id]) => id)])];
  const kevBy = Object.fromEntries(kevList.map(k => [k.id, k]));
  const aiCveNew = await aiCveExplain(explainIds.map(id => {
    const c = cveCache[id] || {}, k = kevBy[id], r = recentBy[id] || {};
    return { id, title: k?.n || c.t, vp: k ? `${k.v} ${k.p}` : c.vp, x: c.x || r.x || k?.x, s: c.sc?.s ?? r.sc?.s, kev: !!k, fix: (fix[id]?.p || []).map(p => `${p.p}: ${p.f.join(', ')}`).join('; ') };
  }), cveAiCache, { log });
  if (aiCveNew) log(`AI CVE explanations: ${aiCveNew} new`);
  await writeJSON(path.join(CACHE, 'ai-cves.json'), cveAiCache);
  const cveAi = Object.fromEntries(Object.entries(cveAiCache).filter(([, v]) => v.t).map(([k, v]) => [k, v.t]));

  // 7. Write
  const generated = Date.now();
  await writeJSON(path.join(OUT, 'news.json'), { generated, stories });
  await writeJSON(path.join(OUT, 'cves.json'), {
    generated, kev: kevRecent, kevIndex, info, epss, poc, fix, ai: cveAi,
    recent: recent.sort((a, b) => b.p - a.p).slice(0, 1500).map(r => ({ id: r.id, p: r.p, x: r.x, s: r.sc?.s, v: r.sc?.v, cwe: r.cwe })),
  });
  if (ransomware) { const { all30, year, ...rw } = ransomware; await writeJSON(path.join(OUT, 'ransomware.json'), rw); }
  await writeJSON(path.join(OUT, 'iocs.json'), { generated, iocs: iocOut });
  // Landmark vulnerabilities with live data; a CVE that CVE.org doesn't know is reported, not shown.
  const kevAll = Object.fromEntries(kevList.map(k => [k.id, k]));
  // NVD's own score for landmark CVEs (vendors sometimes score their own bugs lower, e.g. Zerologon)
  const needNvd = LANDMARKS.flatMap(l => l.cves).filter(id => cveCache[id] && cveCache[id].nvd === undefined).slice(0, Number(process.env.LANDMARK_NVD || 12));
  for (const id of needNvd) {
    try { const j = await fetchJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, { headers: NVD_KEY ? { apiKey: NVD_KEY } : {} }); cveCache[id].nvd = nvdOwnScore(j.vulnerabilities?.[0]?.cve?.metrics) || null; }
    catch { cveCache[id].nvd = undefined; }
    await sleep(NVD_KEY ? 800 : 6500);
  }
  if (needNvd.length) { await writeJSON(path.join(CACHE, 'cves.json'), cveCache); log(`Landmarks: fetched NVD scores for ${needNvd.length}`); }
  const needPub = [...new Set(landmarkIds)].filter(id => !cveCache[id]?.pub && !cveCache[id]?.pubck);
  for (const id of needPub) cveCache[id] ||= {};
  await pool(needPub.slice(0, 400), 6, async id => {
    try { const j = await fetchJSON(`https://cveawg.mitre.org/api/cve/${id}`, { timeout: 20000 }); cveCache[id].pub = Date.parse(j.cveMetadata?.datePublished) || undefined; } catch {}
    cveCache[id].pubck = now;
  });
  if (needPub.length) { await writeJSON(path.join(CACHE, 'cves.json'), cveCache); log(`Landmarks: publication dates for ${needPub.length}`); }
  const pubOf = ids => { const d = ids.map(id => cveCache[id]?.pub).filter(Boolean); return d.length ? Math.min(...d) : undefined; };
  const landmarks = LANDMARKS.map(l => ({ ...l, pub: pubOf(l.cves), kevAt: l.cves.map(id => kevAll[id]?.d).filter(Boolean).sort()[0], live: Object.fromEntries(l.cves.map(id => {
    const c = cveCache[id] || {}, k = kevAll[id], p = pocCache[id];
    return [id, { ok: !!(c.x || c.sc || k), s: c.nvd?.s ?? c.sc?.s, v: c.nvd?.v ?? c.sc?.v, vendor: c.nvd && c.sc && c.sc.s !== c.nvd.s ? c.sc.s : undefined, kev: k?.d, rw: k?.rw || 0, epss: epss[id], poc: p?.n || 0, pocTop: p?.top?.[0] }];
  })) }));
  // Automatic picks for the last two years: CISA-confirmed exploitation ranked by ransomware use,
  // exploitation probability, public exploit code and news coverage. Official text only, labelled as automatic.
  const curated = new Set(LANDMARKS.flatMap(l => l.cves));
  const newsHits = {};
  try {
    for (const f of await fs.readdir(path.join(CACHE, 'archive'))) if (/^(live-)?news-\d{4}-\d{2}\.json$/.test(f))
      for (const x of await readJSON(path.join(CACHE, 'archive', f), [])) for (const c of new Set(x.cv || [])) newsHits[c] = (newsHits[c] || 0) + 1;
  } catch {}
  const catOf = v => /microsoft|windows/i.test(v) ? 'windows' : /linux|kernel|glibc|sudo|openssh|polkit/i.test(v) ? 'linux'
    : /fortinet|cisco|citrix|ivanti|palo alto|sonicwall|f5|juniper|zyxel|check point|netgear|d-link|tp-link|mikrotik|draytek|sophos|barracuda|vmware|broadcom/i.test(v) ? 'edge'
    : /apple|google|android|samsung|qualcomm/i.test(v) ? 'mobile' : 'web';
  for (const y of autoYears) {
    // only vulnerabilities from that year or the one before (not old bugs CISA happened to list late)
    const ranked = kevList.filter(k => k.d.startsWith(String(y)) && !curated.has(k.id) && +k.id.split('-')[1] >= y - 1).map(k => {
      const c = cveCache[k.id] || {}, p = pocCache[k.id], e = epss[k.id], m = newsHits[k.id] || 0, sc = c.nvd?.s ?? c.sc?.s ?? 0;
      return { k, m, score: (k.rw ? 20 : 0) + (e ? e[0] * 25 : 0) + Math.min(p?.n || 0, 50) * 0.4 + Math.min(m, 30) * 3 + sc };
    }).sort((a, b) => b.score - a.score);
    // one pick per product: the strongest
    const seenProd = new Set(), picks = [];
    for (const r of ranked) { const key = `${r.k.v}|${r.k.p}`.toLowerCase(); if (seenProd.has(key)) continue; seenProd.add(key); picks.push(r); if (picks.length === 8) break; }
    for (const { k, m } of picks) {
      const facts = [`Added to CISA's exploited list on ${k.d}`, k.rw ? 'known to be used in ransomware campaigns' : '', m ? `covered in ${m} news stor${m > 1 ? 'ies' : 'y'} this year` : ''].filter(Boolean);
      const c = cveCache[k.id] || {}, p = pocCache[k.id];
      landmarks.push({ name: k.n.replace(/ Vulnerability$/i, ''), cves: [k.id], year: y, pub: pubOf([k.id]), kevAt: k.d, k: catOf(`${k.v} ${k.p}`), product: `${k.v} ${k.p}`, what: k.x, why: facts.join('; ') + '.', auto: true,
        live: { [k.id]: { ok: true, s: c.nvd?.s ?? c.sc?.s, v: c.nvd?.v ?? c.sc?.v, kev: k.d, rw: k.rw, epss: epss[k.id], poc: p?.n || 0, pocTop: p?.top?.[0] } } });
    }
  }
  const unknown = landmarks.flatMap(l => l.cves.filter(id => !l.live[id].ok));
  if (unknown.length) log('Landmarks: not found on CVE.org yet:', unknown.join(', '));
  await writeJSON(path.join(OUT, 'landmarks.json'), { generated, landmarks });
  await writeJSON(path.join(OUT, 'incidents.json'), { generated, incidents: incidents.map(({ sids, ...i }) => i) });
  await writeJSON(path.join(OUT, 'breaches.json'), { generated, hibp });
  if (plugins.length) await writeJSON(path.join(OUT, 'plugins.json'), { generated, plugins });
  if (world) await writeJSON(path.join(OUT, 'world.json'), world);
  await writeJSON(path.join(OUT, 'supply.json'), { generated, advisories: supply });
  const st = Object.fromEntries(status.map(s => [s.n, s]));
  if (ransomware) { try { await syncFlags(new Set([...(ransomware.totals?.countriesYtd || []).map(c => c[0]), ...ransomware.recent.map(v => v.c)])); } catch (e) { log('Flags failed:', e.message); } }
  let icons = {};
  try { icons = await syncIcons(sources); log(`Site icons: ${Object.keys(icons).length}`); } catch (e) { log('Icons failed:', e.message); }
  await writeJSON(path.join(OUT, 'sources.json'), { generated, sources: sources.map(s => ({ n: s.name, c: s.cat, site: s.site, feed: s.feed || null, ic: icons[s.name], via: s.via, ...(st[s.name] ? { ok: st[s.name].ok, count: st[s.name].count, latest: st[s.name].latest, err: st[s.name].err } : {}) })) });
  try { const t = await writeArchive({ root: ROOT, items, recent, kevList, ransomwareYear: ransomware?.year, hibpAll, sources, clip }); log(`Archive: ${t.news} news items, ${t.cves} CVEs, ${t.rw} ransomware claims, ${t.kev} KEV, ${t.hibp} HIBP this year`); } catch (e) { log('Archive failed:', e.message); }
  await writeDigestPage({ stories: stories.filter(s => !s.so), kevList, info, epss, ransomware }); // after the archive: the monthly recap reads it
  const pages = await writeSite({ root: ROOT, stories, kevList, info, ransomware, incidents, siteUrl: process.env.SITE_URL || '' });
  log(`Static pages: ${pages}`);
  log(`Done in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(e => { console.error(e); process.exit(1); });
}
