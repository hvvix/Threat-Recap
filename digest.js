#!/usr/bin/env node
// Email digests: a weekly digest and a monthly recap. Everyone who subscribes gets both.
//  - writeDigestPage(): called by build.js, writes public/digest.html (this week) and
//    public/monthly.html (last full month), the web versions of the emails.
//  - `node digest.js [--weekly | --monthly]`: sends one to Buttondown (draft by default).
//      BUTTONDOWN_API_KEY=...   required to send
//      DIGEST_AUTOSEND=true     send immediately instead of saving a draft
//      SITE_URL=https://...     used for links back to the site

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DATA = path.join(ROOT, 'public', 'data');
const DAY = 864e5;
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const fmtDate = t => new Date(t).toUTCString().slice(5, 16);
const clip = (s, n) => { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n).replace(/\s+\S*$/, '') + '…' : s; };
const fmtCount = n => n >= 1e9 ? `${+(n / 1e9).toFixed(1)} billion` : n >= 1e6 ? `${+(n / 1e6).toFixed(1)} million` : n.toLocaleString('en-US');
const monthName = t => new Date(t).toLocaleString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
const readJSON = async (f, d = null) => { try { return JSON.parse(await fs.readFile(f, 'utf8')); } catch { return d; } };

// The last full calendar month before `now` (UTC): on 1 October that is September.
function lastMonth(now) {
  const d = new Date(now);
  const until = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
  const s = new Date(until - DAY);
  return { since: Date.UTC(s.getUTCFullYear(), s.getUTCMonth(), 1), until, key: s.toISOString().slice(0, 7) };
}

// Biggest breaches: stories tagged "breach", largest record counts first, one story per incident.
function topBreaches(stories, n) {
  const seen = new Set(), out = [];
  const list = stories.filter(s => s.tg.includes('breach')).sort((a, b) => (b.rc || 0) - (a.rc || 0) || b.r.length - a.r.length);
  for (const s of list) {
    const key = s.rc ? `${s.rc}|${s.ru}` : s.t.toLowerCase().replace(/[^a-z0-9 ]/g, '').split(' ').slice(0, 4).join(' ');
    if (seen.has(key)) continue;
    seen.add(key); out.push(s);
    if (out.length === n) break;
  }
  return out;
}

export function buildDigest({ stories, kevList, info = {}, epss = {}, ransomware, archive }, { kind = 'weekly', now = Date.now(), range } = {}) {
  const monthly = kind === 'monthly';
  const { since, until, key } = range || (monthly ? lastMonth(now) : { since: now - 7 * DAY, until: now });
  const inRange = t => t >= since && t < until;
  const period = stories.filter(s => inRange(s.d) && !s.b);
  const top = period.slice().sort((a, b) => b.r.length - a.r.length || b.d - a.d).slice(0, monthly ? 15 : 10);
  const zeroDays = period.filter(s => s.tg.includes('zeroday')).sort((a, b) => b.r.length - a.r.length).slice(0, monthly ? 10 : 6);
  const breaches = topBreaches(period, monthly ? 8 : 5);
  const newKev = kevList.filter(k => { const t = Date.parse(k.d); return t >= since - (monthly ? 0 : DAY) && t < until; });
  const cves = [...new Set(period.flatMap(s => s.cv))];
  const hotEpss = cves.filter(c => epss[c]).sort((a, b) => epss[b][0] - epss[a][0]).slice(0, 8);
  let groups = ransomware?.groups?.slice(0, 8) || [], countries = [], claims = ransomware?.total30, stats = null;
  if (monthly) {
    // Exact month figures from the year archive (every claim, and per-month counts).
    const tally = (list, f) => Object.entries(list.reduce((m, x) => { const k = f(x); if (k) m[k] = (m[k] || 0) + 1; return m; }, {})).sort((a, b) => b[1] - a[1]);
    const monthClaims = (archive?.ransomware || []).filter(v => inRange(v.d));
    claims = monthClaims.length || null;
    groups = tally(monthClaims, v => v.g).slice(0, 8);
    countries = tally(monthClaims, v => v.c).slice(0, 5);
    stats = archive?.index?.months?.find(m => m.m === key) || null;
  }
  return { kind, since, until, top, zeroDays, breaches, newKev, hotEpss, groups, countries, claims, stats, info, epss };
}

export function toHtml(d, siteUrl = '') {
  const monthly = d.kind === 'monthly';
  const site = siteUrl ? siteUrl.replace(/\/?$/, '/') : '';
  // Some feeds put category lists or the headline itself in the summary; those are left out.
  const summary = s => { const x = clip(s.x, 220); return x && !/^(categories|tags|filed under|posted in)\b/i.test(x) && !x.toLowerCase().startsWith(s.t.toLowerCase().slice(0, 40)) ? x : ''; };
  const story = (s, sum = true) => `<li><a href="${esc(s.u)}">${esc(s.t)}</a> <span class="m">${esc(s.s)}${s.r.length ? ` +${s.r.length} source${s.r.length > 1 ? 's' : ''}` : ''} · ${fmtDate(s.d)}</span>${sum && summary(s) ? `<br><span class="x">${esc(summary(s))}</span>` : ''}</li>`;
  const breach = s => `<li>${s.rc ? `<b>${fmtCount(s.rc)} ${esc(s.ru || 'records')}</b> — ` : ''}<a href="${esc(s.u)}">${esc(s.t)}</a> <span class="m">${esc(s.s)} · ${fmtDate(s.d)}</span></li>`;
  const cve = id => { const i = d.info[id] || {}; return `<a href="https://nvd.nist.gov/vuln/detail/${id}">${id}</a>${i.s != null ? ` <b>CVSS ${i.s}</b>` : ''}`; };
  const st = d.stats;
  return `
${monthly && st ? `<p><b>${monthName(d.since)} in numbers:</b> ${st.news.toLocaleString('en-US')} security stories · ${st.cves.toLocaleString('en-US')} new CVEs (${st.crit.toLocaleString('en-US')} critical) · ${st.kev} added to CISA's exploited list · ${(d.claims ?? st.rw).toLocaleString('en-US')} ransomware claims</p>` : ''}
<h2>Top stories</h2><ol>${d.top.map(s => story(s)).join('') || '<li>No stories.</li>'}</ol>
<h2>Zero-days &amp; actively exploited</h2><ul>${d.zeroDays.map(s => story(s, false)).join('') || '<li>Nothing flagged.</li>'}</ul>
<h2>Biggest breaches</h2><ul>${d.breaches.map(breach).join('') || '<li>No breaches reported.</li>'}</ul>
<h2>Added to CISA KEV (${d.newKev.length})</h2><ul>${d.newKev.map(k => `<li>${cve(k.id)} — ${esc(k.v)} ${esc(k.p)}: ${esc(k.n)}${k.rw ? ' <b>(used by ransomware)</b>' : ''} <span class="m">added ${k.d}</span></li>`).join('') || '<li>No new entries.</li>'}</ul>
<h2>Highest exploit probability (EPSS) in the news</h2><ul>${d.hotEpss.map(c => `<li>${cve(c)} — EPSS ${(d.epss[c][0] * 100).toFixed(1)}% (top ${(100 - d.epss[c][1] * 100).toFixed(1)}%)</li>`).join('') || '<li>None.</li>'}</ul>
<h2>Most active ransomware groups (${monthly ? monthName(d.since) : 'last 30 days'})</h2><ul>${d.groups.map(([g, n]) => `<li>${esc(g)} — ${n} claimed victims</li>`).join('') || '<li>No data.</li>'}</ul>
${d.countries.length ? `<p class="m">Most targeted countries: ${d.countries.map(([c, n]) => `${esc(c)} (${n})`).join(', ')}.</p>` : ''}
${site ? `<p class="m">Want news daily or the moment something is exploited? Use the free <a href="${esc(site)}api.html">RSS feeds</a> or turn on notifications on <a href="${esc(site)}">Threat Recap</a>.</p>` : ''}
<p class="m">Ransomware figures are unverified claims posted by criminal groups. Tags are keyword-based.</p>`;
}

async function loadArchive() {
  const index = await readJSON(path.join(DATA, 'archive', 'index.json'));
  const ransomware = index ? await readJSON(path.join(DATA, 'archive', `ransomware-${index.year}.json`), []) : [];
  return { index, ransomware };
}

function page(d, title, sub) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>${esc(title)} · Threat Recap</title><link rel="icon" href="icon.svg">
<style>
:root{--bg:#f7f7f5;--fg:#1a1a19;--muted:#6b6a66;--link:#1f63b8;--card:#fff;--line:#e4e3de;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#121211;--fg:#ecebe6;--muted:#a09f98;--link:#7fb0f0;--card:#1c1c1a;--line:#2e2e2b;color-scheme:dark}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px 16px}
main{max-width:780px;margin:0 auto;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:8px 24px 24px}
h1{font-size:22px}h2{font-size:16px;margin-top:28px;border-bottom:1px solid var(--line);padding-bottom:6px}
a{color:var(--link)}li{margin:8px 0}.m{color:var(--muted);font-size:13px}.x{font-size:14px}
</style></head><body><main>
<p><a href="./">← Back to Threat Recap</a> · <a href="digest.html">This week</a> · <a href="monthly.html">Monthly recap</a></p>
<h1>${esc(title)}</h1><p class="m">${sub} · generated ${new Date().toUTCString()}</p>
${toHtml(d, './')}
</main></body></html>`;
}

export async function writeDigestPage(input) {
  const archive = await loadArchive();
  const w = buildDigest({ ...input, archive }, { kind: 'weekly' });
  await fs.writeFile(path.join(ROOT, 'public', 'digest.html'), page(w, 'This week in security', `${fmtDate(w.since)} – ${fmtDate(w.until)}`));
  await fs.writeFile(path.join(ROOT, 'public', 'monthly.html'), await monthlyPage(input, archive));
}

// Full stories are only kept for 30 days, so last month's recap can only be built in the
// first day or so of a month (when the email goes out). It is saved to cache/ then and
// reused for the rest of the month; before the first save, the page shows this month so far.
async function monthlyPage(input, archive, now = Date.now()) {
  const m = lastMonth(now);
  const snap = path.join(ROOT, 'cache', `monthly-${m.key}.html`);
  const saved = await fs.readFile(snap, 'utf8').catch(() => null);
  if (saved) return saved;                       // the first build of the month has the most complete data
  if (now - 30 * DAY <= m.since + DAY) {
    const d = buildDigest({ ...input, archive }, { kind: 'monthly', now });
    const html = page(d, `${monthName(d.since)} in security`, 'Monthly recap');
    await fs.mkdir(path.dirname(snap), { recursive: true });
    await fs.writeFile(snap, html);
    return html;
  }
  const start = Date.UTC(new Date(now).getUTCFullYear(), new Date(now).getUTCMonth(), 1);
  const d = buildDigest({ ...input, archive }, { kind: 'monthly', now, range: { since: start, until: now, key: new Date(now).toISOString().slice(0, 7) } });
  return page(d, `${monthName(start)} so far`, `Month to date; the full recap for ${monthName(start)} appears here on the 1st`);
}

async function send(kind) {
  const key = process.env.BUTTONDOWN_API_KEY;
  if (!key) { console.error('BUTTONDOWN_API_KEY is not set; nothing to send.'); process.exit(1); }
  const read = f => readJSON(path.join(DATA, f));
  const news = await read('news.json'), cves = await read('cves.json'), ransomware = await read('ransomware.json');
  const d = buildDigest({ stories: news.stories.filter(s => !s.so), kevList: cves.kev, info: cves.info, epss: cves.epss, ransomware, archive: await loadArchive() }, { kind });
  const subject = kind === 'monthly' ? `Threat Recap: ${monthName(d.since)} in security` : `Threat Recap weekly: ${d.top[0]?.t?.slice(0, 80) || 'this week in security'}`;
  const body = toHtml(d, process.env.SITE_URL || '');
  const status = process.env.DIGEST_AUTOSEND === 'true' ? 'about_to_send' : 'draft';
  const r = await fetch('https://api.buttondown.com/v1/emails', {
    method: 'POST', headers: { authorization: `Token ${key}`, 'content-type': 'application/json' },
    body: JSON.stringify({ subject, body, status }),
  });
  const text = await r.text();
  if (!r.ok) { console.error(`Buttondown error ${r.status}: ${text.slice(0, 500)}`); process.exit(1); }
  console.log(`${kind === 'monthly' ? 'Monthly recap' : 'Weekly digest'} ${status === 'draft' ? 'saved as draft' : 'queued to send'}: ${subject}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) send(process.argv.includes('--monthly') ? 'monthly' : 'weekly');
