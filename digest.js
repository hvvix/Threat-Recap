#!/usr/bin/env node
// Weekly digest.
//  - writeDigestPage(): called by build.js, writes public/digest.html ("This week").
//  - `node digest.js`: sends the digest to Buttondown (draft by default).
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

export function buildDigest({ stories, kevList, info = {}, epss = {}, ransomware }, now = Date.now()) {
  const since = now - 7 * DAY;
  const week = stories.filter(s => s.d > since && !s.b);
  const top = week.slice().sort((a, b) => b.r.length - a.r.length || b.d - a.d).slice(0, 10);
  const zeroDays = week.filter(s => s.tg.includes('zeroday')).sort((a, b) => b.r.length - a.r.length).slice(0, 6);
  const newKev = kevList.filter(k => Date.parse(k.d) > since - DAY);
  const weekCves = [...new Set(week.flatMap(s => s.cv))];
  const hotEpss = weekCves.filter(c => epss[c]).sort((a, b) => epss[b][0] - epss[a][0]).slice(0, 8);
  const groups = ransomware?.groups?.slice(0, 8) || [];
  return { since, now, top, zeroDays, newKev, hotEpss, groups, info, epss, ransomware };
}

function toHtml(d, siteUrl = '') {
  const story = s => `<li><a href="${esc(s.u)}">${esc(s.t)}</a> <span class="m">${esc(s.s)}${s.r.length ? ` +${s.r.length} sources` : ''} · ${fmtDate(s.d)}</span></li>`;
  const cve = id => { const i = d.info[id] || {}; return `<a href="https://nvd.nist.gov/vuln/detail/${id}">${id}</a>${i.s != null ? ` <b>CVSS ${i.s}</b>` : ''}`; };
  return `
<h2>Top stories</h2><ol>${d.top.map(story).join('') || '<li>No stories.</li>'}</ol>
<h2>Zero-days &amp; actively exploited</h2><ul>${d.zeroDays.map(story).join('') || '<li>Nothing flagged this week.</li>'}</ul>
<h2>Added to CISA KEV (${d.newKev.length})</h2><ul>${d.newKev.map(k => `<li>${cve(k.id)} — ${esc(k.v)} ${esc(k.p)}: ${esc(k.n)}${k.rw ? ' <b>(used by ransomware)</b>' : ''} <span class="m">added ${k.d}</span></li>`).join('') || '<li>No new entries.</li>'}</ul>
<h2>Highest exploit probability (EPSS) in this week's news</h2><ul>${d.hotEpss.map(c => `<li>${cve(c)} — EPSS ${(d.epss[c][0] * 100).toFixed(1)}% (top ${(100 - d.epss[c][1] * 100).toFixed(1)}%)</li>`).join('') || '<li>None.</li>'}</ul>
<h2>Most active ransomware groups (30 days)</h2><ul>${d.groups.map(([g, n]) => `<li>${esc(g)} — ${n} claimed victims</li>`).join('') || '<li>No data.</li>'}</ul>
<p class="m">Ransomware figures are unverified claims posted by criminal groups. Tags are keyword-based. ${siteUrl ? `Full feed: <a href="${esc(siteUrl)}">${esc(siteUrl)}</a>` : ''}</p>`;
}

export async function writeDigestPage(input) {
  const d = buildDigest(input);
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>This week in security · Threat Recap</title><link rel="icon" href="icon.svg">
<style>
:root{--bg:#f7f7f5;--fg:#1a1a19;--muted:#6b6a66;--link:#1f63b8;--card:#fff;--line:#e4e3de;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#121211;--fg:#ecebe6;--muted:#a09f98;--link:#7fb0f0;--card:#1c1c1a;--line:#2e2e2b;color-scheme:dark}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px 16px}
main{max-width:780px;margin:0 auto;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:8px 24px 24px}
h1{font-size:22px}h2{font-size:16px;margin-top:28px;border-bottom:1px solid var(--line);padding-bottom:6px}
a{color:var(--link)}li{margin:6px 0}.m{color:var(--muted);font-size:13px}
</style></head><body><main>
<p><a href="./">← Back to Threat Recap</a></p>
<h1>This week in security</h1><p class="m">${fmtDate(d.since)} – ${fmtDate(d.now)} · generated ${new Date(d.now).toUTCString()}</p>
${toHtml(d)}
</main></body></html>`;
  await fs.writeFile(path.join(ROOT, 'public', 'digest.html'), html);
}

async function send() {
  const key = process.env.BUTTONDOWN_API_KEY;
  if (!key) { console.error('BUTTONDOWN_API_KEY is not set; nothing to send.'); process.exit(1); }
  const read = async f => JSON.parse(await fs.readFile(path.join(DATA, f), 'utf8'));
  const news = await read('news.json'), cves = await read('cves.json');
  let ransomware = null; try { ransomware = await read('ransomware.json'); } catch {}
  const d = buildDigest({ stories: news.stories, kevList: cves.kev, info: cves.info, epss: cves.epss, ransomware });
  const subject = `Security week: ${d.top[0]?.t?.slice(0, 80) || 'your weekly digest'}`;
  const body = toHtml(d, process.env.SITE_URL || '');
  const status = process.env.DIGEST_AUTOSEND === 'true' ? 'about_to_send' : 'draft';
  const r = await fetch('https://api.buttondown.com/v1/emails', {
    method: 'POST', headers: { authorization: `Token ${key}`, 'content-type': 'application/json' },
    body: JSON.stringify({ subject, body, status }),
  });
  const text = await r.text();
  if (!r.ok) { console.error(`Buttondown error ${r.status}: ${text.slice(0, 500)}`); process.exit(1); }
  console.log(`Digest ${status === 'draft' ? 'saved as draft' : 'queued to send'}: ${subject}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) send();
