// Static pages & feeds generated on every build:
//   public/actors/…, public/vendors/…, public/groups/…  profile pages (good for search engines)
//   public/feeds/*.xml                                   RSS feeds people can subscribe to
//   public/sitemap.xml, public/robots.txt
import fs from 'node:fs/promises';
import path from 'node:path';
import { ACTOR_INFO, slug } from './actors.js';
import { VENDORS, TAG_LABELS } from './taxonomy.js';
import { CATEGORIES, PRODUCTS } from './topics.js';

const DAY = 864e5;
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fmt = t => new Date(t).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
const day = t => new Date(t).toISOString().slice(0, 10);
const regionNames = (() => { try { return new Intl.DisplayNames(['en'], { type: 'region' }); } catch { return null; } })();
const country = c => { try { return c ? regionNames?.of(c) || c : ''; } catch { return c; } };

function page({ title, desc, body, depth = 1, siteUrl = '', pathName = '' }) {
  const up = '../'.repeat(depth);
  const canonical = siteUrl ? `${siteUrl.replace(/\/$/, '')}/${pathName}` : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark"><title>${esc(title)} · Threat Recap</title><meta name="description" content="${esc(desc)}">
${canonical ? `<link rel="canonical" href="${esc(canonical)}"><meta property="og:url" content="${esc(canonical)}"><meta property="og:image" content="${esc(siteUrl.replace(/\/$/, ''))}/og.png">` : ''}
<meta property="og:title" content="${esc(title)} · Threat Recap"><meta property="og:description" content="${esc(desc)}"><meta property="og:type" content="website"><meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="${up}icon.svg" type="image/svg+xml"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&family=Source+Serif+4:opsz,wght@8..60,600;8..60,700&display=swap"><link rel="stylesheet" href="${up}style.css">
<script>try{var t=localStorage.getItem('cih.theme');if(t)document.documentElement.dataset.theme=t}catch(e){}</script></head>
<body><a class="skip" href="#main">Skip to content</a><header class="top"><div class="wrap top-row"><a class="brand" href="${up}"><img src="${up}icon.svg" alt=""><span>Threat Recap</span></a>
<nav class="crumbs"><a href="${up}">News</a> · <a href="${up}actors/">Threat actors</a> · <a href="${up}vendors/">Vendors</a> · <a href="${up}groups/">Ransomware groups</a></nav></div></header>
<main class="wrap" id="main">${body}</main>
<footer><div class="wrap">Threat Recap — free cybersecurity news. Tags and actor names are keyword-based and can be wrong. Updated ${fmt(Date.now())}.</div></footer></body></html>`;
}
const storyLi = s => `<li><a href="${esc(s.u)}" rel="noopener">${esc(s.t)}</a> <span class="muted">— ${esc(s.s)}${s.r.length ? ` +${s.r.length} sources` : ''}, ${day(s.d)}</span></li>`;
const barsHtml = (entries, label = x => x) => { const max = Math.max(1, ...entries.map(e => e[1])); return `<div class="bars">${entries.map(([k, n]) => `<div class="bar-row"><div class="lbl" title="${esc(label(k))}">${esc(label(k))}</div><div class="bar-track" title="${esc(label(k))}: ${n}"><div class="bar" style="width:${(n / max) * 88}%"></div><span class="bar-val">${n}</span></div></div>`).join('')}</div>`; };
function weekly(stories, now) {
  const weeks = []; for (let w = 4; w >= 0; w--) { const end = now - w * 7 * DAY, start = end - 7 * DAY; weeks.push([`Week of ${day(start).slice(5)}`, stories.filter(s => s.d > start && s.d <= end).length]); }
  return weeks;
}
const count = arr => { const m = {}; for (const x of arr) m[x] = (m[x] || 0) + 1; return Object.entries(m).sort((a, b) => b[1] - a[1]); };
const rssLink = (href, up) => `<a class="chip" href="${up}${href}">RSS feed</a>`;

function rss({ title, link, desc, items }) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel><title>${esc(title)}</title><link>${esc(link)}</link><description>${esc(desc)}</description><lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
${items.slice(0, 60).map(i => `<item><title>${esc(i.title)}</title><link>${esc(i.link)}</link><guid isPermaLink="false">${esc(i.guid || i.link)}</guid><pubDate>${new Date(i.date).toUTCString()}</pubDate>${i.desc ? `<description>${esc(i.desc)}</description>` : ''}${(i.cats || []).map(c => `<category>${esc(c)}</category>`).join('')}</item>`).join('\n')}
</channel></rss>\n`;
}
const storyItem = s => ({ title: s.t, link: s.u, date: s.d, guid: s.id, desc: `${s.s}${s.r.length ? ` (+${s.r.length} more sources)` : ''}. ${s.x || ''}${s.ai ? ` Why it matters: ${s.ai}` : ''}`, cats: s.tg.map(t => TAG_LABELS[t] || t) });

export async function writeSite({ root, stories, kevList, info, ransomware, incidents = [], siteUrl = '' }) {
  const pub = path.join(root, 'public'); const now = Date.now();
  const base = siteUrl ? siteUrl.replace(/\/$/, '') + '/' : '';
  const urls = [''];
  const write = async (rel, content) => { const f = path.join(pub, rel); await fs.mkdir(path.dirname(f), { recursive: true }); await fs.writeFile(f, content); };
  for (const dir of ['actors', 'vendors', 'groups', 'feeds', 'stories']) await fs.rm(path.join(pub, dir), { recursive: true, force: true });
  const main = stories.filter(s => !s.b && !s.so);

  // ---- feeds ----
  const feeds = [
    ['latest', 'Latest cybersecurity news', main],
    ['zeroday', 'Zero-days & actively exploited', stories.filter(s => s.tg.includes('zeroday') && !s.so)],
    ['breach', 'Data breaches', main.filter(s => s.tg.includes('breach'))],
    ['apt', 'APT & nation-state activity', stories.filter(s => s.tg.includes('apt') && !s.so)],
    ['ransomware', 'Ransomware news', main.filter(s => s.tg.includes('ransomware'))],
    ['research', 'Threat research', stories.filter(s => s.c === 'research')],
    ['advisories', 'Security advisories', stories.filter(s => s.c === 'advisory')],
    ['supply-chain', 'Supply chain attacks', main.filter(s => s.tg.includes('supply'))],
    ['top', 'Most covered stories (3+ outlets)', main.filter(s => s.r.length >= 2)],
  ];
  for (const [name, title, list] of feeds) await write(`feeds/${name}.xml`, rss({ title: `${title} · Threat Recap`, link: base || './', desc: title, items: list.map(storyItem) }));
  await write('feeds/kev.xml', rss({ title: 'CISA Known Exploited Vulnerabilities · Threat Recap', link: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', desc: 'Newest additions to the CISA KEV catalog',
    items: kevList.slice(0, 60).map(k => ({ title: `${k.id} — ${k.v} ${k.p}: ${k.n}`, link: `https://nvd.nist.gov/vuln/detail/${k.id}`, date: Date.parse(k.d + 'T12:00:00Z'), guid: 'kev-' + k.id, desc: `${k.x}${k.rw ? ' Known to be used in ransomware campaigns.' : ''} Federal due date ${k.due}.` })) }));

  // ---- actors ----
  const actorRows = [];
  for (const a of ACTOR_INFO) {
    const list = stories.filter(s => s.ac.includes(a.name) && !s.so);
    actorRows.push({ a, n: list.length, last: list[0]?.d });
    const sl = slug(a.name), up = '../';
    const cves = count(list.flatMap(s => s.cv)).slice(0, 15), vend = count(list.flatMap(s => s.ve)).slice(0, 8), mw = count(list.flatMap(s => s.mw || [])).slice(0, 10), att = count(list.flatMap(s => s.at)).slice(0, 8);
    await write(`feeds/actor-${sl}.xml`, rss({ title: `${a.name} · Threat Recap`, link: `${base}actors/${sl}.html`, desc: `News mentioning ${a.name}`, items: list.map(storyItem) }));
    await write(`actors/${sl}.html`, page({ siteUrl, pathName: `actors/${sl}.html`, title: `${a.name} threat actor — latest activity`, desc: `Latest news, CVEs and techniques linked to ${a.name} (${a.aliases.slice(1, 4).join(', ')}).`, body: `
<p><a href="./">← All threat actors</a></p>
<div class="panel"><h1 style="margin:0 0 4px;font-size:26px">${esc(a.name)}</h1><p class="desc">${esc(a.origin)} · also known as ${a.aliases.filter(x => x !== a.name).map(esc).join(', ') || '—'}</p>
<div class="chips"><a class="chip" href="${a.mitre ? `https://attack.mitre.org/groups/${a.mitre}/` : 'https://attack.mitre.org/groups/'}" rel="noopener">MITRE ATT&amp;CK${a.mitre ? ` ${a.mitre}` : ''}</a><a class="chip" href="https://www.google.com/search?q=${encodeURIComponent(`"${a.name}" threat report`)}" rel="noopener">Search reports</a><a class="chip" href="${up}?q=${encodeURIComponent(`actor:"${a.name}"`)}">Search on Threat Recap</a>${rssLink(`feeds/actor-${sl}.xml`, up)}</div></div>
<div class="brief"><div class="tile"><div class="k">Stories · 30d</div><div class="v">${list.length}</div></div><div class="tile"><div class="k">Last seen in the news</div><div class="v" style="font-size:18px">${list[0] ? day(list[0].d) : '—'}</div></div><div class="tile"><div class="k">CVEs mentioned</div><div class="v">${cves.length}</div></div></div>
<div class="grid-2"><div class="panel"><h2>Activity in the news</h2>${barsHtml(weekly(list, now))}</div>
${cves.length ? `<div class="panel"><h2>CVEs mentioned alongside</h2><div class="chips">${cves.map(([c, n]) => `<a class="chip cve" href="${up}#${c}">${c}${info[c]?.s != null ? ` <span class="sev ${info[c].v}">${info[c].s}</span>` : ''}</a>`).join('')}</div></div>` : ''}
${vend.length ? `<div class="panel"><h2>Vendors in these stories</h2>${barsHtml(vend)}</div>` : ''}
${mw.length ? `<div class="panel"><h2>Malware &amp; tools</h2>${barsHtml(mw)}</div>` : ''}
${att.length ? `<div class="panel"><h2>Likely ATT&amp;CK techniques</h2><div class="chips">${att.map(([t]) => `<a class="chip attack" href="https://attack.mitre.org/techniques/${t.replace('.', '/')}/" rel="noopener">${t}</a>`).join('')}</div><p class="desc">Keyword guesses from headlines, not confirmed attributions.</p></div>` : ''}</div>
<div class="panel"><h2>Timeline (last 30 days)</h2>${list.length ? `<ul class="rel">${list.map(storyLi).join('')}</ul>` : '<p class="muted">No stories in the last 30 days.</p>'}</div>` }));
    urls.push(`actors/${sl}.html`);
  }
  actorRows.sort((x, y) => y.n - x.n || x.a.name.localeCompare(y.a.name));
  await write('actors/index.html', page({ siteUrl, pathName: 'actors/', title: 'Threat actors', desc: 'APT and cybercrime groups tracked by Threat Recap, with aliases and their latest activity in the news.', body: `
<h1 style="font-size:24px">Threat actors</h1><p class="desc">Ranked by stories in the last 30 days. Aliases from vendor naming schemes (Microsoft, CrowdStrike, Mandiant…) are merged.</p>
<div class="panel"><div class="table-wrap"><table><thead><tr><th>Actor</th><th>Origin</th><th>Also known as</th><th>Stories · 30d</th><th>Last seen</th></tr></thead><tbody>
${actorRows.map(({ a, n, last }) => `<tr><td><a href="${slug(a.name)}.html"><strong>${esc(a.name)}</strong></a></td><td class="nowrap">${esc(a.origin)}</td><td><div class="clamp">${a.aliases.filter(x => x !== a.name).slice(0, 5).map(esc).join(', ')}</div></td><td class="num">${n}</td><td class="nowrap">${last ? day(last) : '<span class="muted">—</span>'}</td></tr>`).join('')}
</tbody></table></div></div>` }));
  urls.push('actors/');

  // ---- vendors ----
  const vendorRows = [];
  for (const [name, re] of VENDORS) {
    const list = main.filter(s => s.ve.includes(name)).concat(stories.filter(s => s.b && s.ve.includes(name))).sort((a, b) => b.d - a.d);
    const kev = kevList.filter(k => re.test(`${k.v} ${k.p}`)).slice(0, 25);
    const sl = slug(name), up = '../';
    vendorRows.push({ name, n: list.filter(s => !s.b).length, kev: kev.filter(k => now - Date.parse(k.d) < 90 * DAY).length, last: list[0]?.d });
    const cves = count(list.flatMap(s => s.cv)).slice(0, 20);
    await write(`feeds/vendor-${sl}.xml`, rss({ title: `${name} security news · Threat Recap`, link: `${base}vendors/${sl}.html`, desc: `Security news, advisories and CVEs for ${name}`, items: list.map(storyItem) }));
    await write(`vendors/${sl}.html`, page({ siteUrl, pathName: `vendors/${sl}.html`, title: `${name} security news, vulnerabilities & exploited CVEs`, desc: `Latest ${name} vulnerabilities, actively exploited CVEs (CISA KEV), advisories and security news.`, body: `
<p><a href="./">← All vendors</a></p>
<div class="panel"><h1 style="margin:0 0 4px;font-size:26px">${esc(name)}</h1><p class="desc">Security news, advisories and exploited vulnerabilities.</p><div class="chips"><a class="chip" href="${up}?q=${encodeURIComponent(`vendor:"${name}"`)}">Search on Threat Recap</a>${rssLink(`feeds/vendor-${sl}.xml`, up)}</div></div>
<div class="brief"><div class="tile"><div class="k">News stories · 30d</div><div class="v">${list.filter(s => !s.b).length}</div></div><div class="tile"><div class="k">Advisories · 30d</div><div class="v">${list.filter(s => s.b).length}</div></div><div class="tile"><div class="k">Added to KEV · 90d</div><div class="v">${kev.filter(k => now - Date.parse(k.d) < 90 * DAY).length}</div></div></div>
${kev.length ? `<div class="panel"><h2>Actively exploited (CISA KEV)</h2><div class="table-wrap"><table><thead><tr><th>Added</th><th>CVE</th><th>Product</th><th>Vulnerability</th><th>Ransomware</th></tr></thead><tbody>${kev.map(k => `<tr><td class="nowrap">${k.d}</td><td><a href="${up}#${k.id}" class="linkbtn">${k.id}</a></td><td>${esc(k.p)}</td><td><div class="clamp">${esc(k.n)}</div></td><td>${k.rw ? '<span class="sev CRITICAL">Known</span>' : ''}</td></tr>`).join('')}</tbody></table></div></div>` : ''}
${cves.length ? `<div class="panel"><h2>CVEs in the news</h2><div class="chips">${cves.map(([c]) => `<a class="chip cve" href="${up}#${c}">${c}${info[c]?.s != null ? ` <span class="sev ${info[c].v}">${info[c].s}</span>` : ''}</a>`).join('')}</div></div>` : ''}
<div class="panel"><h2>Timeline (last 30 days)</h2>${list.length ? `<ul class="rel">${list.slice(0, 150).map(storyLi).join('')}</ul>` : '<p class="muted">No stories in the last 30 days.</p>'}</div>` }));
    urls.push(`vendors/${sl}.html`);
  }
  vendorRows.sort((a, b) => b.n - a.n);
  await write('vendors/index.html', page({ siteUrl, pathName: 'vendors/', title: 'Vendors', desc: 'Security news, vulnerabilities and actively exploited CVEs by vendor.', body: `
<h1 style="font-size:24px">Vendors</h1><p class="desc">Ranked by news coverage in the last 30 days.</p>
<div class="panel"><div class="table-wrap"><table><thead><tr><th>Vendor</th><th>News · 30d</th><th>Added to KEV · 90d</th><th>Latest</th></tr></thead><tbody>
${vendorRows.map(v => `<tr><td><a href="${slug(v.name)}.html"><strong>${esc(v.name)}</strong></a></td><td class="num">${v.n}</td><td class="num">${v.kev || '<span class="muted">0</span>'}</td><td class="nowrap">${v.last ? day(v.last) : '—'}</td></tr>`).join('')}
</tbody></table></div></div>` }));
  urls.push('vendors/');

  // ---- ransomware groups ----
  if (ransomware) {
    const byGroup = {}; for (const v of ransomware.all30 || []) (byGroup[v.g] ||= []).push(v);
    const groups = Object.entries(byGroup).sort((a, b) => b[1].length - a[1].length).slice(0, 80);
    for (const [g, vs] of groups) {
      const sl = slug(g), up = '../';
      const nameRe = new RegExp(`(?<![\\w-])${g.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\d+$/, '\\d*')}(?![\\w-])`, 'i');
      const news = g.length >= 4 ? main.filter(s => nameRe.test(`${s.t} ${s.x}`)) : [];
      const daily = {}; for (const v of vs) { const k = day(v.d); daily[k] = (daily[k] || 0) + 1; }
      const days = []; for (let i = 29; i >= 0; i--) { const k = day(now - i * DAY); days.push([k, daily[k] || 0]); }
      const max = Math.max(1, ...days.map(d => d[1]));
      await write(`groups/${sl}.html`, page({ siteUrl, pathName: `groups/${sl}.html`, title: `${g} ransomware group — claimed victims & news`, desc: `${g}: ${vs.length} claimed victims in the last 30 days, targeted countries and sectors, and related news.`, body: `
<p><a href="./">← All ransomware groups</a></p>
<div class="note">Figures are unverified claims posted on the group's leak site (via ${esc(ransomware.source)}). Victim websites are not linked.</div>
<div class="panel"><h1 style="margin:0 0 4px;font-size:26px">${esc(g)}</h1><div class="chips"><a class="chip" href="https://www.ransomware.live/group/${encodeURIComponent(g)}" rel="noopener">ransomware.live profile</a><a class="chip" href="https://www.google.com/search?q=${encodeURIComponent(`"${g}" ransomware analysis`)}" rel="noopener">Search analysis</a></div></div>
<div class="brief"><div class="tile"><div class="k">Claims · 30d</div><div class="v">${vs.length}</div></div><div class="tile"><div class="k">Countries</div><div class="v">${new Set(vs.map(v => v.c).filter(Boolean)).size}</div></div><div class="tile"><div class="k">Latest claim</div><div class="v" style="font-size:18px">${day(vs[0].d)}</div></div></div>
<div class="panel"><h2>Claims per day</h2><div class="cols"><span class="ymax">${max}</span>${days.map(([d, n]) => `<div class="col" title="${d}: ${n}"><i style="height:${(n / max) * 100}%"></i></div>`).join('')}</div><div class="cols-axis"><span>${days[0][0]}</span><span>${days.at(-1)[0]}</span></div></div>
<div class="grid-2"><div class="panel"><h2>Countries</h2>${barsHtml(count(vs.map(v => v.c).filter(Boolean)).slice(0, 10), country)}</div><div class="panel"><h2>Sectors</h2>${barsHtml(count(vs.map(v => v.a).filter(a => a && a !== 'Not Found')).slice(0, 10))}</div></div>
${news.length ? `<div class="panel"><h2>In the news</h2><ul class="rel">${news.map(storyLi).join('')}</ul></div>` : ''}
<div class="panel"><h2>Latest claims</h2><div class="table-wrap"><table><thead><tr><th>Discovered</th><th>Victim (as claimed)</th><th>Country</th><th>Sector</th></tr></thead><tbody>${vs.slice(0, 60).map(v => `<tr><td class="nowrap">${day(v.d)}</td><td>${esc(v.t)}</td><td>${esc(country(v.c))}</td><td>${esc(v.a && v.a !== 'Not Found' ? v.a : '')}</td></tr>`).join('')}</tbody></table></div></div>` }));
      urls.push(`groups/${sl}.html`);
    }
    await write('groups/index.html', page({ siteUrl, pathName: 'groups/', title: 'Ransomware groups', desc: 'Active ransomware groups ranked by claimed victims in the last 30 days.', body: `
<h1 style="font-size:24px">Ransomware groups</h1><div class="note">Unverified claims from leak sites, last 30 days.</div>
<div class="panel"><div class="table-wrap"><table><thead><tr><th>Group</th><th>Claims · 30d</th><th>Top country</th><th>Latest claim</th></tr></thead><tbody>
${groups.map(([g, vs]) => `<tr><td><a href="${slug(g)}.html"><strong>${esc(g)}</strong></a></td><td class="num">${vs.length}</td><td>${esc(country(count(vs.map(v => v.c).filter(Boolean))[0]?.[0]))}</td><td class="nowrap">${day(vs[0].d)}</td></tr>`).join('')}
</tbody></table></div></div>` }));
    urls.push('groups/');
  }

  // ---- developing stories (timelines) ----
  const KIND = { exploit: 'Exploitation', patch: 'Patch / fix', analysis: 'Analysis', news: 'News', advisory: 'Advisory', kev: 'CISA KEV', poc: 'Public exploit', cve: 'CVE published' };
  for (const inc of incidents) {
    const up = '../';
    let lastDay = '';
    const rows = inc.events.map(e => { const d = day(e.d); const head = d !== lastDay ? `<li class="tl-day">${new Date(e.d).toUTCString().slice(0, 16)}</li>` : ''; lastDay = d;
      return head + `<li class="tl-ev tl-${e.k}"><span class="tl-time">${new Date(e.d).toISOString().slice(11, 16)}</span><span class="tl-kind">${KIND[e.k] || e.k}</span><a href="${esc(e.u)}" rel="noopener">${esc(e.t)}</a>${e.s ? ` <span class="muted">— ${esc(e.s)}</span>` : ''}</li>`; }).join('');
    await write(`stories/${inc.id}.html`, page({ siteUrl, pathName: `stories/${inc.id}.html`, title: inc.title, desc: `Timeline: ${inc.n} stories from ${inc.outlets} outlets, ${day(inc.first)} to ${day(inc.last)}.`, body: `
<p><a href="./">← All developing stories</a></p>
<p class="hero-label">Developing story</p><h1 style="font-size:34px;margin:0 0 8px">${esc(inc.title)}</h1>
<p class="lede">${inc.n} stories from ${inc.outlets} outlets · first report ${day(inc.first)} · latest ${day(inc.last)}${inc.cves?.length ? ` · ${inc.cves.map(c => `<a href="${up}#${c}">${c}</a>`).join(', ')}` : ''}</p>
<ol class="timeline">${rows}</ol>` }));
    urls.push(`stories/${inc.id}.html`);
  }
  if (incidents.length) {
    await write('stories/index.html', page({ siteUrl, pathName: 'stories/', title: 'Developing stories', desc: 'Timelines of the biggest ongoing security incidents and vulnerabilities.', body: `<h1 style="font-size:32px">Developing stories</h1><p class="lede">Ongoing incidents followed across outlets, with exploitation, patches and analysis in date order.</p>
<div class="cve-list">${incidents.map(i => `<article class="cve-row"><div class="cr-main"><h3 class="cr-title"><a href="${i.id}.html">${esc(i.title)}</a></h3><p class="cr-sum">${i.n} stories · ${i.outlets} outlets · ${day(i.first)} → ${day(i.last)}</p></div></article>`).join('')}</div>` }));
    urls.push('stories/');
  }

  // ---- lookup lists for the app (settings, command palette) ----
  const groupList = ransomware ? Object.entries((ransomware.all30 || []).reduce((m, v) => ((m[v.g] = (m[v.g] || 0) + 1), m), {})).sort((a, b) => b[1] - a[1]).slice(0, 80) : [];
  await write('data/meta.json', JSON.stringify({
    vendors: VENDORS.map(([n]) => ({ n, sl: slug(n) })),
    actors: ACTOR_INFO.map(a => ({ n: a.name, sl: slug(a.name), o: a.origin, al: a.aliases.filter(x => x !== a.name).slice(0, 6) })),
    groups: groupList.map(([n, c]) => ({ n, sl: slug(n), c })),
    malware: [...new Set(stories.flatMap(s => s.mw || []))],
    categories: CATEGORIES.map(([c, l]) => ({ c, l })),
    products: PRODUCTS.map(([n, k]) => ({ n, k })),
  }));

  // ---- SEO ----
  if (siteUrl) {
    await write('sitemap.xml', `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${[...urls, 'digest.html', 'api.html'].map(u => `<url><loc>${esc(base + u)}</loc><changefreq>hourly</changefreq></url>`).join('\n')}\n</urlset>\n`);
    await write('robots.txt', `User-agent: *\nAllow: /\nSitemap: ${base}sitemap.xml\n`);
    // absolute share-preview URLs in the main page
    const idx = path.join(pub, 'index.html');
    const html = await fs.readFile(idx, 'utf8');
    await fs.writeFile(idx, html.replace(/(<meta property="og:image" content=")[^"]*(")/, `$1${base}og.png$2`).replace(/(<meta property="og:url" content=")[^"]*(")/, `$1${base}$2`).replace(/(<link rel="canonical" href=")[^"]*(")/, `$1${base}$2`));
  }
  return urls.length;
}
