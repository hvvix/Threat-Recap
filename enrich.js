// Enrichment steps used by build.js: IOC extraction, public PoC lookup, HIBP breaches,
// world map geometry and optional AI "why it matters" lines.

const DAY = 864e5;
const UA = 'Mozilla/5.0 (compatible; ThreatRecap/1.0; +https://github.com/)';
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function getJSON(url, { timeout = 30000, headers = {} } = {}) {
  const r = await fetch(url, { headers: { 'user-agent': UA, accept: 'application/json', ...headers }, signal: AbortSignal.timeout(timeout) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ---------- IOCs ----------
// Precision over recall: defanged indicators are always taken; plain IPs and hashes
// only when the article reads like an IOC write-up. Plain domains are never taken
// (too many false positives from ordinary links).
const IOC_CONTEXT = /indicators? of compromise|\bIoCs?\b|\bSHA-?256\b|\bSHA-?1\b|\bMD5\b|file hash|hashes|C2 (server|infrastructure|domains?|IPs?)|command[- ]and[- ]control/i;
const PRIVATE_IP = /^(192\.0\.2|198\.51\.100|203\.0\.113|198\.1[89]|0|10|127|169\.254|172\.(1[6-9]|2\d|3[01])|192\.168|22[4-9]|23\d|24\d|25[0-5]|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\./;
const BENIGN_IP = new Set(['1.2.3.4', '4.3.2.1', '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '208.67.222.222', '208.67.220.220', '4.2.2.2']);
const EMPTY_HASH = new Set(['d41d8cd98f00b204e9800998ecf8427e', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']);
const FAKE_HASH = /^(0+|f+|(.)\2+|0123456789abcdef.*)$/i;

export function extractIocs(text) {
  if (!text || text.length < 200) return null;
  const refanged = text
    .replace(/hxxps?/gi, m => m.replace(/xx/i, 'tt'))
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
    .replace(/\[:\]|\[:\/\/\]/g, m => (m === '[:]' ? ':' : '://'));
  const defanged = text !== refanged;
  const iocish = IOC_CONTEXT.test(text);
  const out = { h: new Set(), ip: new Set(), d: new Set(), u: new Set() };
  // Defanged URLs / domains / IPs: any whitespace-separated token carrying a defang marker.
  for (const raw of text.split(/[\s"'<>,;]+/)) {
    if (!/hxxp|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[:\]/i.test(raw)) continue;
    const tok = raw.replace(/hxxp/gi, 'http').replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.').replace(/\[:\]/g, ':').replace(/^[([{]+|[)\]}.:]+$/g, '');
    if (/^https?:\/\//i.test(tok)) { out.u.add(tok.slice(0, 300)); try { const h = new URL(tok).hostname.toLowerCase(); (/^[\d.]+$/.test(h) ? out.ip : out.d).add(h); } catch {} }
    else if (/^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(tok)) out.ip.add(tok.replace(/:\d+$/, ''));
    else if (/^(?:[a-z0-9-]+\.)+[a-z]{2,24}(\/\S*)?$/i.test(tok)) out.d.add(tok.split('/')[0].toLowerCase());
  }
  if (defanged || iocish) {
    const noUrls = refanged.replace(/https?:\/\/\S+/g, ' ');
    for (const m of noUrls.matchAll(/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/g)) {
      const ip = m[0], before = noUrls.slice(Math.max(0, m.index - 14), m.index);
      if (ip.split('.').every(o => +o <= 255) && !PRIVATE_IP.test(ip) && !BENIGN_IP.has(ip) && !/^\d+\.\d+\.\d+\.0$/.test(ip) && !/(version|ver\.?|v|build|release|firmware|update)\s*$/i.test(before)) out.ip.add(ip);
    }
    if (iocish) for (const m of noUrls.matchAll(/(?<![a-f0-9])(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-f0-9])/gi)) {
      const h = m[0].toLowerCase(); if (!FAKE_HASH.test(h) && !EMPTY_HASH.has(h) && /[a-f]/.test(h) && /\d/.test(h)) out.h.add(h);
    }
  }
  const res = { h: [...out.h].slice(0, 300), ip: [...out.ip].slice(0, 200), d: [...out.d].filter(d => d.length <= 70 && d.split('.').every(l => l.length <= 40) && !/\.(png|jpe?g|gif|svg|js|css|html?|php)$/.test(d)).slice(0, 200), u: [...out.u].slice(0, 200) };
  const n = res.h.length + res.ip.length + res.d.length + res.u.length;
  return n ? res : null;
}

export async function fetchArticleText(url) {
  const r = await fetch(url, { headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36' }, redirect: 'follow', signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  let html = await r.text();
  const art = html.match(/<article[\s\S]*?<\/article>/i) || html.match(/<main[\s\S]*?<\/main>/i);
  if (art) html = art[0];
  return html.replace(/<(script|style|nav|footer|header)[\s\S]*?<\/\1>/gi, ' ').replace(/<br\s*\/?>|<\/(p|li|tr|td|pre|div|code)>/gi, '\n').replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#(\d+);/g, (_, c) => String.fromCharCode(+c)).replace(/[ \t]+/g, ' ');
}

// ---------- public exploit / PoC watch (nomi-sec/PoC-in-GitHub mirror) ----------
export async function fetchPocs(ids, cache, { budget = 400, now = Date.now() } = {}) {
  const due = ids.filter(id => !cache[id] || now - cache[id].ck > (cache[id].n ? 12 : 24) * 3600e3).slice(0, budget);
  let i = 0;
  await Promise.all(Array.from({ length: 8 }, async () => {
    while (i < due.length) {
      const id = due[i++]; const year = id.split('-')[1];
      try {
        const j = await getJSON(`https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/${year}/${id}.json`, { timeout: 15000 });
        const repos = (j || []).filter(r => !r.fork).sort((a, b) => (b.stargazers_count || 0) - (a.stargazers_count || 0));
        cache[id] = { ck: now, n: repos.length, first: repos.length ? Math.min(...repos.map(r => Date.parse(r.created_at))) : null,
          top: repos.slice(0, 5).map(r => ({ n: r.full_name, u: r.html_url, s: r.stargazers_count || 0, c: Date.parse(r.created_at), d: (r.description || '').slice(0, 140) })) };
      } catch { cache[id] = { ...(cache[id] || {}), ck: now - 20 * 3600e3 }; } // retry soon
    }
  }));
  return due.length;
}

// ---------- Have I Been Pwned: newest breaches loaded ----------
export async function fetchHibp() {
  const j = await getJSON('https://haveibeenpwned.com/api/v3/breaches', { timeout: 60000 });
  return j.filter(b => !b.IsSpamList && !b.IsFabricated).sort((a, b) => b.AddedDate.localeCompare(a.AddedDate)).map(b => ({
    n: b.Title, dom: b.Domain, bd: b.BreachDate, ad: Date.parse(b.AddedDate), c: b.PwnCount, dc: b.DataClasses.slice(0, 6), v: b.IsVerified ? 1 : 0,
    x: b.Description.replace(/<[^>]+>/g, '').replace(/&quot;/g, '"').replace(/&amp;/g, '&').slice(0, 260),
  }));
}

// ---------- world map (TopoJSON -> SVG paths keyed by ISO alpha-2) ----------
export async function buildWorld() {
  const topo = await getJSON('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json', { timeout: 60000 });
  const codes = await getJSON('https://cdn.jsdelivr.net/npm/i18n-iso-countries@7/codes.json');
  const numToA2 = Object.fromEntries(codes.map(([a2, , num]) => [String(+num), a2]));
  const { scale: [sx, sy], translate: [tx, ty] } = topo.transform;
  const arcs = topo.arcs.map(arc => { let x = 0, y = 0; return arc.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx, y * sy + ty]; }); });
  const W = 960, H = 470;
  // Equirectangular, cropped to latitudes 84N..-58S (drops Antarctica).
  const proj = ([lon, lat]) => [((lon + 180) / 360) * W, ((84 - lat) / 142) * H];
  const ring = idxs => {
    const pts = [];
    for (const i of idxs) { const a = i >= 0 ? arcs[i] : arcs[~i].slice().reverse(); pts.push(...(pts.length ? a.slice(1) : a)); }
    // split rings that wrap the antimeridian to avoid horizontal streaks
    let d = '', prev = null;
    for (const p of pts) { const [x, y] = proj(p); d += (!prev || Math.abs(x - prev[0]) > W / 2 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1); prev = [x, y]; }
    return d + 'Z';
  };
  // Marker position: centroid of the country's largest polygon (so the US marker sits on
  // the mainland, not between Alaska and Hawaii).
  const centroid = idxs => {
    const pts = [];
    for (const i of idxs) { const a = i >= 0 ? arcs[i] : arcs[~i].slice().reverse(); pts.push(...a.map(proj)); }
    let A = 0, cx = 0, cy = 0;
    for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) { const f = pts[j][0] * pts[i][1] - pts[i][0] * pts[j][1]; A += f; cx += (pts[j][0] + pts[i][0]) * f; cy += (pts[j][1] + pts[i][1]) * f; }
    return Math.abs(A) < 1e-6 ? null : { a: Math.abs(A / 2), x: cx / (3 * A), y: cy / (3 * A) };
  };
  const paths = {}, centers = {};
  for (const g of topo.objects.countries.geometries) {
    const a2 = numToA2[String(+g.id)]; if (!a2 || g.properties?.name === 'Antarctica') continue;
    const polys = g.type === 'Polygon' ? [g.arcs] : g.type === 'MultiPolygon' ? g.arcs : [];
    paths[a2] = polys.map(p => p.map(ring).join('')).join('');
    const best = polys.map(p => centroid(p[0])).filter(Boolean).sort((a, b) => b.a - a.a)[0];
    if (best) centers[a2] = [+best.x.toFixed(1), +best.y.toFixed(1)];
  }
  return { w: W, h: H, paths, centers };
}

// ---------- Tenable plugins (public RSS of the newest plugins) ----------
const DISTRO = /^(Alpine|Debian|Ubuntu|Oracle Linux|RHEL|Red Hat|SUSE|SUSE SLE|openSUSE|Fedora|AlmaLinux|Alma Linux|Rocky Linux|Amazon Linux|MiracleLinux|CentOS|Photon OS|Slackware|Gentoo|FreeBSD|Azure Linux|Mariner|CBL Mariner|EulerOS|openEuler|Huawei|Tencent|Anolis|TencentOS|Kylin|NewStart|Virtuozzo|Scientific Linux|Mageia|Arch Linux|OracleVM|RockyLinux|Wolfi|Chainguard|Mandriva|AIX|Solaris|HP-UX)\b/i;
export async function fetchTenable(store, { now = Date.now() } = {}) {
  const r = await fetch('https://www.tenable.com/plugins/feeds?sort=newest', { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(60000) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const xml = await r.text();
  const txt = h => h.replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/\s+/g, ' ').trim();
  let added = 0;
  for (const it of xml.match(/<item>[\s\S]*?<\/item>/g) || []) {
    const link = (it.match(/<link>([^<]+)/) || [])[1]; if (!link) continue;
    const m = link.match(/plugins\/([a-z-]+)\/(\d+)/); if (!m) continue;
    const key = m[1] + ':' + m[2]; if (store[key]) continue;
    const title = txt((it.match(/<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/) || [])[1] || '');
    const desc = (it.match(/<description>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/) || [])[1] || '';
    const sev = (desc.match(/with (Critical|High|Medium|Low|Info)\s+Severity/i) || [])[1] || '';
    const section = name => txt((desc.match(new RegExp(`<h3>${name}<\\/h3>\\s*([\\s\\S]*?)(?:<h3>|<p>Read more)`, 'i')) || [])[1] || '').replace(/^null$/, '');
    const cves = [...new Set((desc.match(/CVE-\d{4}-\d{4,7}/g) || []))];
    store[key] = {
      id: +m[2], p: m[1], t: title, v: sev ? sev[0].toUpperCase() + sev.slice(1).toLowerCase() : '', d: Date.parse((it.match(/<pubDate>([^<]+)/) || [])[1]) || now,
      syn: section('Synopsis').slice(0, 220), sol: section('Solution').slice(0, 220), cv: cves.slice(0, 30), ncv: cves.length, distro: DISTRO.test(title) ? 1 : 0, u: link, f: now,
    };
    added++;
  }
  for (const [k, v] of Object.entries(store)) if (now - v.f > 30 * 864e5) delete store[k];
  return added;
}

// ---------- optional AI "why it matters" (needs ANTHROPIC_API_KEY + @anthropic-ai/sdk) ----------
export async function aiSummaries(stories, cache, { max = 30, log = console.log } = {}) {
  if (!process.env.ANTHROPIC_API_KEY) return 0;
  let Anthropic;
  try { ({ default: Anthropic } = await import('@anthropic-ai/sdk')); }
  catch { log('AI summaries skipped: run `npm install` to add @anthropic-ai/sdk'); return 0; }
  const client = new Anthropic();
  const model = process.env.AI_MODEL || 'claude-opus-5-5';
  // Only the stories people are most likely to read: widely covered or zero-days, last 48h.
  const todo = stories.filter(s => !s.b && !s.so && !cache[s.id] && Date.now() - s.d < 2 * DAY && (s.r.length >= 2 || s.tg.includes('zeroday')))
    .sort((a, b) => b.r.length - a.r.length).slice(0, max);
  let done = 0;
  for (const s of todo) {
    const text = [`Headline: ${s.t}`, `Source: ${s.s}`, s.x && `Summary: ${s.x}`, s.r.length && `Other headlines: ${s.r.slice(0, 5).map(r => r[1]).join(' | ')}`,
      s.cv.length && `CVEs: ${s.cv.join(', ')}`].filter(Boolean).join('\n');
    try {
      const res = await client.beta.messages.create({
        model, max_tokens: 1024,
        betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default',
        output_config: { effort: 'low' },
        system: 'You write one-sentence "why it matters" notes for a cybersecurity news site read by defenders. Use only the facts given. Say who is affected and what to do if that is clear. Maximum 30 words. No preamble, no hype, no markdown.',
        messages: [{ role: 'user', content: text }],
      });
      if (res.stop_reason === 'refusal') { cache[s.id] = { t: '', at: Date.now() }; continue; }
      const out = res.content.filter(b => b.type === 'text').map(b => b.text).join(' ').trim();
      if (out) { cache[s.id] = { t: out.slice(0, 300), at: Date.now() }; done++; }
    } catch (e) {
      if (e instanceof Anthropic.AuthenticationError) { log('AI summaries: invalid ANTHROPIC_API_KEY'); break; }
      if (e instanceof Anthropic.RateLimitError) { await sleep(5000); continue; }
      log('AI summary failed:', e.message);
    }
  }
  return done;
}

// ---------- optional AI plain-English CVE explanations (same key and SDK as above) ----------
export async function aiCveExplain(items, cache, { max = 30, log = console.log } = {}) {
  if (!process.env.ANTHROPIC_API_KEY) return 0;
  let Anthropic;
  try { ({ default: Anthropic } = await import('@anthropic-ai/sdk')); }
  catch { log('AI CVE explanations skipped: run `npm install` to add @anthropic-ai/sdk'); return 0; }
  const client = new Anthropic();
  const model = process.env.AI_MODEL || 'claude-opus-5-5';
  let done = 0;
  for (const c of items.filter(c => !cache[c.id]).slice(0, max)) {
    const facts = [`CVE: ${c.id}`, c.title && `Name: ${c.title}`, c.vp && `Product: ${c.vp}`, c.x && `Official description: ${c.x}`,
      c.s != null && `CVSS: ${c.s}`, c.kev && 'Listed in CISA KEV (exploited in the wild)', c.fix && `Fixed versions: ${c.fix}`].filter(Boolean).join('\n');
    try {
      const res = await client.beta.messages.create({
        model, max_tokens: 1024,
        betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default',
        output_config: { effort: 'low' },
        system: 'Explain a software vulnerability to a busy IT administrator in plain English. Two or three short sentences: what an attacker can do, who is affected, and what to do. Use only the facts given; do not invent versions or details. No preamble, no markdown, under 60 words.',
        messages: [{ role: 'user', content: facts }],
      });
      if (res.stop_reason === 'refusal') { cache[c.id] = { t: '', at: Date.now() }; continue; }
      const out = res.content.filter(b => b.type === 'text').map(b => b.text).join(' ').trim();
      if (out) { cache[c.id] = { t: out.slice(0, 420), at: Date.now() }; done++; }
    } catch (e) {
      if (e instanceof Anthropic.AuthenticationError) { log('AI CVE explanations: invalid ANTHROPIC_API_KEY'); break; }
      if (e instanceof Anthropic.RateLimitError) { await sleep(5000); continue; }
      log('AI CVE explanation failed:', e.message);
    }
  }
  return done;
}
