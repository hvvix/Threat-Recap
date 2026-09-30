/* Threat Recap — front end. Plain JS, no build step. Data comes from data/*.json written by build.js. */
(() => {
'use strict';

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
// For href/src: escaped like esc(), and any scheme other than http(s) (javascript:, data:, vbscript: …) becomes '#'.
// Browsers ignore tabs, newlines and leading spaces inside a scheme, so those are stripped before checking.
const url = s => { const v = String(s ?? '').replace(/[\x00-\x20]/g, ''); return /^[a-z][a-z0-9+.-]*:/i.test(v) && !/^https?:/i.test(v) ? '#' : esc(s); };
const DAY = 864e5, HOUR = 36e5;
const PAGE = 50;

// ---------- storage (per-browser conveniences; never required) ----------
const store = {
  get(k, d) { try { const v = localStorage.getItem('cih.' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('cih.' + k, JSON.stringify(v)); } catch {} },
};

// ---------- constants ----------
const TAG_LABELS = { vuln: 'Vulnerability', zeroday: 'Zero-day', breach: 'Breach', apt: 'APT', ransomware: 'Ransomware', malware: 'Malware', supply: 'Supply chain', phishing: 'Phishing', ai: 'AI', law: 'Law & policy', research: 'Research', advisory: 'Advisory' };
const TAG_ORDER = ['zeroday', 'breach', 'ransomware', 'apt', 'supply', 'malware', 'phishing', 'vuln', 'ai', 'law'];
const ATTACK_NAMES = { T1190: 'Exploit Public-Facing Application', T1566: 'Phishing', T1486: 'Data Encrypted for Impact', T1567: 'Exfiltration Over Web Service', T1078: 'Valid Accounts', T1110: 'Brute Force', T1195: 'Supply Chain Compromise', T1189: 'Drive-by Compromise', T1204: 'User Execution', T1059: 'Command and Scripting Interpreter', T1055: 'Process Injection', T1574: 'Hijack Execution Flow', T1547: 'Boot or Logon Autostart Execution', T1053: 'Scheduled Task/Job', 'T1505.003': 'Web Shell', T1021: 'Remote Services', T1219: 'Remote Access Software', T1003: 'OS Credential Dumping', T1555: 'Credentials from Password Stores', T1539: 'Steal Web Session Cookie', T1621: 'MFA Request Generation', T1111: 'Multi-Factor Authentication Interception', T1068: 'Exploitation for Privilege Escalation', T1211: 'Exploitation for Defense Evasion', T1562: 'Impair Defenses', T1027: 'Obfuscated Files or Information', T1071: 'Application Layer Protocol', T1090: 'Proxy', T1498: 'Network Denial of Service', T1485: 'Data Destruction', T1657: 'Financial Theft', T1098: 'Account Manipulation', T1133: 'External Remote Services', T1210: 'Exploitation of Remote Services', T1601: 'Modify System Image' };
const TABS = [
  { id: 'latest', label: 'Latest', list: s => !s.b && !s.so },
  { id: 'mystack', label: 'My stack', list: s => !s.so && isMine(s) },
  { id: 'developing', label: 'Developing' },
  { id: 'zeroday', label: 'Zero-days', list: s => !s.so && s.tg.includes('zeroday') },
  { id: 'cves', label: 'CVEs' },
  { id: 'breach', label: 'Breaches', list: s => !s.so && s.tg.includes('breach') && !s.b },
  { id: 'apt', label: 'APT', list: s => !s.so && s.tg.includes('apt') },
  { id: 'ransomware', label: 'Ransomware' },
  { id: 'malware', label: 'Malware', list: s => !s.so && s.tg.includes('malware') && !s.b },
  { id: 'supply', label: 'Supply chain' },
  { id: 'research', label: 'Research', list: s => s.c === 'research' },
  { id: 'landmarks', label: 'Top of the decade' },
  { id: 'plugins', label: 'Tenable plugins' },
  { id: 'iocs', label: 'IOCs', list: s => s.io > 0 },
  { id: 'advisory', label: 'Advisories', list: s => s.c === 'advisory' },
  { id: 'topics', label: 'Topics' },
  { id: 'categories', label: 'Categories' },
  { id: 'trends', label: 'Trends' },
  { id: 'archive', label: 'Archive' },
  { id: 'patch', label: 'Patch Tuesday' },
  { id: 'saved', label: 'Saved' },
  { id: 'sources', label: 'Sources' },
];
const TAB = Object.fromEntries(TABS.map(t => [t.id, t]));
const regionName = (() => { try { const d = new Intl.DisplayNames(['en'], { type: 'region' }); return c => { try { return c ? d.of(c) : ''; } catch { return c; } }; } catch { return c => c; } })();

// ---------- state ----------
const params = new URLSearchParams(location.search);
const state = {
  tab: TAB[params.get('tab')] ? params.get('tab') : 'latest',
  q: params.get('q') || '',
  range: store.get('range', 30),
  sort: 'new',
  hideRead: store.get('hideRead', false),
  shown: PAGE,
  sub: { cves: 'patch', ransomware: 'claims', topics: 'all' },
  rwShown: 50,
  sevFilter: 'HIGH+',
  focus: -1,
};
const D = { news: null, cves: null, rw: null, supply: null, sources: null, breaches: null, meta: null, otd: [], iocs: null, world: null, config: {} };
// Per-browser settings: vendors/keywords you run, notification choices, headline language.
const settings = Object.assign({ stack: { vendors: [], keywords: [] }, notify: { on: false, zeroday: true, kev: true, stack: true, saved: true }, lang: '' }, store.get('settings', {}));
const saveSettings = () => { store.set('settings', settings); syncSwState(); };
// "Since your last visit": fixed for the whole browser session.
const sinceVisit = (() => {
  let v; try { v = +sessionStorage.getItem('cih.since'); } catch {}
  if (!v) { v = store.get('lastVisit', 0) || Date.now() - DAY; try { sessionStorage.setItem('cih.since', v); } catch {} }
  store.set('lastVisit', Date.now());
  return v;
})();
let saved = store.get('saved', {});          // id -> record
let readSet = new Set(store.get('read', []));
let byId = new Map(), byLink = new Map(), cveMentions = new Map(), hay = new Map();

// ---------- time formatting ----------
const fmtAgo = t => {
  const s = (Date.now() - t) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 7) return `${Math.floor(s / 86400)}d ago`;
  return new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
};
const fmtFull = t => new Date(t).toLocaleString(undefined, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
const fmtShort = t => new Date(t).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
const fmtDay = t => {
  const d = new Date(t), today = new Date(); today.setHours(0, 0, 0, 0);
  const diff = Math.round((today - new Date(d.getFullYear(), d.getMonth(), d.getDate())) / DAY);
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  return d.toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' });
};

// ---------- data loading ----------
async function getJSON(name, fresh) {
  const r = await fetch(`data/${name}`, { cache: fresh ? 'no-cache' : 'default' });
  if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
  return r.json();
}
async function loadAll(fresh = false) {
  const [news, cves, rw, supply, sources, breaches, meta, incidents] = await Promise.allSettled(['news.json', 'cves.json', 'ransomware.json', 'supply.json', 'sources.json', 'breaches.json', 'meta.json', 'incidents.json'].map(n => getJSON(n, fresh)));
  if (news.status !== 'fulfilled') throw news.reason;
  D.news = news.value;
  D.cves = cves.value || { kev: [], kevIndex: {}, info: {}, epss: {}, recent: [], poc: {} };
  D.cves.poc ||= {};
  D.rw = rw.value || null;
  D.supply = supply.value || { advisories: [] };
  D.sources = sources.value || { sources: [] };
  D.breaches = breaches.value || { hibp: [] };
  D.meta = meta.value || { vendors: [], actors: [], groups: [], malware: [] };
  D.incidents = incidents.value || { incidents: [] };
  if (fresh) D.iocs = null;
  index();
}
// Large/rarely needed files load on demand.
async function lazy(key, file) { if (!D[key]) { try { D[key] = await getJSON(file); } catch { D[key] = null; } } return D[key]; }
function index() {
  byId = new Map(); byLink = new Map(); cveMentions = new Map(); hay = new Map();
  for (const s of D.news.stories) {
    byId.set(s.id, s);
    byLink.set(s.u, s); for (const r of s.r) byLink.set(r[2], s);
    for (const c of s.cv) { if (!cveMentions.has(c)) cveMentions.set(c, []); cveMentions.get(c).push(s); }
  }
  recentById = new Map((D.cves.recent || []).map(r => [r.id, r]));
  kevById = new Map((D.cves.kev || []).map(k => [k.id, k]));
  srcIcon = Object.fromEntries((D.sources.sources || []).filter(s => s.ic).map(s => [s.n, s.ic]));
  catLabel = Object.fromEntries((D.meta.categories || []).map(c => [c.c, c.l]));
}
let srcIcon = {}, catLabel = {}, recentById = new Map(), kevById = new Map();
const haystack = s => {
  let h = hay.get(s.id);
  if (!h) {
    h = [s.t, s.x, s.s, s.ai || '', ...s.r.map(r => r[0] + ' ' + r[1]), ...s.cv, ...s.ac, ...s.ve, ...s.at, ...(s.mw || []), ...(s.tp || []), ...s.tg.map(t => TAG_LABELS[t] || t)].join(' \u0001 ').toLowerCase();
    hay.set(s.id, h);
  }
  return h;
};
// "#Topic" hashtags: product, vendor, actor, malware, category or tag names without spaces.
const norm = x => String(x).toLowerCase().replace(/[^a-z0-9]/g, '');
const hashtag = name => '#' + String(name).replace(/[^A-Za-z0-9]/g, '');
// Combined vendor labels ("Docker / Kubernetes") become separate topics.
const vendorParts = list => list.flatMap(v => v.split(/\s*\/\s*/)).filter(v => v && v !== 'routers');
function storyTopics(s) { return [...(s.tp || []), ...vendorParts(s.ve), ...s.ve, ...s.ac, ...(s.mw || []), ...(s.ct || []).map(c => catLabel[c] || c), ...(s.ct || []), ...s.tg, ...s.tg.map(t => TAG_LABELS[t] || t)]; }

// ---------- search ----------
// Free text (all words must match), "exact phrases", #hashtags and field filters:
// cve:, actor:, vendor:, malware:, source:, tag:, cat:, attack:   e.g.  vendor:cisco #zeroday cat:exp
function parseQuery(q) {
  const terms = [];
  const re = /(\w+):"([^"]+)"|(\w+):(\S+)|#(\S+)|"([^"]+)"|(\S+)/g; let m;
  while ((m = re.exec(q))) {
    if (m[1]) terms.push({ f: m[1].toLowerCase(), v: m[2].toLowerCase() });
    else if (m[3] && ['cve', 'actor', 'vendor', 'source', 'tag', 'attack', 'src', 'malware', 'cat', 'topic'].includes(m[3].toLowerCase())) terms.push({ f: m[3].toLowerCase(), v: m[4].toLowerCase() });
    else if (m[5]) terms.push({ f: 'topic', v: m[5].toLowerCase() });
    else terms.push({ v: (m[6] || m[3] && `${m[3]}:${m[4]}` || m[7]).toLowerCase() });
  }
  return terms;
}
function matches(s, terms) {
  for (const { f, v } of terms) {
    if (!f) { if (!haystack(s).includes(v)) return false; continue; }
    const inList = list => list.some(x => x.toLowerCase().includes(v));
    if (f === 'cve' && !inList(s.cv)) return false;
    if (f === 'actor' && !inList(s.ac)) return false;
    if (f === 'vendor' && !inList(s.ve)) return false;
    if ((f === 'source' || f === 'src') && !inList([s.s, ...s.r.map(r => r[0])])) return false;
    if (f === 'attack' && !inList(s.at)) return false;
    if (f === 'malware' && !inList(s.mw || [])) return false;
    if (f === 'cat' && !(s.ct || []).includes(v)) return false;
    if (f === 'topic' && !storyTopics(s).some(x => norm(x) === norm(v))) return false;
    if (f === 'tag' && !s.tg.some(t => t.includes(v) || (TAG_LABELS[t] || '').toLowerCase().includes(v))) return false;
  }
  return true;
}
function highlight(text, terms) {
  const words = terms.filter(t => !t.f && t.v.length > 1).map(t => t.v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const safe = esc(text);
  if (!words.length) return safe;
  return safe.replace(new RegExp(`(${words.map(w => esc(w)).join('|')})`, 'gi'), '<mark>$1</mark>');
}
const plainCveQuery = q => (q.trim().match(/^(?:cve:)?(cve-\d{4}-\d{4,7})$/i) || [])[1]?.toUpperCase();

// ---------- saved / read ----------
const persistSaved = () => { store.set('saved', saved); renderTabs(); };
const isSaved = s => !!(saved[s.id] || savedFor(s));
function savedFor(s) {
  if (saved[s.id]) return saved[s.id];
  const links = new Set([s.u, ...s.r.map(r => r[2])]);
  return Object.values(saved).find(v => v.links?.some(l => links.has(l)));
}
const kevOf = s => s.cv.filter(c => D.cves.kevIndex?.[c]);
function toggleSave(s) {
  const rec = savedFor(s);
  if (rec) { delete saved[rec.id]; }
  else saved[s.id] = { id: s.id, t: s.t, u: s.u, s: s.s, d: s.d, cv: s.cv, links: [s.u, ...s.r.map(r => r[2])], n: s.r.length + 1, kev: kevOf(s), savedAt: Date.now() };
  persistSaved();
}
// Update tracking: more outlets covering it, or its CVEs landed in CISA KEV.
function updatesFor(s) {
  const rec = savedFor(s); if (!rec) return null;
  const n = s.r.length + 1, kev = kevOf(s);
  const moreSrc = n - (rec.n || 1), newKev = kev.filter(c => !(rec.kev || []).includes(c));
  if (moreSrc <= 0 && !newKev.length) return null;
  const parts = [];
  if (moreSrc > 0) parts.push(`+${moreSrc} source${moreSrc > 1 ? 's' : ''}`);
  if (newKev.length) parts.push('now in KEV');
  return { rec, text: `Updated: ${parts.join(' · ')}` };
}
function ackUpdate(s) {
  const rec = savedFor(s); if (!rec) return;
  rec.n = s.r.length + 1; rec.kev = kevOf(s); rec.links = [...new Set([...(rec.links || []), s.u, ...s.r.map(r => r[2])])];
  if (rec.id !== s.id) { delete saved[rec.id]; rec.id = s.id; saved[s.id] = rec; }
  persistSaved();
}
function markRead(id) {
  if (readSet.has(id)) return;
  readSet.add(id);
  const arr = [...readSet]; store.set('read', arr.slice(-5000));
  $$(`.story[data-id="${CSS.escape(id)}"]`).forEach(el => el.classList.add('read'));
}

// ---------- rendering helpers ----------
function cveChip(id) {
  const i = D.cves.info?.[id] || {}, k = D.cves.kevIndex?.[id], e = D.cves.epss?.[id];
  const title = [i.v && `CVSS ${i.s} ${i.v}`, e && `EPSS ${(e[0] * 100).toFixed(1)}%`, k && `In CISA KEV since ${k}`].filter(Boolean).join(' · ') || 'Details';
  const p = D.cves.poc?.[id];
  return `<button class="chip cve" data-cve="${id}" title="${esc(title + (p ? ' · public exploit code exists' : ''))}">${id}${i.s != null ? ` <span class="sev ${i.v}">${i.s}</span>` : ''}${k ? ' <span class="kev">KEV</span>' : ''}${p ? ' <span class="poc">PoC</span>' : ''}</button>`;
}
// "My stack": a story matches a vendor you picked or one of your keywords.
function isMine(s) {
  const st = settings.stack;
  if (!st.vendors.length && !st.keywords.length) return false;
  if (s.ve.some(v => st.vendors.includes(v))) return true;
  const h = haystack(s);
  return st.keywords.some(k => k && h.includes(k.toLowerCase()));
}
function reportLink(s) {
  const repo = D.config.repoUrl; if (!repo) return '';
  const body = `Story: ${s.t}\nLink: ${s.u}\nTags: ${s.tg.join(', ')}\nActors: ${s.ac.join(', ')}\nVendors: ${s.ve.join(', ')}\nCVEs: ${s.cv.join(', ')}\n\nWhat's wrong?\n`;
  return `<a class="report" href="${url(`${repo}/issues/new?title=${encodeURIComponent('Wrong tag: ' + s.t.slice(0, 80))}&body=${encodeURIComponent(body)}`)}" target="_blank" rel="noopener" title="Report a wrong tag or problem with this story">Report</a>`;
}
// Source avatar: initials on a hue derived from the name, so each outlet is recognisable at a glance.
// Source icon: the site's favicon (fetched at build time, served locally), else coloured initials.
function avatar(name) {
  if (srcIcon[name]) return `<img class="favicon" src="icons/${esc(srcIcon[name])}" alt="" width="20" height="20" loading="lazy" data-ini="${esc(initials(name))}" data-hue="${hue(name)}">`;
  return `<span class="avatar" style="--h:${hue(name)}" aria-hidden="true">${esc(initials(name))}</span>`;
}
function hue(name) { let h = 0; for (const c of name) h = (h * 31 + c.charCodeAt(0)) % 360; return h; }
function initials(name) {
  const words = name.replace(/\(.*?\)/g, '').replace(/^The /, '').split(/[\s.-]+/).filter(w => /^[A-Za-z0-9]/.test(w));
  return (words.length > 1 ? words[0][0] + words[1][0] : (words[0] || '?').slice(0, 2)).toUpperCase();
}
const catBadges = s => (s.ct || []).map(c => `<button class="cat cat-${c}" data-q="cat:${c}" title="${esc(catLabel[c] || c)} — show all">${c}</button>`).join('');
const ACCENT_ORDER = ['zeroday', 'breach', 'ransomware', 'apt', 'supply', 'malware'];
const showImages = () => settings.images !== false;
function storyCard(s, terms, { hero = false } = {}) {
  const upd = updatesFor(s);
  const tags = TAG_ORDER.filter(t => s.tg.includes(t) && !(t === 'vuln' && s.cv.length));
  const chips = [
    ...tags.map(t => `<button class="chip tag ${t}" data-tag="${t}">${TAG_LABELS[t]}</button>`),
    ...s.cv.slice(0, 6).map(cveChip),
    s.cv.length > 6 ? `<span class="chip" title="${esc(s.cv.slice(6).join(', '))}">+${s.cv.length - 6} CVEs</span>` : '',
    s.io ? `<button class="chip ioc" data-iocs="${esc(s.id)}" title="Indicators of compromise found in this report">${s.io} IOCs</button>` : '',
    ...s.ac.map(a => `<button class="chip actor" data-q="actor:&quot;${esc(a)}&quot;" title="Show all stories about ${esc(a)}">${esc(a)}</button>`),
    ...(s.mw || []).slice(0, 3).map(m => `<button class="chip malware" data-q="malware:&quot;${esc(m)}&quot;" title="Show all stories about ${esc(m)}">${esc(m)}</button>`),
    ...[...new Map([...(s.tp || []), ...vendorParts(s.ve)].map(x => [norm(x), x])).values()].slice(0, 4).map(v => `<button class="chip topic" data-q="${esc(hashtag(v))}" title="All stories about ${esc(v)}">${esc(hashtag(v))}</button>`),
    ...s.at.slice(0, 3).map(t => `<a class="chip attack" href="https://attack.mitre.org/techniques/${t.replace('.', '/')}/" target="_blank" rel="noopener" title="${esc(ATTACK_NAMES[t] || '')} — keyword guess, not confirmed">${t}</a>`),
    s.tg.includes('breach') && !s.so ? `<a class="chip" href="https://haveibeenpwned.com/" target="_blank" rel="noopener" title="Check whether your email appears in known breaches">Check HIBP ↗</a>` : '',
  ].join('');
  const n = s.r.length;
  const mine = !s.so && isMine(s);
  const acc = ACCENT_ORDER.find(t => s.tg.includes(t));
  const isSv = isSaved(s);
  const thumb = showImages() && s.im ? `<a class="thumb" href="${url(s.u)}" target="_blank" rel="noopener" data-open tabindex="-1" aria-hidden="true"><img src="${url(s.im)}" alt="" loading="lazy" referrerpolicy="no-referrer" decoding="async"></a>` : '';
  const cls = ['story', readSet.has(s.id) && 'read', mine && 'mine', acc && `acc-${acc}`, hero && 'hero-story', thumb && 'has-thumb'].filter(Boolean).join(' ');
  return `<article class="${cls}" data-id="${esc(s.id)}"><div class="sc">
  ${hero ? `<div class="hero-label">${icon('flame')} Top story · ${n + 1} outlets</div>` : ''}
  <div class="meta">${avatar(s.s)}<span class="src"><button data-q="source:&quot;${esc(s.s)}&quot;" title="More from ${esc(s.s)}">${esc(s.s)}</button></span>
    <span aria-hidden="true">·</span><time datetime="${new Date(s.d).toISOString()}" title="Published ${esc(fmtFull(s.d))}">${fmtAgo(s.d)}</time>
    <span aria-hidden="true">·</span><span>${esc(fmtShort(s.d))}</span>
    ${n && !hero ? `<span class="badge-src" title="Covered by ${n + 1} outlets">${n + 1} sources</span>` : ''}
    ${upd ? `<button class="badge-update" data-ack="${esc(s.id)}" title="Click to mark as seen">${esc(upd.text)}</button>` : ''}
    ${mine ? '<span class="badge-mine" title="Matches your stack (Settings)">Your stack</span>' : ''}
  </div>
  <div class="head"><h3><a href="${url(s.u)}" target="_blank" rel="noopener" data-open>${highlight(s.t, terms)}</a> <span class="cats">${catBadges(s)}</span></h3>
    <div class="card-actions"><button class="save" data-save aria-pressed="${isSv}" title="${isSv ? 'Remove from saved' : 'Save for later'} (s)">${icon('bookmark')}<span class="lbl">${isSv ? 'Saved' : 'Save'}</span></button><button class="hide-btn" data-hide aria-haspopup="menu" title="Hide this story, its source or a topic" aria-label="Hide options">${icon('eyeoff')}</button></div></div>
  ${s.x && !s.so ? `<p class="sum">${highlight(s.x, terms)}</p>` : ''}
  ${s.ai ? `<p class="ai-note" title="AI-generated from the headline and summary; check the article"><span>Why it matters</span> ${esc(s.ai)}</p>` : ''}
  ${incLine(s)}
  <div class="chips">${chips}<span class="card-links"><a class="report" href="${url(wayback(s.u))}" target="_blank" rel="noopener" title="Saved copy on the Wayback Machine, in case the article changes or disappears">Archived copy</a>${reportLink(s)}</span></div>
  ${hero && n ? `<div class="hero-outlets">${s.r.slice(0, 8).map(r => `<a href="${url(r[2])}" target="_blank" rel="noopener" data-open title="${esc(r[1])}">${esc(r[0])}</a>`).join('')}${n > 8 ? `<span class="muted">+${n - 8} more</span>` : ''}</div>`
    : n ? `<details class="more"><summary>${n} more source${n > 1 ? 's' : ''}</summary><ul>${s.r.map(r => `<li><a href="${url(r[2])}" target="_blank" rel="noopener" data-open>${highlight(r[1], terms)}</a> <span class="muted">— ${esc(r[0])}, ${fmtAgo(r[3])}</span></li>`).join('')}</ul></details>` : ''}
  </div>${thumb}
</article>`;
}
// Dense one-line row (feed-reader style).
function storyRow(s, terms) {
  const isSv = isSaved(s), n = s.r.length;
  const acc = ACCENT_ORDER.find(t => s.tg.includes(t));
  return `<article class="story row${readSet.has(s.id) ? ' read' : ''}${!s.so && isMine(s) ? ' mine' : ''}${acc ? ` acc-${acc}` : ''}" data-id="${esc(s.id)}">
    ${avatar(s.s)}<span class="rsrc" title="${esc(s.s)}">${esc(s.s)}</span>
    <span class="rtitle"><a href="${url(s.u)}" target="_blank" rel="noopener" data-open title="${esc(s.x || s.t)}">${highlight(s.t, terms)}</a>${n ? ` <span class="badge-src" title="Covered by ${n + 1} outlets">${n + 1}</span>` : ''} <span class="cats">${catBadges(s)}</span>${s.cv.slice(0, 2).map(cveChip).join('')}</span>
    <time class="rtime" datetime="${new Date(s.d).toISOString()}" title="${esc(fmtFull(s.d))}">${fmtAgo(s.d)}</time>
    <button class="save icon-only" data-save aria-pressed="${isSv}" title="${isSv ? 'Remove from saved' : 'Save for later'} (s)">${icon('bookmark')}<span class="lbl sr">${isSv ? 'Saved' : 'Save'}</span></button>
  </article>`;
}
function setSaveButton(el, s) {
  const sv = isSaved(s);
  el.setAttribute('aria-pressed', sv); el.title = `${sv ? 'Remove from saved' : 'Save for later'} (s)`;
  el.innerHTML = `${icon('bookmark')}<span class="lbl${el.classList.contains('icon-only') ? ' sr' : ''}">${sv ? 'Saved' : 'Save'}</span>`;
}
function storyList(stories, terms, { groupByDay = state.sort === 'new', hero = false } = {}) {
  if (!stories.length) return `<div class="empty">No stories match${state.q ? ` “${esc(state.q)}”` : ''}. ${state.range < 30 ? 'Try a longer time range.' : ''}</div>`;
  const view = settings.density || 'cards';
  let html = '', lastDay = '';
  let list = stories;
  // Top story: the most covered story of the last 24 hours, pinned above the feed.
  if (hero && view !== 'list' && !state.q && state.sort === 'new') {
    const top = stories.filter(s => Date.now() - s.d < DAY && !s.b).sort((a, b) => b.r.length - a.r.length)[0];
    if (top && top.r.length >= 2) { html += storyCard(top, terms, { hero: true }); list = stories.filter(s => s !== top); }
  }
  const card = view === 'list' ? storyRow : storyCard;
  let group = '';
  for (const s of list.slice(0, state.shown)) {
    if (groupByDay) { const d = fmtDay(s.d); if (d !== lastDay) { if (group) html += `<div class="group">${group}</div>`; group = ''; html += `<div class="day">${esc(d)}</div>`; lastDay = d; } }
    group += card(s, terms);
  }
  html += `<div class="group">${group}</div>`;
  if (list.length > state.shown) html += `<button class="loadmore" data-more>Show more (${list.length - state.shown} remaining)</button>`;
  return `<div class="list view-${view}">${html}</div>`;
}
function toolbar(count, { sort = true } = {}) {
  const ranges = [[1, '24h'], [3, '3d'], [7, '7d'], [30, '30d']];
  return `<div class="toolbar">
    <div class="seg" role="group" aria-label="Time range">${ranges.map(([v, l]) => `<button data-range="${v}" aria-pressed="${state.range === v}">${l}</button>`).join('')}</div>
    ${sort ? `<div class="seg" role="group" aria-label="Sort">${[['new', 'Newest'], ['top', 'Most covered']].map(([v, l]) => `<button data-sort="${v}" aria-pressed="${state.sort === v}">${l}</button>`).join('')}</div>` : ''}
    <div class="seg" role="group" aria-label="Layout">${[['cards', 'Cards'], ['list', 'List'], ['grid', 'Grid']].map(([v, l]) => `<button data-density="${v}" aria-pressed="${(settings.density || 'cards') === v}">${l}</button>`).join('')}</div>
    <label><input type="checkbox" id="hide-read" ${state.hideRead ? 'checked' : ''}> Hide read</label>
    <label><input type="checkbox" id="show-img" ${showImages() ? 'checked' : ''}> Images</label>
    <span class="spacer"></span>${state.hiddenCount ? `<button class="linkish muted" data-show-muted>${state.showMuted ? 'Hide' : 'Show'} ${state.hiddenCount} hidden</button>` : ''}<span class="muted">${count.toLocaleString()} ${count === 1 ? 'story' : 'stories'}</span>
  </div>`;
}
function filterStories(pred, { ignoreRange = false } = {}) {
  const terms = parseQuery(state.q);
  const since = Date.now() - state.range * DAY;
  let list = D.news.stories.filter(s => (ignoreRange || s.d >= since) && (!state.hideRead || !readSet.has(s.id)));
  if (terms.length) list = list.filter(s => matches(s, terms) && (pred === TAB.latest.list ? true : pred(s)));
  else list = list.filter(pred);
  const before = list.length;
  if (!state.showMuted) list = list.filter(s => !isMuted(s));
  state.hiddenCount = before - list.length;
  if (state.sort === 'top') list = list.slice().sort((a, b) => b.r.length - a.r.length || b.d - a.d);
  return { list, terms };
}

// ---------- views ----------
// ---------- icons (inline SVG, stroke = currentColor) ----------
const ICON_PATHS = {
  latest: '<path d="M4 5h12v14H6a2 2 0 0 1-2-2z"/><path d="M16 8h4v9a2 2 0 0 1-2 2h-2"/><path d="M7 9h6M7 13h6M7 17h3"/>',
  mystack: '<path d="m12 3 2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9z"/>',
  saved: '<path d="M6 3h12v18l-6-4-6 4z"/>', bookmark: '<path d="M6 3h12v18l-6-4-6 4z"/>',
  zeroday: '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
  breach: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  ransomware: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  apt: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 1v4M12 19v4M1 12h4M19 12h4"/>',
  malware: '<rect x="7" y="7" width="10" height="13" rx="5"/><path d="M12 7V4M9 4l1.5 3M15 4l-1.5 3M3 11h4M17 11h4M3 17h4M17 17h4"/>',
  supply: '<path d="M3 7l9-4 9 4v10l-9 4-9-4z"/><path d="m3 7 9 4 9-4M12 11v10"/>',
  cves: '<path d="M12 2 4 5v6c0 5 3.5 9.5 8 11 4.5-1.5 8-6 8-11V5z"/><path d="M12 8v5M12 16v.5"/>',
  landmarks: '<path d="M8 21h8M12 17v4M7 4h10v5a5 5 0 0 1-10 0z"/><path d="M7 6H4a3 3 0 0 0 3 4M17 6h3a3 3 0 0 1-3 4"/>',
  plugins: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12l6.4-6.4"/>',
  iocs: '<path d="M9 3 7 21M17 3l-2 18M4 8h17M3 16h17"/>',
  research: '<path d="M9 3h6M10 3v6L4 19a2 2 0 0 0 1.7 3h12.6A2 2 0 0 0 20 19l-6-10V3"/><path d="M7 15h10"/>',
  advisory: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21h4"/>',
  trends: '<path d="m3 17 6-6 4 4 8-8"/><path d="M14 7h7v7"/>',
  topics: '<path d="M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L3 13V3h10l7.6 7.6a2 2 0 0 1 0 2.8z"/><circle cx="7.5" cy="7.5" r="1.5"/>',
  categories: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  archive: '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9M10 13h4"/>',
  patch: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
  sources: '<path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1.5"/>',
  users: '<circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 14 0M16 3.5a4 4 0 0 1 0 8M22 21a7 7 0 0 0-5-6.7"/>',
  building: '<rect x="4" y="3" width="16" height="18" rx="1"/><path d="M9 7h1M14 7h1M9 11h1M14 11h1M9 15h1M14 15h1M10 21v-3h4v3"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  code: '<path d="m8 6-6 6 6 6M16 6l6 6-6 6"/>',
  developing: '<path d="M12 22c4 0 7-2.7 7-7 0-4-3-6-4-9-1 2-2 3-3.5 3.5C11 7 10 5 10 2 6 5 5 9 5 13c0 5 3 9 7 9z"/>',
  eyeoff: '<path d="M3 3l18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.9 5.1A10 10 0 0 1 12 5c5 0 9 4.5 10 7-.4 1-1.2 2.3-2.4 3.6M6.1 6.1C4.2 7.4 2.8 9.3 2 12c1 2.5 5 7 10 7 1.7 0 3.3-.5 4.7-1.3"/>',
  flame: '<path d="M12 22c4 0 7-2.7 7-7 0-4-3-6-4-9-1 2-2 3-3.5 3.5C11 7 10 5 10 2 6 5 5 9 5 13c0 5 3 9 7 9z"/>',
  bolt: '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>', list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  history: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/>',
};
const icon = name => `<svg class="i" viewBox="0 0 24 24" aria-hidden="true">${ICON_PATHS[name] || ICON_PATHS.list}</svg>`;

const NAV_GROUPS = [
  ['Your feed', ['latest', 'mystack', 'saved']],
  ['Threats', ['developing', 'zeroday', 'breach', 'ransomware', 'apt', 'malware', 'supply']],
  ['Intelligence', ['cves', 'landmarks', 'plugins', 'iocs', 'research', 'advisory', 'topics', 'categories', 'trends']],
  ['Tools', ['archive', 'patch', 'sources']],
];
const TAB_INFO = {
  latest: 'Every story from 96 sources, newest first.',
  mystack: 'News about the vendors and keywords you follow.',
  saved: 'Stories you saved, with update alerts.',
  developing: 'Ongoing incidents followed across outlets, in date order.',
  zeroday: 'Zero-days and vulnerabilities exploited in the wild.',
  breach: 'Data breaches, leaks and confirmed incidents.',
  ransomware: 'Leak-site claims, active groups and ransomware news.',
  apt: 'Nation-state and named threat-actor activity.',
  malware: 'Malware families, loaders, stealers and botnets.',
  supply: 'Malicious packages and software supply-chain attacks.',
  cves: 'What to patch first, exploited CVEs and new exploits.',
  landmarks: 'The vulnerabilities that defined the last ten years, with live exploitation data.',
  plugins: 'New Nessus and Tenable scanner checks, with their CVEs.',
  iocs: 'Indicators of compromise from research reports.',
  research: 'Original research and threat-intel reports.',
  advisory: 'Vendor and government security advisories.',
  trends: 'What is rising this week, and this week in numbers.',
  topics: 'Products, vendors, threat actors and malware as #hashtags.',
  categories: 'Stories by technical area: appsec, exploits, cloud, ICS and more.',
  archive: 'Everything since January 1: news, CVEs, exploited list, ransomware and breaches.',
  patch: 'Patch Tuesday and vendor release calendar.',
  sources: 'Every source we read, and whether it is working.',
};
function tabCounts() {
  const now = Date.now(), c = {};
  for (const t of TABS) if (t.list && !['latest', 'mystack', 'research', 'advisory', 'iocs'].includes(t.id)) c[t.id] = D.news.stories.filter(s => now - s.d < DAY && !s.b && t.list(s)).length;
  c.latest = D.news.stories.filter(s => now - s.d < DAY && !s.b && !s.so).length;
  if (settings.stack.vendors.length || settings.stack.keywords.length) c.mystack = D.news.stories.filter(s => now - s.d < DAY && !s.so && isMine(s)).length;
  return c;
}
function renderTabs() {
  const updates = D.news ? D.news.stories.filter(s => updatesFor(s)).length : 0;
  const nSaved = Object.keys(saved).length;
  const counts = D.news ? tabCounts() : {};
  const badge = id => {
    if (id === 'saved') return nSaved ? `${updates ? '<span class="dot" title="Saved stories have updates"></span>' : ''}<span class="count">${nSaved}</span>` : '';
    const n = counts[id]; if (!n) return '';
    return `<span class="count${['zeroday', 'breach'].includes(id) ? ' hot' : ''}" title="${n} in the last 24 hours">${n}</span>`;
  };
  $('#tabs').innerHTML = NAV_GROUPS.map(([g, ids]) => `<h4>${g}</h4>${ids.map(id => `<button class="nav-item" role="tab" data-tab="${id}" aria-selected="${state.tab === id}">${icon(id)}<span>${TAB[id].label}</span>${badge(id)}</button>`).join('')}`).join('') +
    `<h4>Explore</h4>
     <a class="nav-item" href="actors/">${icon('users')}<span>Threat actors</span></a>
     <a class="nav-item" href="vendors/">${icon('building')}<span>Vendors</span></a>
     <a class="nav-item" href="groups/">${icon('ransomware')}<span>Ransomware groups</span></a>
     <a class="nav-item" href="digest.html">${icon('mail')}<span>Weekly digest</span></a>
     <a class="nav-item" href="api.html">${icon('code')}<span>API &amp; RSS</span></a>
     <div class="side-foot">Counts show the last 24 hours. Press <kbd>Ctrl</kbd> <kbd>K</kbd> to jump anywhere.</div>`;
  $('#tabs-m').innerHTML = TABS.map(t => `<button class="tab" role="tab" data-tab="${t.id}" aria-selected="${state.tab === t.id}">${icon(t.id)}${t.label}${badge(t.id)}</button>`).join('');
}
function pageHead(t) {
  if (t === 'latest' && !state.q) return '';
  const title = state.q ? `Results for “${esc(state.q)}”` : esc(TAB[t].label);
  const sub = state.q ? `Searching ${t === 'latest' ? 'all stories' : TAB[t].label}` : TAB_INFO[t] || '';
  return `<div class="page-head"><div><h1>${icon(state.q ? 'list' : t)}${title}</h1><p>${esc(sub)}</p></div>${state.q ? '<button class="save" id="clear-search">Clear search</button>' : ''}</div>`;
}

// ---------- right rail ----------
function renderRail() {
  const rail = $('#rail'); if (!rail || !D.news) return;
  if (getComputedStyle(rail).display === 'none') { rail.innerHTML = ''; return; }
  const now = Date.now();
  const w = [];
  if (state.tab === 'latest' && !state.q && briefCache) w.push(`<section class="widget brief-w">${briefCache}</section>`);
  const devs = (D.incidents?.incidents || []).slice(0, 4);
  if (devs.length) w.push(`<section class="widget"><h3>Developing <button class="linkish" data-tab-go="developing">All →</button></h3><ul>${devs.map(i => `<li><span class="grow"><button class="linkish dev-link" data-inc="${esc(i.id)}" data-tab-go="developing">${esc(i.title)}</button><div class="mini">${i.events.length} updates · latest ${fmtAgo(i.last)}</div></span></li>`).join('')}</ul></section>`);
  const pf = patchFirst().slice(0, 5);
  if (pf.length) w.push(`<section class="widget"><h3>${icon('cves')} Patch first <button class="linkish" data-tab-go="cves" data-sub="patch">All →</button></h3><ol>${pf.map((r, i) => `<li><span class="rank">${i + 1}</span><span class="grow"><button class="linkbtn" data-cve="${r.id}">${r.id}</button><div class="mini">${esc(r.what.slice(0, 60))}</div></span>${r.s != null ? `<span class="sev ${r.v}">${r.s}</span>` : ''}</li>`).join('')}</ol></section>`);
  const kev = (D.cves.kev || []).slice(0, 5);
  if (kev.length) w.push(`<section class="widget"><h3>${icon('zeroday')} Newly exploited <button class="linkish" data-tab-go="cves" data-sub="kev">KEV →</button></h3><ul>${kev.map(k => `<li><span class="grow"><button class="linkbtn" data-cve="${k.id}">${k.id}</button> ${k.rw ? '<span class="sev CRITICAL" title="Used in ransomware campaigns">RW</span>' : ''}<div class="mini">${esc(k.v)} ${esc(k.p)}</div></span><span class="mini">${esc(k.d.slice(5))}</span></li>`).join('')}</ul></section>`);
  const tr = trendRows(s => s.ac, { limit: 5 }).filter(r => r.n > 0);
  const prof = Object.fromEntries((D.meta.actors || []).map(a => [a.n, a.sl]));
  if (tr.length) w.push(`<section class="widget"><h3>${icon('trends')} Trending actors <button class="linkish" data-tab-go="trends">Trends →</button></h3><ul>${tr.map(r => `<li><span class="grow">${prof[r.k] ? `<a href="actors/${prof[r.k]}.html">${esc(r.k)}</a>` : `<button class="linkish" data-q="actor:&quot;${esc(r.k)}&quot;">${esc(r.k)}</button>`}</span><span class="mini">${r.n} mentions</span>${r.p === 0 ? '<span class="sev HIGH">new</span>' : r.n > r.p ? '<span class="up">▲</span>' : ''}</li>`).join('')}</ul></section>`);
  if (D.rw) {
    const day = D.rw.recent.filter(v => now - v.d < DAY).length;
    const g = D.rw.groups.slice(0, 4), max = Math.max(1, ...g.map(x => x[1]));
    w.push(`<section class="widget"><h3>${icon('ransomware')} Ransomware <button class="linkish" data-tab-go="ransomware">Tracker →</button></h3><div class="big">${day}</div><div class="mini" style="margin-bottom:10px">claimed victims in 24 h · ${D.rw.total30.toLocaleString()} in 30 days</div><div class="bars">${g.map(([k, n]) => `<div class="bar-row"><div class="lbl">${esc(k)}</div><div class="bar-track" data-tip="${esc(k)}: ${n} claims in 30 days"><div class="bar" style="width:${(n / max) * 80}%"></div><span class="bar-val">${n}</span></div></div>`).join('')}</div></section>`);
  }
  const otd = todayInHistory();
  if (otd) w.push(`<section class="widget"><h3>${icon('history')} On this day</h3><div style="font-size:13.5px"><strong>${otd.y}</strong> — <a href="${url(otd.u)}" target="_blank" rel="noopener">${esc(otd.t)}</a></div></section>`);
  w.push(`<section class="widget"><h3>${icon('sources')} Follow</h3><div class="chips" style="margin:0"><a class="chip" href="feeds/latest.xml">RSS: all</a><a class="chip" href="feeds/zeroday.xml">RSS: zero-days</a><a class="chip" href="feeds/kev.xml">RSS: KEV</a><a class="chip" href="digest.html">Weekly digest</a></div></section>`);
  rail.innerHTML = w.join('');
}
let briefCache = '';

// ---------- theme ----------
function applyTheme(mode) {
  if (mode === 'light' || mode === 'dark') document.documentElement.dataset.theme = mode;
  else delete document.documentElement.dataset.theme;
  try { mode === 'system' ? localStorage.removeItem('cih.theme') : localStorage.setItem('cih.theme', mode); } catch {}
  const cur = document.documentElement.dataset.theme || 'system';
  $$('[data-theme-set]').forEach(b => b.setAttribute('aria-pressed', b.dataset.themeSet === cur));
  if ($('#map svg')) drawMap(+($('#map-day')?.value || 30));
}

function renderBrief() {
  const el = $('#brief');
  if (state.tab !== 'latest' || state.q) { el.hidden = true; briefCache = ''; return; }
  const now = Date.now(), since = sinceVisit;
  const S = D.news.stories;
  // Published since the last visit (first-seen alone would count a brand-new source's whole backlog).
  const fresh = S.filter(s => !s.b && !s.so && s.d > since && s.f > since);
  const day = S.filter(s => !s.b && !s.so && now - s.d < DAY);
  const top = day.slice().sort((a, b) => b.r.length - a.r.length)[0];
  const kevNew = (D.cves.kev || []).filter(k => Date.parse(k.d + 'T23:59:59Z') > since);
  const breaches = fresh.filter(s => s.tg.includes('breach')).sort((a, b) => b.r.length - a.r.length);
  const zd = fresh.filter(s => s.tg.includes('zeroday')).sort((a, b) => b.r.length - a.r.length);
  const rwSince = D.rw ? D.rw.recent.filter(v => v.d > since).length : null;
  const mine = fresh.filter(isMine);
  const hrs = Math.max(1, Math.round((now - since) / HOUR));
  const sinceLabel = hrs >= 48 ? `${Math.round(hrs / 24)} days` : `${hrs} hour${hrs > 1 ? 's' : ''}`;
  const kevText = kevNew.slice(0, 3).map(k => `<button class="linkish" data-cve="${k.id}">${esc(k.v)} ${esc(k.p)}</button>`).join(', ');
  const otd = todayInHistory();
  const lines = [
    `<li><strong>${fresh.length}</strong> new ${fresh.length === 1 ? 'story' : 'stories'}${mine.length ? `, <button class="linkish" data-tab-go="mystack"><strong>${mine.length}</strong> about your stack</button>` : ''}.</li>`,
    kevNew.length ? `<li><strong>${kevNew.length}</strong> newly exploited ${kevNew.length === 1 ? 'vulnerability' : 'vulnerabilities'} added to CISA KEV: ${kevText}${kevNew.length > 3 ? ` <button class="linkish" data-tab-go="cves" data-sub="kev">+${kevNew.length - 3} more</button>` : ''}.</li>` : `<li>No new entries in CISA's exploited-vulnerabilities list.</li>`,
    zd.length ? `<li><strong>${zd.length}</strong> zero-day / active-exploitation ${zd.length === 1 ? 'story' : 'stories'}, led by <a href="${url(zd[0].u)}" target="_blank" rel="noopener">${esc(zd[0].t)}</a>.</li>` : '',
    breaches.length ? `<li><strong>${breaches.length}</strong> breach ${breaches.length === 1 ? 'report' : 'reports'}, including <a href="${url(breaches[0].u)}" target="_blank" rel="noopener">${esc(breaches[0].t)}</a>.</li>` : '',
    rwSince != null ? `<li><strong>${rwSince}</strong> new ransomware leak-site claims.</li>` : '',
    top ? `<li>Most covered today (${top.r.length + 1} outlets): <a href="${url(top.u)}" target="_blank" rel="noopener">${esc(top.t)}</a>.</li>` : '',
    otd ? `<li class="muted">On this day in ${otd.y}: <a href="${url(otd.u)}" target="_blank" rel="noopener">${esc(otd.t)}</a>.</li>` : '',
  ].filter(Boolean).join('');
  // Collapsed by default on phones so the news is visible straight away.
  const open = el.querySelector('details') ? el.querySelector('details').open : innerWidth > 640;
  el.innerHTML = `<details class="morning" ${open ? 'open' : ''}><summary class="morning-head"><h2>${greeting()} <span class="muted" style="font-weight:500">· ${fresh.length} new since ${sinceLabel} ago</span></h2></summary>
      <ul>${lines}</ul><button class="linkish" id="brief-reset" title="Start the brief from now on your next visit" style="font-size:13px;margin-top:6px">Mark all as seen</button></details>`;
  briefCache = `<h2>${greeting()}</h2><div class="mini" style="margin:-4px 0 8px">Since your last visit ${sinceLabel} ago · <button class="linkish" id="brief-reset">Mark all as seen</button></div><ul>${lines}</ul>`;
  el.hidden = false;
}
const greeting = () => { const h = new Date().getHours(); return h < 5 ? 'Late night brief' : h < 12 ? 'Morning brief' : h < 18 ? 'Afternoon brief' : 'Evening brief'; };
function todayInHistory() {
  const md = new Date().toISOString().slice(5, 10);
  return D.otd.find(e => e.md === md) || null;
}

function renderListTab(tabId, extraTop = '') {
  const pred = TAB[tabId].list;
  const { list, terms } = filterStories(pred);
  const cveId = plainCveQuery(state.q);
  const cveBox = cveId ? cvePanelInline(cveId) : '';
  let top = '';
  const since = Date.now() - state.range * DAY;
  if (tabId === 'apt' && !state.q) {
    const counts = {}; for (const s of D.news.stories) if (s.d >= since && !s.so) for (const a of s.ac) counts[a] = (counts[a] || 0) + 1;
    const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 24);
    const prof = Object.fromEntries((D.meta.actors || []).map(a => [a.n, a]));
    if (ranked.length) top = `<div class="panel"><h2>Most-mentioned threat actors</h2><p class="desc">Names are matched using common aliases (e.g. Fancy Bear → APT28). Click to filter; ↗ opens the actor's profile page.</p><div class="chips">${ranked.map(([a, n]) => `<span class="chip-pair"><button class="chip actor" data-q="actor:&quot;${esc(a)}&quot;">${esc(a)} <span class="muted">${n}</span></button>${prof[a] ? `<a class="chip" href="actors/${prof[a].sl}.html" title="${esc(a)} profile${prof[a].o ? ' · ' + esc(prof[a].o) : ''}">↗</a>` : ''}</span>`).join('')}</div>
      <p class="desc" style="margin:10px 0 0"><a href="actors/">All ${D.meta.actors.length} threat actor profiles →</a> · <a href="https://attack.mitre.org/groups/" target="_blank" rel="noopener">MITRE ATT&amp;CK Groups</a> · <a href="https://malpedia.caad.fkie.fraunhofer.de/actors" target="_blank" rel="noopener">Malpedia</a></p></div>`;
  }
  if (tabId === 'malware' && !state.q) {
    const counts = {}; for (const s of D.news.stories) if (s.d >= since) for (const m of s.mw || []) counts[m] = (counts[m] || 0) + 1;
    const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 20);
    if (ranked.length) top = `<div class="panel"><h2>Malware families in the news</h2><div class="chips">${ranked.map(([m, n]) => `<button class="chip malware" data-q="malware:&quot;${esc(m)}&quot;">${esc(m)} <span class="muted">${n}</span></button>`).join('')}</div></div>`;
  }
  if (tabId === 'breach') {
    const sub = state.sub.breach || 'stories';
    top = `<div class="subtabs">${[['stories', 'Latest breaches'], ['size', 'Largest breaches'], ['hibp', 'Have I Been Pwned']].map(([v, l]) => `<button data-sub-breach="${v}" aria-pressed="${sub === v}">${l}</button>`).join('')}</div>`;
    if (sub === 'size') { $('#view').innerHTML = top + toolbar(0, { sort: false }).replace(/<span class="muted">0 stories<\/span>/, '') + breachTracker(); return; }
    if (sub === 'hibp') { $('#view').innerHTML = top + hibpPanel(); return; }
  }
  if (tabId === 'mystack') top = stackPanel();
  if (tabId === 'iocs') top = `<div class="note">Indicators of compromise (hashes, IPs, domains, URLs) pulled from research reports. Defanged indicators are always taken; plain IPs and hashes only from write-ups that list IOCs. Always verify before blocking. <button class="linkish" id="ioc-export">Download all as CSV</button></div>`;
  const note = tabId === 'zeroday' ? `<div class="note">Stories mentioning zero-days or active exploitation, plus any story whose CVE was added to CISA's Known Exploited Vulnerabilities catalog in the last 3 weeks. See the <button class="linkish" data-tab-go="cves" data-sub="kev">KEV list</button> for the authoritative record, or <button class="linkish" data-tab-go="cves" data-sub="patch">Patch first</button> for priorities.</div>` :
    tabId === 'research' ? `<div class="note">Original research and threat-intel reports from vendor labs and independent researchers.</div>` : '';
  const empty = tabId === 'mystack' && !settings.stack.vendors.length && !settings.stack.keywords.length;
  $('#view').innerHTML = cveBox + extraTop + top + note + (empty ? '' : toolbar(list.length) + storyList(list, terms, { groupByDay: state.sort === 'new', hero: tabId === 'latest' }));
}
function stackPanel() {
  const st = settings.stack;
  if (!st.vendors.length && !st.keywords.length) return `<div class="empty"><p><strong>Tell us what you run</strong> and this tab shows only the news that affects you. Matching stories are also marked everywhere.</p><button class="save" data-open-settings>Choose vendors &amp; keywords</button></div>`;
  const vendorLinks = st.vendors.map(v => { const m = (D.meta.vendors || []).find(x => x.n === v); return m ? `<a class="chip" href="vendors/${m.sl}.html" title="${esc(v)} page with exploited CVEs">${esc(v)} ↗</a>` : `<span class="chip">${esc(v)}</span>`; }).join('');
  const kev = (D.cves.kev || []).filter(k => st.vendors.some(v => `${k.v} ${k.p}`.toLowerCase().includes(v.split(/[ /]/)[0].toLowerCase())) || st.keywords.some(w => w && `${k.v} ${k.p} ${k.n}`.toLowerCase().includes(w.toLowerCase()))).slice(0, 8);
  return `<div class="panel"><h2>Your stack</h2><p class="desc">Stories mentioning these vendors or keywords. Saved in this browser only.</p><div class="chips">${vendorLinks}${st.keywords.map(k => `<span class="chip">“${esc(k)}”</span>`).join('')}<button class="chip" data-open-settings>Edit…</button></div>
    ${kev.length ? `<h3 style="font-size:14px;margin:14px 0 6px">Actively exploited in your stack (CISA KEV)</h3><div class="table-wrap"><table><tbody>${kev.map(k => `<tr><td class="nowrap">${k.d}</td><td><button class="linkbtn" data-cve="${k.id}">${k.id}</button></td><td>${esc(k.v)} · ${esc(k.p)}</td><td><div class="clamp">${esc(k.n)}</div></td></tr>`).join('')}</tbody></table></div>` : ''}</div>`;
}
function hibpPanel() {
  const list = (D.breaches?.hibp || []).slice(0, 12);
  if (!list.length) return '';
  const fmtN = n => n >= 1e6 ? (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M' : n >= 1e3 ? Math.round(n / 1e3) + 'K' : n;
  return `<div class="panel"><h2>Newly added to Have I Been Pwned</h2><p class="desc">Breached datasets recently loaded into <a href="https://haveibeenpwned.com/" target="_blank" rel="noopener">HIBP</a> — check whether your email is in them.</p>
  <details open><summary style="cursor:pointer">${list.length} breaches</summary><div class="table-wrap"><table><thead><tr><th>Added</th><th>Breach</th><th>Accounts</th><th>Data exposed</th><th>Breach date</th></tr></thead><tbody>
  ${list.map(b => `<tr><td class="nowrap" title="${esc(fmtFull(b.ad))}">${fmtAgo(b.ad)}</td><td><a href="https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(b.n.replace(/\s/g, ''))}" target="_blank" rel="noopener"><strong>${esc(b.n)}</strong></a>${b.v ? '' : ' <span class="muted" title="Not verified by HIBP">(unverified)</span>'}<div class="clamp muted" style="font-size:13px">${esc(b.x)}</div></td><td class="num">${fmtN(b.c)}</td><td><div class="clamp">${esc(b.dc.join(', '))}</div></td><td class="nowrap">${esc(b.bd)}</td></tr>`).join('')}
  </tbody></table></div></details></div>`;
}

function cvePanelInline(id) {
  const i = D.cves.info?.[id] || D.cves.recent?.find(r => r.id === id) || {};
  const k = D.cves.kevIndex?.[id];
  return `<div class="panel"><h2 style="font-family:var(--mono)">${id} ${i.s != null ? `<span class="sev ${i.v}">CVSS ${i.s} ${i.v}</span>` : ''} ${k ? '<span class="kev">KEV</span>' : ''}</h2>
    <p class="desc">${esc(i.x || 'No description cached yet.')}</p><button class="linkish" data-cve="${id}">Open full CVE details →</button></div>`;
}

// ----- CVEs -----
// Everything we know about one CVE, merged from KEV, CVE.org/NVD lookups and the recent-CVE feed.
function cveInfo(id) {
  const C = D.cves;
  const i = C.info?.[id] || {}, r = recentById.get(id) || {}, k = kevById.get(id);
  const x = (i.x || r.x || k?.x || '').trim();
  // Title: CISA's vulnerability name, else the CNA's title, else "Vulnerability in <product>".
  const vp = k ? `${k.v} ${k.p}` : (i.vp || '');
  const title = k?.n || i.t || (vp ? `Vulnerability in ${vp}` : '');
  return { id, s: i.s ?? r.s, v: i.v ?? r.v, x, title, vp, k, kev: C.kevIndex?.[id], e: C.epss?.[id], p: C.poc?.[id], pub: r.p, cwe: r.cwe };
}
// Short summary: the first one or two sentences of the official description.
function cveSummary(x, max = 260) {
  if (!x) return 'No description published yet.';
  x = x.replace(/\s+/g, ' ').trim();
  // Split only at a full stop followed by a capital letter, so "23.9.7 and prior" stays intact.
  const parts = x.split(/(?<=[.!?])\s+(?=[A-Z(])/);
  let out = '';
  for (const p of parts) { if (out && (out + ' ' + p).length > max) break; out += (out ? ' ' : '') + p; }
  return out.length > max + 60 ? out.slice(0, max).replace(/\s+\S*$/, '') + '…' : out;
}
const sevLabel = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', NONE: 'None' };
function cveRow(id, { rank, why, side = '', mine = false, terms = [] } = {}) {
  const c = cveInfo(id);
  const badges = [
    c.s != null ? `<span class="sev ${c.v}" title="CVSS base score">${c.s} ${sevLabel[c.v] || ''}</span>` : '<span class="sev NONE" title="Not scored yet">Unscored</span>',
    c.kev ? `<span class="kev" title="In CISA's Known Exploited Vulnerabilities catalog since ${c.kev}">KEV</span>` : '',
    c.p ? `<span class="poc" title="Public exploit code exists">PoC</span>` : '',
    c.k?.rw ? `<span class="rwflag" title="Known to be used in ransomware campaigns">Ransomware</span>` : '',
  ].join('');
  const epss = c.e ? `<span class="metric" title="FIRST EPSS: probability of exploitation in the next 30 days (percentile ${(c.e[1] * 100).toFixed(1)})"><b>${(c.e[0] * 100).toFixed(c.e[0] < 0.1 ? 2 : 1)}%</b> EPSS</span>` : '';
  return `<article class="cve-row${mine ? ' mine' : ''}">
    ${rank ? `<div class="cr-rank">${rank}</div>` : ''}
    <div class="cr-main">
      <div class="cr-top"><button class="cr-id" data-cve="${id}">${id}</button><span class="cr-badges">${badges}</span>${epss}</div>
      <h3 class="cr-title"><button class="linkish" data-cve="${id}">${highlight(c.title || id, terms)}</button></h3>
      ${c.vp && c.title && !c.title.includes(c.vp.split(' ')[0]) ? `<div class="cr-affects">${esc(c.vp)}</div>` : ''}
      <p class="cr-sum">${highlight(cveSummary(c.x), terms)}</p>
      ${aiLine(id)}${fixLine(id)}${pocLine(id)}
      ${why?.length ? `<div class="cr-why">${why.map(w => `<span class="why ${w[1]}">${esc(w[0])}</span>`).join('')}</div>` : ''}
    </div>
    ${side ? `<div class="cr-side">${side}</div>` : ''}
  </article>`;
}
function renderCves() {
  const sub = state.sub.cves;
  const q = state.q.trim().toLowerCase();
  const terms = parseQuery(state.q);
  const subs = [['patch', 'Patch first'], ['news', 'In the news'], ['kev', 'Actively exploited'], ['exploits', 'New exploits'], ['new', 'Newly published'], ['stories', 'Vulnerability stories']];
  const text = id => { const c = cveInfo(id); return `${id} ${c.title} ${c.vp} ${c.x}`.toLowerCase(); };
  let body = '';
  const hasPoc = id => { const p = D.cves.poc?.[id]; return !!(p && (p.n || p.edb)); };
  const pocFilter = `<label class="poc-toggle"><input type="checkbox" id="cve-poc" ${state.cvePoc ? 'checked' : ''}> Only CVEs with public exploit code</label>`;
  const list = rows => `${sub !== 'exploits' ? pocFilter : ''}<div class="cve-list">${rows.join('') || '<div class="empty">No matches.</div>'}</div>`;
  if (sub === 'patch') {
    const rows = patchFirst().filter(r => (!q || text(r.id).includes(q)) && (!state.cvePoc || hasPoc(r.id))).slice(0, 60);
    body = `<p class="lede">A to-do list for patching, ranked by real-world risk rather than severity alone: confirmed exploitation first, then the probability of exploitation (EPSS), public exploit code, news coverage and CVSS.${settings.stack.vendors.length ? ' Rows marked in the margin affect your stack.' : ' Pick your vendors in Settings to mark the ones that affect you.'}</p>` +
      list(rows.map((r, i) => cveRow(r.id, { rank: i + 1, why: r.why, mine: r.mine, terms })));
  } else if (sub === 'exploits') {
    let rows = Object.entries(D.cves.poc || {}).filter(([, p]) => p.first).map(([id, p]) => ({ id, ...p })).sort((a, b) => b.first - a.first);
    if (q) rows = rows.filter(r => `${text(r.id)} ${r.top.map(t => t.n + ' ' + t.d).join(' ')}`.toLowerCase().includes(q));
    body = `<p class="lede">Public proof-of-concept code on GitHub for CVEs in the news, the KEV list or rated critical, newest first. A fresh public exploit often means mass exploitation is days away. Data from <a href="https://github.com/nomi-sec/PoC-in-GitHub" target="_blank" rel="noopener">PoC-in-GitHub</a>; treat exploit repositories as untrusted code.</p>` +
      list(rows.slice(0, 120).map(r => { const t = r.top[0]; return cveRow(r.id, { terms, side: `<div class="cr-when" title="${esc(fmtFull(r.first))}">First exploit ${fmtAgo(r.first)}</div><div class="cr-stat"><b>${r.n}</b> repositor${r.n === 1 ? 'y' : 'ies'}</div>${t ? `<a class="cr-link" href="${url(t.u)}" target="_blank" rel="noopener" title="${esc(t.d)}">${esc(t.n)}</a><span class="muted">★ ${t.s}</span>` : ''}` }); }));
  } else if (sub === 'news') {
    const since = Date.now() - state.range * DAY;
    let rows = [...cveMentions.entries()].map(([id, l]) => ({ id, list: l.filter(s => s.d >= since) })).filter(r => r.list.length);
    rows = rows.map(r => ({ ...r, last: Math.max(...r.list.map(s => s.d)), n: r.list.reduce((a, s) => a + (s.b ? 1 : s.r.length + 1), 0) }));
    if (q) rows = rows.filter(r => `${text(r.id)} ${r.list.map(s => s.t).join(' ')}`.toLowerCase().includes(q));
    if (state.cvePoc) rows = rows.filter(r => hasPoc(r.id));
    rows.sort((a, b) => b.n - a.n || b.last - a.last);
    body = `<p class="lede">CVEs mentioned in news and advisories, ranked by how many outlets covered them.</p>` + toolbar(rows.length, { sort: false }).replace(/stories?</, 'CVEs<') +
      list(rows.slice(0, 150).map(r => { const s = r.list.slice().sort((a, b) => b.d - a.d)[0]; return cveRow(r.id, { terms, side: `<div class="cr-stat"><b>${r.n}</b> mention${r.n > 1 ? 's' : ''}</div><div class="cr-when">Latest ${fmtAgo(r.last)}</div><a class="cr-link" href="${url(s.u)}" target="_blank" rel="noopener">${esc(s.t)}</a>` }); }));
  } else if (sub === 'kev') {
    let rows = D.cves.kev || [];
    if (q) rows = rows.filter(k => text(k.id).includes(q));
    if (state.cvePoc) rows = rows.filter(k => hasPoc(k.id));
    body = `<p class="lede">The newest entries in CISA's <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">Known Exploited Vulnerabilities catalog</a>: confirmed exploitation in the wild. These should be patched first.</p>` +
      list(rows.map(k => cveRow(k.id, { terms, side: `<div class="cr-when">Added ${new Date(k.d + 'T12:00:00Z').toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}</div><div class="cr-stat">US federal deadline <b>${new Date(k.due + 'T12:00:00Z').toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</b></div>` })));
  } else if (sub === 'new') {
    const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    let rows = D.cves.recent || [];
    if (state.sevFilter === 'CRITICAL') rows = rows.filter(r => r.v === 'CRITICAL');
    else if (state.sevFilter === 'HIGH+') rows = rows.filter(r => order[r.v] >= 3);
    if (q) rows = rows.filter(r => `${r.id} ${r.x} ${r.cwe || ''}`.toLowerCase().includes(q));
    if (state.cvePoc) rows = rows.filter(r => hasPoc(r.id));
    body = `<p class="lede">CVEs published to the <a href="https://nvd.nist.gov/" target="_blank" rel="noopener">National Vulnerability Database</a> in the last four days. Many new CVEs are not scored yet.</p>
      <div class="toolbar"><div class="seg" role="group" aria-label="Severity">${[['CRITICAL', 'Critical'], ['HIGH+', 'High and critical'], ['ALL', 'All']].map(([v, l]) => `<button data-sev="${v}" aria-pressed="${state.sevFilter === v}">${l}</button>`).join('')}</div><span class="spacer"></span><span class="muted">${rows.length} CVEs</span></div>` +
      list(rows.slice(0, 150).map(r => cveRow(r.id, { terms, side: `<div class="cr-when">Published ${fmtAgo(r.p)}</div>${r.cwe && r.cwe.startsWith('CWE') ? `<div class="cr-stat"><a href="https://cwe.mitre.org/data/definitions/${r.cwe.replace('CWE-', '')}.html" target="_blank" rel="noopener">${esc(r.cwe)}</a></div>` : ''}` })));
  } else {
    const { list: l, terms: t } = filterStories(s => s.tg.includes('vuln'));
    body = toolbar(l.length) + storyList(l, t);
  }
  const cveId = plainCveQuery(state.q);
  $('#view').innerHTML = (cveId ? cvePanelInline(cveId) : '') + `<div class="subtabs">${subs.map(([v, l]) => `<button data-sub-cves="${v}" aria-pressed="${sub === v}">${l}</button>`).join('')}</div>` + body;
}

// Risk-ranked patch list: exploitation evidence first, then likelihood, then impact.
function patchFirst() {
  const now = Date.now(), C = D.cves;
  const ids = new Set([...(C.kev || []).slice(0, 150).map(k => k.id), ...cveMentions.keys(), ...(C.recent || []).filter(r => r.s >= 9).map(r => r.id)]);
  const kevBy = Object.fromEntries((C.kev || []).map(k => [k.id, k]));
  const rows = [];
  for (const id of ids) {
    const i = C.info?.[id] || recentById.get(id) || {}, k = kevBy[id], kd = C.kevIndex?.[id], e = C.epss?.[id], p = C.poc?.[id];
    const mentions = (cveMentions.get(id) || []).reduce((a, s) => a + (s.b ? 1 : s.r.length + 1), 0);
    let score = 0; const why = [];
    if (kd) { score += 50; why.push(['Exploited in the wild', 'crit']); if (now - Date.parse(kd) < 30 * DAY) score += 10; }
    if (k?.rw) { score += 8; why.push(['Used by ransomware', 'crit']); }
    if (e) { score += e[0] * 30; if (e[0] >= 0.1) why.push([`EPSS ${(e[0] * 100).toFixed(e[0] >= 0.995 ? 1 : 0)}%`, e[0] >= 0.5 ? 'high' : 'med']); }
    if (p?.n || p?.edb) { score += 12 + Math.min(8, Math.log2(1 + (p.top?.[0]?.s || 0))); why.push([p.n ? `Public PoC (${p.n})` : 'Exploit-DB', 'high']); }
    if (mentions) { score += Math.min(10, mentions) * 1.5; if (mentions >= 2) why.push([`${mentions} news mentions`, 'low']); }
    if (i.s != null) score += i.s;
    const what = k ? `${k.v} ${k.p}` : i.vp || (i.x || '').slice(0, 90);
    const mine = settings.stack.vendors.some(v => what.toLowerCase().includes(v.split(/[ /]/)[0].toLowerCase()));
    rows.push({ id, score, why, s: i.s, v: i.v, what, mine });
  }
  return rows.sort((a, b) => b.score - a.score);
}

// ----- CVE drawer -----
function openCve(id) {
  id = id.toUpperCase();
  setTimeout(() => fillCvePlugins(id), 0);
  if (location.hash !== `#${id}`) history.replaceState(null, '', `${location.pathname}${location.search}#${id}`);
  const i = D.cves.info?.[id] || {}, r = recentById.get(id) || {};
  const k = (D.cves.kev || []).find(x => x.id === id), kd = D.cves.kevIndex?.[id], e = D.cves.epss?.[id];
  const s = i.s ?? r.s, v = i.v ?? r.v, desc = i.x || r.x || k?.x;
  const related = (cveMentions.get(id) || []).slice().sort((a, b) => b.d - a.d);
  const num = id.replace('CVE-', '');
  const p = D.cves.poc?.[id];
  const gh = q => `https://github.com/search?q=${encodeURIComponent(q)}&type=code`;
  openDrawer(`
    <h2 id="dr-title">${id}</h2>
    ${i.t ? `<p style="margin:6px 0 0;font-weight:600">${esc(i.t)}</p>` : ''}
    <p>${esc(desc || 'No description cached yet — check NVD or CVE.org below.')}</p>
    <dl>
      <dt>CVSS</dt><dd>${s != null ? `<span class="sev ${v}">${s} ${v}</span>` : '<span class="muted">Not scored yet</span>'}</dd>
      <dt>EPSS</dt><dd>${e ? `${(e[0] * 100).toFixed(2)}% chance of exploitation in 30 days <span class="muted">(higher than ${(e[1] * 100).toFixed(1)}% of CVEs)</span>` : '<span class="muted">—</span>'}</dd>
      <dt>CISA KEV</dt><dd>${kd ? `<span class="kev">KEV</span> added ${kd}${k ? ` · federal due date ${k.due}${k.rw ? ' · <strong>used in ransomware campaigns</strong>' : ''}` : ''}` : 'Not in the catalog'}</dd>
      ${k ? `<dt>Affects</dt><dd>${esc(k.v)} · ${esc(k.p)}</dd>` : i.vp ? `<dt>Affects</dt><dd>${esc(i.vp)}</dd>` : ''}
      ${r.cwe ? `<dt>Weakness</dt><dd><a href="https://cwe.mitre.org/data/definitions/${r.cwe.replace('CWE-', '')}.html" target="_blank" rel="noopener">${esc(r.cwe)}</a></dd>` : ''}
    </dl>
    <div class="links">
      <a href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener">NVD</a>
      <a href="https://www.cve.org/CVERecord?id=${id}" target="_blank" rel="noopener">CVE.org</a>
      ${kd ? `<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}" target="_blank" rel="noopener">CISA KEV</a>` : ''}
      <a href="https://github.com/search?q=${id}&type=repositories" target="_blank" rel="noopener">GitHub PoCs</a>
      <a href="https://www.exploit-db.com/search?cve=${num}" target="_blank" rel="noopener">Exploit-DB</a>
      <a href="https://vulners.com/search?query=${id}" target="_blank" rel="noopener">Vulners</a>
      <a href="https://www.first.org/epss/" target="_blank" rel="noopener">About EPSS</a>
    </div>
    ${aiLine(id)}${fixSection(id)}
    <h3>Public exploits</h3>
    ${p?.n ? `<p class="desc">${p.n} GitHub repositor${p.n > 1 ? 'ies' : 'y'}; first seen ${fmtAgo(p.first)}. Exploit code is untrusted — read before running, only in a lab.</p><ul class="rel">${p.top.map(t => `<li><a href="${url(t.u)}" target="_blank" rel="noopener">${esc(t.n)}</a> <span class="muted">★${t.s} · ${fmtAgo(t.c)}</span>${t.d ? `<div class="muted" style="font-size:13px">${esc(t.d)}</div>` : ''}</li>`).join('')}</ul>` : p?.edb ? '<p>Listed on Exploit-DB.</p>' : '<p class="muted">No public exploit code found yet (checked twice a day).</p>'}
    <h3>Detection &amp; scanning</h3>
    <div class="links">
      <a href="${gh('repo:SigmaHQ/sigma ' + id)}" target="_blank" rel="noopener">Sigma rules</a>
      <a href="${gh('repo:projectdiscovery/nuclei-templates ' + id)}" target="_blank" rel="noopener">Nuclei templates</a>
      <a href="${gh('repo:rapid7/metasploit-framework ' + id)}" target="_blank" rel="noopener">Metasploit modules</a>
      <a href="${gh(id + ' yara')}" target="_blank" rel="noopener">YARA</a>
      <a href="${gh(id + ' suricata OR snort')}" target="_blank" rel="noopener">Suricata / Snort</a>
      <a href="https://www.tenable.com/cve/${id}/plugins" target="_blank" rel="noopener">Tenable / Nessus plugins</a>
      <a href="https://www.google.com/search?q=${encodeURIComponent(id + ' detection')}" target="_blank" rel="noopener">Vendor guidance</a>
    </div>
    <div id="cve-plugins"></div>
    <h3>In the news (${related.length})</h3>
    ${related.length ? `<ul class="rel">${related.map(s => `<li><a href="${url(s.u)}" target="_blank" rel="noopener">${esc(s.t)}</a> <span class="muted">— ${esc(s.s)}${s.r.length ? ` +${s.r.length}` : ''}, ${fmtAgo(s.d)}</span></li>`).join('')}</ul>` : '<p class="muted">No stories in the last 30 days.</p>'}
    <p><button class="linkish" data-q="cve:${id}" data-close>Search all stories for ${id} →</button></p>`);
}
async function fillCvePlugins(id) {
  if (!TAB.plugins) return;                      // section hidden on this deployment
  await lazy('plugins', 'plugins.json');
  const el = $('#cve-plugins'); if (!el) return;
  const ps = pluginsForCve(id);
  if (ps.length) el.innerHTML = `<p class="desc" style="margin:4px 0 0">Recent Tenable checks for this CVE:</p><ul class="rel">${ps.slice(0, 6).map(p => `<li><a href="${url(p.u)}" target="_blank" rel="noopener">${esc(p.t)}</a> <span class="muted">#${p.id} · ${esc(p.v)}</span></li>`).join('')}</ul>`;
}
function closeDrawer() {
  if (!$('#drawer-root').innerHTML) return;
  $('#drawer-root').innerHTML = '';
  lastFocus?.focus?.();
  if (/^#CVE-/i.test(location.hash)) history.replaceState(null, '', location.pathname + location.search);
}

// ----- Ransomware -----
function bars(entries, { label = x => x, q, link } = {}) {
  const max = Math.max(1, ...entries.map(e => e[1]));
  return `<div class="bars">${entries.map(([k, n]) => `<div class="bar-row"><div class="lbl" title="${esc(label(k))}">${q ? `<button data-rwq="${esc(k)}">${esc(label(k))}</button>` : esc(label(k))}${link && link(k) ? ` <a href="${url(link(k))}" title="${esc(label(k))} profile">↗</a>` : ''}</div><div class="bar-track" data-tip="${esc(label(k))}: ${n} claimed victims"><div class="bar" style="width:${(n / max) * 88}%"></div><span class="bar-val">${n}</span></div></div>`).join('')}</div>`;
}
const flag = cc => cc && /^[A-Z]{2}$/.test(cc) ? `<img class="flag" src="flags/${cc.toLowerCase()}.svg" alt="" width="18" height="13" loading="lazy">` : '';
function renderRansomware() {
  const R = D.rw;
  if (!R) { $('#view').innerHTML = `<div class="empty">Ransomware data is unavailable right now.</div>`; return; }
  const sub = state.sub.ransomware;
  const q = state.q.trim().toLowerCase();
  const T = R.totals || {};
  const day24 = R.recent.filter(v => Date.now() - v.d < DAY).length;
  const stats = `<div class="rw-stats">
    <div class="tile"><div class="k">Overall victims</div><div class="v">${(T.all || 0).toLocaleString()}</div><div class="s">all time, tracked by ${esc(R.source)}</div></div>
    <div class="tile"><div class="k">This year</div><div class="v">${(T.ytd || 0).toLocaleString()}</div><div class="s">since Jan 1</div></div>
    <div class="tile"><div class="k">Last 30 days</div><div class="v">${(T.d30 ?? R.total30).toLocaleString()}</div><div class="s">${T.groups30 || '—'} active groups</div></div>
    <div class="tile"><div class="k">Last 24 hours</div><div class="v">${day24}</div><div class="s">new claims</div></div>
    <div class="tile"><div class="k">Groups tracked</div><div class="v">${(T.groupsAll || 0).toLocaleString()}</div><div class="s">most active: ${esc(R.groups[0]?.[0] || '—')}</div></div>
  </div>`;
  // Last 10 days: a plain bar per day; the selected day's breakdown sits underneath.
  const days = R.days10 || [];
  const maxDay = Math.max(1, ...days.map(d => d.n));
  const sel = days.find(d => d.d === state.rwSel) || days.at(-1);
  const dfmt = (d, o) => new Date(d + 'T12:00:00Z').toLocaleDateString(undefined, { ...o, timeZone: 'UTC' });
  const topList = (arr, label = x => esc(x)) => arr.length ? arr.map(([k, n]) => `${label(k)} <span class="muted">${n}</span>`).join(', ') : '<span class="muted">—</span>';
  const strip = days.length ? `<section class="panel d10-panel"><div class="panel-head"><h2>Last 10 days</h2><span class="muted">${days.reduce((a, d) => a + d.n, 0)} claims</span></div>
    <div class="d10" role="group" aria-label="Claims per day">${days.map(d => `<button class="d10-day" data-rwsel="${d.d}" aria-pressed="${d === sel}" title="${d.n} claims on ${esc(dfmt(d.d, { weekday: 'long', month: 'long', day: 'numeric' }))}">
      <span class="d10-n">${d.n}</span><span class="d10-bar"><i style="height:${Math.max(3, (d.n / maxDay) * 100)}%"></i></span><span class="d10-date">${esc(dfmt(d.d, { month: 'short', day: 'numeric' }))}</span></button>`).join('')}</div>
    ${sel ? `<div class="d10-detail"><div class="d10-title"><b>${esc(dfmt(sel.d, { weekday: 'long', month: 'long', day: 'numeric' }))}</b> · ${sel.n} claims</div>
      <dl><dt>Groups</dt><dd>${topList(sel.g)}</dd><dt>Countries</dt><dd>${topList(sel.c, c => `${flag(c)} ${esc(regionName(c))}`)}</dd><dt>Sectors</dt><dd>${topList(sel.a)}</dd></dl>
      <button class="linkish" data-rwday="${sel.d}">View all ${sel.n} victims →</button></div>` : ''}
  </section>` : '';
  const subs = [['claims', 'Overview'], ['live', 'Live map'], ['countries', 'Countries'], ['victims', 'Victims'], ['stories', `News`]];
  let body = '';
  if (sub === 'victims') {
    let vs = R.recent;
    if (state.rwDay) vs = vs.filter(v => new Date(v.d).toISOString().slice(0, 10) === state.rwDay);
    if (state.rwCountry) vs = vs.filter(v => v.c === state.rwCountry);
    if (q) vs = vs.filter(v => `${v.t} ${v.g} ${v.c} ${regionName(v.c)} ${v.a} ${v.w} ${v.x || ''}`.toLowerCase().includes(q));
    const filt = [state.rwDay && `on ${state.rwDay}`, state.rwCountry && `in ${regionName(state.rwCountry)}`, q && `matching “${esc(state.q)}”`].filter(Boolean).join(' ');
    body = `<div class="toolbar"><span>${vs.length} claimed victims ${filt}</span>${state.rwDay || state.rwCountry ? '<button class="linkish" id="rw-clear">Clear filter</button>' : ''}<span class="spacer"></span><span class="muted">Search above filters by victim, group, country, sector or domain.</span></div>
    <div class="victims">${vs.slice(0, state.rwShown).map(v => {
      const grp = (D.meta.groups || []).find(g => g.n === v.g);
      return `<article class="victim">
        <div class="vhead">${flag(v.c)}<strong>${esc(v.t)}</strong></div>
        <div class="vmeta">${grp ? `<a class="chip tag ransomware" href="groups/${grp.sl}.html">${esc(v.g)}</a>` : `<span class="chip tag ransomware">${esc(v.g)}</span>`}${v.a && v.a !== 'Not Found' ? `<span class="chip">${esc(v.a)}</span>` : ''}${v.c ? `<button class="chip" data-rwcountry="${esc(v.c)}">${esc(regionName(v.c))}</button>` : ''}</div>
        ${v.w ? `<div class="vdom" title="Victim domain as claimed (not linked)">${esc(v.w.replace(/^https?:\/\//, ''))}</div>` : ''}
        ${v.x ? `<p class="vdesc">${esc(v.x)}</p>` : ''}
        <div class="vdates"><span title="${esc(fmtFull(v.d))}">Discovered ${fmtAgo(v.d)}</span>${v.p ? `<span title="Date the group says the attack happened">Attack date ${new Date(v.p).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</span>` : ''}</div>
        ${v.n ? `<div class="vnews">In the news: <a href="${url(v.n[1])}" target="_blank" rel="noopener">${esc(v.n[0])}</a> <span class="muted">— ${esc(v.n[2])}</span></div>` : ''}
      </article>`;
    }).join('') || '<div class="empty">No matching claims.</div>'}</div>
    ${vs.length > state.rwShown ? `<button class="loadmore" data-rw-more>Show more (${vs.length - state.rwShown} remaining)</button>` : ''}`;
  } else if (sub === 'countries') {
    body = `${D.rw.countryDaily ? mapHtml() : ''}${countriesTable()}`;
  } else if (sub === 'live') {
    body = liveMapHtml() + countriesTable();
  } else if (sub === 'stories') {
    const stories = filterStories(s => s.tg.includes('ransomware'));
    body = toolbar(stories.list.length) + storyList(stories.list, stories.terms);
  } else {
    const daily = R.daily.slice(-30), tickMax = Math.ceil(Math.max(1, ...daily.map(d => d[1])) / 10) * 10;
    const chart = `<div class="cols" role="img" aria-label="Claimed victims per day, last 30 days">
      <span class="ymax">${tickMax}</span><span class="gridline" style="top:18px"></span><span class="gridline" style="top:calc(18px + (100% - 18px)/2)"></span>
      ${daily.map(([d, n]) => `<div class="col" data-tip="${esc(new Date(d + 'T00:00:00Z').toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' }))}: ${n} claims"><i style="height:${(n / tickMax) * 100}%"></i></div>`).join('')}
    </div><div class="cols-axis"><span>${daily[0]?.[0] || ''}</span><span>${daily.at(-1)?.[0] || ''}</span></div>`;
    body = `<div class="panel"><h2>Claimed victims per day</h2><p class="desc">Last 30 days, by date discovered on leak sites.</p>${chart}</div>
    ${D.rw.countryDaily ? mapHtml() : ''}
    <div class="grid-2">
      <div class="panel"><h2>Most active groups</h2><p class="desc">Last 30 days. Click to filter; ↗ opens the group profile. <a href="groups/">All groups →</a></p>${bars(R.groups.slice(0, 12), { q: true, link: g => { const m = (D.meta.groups || []).find(x => x.n === g); return m ? `groups/${m.sl}.html` : ''; } })}</div>
      <div class="panel"><h2>Most targeted countries</h2><p class="desc">Last 30 days. <button class="linkish" data-sub-rw="countries">All countries →</button></p>${bars(R.countries.slice(0, 12), { label: c => regionName(c), q: true })}</div>
      ${R.sectors.length ? `<div class="panel"><h2>Most targeted sectors</h2><p class="desc">Last 30 days.</p>${bars(R.sectors.slice(0, 12), { q: true })}</div>` : ''}
    </div>`;
  }
  $('#view').innerHTML = `<div class="note">Figures are <strong>unverified claims</strong> posted on ransomware leak sites, collected by <a href="https://www.ransomware.live/" target="_blank" rel="noopener">${esc(R.source)}</a>. Groups exaggerate, re-post old victims and list companies that were never breached. Victim domains are shown as text, never linked.</div>
  ${stats}${sub === 'claims' ? strip : ''}
  <div class="subtabs">${subs.map(([v, l]) => `<button data-sub-rw="${v}" aria-pressed="${sub === v}">${l}</button>`).join('')}</div>${body}`;
  if ($('#map')) drawMap(+($('#map-day')?.value || 30));
  if ($('#live-map')) drawLiveMap();
}

// ----- Supply chain -----
function renderSupply() {
  const q = state.q.trim().toLowerCase();
  let adv = D.supply.advisories || [];
  if (q) adv = adv.filter(a => `${a.id} ${a.s} ${a.e} ${a.p.join(' ')}`.toLowerCase().includes(q));
  const eco = {}; for (const a of D.supply.advisories || []) eco[a.e] = (eco[a.e] || 0) + 1;
  const panel = `<div class="panel"><h2>Malicious packages</h2>
    <p class="desc">The latest malware advisories in the <a href="https://github.com/advisories?query=type%3Amalware" target="_blank" rel="noopener">GitHub Advisory Database</a> (npm, PyPI, RubyGems, NuGet, crates…). If you installed one of these, treat the machine as compromised and rotate its secrets. By ecosystem: ${Object.entries(eco).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${esc(k)} ${n}`).join(' · ')}</p>
    <details ${q ? 'open' : ''}><summary style="cursor:pointer;color:var(--accent)">Show ${adv.length} advisories</summary>
    <div class="table-wrap"><table><thead><tr><th>Published</th><th>Ecosystem</th><th>Package</th><th>Advisory</th></tr></thead><tbody>
    ${adv.map(a => `<tr><td class="nowrap" title="${esc(fmtFull(a.d))}">${fmtAgo(a.d)}</td><td>${esc(a.e)}</td><td style="font-family:var(--mono);font-size:13px">${esc(a.p.join(', '))}</td><td><a href="${url(a.u)}" target="_blank" rel="noopener">${esc(a.id)}</a> <span class="muted">${esc(a.s)}</span></td></tr>`).join('')}
    </tbody></table></div></details></div>`;
  const { list, terms } = filterStories(s => s.tg.includes('supply'));
  $('#view').innerHTML = panel + toolbar(list.length) + storyList(list, terms);
}

// ----- Patch Tuesday -----
function nthWeekday(y, m, weekday, n) { const d = new Date(y, m, 1); const add = (weekday - d.getDay() + 7) % 7; return new Date(y, m, 1 + add + (n - 1) * 7); }
function renderPatch() {
  const now = new Date(); now.setHours(0, 0, 0, 0);
  const months = [];
  for (let k = -2; k < 13; k++) { const d = new Date(now.getFullYear(), now.getMonth() + k, 1); months.push([d.getFullYear(), d.getMonth()]); }
  const rows = months.map(([y, m]) => {
    const pt = nthWeekday(y, m, 2, 2);
    const oracle = [0, 3, 6, 9].includes(m) ? nthWeekday(y, m, 2, 3) : null;
    const android = nthWeekday(y, m, 1, 1);
    return { y, m, pt, oracle, android };
  });
  const next = rows.find(r => r.pt >= now);
  const days = Math.round((next.pt - now) / DAY);
  const nextOracle = rows.find(r => r.oracle && r.oracle >= now);
  const f = d => d.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
  const mon = (y, m) => new Date(y, m, 1).toLocaleDateString('en-US', { month: 'short' });
  const { list, terms } = filterStories(s => /patch tuesday|security updates? (for|released)|out-of-band|CPU \w+ 20\d\d|critical patch update|security bulletin/i.test(s.t) && !s.b);
  $('#view').innerHTML = `
  <div class="panel"><div class="hero">
    <div><div class="k muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.04em;font-weight:600">Next Patch Tuesday</div><div class="big">${days === 0 ? 'Today' : `${days} day${days > 1 ? 's' : ''}`}</div><div>${f(next.pt)} · Microsoft, Adobe, SAP, Siemens, Schneider Electric</div></div>
    ${nextOracle ? `<div><div class="k muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.04em;font-weight:600">Next Oracle Critical Patch Update</div><div style="font-size:24px;font-weight:700">${f(nextOracle.oracle)}</div><div>${Math.round((nextOracle.oracle - now) / DAY)} days · quarterly</div></div>` : ''}
  </div><p class="desc" style="margin-top:12px">Dates are calculated from each vendor's published schedule (second Tuesday of the month; Oracle: third Tuesday of Jan/Apr/Jul/Oct; Android bulletins: usually the first Monday). Emergency out-of-band fixes can land any day — watch the <button class="linkish" data-tab-go="zeroday">Zero-days</button> tab.</p></div>
  <div class="panel"><h2>Calendar</h2><div class="table-wrap"><table class="cal"><thead><tr><th>Month</th><th>Patch Tuesday</th><th>Release notes</th><th>Oracle CPU</th><th>Android bulletin</th></tr></thead><tbody>
  ${rows.map(r => `<tr class="${r === next ? 'next' : r.pt < now ? 'past' : ''}"><td>${new Date(r.y, r.m, 1).toLocaleDateString(undefined, { month: 'long', year: 'numeric' })}</td><td class="nowrap">${f(r.pt)}${r === next ? ' <strong>← next</strong>' : ''}</td>
    <td class="nowrap"><a href="https://msrc.microsoft.com/update-guide/releaseNote/${r.y}-${mon(r.y, r.m)}" target="_blank" rel="noopener">Microsoft</a> · <a href="https://helpx.adobe.com/security.html" target="_blank" rel="noopener">Adobe</a> · <a href="https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html" target="_blank" rel="noopener">SAP</a></td>
    <td class="nowrap">${r.oracle ? `<a href="https://www.oracle.com/security-alerts/cpu${mon(r.y, r.m).toLowerCase()}${r.y}.html" target="_blank" rel="noopener">${f(r.oracle)}</a>` : '<span class="muted">—</span>'}</td>
    <td class="nowrap"><a href="https://source.android.com/docs/security/bulletin/${r.y}-${String(r.m + 1).padStart(2, '0')}-01" target="_blank" rel="noopener">~${f(r.android)}</a></td></tr>`).join('')}
  </tbody></table></div></div>
  <h2 style="font-size:16px;margin:20px 0 8px">Patch release coverage</h2>` + toolbar(list.length, { sort: false }) + storyList(list, terms);
}

// ----- Saved -----
function renderSaved() {
  const recs = Object.values(saved).sort((a, b) => b.savedAt - a.savedAt);
  const terms = parseQuery(state.q);
  const live = recs.map(r => byId.get(r.id) || (r.links || []).map(l => byLink.get(l)).find(Boolean) || null);
  const items = recs.map((r, i) => ({ r, s: live[i] })).filter(({ r, s }) => !terms.length || (s ? matches(s, terms) : (r.t || '').toLowerCase().includes(state.q.toLowerCase())));
  const withUpd = items.filter(x => x.s && updatesFor(x.s)).length;
  $('#view').innerHTML = `<div class="note">Saved stories stay in this browser only (no account). You'll see an orange <strong>Updated</strong> badge when more outlets cover a saved story or its CVE is added to CISA KEV. Keyboard: press <kbd>s</kbd> on a focused story.</div>
  <div class="toolbar"><span>${items.length} saved${withUpd ? ` · <strong style="color:var(--update)">${withUpd} updated</strong>` : ''}</span><span class="spacer"></span>
    ${recs.length ? '<button class="save" id="export-saved">Export JSON</button><button class="save" id="clear-saved">Remove all</button>' : ''}</div>
  ${items.length ? `<div class="list">${items.map(({ r, s }) => s ? storyCard(s, terms) : `<article class="story" data-id="${esc(r.id)}"><div class="meta"><span class="src">${esc(r.s)}</span> · <span>${esc(fmtShort(r.d))}</span> · <span>archived (older than 30 days)</span></div><div class="head"><h3><a href="${url(r.u)}" target="_blank" rel="noopener">${esc(r.t)}</a></h3><button class="save" data-unsave="${esc(r.id)}" aria-pressed="true">✓ Saved</button></div></article>`).join('')}</div>`
    : `<div class="empty">Nothing saved yet. Use <strong>＋ Save</strong> beside any headline to keep it here and track updates.</div>`}`;
}

// ----- Sources -----
// ----- Topics (#hashtags for products, vendors, actors, malware) -----
function topicIndex() {
  const now = Date.now(), m = new Map();
  const kind = Object.fromEntries((D.meta.products || []).map(p => [p.n, p.k]));
  // One entry per hashtag (a name can be both a vendor and a product); each story counts once.
  const add = (name, type, s, seen) => {
    const key = norm(name); if (!key || seen.has(key)) return; seen.add(key);
    let t = m.get(key);
    if (!t) { t = { name, type, desc: type === 'Product' ? kind[name] || 'Product' : type, d1: 0, d7: 0, d30: 0, last: 0 }; m.set(key, t); }
    const age = now - s.d; t.d30++; if (age < 7 * DAY) t.d7++; if (age < DAY) t.d1++; if (s.d > t.last) t.last = s.d;
  };
  for (const s of D.news.stories) {
    if (s.so || s.b) continue;      // news & research only: bulk advisory feeds would drown everything else
    const seen = new Set();
    for (const x of s.ac) add(x, 'Threat actor', s, seen);
    for (const x of s.mw || []) add(x, 'Malware', s, seen);
    for (const x of s.tp || []) add(x, 'Product', s, seen);
    for (const x of vendorParts(s.ve)) add(x, 'Vendor', s, seen);
  }
  return [...m.values()];
}
function renderTopics() {
  const q = state.q.replace(/^#/, '').trim().toLowerCase();
  const type = state.sub.topics || 'all';
  let rows = topicIndex();
  if (type !== 'all') rows = rows.filter(t => t.type === type);
  if (q) rows = rows.filter(t => `${t.name} ${t.desc}`.toLowerCase().includes(q));
  rows.sort((a, b) => b.d7 - a.d7 || b.d30 - a.d30);
  const cloud = rows.slice(0, 50), maxN = Math.max(1, ...cloud.map(t => t.d7));
  const types = [['all', 'All'], ['Product', 'Products'], ['Vendor', 'Vendors'], ['Threat actor', 'Threat actors'], ['Malware', 'Malware']];
  $('#view').innerHTML = `<div class="subtabs">${types.map(([v, l]) => `<button data-sub-topics="${v}" aria-pressed="${type === v}">${l}</button>`).join('')}</div>
  <div class="panel"><h2>Trending this week</h2><p class="desc">Size shows how many stories mentioned it in the last 7 days. Click a hashtag to see those stories — or type <code>#name</code> in the search bar.</p>
    <div class="cloud">${cloud.map(t => `<button class="ht" data-q="${esc(hashtag(t.name))}" data-tab-go="latest" style="--s:${(0.85 + (t.d7 / maxN) * 0.9).toFixed(2)}" title="${esc(t.name)} · ${esc(t.desc)} · ${t.d7} stories this week">${esc(hashtag(t.name))}<sup>${t.d7}</sup></button>`).join('') || '<span class="muted">Nothing yet.</span>'}</div></div>
  <div class="panel"><h2>All topics <span class="muted" style="font-weight:400">(${rows.length})</span></h2><div class="table-wrap"><table><thead><tr><th>Topic</th><th>What it is</th><th>24h</th><th>7 days</th><th>30 days</th><th>Last seen</th></tr></thead><tbody>
    ${rows.slice(0, 300).map(t => `<tr><td><button class="linkish" data-q="${esc(hashtag(t.name))}" data-tab-go="latest"><strong>${esc(hashtag(t.name))}</strong></button></td><td class="muted">${esc(t.desc)}</td><td class="num">${t.d1 || ''}</td><td class="num">${t.d7 || ''}</td><td class="num">${t.d30}</td><td class="nowrap">${fmtAgo(t.last)}</td></tr>`).join('')}
  </tbody></table></div></div>`;
}

// ----- Categories (technical areas) -----
function renderCategories() {
  const now = Date.now();
  const cats = (D.meta.categories || []).map(c => {
    const list = D.news.stories.filter(s => !s.so && (s.ct || []).includes(c.c));
    return { ...c, d1: list.filter(s => now - s.d < DAY).length, d7: list.filter(s => now - s.d < 7 * DAY).length, d30: list.length, top: list.filter(s => !s.b).slice(0, 3) };
  }).sort((a, b) => b.d7 - a.d7);
  $('#view').innerHTML = `<p class="desc">Every story is sorted into up to three technical areas from its headline and summary (keyword-based). Click an area to read its stories, or search with <code>cat:exp</code>.</p>
  <div class="cat-grid">${cats.map(c => `<section class="cat-card">
    <header><button class="cat cat-${c.c}" data-q="cat:${c.c}" data-tab-go="latest">${c.c}</button><h2><button class="linkish" data-q="cat:${c.c}" data-tab-go="latest">${esc(c.l)}</button></h2></header>
    <div class="cat-nums"><span><b>${c.d1}</b> today</span><span><b>${c.d7}</b> this week</span><span><b>${c.d30}</b> in 30 days</span></div>
    <ul>${c.top.map(s => `<li><a href="${url(s.u)}" target="_blank" rel="noopener">${esc(s.t)}</a> <span class="muted">${fmtAgo(s.d)}</span></li>`).join('') || '<li class="muted">No recent stories.</li>'}</ul>
  </section>`).join('')}</div>`;
}

// ----- Sources -----
function renderSources() {
  const list = D.sources.sources || [];
  const q = state.q.trim().toLowerCase();
  const now = Date.now();
  const day = {}; for (const s of D.news.stories) if (now - s.d < DAY) { day[s.s] = (day[s.s] || 0) + 1; for (const r of s.r) if (now - r[3] < DAY) day[r[0]] = (day[r[0]] || 0) + 1; }
  const groups = [['research', 'Threat research & intel'], ['news', 'Cybersecurity news'], ['advisory', 'Alerts & advisories'], ['tool', 'Databases & tools (no feed)']];
  const repo = D.config.repoUrl;
  $('#view').innerHTML = `<div class="note">We read these sources' public RSS/Atom feeds every ~20 minutes and link straight to the original article. Feeds marked <em>via ifin</em> come from the public <a href="https://news.ifin.network/" target="_blank" rel="noopener">IFIN news feed</a> because the publisher has none. ${repo ? `<a href="${url(repo)}/issues/new?title=${encodeURIComponent('Source suggestion / broken source')}" target="_blank" rel="noopener">Suggest a source or report a problem</a>.` : ''}</div>` +
    groups.map(([c, label]) => {
      let rows = list.filter(s => s.c === c);
      if (q) rows = rows.filter(s => s.n.toLowerCase().includes(q));
      if (!rows.length) return '';
      if (c !== 'tool') rows.sort((a, b) => (day[b.n] || 0) - (day[a.n] || 0) || (b.latest || 0) - (a.latest || 0));
      return `<div class="panel"><h2>${label} <span class="muted" style="font-weight:400">(${rows.length})</span></h2><div class="table-wrap"><table><thead><tr><th>Source</th>${c === 'tool' ? '' : '<th>Today</th><th>Latest post</th><th>Status</th><th></th>'}</tr></thead><tbody>
      ${rows.map(s => `<tr><td class="nowrap"><span class="srcname">${avatar(s.n)}<a href="${url(s.site)}" target="_blank" rel="noopener">${esc(s.n)}</a>${s.via ? ` <span class="muted" style="font-size:12px">via ${/ifin/.test(s.via) ? 'ifin' : esc(s.via)}</span>` : ''}</span></td>${c === 'tool' ? '' : `<td class="num">${day[s.n] ? `<button class="linkish" data-q="source:&quot;${esc(s.n)}&quot;" data-tab-go="latest"><b>${day[s.n]}</b></button>` : '<span class="muted">0</span>'}</td><td class="nowrap">${s.latest ? `<span title="${esc(fmtFull(s.latest))}">${fmtAgo(s.latest)}</span>` : '<span class="muted">—</span>'}</td><td class="nowrap">${s.feed ? (s.ok ? `<span class="status ok"></span>OK` : `<span class="status fail"></span>Failing${s.err ? ` <span class="muted">(${esc(s.err)})</span>` : ''}`) : '<span class="status none"></span>No feed'}</td><td class="nowrap">${s.feed ? `<a href="${url(s.feed)}" target="_blank" rel="noopener">RSS</a> · ` : ''}<button class="linkish" data-q="source:&quot;${esc(s.n)}&quot;" data-tab-go="latest">Stories</button></td>`}</tr>`).join('')}
      </tbody></table></div></div>`;
    }).join('');
}

// ----- IOC viewer -----
async function openIocs(id) {
  const data = await lazy('iocs', 'iocs.json');
  const s = byId.get(id), io = data?.iocs?.[id];
  if (!s || !io) return;
  const sections = [['h', 'File hashes', v => `https://www.virustotal.com/gui/file/${v}`, v => `https://bazaar.abuse.ch/browse.php?search=${v.length === 64 ? 'sha256' : v.length === 40 ? 'sha1' : 'md5'}%3A${v}`, 'MalwareBazaar'],
    ['ip', 'IP addresses', v => `https://www.virustotal.com/gui/ip-address/${v}`, v => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${v}`, 'ThreatFox'],
    ['d', 'Domains', v => `https://www.virustotal.com/gui/domain/${v}`, v => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${v}`, 'ThreatFox'],
    ['u', 'URLs', v => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}`, v => `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(v)}`, 'URLhaus']];
  openDrawer(`<h2 id="dr-title" style="font-family:var(--font);font-size:18px">Indicators of compromise</h2>
    <p><a href="${url(io.src || s.u)}" target="_blank" rel="noopener">${esc(s.t)}</a> <span class="muted">— ${esc(s.s)}</span></p>
    <div class="note">Automatically extracted — verify against the original report before blocking. Values are shown refanged; they are not links.</div>
    ${sections.filter(([k]) => io[k]?.length).map(([k, label, vt, other, otherName]) => `<h3>${label} (${io[k].length}) <button class="linkish" data-copy="${k}" style="float:right;text-transform:none;letter-spacing:0">Copy all</button></h3>
      <div class="ioc-list">${io[k].map(v => `<div class="ioc-row"><code>${esc(v)}</code><span><a href="${url(vt(v))}" target="_blank" rel="noopener">VirusTotal</a> · <a href="${url(other(v))}" target="_blank" rel="noopener">${otherName}</a></span></div>`).join('')}</div>`).join('')}`);
  $('#drawer-root').dataset.iocs = id;
}
async function exportIocsCsv() {
  const data = await lazy('iocs', 'iocs.json'); if (!data) return;
  const rows = [['type', 'value', 'story', 'source', 'published', 'report_url']];
  const names = { h: 'hash', ip: 'ip', d: 'domain', u: 'url' };
  for (const [id, io] of Object.entries(data.iocs)) { const s = byId.get(id); if (!s) continue; for (const k of Object.keys(names)) for (const v of io[k] || []) rows.push([names[k], v, s.t, s.s, new Date(s.d).toISOString(), io.src || s.u]); }
  const csv = rows.map(r => r.map(x => `"${String(x).replace(/"/g, '""')}"`).join(',')).join('\n');
  downloadFile(`threat-recap-iocs-${new Date().toISOString().slice(0, 10)}.csv`, csv, 'text/csv');
}
function downloadFile(name, content, type) {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
function toast(msg, undo) {
  const t = $('#toast'); t.innerHTML = `${esc(msg)}${undo ? ' <button class="toast-undo">Undo</button>' : ''}`; t.hidden = false;
  if (undo) t.querySelector('.toast-undo').onclick = () => { t.hidden = true; undo(); };
  clearTimeout(toast.t); toast.t = setTimeout(() => { t.hidden = true; }, undo ? 6000 : 2200);
}

// ----- Trends & weekly numbers -----
function trendRows(field, { limit = 10, now = Date.now() } = {}) {
  const cur = {}, prev = {};
  for (const s of D.news.stories) {
    if (s.so) continue;
    const age = now - s.d; const bucket = age < 7 * DAY ? cur : age < 14 * DAY ? prev : null; if (!bucket) continue;
    const w = s.b ? 1 : s.r.length + 1;
    for (const x of field(s)) bucket[x] = (bucket[x] || 0) + w;
  }
  return Object.entries(cur).map(([k, n]) => ({ k, n, p: prev[k] || 0 })).sort((a, b) => (b.n - b.p) - (a.n - a.p) || b.n - a.n).slice(0, limit);
}
function trendTable(title, rows, render) {
  if (!rows.length) return '';
  return `<div class="panel"><h2>${title}</h2><div class="table-wrap"><table><thead><tr><th></th><th title="Last 7 days">7d</th><th title="The 7 days before">Prior</th><th>Change</th></tr></thead><tbody>
  ${rows.map(r => { const d = r.n - r.p; return `<tr><td>${render(r.k)}</td><td class="num">${r.n}</td><td class="num">${r.p}</td><td class="num">${r.p === 0 ? '<span class="sev HIGH">new</span>' : `<span class="${d > 0 ? 'up' : d < 0 ? 'down' : ''}">${d > 0 ? '▲' : d < 0 ? '▼' : '•'} ${Math.abs(d)}</span>`}</td></tr>`; }).join('')}
  </tbody></table></div></div>`;
}
function weekNumbers(now = Date.now()) {
  const wk = D.news.stories.filter(s => !s.so && now - s.d < 7 * DAY);
  const main = wk.filter(s => !s.b);
  const kev = (D.cves.kev || []).filter(k => now - Date.parse(k.d + 'T12:00:00Z') < 7 * DAY);
  const rw = D.rw ? D.rw.daily.slice(-7).reduce((a, [, n]) => a + n, 0) : null;
  const actors = trendRows(s => s.ac, { limit: 1 })[0];
  const top = main.slice().sort((a, b) => b.r.length - a.r.length)[0];
  return { stories: main.length, advisories: wk.length - main.length, kev: kev.length, zeroday: main.filter(s => s.tg.includes('zeroday')).length, breaches: main.filter(s => s.tg.includes('breach')).length,
    rw, topGroup: D.rw?.groups?.[0]?.[0], topSector: D.rw?.sectors?.[0]?.[0], actor: actors?.k, top, pocs: Object.values(D.cves.poc || {}).filter(p => p.first && now - p.first < 7 * DAY).length };
}
function renderTrends() {
  const W = weekNumbers();
  const prof = Object.fromEntries((D.meta.actors || []).map(a => [a.n, a.sl]));
  const vend = Object.fromEntries((D.meta.vendors || []).map(v => [v.n, v.sl]));
  const otd = (() => { const today = new Date(); const out = []; for (let i = -3; i <= 7; i++) { const d = new Date(today.getTime() + i * DAY); const md = d.toISOString().slice(5, 10); for (const e of D.otd.filter(x => x.md === md)) out.push({ ...e, i }); } return out; })();
  $('#view').innerHTML = `
  <div class="panel"><div class="morning-head"><h2>This week in numbers</h2><button class="save" id="share-img" title="Download a shareable image of this week's numbers">⤓ Share image</button></div>
  <div class="brief" style="margin:10px 0 0">
    <div class="tile"><div class="k">News stories</div><div class="v">${W.stories}</div><div class="s">+${W.advisories} advisories</div></div>
    <div class="tile"><div class="k">Added to CISA KEV</div><div class="v">${W.kev}</div></div>
    <div class="tile"><div class="k">Zero-day stories</div><div class="v">${W.zeroday}</div></div>
    <div class="tile"><div class="k">Breach stories</div><div class="v">${W.breaches}</div></div>
    ${W.rw != null ? `<div class="tile"><div class="k">Ransomware claims</div><div class="v">${W.rw}</div><div class="s">Most active: ${esc(W.topGroup || '—')}</div></div>` : ''}
    <div class="tile"><div class="k">New public exploits</div><div class="v">${W.pocs}</div><div class="s">for CVEs we track</div></div>
  </div>${W.top ? `<p class="desc" style="margin:12px 0 0">Story of the week (${W.top.r.length + 1} outlets): <a href="${url(W.top.u)}" target="_blank" rel="noopener">${esc(W.top.t)}</a> · <a href="digest.html">Full weekly digest →</a></p>` : ''}</div>
  <p class="desc">Trending = biggest rise in coverage this week (each outlet counts once) versus the week before.</p>
  <div class="grid-2">
    ${trendTable('Trending threat actors', trendRows(s => s.ac), k => prof[k] ? `<a href="actors/${prof[k]}.html">${esc(k)}</a>` : `<button class="linkish" data-q="actor:&quot;${esc(k)}&quot;">${esc(k)}</button>`)}
    ${trendTable('Trending vendors', trendRows(s => s.ve), k => vend[k] ? `<a href="vendors/${vend[k]}.html">${esc(k)}</a>` : esc(k))}
    ${trendTable('Trending CVEs', trendRows(s => (s.cv.length <= 4 ? s.cv : [])), k => `<button class="linkbtn" data-cve="${k}">${k}</button>`)}
    ${trendTable('Trending malware', trendRows(s => s.mw || []), k => `<button class="linkish" data-q="malware:&quot;${esc(k)}&quot;">${esc(k)}</button>`)}
    ${trendTable('Trending topics', trendRows(s => s.tg.filter(t => !['research', 'advisory', 'vuln'].includes(t))), k => `<button class="linkish" data-q="tag:${k}">${esc(TAG_LABELS[k] || k)}</button>`)}
  </div>
  ${otd.length ? `<div class="panel"><h2>This week in security history</h2><ul class="rel">${otd.map(e => `<li><strong>${new Date(`2000-${e.md}T12:00:00Z`).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}, ${e.y}</strong>${e.i === 0 ? ' <span class="sev HIGH">today</span>' : ''} — <a href="${url(e.u)}" target="_blank" rel="noopener">${esc(e.t)}</a></li>`).join('')}</ul></div>` : ''}`;
}
async function shareImage() {
  const W = weekNumbers(), c = document.createElement('canvas'); c.width = 1200; c.height = 630;
  const g = c.getContext('2d'), font = getComputedStyle(document.body).fontFamily;
  g.fillStyle = '#0f1115'; g.fillRect(0, 0, 1200, 630);
  g.fillStyle = '#0f5fbf'; g.fillRect(0, 0, 1200, 10);
  g.fillStyle = '#ffffff'; g.font = `700 50px ${font}`; g.fillText('This week in cybersecurity', 60, 100);
  g.fillStyle = '#a9b3c1'; g.font = `400 26px ${font}`;
  const f = t => new Date(t).toLocaleDateString('en', { month: 'short', day: 'numeric' });
  g.fillText(`${f(Date.now() - 7 * DAY)} – ${f(Date.now())}, ${new Date().getFullYear()}`, 60, 145);
  const tiles = [[W.stories, 'news stories'], [W.kev, 'added to CISA KEV'], [W.zeroday, 'zero-day stories'], [W.breaches, 'breach stories'], [W.rw ?? '—', 'ransomware claims'], [W.pocs, 'new public exploits']];
  tiles.forEach(([v, l], i) => { const x = 60 + (i % 3) * 370, y = 215 + Math.floor(i / 3) * 150; g.fillStyle = '#1b1f27'; roundRect(g, x, y, 340, 125, 16); g.fill(); g.fillStyle = '#ffffff'; g.font = `700 56px ${font}`; g.fillText(String(v), x + 26, y + 70); g.fillStyle = '#a9b3c1'; g.font = `400 22px ${font}`; g.fillText(l, x + 26, y + 105); });
  g.fillStyle = '#a9b3c1'; g.font = `400 22px ${font}`;
  if (W.topGroup) g.fillText(`Most active ransomware group: ${W.topGroup}${W.actor ? `  ·  Trending actor: ${W.actor}` : ''}`, 60, 555);
  g.fillStyle = '#6aa6f0'; g.font = `600 24px ${font}`; g.fillText(`Threat Recap${D.config.siteUrl ? ' · ' + D.config.siteUrl.replace(/^https?:\/\//, '').replace(/\/$/, '') : ''}`, 60, 598);
  c.toBlob(b => downloadFile(`security-week-${new Date().toISOString().slice(0, 10)}.png`, b), 'image/png');
}
function roundRect(g, x, y, w, h, r) { g.beginPath(); g.moveTo(x + r, y); g.arcTo(x + w, y, x + w, y + h, r); g.arcTo(x + w, y + h, x, y + h, r); g.arcTo(x, y + h, x, y, r); g.arcTo(x, y, x + w, y, r); g.closePath(); }

// ----- Ransomware map (choropleth, single hue) -----
const MAP_BINS = [1, 3, 10, 30, 100];
function mapHtml() {
  return `<div class="panel"><div class="morning-head"><h2>Where victims are claimed</h2>
      <div class="map-controls"><button class="save" id="map-play" aria-label="Play the last 30 days">▶ Play 30 days</button><input type="range" id="map-day" min="1" max="30" value="30" aria-label="Show claims up to day"><span id="map-label" class="muted"></span></div></div>
    <p class="desc">Cumulative claimed victims by country. Hover a country for its count; the bar chart below lists the same numbers.</p>
    <div class="map-wrap" id="map">Loading map…</div>
    <div class="map-legend" aria-hidden="true"><span>Claims</span>${MAP_BINS.map((b, i) => `<i class="m${i + 1}"></i><span>${b}${i === MAP_BINS.length - 1 ? '+' : ''}</span>`).join('')}</div></div>`;
}
async function drawMap(dayIdx = 30) {
  const el = $('#map'); if (!el) return;
  const world = await lazy('world', 'world.json');
  if (!world) { el.textContent = 'Map data unavailable.'; return; }
  const days = D.rw.countryDaily || [];
  const upto = days.slice(Math.max(0, days.length - 30), Math.max(0, days.length - 30) + dayIdx);
  const counts = {}; for (const [, m] of upto) for (const [c, n] of Object.entries(m)) counts[c] = (counts[c] || 0) + n;
  const bin = n => { let b = 0; MAP_BINS.forEach((t, i) => { if (n >= t) b = i + 1; }); return b; };
  if (!el.querySelector('svg')) el.innerHTML = `<svg viewBox="0 0 ${world.w} ${world.h}" role="img" aria-label="World map of claimed ransomware victims">${Object.entries(world.paths).map(([c, d]) => `<path data-cc="${c}" d="${d}"/>`).join('')}</svg>`;
  for (const p of el.querySelectorAll('path')) { const c = p.dataset.cc, n = counts[c] || 0; p.setAttribute('class', n ? 'm' + bin(n) : 'm0'); p.dataset.tip = `${regionName(c)}: ${n} claim${n === 1 ? '' : 's'}`; }
  const lastDay = upto.at(-1)?.[0];
  if ($('#map-label')) $('#map-label').textContent = lastDay ? `through ${new Date(lastDay + 'T12:00:00Z').toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}` : '';
}
let mapTimer;
function playMap() {
  clearInterval(mapTimer); let d = 1; const input = $('#map-day');
  mapTimer = setInterval(() => { if (!$('#map')) return clearInterval(mapTimer); input.value = d; drawMap(d); if (++d > 30) clearInterval(mapTimer); }, matchMedia('(prefers-reduced-motion: reduce)').matches ? 30 : 220);
}

// ----- Settings -----
function openSettings() {
  const st = settings.stack;
  const vendors = (D.meta.vendors || []).map(v => v.n);
  const langs = [['', 'Original (English)'], ['es', 'Español'], ['fr', 'Français'], ['de', 'Deutsch'], ['pt', 'Português'], ['it', 'Italiano'], ['nl', 'Nederlands'], ['ar', 'العربية'], ['tr', 'Türkçe'], ['ru', 'Русский'], ['uk', 'Українська'], ['hi', 'हिन्दी'], ['ja', '日本語'], ['ko', '한국어'], ['zh', '中文']];
  const notifState = !('Notification' in window) ? 'unsupported' : Notification.permission;
  openDrawer(`<h2 id="dr-title" style="font-family:var(--font);font-size:20px">Settings</h2><p class="muted">Stored in this browser only. Nothing is sent anywhere.</p>
  <h3>My stack</h3><p class="desc">Pick the vendors you run. Matching stories are marked and collected in the <em>My stack</em> section.</p>
  <div class="checks">${vendors.map(v => `<label><input type="checkbox" name="stack-v" value="${esc(v)}" ${st.vendors.includes(v) ? 'checked' : ''}> ${esc(v)}</label>`).join('')}</div>
  <label class="field">Extra keywords (comma-separated, e.g. <em>Jenkins, Grafana, Okta Verify</em>)<input type="text" id="stack-k" value="${esc(st.keywords.join(', '))}"></label>
  <h3>Notifications</h3>
  ${notifState === 'unsupported' ? '<p class="muted">This browser does not support notifications.</p>' : `
  <p class="desc">Alerts while this site is open in a tab. If you install the site as an app (Chrome/Edge), it can also check in the background about every hour.</p>
  <label class="toggle"><input type="checkbox" id="n-on" ${settings.notify.on && notifState === 'granted' ? 'checked' : ''}> Enable notifications ${notifState === 'denied' ? '<span class="muted">(blocked in your browser settings)</span>' : ''}</label>
  <div class="checks" style="grid-template-columns:1fr">
    <label><input type="checkbox" name="n" value="zeroday" ${settings.notify.zeroday ? 'checked' : ''}> New zero-day / actively exploited stories</label>
    <label><input type="checkbox" name="n" value="kev" ${settings.notify.kev ? 'checked' : ''}> New CISA KEV entries</label>
    <label><input type="checkbox" name="n" value="stack" ${settings.notify.stack ? 'checked' : ''}> Stories about my stack</label>
    <label><input type="checkbox" name="n" value="saved" ${settings.notify.saved ? 'checked' : ''}> Updates to saved stories</label>
  </div><button class="save" id="n-test">Send a test notification</button>`}
  ${mutedPanel()}
  <h3>Headline language</h3>
  <label class="field">Translate headlines into<select id="lang">${langs.map(([c, l]) => `<option value="${c}" ${settings.lang === c ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
  <p class="desc" id="lang-note">${translatorNote()}</p>
  <p style="margin-top:20px"><button class="save" id="settings-done" style="background:var(--accent);color:#fff;border-color:transparent">Save</button></p>`);
}
function translatorNote() {
  if ('Translator' in self) return 'Uses your browser’s built-in on-device translator — headlines never leave your device. The first use may download a language pack.';
  return `Your browser has no built-in translator. <a href="https://translate.google.com/translate?sl=en&tl=${settings.lang || 'es'}&u=${encodeURIComponent(location.href.split('#')[0])}" target="_blank" rel="noopener">Open this page in Google Translate</a> instead (works once the site is public).`;
}
async function applySettingsFromDrawer() {
  const dr = $('.drawer'); if (!dr) return;
  settings.stack.vendors = $$('input[name=stack-v]:checked', dr).map(i => i.value);
  settings.stack.keywords = ($('#stack-k', dr)?.value || '').split(',').map(s => s.trim()).filter(Boolean).slice(0, 30);
  for (const i of $$('input[name=n]', dr)) settings.notify[i.value] = i.checked;
  const wantOn = $('#n-on', dr)?.checked;
  if (wantOn && Notification.permission !== 'granted') { const p = await Notification.requestPermission(); settings.notify.on = p === 'granted'; }
  else settings.notify.on = !!wantOn;
  if (settings.notify.on) registerPeriodicSync();
  settings.lang = $('#lang', dr)?.value || '';
  saveSettings(); closeDrawer(); render(); toast('Settings saved');
}

// ----- Notifications -----
async function notify(title, body, url) {
  if (!settings.notify.on || !('Notification' in window) || Notification.permission !== 'granted') return;
  try { const reg = await navigator.serviceWorker?.getRegistration(); if (reg) return reg.showNotification(title, { body, icon: 'icon.svg', badge: 'icon.svg', data: { url }, tag: url }); } catch {}
  try { new Notification(title, { body, icon: 'icon.svg' }); } catch {}
}
function notifyChanges(oldNews, oldCves) {
  if (!settings.notify.on) return;
  const known = new Set(oldNews.stories.map(s => s.id));
  const fresh = D.news.stories.filter(s => !known.has(s.id) && !s.b && !s.so);
  const out = [];
  if (settings.notify.zeroday) for (const s of fresh.filter(s => s.tg.includes('zeroday')).slice(0, 2)) out.push(['Zero-day: ' + s.s, s.t, s.u]);
  if (settings.notify.kev) { const old = new Set((oldCves.kev || []).map(k => k.id)); const n = (D.cves.kev || []).filter(k => !old.has(k.id)); if (n.length) out.push([`${n.length} new actively exploited CVE${n.length > 1 ? 's' : ''} (CISA KEV)`, n.slice(0, 3).map(k => `${k.id} ${k.v} ${k.p}`).join('\n'), `./?tab=cves#${n[0].id}`]); }
  if (settings.notify.stack) for (const s of fresh.filter(isMine).slice(0, 2)) out.push(['Your stack: ' + s.ve.concat(s.s).slice(0, 2).join(' · '), s.t, s.u]);
  if (settings.notify.saved) { const u = D.news.stories.filter(s => updatesFor(s) && !updatesFor(oldNews.stories.find(o => o.id === s.id) || s)); for (const s of u.slice(0, 1)) out.push(['Saved story updated', s.t, './?tab=saved']); }
  out.slice(0, 4).forEach(([t, b, u]) => notify(t, b, u));
}
async function registerPeriodicSync() {
  try {
    const reg = await navigator.serviceWorker?.ready;
    if (reg && 'periodicSync' in reg) {
      const st = await navigator.permissions.query({ name: 'periodic-background-sync' });
      if (st.state === 'granted') await reg.periodicSync.register('cih-check', { minInterval: 60 * 60 * 1000 });
    }
  } catch {}
}
// The service worker can't read localStorage, so hand it what it needs via Cache Storage.
async function syncSwState() {
  try {
    if (!('caches' in window) || !D.news) return;
    const c = await caches.open('cih-state');
    const stateJson = { notify: settings.notify, stack: settings.stack, known: D.news.stories.slice(0, 1500).map(s => s.id), kev: (D.cves.kev || []).map(k => k.id) };
    await c.put('state.json', new Response(JSON.stringify(stateJson), { headers: { 'content-type': 'application/json' } }));
  } catch {}
}

// ----- Translation (browser built-in, on-device) -----
const trCache = new Map(); let translator = null, translatorLang = '';
async function translateVisible() {
  if (!settings.lang || !('Translator' in self)) return;
  try {
    if (translatorLang !== settings.lang) { translator = await self.Translator.create({ sourceLanguage: 'en', targetLanguage: settings.lang }); translatorLang = settings.lang; }
    for (const a of $$('#view .story h3 a').slice(0, 80)) {
      const orig = a.dataset.orig || a.textContent; a.dataset.orig = orig;
      const key = settings.lang + '|' + orig;
      if (!trCache.has(key)) trCache.set(key, await translator.translate(orig));
      a.textContent = trCache.get(key); a.title = orig; a.lang = settings.lang;
    }
  } catch { /* unsupported language pair or download declined */ }
}

// ----- Command palette (Ctrl/⌘+K) -----
function paletteItems() {
  const items = [];
  for (const t of TABS) items.push({ k: 'Tab', label: t.label, run: () => setTab(t.id) });
  items.push({ k: 'Action', label: 'Settings — my stack, notifications, language', run: openSettings });
  items.push({ k: 'Action', label: 'Light mode', run: () => applyTheme('light') });
  items.push({ k: 'Action', label: 'Dark mode', run: () => applyTheme('dark') });
  items.push({ k: 'Action', label: 'Download all IOCs as CSV', run: exportIocsCsv });
  items.push({ k: 'Action', label: 'Share image of this week', run: shareImage });
  items.push({ k: 'Page', label: 'This week’s digest', run: () => { location.href = 'digest.html'; } });
  items.push({ k: 'Page', label: 'Public data API & RSS feeds', run: () => { location.href = 'api.html'; } });
  for (const a of D.meta.actors || []) items.push({ k: 'Actor', label: a.n, hint: a.al.join(', '), run: () => { location.href = `actors/${a.sl}.html`; } });
  for (const v of D.meta.vendors || []) items.push({ k: 'Vendor', label: v.n, run: () => { location.href = `vendors/${v.sl}.html`; } });
  for (const g of D.meta.groups || []) items.push({ k: 'Ransomware', label: g.n, hint: `${g.c} claims · 30d`, run: () => { location.href = `groups/${g.sl}.html`; } });
  for (const m of D.meta.malware || []) items.push({ k: 'Malware', label: m, run: () => { state.tab = 'latest'; setQuery(`malware:"${m}"`, { switchTab: false }); } });
  for (const id of new Set([...cveMentions.keys(), ...(D.cves.kev || []).map(k => k.id)])) items.push({ k: 'CVE', label: id, hint: D.cves.info?.[id]?.vp || '', run: () => openCve(id) });
  for (const s of D.sources.sources || []) items.push({ k: 'Source', label: s.n, run: () => { state.tab = 'latest'; setQuery(`source:"${s.n}"`, { switchTab: false }); } });
  return items;
}
function openPalette() {
  if ($('.palette')) return;
  const all = paletteItems();
  const div = document.createElement('div'); div.className = 'help palette';
  div.innerHTML = `<div role="dialog" aria-modal="true" aria-label="Command palette"><input id="pal-q" type="text" placeholder="Jump to a tab, actor, vendor, CVE, ransomware group, source…" autocomplete="off" aria-controls="pal-list"><ul id="pal-list" role="listbox"></ul><p class="muted" style="font-size:12px;margin:8px 0 0">↑↓ to move · Enter to open · Esc to close</p></div>`;
  document.body.append(div);
  const input = $('#pal-q', div), ul = $('#pal-list', div); let sel = 0, shown = [];
  const draw = () => {
    const q = input.value.trim().toLowerCase();
    shown = (q ? all.map(it => { const l = it.label.toLowerCase(), h = (it.hint || '').toLowerCase(); const sc = l === q ? 0 : l.startsWith(q) ? 1 : l.includes(q) ? 2 : h.includes(q) ? 3 : 9; return [sc, it]; }).filter(([sc]) => sc < 9).sort((a, b) => a[0] - b[0]).map(x => x[1]) : all.filter(i => ['Tab', 'Action'].includes(i.k))).slice(0, 40);
    sel = Math.min(sel, Math.max(0, shown.length - 1));
    ul.innerHTML = shown.map((it, i) => `<li role="option" aria-selected="${i === sel}" data-i="${i}"><span class="pk">${it.k}</span> ${esc(it.label)}${it.hint ? ` <span class="muted">${esc(it.hint)}</span>` : ''}</li>`).join('') || '<li class="muted">No matches</li>';
    ul.querySelector('[aria-selected=true]')?.scrollIntoView({ block: 'nearest' });
  };
  const go = i => { const it = shown[i]; if (!it) return; div.remove(); it.run(); };
  input.addEventListener('input', () => { sel = 0; draw(); });
  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') { sel = Math.min(shown.length - 1, sel + 1); draw(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { sel = Math.max(0, sel - 1); draw(); e.preventDefault(); }
    else if (e.key === 'Enter') go(sel);
    else if (e.key === 'Escape') div.remove();
  });
  ul.addEventListener('click', e => { const li = e.target.closest('li[data-i]'); if (li) go(+li.dataset.i); });
  div.addEventListener('click', e => { if (e.target === div) div.remove(); });
  draw(); input.focus();
}

// ----- shared drawer shell -----
function openDrawer(inner) {
  lastFocus = document.activeElement;
  $('#drawer-root').innerHTML = `<div class="drawer-bg" data-close></div><aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="dr-title"><button class="icon-btn close" data-close aria-label="Close">✕</button>${inner}</aside>`;
  delete $('#drawer-root').dataset.iocs;
  $('.drawer .close').focus();
}
let lastFocus = null;

// ----- 1. Hide (mute) stories, sources and topics -----
settings.mute ||= { src: [], topic: [], id: [] };
function isMuted(s) {
  const m = settings.mute;
  if (m.id.includes(s.id) || m.src.includes(s.s)) return true;
  if (!m.topic.length) return false;
  const t = storyTopics(s).map(norm);
  return m.topic.some(x => t.includes(norm(x)));
}
function openHideMenu(btn, s) {
  closeMenus();
  const topics = [...new Map([...(s.tp || []), ...vendorParts(s.ve), ...s.ac, ...(s.mw || [])].map(x => [norm(x), x])).values()].slice(0, 4);
  const m = document.createElement('div');
  m.className = 'menu'; m.setAttribute('role', 'menu');
  m.innerHTML = `<button role="menuitem" data-mute="id" data-val="${esc(s.id)}">Hide this story</button>
    <button role="menuitem" data-mute="src" data-val="${esc(s.s)}">Hide everything from ${esc(s.s)}</button>
    ${topics.map(t => `<button role="menuitem" data-mute="topic" data-val="${esc(t)}">Hide stories about ${esc(t)}</button>`).join('')}
    <hr><button role="menuitem" data-open-settings>Manage hidden…</button>`;
  document.body.append(m);
  const r = btn.getBoundingClientRect();
  m.style.top = `${r.bottom + 6}px`;
  m.style.left = `${Math.max(8, Math.min(innerWidth - m.offsetWidth - 8, r.right - m.offsetWidth))}px`;
  m.querySelector('button').focus();
}
function closeMenus() { $$('.menu').forEach(m => m.remove()); }
function mute(kind, val) {
  const list = settings.mute[kind];
  if (!list.includes(val)) list.push(val);
  saveSettings(); closeMenus(); render();
  toast(kind === 'id' ? 'Story hidden' : `Hidden: ${val}`, () => { settings.mute[kind] = settings.mute[kind].filter(x => x !== val); saveSettings(); render(); });
}
function mutedPanel() {
  const m = settings.mute, all = [...m.src.map(v => ['src', v, 'Source']), ...m.topic.map(v => ['topic', v, 'Topic'])];
  return `<h3>Hidden sources &amp; topics</h3>${all.length || m.id.length ? `<p class="desc">Stories matching these are left out of every list. Use “Hide” on any story to add more.</p>
    <div class="chips">${all.map(([k, v, l]) => `<button class="chip unmute" data-unmute="${k}" data-val="${esc(v)}" title="Show again">${l}: ${esc(v)} ✕</button>`).join('')}
    ${m.id.length ? `<button class="chip unmute" data-unmute="id" data-val="*">${m.id.length} hidden stor${m.id.length > 1 ? 'ies' : 'y'} ✕</button>` : ''}</div>` : '<p class="desc">Nothing hidden. Use the “Hide” button on any story to hide it, its source or a topic.</p>'}`;
}

// ----- 2 & 5. How to fix, and plain-English explanations for CVEs -----
function fixLine(id) {
  const f = D.cves.fix?.[id], k = kevById.get(id);
  const parts = (f?.p || []).slice(0, 2).map(p => p.f.length ? `${esc(p.p || 'Fixed')}: upgrade to <b>${p.f.slice(0, 3).map(esc).join('</b>, <b>')}</b>${p.f.length > 3 ? ' …' : ''} or later` : `${esc(p.p)}: versions up to ${p.u.map(esc).join(', ')} are affected`);
  const adv = f?.a?.[0] || k?.adv?.[0];
  if (!parts.length && !adv && !k?.ra) return '';
  const action = !parts.length && k?.ra ? esc(k.ra.split(/(?<=\.)\s/)[0]) : '';
  return `<div class="cr-fix"><span class="lbl">Fix</span>${parts.join('; ') || action || 'See the vendor advisory'}${adv ? ` · <a href="${url(adv)}" target="_blank" rel="noopener">Vendor advisory ↗</a>` : ''}</div>`;
}
function fixSection(id) {
  const f = D.cves.fix?.[id], k = kevById.get(id);
  if (!f && !k) return '<h3>How to fix</h3><p class="muted">No fixed versions published yet — check the vendor advisory from NVD.</p>';
  const advs = [...new Set([...(f?.a || []), ...(k?.adv || [])])];
  return `<h3>How to fix</h3>
    ${(f?.p || []).length ? `<table class="fix-table"><thead><tr><th>Product</th><th>Fixed in</th></tr></thead><tbody>${f.p.map(p => `<tr><td>${esc(p.p)}</td><td>${p.f.length ? p.f.map(v => `<code>${esc(v)}</code>`).join(' ') : `Affected up to ${p.u.map(esc).join(', ')}`}</td></tr>`).join('')}</tbody></table>` : ''}
    ${k?.ra ? `<p><b>CISA required action:</b> ${esc(k.ra.split(/(?<=\.)\s/).slice(0, 2).join(' '))}</p>` : ''}
    ${advs.length ? `<ul class="rel">${advs.map(u => { let h = u; try { h = new URL(u).hostname; } catch {} return `<li><a href="${url(u)}" target="_blank" rel="noopener">Advisory on ${esc(h)}</a> <a class="muted" href="${url(wayback(u))}" target="_blank" rel="noopener">(archived copy)</a></li>`; }).join('')}</ul>` : ''}`;
}
// Public exploit code (GitHub PoCs via PoC-in-GitHub, plus Exploit-DB) shown right in CVE lists.
function pocLine(id) {
  const p = D.cves.poc?.[id]; if (!p || (!p.n && !p.edb)) return '';
  const repos = (p.top || []).slice(0, 3).map(t => `<a href="${url(t.u)}" target="_blank" rel="noopener" title="${esc(t.d || t.n)}">${esc(t.n)}</a> <span class="muted">★${t.s}</span>`);
  if (p.n > 3) repos.push(`<a href="https://github.com/search?q=${id}&type=repositories" target="_blank" rel="noopener">+${p.n - 3} more</a>`);
  if (p.edb) repos.push(`<a href="https://www.exploit-db.com/search?cve=${id.replace('CVE-', '')}" target="_blank" rel="noopener">Exploit-DB</a>`);
  return `<div class="cr-poc" title="Exploit code is untrusted — read it before running, and only in a lab"><span class="lbl">PoC</span>${p.first ? `<span class="muted">first published ${fmtAgo(p.first)} · </span>` : ''}${repos.join(' · ')}</div>`;
}
const aiLine = id => D.cves.ai?.[id] ? `<p class="cr-ai" title="AI-generated from the official description; check the advisory"><span class="lbl">In plain English</span>${esc(D.cves.ai[id])}</p>` : '';

// ----- 3. Developing stories -----
const EV_KIND = { exploit: 'Exploitation', patch: 'Patch / fix', analysis: 'Analysis', news: 'News', advisory: 'Advisory', kev: 'CISA KEV', poc: 'Public exploit', cve: 'CVE published' };
function timelineHtml(events) {
  let lastDay = '';
  return `<ol class="timeline">${events.map(e => {
    const d = fmtDay(e.d), head = d !== lastDay ? `<li class="tl-day">${esc(d)}</li>` : ''; lastDay = d;
    return head + `<li class="tl-ev tl-${e.k}"><span class="tl-time">${new Date(e.d).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</span><span class="tl-kind">${EV_KIND[e.k] || e.k}</span><a href="${url(e.u)}" target="_blank" rel="noopener" data-open>${esc(e.t)}</a>${e.s ? ` <span class="muted">— ${esc(e.s)}</span>` : ''}</li>`;
  }).join('')}</ol>`;
}
function renderDeveloping() {
  const list = D.incidents?.incidents || [];
  const q = state.q.trim().toLowerCase();
  const inc = list.find(i => i.id === state.inc);
  if (inc) {
    $('#view').innerHTML = `<p><button class="linkish" data-inc="">← All developing stories</button></p>
      <div class="hero-label">Developing story</div><h2 class="dev-title">${esc(inc.title)}</h2>
      <p class="lede">${inc.n} stories from ${inc.outlets} outlets · first report ${fmtAgo(inc.first)} · latest ${fmtAgo(inc.last)}${inc.cves?.length ? ` · ${inc.cves.map(c => `<button class="linkbtn" data-cve="${c}">${c}</button>`).join(', ')}` : ''}${inc.actor ? ` · <button class="linkish" data-q="actor:&quot;${esc(inc.actor)}&quot;" data-tab-go="latest">all ${esc(inc.actor)} stories</button>` : ''}</p>
      ${inc.cves?.length ? `<div class="cve-list" style="margin-bottom:24px">${inc.cves.slice(0, 3).map(c => cveRow(c)).join('')}</div>` : ''}
      <div class="panel-head"><h2 style="font:700 19px var(--serif);margin:0">Timeline</h2><a class="muted" href="stories/${esc(inc.id)}.html">Shareable page ↗</a></div>
      ${timelineHtml(inc.events.slice().reverse())}`;
    return;
  }
  const rows = list.filter(i => !q || `${i.title} ${(i.cves || []).join(' ')} ${i.actor || ''}`.toLowerCase().includes(q));
  $('#view').innerHTML = `<p class="lede">Incidents and vulnerabilities that kept getting coverage, followed across outlets: first reports, exploitation, CISA listings, public exploits, patches and analysis — in date order.</p>
    <div class="dev-list">${rows.map(i => {
      const kinds = new Set(i.events.map(e => e.k));
      return `<article class="dev">
        <div class="dev-meta"><span class="live${Date.now() - i.last < DAY ? ' on' : ''}">${Date.now() - i.last < DAY ? 'Active today' : `Updated ${fmtAgo(i.last)}`}</span> · ${i.n} stories · ${i.outlets} outlets · since ${new Date(i.first).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</div>
        <h3><button class="linkish" data-inc="${esc(i.id)}">${esc(i.title)}</button></h3>
        <div class="dev-flags">${kinds.has('kev') ? '<span class="kev">KEV</span>' : ''}${kinds.has('poc') ? '<span class="poc">PoC</span>' : ''}${kinds.has('patch') ? '<span class="why">Patch available</span>' : ''}${(i.cves || []).slice(0, 4).map(c => `<button class="linkbtn" data-cve="${c}">${c}</button>`).join(' ')}</div>
        ${timelineHtml(i.events.slice(-4).reverse())}
        <button class="linkish" data-inc="${esc(i.id)}">Full timeline (${i.events.length} events) →</button>
      </article>`;
    }).join('') || '<div class="empty">No developing stories right now.</div>'}</div>`;
}
const incLine = s => { if (!s.inc) return ''; const i = D.incidents?.incidents?.find(x => x.id === s.inc); return i ? `<div class="inc-line"><span class="lbl">Developing</span><button class="linkish" data-inc="${esc(i.id)}" data-tab-go="developing">${esc(i.title)} — ${i.events.length} updates →</button></div>` : ''; };

// ----- 4. Breach tracker -----
const fmtCount = n => n >= 1e9 ? (n / 1e9).toFixed(n >= 1e10 ? 0 : 1) + ' billion' : n >= 1e6 ? (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + ' million' : n.toLocaleString();
function breachTracker() {
  const since = Date.now() - state.range * DAY, q = state.q.trim().toLowerCase();
  let rows = D.news.stories.filter(s => s.rc && s.d >= since && !isMuted(s));
  if (q) rows = rows.filter(s => haystack(s).includes(q));
  rows.sort((a, b) => b.rc - a.rc);
  const max = Math.max(1, ...rows.map(r => r.rc));
  return `<p class="lede">Breaches reported in the last ${state.range} days, largest first. Sizes are read from the headlines and summaries (for example “6.6 million accounts”) and are only as accurate as the reporting.</p>
    <div class="table-wrap"><table class="breach-table"><thead><tr><th>Affected</th><th></th><th>Breach</th><th>Reported</th></tr></thead><tbody>
    ${rows.map(s => `<tr><td class="num"><b>${fmtCount(s.rc)}</b><div class="muted">${esc(s.ru)}</div></td><td style="width:18%"><div class="bar" style="width:${Math.max(2, Math.sqrt(s.rc / max) * 100)}%"></div></td><td><a href="${url(s.u)}" target="_blank" rel="noopener" data-open>${esc(s.t)}</a><div class="muted">${esc(s.s)}${s.r.length ? ` + ${s.r.length} more` : ''}</div></td><td class="nowrap">${fmtAgo(s.d)}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">No breach sizes found in this period.</td></tr>'}
    </tbody></table></div>`;
}

// ----- Tenable plugins -----
const PLUGIN_PRODUCT = { nessus: 'Nessus', 'cloud-security': 'Cloud Security', 'container-security': 'Container Security', was: 'Web App Scanning', nnm: 'Nessus Network Monitor', ot: 'OT Security', lce: 'Log Correlation' };
const pluginType = p => p.distro || /^Linux Distros? Unpatched/i.test(p.t) ? 'os' : /^SCA:/i.test(p.t) ? 'lib' : 'vendor';
function pluginList() {
  // Tenable publishes the same check for several products; show it once with all products.
  const m = new Map();
  for (const p of D.plugins?.plugins || []) {
    const k = p.id + '|' + p.t;
    if (m.has(k)) m.get(k).ps.push(p.p); else m.set(k, { ...p, ps: [p.p] });
  }
  return [...m.values()];
}
async function renderPlugins() {
  if (!D.plugins) { $('#view').innerHTML = '<div class="empty">Loading plugins…</div>'; await lazy('plugins', 'plugins.json'); if (state.tab === 'plugins') render(); return; }
  const all = pluginList();
  if (!all.length) { $('#view').innerHTML = '<div class="empty">Tenable plugin data is unavailable right now.</div>'; return; }
  const type = state.sub.plugins || 'vendor', sev = state.plSev || 'all', q = state.q.trim().toLowerCase();
  const order = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
  let rows = all.filter(p => type === 'all' || pluginType(p) === type);
  if (sev === 'critical') rows = rows.filter(p => p.v === 'Critical'); else if (sev === 'high') rows = rows.filter(p => order[p.v] >= 3);
  if (q) rows = rows.filter(p => `${p.t} ${p.id} ${p.cv.join(' ')} ${p.syn} ${p.sol}`.toLowerCase().includes(q));
  const hot = p => p.cv.filter(c => D.cves.kevIndex?.[c] || cveMentions.has(c));
  const counts = { vendor: 0, os: 0, lib: 0 }; for (const p of all) counts[pluginType(p)]++;
  const days = {}; for (const p of all) { const k = new Date(p.d).toISOString().slice(0, 10); days[k] = (days[k] || 0) + 1; }
  $('#view').innerHTML = `<p class="lede">New vulnerability checks published by Tenable for Nessus, Cloud Security and its other scanners over the last 30 days, from Tenable's public plugin feed. Checks for CVEs that are exploited (KEV) or in the news are flagged, so you know you can scan for them today.</p>
    <div class="subtabs">${[['vendor', `Vendor & application checks (${counts.vendor})`], ['os', `OS package updates (${counts.os})`], ['lib', `Open-source libraries (${counts.lib})`], ['all', 'All']].map(([v, l]) => `<button data-sub-plugins="${v}" aria-pressed="${type === v}">${l}</button>`).join('')}</div>
    <div class="toolbar"><div class="seg" role="group" aria-label="Severity">${[['all', 'All severities'], ['high', 'High and critical'], ['critical', 'Critical']].map(([v, l]) => `<button data-plsev="${v}" aria-pressed="${sev === v}">${l}</button>`).join('')}</div>
      <label><input type="checkbox" id="pl-hot" ${state.plHot ? 'checked' : ''}> Only exploited or in the news</label>
      <span class="spacer"></span><span class="muted">${(state.plHot ? rows.filter(p => hot(p).length) : rows).length} plugins</span></div>
    <div class="plugin-list">${(state.plHot ? rows.filter(p => hot(p).length) : rows).slice(0, state.plShown || 100).map(p => {
      const h = hot(p);
      return `<article class="plugin">
        <div class="pl-top"><span class="sev ${p.v.toUpperCase()}">${esc(p.v || 'Info')}</span><span class="pl-id">#${p.id}</span><span class="muted">${p.ps.map(x => esc(PLUGIN_PRODUCT[x] || x)).join(' · ')}</span><span class="spacer"></span><time class="muted" title="${esc(fmtFull(p.d))}">${fmtAgo(p.d)}</time></div>
        <h3 class="pl-title"><a href="${url(p.u)}" target="_blank" rel="noopener">${highlight(p.t, parseQuery(state.q))}</a></h3>
        ${p.syn ? `<p class="pl-syn">${esc(p.syn)}</p>` : ''}
        ${p.sol ? `<div class="cr-fix"><span class="lbl">Solution</span>${esc(p.sol)}</div>` : ''}
        ${p.cv.length ? `<div class="pl-cves">${h.length ? `<span class="why crit">${h.some(c => D.cves.kevIndex?.[c]) ? 'Exploited CVE' : 'In the news'}</span>` : ''}${p.cv.slice(0, 6).map(cveChip).join('')}${p.ncv > 6 ? `<span class="muted">+${p.ncv - 6} more CVEs</span>` : ''}</div>` : ''}
      </article>`;
    }).join('') || '<div class="empty">No plugins match.</div>'}</div>
    ${rows.length > (state.plShown || 100) ? '<button class="loadmore" data-pl-more>Show more</button>' : ''}
    <p class="desc" style="margin-top:20px">Source: <a href="https://www.tenable.com/plugins" target="_blank" rel="noopener">tenable.com/plugins</a>. Plugin names and details © Tenable. ${Object.keys(days).length} days of history.</p>`;
}
const pluginsForCve = id => pluginList().filter(p => p.cv.includes(id));

// ----- Ransomware: countries table and live map -----
function countriesTable() {
  const R = D.rw, T = R.totals || {}, q = state.q.trim().toLowerCase();
  const cols = [['d24', '24 h'], ['d7', '7 days'], ['d30', '30 days'], ['ytd', 'This year'], ['all', 'All time']];
  const get = arr => Object.fromEntries(arr || []);
  const src = { d24: get(R.countries24), d7: get(R.countries7), d30: get(R.countriesAll30 || R.countries), ytd: get(T.countriesYtd), all: get(T.countriesAll) };
  const codes = new Set(Object.values(src).flatMap(o => Object.keys(o)));
  let rows = [...codes].map(c => ({ c, name: regionName(c), ...Object.fromEntries(cols.map(([k]) => [k, src[k][c] || 0])) }));
  if (q) rows = rows.filter(r => `${r.c} ${r.name}`.toLowerCase().includes(q));
  const key = state.rwSort || 'd30';
  rows.sort((a, b) => b[key] - a[key] || b.all - a.all);
  const total = rows.reduce((a, r) => a + r[key], 0) || 1;
  const hit = rows.filter(r => r[key] > 0).length;
  return `<div class="panel"><div class="panel-head"><h2>Countries affected by ransomware</h2><span class="muted">${hit} countries with claims · ${cols.find(c => c[0] === key)[1].toLowerCase()}</span></div>
    <p class="desc">Claimed victims per country. Click a column to sort, or a country to list its victims.</p>
    <div class="table-wrap"><table class="country-table"><thead><tr><th>#</th><th>Country</th>${cols.map(([k, l]) => `<th class="sortable${k === key ? ' on' : ''}"><button data-rwsort="${k}">${l}${k === key ? ' ↓' : ''}</button></th>`).join('')}<th>Share</th></tr></thead><tbody>
    ${rows.slice(0, state.rwAllCountries || q ? rows.length : 25).map((r, i) => `<tr><td class="num muted">${i + 1}</td><td class="nowrap"><button class="linkish plain" data-rwcountry="${esc(r.c)}">${flag(r.c)} ${esc(r.name)}</button></td>${cols.map(([k]) => `<td class="num${k === key ? ' strong' : ''}">${r[k] ? r[k].toLocaleString() : '<span class="muted">–</span>'}</td>`).join('')}<td style="min-width:120px"><div class="bar" style="width:${Math.max(r[key] ? 2 : 0, (r[key] / (rows[0][key] || 1)) * 100)}%" title="${((r[key] / total) * 100).toFixed(1)}% of claims"></div></td></tr>`).join('')}
    </tbody></table></div>${rows.length > 25 && !q ? `<button class="loadmore" data-rw-allc>${state.rwAllCountries ? 'Show top 25 only' : `Show all ${rows.length} countries`}</button>` : ''}</div>`;
}
function liveMapHtml() {
  const win = state.liveWin || 1;
  return `<div class="panel live-panel"><div class="panel-head"><h2>Live map</h2>
      <div class="map-controls"><div class="seg" role="group" aria-label="Period">${[[1, '24 h'], [3, '3 days'], [7, '7 days']].map(([v, l]) => `<button data-livewin="${v}" aria-pressed="${win === v}">${l}</button>`).join('')}</div>
      <button class="save" id="live-replay">▶ Replay</button></div></div>
    <p class="desc">Each marker is a country with claimed victims in the period; bigger means more claims, pulsing means a claim in the last 3 hours. Replay plays the claims back in the order they were posted.</p>
    <div class="live-grid"><div class="map-wrap live-map" id="live-map">Loading map…</div>
      <aside class="ticker"><h3>Latest claims</h3><ol id="ticker"></ol></aside></div></div>`;
}
let liveTimer;
async function drawLiveMap() {
  const el = $('#live-map'); if (!el) return;
  const world = await lazy('world', 'world.json');
  if (!world?.centers) { el.textContent = 'Map data unavailable.'; return; }
  clearInterval(liveTimer);
  const win = (state.liveWin || 1) * DAY, now = Date.now();
  const claims = D.rw.recent.filter(v => now - v.d < win && v.c).sort((a, b) => a.d - b.d);
  const counts = {}; for (const v of claims) counts[v.c] = (counts[v.c] || 0) + 1;
  const recent = new Set(claims.filter(v => now - v.d < 3 * 36e5).map(v => v.c));
  const r = n => (3 + Math.sqrt(n) * 3.2).toFixed(1);
  el.innerHTML = `<svg viewBox="0 0 ${world.w} ${world.h}" role="img" aria-label="Live map of ransomware claims">
    <g class="base">${Object.entries(world.paths).map(([c, d]) => `<path data-cc="${c}" d="${d}" class="${counts[c] ? 'hit' : ''}" data-tip="${esc(regionName(c))}: ${counts[c] || 0} claims"/>`).join('')}</g>
    <g class="marks">${Object.entries(counts).filter(([c]) => world.centers[c]).sort((a, b) => b[1] - a[1]).map(([c, n]) => { const [x, y] = world.centers[c]; return `<g class="mk${recent.has(c) ? ' fresh' : ''}" data-tip="${esc(regionName(c))}: ${n} claim${n > 1 ? 's' : ''}" transform="translate(${x} ${y})"><circle class="pulse" r="${r(n)}"/><circle class="dot" r="${r(n)}"/>${n >= 5 ? `<text dy="3.5">${n}</text>` : ''}</g>`; }).join('')}</g>
    <g class="pings"></g></svg>`;
  const tick = $('#ticker');
  const line = v => `<li><span class="t">${new Date(v.d).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</span>${flag(v.c)} <b>${esc(v.g)}</b> claimed <span class="v">${esc(v.t)}</span></li>`;
  tick.innerHTML = claims.slice(-25).reverse().map(line).join('') || '<li class="muted">No claims in this period.</li>';
  $('#live-replay').onclick = () => replayLive(world, claims, line);
}
function replayLive(world, claims, line) {
  clearInterval(liveTimer);
  const pings = $('#live-map .pings'), tick = $('#ticker'); if (!pings) return;
  tick.innerHTML = '';
  let i = 0;
  const step = Math.max(60, Math.min(400, 18000 / Math.max(1, claims.length)));
  liveTimer = setInterval(() => {
    if (!$('#live-map') || i >= claims.length) { clearInterval(liveTimer); return; }
    const v = claims[i++], c = world.centers[v.c];
    if (c) {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      g.setAttribute('cx', c[0]); g.setAttribute('cy', c[1]); g.setAttribute('r', 4); g.setAttribute('class', 'ping');
      pings.append(g); setTimeout(() => g.remove(), 1600);
    }
    tick.insertAdjacentHTML('afterbegin', line(v));
    while (tick.children.length > 25) tick.lastChild.remove();
  }, matchMedia('(prefers-reduced-motion: reduce)').matches ? 10 : step);
}

// ----- Archive (year to date) -----
const wayback = u => `https://web.archive.org/web/${u}`;
const AR = { index: undefined, news: {}, cves: {}, loading: false };
async function arLoad(kind, m) {
  if (AR[kind][m]) return AR[kind][m];
  try { AR[kind][m] = await (await fetch(`data/archive/${kind}-${m}.json`)).json(); } catch { AR[kind][m] = []; }
  if (kind === 'cves') for (const c of AR[kind][m]) if (!recentById.has(c.id)) recentById.set(c.id, c);   // lets the CVE panel show archived CVEs
  return AR[kind][m];
}
async function arYear(name) { if (AR[name] === undefined) { try { AR[name] = await (await fetch(`data/archive/${name}-${AR.index.year}.json`)).json(); } catch { AR[name] = []; } } return AR[name]; }
// Loads what the current view needs, then re-renders once. Keeps render() synchronous.
function arEnsure(need) {
  if (AR.loading) return false;
  const missing = need.filter(([k, m]) => (m ? !AR[k][m] : AR[k] === undefined));
  if (!missing.length) return true;
  AR.loading = true;
  Promise.all(missing.map(([k, m]) => (k === 'index' ? fetch('data/archive/index.json').then(r => r.json()).then(j => { AR.index = j; }, () => { AR.index = null; }) : m ? arLoad(k, m) : arYear(k))))
    .finally(() => { AR.loading = false; if (state.tab === 'archive') render(); });
  return false;
}
const monthName = m => new Date(m + '-15T12:00:00Z').toLocaleDateString(undefined, { month: 'long', timeZone: 'UTC' });
const monthShort = m => new Date(m + '-15T12:00:00Z').toLocaleDateString(undefined, { month: 'short', timeZone: 'UTC' });

function renderArchive() {
  const loading = '<div class="empty">Loading the archive…</div>';
  if (!arEnsure([['index']])) { $('#view').innerHTML = loading; return; }
  const idx = AR.index;
  if (!idx || !idx.months.length) { $('#view').innerHTML = '<div class="empty">The archive hasn’t been built yet. Run <code>node backfill.js</code> once, then <code>node build.js</code>.</div>'; return; }
  const sub = state.sub.archive || 'news';
  const q = state.q.trim().toLowerCase(), terms = parseQuery(state.q);
  const months = idx.months.map(x => x.m);
  // A search always covers the whole year; otherwise show the chosen month (default: the current one).
  const sel = q ? 'all' : state.arMonth && (state.arMonth === 'all' || months.includes(state.arMonth)) ? state.arMonth : months.at(-1);
  const wantMonths = sel === 'all' ? months : [sel];
  const subs = [['news', `News (${idx.totals.news.toLocaleString()})`], ['cves', `CVEs (${idx.totals.cves.toLocaleString()})`], ['kev', `Exploited (${idx.totals.kev})`], ['rw', `Ransomware (${idx.totals.rw.toLocaleString()})`], ['hibp', `Breaches (${idx.totals.hibp})`], ['coverage', 'Coverage']];
  const metric = { news: 'news', cves: 'cves', kev: 'kev', rw: 'rw', hibp: 'news', coverage: 'news' }[sub];
  const maxM = Math.max(1, ...idx.months.map(x => x[metric]));
  const monthBar = ['news', 'cves', 'kev', 'rw'].includes(sub) ? `<div class="ar-months" role="group" aria-label="Month">
      <button class="ar-m${sel === 'all' ? ' on' : ''}" data-armonth="all"><span class="n">${idx.months.reduce((a, x) => a + x[metric], 0).toLocaleString()}</span><span class="b"><i style="height:100%"></i></span><span class="l">All ${idx.year}</span></button>
      ${idx.months.map(x => `<button class="ar-m${sel === x.m ? ' on' : ''}" data-armonth="${x.m}" title="${esc(monthName(x.m))}: ${x[metric].toLocaleString()}"><span class="n">${x[metric].toLocaleString()}</span><span class="b"><i style="height:${Math.max(3, (x[metric] / maxM) * 100)}%"></i></span><span class="l">${esc(monthShort(x.m))}</span></button>`).join('')}</div>` : '';
  const head = `<p class="lede">Everything since January 1, ${idx.year}: news rebuilt from the <a href="https://web.archive.org/" target="_blank" rel="noopener">Wayback Machine</a>’s saved copies of each feed, every CVE published this year, CISA’s exploited list, ransomware leak-site claims and breaches loaded into Have I Been Pwned. The search bar searches the whole year.</p>
    <div class="subtabs">${subs.map(([v, l]) => `<button data-sub-archive="${v}" aria-pressed="${sub === v}">${l}</button>`).join('')}</div>${monthBar}`;
  const more = (n, shown) => n > shown ? `<button class="loadmore" data-ar-more>Show more (${(n - shown).toLocaleString()} remaining)</button>` : '';
  const shown = state.arShown || 100;
  let body = '';
  if (sub === 'news' || sub === 'cves') {
    if (!arEnsure(wantMonths.map(m => [sub, m]))) { $('#view').innerHTML = head + loading; return; }
    let rows = wantMonths.flatMap(m => AR[sub][m] || []);
    if (sub === 'news') {
      if (terms.length) rows = rows.filter(x => {
        const h = `${x.t} ${x.x} ${x.s} ${(x.cv || []).join(' ')} ${(x.ac || []).join(' ')} ${(x.ve || []).join(' ')} ${(x.tp || []).join(' ')} ${(x.tg || []).join(' ')}`.toLowerCase();
        return terms.every(({ f, v }) => f === 'source' || f === 'src' ? x.s.toLowerCase().includes(v) : f === 'cve' ? (x.cv || []).some(c => c.toLowerCase().includes(v)) : f === 'topic' ? h.replace(/[^a-z0-9]/g, '').includes(norm(v)) : h.includes(v));
      });
      if (state.arTag) rows = rows.filter(x => (x.tg || []).includes(state.arTag));
      rows.sort((a, b) => b.d - a.d);
      const tags = [['', 'All'], ['zeroday', 'Zero-days'], ['breach', 'Breaches'], ['ransomware', 'Ransomware'], ['apt', 'APT'], ['vuln', 'Vulnerabilities'], ['malware', 'Malware'], ['supply', 'Supply chain']];
      let lastDay = '';
      body = `<div class="toolbar"><div class="seg" role="group" aria-label="Topic">${tags.map(([v, l]) => `<button data-artag="${v}" aria-pressed="${(state.arTag || '') === v}">${l}</button>`).join('')}</div><span class="spacer"></span><span class="muted">${rows.length.toLocaleString()} stories${sel === 'all' ? ` in ${idx.year}` : ` in ${monthName(sel)}`}</span></div>
        <div class="ar-list">${rows.slice(0, shown).map(x => {
          const d = new Date(x.d).toLocaleDateString(undefined, { weekday: 'short', month: 'long', day: 'numeric', timeZone: 'UTC' });
          const hd = d !== lastDay ? `<div class="day">${esc(d)}</div>` : ''; lastDay = d;
          return hd + `<article class="ar-row">${avatar(x.s)}<span class="rsrc">${esc(x.s)}</span><span class="ar-t"><a href="${url(x.u)}" target="_blank" rel="noopener">${highlight(x.t, terms)}</a>${(x.cv || []).slice(0, 2).map(c => ` <button class="linkbtn" data-cve="${c}">${c}</button>`).join('')}</span><a class="ar-wb" href="${url(wayback(x.u))}" target="_blank" rel="noopener" title="Archived copy on the Wayback Machine">archived</a></article>`;
        }).join('') || '<div class="empty">No stories match.</div>'}</div>${more(rows.length, shown)}`;
    } else {
      const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      if (state.sevFilter === 'CRITICAL') rows = rows.filter(r => r.v === 'CRITICAL'); else if (state.sevFilter === 'HIGH+') rows = rows.filter(r => order[r.v] >= 3);
      if (q) rows = rows.filter(r => `${r.id} ${r.x} ${r.cwe || ''}`.toLowerCase().includes(q));
      rows.sort((a, b) => b.p - a.p);
      body = `<div class="toolbar"><div class="seg" role="group" aria-label="Severity">${[['CRITICAL', 'Critical'], ['HIGH+', 'High and critical'], ['ALL', 'All']].map(([v, l]) => `<button data-sev="${v}" aria-pressed="${state.sevFilter === v}">${l}</button>`).join('')}</div><span class="spacer"></span><span class="muted">${rows.length.toLocaleString()} CVEs</span></div>
        <div class="ar-cves">${rows.slice(0, shown).map(r => `<article class="ar-cve"><span class="ar-date">${new Date(r.p).toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })}</span><button class="cr-id" data-cve="${r.id}">${r.id}</button><span>${r.s != null ? `<span class="sev ${r.v}">${r.s}</span>` : '<span class="sev NONE">–</span>'}${D.cves.kevIndex?.[r.id] ? ' <span class="kev">KEV</span>' : ''}${D.cves.poc?.[r.id] ? ' <span class="poc">PoC</span>' : ''}</span><span class="ar-x">${highlight(r.x || '', terms)}</span></article>`).join('') || '<div class="empty">No CVEs match.</div>'}</div>${more(rows.length, shown)}`;
    }
  } else if (sub === 'kev') {
    if (!arEnsure([['kev']])) { $('#view').innerHTML = head + loading; return; }
    let rows = AR.kev.filter(k => sel === 'all' || k.d.startsWith(sel));
    if (q) rows = rows.filter(k => `${k.id} ${k.v} ${k.p} ${k.n}`.toLowerCase().includes(q));
    body = `<div class="table-wrap"><table><thead><tr><th>Added</th><th>CVE</th><th>Vendor · product</th><th>Vulnerability</th><th>Ransomware</th></tr></thead><tbody>${rows.map(k => `<tr><td class="nowrap">${k.d}</td><td><button class="linkbtn" data-cve="${k.id}">${k.id}</button></td><td>${esc(k.v)} · ${esc(k.p)}</td><td><div class="clamp">${esc(k.n)}</div></td><td>${k.rw ? '<span class="rwflag">Known</span>' : ''}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">No entries.</td></tr>'}</tbody></table></div>`;
  } else if (sub === 'rw') {
    if (!arEnsure([['ransomware']])) { $('#view').innerHTML = head + loading; return; }
    let rows = AR.ransomware.filter(v => sel === 'all' || new Date(v.d).toISOString().startsWith(sel));
    if (q) rows = rows.filter(v => `${v.t} ${v.g} ${v.c} ${regionName(v.c)} ${v.a} ${v.w}`.toLowerCase().includes(q));
    const top = k => { const m = {}; for (const v of rows) if (v[k]) m[v[k]] = (m[v[k]] || 0) + 1; return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 8); };
    body = `<div class="grid-2" style="margin-bottom:20px"><div class="panel"><h2>Top groups</h2>${bars(top('g'))}</div><div class="panel"><h2>Top countries</h2>${bars(top('c'), { label: c => regionName(c) })}</div></div>
      <div class="table-wrap"><table><thead><tr><th>Discovered</th><th>Victim (as claimed)</th><th>Group</th><th>Country</th><th>Sector</th></tr></thead><tbody>${rows.slice(0, shown).map(v => `<tr><td class="nowrap">${new Date(v.d).toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })}</td><td>${esc(v.t)}</td><td class="nowrap">${esc(v.g)}</td><td class="nowrap">${flag(v.c)} ${esc(regionName(v.c))}</td><td>${esc(v.a)}</td></tr>`).join('')}</tbody></table></div>${more(rows.length, shown)}`;
  } else if (sub === 'hibp') {
    if (!arEnsure([['breaches']])) { $('#view').innerHTML = head + loading; return; }
    let rows = AR.breaches; if (q) rows = rows.filter(b => `${b.n} ${b.dom} ${b.dc.join(' ')}`.toLowerCase().includes(q));
    body = `<div class="table-wrap"><table class="breach-table"><thead><tr><th>Added to HIBP</th><th>Breach</th><th>Accounts</th><th>Data exposed</th><th>Breach date</th></tr></thead><tbody>${rows.map(b => `<tr><td class="nowrap">${new Date(b.ad).toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })}</td><td><b>${esc(b.n)}</b><div class="clamp muted">${esc(b.x)}</div></td><td class="num">${fmtCount(b.c)}</td><td><div class="clamp">${esc(b.dc.join(', '))}</div></td><td class="nowrap">${esc(b.bd)}</td></tr>`).join('')}</tbody></table></div>`;
  } else {
    const full = idx.sources.filter(s => s.first && s.first < Date.UTC(idx.year, 1, 1)).length;
    body = `<p class="desc">How far back each source goes in this archive. <b>${full}</b> of ${idx.sources.length} sources reach back to January. “Wayback” means rebuilt from saved copies of the feed; “paging” from the site’s own older feed pages; “live” only from our regular updates.</p>
      <div class="table-wrap"><table><thead><tr><th>Source</th><th>Stories this year</th><th>Earliest</th><th>Recovered via</th></tr></thead><tbody>${idx.sources.map(s => `<tr><td class="nowrap"><span class="srcname">${avatar(s.s)}${esc(s.s)}</span></td><td class="num">${s.n.toLocaleString()}</td><td class="nowrap">${s.first ? new Date(s.first).toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' }) : '<span class="muted">—</span>'}</td><td>${esc(s.via)}</td></tr>`).join('')}</tbody></table></div>`;
  }
  $('#view').innerHTML = head + body;
}

// ----- Top vulnerabilities of the decade -----
const LM_CATS = [['all', 'All'], ['windows', 'Windows & AD'], ['linux', 'Linux'], ['edge', 'VPN & edge devices'], ['web', 'Servers & apps'], ['mail', 'Email'], ['client', 'Office & files'], ['mobile', 'Mobile'], ['hw', 'Hardware'], ['supply', 'Supply chain'], ['technique', 'No-CVE techniques']];
// "Dec 2021" when the CVE was published in the landmark year; otherwise the year plus the CVE's own date
// (e.g. ESXiArgs: a 2021 CVE that became a landmark in the 2023 ransomware campaign).
const monYear = t => new Date(t).toLocaleDateString(undefined, { month: 'short', year: 'numeric', timeZone: 'UTC' });
function lmDate(l) {
  const sameYear = l.pub && new Date(l.pub).getUTCFullYear() === l.year;
  const kev = l.kevAt ? `<span class="lm-kev" title="Added to CISA's Known Exploited Vulnerabilities catalog on ${l.kevAt}">CISA listed ${monYear(Date.parse(l.kevAt + 'T12:00:00Z'))}</span>` : '';
  const pubTitle = l.pub ? `CVE published ${new Date(l.pub).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' })}` : 'No CVE — year of first public release';
  if (sameYear) return `<span class="lm-year" title="${esc(pubTitle)}">${monYear(l.pub)}</span>${kev}`;
  return `<span class="lm-year" title="${esc(pubTitle)}">${l.year}</span>${l.pub ? `<span class="lm-kev">CVE from ${monYear(l.pub)}</span>` : ''}${kev}`;
}
function renderLandmarks() {
  if (D.landmarks === undefined) {
    $('#view').innerHTML = '<div class="empty">Loading…</div>';
    lazy('landmarks', 'landmarks.json').then(j => {
      // NVD's own scores are the reference here (some vendors score their own bugs lower)
      for (const l of j?.landmarks || []) for (const [id, v] of Object.entries(l.live || {})) if (v.s != null) D.cves.info[id] = { ...(D.cves.info[id] || {}), s: v.s, v: v.v };
      if (state.tab === 'landmarks') render();
    });
    return;
  }
  const all = D.landmarks?.landmarks || [];
  const cat = state.lmCat || 'all', sort = state.lmSort || 'new', q = state.q.trim().toLowerCase(), terms = parseQuery(state.q);
  const maxEpss = l => Math.max(0, ...l.cves.map(id => l.live[id]?.epss?.[0] || 0));
  const pocs = l => l.cves.reduce((a, id) => a + (l.live[id]?.poc || 0), 0);
  let rows = all.filter(l => cat === 'all' || l.k === cat);
  if (q) rows = rows.filter(l => `${l.name} ${l.cves.join(' ')} ${l.product} ${l.what} ${l.why}`.toLowerCase().includes(q));
  const when = l => l.pub && new Date(l.pub).getUTCFullYear() === l.year ? l.pub : Date.UTC(l.year, 0, 1);
  const order = { new: (a, b) => b.year - a.year || when(b) - when(a), old: (a, b) => a.year - b.year || when(a) - when(b), epss: (a, b) => maxEpss(b) - maxEpss(a) || pocs(b) - pocs(a), poc: (a, b) => pocs(b) - pocs(a) };
  rows = rows.slice().sort(order[sort]);
  const exploited = all.filter(l => l.cves.some(id => l.live[id]?.kev)).length, ransom = all.filter(l => l.cves.some(id => l.live[id]?.rw)).length;
  const card = l => {
    const cves = l.cves.map(id => {
      const v = l.live[id] || {};
      return `<div class="lm-cve"><button class="cr-id" data-cve="${id}">${id}</button>${v.s != null ? `<span class="sev ${v.v}" title="NVD CVSS${v.vendor != null ? ` — the vendor scored it ${v.vendor}` : ''}">${v.s}${v.vendor != null ? '*' : ''}</span>` : ''}${v.kev ? `<span class="kev" title="In CISA KEV since ${v.kev}">KEV</span>` : ''}${v.rw ? '<span class="rwflag" title="Known to be used in ransomware campaigns">Ransomware</span>' : ''}${v.epss ? `<span class="metric" title="Probability of exploitation in the next 30 days (FIRST EPSS)"><b>${(v.epss[0] * 100).toFixed(v.epss[0] < 0.1 ? 1 : 0)}%</b> EPSS</span>` : ''}${v.poc ? `<a class="metric" href="https://github.com/search?q=${id}&type=repositories" target="_blank" rel="noopener" title="Public proof-of-concept repositories on GitHub"><b>${v.poc}</b> PoCs</a>` : ''}</div>`;
    }).join('');
    return `<article class="lm lm-${l.k}">
      <div class="lm-top">${lmDate(l)}<span class="lm-prod">${esc(l.product)}</span>${l.auto ? '<span class="auto-tag" title="Picked automatically: CISA-confirmed exploitation ranked by ransomware use, exploitation probability, public exploits and news coverage. The description is CISA’s own.">Auto-selected</span>' : ''}</div>
      <h3 class="lm-name">${highlight(l.name, terms)}</h3>
      ${cves || '<div class="lm-cve"><span class="muted">No CVE — treated as by design</span></div>'}
      <p class="lm-what">${highlight(l.what, terms)}</p>
      <p class="lm-why"><span class="lbl">${l.auto ? 'Evidence' : 'Why it mattered'}</span>${highlight(l.why, terms)}</p>
      ${l.links?.length ? `<div class="lm-links">${l.links.map(([t, u]) => `<a href="${url(u)}" target="_blank" rel="noopener">${esc(t)} ↗</a>`).join('')}</div>` : ''}
    </article>`;
  };
  let body = '';
  if (sort === 'new' || sort === 'old') {
    const years = [...new Set(rows.map(l => l.year))];
    body = years.map(y => `<section class="lm-yearblock"><h2 class="lm-yh">${y}</h2><div class="lm-grid">${rows.filter(l => l.year === y).map(card).join('')}</div></section>`).join('');
  } else body = `<div class="lm-grid">${rows.map(card).join('')}</div>`;
  $('#view').innerHTML = `<p class="lede">The vulnerabilities that defined the last ten years — the ones behind WannaCry and NotPetya, mass VPN compromises, the Equifax and MOVEit breaches, and the classic privilege-escalation tricks every red and blue team knows. Descriptions are hand-written; scores, exploitation status and exploit counts are live from NVD, CISA, FIRST and GitHub. For the last two years, the biggest vulnerabilities are also picked <b>automatically</b> from that data (marked “Auto-selected”, with CISA’s own description) so the list stays current.</p>
    <div class="brief"><div class="tile"><div class="k">Vulnerabilities</div><div class="v">${all.length}</div><div class="s">2016 – ${new Date().getFullYear()}</div></div>
      <div class="tile"><div class="k">Exploited in the wild</div><div class="v">${exploited}</div><div class="s">in CISA’s KEV catalog</div></div>
      <div class="tile"><div class="k">Used by ransomware</div><div class="v">${ransom}</div><div class="s">per CISA</div></div>
      <div class="tile"><div class="k">Public exploits</div><div class="v">${all.reduce((a, l) => a + pocs(l), 0).toLocaleString()}</div><div class="s">GitHub repositories</div></div></div>
    <div class="subtabs">${LM_CATS.map(([v, l]) => `<button data-lmcat="${v}" aria-pressed="${cat === v}">${l}</button>`).join('')}</div>
    <div class="toolbar"><div class="seg" role="group" aria-label="Sort">${[['new', 'Newest first'], ['old', 'Oldest first'], ['epss', 'Most likely exploited'], ['poc', 'Most exploit code']].map(([v, l]) => `<button data-lmsort="${v}" aria-pressed="${sort === v}">${l}</button>`).join('')}</div><span class="spacer"></span><span class="muted">${rows.length} shown · * vendor’s own score is lower</span></div>
    ${body || '<div class="empty">No matches.</div>'}`;
}

// ---------- main render ----------
function render() {
  if (!D.news) return;
  renderTabs(); renderBrief();
  state.focus = -1;
  const t = state.tab;
  if (TAB[t].list && !['supply'].includes(t)) renderListTab(t);
  else ({ cves: renderCves, ransomware: renderRansomware, supply: renderSupply, patch: renderPatch, saved: renderSaved, sources: renderSources, trends: renderTrends, developing: renderDeveloping, plugins: renderPlugins, landmarks: renderLandmarks, archive: renderArchive, topics: renderTopics, categories: renderCategories })[t]();
  $('#view').insertAdjacentHTML('afterbegin', pageHead(t));
  renderRail();
  const live = $('#live'); if (live) live.textContent = `${TAB[t].label}${state.q ? `, results for ${state.q}` : ''}: ${$$('#view .story').length || $$('#view tbody tr').length} items shown`;
  translateVisible();
  const u = new URL(location.href);
  state.q ? u.searchParams.set('q', state.q) : u.searchParams.delete('q');
  t !== 'latest' ? u.searchParams.set('tab', t) : u.searchParams.delete('tab');
  history.replaceState(null, '', u);
  document.title = `${state.q ? `“${state.q}” · ` : ''}${t === 'latest' ? '' : TAB[t].label + ' · '}Threat Recap`;
}
// Sections a deployment switches off in config.json ("hide": ["plugins"]) disappear from the
// navigation, the command palette and old links.
function hideSections(ids = []) {
  for (const id of ids) {
    const i = TABS.findIndex(t => t.id === id); if (i >= 0) TABS.splice(i, 1);
    for (const [, list] of NAV_GROUPS) { const j = list.indexOf(id); if (j >= 0) list.splice(j, 1); }
    delete TAB[id];
  }
  if (!TAB[state.tab]) state.tab = 'latest';
}
function setTab(t, sub) {
  if (!TAB[t]) t = 'latest';
  state.tab = t; state.shown = PAGE;
  if (sub && t === 'cves') state.sub.cves = sub;
  render(); window.scrollTo({ top: 0 });
  $(`.tab[data-tab="${t}"]`)?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
}
function setQuery(q, { switchTab = true } = {}) {
  state.q = q; state.shown = PAGE;
  $('#q').value = q; $('#q-clear').hidden = !q; $('#kbd-slash').hidden = !!q;
  if (switchTab && q && ['patch', 'categories', 'trends'].includes(state.tab)) state.tab = 'latest';
  render();
}

// ---------- events ----------
let qTimer;
$('#q').addEventListener('input', e => { clearTimeout(qTimer); const v = e.target.value; $('#q-clear').hidden = !v; $('#kbd-slash').hidden = !!v; qTimer = setTimeout(() => setQuery(v), 140); });
$('#q').addEventListener('keydown', e => { if (e.key === 'Escape') { setQuery(''); e.target.blur(); } if (e.key === 'Enter') { const id = plainCveQuery(e.target.value); if (id) openCve(id); } });
$('#q-clear').addEventListener('click', () => { setQuery(''); $('#q').focus(); });
$$('[data-theme-set]').forEach(b => b.addEventListener('click', () => applyTheme(b.dataset.themeSet)));
applyTheme(document.documentElement.dataset.theme || 'system');
let resizeT; addEventListener('resize', () => { clearTimeout(resizeT); resizeT = setTimeout(renderRail, 200); });
$('#about-sources').addEventListener('click', e => { e.preventDefault(); setTab('sources'); });

document.addEventListener('click', e => {
  if (!e.target.closest('.menu') && !e.target.closest('[data-hide]')) closeMenus();
  if (e.target.classList.contains('drawer-bg')) { closeDrawer(); return; }
  const el = e.target.closest('button, a');
  if (!el) return;
  const d = el.dataset;
  if (d.close !== undefined && !d.q) { closeDrawer(); return; }
  if (d.iocs) { e.preventDefault(); openIocs(d.iocs); return; }
  if (d.hide !== undefined) { const card = el.closest('.story'); const st = byId.get(card?.dataset.id); if (st) openHideMenu(el, st); return; }
  if (d.mute) { mute(d.mute, d.val); return; }
  if (d.unmute) { if (d.unmute === 'id') settings.mute.id = []; else settings.mute[d.unmute] = settings.mute[d.unmute].filter(x => x !== d.val); saveSettings(); el.remove(); render(); return; }
  if (d.showMuted !== undefined) { state.showMuted = !state.showMuted; return render(); }
  if (d.inc !== undefined) { state.inc = d.inc; state.tab = 'developing'; render(); window.scrollTo({ top: 0 }); return; }
  if (d.subPlugins) { state.sub.plugins = d.subPlugins; state.plShown = 100; return render(); }
  if (d.plsev) { state.plSev = d.plsev; return render(); }
  if (d.plMore !== undefined) { state.plShown = (state.plShown || 100) + 100; const y = scrollY; render(); setTimeout(() => scrollTo({ top: y }), 0); return; }
  if (d.rwAllc !== undefined) { state.rwAllCountries = !state.rwAllCountries; const y = scrollY; render(); scrollTo({ top: y }); return; }
  if (d.rwsort) { state.rwSort = d.rwsort; const y = scrollY; render(); scrollTo({ top: y }); return; }
  if (d.livewin) { state.liveWin = +d.livewin; const y = scrollY; render(); scrollTo({ top: y }); return; }
  if (d.lmcat) { state.lmCat = d.lmcat; return render(); }
  if (d.lmsort) { state.lmSort = d.lmsort; return render(); }
  if (d.subArchive) { state.sub.archive = d.subArchive; state.arShown = 100; return render(); }
  if (d.armonth) { state.arMonth = d.armonth; state.arShown = 100; return render(); }
  if (d.artag !== undefined) { state.arTag = d.artag; state.arShown = 100; return render(); }
  if (d.arMore !== undefined) { state.arShown = (state.arShown || 100) + 200; const y = scrollY; render(); scrollTo({ top: y }); return; }
  if (d.subBreach) { state.sub.breach = d.subBreach; return render(); }
  if (d.copy) { const io = D.iocs?.iocs?.[$('#drawer-root').dataset.iocs]; if (io) navigator.clipboard?.writeText(io[d.copy].join(String.fromCharCode(10))).then(() => toast(`Copied ${io[d.copy].length} values`), () => toast('Copy failed')); return; }
  if (d.openSettings !== undefined) { openSettings(); return; }
  if (el.id === 'settings-btn') { openSettings(); return; }
  if (el.id === 'settings-done') { applySettingsFromDrawer(); return; }
  if (el.id === 'n-test') { if (Notification.permission !== 'granted') Notification.requestPermission().then(p => { if (p === 'granted') { settings.notify.on = true; saveSettings(); notify('Threat Recap', 'Notifications are working.', './'); } }); else { const was = settings.notify.on; settings.notify.on = true; notify('Threat Recap', 'Notifications are working.', './'); settings.notify.on = was; } return; }
  if (el.id === 'share-img') { shareImage(); return; }
  if (el.id === 'ioc-export') { exportIocsCsv(); return; }
  if (el.id === 'map-play') { playMap(); return; }
  if (el.id === 'palette-btn') { openPalette(); return; }
  if (el.id === 'brief-reset') { try { sessionStorage.setItem('cih.since', Date.now()); } catch {} store.set('lastVisit', Date.now()); location.reload(); return; }
  if (d.tab) return setTab(d.tab);
  if (d.cve) { e.preventDefault(); return openCve(d.cve); }
  if (d.q) { e.preventDefault(); if (d.close !== undefined) closeDrawer(); if (d.tabGo) state.tab = d.tabGo; else if (!TAB[state.tab].list || state.tab === 'supply') state.tab = 'latest'; setQuery(d.q.replace(/&quot;/g, '"'), { switchTab: false }); window.scrollTo({ top: 0 }); return; }
  if (d.tabGo) return setTab(d.tabGo, d.sub);
  if (d.tag) { const map = { zeroday: 'zeroday', breach: 'breach', apt: 'apt', ransomware: 'ransomware', malware: 'malware', supply: 'supply', vuln: 'cves' }; if (map[d.tag]) { if (d.tag === 'vuln') state.sub.cves = 'stories'; setTab(map[d.tag]); } else setQuery(`tag:${d.tag}`); return; }
  if (d.range) { state.range = +d.range; store.set('range', state.range); state.shown = PAGE; return render(); }
  if (d.density) { settings.density = d.density; saveSettings(); state.shown = PAGE; return render(); }
  if (el.id === 'clear-search') { setQuery(''); return; }
  if (d.sort) { state.sort = d.sort; state.shown = PAGE; return render(); }
  if (d.sev) { state.sevFilter = d.sev; return render(); }
  if (d.subCves) { state.sub.cves = d.subCves; return render(); }
  if (d.subRw) { state.sub.ransomware = d.subRw; return render(); }
  if (d.rwMore !== undefined) { state.rwShown += 100; const y = scrollY; render(); scrollTo({ top: y }); return; }
  if (d.subTopics) { state.sub.topics = d.subTopics; return render(); }
  if (d.rwsel) { state.rwSel = d.rwsel; const y = scrollY; render(); scrollTo({ top: y }); return; }
  if (d.rwday) { state.rwDay = d.rwday; state.rwCountry = ''; state.sub.ransomware = 'victims'; state.rwShown = 50; return render(); }
  if (d.rwcountry) { state.rwCountry = d.rwcountry; state.rwDay = ''; state.sub.ransomware = 'victims'; state.rwShown = 50; render(); return window.scrollTo({ top: 0 }); }
  if (el.id === 'rw-clear') { state.rwDay = ''; state.rwCountry = ''; return render(); }
  if (d.rwq) { state.sub.ransomware = 'victims'; setQuery(d.rwq, { switchTab: false }); return; }
  if (d.more !== undefined) { state.shown += PAGE; const y = scrollY; render(); scrollTo({ top: y }); return; }
  if (d.ack) { const s = byId.get(d.ack); if (s) { ackUpdate(s); render(); } return; }
  if (d.unsave) { delete saved[d.unsave]; persistSaved(); return render(); }
  if (d.save !== undefined) { const id = el.closest('.story').dataset.id; const s = byId.get(id); if (s) { toggleSave(s); setSaveButton(el, s); if (state.tab === 'saved') render(); } return; }
  if (d.open !== undefined) { const card = el.closest('.story'); if (card) markRead(card.dataset.id); return; }
  if (el.id === 'clear-saved') { if (el.dataset.confirm) { saved = {}; persistSaved(); render(); } else { el.dataset.confirm = '1'; el.textContent = 'Click again to remove all'; } return; }
  if (el.id === 'export-saved') { downloadFile('threat-recap-saved.json', JSON.stringify(Object.values(saved), null, 2), 'application/json'); return; }
});
document.addEventListener('auxclick', e => { const a = e.target.closest('a[data-open]'); if (a) { const c = a.closest('.story'); if (c) markRead(c.dataset.id); } });
document.addEventListener('input', e => { if (e.target.id === 'map-day') { clearInterval(mapTimer); drawMap(+e.target.value); } });
document.addEventListener('change', e => { if (e.target.id === 'cve-poc') { state.cvePoc = e.target.checked; render(); } });
document.addEventListener('change', e => { if (e.target.id === 'pl-hot') { state.plHot = e.target.checked; render(); } });
document.addEventListener('change', e => { if (e.target.id === 'show-img') { settings.images = e.target.checked; saveSettings(); render(); } });
// Broken preview images disappear; broken favicons fall back to initials.
document.addEventListener('error', e => {
  const t = e.target; if (!(t instanceof HTMLImageElement)) return;
  if (t.closest('.thumb')) { const a = t.closest('.thumb'); a.closest('.story')?.classList.remove('has-thumb'); a.remove(); }
  else if (t.classList.contains('favicon')) { const sp = document.createElement('span'); sp.className = 'avatar'; sp.style.setProperty('--h', t.dataset.hue); sp.textContent = t.dataset.ini; t.replaceWith(sp); }
  else if (t.classList.contains('flag')) t.remove();
}, true);
document.addEventListener('change', e => { if (e.target.id === 'hide-read') { state.hideRead = e.target.checked; store.set('hideRead', state.hideRead); state.shown = PAGE; render(); } });

// tooltip for charts
const tip = $('#tip');
document.addEventListener('pointermove', e => {
  const t = e.target.closest('[data-tip]');
  if (!t) { tip.hidden = true; return; }
  tip.textContent = t.dataset.tip; tip.hidden = false;
  const w = tip.offsetWidth; tip.style.left = Math.min(innerWidth - w - 8, e.clientX + 12) + 'px'; tip.style.top = (e.clientY - 34) + 'px';
});

// keyboard
function focusCard(i) {
  const cards = $$('#view .story'); if (!cards.length) return;
  state.focus = Math.max(0, Math.min(cards.length - 1, i));
  cards.forEach(c => c.classList.remove('focused'));
  const c = cards[state.focus]; c.classList.add('focused'); c.scrollIntoView({ block: 'center', behavior: 'smooth' });
}
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); return; }
  if (e.target.matches?.('input, textarea, select') || e.metaKey || e.ctrlKey || e.altKey) return;
  const card = $$('#view .story')[state.focus];
  if (e.key === '/') { e.preventDefault(); $('#q').focus(); $('#q').select(); }
  else if (e.key === 'Escape') { if ($('.menu')) closeMenus(); else if ($('.help')) $('.help').remove(); else closeDrawer(); }
  else if (e.key === 'j') focusCard(state.focus + 1);
  else if (e.key === 'k') focusCard(state.focus - 1);
  else if ((e.key === 'o' || e.key === 'Enter') && card) { const a = $('h3 a', card); if (a) { markRead(card.dataset.id); open(a.href, '_blank', 'noopener'); } }
  else if (e.key === 's' && card) $('[data-save]', card)?.click();
  else if (e.key === '?') showHelp();
  else if (/^[1-9]$/.test(e.key)) setTab(TABS[+e.key - 1].id);
});
function showHelp() {
  if ($('.help')) return;
  const div = document.createElement('div'); div.className = 'help';
  div.innerHTML = `<div role="dialog" aria-modal="true" aria-label="Help"><h2 style="margin-top:0">Shortcuts & search</h2><table>
    <tr><td><kbd>/</kbd></td><td>Search</td></tr><tr><td><kbd>j</kbd> <kbd>k</kbd></td><td>Next / previous story</td></tr>
    <tr><td><kbd>o</kbd></td><td>Open story</td></tr><tr><td><kbd>s</kbd></td><td>Save / unsave story</td></tr>
    <tr><td><kbd>1</kbd>–<kbd>9</kbd></td><td>Switch tab</td></tr><tr><td><kbd>Esc</kbd></td><td>Close / clear</td></tr></table>
    <h3>Search examples</h3><table>
    <tr><td><code>CVE-2026-1234</code></td><td>A CVE (Enter opens its details)</td></tr>
    <tr><td><code>citrix netscaler</code></td><td>All words must match</td></tr><tr><td><code>"data breach"</code></td><td>Exact phrase</td></tr>
    <tr><td><code>actor:lazarus</code></td><td>Threat actor (aliases resolved)</td></tr><tr><td><code>vendor:fortinet</code></td><td>Vendor</td></tr>
    <tr><td><code>source:"the record"</code></td><td>One outlet</td></tr><tr><td><code>tag:zeroday</code></td><td>Tag</td></tr><tr><td><code>attack:T1190</code></td><td>ATT&amp;CK technique</td></tr></table>
    <p><button class="save" data-close-help>Close</button></p></div>`;
  div.addEventListener('click', ev => { if (ev.target === div || ev.target.dataset.closeHelp !== undefined) div.remove(); });
  document.body.append(div); $('button', div).focus();
}
$('#help-btn').addEventListener('click', showHelp);
addEventListener('hashchange', () => { const m = location.hash.match(/^#(CVE-\d{4}-\d+)$/i); if (m) openCve(m[1]); });

// ---------- auto refresh ----------
async function checkForUpdates() {
  try {
    const n = await getJSON('news.json', true);
    if (n.generated === D.news.generated) return;
    const fresh = n.stories.filter(s => !byId.has(s.id) && !s.b && !s.so).length;
    const oldNews = D.news, oldCves = D.cves;
    await loadAll(true);            // data is swapped now; the view refreshes when convenient
    notifyChanges(oldNews, oldCves); syncSwState(); updateStatus();
    const apply = () => { $('#new-pill').hidden = true; render(); };
    if (!fresh || (scrollY < 200 && !document.activeElement?.matches('input') && !$('#drawer-root').innerHTML)) { apply(); return; }
    const pill = $('#new-pill'); pill.textContent = `↑ ${fresh} new ${fresh > 1 ? 'stories' : 'story'}`; pill.hidden = false;
    pill.onclick = () => { apply(); scrollTo({ top: 0, behavior: 'smooth' }); };
  } catch {}
}
setInterval(checkForUpdates, 5 * 60 * 1000);
document.addEventListener('visibilitychange', () => { if (!document.hidden && D.news && Date.now() - D.news.generated > 10 * 60 * 1000) checkForUpdates(); });
setInterval(() => { if (!document.hidden) $$('time[datetime]').forEach(t => { t.textContent = fmtAgo(Date.parse(t.getAttribute('datetime'))); }); updateStatus(); }, 60 * 1000);

function updateStatus() {
  if (!D.news) return;
  const src = D.sources.sources || [];
  const fed = src.filter(s => s.feed), ok = fed.filter(s => s.ok);
  $('#gen-status').innerHTML = `Updated ${fmtAgo(D.news.generated)} (${esc(fmtFull(D.news.generated))}) · ${ok.length}/${fed.length} feeds OK${fed.length - ok.length ? ` · <button class="linkish" data-tab-go="sources">${fed.length - ok.length} failing</button>` : ''}`;
  $('#src-count').textContent = fed.length;
}

// ---------- boot ----------
(async () => {
  try { D.config = await (await fetch('config.json')).json(); } catch {}
  hideSections(D.config.hide);
  if (D.config.repoUrl) $('#repo-links').innerHTML = ` · <a href="${url(D.config.repoUrl)}" target="_blank" rel="noopener">Source code</a> · <a href="${url(D.config.repoUrl)}/issues/new" target="_blank" rel="noopener">Report a wrong tag or broken source</a>`;
  if (D.config.buttondownUser) { $('#newsletter').hidden = false; $('#nl-form').action = `https://buttondown.com/api/emails/embed-subscribe/${encodeURIComponent(D.config.buttondownUser)}`; }
  $('#q').value = state.q; $('#q-clear').hidden = !state.q; $('#kbd-slash').hidden = !!state.q;
  renderTabs();
  try { await loadAll(); }
  catch (e) { $('#view').innerHTML = `<div class="empty">Couldn't load the news data (${esc(e.message)}). If you're running this yourself, run <code>node build.js</code> first.</div>`; return; }
  try { D.otd = await (await fetch('onthisday.json')).json(); } catch {}
  render(); updateStatus();
  const m = location.hash.match(/^#(CVE-\d{4}-\d+)$/i); if (m) openCve(m[1]);
  if ('serviceWorker' in navigator && location.protocol.startsWith('http')) navigator.serviceWorker.register('sw.js').then(() => { syncSwState(); if (settings.notify.on) registerPeriodicSync(); }).catch(() => {});
  if (D.config.goatcounter) { const g = document.createElement('script'); g.async = true; g.src = 'https://gc.zgo.at/count.js'; g.dataset.goatcounter = `https://${D.config.goatcounter}.goatcounter.com/count`; document.head.append(g); }
})();
})();
