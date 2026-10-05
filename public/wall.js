// Wall display: a read-only dashboard for a screen that stays on all day.
// Fetches the same data files as the main site every few minutes, without reloading the page,
// and each vendor's public status page every few minutes straight from the browser.
// URL options: ?theme=light   ?rotate=15 (seconds per top story)   ?stack=1 (only your products, from Settings → My stack)
(() => {
'use strict';
const $ = s => document.querySelector(s);
const MIN = 6e4, HOUR = 36e5, DAY = 864e5;
const params = new URLSearchParams(location.search);
const ROTATE = Math.max(6, Number(params.get('rotate')) || 15) * 1000;
const REFRESH = 5 * MIN;          // data files change about every 30 minutes
const STATUS_EVERY = 3 * MIN;     // vendor status pages
const RELOAD = 6 * HOUR;          // pick up new versions of the page itself
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const ago = t => { const m = Math.max(0, Math.round((Date.now() - t) / MIN)); return m < 1 ? 'now' : m < 60 ? `${m}m` : m < 1440 ? `${Math.round(m / 60)}h` : `${Math.round(m / 1440)}d`; };
const num = n => n.toLocaleString();
const clip = (s, n) => { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n).replace(/\s+\S*$/, '') + '…' : s; };
const D = {};
let lastOk = 0, generated = 0, spotIdx = 0, spotTimer = 0;

// ---------- "My stack" (shared with the main site's Settings) ----------
const settings = (() => { try { return JSON.parse(localStorage.getItem('cih.settings')) || {}; } catch { return {}; } })();
const stack = { vendors: settings.stack?.vendors || [], keywords: (settings.stack?.keywords || []).filter(Boolean).map(k => k.toLowerCase()) };
const stackMode = params.get('stack') === '1';
const hasStack = stack.vendors.length + stack.keywords.length > 0;
const isMine = s => s.ve.some(v => stack.vendors.includes(v)) || stack.keywords.some(k => `${s.t} ${s.x || ''}`.toLowerCase().includes(k));
const kevMine = k => stack.vendors.some(v => k.v.toLowerCase().includes(v.toLowerCase()) || v.toLowerCase().includes(k.v.toLowerCase())) || stack.keywords.some(w => `${k.v} ${k.p} ${k.n}`.toLowerCase().includes(w));

// ---------- theme, clock, controls ----------
const theme = params.get('theme') || (() => { try { return localStorage.getItem('cih.wallTheme'); } catch { return null; } })();
if (theme === 'light') document.documentElement.dataset.theme = 'light';
function toggleTheme() {
  const light = document.documentElement.dataset.theme !== 'light';
  if (light) document.documentElement.dataset.theme = 'light'; else delete document.documentElement.dataset.theme;
  try { localStorage.setItem('cih.wallTheme', light ? 'light' : 'dark'); } catch {}
}
function tick() {
  const now = new Date();
  $('#clock').textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  $('#date').textContent = `${now.toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' })} · UTC ${now.toISOString().slice(11, 16)}`;
}
function freshness() {
  if (!generated) return;
  const age = Date.now() - generated, offline = Date.now() - lastOk > 15 * MIN;
  $('#live').className = 'live' + (offline ? ' down' : age > 90 * MIN ? ' stale' : '');
  $('#live-txt').textContent = offline ? 'OFFLINE' : age > 90 * MIN ? 'DELAYED' : 'LIVE';
  $('#fresh').innerHTML = `Data updated ${ago(generated)} ago${stackMode ? ` <span class="stackbar">My stack${hasStack ? `: ${esc(clip([...stack.vendors, ...stack.keywords].join(', '), 50))}` : ' (none set)'}</span>` : ''}`;
  const b = $('#banner');
  b.hidden = !offline;
  if (offline) b.textContent = `Can't reach the site — showing data from ${new Date(generated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
}
$('#b-full').onclick = () => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen?.().catch(() => {});
$('#b-theme').onclick = toggleTheme;
addEventListener('keydown', e => { if (e.key === 'f' || e.key === 'F') $('#b-full').click(); if (e.key === 't' || e.key === 'T') toggleTheme(); });
// Hide the cursor and buttons when the mouse is still.
let idleT; const wake = () => { document.body.classList.remove('idle'); clearTimeout(idleT); idleT = setTimeout(() => document.body.classList.add('idle'), 4000); };
addEventListener('mousemove', wake); wake();

// Keep the screen on where the browser allows it (re-requested after the tab becomes visible again).
let lock = null;
async function keepAwake() { try { if (navigator.wakeLock && document.visibilityState === 'visible' && !lock) { lock = await navigator.wakeLock.request('screen'); lock.addEventListener('release', () => { lock = null; }); } } catch {} }
document.addEventListener('visibilitychange', keepAwake);
addEventListener('click', keepAwake);

// Burn-in protection: nudge the whole layout by a couple of pixels every few minutes.
setInterval(() => { const x = Math.round(Math.random() * 4 - 2), y = Math.round(Math.random() * 4 - 2); $('#wall').style.transform = `translate(${x}px, ${y}px)`; }, 4 * MIN);

// ---------- data ----------
async function getJSON(f) { const r = await fetch(`data/${f}`, { cache: 'no-cache' }); if (!r.ok) throw new Error(`${f}: ${r.status}`); return r.json(); }
async function load() {
  try {
    const [news, cves, rw, inc] = await Promise.all([getJSON('news.json'), getJSON('cves.json'), getJSON('ransomware.json').catch(() => null), getJSON('incidents.json').catch(() => null)]);
    if (!D.world) D.world = await getJSON('world.json').catch(() => null);
    Object.assign(D, { news, cves, rw, inc });
    generated = news.generated; lastOk = Date.now();
    render();
  } catch (e) { console.warn('Wall: refresh failed', e); }
  freshness();
}

// ---------- rendering helpers ----------
const TAGS = [['zeroday', 'Zero-day', 'b-zd'], ['breach', 'Breach', 'b-breach'], ['ransomware', 'Ransomware', 'b-rw']];
const badges = s => {
  const out = TAGS.filter(([t]) => s.tg.includes(t)).map(([, l, c]) => `<span class="badge ${c}">${l}</span>`);
  if (s.cv.some(c => D.cves.kevIndex?.[c])) out.push('<span class="badge b-kev">KEV</span>');
  if (s.r.length) out.push(`<span class="badge b-n">${s.r.length + 1} outlets</span>`);
  return out.join('');
};
const isNew = s => Date.now() - (s.f || s.d) < 45 * MIN;
const allStories = () => D.news.stories.filter(s => !s.b && !s.so);
const stories = () => stackMode ? allStories().filter(isMine) : allStories();
const kevList = () => (D.cves.kev || []).filter(k => !stackMode || kevMine(k));

// ---------- panels ----------
function renderKpis() {
  const day = stories().filter(s => Date.now() - s.d < DAY);
  const kev7 = kevList().filter(k => Date.now() - Date.parse(k.d + 'T23:59:59Z') < 7 * DAY).length;
  const rw24 = D.rw ? D.rw.recent.filter(v => Date.now() - v.d < DAY).length : null;
  const zd = day.filter(s => s.tg.includes('zeroday')).length;
  const k = [
    [num(day.length), 'stories · 24h'],
    [num(zd), 'zero-days', zd > 0],
    [num(day.filter(s => s.tg.includes('breach')).length), 'breaches'],
    ...(stackMode ? [] : [[rw24 == null ? '—' : num(rw24), 'ransomware']]),
    [num(kev7), 'new KEV · 7d', kev7 > 0],
  ];
  $('#kpis').innerHTML = k.map(([v, l, hot]) => `<div class="kpi${hot ? ' hot' : ''}"><b>${v}</b><span>${l}</span></div>`).join('');
}

function renderLatest() {
  const list = stories().slice().sort((a, b) => b.d - a.d).slice(0, 18);
  $('#latest').innerHTML = list.map(s => `<li class="${isNew(s) ? 'new' : ''}"><span class="age">${ago(s.d)}</span>
    <span class="src">${esc(s.s)} ${isNew(s) ? '<span class="badge b-new">New</span>' : ''}${badges(s)}</span>
    <span class="t">${esc(s.t)}</span></li>`).join('') || `<li class="empty">${stackMode ? (hasStack ? 'No recent stories about your products.' : 'Pick your products in Settings → My stack on the main site.') : 'No stories yet.'}</li>`;
  $('#latest-n').textContent = `${stories().filter(s => Date.now() - s.d < DAY).length} in 24 h`;
}

function spotlightList() {
  const day = stories().filter(s => Date.now() - s.d < DAY);
  const top = day.slice().sort((a, b) => b.r.length - a.r.length || b.d - a.d).slice(0, 6);
  return top.length ? top : stories().slice().sort((a, b) => b.d - a.d).slice(0, 6);
}
function renderSpot() {
  const list = spotlightList(); if (!list.length) { $('#spot').innerHTML = '<p class="empty">No stories yet.</p>'; return; }
  spotIdx %= list.length;
  const s = list[spotIdx], info = D.cves.info || {};
  const cves = s.cv.slice(0, 4).map(c => { const i = info[c] || {}; return `<span class="cvechip">${c}${i.s != null ? `<b class="sev ${esc(i.v)}">${i.s}</b>` : ''}</span>`; }).join('');
  const dev = (D.inc?.incidents || []).slice().sort((a, b) => b.last - a.last)[0];
  $('#spot').innerHTML = `<div class="slide">
      <span class="kicker">${s.r.length ? `Covered by ${s.r.length + 1} outlets` : 'Top story'} · ${ago(s.d)} ago</span>
      ${s.im && /^https?:\/\//.test(s.im) ? `<img class="img" src="${esc(s.im)}" alt="" referrerpolicy="no-referrer" onerror="this.remove()">` : ''}
      <h3>${esc(s.t)}</h3>
      ${s.x ? `<p>${esc(clip(s.x, 320))}</p>` : ''}
      <div class="meta">${esc(s.s)}${s.r.length ? ` · ${esc(s.r.slice(0, 3).map(r => r[0]).join(', '))}${s.r.length > 3 ? ` +${s.r.length - 3}` : ''}` : ''}</div>
      ${cves ? `<div class="chips">${cves}</div>` : ''}
    </div>
    <div class="dots" style="--rot:${ROTATE}ms">${list.map((_, i) => `<i class="${i === spotIdx ? 'on' : ''}"></i>`).join('')}</div>
    ${dev && !stackMode ? `<div class="dev">Developing: <b>${esc(dev.title)}</b> · ${dev.n} updates · latest ${ago(dev.last)} ago</div>` : ''}`;
}
function rotateSpot() { clearInterval(spotTimer); spotTimer = setInterval(() => { spotIdx++; renderSpot(); }, ROTATE); }

// Newly exploited (KEV) and zero-days share one panel and alternate every 20 seconds.
function renderKev() {
  const info = D.cves.info || {}, list = kevList().slice(0, 8);
  $('#kev').innerHTML = list.map(k => { const i = info[k.id] || {}; return `<li><div class="l1">${k.id}${i.s != null ? `<span class="sev ${esc(i.v)}">${i.s}</span>` : ''}${k.rw ? '<span class="badge b-rw">Ransomware</span>' : ''}<span class="when">${esc(new Date(k.d + 'T12:00:00Z').toLocaleDateString([], { month: 'short', day: 'numeric' }))}</span></div>
    <div class="l2">${esc(k.v)} ${esc(k.p)}: ${esc(k.n.replace(new RegExp(`^${k.v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s+`, 'i'), ''))}</div></li>`; }).join('') || '<li class="empty">No recent entries.</li>';
}
function renderZd() {
  const list = stories().filter(s => s.tg.includes('zeroday') && Date.now() - s.d < 3 * DAY).sort((a, b) => b.r.length - a.r.length || b.d - a.d).slice(0, 8);
  $('#zd').innerHTML = list.map(s => `<li><div class="l1"><span style="color:var(--muted)">${esc(s.s)}</span>${s.r.length ? `<span class="badge b-n">${s.r.length + 1} outlets</span>` : ''}${s.cv.slice(0, 2).map(c => `<span>${c}</span>`).join('')}<span class="when">${ago(s.d)}</span></div><div class="l2">${esc(s.t)}</div></li>`).join('') || '<li class="empty">Nothing flagged in the last 72 hours.</li>';
}
let expPane = 'kev';
function showPane(p) {
  expPane = p;
  $('#kev').hidden = p !== 'kev'; $('#zd').hidden = p !== 'zd';
  document.querySelectorAll('.p-exp [data-pane]').forEach(el => el.classList.toggle('on', el.dataset.pane === p));
  const dots = [...document.querySelectorAll('#exp-dots i')];
  dots.forEach(d => d.classList.remove('on')); void $('#exp-dots').offsetWidth;   // restart the progress animation
  dots[p === 'kev' ? 0 : 1].classList.add('on');
  const week = kevList().filter(k => Date.now() - Date.parse(k.d + 'T23:59:59Z') < 7 * DAY).length;
  $('#exp-n').textContent = p === 'kev' ? `${week} this week` : `${stories().filter(s => s.tg.includes('zeroday') && Date.now() - s.d < 3 * DAY).length} stories`;
  requestAnimationFrame(fit);
}
setInterval(() => showPane(expPane === 'kev' ? 'zd' : 'kev'), 20000);

// ---------- attack map ----------
const region = (() => { try { return new Intl.DisplayNames(['en'], { type: 'region' }); } catch { return null; } })();
let nameToCode = null;
function countryCode(name) {
  if (!nameToCode) {
    nameToCode = { uae: 'AE', usa: 'US', us: 'US', uk: 'GB', 'united states of america': 'US', 'south korea': 'KR', korea: 'KR', russia: 'RU', 'czech republic': 'CZ', turkey: 'TR', 'türkiye': 'TR', taiwan: 'TW', vietnam: 'VN', 'hong kong': 'HK' };
    for (const c of Object.keys(D.world?.centers || {})) { const n = region?.of(c); if (n) nameToCode[n.toLowerCase()] = c; }
  }
  return nameToCode[String(name).toLowerCase().trim()] || null;
}
// Small, stable offset per event so several attacks in one country don't sit on the same pixel.
const jitter = (key, r) => { let h = 0; for (const ch of key) h = (h * 31 + ch.charCodeAt(0)) | 0; return [((h & 255) / 255 - 0.5) * r, (((h >> 8) & 255) / 255 - 0.5) * r]; };
let mapEvents = [], mapIdx = 0;
function renderMap() {
  const W = D.world; if (!W) { $('#map').innerHTML = '<p class="empty">Map unavailable.</p>'; return; }
  const since = Date.now() - 3 * DAY, ev = [];
  if (!stackMode) for (const v of D.rw?.recent || []) if (v.d > since && v.c && W.centers[v.c]) ev.push({ k: 'rw', c: v.c, d: v.d, who: v.g, what: v.t, where: v.x || region?.of(v.c) || v.c });
  for (const s of stories()) {
    if (s.s !== 'Hackmanac Alerts' || s.d < since) continue;
    const m = s.t.match(/\(([^)]{2,40})\)/); const c = m && countryCode(m[1]);
    if (c && W.centers[c]) ev.push({ k: 'hm', c, d: s.d, who: 'Hackmanac', what: s.t, where: region?.of(c) || m[1] });
  }
  ev.sort((a, b) => b.d - a.d);
  mapEvents = ev.slice(0, 120);
  // Shade countries by the last 7 days of ransomware claims.
  const counts = Object.fromEntries(D.rw?.countries7 || []), max = Math.max(1, ...Object.values(counts));
  const tier = c => { const n = counts[c]; if (!n) return ''; const r = n / max; return r > 0.5 ? 't4' : r > 0.2 ? 't3' : r > 0.07 ? 't2' : 't1'; };
  const land = Object.entries(W.paths).map(([c, d]) => `<path class="land ${tier(c)}" d="${d}"><title>${esc(region?.of(c) || c)}${counts[c] ? `: ${counts[c]} claims in 7 days` : ''}</title></path>`).join('');
  const dots = mapEvents.slice().reverse().map((e, i) => { const [x, y] = W.centers[e.c], [dx, dy] = jitter(e.what, 14); return `<circle class="p ${e.k}${Date.now() - e.d < 6 * HOUR ? ' fresh' : ''}" cx="${(x + dx).toFixed(1)}" cy="${(y + dy).toFixed(1)}" r="${Date.now() - e.d < 6 * HOUR ? 5.5 : 3.8}"/>`; }).join('');
  $('#map').innerHTML = `<svg viewBox="0 0 ${W.w} ${W.h}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="World map of recent attacks">${land}<g>${dots}</g><g id="map-ring"></g></svg>`;
  const rwN = mapEvents.filter(e => e.k === 'rw').length, hmN = mapEvents.length - rwN;
  $('#map-n').textContent = stackMode ? `${hmN} alerts` : `${rwN} claims · ${hmN} alerts`;
  mapIdx = 0; spotlightEvent();
}
// Every few seconds, highlight one of the newest attacks with a ring and a caption.
function spotlightEvent() {
  const W = D.world, list = mapEvents.slice(0, 12); if (!W || !list.length) { $('#map-cap').innerHTML = '<span class="empty">No attacks recorded in the last 72 hours.</span>'; return; }
  const e = list[mapIdx % list.length]; mapIdx++;
  const [x, y] = W.centers[e.c], [dx, dy] = jitter(e.what, 14);
  const ring = $('#map-ring'); if (ring) ring.innerHTML = `<circle class="ring" cx="${(x + dx).toFixed(1)}" cy="${(y + dy).toFixed(1)}" r="5"/>`;
  $('#map-cap').innerHTML = `<b style="color:${e.k === 'rw' ? 'var(--violet)' : 'var(--accent)'}">${esc(e.who)}</b>${e.k === 'rw' ? `claimed <strong>${esc(e.what)}</strong>` : esc(e.what.replace(/\s*\([^)]*\)/, ''))} · ${esc(e.where)}<span class="when">${ago(e.d)} ago</span>`;
}
setInterval(spotlightEvent, 6000);

// ---------- vendor status ----------
// Public Statuspage endpoints (they allow cross-site reads). Palo Alto's page covers Cortex, Prisma Access and Cloud NGFW.
const VENDORS = [
  { n: 'Palo Alto Networks', sub: 'Cortex · Prisma · NGFW', host: 'status.paloaltonetworks.com', match: ['Palo Alto Networks'] },
  { n: 'Fortinet', sub: 'FortiCloud', host: 'status.forticloud.com', match: ['Fortinet'] },
  { n: 'Check Point', sub: 'Infinity', host: 'status.checkpoint.com', match: ['Check Point'] },
  { n: 'SentinelOne', host: 'status.sentinelone.com', match: ['SentinelOne'] },
  { n: 'Cisco Duo', host: 'status.duo.com', match: ['Cisco', 'Duo'] },
  { n: 'Cloudflare', host: 'www.cloudflarestatus.com', match: ['Cloudflare'] },
  { n: 'Tenable', host: 'status.tenable.com', match: ['Tenable'] },
  { n: 'Rapid7', host: 'status.rapid7.com', match: ['Rapid7'] },
  { n: 'Qualys', host: 'status.qualys.com', match: ['Qualys'] },
  { n: 'Wiz', host: 'status.wiz.io', match: ['Wiz'] },
  { n: 'Imperva', host: 'status.imperva.com', match: ['Imperva', 'Thales'] },
];
const SEV = { critical: 4, major: 3, minor: 2, maint: 1, none: 0, unknown: -1 };
const vMine = v => v.match.some(m => stack.vendors.some(s => s.toLowerCase() === m.toLowerCase()));
async function vendorStatus(v) {
  try {
    const r = await fetch(`https://${v.host}/api/v2/summary.json`, { signal: AbortSignal.timeout(15000), cache: 'no-cache' });
    if (!r.ok) throw new Error(r.status);
    const j = await r.json();
    const comps = j.components || [], byId = Object.fromEntries(comps.map(c => [c.id, c]));
    const open = (j.incidents || []).filter(i => !['resolved', 'postmortem'].includes(i.status));
    const maint = (j.scheduled_maintenances || []).filter(m => m.status === 'in_progress');
    // Affected products: the top-level groups of components that aren't operational.
    const affected = [...new Set(comps.filter(c => c.status !== 'operational' && !c.group).map(c => (byId[c.group_id] || c).name))];
    let s = j.status?.indicator || 'none';
    if (s === 'maintenance' || (s === 'none' && maint.length)) s = 'maint';
    return { ...v, s, label: j.status?.description || 'Unknown', inc: open[0]?.name || maint[0]?.name || '', more: Math.max(0, open.length - 1), affected, ok: true };
  } catch { return { ...v, s: 'unknown', label: 'Status unavailable', inc: '', more: 0, affected: [], ok: false }; }
}
let statusAt = 0;
async function loadStatus() {
  const list = await Promise.all(VENDORS.filter(v => !stackMode || !hasStack || vMine(v)).map(vendorStatus));
  list.sort((a, b) => SEV[b.s] - SEV[a.s] || vMine(b) - vMine(a) || a.n.localeCompare(b.n));
  statusAt = Date.now();
  const short = { none: 'Operational', minor: 'Degraded', major: 'Outage', critical: 'Major outage', maint: 'Maintenance', unknown: 'Unavailable' };
  $('#status').innerHTML = list.map(v => `<li class="s-${v.s}" title="${esc(v.label)}"><span class="sd"></span>
      <span class="nm"><a href="https://${v.host}" target="_blank" rel="noopener">${vMine(v) ? '<span class="mine">★ </span>' : ''}${esc(v.n)}</a>${v.sub ? `<small>${esc(v.sub)}</small>` : ''}</span>
      <span class="st">${short[v.s]}</span>
      ${v.inc || v.affected.length ? `<span class="inc">${esc(v.inc)}${v.more ? ` <em>+${v.more} more</em>` : ''}${v.affected.length ? ` <em>· ${esc(clip(v.affected.slice(0, 3).join(', '), 70))}</em>` : ''}</span>` : ''}</li>`).join('')
    || '<li class="empty">None of your vendors have a public status page here.</li>';
  const issues = list.filter(v => SEV[v.s] >= 2).length;
  $('#status-n').textContent = `${issues ? `${issues} with issues · ` : 'all operational · '}checked ${ago(statusAt) === 'now' ? 'just now' : ago(statusAt) + ' ago'}`;
  requestAnimationFrame(fit);
}

function renderTicker() {
  const list = stories().slice().sort((a, b) => b.d - a.d).slice(0, 24);
  const items = list.map(s => `<span><b>${esc(s.s)}</b>${esc(s.t)}</span>`).join('');
  const run = $('#ticker');
  run.innerHTML = items + items;                       // two copies for a seamless loop
  run.style.setProperty('--dur', `${Math.max(60, list.length * 7)}s`);
}

// Show only the rows that fit completely, so no panel ends with a half-cut line.
function fit() {
  for (const ul of document.querySelectorAll('.grid .list')) {
    if (ul.hidden) continue;
    const items = [...ul.children];
    items.forEach(li => { li.hidden = false; });
    if (getComputedStyle(ul).overflow !== 'hidden' || !ul.clientHeight) continue;   // stacked layout on small screens scrolls instead
    const limit = ul.getBoundingClientRect().bottom + 1;
    items.forEach((li, i) => { if (i > 0 && li.getBoundingClientRect().bottom > limit) li.hidden = true; });
  }
}
addEventListener('resize', () => requestAnimationFrame(fit));
document.fonts?.ready.then(() => requestAnimationFrame(fit));      // web fonts change line heights

function render() {
  for (const f of [renderKpis, renderLatest, renderSpot, renderKev, renderZd, renderMap, renderTicker]) { try { f(); } catch (e) { console.warn('Wall:', f.name, e); } }
  showPane(expPane);
}

// Relative times ("12m") keep counting between refreshes.
function refreshAges() {
  if (D.news) { renderLatest(); renderKpis(); requestAnimationFrame(fit); }
  if (statusAt) $('#status-n').textContent = $('#status-n').textContent.replace(/checked .*$/, `checked ${ago(statusAt) === 'now' ? 'just now' : ago(statusAt) + ' ago'}`);
  freshness();
}

tick(); setInterval(tick, 1000);
load().then(() => { rotateSpot(); keepAwake(); });
loadStatus(); setInterval(loadStatus, STATUS_EVERY);
setInterval(load, REFRESH);
setInterval(refreshAges, MIN);
// Reload only while the site is reachable, so a screen that lost its network keeps showing the last data.
setInterval(() => { if (performance.now() > RELOAD && Date.now() - lastOk < 10 * MIN) location.reload(); }, 10 * MIN);
})();
