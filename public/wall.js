// Wall display: a read-only dashboard for a screen that stays on all day.
// Fetches the same data files as the main site every few minutes, without reloading the page,
// URL options: ?theme=light   ?rotate=15 (seconds per top story)   ?stack=1 (only your products, from Settings → My stack)
(() => {
'use strict';
const $ = s => document.querySelector(s);
const MIN = 6e4, HOUR = 36e5, DAY = 864e5;
const params = new URLSearchParams(location.search);
const ROTATE = Math.max(6, Number(params.get('rotate')) || 15) * 1000;
const REFRESH = 5 * MIN;          // data files change about every 30 minutes
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
  $('#live').title = `News data updated ${ago(generated) === 'now' ? 'just now' : ago(generated) + ' ago'}`;
  $('#fresh').innerHTML = stackMode ? `<span class="stackbar" title="${esc([...stack.vendors, ...stack.keywords].join(', '))}">My stack${hasStack ? '' : ' (none set)'}</span>` : '';
  const b = $('#banner');
  b.hidden = !offline;
  if (offline) b.textContent = `Can't reach the site — showing data from ${new Date(generated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
}
$('#b-full').onclick = () => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen?.().catch(() => {});
$('#b-theme').onclick = toggleTheme;
addEventListener('keydown', e => { if (e.key === 'f' || e.key === 'F') $('#b-full').click(); if (e.key === 't' || e.key === 'T') toggleTheme(); });
// Zoom: - / + / 0 (or ?zoom=0.9). Remembered on this screen.
let zoom = Number(params.get('zoom')) || (() => { try { return Number(localStorage.getItem('cih.wallZoom')) || 1; } catch { return 1; } })();
function setZoom(z) {
  zoom = Math.min(1.6, Math.max(0.6, Math.round(z * 100) / 100));
  document.documentElement.style.setProperty('--zoom', zoom);
  try { localStorage.setItem('cih.wallZoom', zoom); } catch {}
  requestAnimationFrame(fit);
}
setZoom(zoom);
addEventListener('keydown', e => {
  if (e.ctrlKey || e.metaKey || e.altKey) return;            // leave the browser's own Ctrl +/- alone
  if (e.key === '-' || e.key === '_') setZoom(zoom - 0.05);
  else if (e.key === '+' || e.key === '=') setZoom(zoom + 0.05);
  else if (e.key === '0') setZoom(1);
});
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
  if (s.r.length > 1) out.push(`<span class="badge b-n">${s.r.length + 1} outlets</span>`);
  return out.slice(0, isNew(s) ? 1 : 2).join('');
};
const isNew = s => Date.now() - (s.f || s.d) < 45 * MIN;
const allStories = () => D.news.stories.filter(s => !s.b && !s.so);
const stories = () => stackMode ? allStories().filter(isMine) : allStories();
const kevList = () => (D.cves.kev || []).filter(k => !stackMode || kevMine(k));

// ---------- panels ----------
// ---------- Hackmanac: weekly Hack Tuesday count (strip) and attack alerts (panel) ----------
const hmAll = () => allStories().filter(s => s.s === 'Hackmanac Alerts').sort((a, b) => b.d - a.d);
const hmAlerts = () => hmAll().filter(s => !/^Hack Tuesday/i.test(s.t));
function renderStrip() {
  // The Bluesky post is usually merged with Hackmanac's own website report of the same week, so it can
  // sit among a story's other outlets (r: [source, title, link, date]) rather than be the story itself.
  const ht = allStories().flatMap(s => [{ t: s.t, u: s.u, d: s.d }, ...s.r.map(r => ({ t: r[1], u: r[2], d: r[3] }))])
    .filter(x => /^Hack Tuesday \(/.test(x.t)).sort((a, b) => b.d - a.d)[0];
  const m = ht && ht.t.match(/^Hack Tuesday \(([^)]+)\): ([\d,.]+) cyber attacks across (\d+) countries/);
  const all = hmAlerts(), recent = all.filter(s => Date.now() - s.d < 7 * DAY);
  const week = recent.length, day = all.filter(s => Date.now() - s.d < DAY).length;
  const countries = new Set(recent.map(alertCountry).filter(Boolean)).size;
  const parts = [];
  if (m) parts.push(`<span class="h">Hack Tuesday</span><a href="${esc(ht.u)}" target="_blank" rel="noopener"><span class="k">${esc(m[1])}</span> <span class="k"><span class="big">${esc(m[2])}</span> verified cyber attacks across <b>${esc(m[3])}</b> countries</span></a>`);
  parts.push(`<span class="k">alerts posted this week <b>${num(week)}</b>${countries ? ` in ${countries} countr${countries === 1 ? 'y' : 'ies'}` : ''}</span>`);
  $('#kpis').innerHTML = parts.join('<span class="sep">·</span>') + '<span class="src">Source: Hackmanac</span>';
  $('#kpis').title = "Hack Tuesday is Hackmanac's weekly count of verified cyber attacks worldwide.";
}
// Alert titles look like "Victim (Country): what happened"; the bold part can also be a whole headline.
const boldActor = t => esc(t).replace(/^([A-Z][\w.&' -]{1,40}?)( hacking group| ransomware group| ransomware| group)? (claims|claimed)/, '<b>$1$2</b> $3');
// One line per alert (flag · victim · attacker · age) so a full feed fits; the whole alert is in the tooltip.
function renderAlerts() {
  const all = hmAlerts(), list = all.slice(0, 16);
  $('#alerts').innerHTML = list.map(s => {
    const m = s.t.match(/^(.+?) \(([^)]{2,40})\)(?::\s*(.*))?$/);
    const who = m ? m[1] : s.t, where = m ? m[2] : '';
    const c = alertCountry(s), country = (c && region?.of(c)) || where;
    const actor = actorOf(s.t);
    const flag = c ? `<img src="flags/${c.toLowerCase()}.svg" alt="" onerror="this.style.visibility='hidden'">` : '<span></span>';
    return `<li class="${isNew(s) ? 'new' : ''}" title="${esc(s.t)}${country ? ` · ${esc(country)}` : ''}">${flag}
      <span class="who">${esc(who)}${actor ? `<small>${esc(actor)}</small>` : country ? `<small>${esc(country)}</small>` : ''}</span><span class="when">${isNew(s) ? 'NEW · ' : ''}${ago(s.d)}</span></li>`;
  }).join('') || '<li class="empty">No alerts yet.</li>';
  // When Hackmanac last posted, so a quiet panel is clearly quiet at the source, not broken.
  const week = all.filter(s => Date.now() - s.d < 7 * DAY).length;
  $('#alerts-n').textContent = `${week} this week${all[0] ? ` · last post ${ago(all[0].d) === 'now' ? 'just now' : ago(all[0].d) + ' ago'}` : ''}`;
}

function renderLatest() {
  const list = stories().slice().sort((a, b) => b.d - a.d).slice(0, 18);
  $('#latest').innerHTML = list.map(s => `<li class="${isNew(s) ? 'new' : ''}"><span class="age">${ago(s.d)}</span>
    <span class="src">${esc(s.s)} ${isNew(s) ? '<span class="badge b-new">New</span>' : ''}${badges(s)}</span>
    <span class="t">${esc(s.t)}</span></li>`).join('') || `<li class="empty">${stackMode ? (hasStack ? 'No recent stories about your products.' : 'Pick your products in Settings → My stack on the main site.') : 'No stories yet.'}</li>`;
  $('#latest-n').textContent = `${stories().filter(s => Date.now() - s.d < DAY).length} in 24 h`;
}

function spotlightList() {
  // Hackmanac alerts have their own panel, so they are left out of the spotlight.
  const day = stories().filter(s => Date.now() - s.d < DAY && s.s !== 'Hackmanac Alerts');
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
      <span class="kicker">${s.r.length ? `Covered by ${s.r.length + 1} outlets` : 'Top story'} · ${ago(s.d)} ago${cves ? ` <span class="chips">${cves}</span>` : ''}</span>
      ${s.im && /^https?:\/\//.test(s.im) ? `<img class="img" src="${esc(s.im)}" alt="" referrerpolicy="no-referrer" onerror="this.remove()">` : ''}
      <h3>${esc(s.t)}</h3>
      ${s.x ? `<p>${esc(clip(s.x, 320))}</p>` : ''}
      <div class="meta">${esc(s.s)}${s.r.length ? ` · ${esc(s.r.slice(0, 3).map(r => r[0]).join(', '))}${s.r.length > 3 ? ` +${s.r.length - 3}` : ''}` : ''}</div>
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
// The map replays the last 72 hours as a loop: each reported attack streaks in and lands on its country,
// with a ripple and a label, while a playhead moves along a timeline. Only victims' countries are known,
// so the streaks show when an attack was reported, not where it came from.
let mapEvents = [], mapWin = { start: 0, end: 0 }, play = null;
const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
const monthName = () => new Date().toLocaleDateString([], { month: 'long' });
// Hackmanac alert titles end the victim with "(Country)".
const alertCountry = s => { const m = s.t.match(/\(([^)]{2,40})\)/); return m ? countryCode(m[1]) : null; };
// "Qilin hacking group claims…", "The Aur0ra cybercrime group claims…", "LockBit 5.0 claims…" → the attacker's name.
const actorOf = t => { const m = t.match(/^(?:.*?\):\s*)?(?:The\s+)?([A-Z][\w.&' -]{1,40}?)(?: hacking group| cybercrime group| ransomware group| threat group| ransomware| gang| group)? claim/); return m ? m[1] : undefined; };
const victimOf = t => t.replace(/\s*\([^)]*\).*$/, '');
const SVG = 'http://www.w3.org/2000/svg';
const svgEl = (tag, attrs) => { const el = document.createElementNS(SVG, tag); for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v); return el; };

function renderMap() {
  const W = D.world; if (!W) { $('#map').innerHTML = '<p class="empty">Map unavailable.</p>'; return; }
  // Attacks aren't tied to products, so the map always shows global activity (also in My stack mode).
  const collect = since => {
    const ev = [];
    for (const v of D.rw?.recent || []) if (v.d > since && v.c && W.centers[v.c]) ev.push({ k: 'rw', c: v.c, d: v.d, who: v.g, what: v.t });
    for (const s of allStories()) {
      if (s.s !== 'Hackmanac Alerts' || s.d < since || /^Hack Tuesday/i.test(s.t)) continue;
      const c = alertCountry(s);
      if (c && W.centers[c]) ev.push({ k: 'hm', c, d: s.d, who: actorOf(s.t) || 'Attack', what: victimOf(s.t) });
    }
    return ev.sort((a, b) => a.d - b.d);
  };
  let span = 3 * DAY, ev = collect(Date.now() - span);
  if (ev.length < 25) { span = 7 * DAY; ev = collect(Date.now() - span); }   // quiet days: widen to a week
  mapEvents = ev.slice(-180).map((e, i) => { const [x, y] = W.centers[e.c], [dx, dy] = jitter(e.what + e.d, 14); return { ...e, i, x: x + dx, y: y + dy, where: region?.of(e.c) || e.c }; });
  mapWin = { start: Date.now() - span, end: Date.now() };
  $('.p-map h2').firstChild.textContent = `Attacks · last ${span > 3 * DAY ? '7 days' : '72 h'} `;
  const rwN = mapEvents.filter(e => e.k === 'rw').length;
  $('#map-n').textContent = `${rwN} claims · ${mapEvents.length - rwN} alerts`;

  // Countries shaded by the last 7 days of ransomware claims; every attack is a dim dot until the replay reaches it.
  const counts = Object.fromEntries(D.rw?.countries7 || []), max = Math.max(1, ...Object.values(counts));
  const tier = c => { const n = counts[c]; if (!n) return ''; const r = n / max; return r > 0.5 ? 't4' : r > 0.2 ? 't3' : r > 0.07 ? 't2' : 't1'; };
  const land = Object.entries(W.paths).map(([c, d]) => `<path class="land ${tier(c)}" d="${d}"><title>${esc(region?.of(c) || c)}${counts[c] ? `: ${counts[c]} ransomware claims in 7 days` : ''}</title></path>`).join('');
  const dots = mapEvents.map(e => `<circle id="ev${e.i}" class="p ${e.k}" cx="${e.x.toFixed(1)}" cy="${e.y.toFixed(1)}" r="4.6"><title>${esc(e.who)} → ${esc(e.what)} · ${esc(e.where)} · ${ago(e.d)} ago</title></circle>`).join('');
  $('#map').innerHTML = `<svg viewBox="0 0 ${W.w} ${W.h}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Replay of attacks reported in the last ${span > 3 * DAY ? '7 days' : '72 hours'}">${land}<g id="map-dots">${dots}</g><g id="map-fx"></g></svg><ul class="map-feed" id="map-feed"></ul>`;

  const top = (D.rw?.totals?.month?.countries || []).slice(0, 3);
  $('#map-top').innerHTML = top.length ? `<span class="lbl">Most targeted · ${esc(monthName())}</span>${top.map(([c, n]) => `<span class="mt"><img src="flags/${esc(c.toLowerCase())}.svg" alt="" onerror="this.remove()">${esc(region?.of(c) || c)} <b>${num(n)}</b></span>`).join('')}` : '';
  startReplay();
}

function landAttack(e) {
  const W = D.world, fx = $('#map-fx'), dot = document.getElementById(`ev${e.i}`); if (!fx) return;
  dot?.classList.add('hit');
  // Streak: a short curve that comes in from the upper left and lands on the target.
  const sx = Math.max(4, e.x - 70 - (e.i % 5) * 12), sy = Math.max(4, e.y - 95 + (e.i % 3) * 10), cx = (sx + e.x) / 2 - 20, cy = Math.min(sy, e.y) - 25;
  const g = svgEl('g', { class: `fx ${e.k}` });
  g.append(svgEl('path', { class: 'streak', d: `M${sx.toFixed(1)},${sy.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${e.x.toFixed(1)},${e.y.toFixed(1)}`, pathLength: '1' }));
  g.append(svgEl('circle', { class: 'impact', cx: e.x.toFixed(1), cy: e.y.toFixed(1), r: '4' }));
  // Label, kept inside the map.
  const lx = Math.min(W.w - 300, Math.max(6, e.x + 10)), ly = Math.max(22, e.y - 10);
  const label = svgEl('text', { class: 'lbl', x: lx.toFixed(1), y: ly.toFixed(1) });
  label.textContent = `${e.who} → ${e.what.length > 26 ? e.what.slice(0, 25) + '…' : e.what}`;
  g.append(label);
  fx.append(g);
  setTimeout(() => g.remove(), 3200);
  while (fx.childElementCount > 6) fx.firstChild.remove();
  // Feed of the latest landings (newest first).
  const feed = $('#map-feed');
  if (feed) {
    const li = document.createElement('li');
    li.className = e.k;
    li.innerHTML = `<b>${esc(e.who)}</b> → ${esc(e.what)} <span class="w">${esc(e.where)} · ${ago(e.d)} ago</span>`;
    feed.prepend(li);
    while (feed.childElementCount > 3) feed.lastChild.remove();
  }
}

function startReplay() {
  if (play) cancelAnimationFrame(play.raf);
  const list = mapEvents, { start, end } = mapWin;
  const fmt = t => new Date(t).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' });
  if (reduceMotion || !list.length) {
    document.querySelectorAll('#map-dots circle').forEach(c => c.classList.add('hit'));
    list.slice(-3).forEach(landAttack);
    $('#map-ph').style.width = '100%'; $('#map-clock').textContent = list.length ? `Up to ${fmt(end)}` : 'No attacks reported';
    return;
  }
  const LOOP = Math.min(90, Math.max(40, list.length * 0.9)) * 1000, HOLD = 4000;
  play = { t0: performance.now(), next: 0, raf: 0, lastLabel: 0 };
  const frame = now => {
    const el = now - play.t0;
    if (el > LOOP + HOLD) {                           // loop: dim everything and start again
      document.querySelectorAll('#map-dots circle.hit').forEach(c => c.classList.remove('hit'));
      play.t0 = now; play.next = 0;
    } else {
      const sim = start + Math.min(1, el / LOOP) * (end - start);
      while (play.next < list.length && list[play.next].d <= sim) landAttack(list[play.next++]);
      $('#map-ph').style.width = `${Math.min(100, el / LOOP * 100)}%`;
      if (now - play.lastLabel > 250) { $('#map-clock').textContent = `Replay · ${fmt(sim)}`; play.lastLabel = now; }
    }
    play.raf = requestAnimationFrame(frame);
  };
  play.raf = requestAnimationFrame(frame);
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
  for (const f of [renderStrip, renderAlerts, renderLatest, renderSpot, renderKev, renderZd, renderMap, renderTicker]) { try { f(); } catch (e) { console.warn('Wall:', f.name, e); } }
  showPane(expPane);
}

// Relative times ("12m") keep counting between refreshes.
function refreshAges() {
  if (D.news) { renderLatest(); renderAlerts(); renderStrip(); requestAnimationFrame(fit); }
  freshness();
}

tick(); setInterval(tick, 1000);
load().then(() => { rotateSpot(); keepAwake(); });
setInterval(load, REFRESH);
setInterval(refreshAges, MIN);
// Reload only while the site is reachable, so a screen that lost its network keeps showing the last data.
setInterval(() => { if (performance.now() > RELOAD && Date.now() - lastOk < 10 * MIN) location.reload(); }, 10 * MIN);
})();
