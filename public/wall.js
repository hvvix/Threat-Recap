// Wall display: a read-only dashboard for a screen that stays on all day.
// Fetches the same data files as the main site every few minutes, without reloading the page.
// URL options: ?theme=light   ?rotate=15 (seconds per top story)
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
  const live = $('#live');
  live.className = 'live' + (offline ? ' down' : age > 90 * MIN ? ' stale' : '');
  $('#live-txt').textContent = offline ? 'OFFLINE' : age > 90 * MIN ? 'DELAYED' : 'LIVE';
  $('#fresh').textContent = `Data updated ${ago(generated)} ago`;
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
    Object.assign(D, { news, cves, rw, inc });
    generated = news.generated; lastOk = Date.now();
    render();
  } catch (e) { console.warn('Wall: refresh failed', e); }
  freshness();
}

// ---------- rendering ----------
const TAGS = [['zeroday', 'Zero-day', 'b-zd'], ['breach', 'Breach', 'b-breach'], ['ransomware', 'Ransomware', 'b-rw']];
const badges = s => {
  const out = TAGS.filter(([t]) => s.tg.includes(t)).map(([, l, c]) => `<span class="badge ${c}">${l}</span>`);
  if (s.cv.some(c => D.cves.kevIndex?.[c])) out.push('<span class="badge b-kev">KEV</span>');
  if (s.r.length) out.push(`<span class="badge b-n">${s.r.length + 1} outlets</span>`);
  return out.join('');
};
const isNew = s => Date.now() - (s.f || s.d) < 45 * MIN;
const stories = () => D.news.stories.filter(s => !s.b && !s.so);

function renderLatest() {
  const list = stories().slice().sort((a, b) => b.d - a.d).slice(0, 18);
  $('#latest').innerHTML = list.map(s => `<li class="${isNew(s) ? 'new' : ''}"><span class="age">${ago(s.d)}</span>
    <span class="src">${esc(s.s)} ${isNew(s) ? '<span class="badge b-new">New</span>' : ''}${badges(s)}</span>
    <span class="t">${esc(s.t)}</span></li>`).join('') || '<li class="empty">No stories yet.</li>';
  $('#latest-n').textContent = `${stories().filter(s => Date.now() - s.d < DAY).length} in 24 h`;
}

function spotlightList() {
  const day = stories().filter(s => Date.now() - s.d < DAY);
  const top = day.slice().sort((a, b) => b.r.length - a.r.length || b.d - a.d).slice(0, 6);
  return top.length ? top : stories().slice(0, 6);
}
function renderSpot() {
  const list = spotlightList(); if (!list.length) { $('#spot').innerHTML = '<p class="empty">No stories yet.</p>'; return; }
  spotIdx %= list.length;
  const s = list[spotIdx], info = D.cves.info || {};
  const cves = s.cv.slice(0, 4).map(c => { const i = info[c] || {}; return `<span class="cvechip">${c}${i.s != null ? `<b class="sev ${esc(i.v)}">${i.s}</b>` : ''}</span>`; }).join('');
  const dev = (D.inc?.incidents || []).slice().sort((a, b) => b.last - a.last)[0];
  $('#spot').innerHTML = `<div class="slide">
      <span class="kicker">${s.r.length ? `Covered by ${s.r.length + 1} outlets` : 'Top story'} · ${ago(s.d)} ago</span>
      ${s.im ? `<img class="img" src="${/^https?:\/\//.test(s.im) ? esc(s.im) : ''}" alt="" referrerpolicy="no-referrer" onerror="this.remove()">` : ''}
      <h3>${esc(s.t)}</h3>
      ${s.x ? `<p>${esc(clip(s.x, 320))}</p>` : ''}
      <div class="meta">${esc(s.s)}${s.r.length ? ` · ${esc(s.r.slice(0, 3).map(r => r[0]).join(', '))}${s.r.length > 3 ? ` +${s.r.length - 3}` : ''}` : ''}</div>
      ${cves ? `<div class="chips">${cves}</div>` : ''}
    </div>
    <div class="dots" style="--rot:${ROTATE}ms">${list.map((_, i) => `<i class="${i === spotIdx ? 'on' : ''}"></i>`).join('')}</div>
    ${dev ? `<div class="dev">Developing: <b>${esc(dev.title)}</b> · ${dev.n} updates · latest ${ago(dev.last)} ago</div>` : ''}`;
}
function rotateSpot() { clearInterval(spotTimer); spotTimer = setInterval(() => { spotIdx++; renderSpot(); }, ROTATE); }

function renderStats() {
  const day = stories().filter(s => Date.now() - s.d < DAY);
  const kev7 = (D.cves.kev || []).filter(k => Date.now() - Date.parse(k.d + 'T23:59:59Z') < 7 * DAY).length;
  const rw24 = D.rw ? D.rw.recent.filter(v => Date.now() - v.d < DAY).length : null;
  const zd = day.filter(s => s.tg.includes('zeroday')).length;
  const tiles = [
    [num(day.length), 'stories'],
    [num(zd), 'zero-day stories', zd > 0],
    [num(day.filter(s => s.tg.includes('breach')).length), 'breach reports'],
    [rw24 == null ? '—' : num(rw24), 'ransomware claims'],
    [num(kev7), 'new KEV · 7 days', kev7 > 0],
    [num(new Set(day.flatMap(s => s.cv)).size), 'CVEs in the news'],
  ];
  $('#stats').innerHTML = tiles.map(([v, k, hot]) => `<div class="tile${hot ? ' hot' : ''}"><div class="v">${v}</div><div class="k">${k}</div></div>`).join('');
}

function renderKev() {
  const info = D.cves.info || {}, list = (D.cves.kev || []).slice(0, 8);
  $('#kev').innerHTML = list.map(k => { const i = info[k.id] || {}; return `<li><div class="l1">${k.id}${i.s != null ? `<span class="sev ${esc(i.v)}">${i.s}</span>` : ''}${k.rw ? '<span class="badge b-rw">Ransomware</span>' : ''}<span class="when">${esc(new Date(k.d + 'T12:00:00Z').toLocaleDateString([], { month: 'short', day: 'numeric' }))}</span></div>
    <div class="l2">${esc(k.v)} ${esc(k.p)}: ${esc(k.n.replace(new RegExp(`^${k.v}\\s+${k.p}\\s+`, 'i'), ''))}</div></li>`; }).join('') || '<li class="empty">No recent entries.</li>';
  const week = (D.cves.kev || []).filter(k => Date.now() - Date.parse(k.d + 'T23:59:59Z') < 7 * DAY).length;
  $('#kev-n').textContent = `${week} this week`;
}

function renderZd() {
  const list = stories().filter(s => s.tg.includes('zeroday') && Date.now() - s.d < 3 * DAY).sort((a, b) => b.r.length - a.r.length || b.d - a.d).slice(0, 8);
  $('#zd').innerHTML = list.map(s => `<li><div class="l1"><span style="color:var(--muted)">${esc(s.s)}</span>${s.r.length ? `<span class="badge b-n">${s.r.length + 1} outlets</span>` : ''}${s.cv.slice(0, 2).map(c => `<span>${c}</span>`).join('')}<span class="when">${ago(s.d)}</span></div><div class="l2">${esc(s.t)}</div></li>`).join('') || '<li class="empty">Nothing flagged in the last 72 hours.</li>';
}

function renderRw() {
  const rw = D.rw; if (!rw) { $('#rw').innerHTML = '<li class="empty">Ransomware data unavailable.</li>'; return; }
  const days = rw.daily.slice(-10), max = Math.max(1, ...days.map(d => d[1])), today = new Date().toISOString().slice(0, 10);
  $('#rw-chart').innerHTML = days.map(([d, n]) => `<div class="c${d === today ? ' today' : ''}" title="${d}: ${n} claims"><span class="val">${n}</span><div class="bar" style="height:${Math.max(2, (n / max) * 72)}%"></div><span class="day">${new Date(d + 'T12:00:00Z').toLocaleDateString([], { day: 'numeric' })}</span></div>`).join('');
  const region = (() => { try { return new Intl.DisplayNames([], { type: 'region' }); } catch { return null; } })();
  $('#rw').innerHTML = rw.recent.slice(0, 7).map(v => `<li>${v.c ? `<img src="flags/${esc(v.c.toLowerCase())}.svg" alt="" title="${esc(v.x || region?.of(v.c) || v.c)}" onerror="this.remove()">` : ''}<span class="g">${esc(v.g)}</span><span class="v">${esc(v.t)}</span><span class="when">${ago(v.d)}</span></li>`).join('');
  $('#rw-n').textContent = `${num(rw.recent.filter(v => Date.now() - v.d < DAY).length)} in 24 h · ${num(rw.total30)} in 30 days`;
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
  for (const f of [renderLatest, renderSpot, renderStats, renderKev, renderZd, renderRw, renderTicker]) { try { f(); } catch (e) { console.warn('Wall:', f.name, e); } }
  requestAnimationFrame(fit);
}

// Relative times ("12m") keep counting between refreshes.
function refreshAges() { if (D.news) { renderLatest(); renderStats(); requestAnimationFrame(fit); } freshness(); }

tick(); setInterval(tick, 1000);
load().then(() => { rotateSpot(); keepAwake(); });
setInterval(load, REFRESH);
setInterval(refreshAges, MIN);
// Reload only while the site is reachable, so a screen that lost its network keeps showing the last data.
setInterval(() => { if (performance.now() > RELOAD && Date.now() - lastOk < 10 * MIN) location.reload(); }, 10 * MIN);
})();
