// Developing stories (incident timelines) and breach-size extraction.
const DAY = 864e5;

// ---------- breach sizes ----------
const UNITS = 'records|users|customers|accounts|people|individuals|patients|students|employees|members|clients|subscribers|rows|emails|email addresses|passengers|citizens|voters|residents|victims|persons|consumers|donors|families|workers|applicants';
const SIZE_RE = new RegExp(`(\\d{1,3}(?:[.,]\\d{1,3})*(?:\\.\\d+)?)\\s*(million|billion|thousand|[MBK])?\\+?\\s+(?:[A-Za-z'’-]+\\s+){0,3}?(${UNITS})\\b`, 'gi');
export function breachSize(text) {
  let best = null;
  for (const m of text.matchAll(SIZE_RE)) {
    let n = parseFloat(m[1].replace(/,(?=\d{3}\b)/g, ''));
    const mult = (m[2] || '').toLowerCase();
    if (mult === 'million' || mult === 'm') n *= 1e6; else if (mult === 'billion' || mult === 'b') n *= 1e9; else if (mult === 'thousand' || mult === 'k') n *= 1e3;
    if (!Number.isFinite(n) || n < 500 || n > 2e10) continue;
    if (/^(19|20)\d\d$/.test(m[1]) && !m[2]) continue;           // a year, not a count
    if (!best || n > best.n) best = { n: Math.round(n), u: m[3].toLowerCase() };
  }
  return best;
}

// ---------- developing stories ----------
// A developing story is a group of CVEs reported together (or a threat actor) that kept
// getting coverage: at least 4 news/research stories in the last 30 days.
export function buildIncidents({ stories, kevList, poc, recent, now = Date.now() }) {
  const kevBy = Object.fromEntries(kevList.map(k => [k.id, k]));
  const recentBy = Object.fromEntries(recent.map(r => [r.id, r]));
  const news = stories.filter(s => !s.so && now - s.d < 30 * DAY);

  // union CVEs that appear together in focused stories (≤ 3 CVEs)
  const parent = {};
  const find = x => (parent[x] === x ? x : (parent[x] = find(parent[x])));
  const union = (a, b) => { a = find(a); b = find(b); if (a !== b) parent[b] = a; };
  for (const s of news) {
    const cv = s.cv.length <= 3 ? s.cv : [];
    for (const c of cv) parent[c] ??= c;
    for (let i = 1; i < cv.length; i++) union(cv[0], cv[i]);
  }
  const groups = {};
  for (const c of Object.keys(parent)) (groups[find(c)] ||= new Set()).add(c);

  const incidents = [];
  const kind = s => s.b ? 'advisory'
    : /\b(patch(es|ed)?|fix(es|ed)?|update[sd]?|releases? (a )?fix|hotfix)\b/i.test(s.t) ? 'patch'
    : /\b(exploit(ed|ation|s)?|in the wild|zero-day|0-day|attack(s|ed)?|hack(ed|ers)?|compromise[sd]?|breach(ed)?)\b/i.test(s.t) ? 'exploit'
    : s.c === 'research' ? 'analysis' : 'news';
  // Every outlet's article becomes its own timeline entry (merged stories are unpacked).
  const make = (id, title, related, extra = []) => {
    const main = related.filter(s => !s.b);
    const articles = main.reduce((a, s) => a + s.r.length + 1, 0);
    if (articles < 5 || main.length < 2) return null;
    const events = related.flatMap(s => [
      { d: s.d, k: kind(s), t: s.t, u: s.u, s: s.s, sid: s.id },
      ...s.r.map(r => ({ d: r[3], k: kind({ t: r[1], c: '', b: s.b }), t: r[1], u: r[2], s: r[0], sid: s.id })),
    ]).concat(extra).sort((a, b) => a.d - b.d);
    const first = events[0].d, last = events.at(-1).d;
    const inc = { id, title, first, last, n: main.length, outlets: new Set(main.flatMap(s => [s.s, ...s.r.map(r => r[0])])).size, events: events.slice(-80), sids: related.map(s => s.id) };
    incidents.push(inc); return inc;
  };

  for (const set of Object.values(groups)) {
    const cves = [...set];
    const byCve = news.filter(s => s.cv.some(c => set.has(c)));
    if (!byCve.length) continue;
    // Headlines often skip the CVE number ("Citrix patches NetScaler zero-days"): also take
    // vulnerability stories about the same product from the same period.
    const prodCount = {};
    for (const s of byCve) for (const p of s.tp || []) prodCount[p] = (prodCount[p] || 0) + 1;
    const prod = Object.entries(prodCount).sort((a, b) => b[1] - a[1])[0];
    // Ubiquitous products (Windows, Chrome…) would pull in unrelated stories: only match specific ones.
    const prodFreq = prod ? news.filter(s => (s.tp || []).includes(prod[0])).length : 0;
    const start = Math.min(...byCve.map(s => s.d)) - 2 * DAY;
    const related = prod && prod[1] >= 2 && prodFreq <= 20
      ? news.filter(s => byCve.includes(s) || (s.d >= start && (s.tp || []).includes(prod[0]) && (s.tg.includes('vuln') || s.tg.includes('zeroday')) && s.cv.length <= 3 && !s.cv.some(c => !set.has(c) && kevBy[c])))
      : byCve;
    const lead = cves.map(c => ({ c, k: kevBy[c], m: related.filter(s => s.cv.includes(c)).length })).sort((a, b) => (b.k ? 1 : 0) - (a.k ? 1 : 0) || b.m - a.m)[0];
    const extra = [];
    for (const c of cves) {
      if (kevBy[c] && now - Date.parse(kevBy[c].d) < 60 * DAY) extra.push({ d: Date.parse(kevBy[c].d + 'T12:00:00Z'), k: 'kev', t: `${c} added to CISA's Known Exploited Vulnerabilities catalog`, u: `https://nvd.nist.gov/vuln/detail/${c}` });
      if (poc[c]?.first && now - poc[c].first < 60 * DAY) extra.push({ d: poc[c].first, k: 'poc', t: `First public exploit code for ${c} on GitHub${poc[c].top?.[0] ? ` (${poc[c].top[0].n})` : ''}`, u: poc[c].top?.[0]?.u || `https://github.com/search?q=${c}` });
      if (recentBy[c]?.p) extra.push({ d: recentBy[c].p, k: 'cve', t: `${c} published`, u: `https://nvd.nist.gov/vuln/detail/${c}` });
    }
    const k = lead?.k;
    const title = k ? `${k.v} ${k.p}: ${k.n.replace(new RegExp(`^${k.v}\\s+(${k.p}\\s+)?`, 'i'), '').replace(/ Vulnerability$/i, '')}` : related.slice().sort((a, b) => b.r.length - a.r.length)[0]?.t;
    const inc = make(`cve-${lead?.c || cves[0]}`.toLowerCase(), title, related, extra);
    if (inc) inc.cves = cves.sort();
  }

  // threat-actor campaigns not already covered by a CVE story line
  const inCve = new Set(incidents.flatMap(i => i.sids));
  const byActor = {};
  for (const s of news) for (const a of s.ac) (byActor[a] ||= []).push(s);
  for (const [a, list] of Object.entries(byActor)) {
    const fresh = list.filter(s => now - s.d < 14 * DAY && !inCve.has(s.id));
    if (fresh.filter(s => !s.b).reduce((n, s) => n + s.r.length + 1, 0) >= 6) { const inc = make(`actor-${a}`.toLowerCase().replace(/[^a-z0-9]+/g, '-'), `${a} activity`, fresh); if (inc) inc.actor = a; }
  }

  // Merge story lines that mostly cover the same articles (e.g. two CVEs in one product).
  for (let i = 0; i < incidents.length; i++) for (let j = i + 1; j < incidents.length; j++) {
    const A = incidents[i], B = incidents[j]; if (!A || !B) continue;
    const shared = B.sids.filter(x => A.sids.includes(x)).length;
    if (shared / Math.min(A.sids.length, B.sids.length) < 0.5) continue;
    const [keep, drop] = A.n >= B.n ? [A, B] : [B, A];
    const seen = new Set(keep.events.map(e => e.u + e.k));
    keep.events = keep.events.concat(drop.events.filter(e => !seen.has(e.u + e.k))).sort((a, b) => a.d - b.d).slice(-100);
    keep.sids = [...new Set([...keep.sids, ...drop.sids])];
    keep.cves = [...new Set([...(keep.cves || []), ...(drop.cves || [])])].sort();
    keep.first = keep.events[0].d; keep.last = keep.events.at(-1).d;
    keep.n = keep.sids.length; keep.outlets = new Set(keep.events.map(e => e.s).filter(Boolean)).size;
    if (keep.cves.length > 1 && /: /.test(keep.title)) keep.title = keep.title.split(': ')[0] + ': multiple exploited vulnerabilities';
    incidents[incidents.indexOf(drop)] = null;
  }
  return incidents.filter(Boolean).sort((a, b) => b.last - a.last);
}
