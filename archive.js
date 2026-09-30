// Year-to-date archive, published to public/data/archive/.
// Sources: backfill.js output (cache/archive/news-*.json, cves-*.json) plus everything the
// regular build sees, which is appended to cache/archive/live-*.json on every run. The two
// are kept in separate files so a running backfill and a build never overwrite each other.
import fs from 'node:fs/promises';
import path from 'node:path';

const readJSON = async (f, d) => { try { return JSON.parse(await fs.readFile(f, 'utf8')); } catch { return d; } };
const writeJSON = (f, v) => fs.writeFile(f, JSON.stringify(v));
const month = t => new Date(t).toISOString().slice(0, 7);
const key = u => String(u).replace(/^https?:\/\/(www\.)?/i, '').replace(/[?#].*$/, '').replace(/\/$/, '').toLowerCase();

export async function writeArchive({ root, items, recent, kevList, ransomwareYear, hibpAll, sources, clip }) {
  const year = new Date().getUTCFullYear(), start = Date.UTC(year, 0, 1);
  const cache = path.join(root, 'cache', 'archive'), out = path.join(root, 'public', 'data', 'archive');
  await fs.mkdir(cache, { recursive: true }); await fs.mkdir(out, { recursive: true });

  // 1. append what the live build saw
  const liveNews = {}, liveCves = {};
  for (const it of items) {
    if (it.bulk || it.social || it.date < start) continue;
    (liveNews[month(it.date)] ||= []).push({ t: it.title, u: it.link, s: it.source, d: it.date, x: clip(it.summary || '', 220), cv: it.cves.slice(0, 8), tg: it.tags, ac: it.actors, ve: it.vendors, ct: it.cats, tp: it.topics });
  }
  for (const r of recent) if (r.p >= start) (liveCves[month(r.p)] ||= []).push({ id: r.id, p: r.p, s: r.sc?.s, v: r.sc?.v, x: clip(r.x || '', 200), cwe: r.cwe });
  const merge = async (file, add, k) => {
    const cur = await readJSON(file, []);
    const m = new Map(cur.map(x => [k(x), x]));
    for (const x of add) m.set(k(x), x);
    await writeJSON(file, [...m.values()]);
  };
  for (const [m, list] of Object.entries(liveNews)) await merge(path.join(cache, `live-news-${m}.json`), list, x => key(x.u));
  for (const [m, list] of Object.entries(liveCves)) await merge(path.join(cache, `live-cves-${m}.json`), list, x => x.id);

  // 2. publish month files (backfill ∪ live)
  const files = await fs.readdir(cache);
  const months = [...new Set(files.map(f => (f.match(/(\d{4}-\d{2})\.json$/) || [])[1]).filter(m => m && m.startsWith(String(year))))].sort();
  const index = { generated: Date.now(), year, months: [], sources: [], totals: {} };
  const perSource = {};
  for (const m of months) {
    const news = new Map();
    for (const f of [`news-${m}.json`, `live-news-${m}.json`]) for (const x of await readJSON(path.join(cache, f), [])) news.set(key(x.u), x);
    const newsList = [...news.values()].sort((a, b) => b.d - a.d);
    for (const x of newsList) { const p = (perSource[x.s] ||= { n: 0, first: Infinity }); p.n++; if (x.d < p.first) p.first = x.d; }
    const cves = new Map();
    for (const f of [`cves-${m}.json`, `live-cves-${m}.json`]) for (const x of await readJSON(path.join(cache, f), [])) cves.set(x.id, x);
    const cveList = [...cves.values()].sort((a, b) => b.p - a.p);
    await writeJSON(path.join(out, `news-${m}.json`), newsList);
    await writeJSON(path.join(out, `cves-${m}.json`), cveList);
    index.months.push({ m, news: newsList.length, cves: cveList.length, crit: cveList.filter(c => c.v === 'CRITICAL').length,
      rw: ransomwareYear ? ransomwareYear.filter(v => month(v.d) === m).length : 0, kev: kevList.filter(k => k.d.startsWith(m)).length });
  }

  // 3. the smaller datasets: one file for the whole year
  const kevYear = kevList.filter(k => Date.parse(k.d) >= start);
  await writeJSON(path.join(out, `kev-${year}.json`), kevYear);
  if (ransomwareYear) await writeJSON(path.join(out, `ransomware-${year}.json`), ransomwareYear);
  const hibpYear = (hibpAll || []).filter(b => b.ad >= start);
  await writeJSON(path.join(out, `breaches-${year}.json`), hibpYear);

  // 4. coverage per source (so the page can say how complete the archive is)
  const cov = await readJSON(path.join(cache, 'coverage.json'), {});
  index.sources = sources.filter(s => s.feed && !s.bulk && s.cat !== 'tool').map(s => ({ s: s.name, n: perSource[s.name]?.n || 0, first: perSource[s.name]?.first === Infinity ? null : perSource[s.name]?.first || null, via: cov[s.name]?.method || (perSource[s.name] ? 'live' : 'none') })).sort((a, b) => b.n - a.n);
  index.totals = { news: index.months.reduce((a, m) => a + m.news, 0), cves: index.months.reduce((a, m) => a + m.cves, 0), kev: kevYear.length, rw: ransomwareYear?.length || 0, hibp: hibpYear.length };
  await writeJSON(path.join(out, 'index.json'), index);
  return index.totals;
}
