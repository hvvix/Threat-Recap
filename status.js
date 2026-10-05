// Vendor status that browsers can't read directly (no cross-site access), collected at build time
// and published as data/status.json. The wall display reads the rest live from each vendor's status page.

const UA = 'ThreatRecap/1.0 (+https://github.com/hvvix/Threat-Recap)';
const get = (url, timeout = 20000) => fetch(url, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(timeout) });
const clip = (s, n) => { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n).replace(/\s+\S*$/, '') + '…' : s; };

// AWS Health Dashboard: current events, served as UTF-16 JSON. Status "0" = resolved, 1 = informational, 2 = degraded, 3 = disrupted.
async function aws() {
  const buf = Buffer.from(await (await get('https://health.aws.amazon.com/public/currentevents')).arrayBuffer());
  // The feed is UTF-16 with a byte-order mark: FE FF = big-endian (what AWS sends), FF FE = little-endian.
  let text;
  if (buf[0] === 0xfe && buf[1] === 0xff) text = Buffer.from(buf.subarray(2)).swap16().toString('utf16le');
  else if (buf[0] === 0xff && buf[1] === 0xfe) text = buf.subarray(2).toString('utf16le');
  else text = buf.toString('utf8').replace(/^﻿/, '');
  const open = JSON.parse(text).filter(e => String(e.status) !== '0');
  const worst = Math.max(0, ...open.map(e => Number(e.status) || 1));
  return {
    s: worst >= 3 ? 'major' : worst === 2 ? 'minor' : 'none',
    label: open.length ? (worst >= 2 ? 'Service issues' : 'Informational notices') : 'All services operating normally',
    inc: open[0] ? clip(`${open[0].service_name} (${open[0].region_name}): ${open[0].summary}`, 140) : '',
    more: Math.max(0, open.length - 1),
    affected: [...new Set(open.map(e => e.region_name).filter(Boolean))].slice(0, 4),
  };
}

// Azure status RSS: lists only active incidents (an empty feed means everything is fine).
async function azure() {
  const xml = await (await get('https://azure.status.microsoft/en-us/status/feed/')).text();
  const items = [...xml.matchAll(/<item>[\s\S]*?<title>([\s\S]*?)<\/title>/g)].map(m => m[1].replace(/<!\[CDATA\[|\]\]>/g, '').trim());
  return { s: items.length ? 'minor' : 'none', label: items.length ? 'Active incident' : 'All services operational', inc: clip(items[0] || '', 140), more: Math.max(0, items.length - 1), affected: [] };
}

const SOURCES = [
  { n: 'AWS', url: 'https://health.aws.amazon.com/health/status', match: ['Amazon', 'AWS'], fn: aws },
  { n: 'Microsoft Azure', url: 'https://azure.status.microsoft/status', match: ['Microsoft', 'Azure'], fn: azure },
];

export async function fetchStatus() {
  const out = await Promise.all(SOURCES.map(async ({ fn, ...v }) => {
    try { return { ...v, ...(await fn()), ok: true }; }
    catch (e) { return { ...v, s: 'unknown', label: 'Status unavailable', inc: '', more: 0, affected: [], ok: false, err: e.message }; }
  }));
  return { generated: Date.now(), vendors: out };
}
