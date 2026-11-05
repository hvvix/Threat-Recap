#!/usr/bin/env node
// Private site health alerts for the owner. Nothing here is published: the state lives in
// cache/health.json (the Actions cache, not the site), and alerts go only to the owner's own device
// through the push setup (push.js / push/worker.js).
//
//   node health.js feeds   after a successful build: track which feeds failed, alert once when a feed
//                          has failed HEALTH_FEED_RUNS updates in a row (default 3) for at least
//                          HEALTH_FEED_HOURS hours (default 6), so short outages stay quiet
//   node health.js job     at the end of every update (JOB_STATUS, STAGE from the workflow): alert when
//                          an update fails (then at most every 6 hours while it keeps failing) and once
//                          when it works again
//   node health.js --test  send a sample alert and the current summary to the owner
//
//   OWNER_PUSH_ID   the owner's device ID (shown in the "Push alerts are working" test message); several
//                   can be given, comma-separated. Without it nothing is sent, only recorded.
//   PUSH_API, PUSH_ADMIN_TOKEN, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY   same as push.js
//   HEALTH_DRY=1    print the messages instead of sending them (for local testing)
//
// push.js adds healthLine() to the owner's morning recap.

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const STATE = path.join(ROOT, 'cache', 'health.json');
const HOUR = 36e5, DAY = 24 * HOUR;
const RUNS = process.env.HEALTH_FEED_RUNS ? +process.env.HEALTH_FEED_RUNS : 3;
const HOURS = process.env.HEALTH_FEED_HOURS ? +process.env.HEALTH_FEED_HOURS : 6;
const REPEAT = 6 * HOUR;                 // reminder while updates keep failing
const log = (...a) => console.log('[health]', ...a);
const readJSON = async (f, d) => { try { return JSON.parse(await fs.readFile(f, 'utf8')); } catch { return d; } };
const ago = ms => ms < HOUR ? `${Math.max(1, Math.round(ms / 6e4))} min` : ms < 2 * DAY ? `${Math.round(ms / HOUR)} h` : `${Math.round(ms / DAY)} days`;
const SITE = (process.env.SITE_URL || 'https://hvvix.github.io/Threat-Recap/').replace(/\/?$/, '/');
const { GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID } = process.env;
const RUN_URL = GITHUB_RUN_ID ? `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}` : SITE;

// One line for the owner's morning recap, from the saved state. Empty when there is no state yet.
export function healthLine(state, now = Date.now()) {
  if (!state?.history?.length) return '';
  const day = state.history.filter(h => now - h.at < DAY);
  const bad = day.filter(h => !h.ok).length;
  const failing = Object.entries(state.feeds || {}).filter(([, f]) => f.streak >= RUNS).sort((a, b) => a[1].since - b[1].since);
  const parts = [bad ? `${bad} of ${day.length} updates failed` : `${day.length}/${day.length} updates OK`];
  if (state.job?.failStreak) parts[0] += ' (failing now)';
  parts.push(failing.length ? `${failing.length} feed${failing.length > 1 ? 's' : ''} down: ${failing.slice(0, 3).map(([n]) => n).join(', ')}${failing.length > 3 ? ` +${failing.length - 3}` : ''}` : 'all feeds OK');
  return `🩺 Site: ${parts.join(' · ')}`;
}

async function sendToOwner(messages) {
  if (!messages.length) return;
  if (process.env.HEALTH_DRY) { for (const m of messages) log(`would send: ${m.title} | ${m.body.replace(/\n/g, ' / ')}`); return; }
  const owners = (process.env.OWNER_PUSH_ID || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  const { PUSH_API, PUSH_ADMIN_TOKEN, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY } = process.env;
  if (!owners.length || !PUSH_API || !PUSH_ADMIN_TOKEN || !VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) { log(`${messages.length} alert(s) not sent: owner device or push not configured`); return; }
  const webpush = (await import('web-push')).default;
  webpush.setVapidDetails('https://github.com/hvvix/Threat-Recap', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  const r = await fetch(`${PUSH_API}/subscriptions`, { headers: { authorization: `Bearer ${PUSH_ADMIN_TOKEN}` } });
  if (!r.ok) { log(`could not read subscriptions: HTTP ${r.status}`); return; }
  const mine = (await r.json()).filter(s => owners.some(o => s.id.startsWith(o)));
  if (!mine.length) { log('owner device not found among subscribers'); return; }
  let ok = 0;
  for (const s of mine) for (const m of messages) {
    try { await webpush.sendNotification(s.sub, JSON.stringify(m), { TTL: 12 * 3600, urgency: 'high' }); ok++; }
    catch (e) { log(`send failed (${e.statusCode || e.message})`); }
  }
  log(`sent ${ok} alert(s) to the owner`);
}

async function main() {
  const mode = process.argv.includes('--test') ? 'test' : process.argv[2] || 'feeds';
  const now = Date.now();
  const state = await readJSON(STATE, {});
  state.feeds ||= {}; state.job ||= { failStreak: 0 }; state.history ||= [];
  const out = [];

  if (mode === 'feeds') {
    const src = await readJSON(path.join(ROOT, 'cache', 'feed-status.json'), null);
    if (!src || now - src.generated > HOUR) { log('no fresh feed-status.json; feeds not checked'); process.exit(0); }
    const seen = new Set(), recovered = [];
    for (const s of src.sources) {
      seen.add(s.n);
      const f = state.feeds[s.n];
      if (s.ok) { if (f?.alerted) recovered.push(s.n); delete state.feeds[s.n]; continue; }
      state.feeds[s.n] = { streak: (f?.streak || 0) + 1, since: f?.since || now, err: s.err || 'failed', alerted: f?.alerted || 0 };
    }
    for (const n of Object.keys(state.feeds)) if (!seen.has(n)) delete state.feeds[n];   // removed from sources.json
    const down = Object.entries(state.feeds).filter(([, f]) => !f.alerted && f.streak >= RUNS && now - f.since >= HOURS * HOUR);
    if (down.length) {
      out.push({ title: `📡 ${down.length} feed${down.length > 1 ? 's' : ''} failing`, tag: `health-feeds-${now}`, url: `${SITE}?tab=sources`,
        body: down.slice(0, 4).map(([n, f]) => `${n}: ${f.err} · ${ago(now - f.since)}, ${f.streak} updates`).join('\n') + (down.length > 4 ? `\n+${down.length - 4} more` : '') });
      for (const [, f] of down) f.alerted = now;
    }
    if (recovered.length) log(`recovered: ${recovered.length} feed(s)`);
    const failing = Object.values(state.feeds).filter(f => f.streak >= RUNS).length;
    log(`${src.sources.length} feeds · ${Object.keys(state.feeds).length} failed this update · ${failing} failing ${RUNS}+ updates in a row · ${down.length} new alert(s)`);
  }

  if (mode === 'job') {
    const status = process.env.JOB_STATUS || 'success';
    if (status === 'cancelled') { log('update cancelled; not counted'); process.exit(0); }
    const j = state.job, ok = status === 'success';
    if (!ok) {
      j.failStreak = (j.failStreak || 0) + 1; j.since ||= now;
      const stage = process.env.STAGE === 'build' ? 'building the data' : 'publishing the site';
      if (j.failStreak === 1 || now - (j.lastAlert || 0) >= REPEAT) {
        out.push({ title: '⚠️ Threat Recap update failed', url: RUN_URL, tag: 'health-job',
          body: `Failed while ${stage}${j.failStreak > 1 ? ` · ${j.failStreak} updates in a row, for ${ago(now - j.since)}` : ''}.\nThe site still shows the last good update. Tap for the log.` });
        j.lastAlert = now;
      }
    } else if (j.failStreak) {
      out.push({ title: '✅ Threat Recap updates working again', url: SITE, tag: 'health-job', body: `After ${j.failStreak} failed update${j.failStreak > 1 ? 's' : ''} over ${ago(now - j.since)}.` });
      state.job = { failStreak: 0 };
    }
    state.history = [...state.history.filter(h => now - h.at < 7 * DAY), { at: now, ok }];
    log(`update ${ok ? 'OK' : `failed (${state.job.failStreak} in a row)`}`);
  }

  if (mode === 'test') {
    out.push({ title: '🩺 Health alerts are working', url: SITE, tag: 'health-test',
      body: `${healthLine(state) || 'No health data yet.'}\nYou'll get an alert when an update fails or a feed fails ${RUNS} updates in a row.` });
  }

  await sendToOwner(out);
  if (mode !== 'test') {
    await fs.mkdir(path.dirname(STATE), { recursive: true });
    await fs.writeFile(STATE, JSON.stringify(state));
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
