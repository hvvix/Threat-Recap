#!/usr/bin/env node
// Self-hosting option: serves public/ and rebuilds the data every 20 minutes.
//   node server.js            → http://localhost:3000
//   PORT=8080 REBUILD_MINUTES=15 node server.js

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT || 3000);
const EVERY = Number(process.env.REBUILD_MINUTES || 20) * 60 * 1000;
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml; charset=utf-8' };

let building = false;
function build() {
  if (building) return; building = true;
  const p = spawn(process.execPath, [path.join(ROOT, 'build.js')], { stdio: 'inherit', env: process.env });
  p.on('exit', code => { building = false; if (code) console.error(`build exited with code ${code}`); });
}

http.createServer((req, res) => {
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch { res.writeHead(400).end(); return; }
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405).end(); return; }
  if (pathname.endsWith('/')) pathname += 'index.html';
  // Only files inside public/ are reachable (no ../ escapes, no server code).
  const file = path.normalize(path.join(PUBLIC, pathname));
  if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403).end('Forbidden'); return; }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'content-type': 'text/plain' }).end('Not found'); return; }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, {
      'content-type': TYPES[ext] || 'application/octet-stream',
      'content-length': st.size,
      'cache-control': ext === '.json' || ext === '.xml' ? 'no-cache' : 'public, max-age=300',
      'x-content-type-options': 'nosniff',
      ...(ext === '.json' || ext === '.xml' ? { 'access-control-allow-origin': '*' } : {}),
      'referrer-policy': 'strict-origin-when-cross-origin',
    });
    if (req.method === 'HEAD') { res.end(); return; }
    fs.createReadStream(file).pipe(res);
  });
}).listen(PORT, () => console.log(`Threat Recap on http://localhost:${PORT} (rebuilding every ${EVERY / 60000} min)`));

build();
setInterval(build, EVERY);
