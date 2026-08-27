// D7 Ranger Kiosk — GPS spoofer live relay
//
// Laptops POST /report the instant their gps_spoofer state changes
// (event-driven, from statusbar.py's existing 2s poll loop — see
// _refresh_gps_panel_thread). This process rebroadcasts that update
// immediately to every connected dashboard over WebSocket, so the
// GitHub Pages dashboard reflects each laptop's GPS panel live.
//
// Auth: a single shared bearer token (RELAY_TOKEN env var), checked on
// both /report and the /dashboard WebSocket upgrade. This is fleet
// telemetry (truck GPS coordinates) — token, not the endpoint URL, is
// what has to stay private, since the dashboard HTML is a public static
// GitHub Pages file with the token deliberately left out of it.
'use strict';

const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const TOKEN = process.env.RELAY_TOKEN;
if (!TOKEN) {
  console.error('RELAY_TOKEN env var is required — refusing to start.');
  process.exit(1);
}

// ── Login endpoints — let the dashboard and message-sender pages hand
// out their real secrets after a password check instead of shipping
// those secrets in public page source. Each is optional: if its env var
// isn't set, that login route just stays disabled (404).
const LOGIN_USERNAME = process.env.LOGIN_USERNAME || 'admin';

const DASHBOARD_LOGIN_PASSWORD = process.env.DASHBOARD_LOGIN_PASSWORD || null;
const RELAY_DASHBOARD_URL      = process.env.RELAY_DASHBOARD_URL || null; // wss://.../dashboard, handed out on login

const SENDER_LOGIN_PASSWORD = process.env.SENDER_LOGIN_PASSWORD || null;
const SENDER_GITHUB_TOKEN   = process.env.SENDER_GITHUB_TOKEN || null; // fleet-repo write token, handed out on login

// Origin allowed to call the login endpoints via browser fetch(). Login
// responses carry real secrets, so this is deliberately not "*".
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://lucentgp.github.io';

// ── TeamViewer device lookup — fetched server-side only, never exposed
// to the browser. Devices are matched to laptops by hostname prefix
// (TeamViewer's alias convention here is "HOSTNAME-truck-serial", e.g.
// "HW538173-753-0DTTA19403"), so this works with zero laptop-side code:
// no fleet rollout needed for a laptop to start showing a Remote In
// link, just this relay knowing the token.
const TEAMVIEWER_API_TOKEN = process.env.TEAMVIEWER_API_TOKEN || null;
const TEAMVIEWER_REFRESH_MS = 5 * 60 * 1000;
let tvDevices = [];

// ── Firestore publish (2026-08-27, canary) — the TeamViewer device list
// itself is not sensitive (it's the same aliases already shown on the
// public dashboard for every relay-sourced laptop); only fetching it
// needs the private TEAMVIEWER_API_TOKEN above, which stays server-side
// here same as always. This just also hands the already-fetched list to
// Firestore so a laptop that's fully cut over to Firebase (no longer
// known to this relay at all) can still get a working Remote In button
// -- the dashboard does the same hostname-prefix match client-side.
// FIRESTORE_WRITE_SECRET must be set as a Render env var, never
// committed -- this file is a public repo.
const FIRESTORE_PROJECT_ID = process.env.FIRESTORE_PROJECT_ID || null;
const FIRESTORE_WRITE_SECRET = process.env.FIRESTORE_WRITE_SECRET || null;

async function publishTeamViewerDevicesToFirestore() {
  if (!FIRESTORE_PROJECT_ID || !FIRESTORE_WRITE_SECRET) return; // not configured -- silently skip, same as the snapshot persistence above
  try {
    const url = 'https://firestore.googleapis.com/v1/projects/' + FIRESTORE_PROJECT_ID +
      '/databases/(default)/documents/meta/teamviewer_devices';
    const body = {
      fields: {
        devices: { stringValue: JSON.stringify(tvDevices) },
        updatedAt: { integerValue: String(Date.now()) },
        secret: { stringValue: FIRESTORE_WRITE_SECRET },
      },
    };
    const res = await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) console.error('Firestore TeamViewer publish failed:', res.status);
  } catch (e) {
    console.error('Firestore TeamViewer publish error:', e.message);
  }
}

// ── Fleet status persistence — this process's `laptops` map is otherwise
// in-memory only, so a Render redeploy (which restarts the process) wipes
// every laptop's last-known status, and truly-offline laptops (nothing
// left to report and repopulate themselves) just vanish from the
// dashboard instead of showing greyed-out. To survive that, the map is
// periodically snapshotted to a JSON file in the fleet code repo -- same
// repo, same token (SENDER_GITHUB_TOKEN) already used for broadcast
// history, just a different file, so no new secret to configure. This is
// a durability nice-to-have, not a source of truth: if the token isn't
// set, everything above still works exactly as before, just without
// surviving a restart.
const SNAPSHOT_REPO = 'Lucentgp/NEW-RANGER-LAPTOP-V2';
const SNAPSHOT_PATH = 'fleet-status-snapshot.json';
const SNAPSHOT_GITHUB_TOKEN = SENDER_GITHUB_TOKEN;
const SNAPSHOT_WRITE_INTERVAL_MS = 60 * 1000;
let snapshotDirty = false;

function snapshotHeaders(extra) {
  return { Authorization: 'token ' + SNAPSHOT_GITHUB_TOKEN, 'User-Agent': 'gps-relay', ...extra };
}

async function loadLaptopsSnapshot() {
  if (!SNAPSHOT_GITHUB_TOKEN) {
    console.log('No GitHub token configured for fleet snapshot persistence — starting with empty state.');
    return;
  }
  try {
    const res = await fetch(
      `https://api.github.com/repos/${SNAPSHOT_REPO}/contents/${SNAPSHOT_PATH}`,
      { headers: snapshotHeaders({ Accept: 'application/vnd.github.v3.raw' }) },
    );
    if (res.status === 404) {
      console.log('No fleet snapshot file yet — starting with empty state.');
      return;
    }
    if (!res.ok) {
      console.error('Fleet snapshot load failed:', res.status);
      return;
    }
    const data = await res.json();
    let count = 0;
    for (const [hostname, entry] of Object.entries(data.laptops || {})) {
      laptops.set(hostname, entry);
      count++;
    }
    console.log(`Loaded fleet snapshot: ${count} laptop(s), saved ${data.savedAt ? new Date(data.savedAt).toISOString() : 'unknown time'}.`);
  } catch (e) {
    console.error('Fleet snapshot load error:', e.message);
  }
}

async function saveLaptopsSnapshot() {
  if (!SNAPSHOT_GITHUB_TOKEN || !snapshotDirty) return;
  snapshotDirty = false; // best-effort persistence, not a source of truth — a failed write below re-dirties it for the next cycle
  try {
    const getRes = await fetch(
      `https://api.github.com/repos/${SNAPSHOT_REPO}/contents/${SNAPSHOT_PATH}`,
      { headers: snapshotHeaders({ Accept: 'application/vnd.github+json' }) },
    );
    const sha = getRes.ok ? (await getRes.json()).sha : undefined;
    const body = {
      message: 'Fleet status snapshot (automated)',
      content: Buffer.from(JSON.stringify({ laptops: Object.fromEntries(laptops), savedAt: Date.now() })).toString('base64'),
      ...(sha ? { sha } : {}),
    };
    const putRes = await fetch(
      `https://api.github.com/repos/${SNAPSHOT_REPO}/contents/${SNAPSHOT_PATH}`,
      { method: 'PUT', headers: snapshotHeaders({ 'Content-Type': 'application/json', Accept: 'application/vnd.github+json' }), body: JSON.stringify(body) },
    );
    if (!putRes.ok) {
      console.error('Fleet snapshot save failed:', putRes.status);
      snapshotDirty = true;
    }
  } catch (e) {
    console.error('Fleet snapshot save error:', e.message);
    snapshotDirty = true;
  }
}

async function refreshTeamViewerDevices() {
  if (!TEAMVIEWER_API_TOKEN) return;
  try {
    const res = await fetch('https://webapi.teamviewer.com/api/v1/devices', {
      headers: { Authorization: 'Bearer ' + TEAMVIEWER_API_TOKEN },
    });
    if (!res.ok) {
      console.error('TeamViewer device fetch failed:', res.status);
      return;
    }
    const data = await res.json();
    tvDevices = Array.isArray(data.devices) ? data.devices : [];
    publishTeamViewerDevicesToFirestore();
  } catch (e) {
    console.error('TeamViewer device fetch error:', e.message);
  }
}

function lookupTeamViewer(hostname) {
  const upper = String(hostname || '').toUpperCase();
  if (!upper) return null;
  const match = tvDevices.find((d) => String(d.alias || '').toUpperCase().startsWith(upper));
  if (!match) return null;
  return {
    teamviewer_id: match.teamviewer_id || null,
    teamviewer_alias: match.alias || null,
    teamviewer_online: match.online_state || null,
  };
}

// A laptop that hasn't reported in this long is shown offline. statusbar.py
// heartbeats even when nothing changed (see the laptop-side comment), so
// this only trips on a genuinely stuck/disconnected laptop.
const OFFLINE_AFTER_MS = 45_000;
const SNAPSHOT_PUSH_INTERVAL_MS = 10_000;
const MAX_BODY_BYTES = 1_000_000;

// hostname -> latest reported fields + lastSeen (epoch ms)
const laptops = new Map();
const dashboards = new Set();

// Who's-viewing tracking. "name" is self-reported by the browser (typed
// into the login form) -- there's no per-person auth here, just a shared
// password, so this is purely for staff visibility ("who's got the
// dashboard open right now"), not access control. viewerLog is a capped
// ring buffer of connect/disconnect events; in-memory only, resets on
// redeploy -- same tradeoff as loginAttempts above, fine for this threat
// model.
const MAX_VIEWER_LOG = 300;
const viewerLog = [];

function pushViewerLog(entry) {
  viewerLog.push(entry);
  if (viewerLog.length > MAX_VIEWER_LOG) viewerLog.shift();
}

function currentViewers() {
  const out = [];
  for (const ws of dashboards) {
    if (ws.viewerMeta) out.push({ ...ws.viewerMeta });
  }
  return out;
}

function broadcastViewers() {
  const payload = JSON.stringify({
    type: 'viewers',
    current: currentViewers(),
    log: viewerLog.slice(-50).reverse(),
  });
  for (const ws of dashboards) {
    if (ws.readyState === ws.OPEN) ws.send(payload);
  }
}

function tokenMatches(supplied, expected) {
  if (!supplied || !expected) return false;
  const a = Buffer.from(supplied);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ── Login rate limiting — these two endpoints hand out real secrets
// (one of them full write access to the fleet code repo), so brute
// forcing the password can't be allowed to run unthrottled. Per-IP:
// 20 attempts per 10-minute window, then 429 regardless of correctness
// until the window rolls over. Raised from an initial 5 -- many staff
// share a small number of office/NAT IPs, so a tight per-IP cap was
// hitting real users, not just abuse. In-memory only -- resets on
// redeploy, which is fine for this threat model.
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 20;
const loginAttempts = new Map(); // ip -> { count, windowStart }

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function rateLimited(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (!rec || now - rec.windowStart > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { count: 1, windowStart: now });
    return false;
  }
  rec.count += 1;
  return rec.count > LOGIN_MAX_ATTEMPTS;
}

function extractToken(req, urlObj) {
  const header = req.headers['authorization'] || '';
  if (header.startsWith('Bearer ')) return header.slice(7);
  return urlObj.searchParams.get('token');
}

function snapshot() {
  const now = Date.now();
  const out = {};
  for (const [hostname, data] of laptops) {
    out[hostname] = {
      ...data,
      online: (now - data.lastSeen) < OFFLINE_AFTER_MS,
      ...(lookupTeamViewer(hostname) || {}),
    };
  }
  return out;
}

function broadcastUpdate(hostname) {
  const entry = laptops.get(hostname);
  const payload = JSON.stringify({
    type: 'update',
    hostname,
    data: { ...entry, online: true, ...(lookupTeamViewer(hostname) || {}) },
  });
  for (const ws of dashboards) {
    if (ws.readyState === ws.OPEN) ws.send(payload);
  }
}

function broadcastSnapshot() {
  const payload = JSON.stringify({ type: 'snapshot', data: snapshot() });
  for (const ws of dashboards) {
    if (ws.readyState === ws.OPEN) ws.send(payload);
  }
}

function withCors(res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function readJsonBody(req, onDone) {
  let body = '';
  let tooLarge = false;
  req.on('data', (chunk) => {
    body += chunk;
    if (body.length > MAX_BODY_BYTES) { tooLarge = true; req.destroy(); }
  });
  req.on('end', () => {
    if (tooLarge) return onDone(null);
    try { onDone(JSON.parse(body)); } catch { onDone(null); }
  });
}

const server = http.createServer((req, res) => {
  let urlObj;
  try {
    urlObj = new URL(req.url, `http://${req.headers.host}`);
  } catch {
    res.writeHead(400); res.end('bad url'); return;
  }

  if (req.method === 'GET' && urlObj.pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  if (req.method === 'OPTIONS' && (urlObj.pathname === '/login' || urlObj.pathname === '/sender-login')) {
    withCors(res);
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === 'POST' && urlObj.pathname === '/login') {
    withCors(res);
    if (!DASHBOARD_LOGIN_PASSWORD || !RELAY_DASHBOARD_URL) {
      res.writeHead(404); res.end('not configured'); return;
    }
    const ip = clientIp(req);
    if (rateLimited(ip)) { res.writeHead(429); res.end('too many attempts'); return; }
    readJsonBody(req, (payload) => {
      const userOk = payload && String(payload.username || '') === LOGIN_USERNAME;
      const passOk = payload && tokenMatches(String(payload.password || ''), DASHBOARD_LOGIN_PASSWORD);
      if (!userOk || !passOk) { res.writeHead(401); res.end(JSON.stringify({ error: 'invalid username or password' })); return; }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ relayUrl: RELAY_DASHBOARD_URL, relayToken: TOKEN }));
    });
    return;
  }

  if (req.method === 'POST' && urlObj.pathname === '/sender-login') {
    withCors(res);
    if (!SENDER_LOGIN_PASSWORD || !SENDER_GITHUB_TOKEN) {
      res.writeHead(404); res.end('not configured'); return;
    }
    const ip = clientIp(req);
    if (rateLimited(ip)) { res.writeHead(429); res.end('too many attempts'); return; }
    readJsonBody(req, (payload) => {
      const userOk = payload && String(payload.username || '') === LOGIN_USERNAME;
      const passOk = payload && tokenMatches(String(payload.password || ''), SENDER_LOGIN_PASSWORD);
      if (!userOk || !passOk) { res.writeHead(401); res.end(JSON.stringify({ error: 'invalid username or password' })); return; }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ githubToken: SENDER_GITHUB_TOKEN }));
    });
    return;
  }

  if (req.method === 'POST' && urlObj.pathname === '/report') {
    if (!tokenMatches(extractToken(req, urlObj), TOKEN)) {
      res.writeHead(401); res.end('unauthorized'); return;
    }
    let body = '';
    let tooLarge = false;
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > MAX_BODY_BYTES) {
        tooLarge = true;
        req.destroy();
      }
    });
    req.on('end', () => {
      if (tooLarge) return;
      let payload;
      try {
        payload = JSON.parse(body);
      } catch {
        res.writeHead(400); res.end('bad json'); return;
      }
      const hostname = String(payload.hostname || '').trim().slice(0, 128);
      if (!hostname) {
        res.writeHead(400); res.end('missing hostname'); return;
      }
      const { hostname: _drop, ...fields } = payload;
      // Merge, don't replace -- statusbar.py (GPS fields, every few
      // seconds) and update_kiosk.py (version/update fields, every ~2h)
      // both report under the same hostname key, and a wholesale
      // replace here would let whichever reports last wipe out the
      // other's fields.
      const existing = laptops.get(hostname) || {};
      laptops.set(hostname, { ...existing, ...fields, lastSeen: Date.now() });
      snapshotDirty = true;
      broadcastUpdate(hostname);
      res.writeHead(204);
      res.end();
    });
    return;
  }

  if (req.method === 'GET' && urlObj.pathname === '/snapshot') {
    if (!tokenMatches(extractToken(req, urlObj), TOKEN)) {
      res.writeHead(401); res.end('unauthorized'); return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(snapshot()));
    return;
  }

  if (req.method === 'DELETE' && urlObj.pathname === '/report') {
    if (!tokenMatches(extractToken(req, urlObj), TOKEN)) {
      res.writeHead(401); res.end('unauthorized'); return;
    }
    const hostname = urlObj.searchParams.get('hostname');
    if (!hostname) { res.writeHead(400); res.end('missing hostname'); return; }
    laptops.delete(hostname);
    snapshotDirty = true;
    broadcastSnapshot();
    res.writeHead(204);
    res.end();
    return;
  }

  res.writeHead(404);
  res.end('not found');
});

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const urlObj = new URL(req.url, `http://${req.headers.host}`);
  if (urlObj.pathname !== '/dashboard' || !tokenMatches(extractToken(req, urlObj), TOKEN)) {
    socket.destroy();
    return;
  }
  // A name is mandatory -- this also doubles as a forced-logout mechanism:
  // any tab still running pre-name-field client code (already open before
  // this deploy) reconnects without a &name= param and gets rejected here,
  // instead of silently resuming with its old cached token.
  const name = String(urlObj.searchParams.get('name') || '').trim().slice(0, 60);
  if (!name) {
    socket.destroy();
    return;
  }
  const ip = clientIp(req);
  const userAgent = String(req.headers['user-agent'] || 'unknown').slice(0, 300);
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.viewerMeta = { name, ip, userAgent, connectedAt: Date.now() };
    dashboards.add(ws);
    pushViewerLog({ name, ip, userAgent, event: 'connect', ts: Date.now() });
    ws.send(JSON.stringify({ type: 'snapshot', data: snapshot() }));
    broadcastViewers();
    ws.on('close', () => {
      dashboards.delete(ws);
      pushViewerLog({ name, ip, userAgent, event: 'disconnect', ts: Date.now() });
      broadcastViewers();
    });
    ws.on('error', () => dashboards.delete(ws));
  });
});

// Periodic snapshot push so a laptop that silently stopped reporting
// (crashed, lost network) flips to "offline" in the UI without waiting
// for a /report that will never come.
setInterval(broadcastSnapshot, SNAPSHOT_PUSH_INTERVAL_MS);

refreshTeamViewerDevices();
setInterval(refreshTeamViewerDevices, TEAMVIEWER_REFRESH_MS);

setInterval(saveLaptopsSnapshot, SNAPSHOT_WRITE_INTERVAL_MS);

// Render sends SIGTERM before killing the old instance on a redeploy --
// this is the case that actually matters (it's what wiped the fleet map
// last time), so it gets one last synchronous-ish save attempt instead of
// waiting for the periodic interval to maybe not fire in time.
async function shutdown(signal) {
  console.log(`${signal} received — saving fleet snapshot before exit...`);
  snapshotDirty = true;
  try {
    await saveLaptopsSnapshot();
  } catch (e) {
    console.error('Shutdown snapshot save failed:', e.message);
  }
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

(async () => {
  await loadLaptopsSnapshot();
  server.listen(PORT, () => {
    console.log(`gps relay listening on :${PORT}`);
  });
})();
