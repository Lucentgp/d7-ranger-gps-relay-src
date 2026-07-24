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

// A laptop that hasn't reported in this long is shown offline. statusbar.py
// heartbeats even when nothing changed (see the laptop-side comment), so
// this only trips on a genuinely stuck/disconnected laptop.
const OFFLINE_AFTER_MS = 45_000;
const SNAPSHOT_PUSH_INTERVAL_MS = 10_000;
const MAX_BODY_BYTES = 1_000_000;

// hostname -> latest reported fields + lastSeen (epoch ms)
const laptops = new Map();
const dashboards = new Set();

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
    out[hostname] = { ...data, online: (now - data.lastSeen) < OFFLINE_AFTER_MS };
  }
  return out;
}

function broadcastUpdate(hostname) {
  const entry = laptops.get(hostname);
  const payload = JSON.stringify({
    type: 'update',
    hostname,
    data: { ...entry, online: true },
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
  wss.handleUpgrade(req, socket, head, (ws) => {
    dashboards.add(ws);
    ws.send(JSON.stringify({ type: 'snapshot', data: snapshot() }));
    ws.on('close', () => dashboards.delete(ws));
    ws.on('error', () => dashboards.delete(ws));
  });
});

// Periodic snapshot push so a laptop that silently stopped reporting
// (crashed, lost network) flips to "offline" in the UI without waiting
// for a /report that will never come.
setInterval(broadcastSnapshot, SNAPSHOT_PUSH_INTERVAL_MS);

server.listen(PORT, () => {
  console.log(`gps relay listening on :${PORT}`);
});
