'use strict';
/**
 * Minimal HTTP toolkit (router, body readers, cookies, rate limiter, security headers).
 * Written against node:http so the whole system has zero third-party runtime dependencies.
 */
const { HttpError, isId } = require('./util');

class Router {
  constructor() { this.routes = []; }
  add(method, pattern, ...handlers) {
    const keys = [];
    const re = new RegExp(`^${pattern.replace(/:([a-zA-Z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; })}$`);
    this.routes.push({ method, re, keys, handlers });
  }
  get(p, ...h) { this.add('GET', p, ...h); }
  post(p, ...h) { this.add('POST', p, ...h); }
  put(p, ...h) { this.add('PUT', p, ...h); }
  patch(p, ...h) { this.add('PATCH', p, ...h); }
  delete(p, ...h) { this.add('DELETE', p, ...h); }

  match(method, pathname) {
    let pathMatched = false;
    for (const r of this.routes) {
      const m = r.re.exec(pathname);
      if (!m) continue;
      pathMatched = true;
      if (r.method !== method) continue;
      const params = {};
      r.keys.forEach((k, i) => {
        try { params[k] = decodeURIComponent(m[i + 1]); } catch { params[k] = '\u0000bad'; }
      });
      return { route: r, params };
    }
    return { route: null, pathMatched };
  }
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) {
      req.resume();
      return reject(new HttpError(413, 'too_large', 'Request body is too large'));
    }
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', (c) => {
      if (done) return;
      size += c.length;
      if (size > maxBytes) {
        done = true;
        chunks.length = 0;
        req.resume();
        reject(new HttpError(413, 'too_large', 'Request body is too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => { if (!done) { done = true; resolve(Buffer.concat(chunks)); } });
    req.on('error', (e) => { if (!done) { done = true; reject(e); } });
    req.on('aborted', () => { if (!done) { done = true; reject(new HttpError(400, 'aborted', 'Request aborted')); } });
  });
}

async function readJson(req, maxBytes = 64 * 1024) {
  const ct = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'application/json') throw new HttpError(415, 'unsupported_media_type', 'Content-Type must be application/json');
  const buf = await readBody(req, maxBytes);
  if (buf.length === 0) return {};
  let v;
  try { v = JSON.parse(buf.toString('utf8')); } catch { throw new HttpError(400, 'bad_json', 'Body is not valid JSON'); }
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new HttpError(400, 'bad_json', 'Body must be a JSON object');
  return v;
}

/** Fixed-window in-memory limiter. Per-process: documented limitation, fine for a single instance. */
class RateLimiter {
  constructor(max, windowMs) {
    this.max = max; this.windowMs = windowMs; this.hits = new Map();
    this.timer = setInterval(() => this.sweep(), windowMs).unref();
  }
  sweep() { const now = Date.now(); for (const [k, v] of this.hits) if (v.reset <= now) this.hits.delete(k); }
  take(key) {
    const now = Date.now();
    let e = this.hits.get(key);
    if (!e || e.reset <= now) { e = { n: 0, reset: now + this.windowMs }; this.hits.set(key, e); }
    e.n += 1;
    return { ok: e.n <= this.max, retryAfter: Math.ceil((e.reset - now) / 1000) };
  }
  stop() { clearInterval(this.timer); }
}

const CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:",
  "connect-src 'self'", "form-action 'self'", "base-uri 'none'", "frame-ancestors 'none'",
].join('; ');

function baseHeaders(res, cfg) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (cfg.cookieSecure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

function sendJson(res, status, body, extra = {}) {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': buf.length, 'Cache-Control': 'no-store', ...extra });
  res.end(buf);
}

function clientIp(req, trustProxy) {
  if (trustProxy) {
    const xf = req.headers['x-forwarded-for'];
    if (xf) { const parts = String(xf).split(',').map((s) => s.trim()); return parts[parts.length - 1]; }
  }
  return req.socket.remoteAddress || 'unknown';
}

/** Route params that name records must be well-formed ids before any handler sees them. */
function paramsAreIds(params) {
  for (const k of ['id', 'userId', 'version', 'sid']) {
    if (k in params) {
      if (k === 'version') { if (!/^\d{1,6}$/.test(params[k])) return false; } else if (!isId(params[k])) return false;
    }
  }
  return true;
}

module.exports = { Router, parseCookies, readBody, readJson, RateLimiter, baseHeaders, sendJson, clientIp, paramsAreIds };
