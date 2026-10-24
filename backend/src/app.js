'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { loadConfig } = require('./config/env');
const { openDb } = require('./config/db');
const { HttpError } = require('./util');
const { Router, RateLimiter, baseHeaders, sendJson, clientIp, paramsAreIds } = require('./http');

const userModel = require('./models/User');
const documentModel = require('./models/Document');
const grantModel = require('./models/Grant');
const auditModel = require('./models/AuditEvent');

// The ONLY /api routes reachable without a session. Everything else is authenticated + CSRF-checked by default.
const PUBLIC = new Set(['POST /api/auth/login', 'POST /api/auth/register']);
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };
const DOC_PATH = /^\/api\/documents\/([0-9a-f-]{36})(?:\/|$)/;

function createApp(overrides = {}) {
  const cfg = loadConfig(overrides);
  const db = openDb(cfg.dbFile);
  const models = { user: userModel(db), document: documentModel(db), grant: grantModel(db), audit: auditModel(db) };
  const svc = { cfg, db, models };
  svc.audit = require('./services/audit.service')(svc);
  svc.storage = require('./services/storage.service')(svc);
  svc.password = require('./services/password')(cfg);
  svc.auth = require('./middleware/authenticate')(svc);
  svc.permissions = require('./services/permission.service')(svc);
  svc.limiters = {
    login: new RateLimiter(cfg.loginRatePerMinute, 60e3),
    api: new RateLimiter(cfg.apiRatePerMinute, 60e3),
    upload: new RateLimiter(60, 60e3),
  };
  const G = require('./middleware/authorizeDocument')(svc);

  const R = new Router();
  require('./routes/auth.routes')(R, svc);
  require('./routes/document.routes')(R, svc, G);
  require('./routes/grant.routes')(R, svc, G);
  require('./routes/audit.routes')(R, svc, G);

  // Structural default-deny: a route that names a document must run the document guard, or the server will not start.
  for (const r of R.routes) {
    if (r.re.source.includes('([^/]+)') && r.keys.includes('id') && !r.handlers.some((h) => h.guards === 'document')) {
      throw new Error(`Route ${r.method} ${r.re.source} takes a document :id but has no authorizeDocument() guard`);
    }
  }

  // ---- static front end: an allow-list built once at startup, so there is no path to traverse ----------
  const statics = new Map();
  (function walk(dir, prefix) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) walk(path.join(dir, e.name), `${prefix}${e.name}/`);
      else if (MIME[path.extname(e.name)]) statics.set(`/${prefix}${e.name}`, path.join(dir, e.name));
    }
  }(cfg.frontendDir, ''));

  function serveStatic(req, res, pathname) {
    if (pathname === '/healthz') { res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' }); return res.end('ok'); }
    if (pathname === '/') { res.writeHead(302, { Location: '/login.html' }); return res.end(); }
    const file = statics.get(pathname);
    if (!file) throw new HttpError(404, 'not_found', 'Not found');
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'method_not_allowed', 'Method not allowed');
    const buf = fs.readFileSync(file);
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)], 'Content-Length': buf.length, 'Cache-Control': 'no-cache' });
    return res.end(req.method === 'HEAD' ? undefined : buf);
  }

  async function api(req, res, url, ip) {
    const ctx = { req, res, url, ip, params: {}, status: 200, svc };
    const rl = svc.limiters.api.take(ip);
    if (!rl.ok) { res.setHeader('Retry-After', String(rl.retryAfter)); throw new HttpError(429, 'rate_limited', 'Too many requests'); }

    const { route, params, pathMatched } = R.match(req.method, url.pathname);
    if (!route) throw pathMatched ? new HttpError(405, 'method_not_allowed', 'Method not allowed') : new HttpError(404, 'not_found', 'Not found');
    ctx.params = params;

    const mutating = req.method !== 'GET' && req.method !== 'HEAD';
    const origin = req.headers.origin;
    if (mutating && origin) {
      let ok = false;
      try { ok = new URL(origin).host === req.headers.host; } catch { /* malformed */ }
      if (!ok) throw new HttpError(403, 'bad_origin', 'Cross-origin request refused');
    }

    if (!PUBLIC.has(`${req.method} ${url.pathname}`)) {
      try {
        svc.auth.required(ctx);
      } catch (e) {
        const m = DOC_PATH.exec(url.pathname);
        if (m && e.status === 401) svc.audit.append({ action: 'access_denied', outcome: 'denied', documentId: m[1], ip, detail: { reason: 'unauthenticated', method: req.method } });
        throw e;
      }
      svc.auth.csrf(ctx);
    }
    if (!paramsAreIds(params)) throw new HttpError(400, 'invalid_id', 'Malformed identifier');

    for (const h of route.handlers) {
      const out = await h(ctx);
      if (ctx.raw || res.writableEnded) return;
      if (out !== undefined) return sendJson(res, ctx.status, out);
    }
    if (!ctx.raw && !res.writableEnded) { res.writeHead(204); res.end(); }
  }

  async function handler(req, res) {
    baseHeaders(res, cfg);
    try {
      let url;
      try { url = new URL(req.url, 'http://localhost'); } catch { throw new HttpError(400, 'bad_url', 'Bad URL'); }
      const ip = clientIp(req, cfg.trustProxy);
      if (url.pathname.startsWith('/api/')) await api(req, res, url, ip);
      else serveStatic(req, res, url.pathname);
    } catch (e) {
      if (res.headersSent) { res.destroy(); return; }
      if (e instanceof HttpError) {
        return sendJson(res, e.status, { error: { code: e.code, message: e.message } });
      }
      console.error('Unhandled error:', e);
      return sendJson(res, 500, { error: { code: 'internal', message: 'Something went wrong' } });
    }
  }

  // ---- housekeeping: purge trash past retention, expire old sessions ------------------------------------
  function purgeExpired() {
    const cutoff = new Date(Date.now() - cfg.retentionDays * 86400e3).toISOString();
    for (const { id } of models.document.expiredDeleted(cutoff)) {
      const keys = models.document.storageKeys(id).map((k) => k.storage_key);
      db.tx(() => {
        models.document.hardDelete(id);
        svc.audit.append({ action: 'purge', documentId: id, detail: { files: keys.length, reason: `deleted more than ${cfg.retentionDays} days ago` } });
      });
      keys.forEach((k) => svc.storage.remove(k));
    }
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(new Date().toISOString());
  }
  purgeExpired();
  const timer = setInterval(() => { try { purgeExpired(); } catch (e) { console.error('purge failed', e.message); } }, 3600e3).unref();

  return {
    handler, cfg, db, svc, router: R, purgeExpired,
    close() { clearInterval(timer); Object.values(svc.limiters).forEach((l) => l.stop()); db.close(); },
  };
}

module.exports = { createApp, PUBLIC };
