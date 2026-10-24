'use strict';
const crypto = require('node:crypto');
const { HttpError, nowIso } = require('../util');
const { parseCookies } = require('../http');

const COOKIE = 'tv_sid';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)); const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

/**
 * Sessions are rows in the database, not self-contained tokens. That is what makes "take access away
 * immediately" real: disabling a user or changing a password deletes their rows, and the very next request
 * carrying the old cookie finds nothing. (A signed JWT would stay valid until it expired.)
 */
module.exports = ({ db, cfg, models, audit }) => {
  const cookieName = cfg.cookieSecure ? `__Host-${COOKIE}` : COOKIE;

  function cookieHeader(value, maxAgeSec) {
    const parts = [`${cookieName}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAgeSec}`];
    if (cfg.cookieSecure) parts.push('Secure');
    return parts.join('; ');
  }

  function createSession(ctx, user) {
    const token = crypto.randomBytes(32).toString('base64url');
    const csrf = crypto.randomBytes(24).toString('base64url');
    const now = nowIso();
    const expires = new Date(Date.now() + cfg.sessionMaxHours * 3600e3).toISOString();
    db.prepare('INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(sha(token), user.id, csrf, now, now, expires, ctx.ip, String(ctx.req.headers['user-agent'] || '').slice(0, 200));
    ctx.res.setHeader('Set-Cookie', cookieHeader(token, cfg.sessionMaxHours * 3600));
    return csrf;
  }

  const destroyAllForUser = (userId) => db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId).changes;
  const destroyOthers = (userId, idHash) => db.prepare('DELETE FROM sessions WHERE user_id = ? AND id_hash <> ?').run(userId, idHash).changes;

  function destroyCurrent(ctx) {
    if (ctx.session) db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(ctx.session.idHash);
    ctx.res.setHeader('Set-Cookie', cookieHeader('', 0));
  }

  /** Looks the session up fresh, every time. Used on entry and again right before any write. */
  function lookup(idHash) {
    const row = db.prepare(
      `SELECT s.id_hash, s.csrf_token, s.last_seen, s.expires_at, u.id, u.email, u.name, u.role, u.disabled
         FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?`
    ).get(idHash);
    if (!row) return null;
    const now = Date.now();
    if (Date.parse(row.expires_at) <= now || Date.parse(row.last_seen) + cfg.sessionIdleMinutes * 60e3 <= now || row.disabled) return null;
    return row;
  }

  function stillValid(ctx) {
    return Boolean(ctx.session && lookup(ctx.session.idHash));
  }

  /** Default for every /api route except the explicit public list (see app.js). */
  function required(ctx) {
    const token = parseCookies(ctx.req.headers.cookie)[cookieName];
    if (!token || token.length > 100) throw new HttpError(401, 'unauthenticated', 'Sign in required');
    const idHash = sha(token);
    const row = lookup(idHash);
    if (!row) {
      db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
      throw new HttpError(401, 'unauthenticated', 'Sign in required');
    }
    if (Date.now() - Date.parse(row.last_seen) > 15e3) db.prepare('UPDATE sessions SET last_seen = ? WHERE id_hash = ?').run(nowIso(), idHash);
    ctx.user = { id: row.id, email: row.email, name: row.name, role: row.role, disabled: row.disabled };
    ctx.session = { idHash, csrf: row.csrf_token };
  }

  /** State-changing requests must carry the per-session token, which a cross-site page cannot read. */
  function csrf(ctx) {
    if (ctx.req.method === 'GET' || ctx.req.method === 'HEAD') return;
    const sent = ctx.req.headers['x-csrf-token'];
    if (typeof sent !== 'string' || !safeEq(sent, ctx.session.csrf)) {
      audit.append({ actor: ctx.user, action: 'csrf_failure', outcome: 'denied', ip: ctx.ip, detail: { path: ctx.url.pathname, method: ctx.req.method } });
      throw new HttpError(403, 'csrf', 'Missing or wrong CSRF token');
    }
  }

  const requireRole = (...roles) => {
    const fn = (ctx) => {
      if (!roles.includes(ctx.user.role)) {
        audit.append({ actor: ctx.user, action: 'access_denied', outcome: 'denied', ip: ctx.ip, detail: { reason: 'role', needed: roles, path: ctx.url.pathname } });
        throw new HttpError(403, 'forbidden', 'Your role cannot do that');
      }
    };
    fn.roles = roles;
    return fn;
  };

  return { required, csrf, requireRole, createSession, destroyCurrent, destroyAllForUser, destroyOthers, stillValid, cookieName };
};
