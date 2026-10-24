'use strict';
const crypto = require('node:crypto');
const { HttpError, isId, cleanText, cleanEmail, nowIso } = require('../util');
const { readJson } = require('../http');

const ROLES = ['admin', 'owner', 'viewer'];

module.exports = (R, svc) => {
  const { db, cfg, models, audit, auth, password, limiters } = svc;
  const admin = auth.requireRole('admin');
  const publicUser = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role });

  // ---- public ------------------------------------------------------------------------------------------
  R.post('/api/auth/login', async (ctx) => {
    const lim = limiters.login.take(ctx.ip);
    if (!lim.ok) {
      ctx.res.setHeader('Retry-After', String(lim.retryAfter));
      throw new HttpError(429, 'rate_limited', 'Too many attempts, slow down');
    }
    const body = await readJson(ctx.req);
    let email;
    try { email = cleanEmail(body.email); } catch { email = null; }
    const pw = typeof body.password === 'string' && body.password.length <= 256 ? body.password : '';
    const user = email ? models.user.findByEmail(email) : null;
    const locked = Boolean(user?.locked_until && Date.parse(user.locked_until) > Date.now());
    // Always do the same amount of hashing work whether or not the account exists.
    const passwordOk = await password.verify(pw, user?.password_hash);
    if (!user || !passwordOk || user.disabled || locked) {
      let reason = !user ? 'unknown_user' : locked ? 'locked' : user.disabled ? 'disabled' : 'bad_password';
      if (user && !locked && !user.disabled && !passwordOk) {
        if (models.user.recordFailure(user.id, cfg.lockoutThreshold, cfg.lockoutMinutes).locked) reason = 'bad_password_now_locked';
      }
      audit.append({ actor: user ? { id: user.id, email: user.email } : null, action: 'login_failed', outcome: 'denied', ip: ctx.ip, detail: { email: email ?? '(invalid)', reason } });
      throw new HttpError(401, 'invalid_credentials', 'Wrong email or password'); // identical for every cause
    }
    models.user.clearFailures(user.id);
    const csrf = db.tx(() => {
      const t = auth.createSession(ctx, user);
      audit.append({ actor: user, action: 'login_success', ip: ctx.ip, detail: { userAgent: String(ctx.req.headers['user-agent'] || '').slice(0, 120) } });
      return t;
    });
    return { user: publicUser(user), csrfToken: csrf };
  });

  R.post('/api/auth/register', async (ctx) => {
    const body = await readJson(ctx.req);
    const email = cleanEmail(body.email);
    const name = cleanText(body.name, { field: 'name', max: 100 });
    const role = body.role || 'viewer';
    if (!ROLES.includes(role)) {
      throw new HttpError(422, 'invalid_field', 'Role must be administrator, owner or viewer');
    }
    // Administrator sign-up is only possible with the server-side registration code (ADMIN_REGISTRATION_CODE).
    // With no code configured it is disabled entirely. Failures are audited.
    if (role === 'admin') {
      const expected = String(cfg.adminRegistrationCode || '');
      const given = String(body.adminCode ?? '');
      const sha = (s) => crypto.createHash('sha256').update(s).digest();
      const ok = expected.length >= 12 && crypto.timingSafeEqual(sha(given), sha(expected));
      if (!ok) {
        audit.append({ actor: null, action: 'access_denied', outcome: 'denied', ip: ctx.ip, detail: { reason: 'admin_registration', email } });
        throw new HttpError(403, 'admin_code_invalid', expected.length >= 12
          ? 'Invalid administrator registration code'
          : 'Administrator registration is not enabled on this server');
      }
    }
    password.checkPolicy(body.password, email);
    if (models.user.findByEmail(email)) {
      throw new HttpError(409, 'email_taken', 'An account with this email already exists');
    }
    const hash = await password.hash(body.password);
    const id = db.tx(() => {
      const userId = models.user.create({ email, name, role, passwordHash: hash });
      audit.append({ actor: null, targetUserId: userId, action: 'user_registered', ip: ctx.ip, detail: { email, role } });
      return userId;
    });
    ctx.status = 201;
    return { ok: true, id, email, name, role, message: 'Account created. Please sign in.' };
  });

  // ---- everyone signed in ------------------------------------------------------------------------------
  R.get('/api/auth/me', (ctx) => ({ user: publicUser(ctx.user), csrfToken: ctx.session.csrf }));

  R.post('/api/auth/logout', (ctx) => {
    db.tx(() => {
      audit.append({ actor: ctx.user, action: 'logout', ip: ctx.ip });
      auth.destroyCurrent(ctx);
    });
    return { ok: true };
  });

  R.post('/api/auth/password', async (ctx) => {
    const body = await readJson(ctx.req);
    const u = models.user.findById(ctx.user.id);
    if (!(await password.verify(String(body.currentPassword ?? ''), u.password_hash))) {
      audit.append({ actor: ctx.user, action: 'password_change_failed', outcome: 'denied', ip: ctx.ip, detail: {} });
      throw new HttpError(403, 'wrong_password', 'Current password is wrong');
    }
    password.checkPolicy(body.newPassword, u.email);
    const hash = await password.hash(body.newPassword);
    db.tx(() => {
      models.user.setPassword(u.id, hash);
      const killed = auth.destroyOthers(u.id, ctx.session.idHash); // every other device is signed out now
      audit.append({ actor: ctx.user, action: 'password_changed', ip: ctx.ip, detail: { otherSessionsEnded: killed } });
    });
    return { ok: true };
  });

  // Owners need to find people to share with. Name + email only, enabled accounts, min 2 chars, capped.
  R.get('/api/users/directory', auth.requireRole('owner'), (ctx) => {
    const q = String(ctx.url.searchParams.get('q') ?? '').trim();
    if (q.length < 2 || q.length > 100) throw new HttpError(422, 'invalid_field', 'q must be 2-100 characters');
    const like = `%${q.replace(/[\\%_]/g, '\\$&')}%`;
    return {
      users: db.prepare(
        `SELECT id, email, name, role FROM users WHERE disabled = 0 AND id <> ? AND role <> 'admin'
            AND (email LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\') ORDER BY email LIMIT 10`
      ).all(ctx.user.id, like, like),
    };
  });

  // ---- administrators: accounts (never document content) -----------------------------------------------
  R.get('/api/users', admin, () => ({ users: models.user.list() }));

  R.post('/api/users', admin, async (ctx) => {
    const b = await readJson(ctx.req);
    const email = cleanEmail(b.email);
    const name = cleanText(b.name, { field: 'name', max: 100 });
    if (!ROLES.includes(b.role)) throw new HttpError(422, 'invalid_field', `role must be one of ${ROLES.join(', ')}`);
    password.checkPolicy(b.password, email);
    if (models.user.findByEmail(email)) throw new HttpError(409, 'email_taken', 'That email is already registered');
    const hash = await password.hash(b.password);
    const id = db.tx(() => {
      const uid = models.user.create({ email, name, role: b.role, passwordHash: hash });
      audit.append({ actor: ctx.user, action: 'user_created', targetUserId: uid, ip: ctx.ip, detail: { email, role: b.role } });
      return uid;
    });
    ctx.status = 201;
    return { id, email, name, role: b.role };
  });

  R.patch('/api/users/:userId', admin, async (ctx) => {
    const b = await readJson(ctx.req);
    const target = models.user.findById(ctx.params.userId);
    if (!target) throw new HttpError(404, 'not_found', 'User not found');
    const changes = {};
    return db.tx(() => {
      if (b.role !== undefined) {
        if (!ROLES.includes(b.role)) throw new HttpError(422, 'invalid_field', 'invalid role');
        if (target.role === 'admin' && b.role !== 'admin' && !target.disabled && models.user.activeAdminCount() <= 1) throw new HttpError(409, 'last_admin', 'Cannot demote the last administrator');
        if (b.role === 'viewer' && models.user.ownedLiveDocCount(target.id) > 0) throw new HttpError(409, 'owns_documents', 'This user owns documents; they cannot become a viewer');
        if (b.role !== target.role) { models.user.setRole(target.id, b.role); changes.role = b.role; }
      }
      if (b.disabled !== undefined) {
        if (typeof b.disabled !== 'boolean') throw new HttpError(422, 'invalid_field', 'disabled must be true/false');
        if (b.disabled && target.id === ctx.user.id) throw new HttpError(409, 'self_disable', 'You cannot disable yourself');
        if (b.disabled && target.role === 'admin' && !target.disabled && models.user.activeAdminCount() <= 1) throw new HttpError(409, 'last_admin', 'Cannot disable the last administrator');
        if (Boolean(target.disabled) !== b.disabled) {
          models.user.setDisabled(target.id, b.disabled);
          changes.disabled = b.disabled;
          if (b.disabled) {
            changes.sessionsEnded = auth.destroyAllForUser(target.id);          // cookies die now
            changes.grantsRevoked = models.grant.revokeAllForUser(target.id, ctx.user.id); // access dies now
          }
        }
      }
      if (b.role !== undefined && changes.role) auth.destroyAllForUser(target.id); // role change = sign in again
      if (Object.keys(changes).length) {
        audit.append({ actor: ctx.user, action: changes.disabled ? 'user_disabled' : 'user_updated', targetUserId: target.id, ip: ctx.ip, detail: changes });
      }
      return { id: target.id, changes };
    });
  });
};
