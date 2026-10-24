'use strict';
const { newId, nowIso } = require('../util');

const PUBLIC_COLS = 'id, email, name, role, disabled, created_at, locked_until';

module.exports = (db) => ({
  findById: (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id) ?? null,
  findByEmail: (email) => db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(email) ?? null,
  count: () => db.prepare('SELECT COUNT(*) AS n FROM users').get().n,
  list: () => db.prepare(`SELECT ${PUBLIC_COLS} FROM users ORDER BY created_at`).all(),

  create({ email, name, role, passwordHash }) {
    const id = newId();
    const now = nowIso();
    db.prepare(
      `INSERT INTO users (id, email, name, role, password_hash, created_at, password_changed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(id, email, name, role, passwordHash, now, now);
    return id;
  },

  setDisabled: (id, disabled) => db.prepare('UPDATE users SET disabled = ? WHERE id = ?').run(disabled ? 1 : 0, id),
  setRole: (id, role) => db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id),
  setPassword: (id, hash) =>
    db.prepare('UPDATE users SET password_hash = ?, password_changed_at = ?, failed_logins = 0, locked_until = NULL WHERE id = ?')
      .run(hash, nowIso(), id),

  recordFailure(id, threshold, lockMinutes) {
    const u = db.prepare('SELECT failed_logins FROM users WHERE id = ?').get(id);
    const fails = (u?.failed_logins ?? 0) + 1;
    const lockedUntil = fails >= threshold ? new Date(Date.now() + lockMinutes * 60000).toISOString() : null;
    db.prepare('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?')
      .run(fails >= threshold ? 0 : fails, lockedUntil, id);
    return { locked: Boolean(lockedUntil) };
  },
  clearFailures: (id) => db.prepare('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?').run(id),

  activeAdminCount: () => db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0").get().n,
  ownedLiveDocCount: (id) =>
    db.prepare('SELECT COUNT(*) AS n FROM documents WHERE owner_id = ? AND deleted_at IS NULL').get(id).n,
});
