'use strict';
const { newId, nowIso } = require('../util');

module.exports = (db) => ({
  /** The live grant for (document, user), or null. "Live" = not revoked and not expired. Read fresh on every request. */
  active(docId, userId, now = nowIso()) {
    return db.prepare(
      `SELECT * FROM grants
        WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > ?)`
    ).get(docId, userId, now) ?? null;
  },

  listActive(docId, now = nowIso()) {
    return db.prepare(
      `SELECT g.user_id, u.email, u.name, u.role, g.level, g.created_at, g.expires_at, g.granted_by
         FROM grants g JOIN users u ON u.id = g.user_id
        WHERE g.document_id = ? AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > ?)
        ORDER BY g.created_at`
    ).all(docId, now);
  },

  history(docId) {
    return db.prepare(
      `SELECT g.user_id, u.email, g.level, g.created_at, g.expires_at, g.revoked_at
         FROM grants g JOIN users u ON u.id = g.user_id
        WHERE g.document_id = ? ORDER BY g.created_at DESC LIMIT 200`
    ).all(docId);
  },

  /** Create or change the single live grant. Returns 'created' | 'updated'. */
  upsert({ docId, userId, level, grantedBy, expiresAt }) {
    const existing = db.prepare(
      'SELECT id FROM grants WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL'
    ).get(docId, userId);
    if (existing) {
      db.prepare('UPDATE grants SET level = ?, expires_at = ?, granted_by = ? WHERE id = ?')
        .run(level, expiresAt, grantedBy, existing.id);
      return 'updated';
    }
    db.prepare(
      `INSERT INTO grants (id, document_id, user_id, level, granted_by, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(newId(), docId, userId, level, grantedBy, nowIso(), expiresAt);
    return 'created';
  },

  /** Revoke the live grant. Returns number of rows changed (0 = nothing to revoke). */
  revoke(docId, userId, revokedBy) {
    return db.prepare(
      'UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL'
    ).run(nowIso(), revokedBy, docId, userId).changes;
  },

  revokeAllForUser: (userId, revokedBy) =>
    db.prepare('UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE user_id = ? AND revoked_at IS NULL')
      .run(nowIso(), revokedBy, userId).changes,

  /** Everyone who has ever had access to this owner's other documents in a category (used by the suggester). */
  peersForOwnerCategory(ownerId, category, excludeDocId) {
    return db.prepare(
      `SELECT u.id, u.email, u.name, u.role, COUNT(DISTINCT g.document_id) AS shared_docs, MAX(g.level) AS top_level
         FROM grants g
         JOIN documents d ON d.id = g.document_id
         JOIN users u ON u.id = g.user_id
        WHERE d.owner_id = ? AND d.category = ? COLLATE NOCASE AND d.id <> ? AND u.disabled = 0
        GROUP BY u.id ORDER BY shared_docs DESC LIMIT 10`
    ).all(ownerId, category, excludeDocId);
  },
});
