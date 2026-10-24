'use strict';
const { nowIso, escapeLike } = require('../util');

module.exports = (db) => ({
  findById: (id) => db.prepare('SELECT * FROM documents WHERE id = ?').get(id) ?? null,

  currentVersion: (docId) =>
    db.prepare(
      `SELECT v.* FROM document_versions v
         JOIN documents d ON d.id = v.document_id AND d.current_version = v.version
        WHERE d.id = ?`
    ).get(docId) ?? null,

  versions: (docId) =>
    db.prepare(
      `SELECT v.version, v.size, v.sha256, v.created_at, u.email AS uploaded_by_email
         FROM document_versions v JOIN users u ON u.id = v.uploaded_by
        WHERE v.document_id = ? ORDER BY v.version DESC`
    ).all(docId),

  create({ id, ownerId, title, category, originalName, mime, file }) {
    const now = nowIso();
    db.prepare(
      `INSERT INTO documents (id, owner_id, title, category, original_name, mime, current_version, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`
    ).run(id, ownerId, title, category, originalName, mime, now, now);
    db.prepare(
      `INSERT INTO document_versions (document_id, version, storage_key, size, sha256, uploaded_by, created_at)
       VALUES (?, 1, ?, ?, ?, ?, ?)`
    ).run(id, file.storageKey, file.size, file.sha256, ownerId, now);
  },

  /** Adds a version. Refuses (returns null) if the document was deleted in the meantime. */
  addVersion(docId, { storageKey, size, sha256, uploadedBy, originalName, mime }) {
    const now = nowIso();
    const r = db.prepare(
      `UPDATE documents SET current_version = current_version + 1, updated_at = ?, original_name = ?, mime = ?
        WHERE id = ? AND deleted_at IS NULL`
    ).run(now, originalName, mime, docId);
    if (r.changes !== 1) return null;
    const { current_version: version } = db.prepare('SELECT current_version FROM documents WHERE id = ?').get(docId);
    db.prepare(
      `INSERT INTO document_versions (document_id, version, storage_key, size, sha256, uploaded_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(docId, version, storageKey, size, sha256, uploadedBy, now);
    return version;
  },

  updateMeta: (docId, { title, category }) =>
    db.prepare('UPDATE documents SET title = ?, category = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL')
      .run(title, category, nowIso(), docId).changes,

  softDelete: (docId) =>
    db.prepare('UPDATE documents SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL')
      .run(nowIso(), nowIso(), docId).changes,

  restore: (docId) =>
    db.prepare('UPDATE documents SET deleted_at = NULL, updated_at = ? WHERE id = ? AND deleted_at IS NOT NULL')
      .run(nowIso(), docId).changes,

  /**
   * Search within what `access` (from permission.service.accessPredicate) allows. The access predicate is
   * ALWAYS part of the WHERE clause, so a filter can never widen the result set beyond what the person may read.
   */
  search(user, f, access, now = nowIso()) {
    const where = [];
    const wp = [];
    if (f.scope === 'trash') {
      where.push('d.owner_id = ? AND d.deleted_at IS NOT NULL');
      wp.push(user.id);
    } else {
      where.push(access.sql);
      wp.push(...access.params);
      if (f.scope === 'mine') { where.push('d.owner_id = ?'); wp.push(user.id); }
      if (f.scope === 'shared') { where.push('d.owner_id <> ?'); wp.push(user.id); }
    }
    if (f.q) {
      where.push("(d.title LIKE ? ESCAPE '\\' OR d.original_name LIKE ? ESCAPE '\\')");
      const like = `%${escapeLike(f.q)}%`;
      wp.push(like, like);
    }
    if (f.owner) {
      where.push("(u.email LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\')");
      const like = `%${escapeLike(f.owner)}%`;
      wp.push(like, like);
    }
    if (f.category) { where.push('d.category = ? COLLATE NOCASE'); wp.push(f.category); }
    if (f.from) { where.push('d.created_at >= ?'); wp.push(`${f.from}T00:00:00.000Z`); }
    if (f.to) {
      where.push('d.created_at < ?');
      wp.push(new Date(Date.parse(`${f.to}T00:00:00.000Z`) + 86400000).toISOString());
    }
    const sql = `
      SELECT d.id, d.title, d.category, d.original_name, d.mime, d.current_version, d.created_at, d.updated_at,
             d.deleted_at, u.email AS owner_email, u.name AS owner_name, v.size,
             CASE WHEN d.owner_id = ? THEN 'owner'
                  ELSE (SELECT g.level FROM grants g
                         WHERE g.document_id = d.id AND g.user_id = ? AND g.revoked_at IS NULL
                           AND (g.expires_at IS NULL OR g.expires_at > ?)) END AS access
        FROM documents d
        JOIN users u ON u.id = d.owner_id
        JOIN document_versions v ON v.document_id = d.id AND v.version = d.current_version
       WHERE ${where.join(' AND ')}
       ORDER BY d.updated_at DESC
       LIMIT ? OFFSET ?`;
    const rows = db.prepare(sql).all(user.id, user.id, now, ...wp, f.limit, f.offset);
    // A viewer-role account can never exceed read, even if an edit grant row somehow exists.
    return rows.map((r) => (user.role === 'viewer' && r.access === 'edit' ? { ...r, access: 'read' } : r));
  },

  /** Metadata only, for the administrator. No content access, no storage keys. */
  listForAdmin: ({ limit, offset }) =>
    db.prepare(
      `SELECT d.id, d.title, d.category, d.created_at, d.updated_at, d.deleted_at, u.email AS owner_email,
              v.size, d.current_version,
              (SELECT COUNT(*) FROM grants g WHERE g.document_id = d.id AND g.revoked_at IS NULL) AS active_grants
         FROM documents d JOIN users u ON u.id = d.owner_id
         JOIN document_versions v ON v.document_id = d.id AND v.version = d.current_version
        ORDER BY d.updated_at DESC LIMIT ? OFFSET ?`
    ).all(limit, offset),

  expiredDeleted: (cutoffIso) =>
    db.prepare('SELECT id FROM documents WHERE deleted_at IS NOT NULL AND deleted_at < ?').all(cutoffIso),

  storageKeys: (docId) => db.prepare('SELECT storage_key FROM document_versions WHERE document_id = ?').all(docId),

  hardDelete(docId) {
    db.prepare('DELETE FROM suggestions WHERE document_id = ?').run(docId);
    db.prepare('DELETE FROM grants WHERE document_id = ?').run(docId);
    db.prepare('DELETE FROM document_versions WHERE document_id = ?').run(docId);
    db.prepare('DELETE FROM documents WHERE id = ?').run(docId);
  },
});
