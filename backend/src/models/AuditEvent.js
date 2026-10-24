'use strict';
const { escapeLike } = require('../util');

/** Read-side queries for the audit trail. Writes only ever go through audit.service (append + hash chain). */
module.exports = (db) => ({
  list(f) {
    const where = [];
    const p = [];
    if (f.action) { where.push('action = ?'); p.push(f.action); }
    if (f.outcome) { where.push('outcome = ?'); p.push(f.outcome); }
    if (f.actor) { where.push('(actor_email LIKE ? ESCAPE \'\\\' OR actor_id = ?)'); p.push(`%${escapeLike(f.actor)}%`, f.actor); }
    if (f.documentId) { where.push('document_id = ?'); p.push(f.documentId); }
    if (f.from) { where.push('ts >= ?'); p.push(`${f.from}T00:00:00.000Z`); }
    if (f.to) { where.push('ts < ?'); p.push(new Date(Date.parse(`${f.to}T00:00:00.000Z`) + 86400000).toISOString()); }
    const sql = `SELECT seq, ts, actor_id, actor_email, action, outcome, document_id, target_user_id, ip, detail, hash
                   FROM audit_events ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
                  ORDER BY seq DESC LIMIT ? OFFSET ?`;
    return db.prepare(sql).all(...p, f.limit, f.offset);
  },

  forDocument: (docId, limit, offset) =>
    db.prepare(
      `SELECT seq, ts, actor_email, action, outcome, target_user_id, detail
         FROM audit_events WHERE document_id = ? ORDER BY seq DESC LIMIT ? OFFSET ?`
    ).all(docId, limit, offset),

  /** Signals an administrator should look at. All thresholds are deliberately simple and explainable. */
  alerts(sinceIso) {
    const out = [];
    const burst = (sql, params, make) => { for (const r of db.prepare(sql).all(...params)) out.push(make(r)); };

    burst(
      `SELECT actor_email, COUNT(*) AS n FROM audit_events
        WHERE outcome = 'denied' AND action = 'access_denied' AND ts >= ? AND actor_email IS NOT NULL
        GROUP BY actor_email HAVING n >= 5`,
      [sinceIso],
      (r) => ({ kind: 'repeated_denials', severity: 'high', actor: r.actor_email, count: r.n,
        message: `${r.actor_email} was refused access ${r.n} times` })
    );
    burst(
      `SELECT actor_email, COUNT(*) AS n FROM audit_events
        WHERE outcome = 'denied' AND action = 'access_denied' AND json_extract(detail, '$.reason') = 'not_found'
          AND ts >= ? AND actor_email IS NOT NULL
        GROUP BY actor_email HAVING n >= 3`,
      [sinceIso],
      (r) => ({ kind: 'id_probing', severity: 'high', actor: r.actor_email, count: r.n,
        message: `${r.actor_email} requested ${r.n} document ids that do not exist (guessing)` })
    );
    burst(
      `SELECT actor_email, COUNT(*) AS n FROM audit_events
        WHERE action = 'download' AND outcome = 'success' AND ts >= ? GROUP BY actor_email HAVING n >= 20`,
      [sinceIso],
      (r) => ({ kind: 'bulk_download', severity: 'medium', actor: r.actor_email, count: r.n,
        message: `${r.actor_email} downloaded ${r.n} documents` })
    );
    burst(
      `SELECT json_extract(detail, '$.email') AS who, COUNT(*) AS n FROM audit_events
        WHERE action = 'login_failed' AND ts >= ? GROUP BY who HAVING n >= 5`,
      [sinceIso],
      (r) => ({ kind: 'login_failures', severity: 'medium', actor: r.who, count: r.n,
        message: `${r.n} failed logins for ${r.who}` })
    );
    burst(
      `SELECT document_id, COUNT(*) AS n FROM audit_events
        WHERE action IN ('grant_created','grant_updated') AND json_extract(detail, '$.level') = 'edit' AND ts >= ?
        GROUP BY document_id HAVING n >= 3`,
      [sinceIso],
      (r) => ({ kind: 'edit_grants_spree', severity: 'low', document: r.document_id, count: r.n,
        message: `${r.n} edit grants issued on one document` })
    );
    burst(
      `SELECT seq, document_id FROM audit_events WHERE action = 'integrity_failure' AND ts >= ?`,
      [sinceIso],
      (r) => ({ kind: 'integrity_failure', severity: 'critical', document: r.document_id,
        message: 'A stored file failed its integrity check when read' })
    );
    return out;
  },

  head: () => db.prepare('SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1').get() ?? null,
});
