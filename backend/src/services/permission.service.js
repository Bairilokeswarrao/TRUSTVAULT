'use strict';
const { HttpError, nowIso } = require('../util');

/**
 * THE permission model. One function decides; every route calls it; nothing else grants access.
 *
 *   owner  : the uploader. Everything, including sharing, deleting and reading the document's audit.
 *   edit   : read + replace content (new version) + rename/recategorise.
 *   read   : see metadata, download the CURRENT version.
 *   (none) : the document does not exist as far as they can tell (404, same as a bad id).
 *
 * Roles are a ceiling, not a key: 'viewer' accounts can never exceed read; 'admin' gets no implicit access to
 * content (separation of duties: whoever manages accounts and reads the audit cannot also read your salary letters).
 * Access is computed from the database on every request. Nothing is cached, nothing is signed, nothing is
 * a bearer link, so there is nothing issued earlier that outlives a revocation.
 */
const RANK = { read: 1, edit: 2, owner: 3 };
const NEED = {
  view: 'read', download: 'read',
  edit: 'edit', new_version: 'edit',
  delete: 'owner', restore: 'owner', share: 'owner', view_audit: 'owner',
};
const ALLOWED_WHEN_DELETED = new Set(['restore', 'view', 'view_audit']);

class Denied extends Error {
  constructor(info) { super('denied'); this.info = info; }
}

module.exports = ({ db, models, audit, auth }) => {
  function resolve(user, docId, now = nowIso()) {
    const doc = models.document.findById(docId);
    if (!doc) return { doc: null, level: null, reason: 'not_found' };
    if (!user || user.disabled) return { doc, level: null, reason: 'user_disabled' };
    let level = null;
    let reason = 'no_grant';
    if (doc.owner_id === user.id && user.role !== 'viewer') {
      level = 'owner';
    } else {
      const g = models.grant.active(doc.id, user.id, now);
      if (g) level = g.level;
      else {
        const last = db.prepare('SELECT revoked_at, expires_at FROM grants WHERE document_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 1').get(doc.id, user.id);
        if (last) reason = last.revoked_at ? 'grant_revoked' : 'grant_expired';
      }
    }
    if (user.role === 'viewer' && level === 'edit') level = 'read';
    return { doc, level, reason };
  }

  function decide(ctx, docId, action) {
    const need = NEED[action];
    if (!need) throw new Error(`unknown action ${action}`);
    const r = resolve(ctx.user, docId);
    const trash = Boolean(r.doc?.deleted_at);
    let ok = Boolean(r.level) && RANK[r.level] >= RANK[need];
    if (trash && !(r.level === 'owner' && ALLOWED_WHEN_DELETED.has(action))) ok = false;
    if (ok && !auth.stillValid(ctx)) ok = false; // session killed / user disabled mid-request
    const knowsItExists = Boolean(r.level) && !trash;
    return {
      ok, doc: r.doc, level: r.level,
      info: { action, reason: r.level ? (trash ? 'deleted' : 'insufficient_level') : (trash ? 'deleted' : r.reason), level: r.level },
      knowsItExists,
    };
  }

  const toError = (d) => (d.knowsItExists ? new HttpError(403, 'forbidden', 'You do not have permission to do that') : new HttpError(404, 'not_found', 'Document not found'));

  function recordDenial(ctx, docId, d) {
    audit.append({ actor: ctx.user, action: 'access_denied', outcome: 'denied', documentId: docId, ip: ctx.ip, detail: { attempted: d.info.action, reason: d.info.reason, level: d.info.level } });
  }

  /** Use OUTSIDE a transaction: records the refusal, then throws 403/404. */
  function authorize(ctx, docId, action) {
    const d = decide(ctx, docId, action);
    if (d.ok) return { doc: d.doc, level: d.level };
    recordDenial(ctx, docId, d);
    throw toError(d);
  }

  /** Use INSIDE a transaction (re-check at the moment of writing). Throws Denied; wrap with denialGuard. */
  function recheck(ctx, docId, action) {
    const d = decide(ctx, docId, action);
    if (!d.ok) throw new Denied({ docId, d });
    return { doc: d.doc, level: d.level };
  }

  /** Runs fn; if a re-check inside it was denied, the transaction has rolled back, so record that and answer 403/404. */
  function denialGuard(ctx, fn) {
    try { return fn(); } catch (e) {
      if (e instanceof Denied) { recordDenial(ctx, e.info.docId, e.info.d); throw toError(e.info.d); }
      throw e;
    }
  }

  /** SQL fragment for search: the ONLY documents a person may even see listed. */
  function accessPredicate(user, now = nowIso()) {
    return {
      sql: `(d.deleted_at IS NULL AND ((d.owner_id = ? AND ? <> 'viewer') OR EXISTS (
              SELECT 1 FROM grants g WHERE g.document_id = d.id AND g.user_id = ? AND g.revoked_at IS NULL
                 AND (g.expires_at IS NULL OR g.expires_at > ?))))`,
      params: [user.id, user.role, user.id, now],
    };
  }

  return { resolve, decide, authorize, recheck, denialGuard, accessPredicate, Denied, RANK };
};
