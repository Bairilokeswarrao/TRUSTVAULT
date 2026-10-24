'use strict';
const { HttpError, isId, newId, nowIso } = require('../util');
const { readJson } = require('../http');

const MAX_EXPIRY_DAYS = 365;

module.exports = (R, svc, G) => {
  const { db, models, audit, permissions } = svc;

  function parseExpiry(v) {
    if (v === undefined || v === null || v === '') return null;
    const t = typeof v === 'string' ? Date.parse(v) : NaN;
    if (Number.isNaN(t)) throw new HttpError(422, 'invalid_field', 'expiresAt must be an ISO date-time');
    if (t <= Date.now()) throw new HttpError(422, 'invalid_field', 'expiresAt must be in the future');
    if (t > Date.now() + MAX_EXPIRY_DAYS * 86400e3) throw new HttpError(422, 'invalid_field', `expiresAt may be at most ${MAX_EXPIRY_DAYS} days away`);
    return new Date(t).toISOString();
  }

  // Only the owner sees who has access.
  R.get('/api/documents/:id/grants', G('share'), (ctx) => ({
    grants: models.grant.listActive(ctx.doc.id),
    history: models.grant.history(ctx.doc.id),
  }));

  // Create or change a grant. The caller is the owner (checked by the guard AND re-checked in the transaction).
  R.put('/api/documents/:id/grants/:userId', G('share'), async (ctx) => {
    const b = await readJson(ctx.req);
    if (!['read', 'edit'].includes(b.level)) throw new HttpError(422, 'invalid_field', "level must be 'read' or 'edit'");
    const expiresAt = parseExpiry(b.expiresAt);
    const target = models.user.findById(ctx.params.userId);
    if (!target || target.disabled) throw new HttpError(404, 'not_found', 'User not found');
    if (target.id === ctx.user.id) throw new HttpError(422, 'invalid_field', 'You already own this document');
    if (target.role === 'viewer' && b.level === 'edit') throw new HttpError(422, 'role_ceiling', 'Viewer accounts can only be given read access');
    let suggestion = null;
    if (b.suggestionId !== undefined) {
      if (!isId(b.suggestionId)) throw new HttpError(422, 'invalid_field', 'bad suggestionId');
      suggestion = db.prepare('SELECT * FROM suggestions WHERE id = ?').get(b.suggestionId);
      if (!suggestion || suggestion.document_id !== ctx.doc.id || suggestion.user_id !== target.id || suggestion.decision) {
        throw new HttpError(409, 'bad_suggestion', 'That suggestion does not apply');
      }
      if (b.level !== suggestion.level) throw new HttpError(422, 'invalid_field', `A suggestion can only be accepted as '${suggestion.level}'`);
    }
    const result = permissions.denialGuard(ctx, () => db.tx(() => {
      permissions.recheck(ctx, ctx.doc.id, 'share');
      const outcome = models.grant.upsert({ docId: ctx.doc.id, userId: target.id, level: b.level, grantedBy: ctx.user.id, expiresAt });
      audit.append({ actor: ctx.user, action: outcome === 'created' ? 'grant_created' : 'grant_updated', documentId: ctx.doc.id, targetUserId: target.id, ip: ctx.ip, detail: { level: b.level, expiresAt, targetEmail: target.email, viaSuggestion: suggestion?.id ?? null } });
      if (suggestion) {
        db.prepare("UPDATE suggestions SET decision = 'accepted', decided_at = ? WHERE id = ?").run(nowIso(), suggestion.id);
        audit.append({ actor: ctx.user, action: 'suggestion_accepted', documentId: ctx.doc.id, targetUserId: target.id, ip: ctx.ip, detail: { suggestionId: suggestion.id, level: b.level, reason: suggestion.reason } });
      }
      return outcome;
    }));
    return { ok: true, result, userId: target.id, level: b.level, expiresAt };
  });

  // Taking access away. Effective on the next request of any kind: nothing was issued that could outlive this row.
  R.delete('/api/documents/:id/grants/:userId', G('share'), (ctx) => {
    const target = models.user.findById(ctx.params.userId);
    const n = permissions.denialGuard(ctx, () => db.tx(() => {
      permissions.recheck(ctx, ctx.doc.id, 'share');
      const changed = models.grant.revoke(ctx.doc.id, ctx.params.userId, ctx.user.id);
      if (changed) audit.append({ actor: ctx.user, action: 'grant_revoked', documentId: ctx.doc.id, targetUserId: ctx.params.userId, ip: ctx.ip, detail: { targetEmail: target?.email ?? null } });
      return changed;
    }));
    if (!n) throw new HttpError(404, 'not_found', 'That person has no access to revoke');
    return { ok: true };
  });

  // ---- assistive suggestions: they propose, a person decides, both are on the record --------------------
  // Nothing here can create access. The only path to a grant is the PUT above, made by the owner.
  R.post('/api/documents/:id/suggestions', G('share'), (ctx) => {
    const peers = models.grant.peersForOwnerCategory(ctx.user.id, ctx.doc.category, ctx.doc.id);
    const out = [];
    db.tx(() => {
      for (const p of peers) {
        if (permissions.resolve(p, ctx.doc.id).level) continue; // already has access
        if (p.role === 'admin') continue;
        const open = db.prepare('SELECT id FROM suggestions WHERE document_id = ? AND user_id = ? AND decision IS NULL').get(ctx.doc.id, p.id);
        const reason = `Has access to ${p.shared_docs} other "${ctx.doc.category}" document${p.shared_docs > 1 ? 's' : ''} you own`;
        const id = open?.id ?? newId();
        if (!open) {
          db.prepare('INSERT INTO suggestions (id, document_id, user_id, level, reason, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
            .run(id, ctx.doc.id, p.id, 'read', reason, ctx.user.id, nowIso());
        }
        out.push({ id, userId: p.id, email: p.email, name: p.name, level: 'read', reason });
      }
      audit.append({ actor: ctx.user, action: 'suggestion_created', documentId: ctx.doc.id, ip: ctx.ip, detail: { count: out.length, suggested: out.map((s) => ({ id: s.id, email: s.email, reason: s.reason })), granted: 'nothing; awaiting owner decision' } });
    });
    return { suggestions: out, note: 'Suggestions grant nothing. Choose who, if anyone, gets access.' };
  });

  R.post('/api/documents/:id/suggestions/:sid/reject', G('share'), (ctx) => {
    permissions.denialGuard(ctx, () => db.tx(() => {
      permissions.recheck(ctx, ctx.doc.id, 'share');
      const s = db.prepare('SELECT * FROM suggestions WHERE id = ? AND document_id = ?').get(ctx.params.sid, ctx.doc.id);
      if (!s || s.decision) throw new HttpError(409, 'bad_suggestion', 'That suggestion does not apply');
      db.prepare("UPDATE suggestions SET decision = 'rejected', decided_at = ? WHERE id = ?").run(nowIso(), s.id);
      audit.append({ actor: ctx.user, action: 'suggestion_rejected', documentId: ctx.doc.id, targetUserId: s.user_id, ip: ctx.ip, detail: { suggestionId: s.id, reason: s.reason } });
    }));
    return { ok: true };
  });
};
