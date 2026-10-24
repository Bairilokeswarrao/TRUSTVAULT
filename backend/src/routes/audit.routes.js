'use strict';
const { HttpError, parseDateOnly, clampInt, cleanText } = require('../util');

const ACTIONS_MAX = 60;

module.exports = (R, svc, G) => {
  const { models, audit, auth, permissions } = svc;
  const admin = auth.requireRole('admin');

  // Admin: everything that happened, including refusals. Looking is itself recorded.
  R.get('/api/audit', admin, (ctx) => {
    const q = ctx.url.searchParams;
    const f = {
      action: q.get('action') ? cleanText(q.get('action'), { field: 'action', max: ACTIONS_MAX }) : '',
      outcome: ['success', 'denied', 'error'].includes(q.get('outcome')) ? q.get('outcome') : '',
      actor: q.get('actor') ? cleanText(q.get('actor'), { field: 'actor', max: 100 }) : '',
      documentId: q.get('documentId') ? cleanText(q.get('documentId'), { field: 'documentId', max: 36 }) : '',
      from: parseDateOnly(q.get('from'), 'from'),
      to: parseDateOnly(q.get('to'), 'to'),
      limit: clampInt(q.get('limit'), 50, 1, 200),
      offset: clampInt(q.get('offset'), 0, 0, 1000000),
    };
    const events = models.audit.list(f).map((e) => ({ ...e, detail: JSON.parse(e.detail) }));
    audit.append({ actor: ctx.user, action: 'audit_view', ip: ctx.ip, detail: { filters: { ...f, limit: undefined, offset: undefined } } });
    return { events, limit: f.limit, offset: f.offset };
  });

  R.get('/api/audit/alerts', admin, () => {
    const since = new Date(Date.now() - 24 * 3600e3).toISOString();
    return { since, alerts: models.audit.alerts(since) };
  });

  R.get('/api/audit/verify', admin, (ctx) => {
    const result = audit.verify();
    audit.append({ actor: ctx.user, action: 'audit_verify', outcome: result.ok ? 'success' : 'error', ip: ctx.ip, detail: { ok: result.ok, events: result.events, problems: result.problems.length } });
    return result;
  });

  // Owner: the history of THEIR document only (who looked, who was refused, who was granted what).
  R.get('/api/documents/:id/audit', G('view_audit'), (ctx) => {
    const q = ctx.url.searchParams;
    const events = models.audit.forDocument(ctx.doc.id, clampInt(q.get('limit'), 100, 1, 200), clampInt(q.get('offset'), 0, 0, 100000));
    return { events: events.map((e) => ({ ...e, detail: JSON.parse(e.detail) })) };
  });
};
