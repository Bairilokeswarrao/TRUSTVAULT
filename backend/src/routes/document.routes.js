'use strict';
const path = require('node:path');
const { HttpError, newId, cleanText, parseDateOnly, clampInt } = require('../util');
const { readBody, readJson } = require('../http');

const CATEGORIES = ['general', 'contracts', 'hr', 'finance', 'engineering', 'legal', 'audit'];

function cleanCategory(v) {
  const c = cleanText(v ?? 'general', { field: 'category', max: 40 }).toLowerCase();
  if (!CATEGORIES.includes(c)) throw new HttpError(422, 'invalid_field', `category must be one of ${CATEGORIES.join(', ')}`);
  return c;
}

/** Filename comes percent-encoded in a header; strip any path, control and bidi characters. */
function cleanFilename(raw) {
  let s;
  try { s = decodeURIComponent(String(raw ?? '')); } catch { throw new HttpError(422, 'invalid_field', 'X-Filename is not valid'); }
  s = cleanText(s, { field: 'filename', max: 200 });
  s = s.split(/[\\/]/).pop();
  if (!s || s === '.' || s === '..') throw new HttpError(422, 'invalid_field', 'filename is not valid');
  return s;
}

const asciiName = (n) => n.replace(/[^\x20-\x7e]|["\;]/g, '_');

module.exports = (R, svc, G) => {
  const { db, cfg, models, audit, storage, permissions, limiters } = svc;
  const owners = svc.auth.requireRole('owner');
  const admin = svc.auth.requireRole('admin');

  const shape = (d, level) => ({
    id: d.id, title: d.title, category: d.category, originalName: d.original_name, mime: d.mime,
    version: d.current_version, createdAt: d.created_at, updatedAt: d.updated_at, deletedAt: d.deleted_at, access: level,
  });

  const readUpload = async (ctx) => {
    const ct = (ctx.req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/octet-stream') throw new HttpError(415, 'unsupported_media_type', 'Send the file as application/octet-stream');
    const lim = limiters.upload.take(ctx.user.id);
    if (!lim.ok) throw new HttpError(429, 'rate_limited', 'Too many uploads, slow down');
    return readBody(ctx.req, cfg.maxUploadBytes);
  };

  // ---- upload: only the 'owner' role creates documents -------------------------------------------------
  R.post('/api/documents', owners, async (ctx) => {
    const q = ctx.url.searchParams;
    const originalName = cleanFilename(ctx.req.headers['x-filename']);
    const title = cleanText(q.get('title') || originalName, { field: 'title', max: 200 });
    const category = cleanCategory(q.get('category'));
    const body = await readUpload(ctx);
    let kind;
    try { kind = storage.inspect(body, originalName); } catch (e) {
      audit.append({ actor: ctx.user, action: 'upload_rejected', outcome: 'denied', ip: ctx.ip, detail: { filename: originalName, reason: e.code ?? e.message, size: body.length } });
      throw e;
    }
    const file = storage.save(body);
    const id = newId();
    try {
      db.tx(() => {
        models.document.create({ id, ownerId: ctx.user.id, title, category, originalName, mime: kind.mime, file });
        audit.append({ actor: ctx.user, action: 'upload', documentId: id, ip: ctx.ip, detail: { title, category, filename: originalName, size: file.size, sha256: file.sha256 } });
      });
    } catch (e) { storage.remove(file.storageKey); throw e; }
    ctx.status = 201;
    return { id, title, category, version: 1, size: file.size, sha256: file.sha256 };
  });

  // ---- search: the access predicate is always inside the query ------------------------------------------
  R.get('/api/documents', (ctx) => {
    const q = ctx.url.searchParams;
    const scope = q.get('scope') || 'all';
    if (!['all', 'mine', 'shared', 'trash'].includes(scope)) throw new HttpError(422, 'invalid_field', 'bad scope');
    const f = {
      scope,
      q: q.get('q') ? cleanText(q.get('q'), { field: 'q', max: 100 }) : '',
      owner: q.get('owner') ? cleanText(q.get('owner'), { field: 'owner', max: 100 }) : '',
      category: q.get('category') ? cleanCategory(q.get('category')) : '',
      from: parseDateOnly(q.get('from'), 'from'),
      to: parseDateOnly(q.get('to'), 'to'),
      limit: clampInt(q.get('limit'), 25, 1, 100),
      offset: clampInt(q.get('offset'), 0, 0, 100000),
    };
    const rows = models.document.search(ctx.user, f, permissions.accessPredicate(ctx.user));
    return {
      documents: rows.map((r) => ({
        id: r.id, title: r.title, category: r.category, originalName: r.original_name, version: r.current_version, size: r.size,
        owner: r.owner_email, ownerName: r.owner_name, createdAt: r.created_at, updatedAt: r.updated_at, deletedAt: r.deleted_at, access: r.access,
      })),
      limit: f.limit, offset: f.offset,
    };
  });

  // ---- metadata ----------------------------------------------------------------------------------------
  R.get('/api/documents/:id', G('view'), (ctx) => {
    const d = ctx.doc;
    audit.append({ actor: ctx.user, action: 'view', documentId: d.id, ip: ctx.ip, detail: {} });
    const out = shape(d, ctx.level);
    const cur = models.document.currentVersion(d.id);
    out.size = cur.size;
    out.sha256 = cur.sha256;
    out.owner = models.user.findById(d.owner_id)?.email;
    if (ctx.level === 'owner') out.versions = models.document.versions(d.id); // history is the owner's; see THREATS T-18
    return out;
  });

  R.patch('/api/documents/:id', G('edit'), async (ctx) => {
    const b = await readJson(ctx.req);
    const title = b.title === undefined ? ctx.doc.title : cleanText(b.title, { field: 'title', max: 200 });
    const category = b.category === undefined ? ctx.doc.category : cleanCategory(b.category);
    permissions.denialGuard(ctx, () => db.tx(() => {
      permissions.recheck(ctx, ctx.doc.id, 'edit');
      if (models.document.updateMeta(ctx.doc.id, { title, category }) !== 1) throw new HttpError(404, 'not_found', 'Document not found');
      audit.append({ actor: ctx.user, action: 'update_metadata', documentId: ctx.doc.id, ip: ctx.ip, detail: { from: { title: ctx.doc.title, category: ctx.doc.category }, to: { title, category } } });
    }));
    return { ok: true };
  });

  // ---- download: authorised, decrypted, integrity-checked, forced to download --------------------------
  R.get('/api/documents/:id/download', G('download'), (ctx) => {
    const d = ctx.doc;
    let ver = d.current_version;
    const asked = ctx.url.searchParams.get('version');
    if (asked !== null) {
      if (!/^\d{1,6}$/.test(asked)) throw new HttpError(422, 'invalid_field', 'version must be a number');
      ver = Number(asked);
      if (ver !== d.current_version && ctx.level !== 'owner') {
        // Older versions may hold what the owner later removed. Only the owner may fetch them.
        audit.append({ actor: ctx.user, action: 'access_denied', outcome: 'denied', documentId: d.id, ip: ctx.ip, detail: { attempted: 'download_old_version', reason: 'insufficient_level', level: ctx.level, version: ver } });
        throw new HttpError(403, 'forbidden', 'Only the owner can download earlier versions');
      }
    }
    const v = db.prepare('SELECT * FROM document_versions WHERE document_id = ? AND version = ?').get(d.id, ver);
    if (!v) throw new HttpError(404, 'not_found', 'Version not found');
    let data;
    try { data = storage.read(v.storage_key, v.sha256); } catch (e) {
      if (e.integrity) {
        audit.append({ actor: ctx.user, action: 'integrity_failure', outcome: 'error', documentId: d.id, ip: ctx.ip, detail: { version: ver } });
        throw new HttpError(500, 'integrity', 'This file failed its integrity check and has been withheld');
      }
      throw e;
    }
    // The success record is written BEFORE any byte leaves; if it cannot be written, nothing is sent.
    audit.append({ actor: ctx.user, action: 'download', documentId: d.id, ip: ctx.ip, detail: { version: ver, size: v.size, sha256: v.sha256 } });
    const ext = path.extname(d.original_name);
    const name = `${d.title.replace(/[\\/]/g, '_').slice(0, 120)}${ext && !d.title.toLowerCase().endsWith(ext.toLowerCase()) ? ext : ''}`;
    ctx.raw = true;
    ctx.res.writeHead(200, {
      'Content-Type': d.mime,
      'Content-Length': data.length,
      'Content-Disposition': `attachment; filename="${asciiName(name)}"; filename*=UTF-8''${encodeURIComponent(name)}`,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox",
    });
    ctx.res.end(data);
  });

  // ---- new version: authorise, read body, then authorise AGAIN at the moment of writing ----------------
  R.put('/api/documents/:id/content', G('new_version'), async (ctx) => {
    const d = ctx.doc;
    const originalName = cleanFilename(ctx.req.headers['x-filename'] || d.original_name);
    const body = await readUpload(ctx);
    let kind;
    try { kind = storage.inspect(body, originalName); } catch (e) {
      audit.append({ actor: ctx.user, action: 'upload_rejected', outcome: 'denied', documentId: d.id, ip: ctx.ip, detail: { filename: originalName, reason: e.code ?? e.message, size: body.length } });
      throw e;
    }
    if (kind.mime !== d.mime) throw new HttpError(422, 'type_changed', 'A new version must be the same kind of file');
    const file = storage.save(body);
    let version;
    try {
      version = permissions.denialGuard(ctx, () => db.tx(() => {
        permissions.recheck(ctx, d.id, 'new_version'); // revoked while the upload was in flight? refused.
        const v = models.document.addVersion(d.id, { storageKey: file.storageKey, size: file.size, sha256: file.sha256, uploadedBy: ctx.user.id, originalName, mime: kind.mime });
        if (v === null) throw new HttpError(404, 'not_found', 'Document not found');
        audit.append({ actor: ctx.user, action: 'new_version', documentId: d.id, ip: ctx.ip, detail: { version: v, size: file.size, sha256: file.sha256, filename: originalName } });
        return v;
      }));
    } catch (e) { storage.remove(file.storageKey); throw e; }
    return { version, size: file.size, sha256: file.sha256 };
  });

  // ---- delete / restore (owner only; soft delete first, purge after the retention window) --------------
  R.delete('/api/documents/:id', G('delete'), (ctx) => {
    permissions.denialGuard(ctx, () => db.tx(() => {
      permissions.recheck(ctx, ctx.doc.id, 'delete');
      if (models.document.softDelete(ctx.doc.id) !== 1) throw new HttpError(404, 'not_found', 'Document not found');
      audit.append({ actor: ctx.user, action: 'delete', documentId: ctx.doc.id, ip: ctx.ip, detail: { title: ctx.doc.title, recoverableForDays: cfg.retentionDays } });
    }));
    return { ok: true, recoverableForDays: cfg.retentionDays };
  });

  R.post('/api/documents/:id/restore', G('restore'), (ctx) => {
    permissions.denialGuard(ctx, () => db.tx(() => {
      permissions.recheck(ctx, ctx.doc.id, 'restore');
      if (models.document.restore(ctx.doc.id) !== 1) throw new HttpError(409, 'not_deleted', 'Document is not in the trash');
      audit.append({ actor: ctx.user, action: 'restore', documentId: ctx.doc.id, ip: ctx.ip, detail: { title: ctx.doc.title } });
    }));
    return { ok: true };
  });

  // ---- admin: metadata only. No content, no storage keys, no way to download from here -----------------
  R.get('/api/admin/documents', admin, (ctx) => {
    const q = ctx.url.searchParams;
    const rows = models.document.listForAdmin({ limit: clampInt(q.get('limit'), 50, 1, 200), offset: clampInt(q.get('offset'), 0, 0, 100000) });
    return { documents: rows.map((r) => ({ id: r.id, title: r.title, category: r.category, owner: r.owner_email, size: r.size, version: r.current_version, activeGrants: r.active_grants, createdAt: r.created_at, updatedAt: r.updated_at, deletedAt: r.deleted_at })) };
  });
};
module.exports.CATEGORIES = CATEGORIES;
