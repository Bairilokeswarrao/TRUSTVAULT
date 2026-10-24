'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { world, pdf, events } = require('./helpers');

let w;
before(async () => { w = await world(); });
after(async () => { await w.close(); });
const D = () => `/api/documents/${w.docId}`;
const grant = (who, level = 'read', extra = {}) => w.c.alice.put(`${D()}/grants/${w.users[who].id}`, { level, ...extra });
const revoke = (who) => w.c.alice.del(`${D()}/grants/${w.users[who].id}`);

test('R-01 revoking a grant works on the very next request, on the session the person already had open', async () => {
  assert.equal((await grant('carol')).status, 200);
  assert.equal((await w.c.carol.get(`${D()}/download`)).status, 200);
  assert.equal((await revoke('carol')).status, 200);
  for (const r of [await w.c.carol.get(`${D()}/download`), await w.c.carol.get(D()), await w.c.carol.get('/api/documents')]) {
    assert.ok(r.status === 404 || (r.status === 200 && r.json.documents.length === 0), `still reachable: ${r.status}`);
  }
  assert.equal((await w.c.carol.get(`${D()}/download`)).status, 404);
});

test('R-02 a download that was allowed once leaves no reusable link: there is no URL, token or cache that survives', async () => {
  await grant('carol');
  const first = await w.c.carol.get(`${D()}/download`);
  assert.equal(first.headers.get('cache-control'), 'no-store');
  assert.ok(!first.headers.get('location') && !first.headers.get('set-cookie'));
  await revoke('carol');
  // replay the exact same request, with the cookie, a second time, and with a brand new login
  assert.equal((await w.c.carol.get(`${D()}/download`)).status, 404);
  const fresh = w.client(); await fresh.login(w.users.carol.email);
  assert.equal((await fresh.get(`${D()}/download`)).status, 404);
});

test('R-03 downgrading edit to read takes effect immediately', async () => {
  await grant('bob', 'edit');
  assert.equal((await w.c.bob.patch(D(), { title: 'by bob' })).status, 200);
  await grant('bob', 'read');
  assert.equal((await w.c.bob.patch(D(), { title: 'by bob again' })).status, 403);
  assert.equal((await w.c.bob.get(`${D()}/download`)).status, 200);
  await revoke('bob');
  await w.c.alice.patch(D(), { title: 'Salary letter' });
});

test('R-04 an expiring grant stops working at its expiry without anyone doing anything', async () => {
  const soon = new Date(Date.now() + 1500).toISOString();
  assert.equal((await grant('carol', 'read', { expiresAt: soon })).status, 200);
  assert.equal((await w.c.carol.get(`${D()}/download`)).status, 200);
  await new Promise((r) => setTimeout(r, 1700));
  assert.equal((await w.c.carol.get(`${D()}/download`)).status, 404);
  assert.equal((await w.c.carol.get('/api/documents')).json.documents.length, 0);
  assert.equal(events(w.db, "action='access_denied' AND actor_email=?", w.users.carol.email).pop().detail.reason, 'grant_expired');
});

test('R-05 expiry must be in the future and within a year; the past or the far future cannot be granted', async () => {
  assert.equal((await grant('carol', 'read', { expiresAt: new Date(Date.now() - 1000).toISOString() })).status, 422);
  assert.equal((await grant('carol', 'read', { expiresAt: new Date(Date.now() + 400 * 86400e3).toISOString() })).status, 422);
  assert.equal((await grant('carol', 'read', { expiresAt: 'tomorrow' })).status, 422);
});

test('R-06 a revocation that lands in the middle of an upload stops that upload from being written', async () => {
  await grant('bob', 'edit');
  const before = w.db.prepare('SELECT current_version v FROM documents WHERE id = ?').get(w.docId).v;
  const body = pdf('LATE-WRITE');
  const url = new URL(w.base + `${D()}/content`);
  const result = await new Promise((resolve, reject) => {
    const req = http.request({ host: url.hostname, port: url.port, path: url.pathname, method: 'PUT', headers: {
      cookie: w.c.bob.cookie, 'x-csrf-token': w.c.bob.csrf, 'content-type': 'application/octet-stream', 'content-length': body.length, 'x-filename': 'salary.pdf' } }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.write(body.subarray(0, 10)); // headers + a few bytes: the guard has already said yes
    setTimeout(async () => { await revoke('bob'); req.end(body.subarray(10)); }, 200);
  });
  assert.equal(result.status, 404);
  assert.equal(w.db.prepare('SELECT current_version v FROM documents WHERE id = ?').get(w.docId).v, before, 'a version was written after revocation');
  assert.equal(require('node:fs').readdirSync(w.app.cfg.uploadDir).length, w.db.prepare('SELECT COUNT(*) n FROM document_versions').get().n, 'orphan ciphertext left on disk');
  assert.ok(events(w.db, "action='access_denied' AND actor_email=?", w.users.bob.email).some((e) => e.detail.attempted === 'new_version'));
});

test('R-07 disabling a person ends their sessions and every grant they held, instantly', async () => {
  await grant('carol');
  await grant('dave');
  assert.equal((await w.c.carol.get(`${D()}/download`)).status, 200);
  const r = await w.c.root.patch(`/api/users/${w.users.carol.id}`, { disabled: true });
  assert.equal(r.status, 200);
  assert.equal((await w.c.carol.get(`${D()}/download`)).status, 401, 'old cookie still works');
  assert.equal((await w.client().login(w.users.carol.email)).status, 401, 'disabled account can sign in');
  assert.equal(w.db.prepare('SELECT COUNT(*) n FROM grants WHERE user_id = ? AND revoked_at IS NULL').get(w.users.carol.id).n, 0);
  assert.equal((await w.c.dave.get(`${D()}/download`)).status, 200, 'others are unaffected');
  await revoke('dave');
});

test('R-08 changing a password signs out every other session at once', async () => {
  const phone = w.client(); await phone.login(w.users.bob.email);
  const laptop = w.client(); await laptop.login(w.users.bob.email);
  assert.equal((await phone.get('/api/auth/me')).status, 200);
  const r = await laptop.post('/api/auth/password', { currentPassword: 'correct-horse-battery-9', newPassword: 'a-brand-new-passphrase-7' });
  assert.equal(r.status, 200);
  assert.equal((await phone.get('/api/auth/me')).status, 401);
  assert.equal((await laptop.get('/api/auth/me')).status, 200);
  assert.equal((await w.c.bob.get('/api/auth/me')).status, 401);
});

test('R-09 logout invalidates the session on the server, not just in the browser', async () => {
  const c = w.client(); await c.login(w.users.alice.email);
  const stolen = c.cookie;
  assert.equal((await c.post('/api/auth/logout')).status, 200);
  const thief = w.client(); thief.cookie = stolen; thief.csrf = c.csrf;
  assert.equal((await thief.get('/api/auth/me')).status, 401);
});

test('R-10 idle and absolute session limits are enforced server-side', async () => {
  const c = w.client(); await c.login(w.users.alice.email);
  const h = require('node:crypto').createHash('sha256').update(c.cookie.split('=')[1]).digest('hex');
  w.db.prepare('UPDATE sessions SET last_seen = ? WHERE id_hash = ?').run(new Date(Date.now() - 3600e3).toISOString(), h);
  assert.equal((await c.get('/api/auth/me')).status, 401, 'idle session accepted');
  const d = w.client(); await d.login(w.users.alice.email);
  const h2 = require('node:crypto').createHash('sha256').update(d.cookie.split('=')[1]).digest('hex');
  w.db.prepare('UPDATE sessions SET expires_at = ? WHERE id_hash = ?').run(new Date(Date.now() - 1000).toISOString(), h2);
  assert.equal((await d.get('/api/auth/me')).status, 401, 'expired session accepted');
});

test('R-11 deleting a document removes everyone else\'s access at once; restore does not resurrect revoked grants', async () => {
  await w.c.bob.login(w.users.bob.email, 'a-brand-new-passphrase-7'); // R-08 changed bob's password
  const up = await w.c.alice.upload('d.pdf', pdf('DEL'), { title: 'doc to delete' });
  const id = up.json.id;
  await w.c.alice.put(`/api/documents/${id}/grants/${w.users.dave.id}`, { level: 'read' });
  assert.equal((await w.c.dave.get(`/api/documents/${id}/download`)).status, 200);
  assert.equal((await w.c.alice.del(`/api/documents/${id}`)).status, 200);
  assert.equal((await w.c.dave.get(`/api/documents/${id}/download`)).status, 404);
  assert.equal((await w.c.dave.get('/api/documents?q=doc to delete')).json.documents.length, 0);
  assert.equal((await w.c.alice.get(`/api/documents/${id}/download`)).status, 404, 'even the owner cannot read from the trash');
  assert.equal((await w.c.alice.get('/api/documents?scope=trash')).json.documents.length, 1);
  assert.equal((await w.c.bob.post(`/api/documents/${id}/restore`)).status, 404);
  assert.equal((await w.c.alice.post(`/api/documents/${id}/restore`)).status, 200);
  assert.equal((await w.c.dave.get(`/api/documents/${id}/download`)).status, 200);
  await w.c.alice.del(`/api/documents/${id}/grants/${w.users.dave.id}`);
  await w.c.alice.del(`/api/documents/${id}`);
  assert.equal((await w.c.alice.post(`/api/documents/${id}/restore`)).status, 200);
  assert.equal((await w.c.dave.get(`/api/documents/${id}/download`)).status, 404, 'a revoked grant stayed revoked');
});

test('R-12 retention: trash older than the window is destroyed (rows and encrypted files), and recorded', async () => {
  const up = await w.c.alice.upload('p.pdf', pdf('PURGE'), { title: 'purge me' });
  await w.c.alice.del(`/api/documents/${up.json.id}`);
  w.db.prepare('UPDATE documents SET deleted_at = ? WHERE id = ?').run(new Date(Date.now() - 40 * 86400e3).toISOString(), up.json.id);
  const key = w.db.prepare('SELECT storage_key k FROM document_versions WHERE document_id = ?').get(up.json.id).k;
  w.app.purgeExpired();
  assert.equal(w.db.prepare('SELECT COUNT(*) n FROM documents WHERE id = ?').get(up.json.id).n, 0);
  assert.ok(!require('node:fs').existsSync(require('node:path').join(w.app.cfg.uploadDir, key)));
  assert.equal(events(w.db, "action='purge' AND document_id = ?", up.json.id).length, 1);
});

test('R-13 the last administrator cannot be removed or demoted; a viewer-to-owner swap cannot orphan documents', async () => {
  assert.equal((await w.c.root.patch(`/api/users/${w.users.root.id}`, { disabled: true })).status, 409);
  assert.equal((await w.c.root.patch(`/api/users/${w.users.root.id}`, { role: 'viewer' })).status, 409);
  assert.equal((await w.c.root.patch(`/api/users/${w.users.alice.id}`, { role: 'viewer' })).status, 409);
});

// A request that was authorised at the door but is still being read when the world changes must be re-checked before it writes.
function slowRequest(w, who, method, path, body, midway) {
  const url = new URL(w.base + path);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: url.hostname, port: url.port, path: url.pathname, method, headers: {
      cookie: w.c[who].cookie, 'x-csrf-token': w.c[who].csrf, 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.write(body.slice(0, 5));
    setTimeout(async () => { await midway(); req.end(body.slice(5)); }, 200);
  });
}

test('R-14 granting is re-checked at write time: an owner disabled mid-request creates no grant', async () => {
  const t = await world();
  try {
    const body = JSON.stringify({ level: 'read' });
    const r = await slowRequest(t, 'alice', 'PUT', `/api/documents/${t.docId}/grants/${t.users.carol.id}`, body,
      () => t.c.root.patch(`/api/users/${t.users.alice.id}`, { disabled: true }));
    assert.ok([401, 403, 404].includes(r.status), `got ${r.status}`);
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM grants').get().n, 0, 'grant created by a disabled owner');
  } finally { await t.close(); }
});

test('R-15 disabling a user removes their session rows, not just their access', async () => {
  const t = await world();
  try {
    assert.ok(t.db.prepare('SELECT COUNT(*) n FROM sessions WHERE user_id = ?').get(t.users.carol.id).n >= 1);
    await t.c.root.patch(`/api/users/${t.users.carol.id}`, { disabled: true });
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM sessions WHERE user_id = ?').get(t.users.carol.id).n, 0);
  } finally { await t.close(); }
});
