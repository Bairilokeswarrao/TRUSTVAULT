'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { world, pdf, events } = require('./helpers');

let w;
before(async () => { w = await world(); });
after(async () => { await w.close(); });
const D = () => `/api/documents/${w.docId}`;

test('A-01 every kind of access is recorded with who, what, when, from where, and the outcome', async () => {
  await w.c.alice.put(`${D()}/grants/${w.users.carol.id}`, { level: 'read' });
  await w.c.carol.get(`${D()}/download`);
  await w.c.alice.patch(D(), { title: 'Salary letter 2' });
  await w.c.alice.upload('s.pdf', pdf('V2'), { url: `${D()}/content`, method: 'PUT' });
  await w.c.alice.del(`${D()}/grants/${w.users.carol.id}`);
  const actions = events(w.db).map((e) => e.action);
  for (const a of ['login_success', 'upload', 'grant_created', 'download', 'update_metadata', 'new_version', 'grant_revoked']) assert.ok(actions.includes(a), `missing ${a}`);
  const dl = events(w.db, "action='download'")[0];
  assert.equal(dl.actor_email, w.users.carol.email);
  assert.equal(dl.document_id, w.docId);
  assert.equal(dl.outcome, 'success');
  assert.ok(dl.ip && dl.ts && dl.detail.sha256);
  await w.c.alice.del(D()); await w.c.alice.post(`${D()}/restore`);
  assert.ok(events(w.db, "action='delete'").length === 1 && events(w.db, "action='restore'").length === 1);
});

test('A-02 refused attempts are recorded too: wrong user, wrong level, unknown id, no session, wrong role', async () => {
  await w.c.bob.get(`${D()}/download`);
  await w.c.bob.get('/api/documents/00000000-0000-4000-8000-0000000000aa');
  await w.client().get(`${D()}/download`);
  await w.c.carol.get('/api/audit');
  const denied = events(w.db, "outcome='denied'");
  const bobs = denied.filter((e) => e.actor_email === w.users.bob.email);
  assert.ok(bobs.some((e) => e.document_id === w.docId && e.detail.reason === 'no_grant' && e.detail.attempted === 'download'));
  assert.ok(bobs.some((e) => e.document_id === '00000000-0000-4000-8000-0000000000aa' && e.detail.reason === 'not_found'));
  assert.ok(denied.some((e) => e.actor_email === null && e.detail.reason === 'unauthenticated' && e.document_id === w.docId));
  assert.ok(denied.some((e) => e.actor_email === w.users.carol.email && e.detail.reason === 'role'));
  await w.client().login(w.users.bob.email, 'nope-nope-nope-nope');
  assert.ok(events(w.db, "action='login_failed'").some((e) => e.detail.email === w.users.bob.email));
});

test('A-03 an action and its audit record commit together: if the record cannot be written, the change does not happen', async () => {
  const before = w.db.prepare('SELECT title FROM documents WHERE id = ?').get(w.docId).title;
  const real = w.app.svc.audit.append;
  w.app.svc.audit.append = () => { throw new Error('disk full'); };
  try {
    const r = await w.c.alice.patch(D(), { title: 'unaudited change' });
    assert.equal(r.status, 500);
    const dl = await w.c.alice.get(`${D()}/download`);
    assert.equal(dl.status, 500, 'bytes were sent without a record');
  } finally { w.app.svc.audit.append = real; }
  assert.equal(w.db.prepare('SELECT title FROM documents WHERE id = ?').get(w.docId).title, before);
});

test('A-04 the application cannot rewrite or delete history (append-only triggers)', () => {
  assert.throws(() => w.db.prepare("UPDATE audit_events SET actor_email = 'x' WHERE seq = 1").run(), /append-only/);
  assert.throws(() => w.db.prepare('DELETE FROM audit_events WHERE seq = 1').run(), /append-only/);
  assert.throws(() => w.db.prepare('DELETE FROM audit_events').run(), /append-only/);
});

test('A-05 the chain verifies when untouched', async () => {
  const r = await w.c.root.get('/api/audit/verify');
  assert.equal(r.status, 200);
  assert.equal(r.json.ok, true, JSON.stringify(r.json));
  assert.ok(r.json.events > 10);
});

test('A-06 someone with raw database access who edits a row is caught, even after dropping the triggers', async () => {
  w.db.exec('DROP TRIGGER audit_no_update');
  w.db.prepare("UPDATE audit_events SET actor_email = 'someone.else@test.local' WHERE action = 'download'").run();
  const r = (await w.c.root.get('/api/audit/verify')).json;
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /does not match its hash/.test(p.reason)));
  assert.ok(r.problems.some((p) => /triggers are missing/.test(p.reason)));
});

test('A-07 ...and cannot repair it by recomputing hashes without the secret key', async () => {
  const rows = w.db.prepare('SELECT * FROM audit_events ORDER BY seq').all();
  let prev = '0'.repeat(64);
  for (const r of rows) {
    const naive = crypto.createHash('sha256').update(JSON.stringify([r.seq, r.ts, r.actor_id, r.actor_email, r.action, r.outcome, r.document_id, r.target_user_id, r.ip, r.detail, prev])).digest('hex');
    w.db.prepare('UPDATE audit_events SET prev_hash = ?, hash = ? WHERE seq = ?').run(prev, naive, r.seq);
    prev = naive;
  }
  const v = w.app.svc.audit.verify();
  assert.equal(v.ok, false);
  assert.ok(v.problems.length >= rows.length);
});

test('A-08 deleting rows from the middle, or truncating the end, is detected (sequence gap / external anchor)', async () => {
  const t = await world();
  try {
    await t.c.alice.get(`/api/documents/${t.docId}`);
    await t.c.alice.get(`/api/documents/${t.docId}`);
    assert.equal(t.app.svc.audit.verify().ok, true);
    t.db.exec('DROP TRIGGER audit_no_delete');
    const max = t.db.prepare('SELECT MAX(seq) m FROM audit_events').get().m;
    t.db.prepare('DELETE FROM audit_events WHERE seq = ?').run(max); // chop the tail: the chain alone cannot see this
    const v1 = t.app.svc.audit.verify();
    assert.ok(v1.problems.some((p) => /anchored event is missing/.test(p.reason)), JSON.stringify(v1));
    t.db.prepare('DELETE FROM audit_events WHERE seq = ?').run(max - 3); // and a hole in the middle
    assert.ok(t.app.svc.audit.verify().problems.some((p) => /gap in sequence|prev_hash/.test(p.reason)));
  } finally { await t.close(); }
});

test('A-09 secrets never enter the audit trail', async () => {
  const dump = JSON.stringify(w.db.prepare('SELECT * FROM audit_events').all());
  for (const s of ['correct-horse-battery-9', 'a-brand-new', 'password_hash', 'scrypt$', 'storage_key']) assert.ok(!dump.includes(s), s);
});

test('A-10 only an administrator reads the global trail; an owner reads only the trail of a document they own', async () => {
  const t = await world();
  try {
    await t.c.bob.get(`/api/documents/${t.docId}/download`); // refused
    const own = await t.c.alice.get(`/api/documents/${t.docId}/audit`);
    assert.equal(own.status, 200);
    assert.ok(own.json.events.some((e) => e.action === 'access_denied' && e.actor_email === t.users.bob.email), 'owner should see the refused attempt');
    const bobDoc = (await t.c.bob.upload('b.pdf', pdf('B'), { title: 'bob' })).json.id;
    assert.equal((await t.c.alice.get(`/api/documents/${bobDoc}/audit`)).status, 404);
    assert.equal((await t.c.carol.get('/api/audit')).status, 403);
    assert.equal((await t.c.alice.get('/api/audit')).status, 403);
    const all = await t.c.root.get('/api/audit?outcome=denied');
    assert.equal(all.status, 200);
    assert.ok(all.json.events.length >= 1);
    assert.ok(t.db.prepare("SELECT COUNT(*) n FROM audit_events WHERE action = 'audit_view'").get().n >= 1, 'reading the audit is itself audited');
  } finally { await t.close(); }
});

test('A-11 the audit filters are parameterised: injection through filters returns nothing odd and breaks nothing', async () => {
  const r = await w.c.root.get(`/api/audit?actor=${encodeURIComponent("' OR 1=1 --")}&action=${encodeURIComponent("x'; DROP TABLE users; --")}`);
  assert.equal(r.status, 200);
  assert.equal(r.json.events.length, 0);
  assert.ok(w.db.prepare('SELECT COUNT(*) n FROM users').get().n >= 5);
});

test('A-12 admin alerts flag probing: repeated refusals and guessed ids', async () => {
  const t = await world();
  try {
    for (let i = 0; i < 6; i++) await t.c.bob.get(`/api/documents/${t.docId}/download`);
    for (let i = 0; i < 3; i++) await t.c.bob.get(`/api/documents/00000000-0000-4000-8000-00000000000${i}`);
    const kinds = (await t.c.root.get('/api/audit/alerts')).json.alerts.map((a) => a.kind);
    assert.ok(kinds.includes('repeated_denials') && kinds.includes('id_probing'), kinds.join());
  } finally { await t.close(); }
});

test('A-13 suggestions grant nothing; the decision and the suggestion are both on the record', async () => {
  const t = await world();
  try {
    const a = t.c.alice;
    const mk = async (title, cat) => (await a.upload('x.pdf', pdf(title), { title, category: cat })).json.id;
    const old = await mk('older hr doc', 'hr');
    await a.put(`/api/documents/${old}/grants/${t.users.carol.id}`, { level: 'read' });
    await a.put(`/api/documents/${old}/grants/${t.users.bob.id}`, { level: 'read' });
    const s = await a.post(`/api/documents/${t.docId}/suggestions`);
    assert.equal(s.status, 200);
    assert.equal(s.json.suggestions.length, 2);
    const bobS = s.json.suggestions.find((x) => x.email === t.users.bob.email);
    assert.equal((await a.put(`/api/documents/${t.docId}/grants/${t.users.bob.id}`, { level: 'edit', suggestionId: bobS.id })).status, 422, 'owner-role target: only the role ceiling would stop this, the suggestion level must too');
    assert.equal((await t.c.bob.get(`/api/documents/${t.docId}`)).status, 404);
    assert.equal((await t.c.carol.get(`/api/documents/${t.docId}/download`)).status, 404, 'a suggestion must not grant access');
    assert.equal((await t.c.carol.post(`/api/documents/${t.docId}/suggestions`)).status, 404, 'non-owners cannot create suggestions');
    const sid = s.json.suggestions.find((x) => x.email === t.users.carol.email).id;
    assert.equal((await a.put(`/api/documents/${t.docId}/grants/${t.users.carol.id}`, { level: 'edit', suggestionId: sid })).status, 422, 'a suggestion for read cannot be widened to edit on acceptance');
    assert.equal((await t.c.carol.get(`/api/documents/${t.docId}/download`)).status, 404);
    assert.equal((await a.put(`/api/documents/${t.docId}/grants/${t.users.bob.id}`, { level: 'read', suggestionId: sid })).status, 409, 'a suggestion is for one person only');
    assert.equal((await a.put(`/api/documents/${t.docId}/grants/${t.users.carol.id}`, { level: 'read', suggestionId: sid })).status, 200);
    assert.equal((await t.c.carol.get(`/api/documents/${t.docId}/download`)).status, 200);
    const acts = events(t.db, 'document_id = ?', t.docId).map((e) => e.action);
    assert.ok(acts.includes('suggestion_created') && acts.includes('suggestion_accepted') && acts.includes('grant_created'));
    assert.equal((await a.put(`/api/documents/${t.docId}/grants/${t.users.carol.id}`, { level: 'read', suggestionId: sid })).status, 409, 'a decided suggestion cannot be replayed');
    // reject path
    await a.del(`/api/documents/${t.docId}/grants/${t.users.carol.id}`);
    const s2 = (await a.post(`/api/documents/${t.docId}/suggestions`)).json.suggestions.find((x) => x.email === t.users.carol.email);
    assert.equal((await a.post(`/api/documents/${t.docId}/suggestions/${s2.id}/reject`)).status, 200);
    assert.ok(events(t.db, "action='suggestion_rejected'").length === 1);
    assert.equal((await t.c.carol.get(`/api/documents/${t.docId}/download`)).status, 404);
  } finally { await t.close(); }
});
