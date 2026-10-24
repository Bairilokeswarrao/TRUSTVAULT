'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { world, pdf, events } = require('./helpers');
const { PUBLIC } = require('../src/app');

let w;
before(async () => { w = await world(); });
after(async () => { await w.close(); });

const D = () => `/api/documents/${w.docId}`;
const SECRET = 'ALICE-SALARY-LETTER';

test('T-01 an unauthenticated caller reaches nothing: every non-public route answers 401', async () => {
  const anon = w.client();
  for (const r of w.app.router.routes) {
    const key = `${r.method} ${r.re.source}`;
    const url = r.keys.reduce((u, k) => u.replace(/\(\[\^\/\]\+\)/, k === 'version' ? '1' : w.docId), r.re.source.replace(/^\^|\$$/g, '').replace(/\\\//g, '/'));
    if (PUBLIC.has(`${r.method} ${url}`)) continue;
    const res = await anon.req(r.method, url);
    assert.equal(res.status, 401, `${key} -> ${url} answered ${res.status}`);
  }
});

test('T-02 a user with no grant cannot read, download, edit, delete, share, restore or read the audit of a document (404, not 403)', async () => {
  for (const who of ['bob', 'carol', 'root']) {
    const c = w.c[who];
    const probes = [
      c.get(D()), c.get(`${D()}/download`), c.patch(D(), { title: 'x' }),
      c.upload('salary.pdf', pdf('HOSTILE'), { url: `${D()}/content`, method: 'PUT' }),
      c.del(D()), c.post(`${D()}/restore`), c.get(`${D()}/grants`),
      c.put(`${D()}/grants/${w.users[who].id}`, { level: 'read' }), c.get(`${D()}/audit`), c.post(`${D()}/suggestions`),
    ];
    for (const r of await Promise.all(probes)) {
      assert.equal(r.status, 404, `${who} got ${r.status}`);
      assert.ok(!r.buf.includes(SECRET));
    }
  }
  // and nothing changed
  assert.equal((await w.c.alice.get(D())).json.title, 'Salary letter');
});

test('T-02b the refusal body for "exists but not yours" is identical to "does not exist" (no existence oracle)', async () => {
  const a = await w.c.bob.get(D());
  const b = await w.c.bob.get('/api/documents/00000000-0000-4000-8000-000000000000');
  assert.equal(a.status, b.status);
  assert.deepEqual(a.json, b.json);
});

test('T-03 search never lists, counts or matches documents the caller was not granted', async () => {
  for (const who of ['bob', 'carol', 'root']) {
    for (const qs of ['', '?q=Salary', '?category=hr', '?owner=alice', '?q=%25', '?scope=shared', '?scope=mine', '?scope=trash']) {
      const r = await w.c[who].get(`/api/documents${qs}`);
      assert.equal(r.status, 200);
      assert.equal(r.json.documents.length, 0, `${who} ${qs} saw ${r.buf}`);
    }
  }
  assert.equal((await w.c.alice.get('/api/documents?q=Salary&owner=alice&category=hr')).json.documents.length, 1);
});

test('T-04 admin has no implicit content access, only a metadata view with no way to the bytes', async () => {
  assert.equal((await w.c.root.get(`${D()}/download`)).status, 404);
  const list = await w.c.root.get('/api/admin/documents');
  assert.equal(list.status, 200);
  assert.equal(list.json.documents.length, 1);
  assert.ok(!list.buf.toString().includes('storage'));
  assert.ok(!list.buf.toString().includes(SECRET));
  for (const who of ['alice', 'bob', 'carol']) assert.equal((await w.c[who].get('/api/admin/documents')).status, 403);
});

test('T-05 role gates: viewers cannot upload; only admins manage users or read the audit', async () => {
  assert.equal((await w.c.carol.upload('a.pdf', pdf())).status, 403);
  assert.equal((await w.c.root.upload('a.pdf', pdf())).status, 403);
  for (const who of ['alice', 'bob', 'carol']) {
    assert.equal((await w.c[who].get('/api/users')).status, 403);
    assert.equal((await w.c[who].get('/api/audit')).status, 403);
    assert.equal((await w.c[who].get('/api/audit/verify')).status, 403);
    assert.equal((await w.c[who].post('/api/users', { email: 'x@y.zz', name: 'x', role: 'admin', password: 'a-long-password-1' })).status, 403);
    assert.equal((await w.c[who].patch(`/api/users/${w.users[who].id}`, { role: 'admin' })).status, 403);
  }
});

test('T-06 grant levels: read can download but not edit/delete/share; edit can write but not delete/share', async () => {
  await w.c.alice.put(`${D()}/grants/${w.users.carol.id}`, { level: 'read' });
  const c = w.c.carol;
  const dl = await c.get(`${D()}/download`);
  assert.equal(dl.status, 200);
  assert.ok(dl.buf.includes(SECRET));
  assert.equal((await c.patch(D(), { title: 'mine now' })).status, 403);
  assert.equal((await c.upload('x.pdf', pdf('X'), { url: `${D()}/content`, method: 'PUT' })).status, 403);
  assert.equal((await c.del(D())).status, 403);
  assert.equal((await c.get(`${D()}/grants`)).status, 403);
  assert.equal((await c.put(`${D()}/grants/${w.users.dave.id}`, { level: 'read' })).status, 403);
  assert.equal((await c.get(`${D()}/audit`)).status, 403);

  await w.c.alice.put(`${D()}/grants/${w.users.bob.id}`, { level: 'edit' });
  const b = w.c.bob;
  assert.equal((await b.patch(D(), { title: 'Edited by Bob' })).status, 200);
  assert.equal((await b.del(D())).status, 403);
  assert.equal((await b.put(`${D()}/grants/${w.users.dave.id}`, { level: 'read' })).status, 403);
  assert.equal((await b.get(`${D()}/grants`)).status, 403);
  await w.c.alice.patch(D(), { title: 'Salary letter' });
  await w.c.alice.del(`${D()}/grants/${w.users.carol.id}`);
  await w.c.alice.del(`${D()}/grants/${w.users.bob.id}`);
});

test('T-07 a viewer-role account can never hold edit, even if an edit grant row is forced into the database', async () => {
  const r = await w.c.alice.put(`${D()}/grants/${w.users.carol.id}`, { level: 'edit' });
  assert.equal(r.status, 422);
  w.db.prepare('INSERT INTO grants (id, document_id, user_id, level, granted_by, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run('11111111-1111-4111-8111-111111111111', w.docId, w.users.carol.id, 'edit', w.users.alice.id, new Date().toISOString());
  assert.equal((await w.c.carol.patch(D(), { title: 'pwned' })).status, 403);
  assert.equal((await w.c.carol.get(D())).json.access, 'read');
  w.db.prepare('DELETE FROM grants WHERE id = ?').run('11111111-1111-4111-8111-111111111111');
});

test('T-08 earlier versions are owner-only: a later reader cannot fetch what the owner removed', async () => {
  const v2 = await w.c.alice.upload('salary.pdf', pdf('VERSION-TWO'), { url: `${D()}/content`, method: 'PUT' });
  assert.equal(v2.status, 200);
  await w.c.alice.put(`${D()}/grants/${w.users.carol.id}`, { level: 'read' });
  const cur = await w.c.carol.get(`${D()}/download`);
  assert.ok(cur.buf.includes('VERSION-TWO'));
  assert.equal((await w.c.carol.get(`${D()}/download?version=1`)).status, 403);
  assert.equal((await w.c.alice.get(`${D()}/download?version=1`)).status, 200);
  assert.equal((await w.c.carol.get(`${D()}/download?version=abc`)).status, 422);
  await w.c.alice.del(`${D()}/grants/${w.users.carol.id}`);
});

test('T-09 identifiers are validated: traversal, SQL and junk ids never reach a query', async () => {
  for (const id of ['..%2F..%2Fetc%2Fpasswd', "1'%20OR%20'1'='1", '%00', 'null', w.docId + 'x', w.docId.toUpperCase().slice(0, 35)]) {
    const r = await w.c.alice.get(`/api/documents/${id}`);
    assert.ok([400, 404].includes(r.status), `${id} -> ${r.status}`);
  }
});

test('T-10 mass assignment: owner_id / id / role in request bodies are ignored', async () => {
  const r = await w.c.bob.patch(D(), { owner_id: w.users.bob.id, title: 'x' });
  assert.equal(r.status, 404);
  const up = await w.c.bob.upload('b.pdf', pdf('BOB'), { title: 'Bob doc' });
  assert.equal(up.status, 201);
  const list = (await w.c.bob.get('/api/documents')).json.documents;
  assert.ok(list.every((d) => d.owner === w.users.bob.email));
  const me = await w.c.bob.patch(`/api/users/${w.users.bob.id}`, { role: 'admin' });
  assert.equal(me.status, 403);
});

test('T-11 files at rest are encrypted, randomly named, outside the web root, and never served', async () => {
  const files = fs.readdirSync(w.app.cfg.uploadDir);
  assert.ok(files.length >= 1);
  for (const f of files) {
    assert.match(f, /^[0-9a-f]{48}$/);
    assert.ok(!fs.readFileSync(path.join(w.app.cfg.uploadDir, f)).includes(SECRET), 'plaintext found on disk');
    assert.equal((await w.c.alice.get(`/${f}`)).status, 404);
    assert.equal((await w.c.alice.get(`/private_uploads/${f}`)).status, 404);
  }
  for (const p of ['/../src/app.js', '/..%2fsrc%2fapp.js', '/.env', '/%2e%2e/.env', '/css/../../.env', '/js/app.js/../../../.env']) {
    const r = await w.c.alice.get(p);
    assert.ok(![200].includes(r.status) || !r.buf.includes('FILE_ENC_KEY'), p);
    assert.ok(!r.buf.toString().includes('FILE_ENC_KEY'));
  }
});

test('T-12 a tampered or swapped ciphertext is refused and recorded, never served', async () => {
  const up = await w.c.alice.upload('t.pdf', pdf('TAMPER-ME'), { title: 'tamper' });
  const row = w.db.prepare('SELECT storage_key FROM document_versions WHERE document_id = ?').get(up.json.id);
  const f = path.join(w.app.cfg.uploadDir, row.storage_key);
  const blob = fs.readFileSync(f);
  blob[blob.length - 1] ^= 0xff;
  fs.writeFileSync(f, blob);
  const r = await w.c.alice.get(`/api/documents/${up.json.id}/download`);
  assert.equal(r.status, 500);
  assert.ok(!r.buf.includes('TAMPER-ME'));
  assert.equal(events(w.db, "action = 'integrity_failure' AND document_id = ?", up.json.id).length, 1);
});

test('T-13 upload validation: type allow-list, magic bytes, size, macros/scripts, empty, spoofed names', async () => {
  const a = w.c.alice;
  assert.equal((await a.upload('evil.exe', Buffer.from('MZ\x90\x00'))).status, 415);
  assert.equal((await a.upload('page.html', Buffer.from('<script>alert(1)</script>'))).status, 415);
  assert.equal((await a.upload('image.svg', Buffer.from('<svg onload=alert(1)>'))).status, 415);
  assert.equal((await a.upload('fake.pdf', Buffer.from('MZ\x90\x00 this is an exe'))).status, 415);
  assert.equal((await a.upload('fake.png', pdf())).status, 415);
  assert.equal((await a.upload('fake.docx', Buffer.from('PK\x03\x04 nothing office'))).status, 415);
  assert.equal((await a.upload('script.pdf', Buffer.from('%PDF-1.4\n/JavaScript (app.alert(1))\n%%EOF'))).status, 422);
  assert.equal((await a.upload('bin.txt', Buffer.from([0x68, 0x00, 0x69]))).status, 415);
  assert.equal((await a.upload('empty.pdf', Buffer.alloc(0))).status, 422);
  assert.equal((await a.upload('noext', pdf())).status, 415);
  assert.equal((await a.upload('double.pdf.exe', pdf())).status, 415);
  const big = Buffer.concat([Buffer.from('%PDF-1.4\n'), Buffer.alloc(w.app.cfg.maxUploadBytes + 10, 0x61)]);
  assert.equal((await a.upload('big.pdf', big)).status, 413);
  const wrongCT = await a.req('POST', '/api/documents?title=x&category=general', { body: pdf(), headers: { 'content-type': 'text/html', 'x-filename': 'a.pdf' } });
  assert.equal(wrongCT.status, 415);
  assert.equal((await a.upload('a.pdf', pdf(), { category: 'nonsense' })).status, 422);
  const ok = await a.upload('../../etc/passwd.txt', Buffer.from('hello'), { title: 'plain' });
  assert.equal(ok.status, 201);
  assert.equal((await a.get(`/api/documents/${ok.json.id}`)).json.originalName, 'passwd.txt');
});

test('T-14 downloads are forced to save, typed by what we verified, never rendered by the browser', async () => {
  const r = await w.c.alice.get(`${D()}/download`);
  assert.match(r.headers.get('content-disposition'), /^attachment;/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('content-type'), 'application/pdf');
  assert.match(r.headers.get('content-security-policy'), /sandbox/);
  assert.equal(r.headers.get('cache-control'), 'no-store');
});

test('T-15 CSRF: a state change with a valid cookie but no/incorrect token is refused; cross-origin is refused', async () => {
  const c = w.c.alice;
  assert.equal((await c.patch(D(), { title: 'csrf' }, { csrf: false })).status, 403);
  assert.equal((await c.patch(D(), { title: 'csrf' }, { headers: { 'x-csrf-token': 'wrong' } })).status, 403);
  assert.equal((await c.patch(D(), { title: 'csrf' }, { headers: { origin: 'https://evil.example' } })).status, 403);
  assert.equal((await c.get(D())).json.title, 'Salary letter');
  assert.equal(events(w.db, "action = 'csrf_failure'").length >= 2, true);
});

test('T-16 response headers: CSP, nosniff, frame denial; API responses are never cached', async () => {
  const r = await w.c.alice.get('/api/auth/me');
  assert.match(r.headers.get('content-security-policy'), /default-src 'none'/);
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('cache-control'), 'no-store');
});

test('T-17 login does not reveal which accounts exist, and locks after repeated failure', async () => {
  const c = w.client();
  const a = await c.login('nobody@test.local', 'whatever-whatever-1');
  const b = await c.login(w.users.carol.email, 'wrong-wrong-wrong-1');
  assert.equal(a.status, 401); assert.equal(b.status, 401);
  assert.deepEqual(a.json, b.json);
  for (let i = 0; i < 6; i++) await c.login(w.users.dave.email, 'wrong-wrong-wrong-1');
  assert.equal((await c.login(w.users.dave.email)).status, 401, 'correct password must fail while locked');
});

test('T-18 positive control: a grantee DOES see the shared document in search, with the right access level, and the owner sees it as owner', async () => {
  await w.c.alice.put(`${D()}/grants/${w.users.carol.id}`, { level: 'read' });
  const r = await w.c.carol.get('/api/documents?q=Salary');
  assert.equal(r.json.documents.length, 1);
  assert.equal(r.json.documents[0].access, 'read');
  assert.equal((await w.c.carol.get('/api/documents?scope=shared')).json.documents.length, 1);
  assert.equal((await w.c.carol.get('/api/documents?scope=mine')).json.documents.length, 0);
  assert.equal((await w.c.alice.get('/api/documents')).json.documents[0].access, 'owner');
  await w.c.alice.del(`${D()}/grants/${w.users.carol.id}`);
  assert.equal((await w.c.carol.get('/api/documents?q=Salary')).json.documents.length, 0);
});

test('T-19 the people directory is for owners only, never lists admins or disabled accounts, and needs a real query', async () => {
  assert.equal((await w.c.carol.get('/api/users/directory?q=bob')).status, 403);
  assert.equal((await w.c.root.get('/api/users/directory?q=bob')).status, 403);
  const ok = await w.c.alice.get('/api/users/directory?q=test.local');
  assert.equal(ok.status, 200);
  assert.ok(ok.json.users.length >= 2 && ok.json.users.length <= 10);
  assert.ok(ok.json.users.every((u) => u.role !== 'admin' && u.id !== w.users.alice.id && !('password_hash' in u)));
  assert.equal((await w.c.alice.get('/api/users/directory?q=a')).status, 422);
});

test('T-20 a ciphertext moved to another record is refused (the file name is bound into the encryption)', async () => {
  const a = (await w.c.alice.upload('a.pdf', pdf('AAA'), { title: 'A' })).json.id;
  const b = (await w.c.alice.upload('b.pdf', pdf('BBB'), { title: 'B' })).json.id;
  const ka = w.db.prepare('SELECT storage_key k FROM document_versions WHERE document_id = ?').get(a).k;
  const kb = w.db.prepare('SELECT storage_key k FROM document_versions WHERE document_id = ?').get(b).k;
  fs.copyFileSync(path.join(w.app.cfg.uploadDir, ka), path.join(w.app.cfg.uploadDir, kb));
  const r = await w.c.alice.get(`/api/documents/${b}/download`);
  assert.equal(r.status, 500);
  assert.ok(!r.buf.includes('AAA'));
});
