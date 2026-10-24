'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { createApp } = require('../src/app');

const PW = 'correct-horse-battery-9';

/** A fully isolated TrustVault (own database, own upload dir, own keys, random port) per test file. */
async function startApp(extra = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-'));
  const app = createApp({
    dataDir: dir, uploadDir: path.join(dir, 'files'),
    auditKey: crypto.randomBytes(32), fileKey: crypto.randomBytes(32),
    scryptN: 1024, loginRatePerMinute: 1000, apiRatePerMinute: 100000, ...extra,
  });
  const server = http.createServer(app.handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const hash = await app.svc.password.hash(PW);
  const users = {};
  async function addUser(key, role) {
    const email = `${key}@test.local`;
    const id = app.svc.models.user.create({ email, name: key, role, passwordHash: hash });
    users[key] = { id, email, role };
    return users[key];
  }
  return {
    app, base, dir, users, addUser, db: app.db,
    client: () => new Client(base),
    async close() { server.closeAllConnections(); await new Promise((r) => server.close(r)); app.close(); fs.rmSync(dir, { recursive: true, force: true }); },
  };
}

class Client {
  constructor(base) { this.base = base; this.cookie = null; this.csrf = null; }
  async login(email, password = PW) {
    const r = await this.req('POST', '/api/auth/login', { json: { email, password } });
    if (r.status === 200) this.csrf = r.json.csrfToken;
    return r;
  }
  async req(method, url, { json, body, headers = {}, csrf = true, cookie = true } = {}) {
    const h = { ...headers };
    if (cookie && this.cookie) h.cookie = this.cookie;
    if (csrf && this.csrf && !h['x-csrf-token']) h['x-csrf-token'] = this.csrf;
    let payload = body;
    if (json !== undefined) { h['content-type'] = 'application/json'; payload = JSON.stringify(json); }
    const res = await fetch(this.base + url, { method, headers: h, body: payload, redirect: 'manual' });
    const set = res.headers.get('set-cookie');
    if (set) this.cookie = set.split(';')[0].endsWith('=') ? null : set.split(';')[0];
    const buf = Buffer.from(await res.arrayBuffer());
    let j = null;
    try { j = JSON.parse(buf.toString('utf8')); } catch { /* binary or empty */ }
    return { status: res.status, headers: res.headers, buf, json: j };
  }
  get(url, o) { return this.req('GET', url, o); }
  post(url, json, o) { return this.req('POST', url, { json, ...o }); }
  put(url, json, o) { return this.req('PUT', url, { json, ...o }); }
  patch(url, json, o) { return this.req('PATCH', url, { json, ...o }); }
  del(url, o) { return this.req('DELETE', url, o); }
  upload(name, content, { title, category = 'general', url = '/api/documents', method = 'POST' } = {}) {
    const q = method === 'POST' ? `?title=${encodeURIComponent(title ?? name)}&category=${category}` : '';
    return this.req(method, url + q, { body: content, headers: { 'content-type': 'application/octet-stream', 'x-filename': encodeURIComponent(name) } });
  }
}

const pdf = (marker = 'SECRET') => Buffer.from(`%PDF-1.4\n1 0 obj<<>>endobj\n% ${marker}\ntrailer<<>>\n%%EOF\n`);
const events = (db, where = '1=1', ...p) => db.prepare(`SELECT * FROM audit_events WHERE ${where} ORDER BY seq`).all(...p).map((e) => ({ ...e, detail: JSON.parse(e.detail) }));

/** alice (owner) owns a document; bob (owner), carol (viewer), dave (viewer), root (admin) are bystanders. */
async function world(extra) {
  const t = await startApp(extra);
  for (const [k, r] of [['root', 'admin'], ['alice', 'owner'], ['bob', 'owner'], ['carol', 'viewer'], ['dave', 'viewer']]) await t.addUser(k, r);
  const c = {};
  for (const k of Object.keys(t.users)) { c[k] = t.client(); const r = await c[k].login(t.users[k].email); if (r.status !== 200) throw new Error(`login ${k} ${r.status}`); }
  const up = await c.alice.upload('salary.pdf', pdf('ALICE-SALARY-LETTER'), { title: 'Salary letter', category: 'hr' });
  if (up.status !== 201) throw new Error(`upload ${up.status} ${up.buf}`);
  return { ...t, c, docId: up.json.id };
}

module.exports = { startApp, world, Client, pdf, events, PW };
