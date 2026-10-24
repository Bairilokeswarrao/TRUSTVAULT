'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp, events } = require('./helpers');

const reg = (c, extra) => c.post('/api/auth/register', { name: 'New Admin', email: 'na@test.local', password: 'correct-horse-battery-9', role: 'admin', ...extra }, { csrf: false });

test('R-16 admin self-registration needs the server code; disabled when none is configured', async () => {
  const off = await startApp();
  try { assert.equal((await reg(off.client(), { adminCode: 'anything-at-all-123' })).status, 403); } finally { await off.close(); }

  const t = await startApp({ adminRegistrationCode: 'let-me-in-please-42' });
  try {
    const c = t.client();
    assert.equal((await reg(c)).status, 403);
    assert.equal((await reg(c, { adminCode: 'wrong-code-wrong-1' })).status, 403);
    assert.ok(events(t.db, "action = 'access_denied'").some((e) => e.detail.reason === 'admin_registration'));
    assert.equal((await reg(c, { adminCode: 'let-me-in-please-42' })).status, 201);
    assert.equal(t.app.svc.models.user.findByEmail('na@test.local').role, 'admin');
    assert.equal((await c.post('/api/auth/register', { name: 'O', email: 'o@test.local', password: 'correct-horse-battery-9', role: 'owner' }, { csrf: false })).status, 201);
  } finally { await t.close(); }
});
